"""Fixed private Linux worker: one owned create, fresh recovery, confirmed cleanup.

This entry requires a root Delegate=yes dw-writer-host unit supplied by its trusted
embedding. The daemon probe does not provide that parent unit. No CLI, arbitrary
program selector, serialized drain authority, or production admission is exposed.
"""
import base64
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid

import deployment_compose_live_worker_v3_host as live
from deployment_compose_coordinator_v3_host import Profile3StepExecutor, ComposeCoordinatorV3, canonical
from deployment_compose_create_transport_v3_host import OwnedCreateTransportV3
from deployment_compose_history_v3_host import AuthenticatedHistoryV3
from deployment_compose_intent_status_v3 import IntentStatusClientV3
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, hex_value, binding_value
from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
from deployment_compose_startup_fence_v3_host import Profile3RecoveryFenceV3
from deployment_compose_writer_cgroup_v3_host import WriterCgroupV3
from deployment_gateway import GatePolicy

ENTRYPOINT = 'deployment_compose_owned_recovery_worker_v3_host.run'
# Fixed trusted local profile, never supplied by a candidate or protocol frame.
WORKER_UID = 65534
WORKER_GID = 65534


def reject():
    raise ValueError('compose-owned-recovery-worker-v3-rejected')


class Channel(live.Channel):
    def __init__(self, config, stdin, stdout):
        if type(config) is not dict or config.get('entrypoint') != ENTRYPOINT:
            reject()
        adapted = dict(config, entrypoint=live.ENTRYPOINT)
        super().__init__(adapted, stdin, stdout)
        self.config = dict(config)


def preflight():
    """Actual OS/delegation check before provisioning; placeholders grant nothing."""
    group = WriterCgroupV3('0'*64, '0'*64, WORKER_UID, WORKER_GID)
    group.close(deadline=time.monotonic()+5)


def consume(channel, bundle, request, policy, epoch, operation, index, receipts):
    refs = channel.receive('consume-intent')
    if (type(refs) is not dict or set(refs) != {'requestHash','receiptHash','firstBinding'}
            or refs['requestHash'] != request.digest() or not hex_value(refs['receiptHash'])):
        reject()
    binding = binding_value(refs['firstBinding'])
    desc = Profile3StepExecutor.scope_descriptor(bundle, request, refs['receiptHash'], operation, index, receipts)
    expected = dict(scopeHash=desc['scopeHash'], generation=desc['generation'],
                    policyHash=policy.identity_hash(), epoch=epoch)
    if binding != expected:
        reject()
    return refs['receiptHash'], binding


def _reconcile(session, tracker, history):
    original = sys.exc_info()[1]
    try:
        tracker.apply_to_session(session, history)
    except BaseException as error:
        if original is None:
            raise
        if hasattr(original, 'add_note'):
            original.add_note('ownership reconciliation failed: '+str(error))


def _inputs(channel, session, prepared, policy, gate_key, public, status_public, tls,
            tracker, operation, index, receipts, *, parent=None, reviewed=None):
    bundle, request = prepared['bundle'], prepared['request']
    receipt, binding = consume(channel, bundle, request, policy, tracker.epoch, operation, index, receipts)
    authority = IntentStatusClientV3(request, status_public, lambda req:channel.rpc('intent','check',req))
    authority.check_consumed_intent(request)
    factory = lambda b:OperationWitnessClientV3(b, public, lambda method,req:channel.rpc('witness',method,req))
    history = AuthenticatedHistoryV3(bundle, request, gate_policy=policy, gate_key=gate_key,
        consumption_receipt_hash=receipt, witness_client=factory(binding), witness_client_factory=factory,
        parent_history=parent, reviewed_parent_snapshot=reviewed)
    @contextmanager
    def scope(deadline):
        with channel.operation_scope(deadline), session.producer.operation_scope(deadline):
            yield
    args = dict(intent_authority=authority, phase_guard=session.guard,
        gate_root=session.root/('owned-recovery-gate-'+request.digest()), gate_key=gate_key, gate_policy=policy,
        consumption_receipt_hash=receipt, witness_client_factory=factory, registered_binding=binding,
        tls_server_context=tls[0], tls_client_context=tls[1], server_certificate_sha256=tls[2],
        docker_socket=Path(session.target.socket), operation_scope=scope)
    return history, args


def create_cut(channel, session, prepared, policy, gate_key, public, status_public, tls, tracker, retained):
    """Execute only index zero and retain its opaque local issuer/record."""
    bundle, request = prepared['bundle'], prepared['request']
    operations = bundle.creation_operations()
    if request.operation != 'deploy' or len(operations) != 1:
        reject()
    history, args = _inputs(channel,session,prepared,policy,gate_key,public,status_public,tls,
                            tracker,operations[0],0,{})
    directory = session.root/'live-writer-tls'
    owned = OwnedCreateTransportV3(worker_uid=WORKER_UID,worker_gid=WORKER_GID,
        ca_pem=(directory/'ca.pem').read_bytes(),client_cert_pem=(directory/'writer.pem').read_bytes(),
        client_key_pem=(directory/'writer.key').read_bytes())
    session.unknown_write_result = True
    tracker.mark_product_pending()
    try:
        executor = Profile3StepExecutor(bundle,request,owned_create_transport=owned,**args)
        retained['executor'] = executor
        executor.execute(operations[0],phase_index=0,receipts={},completed_operations=[])
        record = executor.capture_owned_closed_create(history)
        reviewed = history.capture()
        retained.update(record=record,history=history,reviewed=reviewed)
    finally:
        # Register the root prefix before any child can transition its chain.
        _reconcile(session,tracker,history)
    return history


def complete_history(history, reviewed, result):
    """Schema two has five total writes and four child scopes."""
    snapshot = history.capture()
    value = json.loads(snapshot.canonical)
    parent = json.loads(reviewed.canonical)
    operations = [op for op in history._bundle.resolve_operations(value['receiptMap']) if op['method'] != 'GET']
    expected_parent = dict(historyDigest=reviewed.digest,originalRequestHash=parent['originalRequestHash'],
        bundleDigest=parent['bundleDigest'],tail=parent['closedTail'],scopeCount=1,startWriteIndex=1)
    tail = value.get('closedTail')
    if (value.get('schemaVersion') != 2 or value.get('parent') != expected_parent
            or len(operations) != 5 or value['knownPrefix'] != operations or len(value['scopes']) != 4
            or value['blocker'] is not None or value['pending'] is not None
            or any(scope['seq'] != 6 for scope in value['scopes'])
            or tail != {k:value['scopes'][-1][k] for k in ('binding','seq','head')}
            or value['chainStatus']['activePhase'] != 'closed'
            or tail != dict(binding=value['chainStatus']['activeBinding'],seq=value['chainStatus']['activeSeq'],head=value['chainStatus']['activeHead'])
            or value['receiptMap'] != result['receipts'] or value['receiptMap'] != parent['receiptMap']
            or result['initialWriteCount'] != 1 or result['productionReady'] is not False):
        reject()
    return value


def recover_suffix(channel, session, prepared, preparation, context, policy, gate_key,
                   public, status_public, tls, tracker, retained):
    reviewed = prepared['reviewed_history']
    if context['startWriteIndex'] != 1 or reviewed.canonical != retained['reviewed'].canonical:
        reject()
    history,args = _inputs(channel,session,prepared,policy,gate_key,public,status_public,tls,tracker,
        context['nextOperation'],1,context['receiptMap'],parent=retained['history'],reviewed=reviewed)
    session.unknown_write_result = True
    tracker.mark_product_pending()
    try:
        fence = Profile3RecoveryFenceV3(preparation=preparation,
            context_reference=prepared['recovery_context_reference'],reviewed_history=reviewed,
            original_executor=retained['executor'],closed_create_drain=retained['record'])
        executor = Profile3StepExecutor(prepared['bundle'],prepared['request'],startup_fence=fence,**args)
        bundle = prepared['bundle']
        def verify(receipts):
            done = bundle.creation_operations()
            op = bundle.resolve_operations(dict(receipts))[len(done)]
            return session.guard(dict(phase_index=len(done),operation=op,receipts=dict(receipts),completed_operations=done)) is True
        def ready(service,cid):
            if service != 'backend' or live.readiness(session,cid) is not True:
                return False
            receipts = {service:cid}
            done = bundle.resolve_operations(receipts)
            return canonical(session.guard._capture(done,receipts)) == canonical(session.guard._capture(done,receipts))
        result = ComposeCoordinatorV3(executor,verify_candidates=verify,readiness=ready).run()
        final = complete_history(history,reviewed,result)
    finally:
        _reconcile(session,tracker,history)
    return result,final


def run(config, stdin, stdout):
    channel = Channel(config,stdin,stdout)
    preflight()
    from deployment_compose_profile3_prepare_ssh_probe import _probe
    from compose_profile3_prepare_fixture import prepare_profile3
    from compose_profile3_ownership_fixture import FixtureOwnershipTrackerV3
    from deployment_gate_witness import key_material
    final_payload = None
    workload_error = None
    def workload(root,info):
        nonlocal final_payload,workload_error
        session = None
        retained = {}
        try:
            tls = live.writer_tls(root)
            channel.emit('hello',root=str(root),daemonId=info['ID'],writerCertificateSha256=tls[3],
                serverCertificateSha256=tls[2],sourceSha=config['sourceSha'],archiveDigest=config['archiveDigest'],hostId=config['hostId'])
            setup = channel.receive('configure')
            if set(setup) != {'policy','epoch','witnessPublicKey','statusPublicKey','keys','gateKey'}:
                reject()
            policy = GatePolicy(**setup['policy'])
            public = base64.b64decode(setup['witnessPublicKey'],validate=True)
            status = base64.b64decode(setup['statusPublicKey'],validate=True)
            gate_key = base64.b64decode(setup['gateKey'],validate=True)
            keys = {k:base64.b64decode(v,validate=True) for k,v in setup['keys'].items()}
            if (set(keys) != live.KEYS or any(len(v) != 32 for v in keys.values()) or len(gate_key) != 32
                    or not hex_value(setup['epoch']) or policy.writer_certificate_sha256 != tls[3]
                    or policy.operation_profile != 'compose-v3' or policy.witness_scope_hash != '0'*64
                    or policy.witness_key_sha256 != hashlib.sha256(key_material(public)).hexdigest()):
                reject()
            session = prepare_profile3(root,info,source_sha=config['sourceSha'],host_id=config['hostId'],
                expected_daemon_id=info['ID'],keys=keys,policy_hash=policy.identity_hash(),environment='staging',expiry_seconds=900)
            tracker = FixtureOwnershipTrackerV3(project=session.project,daemon_id=info['ID'],policy_hash=policy.identity_hash(),
                witness_pub_hash=policy.witness_key_sha256,epoch=setup['epoch'],initial_confirmed_ids=session.created_ids,
                protected_ids=[x['containerId'] for x in session.prepared['bundle'].to_dict()['protectedContainers']])
            live.emit_observer_facts(channel,session,session.prepared,root)
            channel.emit('prepared-private',**live.private_capsule(session,session.prepared))
            create_cut(channel,session,session.prepared,policy,gate_key,public,status,tls,tracker,retained)
            preparation = RecoveryPreparationHostV3(original_history=retained['history'],store=session.store,
                phase_guard=session.guard,readiness=lambda service,cid:live.readiness(session,cid))
            expiry = (datetime.now(timezone.utc)+timedelta(seconds=900)).strftime('%Y-%m-%dT%H:%M:%SZ')
            prepared = preparation.prepare_intent(operation_nonce=uuid.uuid4().hex+uuid.uuid4().hex,expires_at=expiry)
            context = preparation.verify_context(prepared['recovery_context_reference'],prepared['request'],prepared['reviewed_history'])
            channel.emit('recovery-prepared-private',request=asdict(prepared['request']),context=context)
            result,history = recover_suffix(channel,session,prepared,preparation,context,policy,gate_key,public,status,tls,tracker,retained)
            session.cleanup()
            session = None
            final_payload = dict(result=result,history=history,success=True,cleanupCompleted=True,productionReady=False)
            return dict(success=True)
        except BaseException as error:
            workload_error = error
            if session is None:
                session = getattr(error,'preparation_session',None)
            raise
        finally:
            original = sys.exc_info()[1]
            for action in ([lambda:retained['executor'].retry_owned_cleanup(time.monotonic()+5)] if original is not None and 'executor' in retained else []):
                try:
                    action()
                except BaseException as error:
                    if session is not None:
                        session.unknown_write_result = True
                    if original is None:
                        workload_error = error
                        raise
                    if hasattr(original,'add_note'):
                        original.add_note('owned process cleanup failed: '+str(error))
            if session is not None:
                try:
                    session.cleanup()
                except BaseException as error:
                    if original is None:
                        workload_error = error
                        raise
                    if hasattr(original,'add_note'):
                        original.add_note('fixture cleanup failed: '+str(error))
    report = _probe(workload)
    if workload_error is not None:
        raise workload_error
    return live.finish_probe(channel,report,final_payload)
