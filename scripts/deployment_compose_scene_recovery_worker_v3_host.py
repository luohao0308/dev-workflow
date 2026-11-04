"""Validate the consumed intent and active empty scope before worker startup."""
from datetime import datetime, timezone
import base64
import hashlib
import os
from pathlib import Path
import selectors
import secrets
import time
from types import SimpleNamespace

from deployment_compose_daemon_owner_v3_host import _finish, _left, _receive
from deployment_compose_owned_recovery_unit_v3_host import OwnedRecoveryUnitV3
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_scene_recovery_handoff_v3_host import digest, reject, verify, verify_signature
from deployment_compose_v3_channel_worker import write_frame
from deployment_compose_witness_store import ZERO, canonical, hex_value
from deployment_contract_v2 import RequestV2

INTENT_NAMESPACE = 'dev-workflow-scene-worker-intent-v3'
WITNESS_NAMESPACE = 'dev-workflow-scene-worker-witness-v3'
ENTRYPOINT = 'deployment_compose_scene_recovery_worker_v3_host.run'
_CONFIG = {'entrypoint', 'sourceSha', 'archiveDigest', 'channelNonce', 'daemonBinding',
           'handoff', 'proof', 'nonce', 'intentKey', 'witnessKey'}
RELAY_CLOSED = 'scene-recovery-relay-closed-v3'
STOP_CLOSED = 'scene-recovery-stop-closed-v3'
DELETE_CLOSED = 'scene-recovery-delete-closed-v3'
RECOVERY_CLOSED = 'scene-recovery-complete-v3'


def relay_terminal(channel_nonce, proof_digest):
    return dict(kind=RELAY_CLOSED, channelNonce=channel_nonce, workerProofDigest=proof_digest,
                authorityGranted=False, runtimePermit=False, productionReady=False)


def stop_terminal(channel_nonce, proof_digest, head, status, *, through_delete=False, terminal_digest=None):
    result = dict(relay_terminal(channel_nonce, proof_digest), kind=DELETE_CLOSED if through_delete else STOP_CLOSED,
                  head=head, status=status)
    if terminal_digest is not None:
        result.update(kind=RECOVERY_CLOSED, terminalPhaseDigest=terminal_digest)
    return result


class SceneFirstStopFenceV3:
    """Bind the already activated scope to one verified stop."""
    def __init__(self, handoff, receipts, operation_digest, *, through_delete=False, full_recovery=False):
        self._handoff = canonical(handoff)
        self._receipts = canonical(receipts)
        self._operation_digest = operation_digest
        self._owner = os.getpid()
        self._used = False
        self._phases = ('stop','delete','rename','start') if full_recovery else ('stop','delete') if through_delete else ('stop',)

    def activate(self, *, bundle, request, binding, intent_authority, phase_guard,
                 witness_client_factory, consumption_receipt_hash, gate_policy):
        from deployment_compose_coordinator_v3_host import Profile3StepExecutor

        if self._used or self._owner != os.getpid():
            reject()
        self._used = True
        handoff = decode(self._handoff)
        receipts = decode(self._receipts)
        operation = bundle.resolve_operations(receipts)[1]
        scope = Profile3StepExecutor.scope_descriptor(bundle, request, consumption_receipt_hash, operation, 1, receipts)
        if (request.canonical_json().encode('ascii') != canonical(handoff['request'])
                or operation['phase'] != 'stop' or operation['requestDigest'] != self._operation_digest
                or consumption_receipt_hash != handoff['receiptDigest'] or binding != handoff['firstBinding']
                or binding['generation'] != scope['generation'] or binding['scopeHash'] != scope['scopeHash']
                or binding['policyHash'] != gate_policy.identity_hash()):
            reject()
        intent_authority.check_consumed_intent(request)
        view = witness_client_factory(binding).check(expected_seq=0, expected_head=ZERO)
        if view['active'] is not True or view['phase'] != 'empty' or view['lineage'] != [handoff['parentTail']]:
            reject()
        return dict(startWriteIndex=1, receiptMap=receipts, scenePhases=self._phases)


def execute_stop(config, request, handoff, intent, factory, deadline):
    from deployment_compose_coordinator_v3_host import Profile3StepExecutor
    from deployment_compose_live_ssh_v3_host import verify_private_capsule
    from deployment_compose_phase_guard_v3_host import baseline_state_digest
    from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
    from deployment_compose_cold_writer_v3_host import observe_stopped_writer
    from deployment_compose_scene_create_worker_v3_host import _tls
    from deployment_gateway import GatePolicy

    context = config['stopContext']
    if type(context) is not dict or set(context) != {'capsule', 'hello', 'bootId', 'keys', 'policy', 'gateKey',
            'firstWrite', 'receiptMap', 'writerOrigin', 'version', 'throughDelete', 'fullRecovery'}:
        reject()
    through_delete = context['throughDelete']
    full_recovery = context['fullRecovery']
    if (type(through_delete) is not bool or type(full_recovery) is not bool
            or full_recovery and not through_delete):
        reject()
    policy = GatePolicy(**context['policy'])
    keys = {key: base64.b64decode(value, validate=True) for key, value in context['keys'].items()}
    gate_key = base64.b64decode(context['gateKey'], validate=True)
    daemon = config['daemonBinding']
    hello = context['hello']
    capsule = decode(base64.b64decode(context['capsule'], validate=True))
    bundle, original = verify_private_capsule(capsule, keys=keys, hello=hello, source_sha=config['sourceSha'],
        ssh_alias=request.host_id, policy=policy, trusted_boot_id=context['bootId'], trusted_bind_digest=None,
        historical=True)
    pins = context['firstWrite']
    receipts = context['receiptMap']
    verified = verify(config['handoff'], public_key=base64.b64decode(config['intentKey'], validate=True),
        scene_id=handoff['sceneId'], nonce=handoff['nonce'], first_write=pins, original=original, bundle=bundle,
        history=dict(closedTail=handoff['parentTail'], receiptMap=receipts))
    if verified != request or hello['root'] != daemon['root'] or hello['daemonId'] != daemon['daemonId']:
        reject()
    rows = {row['Id']: row for row in capsule['rawRows'].values()}
    if baseline_state_digest(rows) != bundle.to_dict()['baselineStateDigest']:
        reject()
    origin = canonical(context['writerOrigin'])

    def guard(snapshot):
        stopped = observe_stopped_writer(origin, expected_digest=hashlib.sha256(origin).hexdigest(),
            expected_source_sha=config['sourceSha'], expected_archive_digest=config['archiveDigest'],
            timeout=min(5, _left(deadline)))
        if stopped.writerStoppedObserved is not True or stopped.observation_digest != handoff['writerStopObservationDigest']:
            reject()
        observer = ObservedRecoveryDaemonV3(daemon['root'], daemon['daemonId'], kernel_boot=daemon['kernelBoot'],
                                            timeout=min(5, _left(deadline)))
        try:
            if canonical(observer.binding()) != canonical(daemon):
                reject()
            phase, endpoint = observer.capture_recovery_phase(bundle, rows, snapshot,
                expected_version=context['version'], timeout=min(15, _left(deadline)))
            return (hashlib.sha256(endpoint).hexdigest() == pins['endpointBindingDigest']
                    and (snapshot['phase_index'] > 1 or hashlib.sha256(phase).hexdigest() == pins['phaseDigest']))
        finally:
            observer.close()

    root = Path(daemon['root'])
    server, client, pin, _ = _tls(root, hello)
    binding = handoff['firstBinding']
    operations = bundle.resolve_operations(receipts)
    operation = operations[1]
    executor = Profile3StepExecutor(bundle, request, intent_authority=intent, phase_guard=guard,
        gate_root=root/('scene-stop-gate-'+request.digest()), gate_key=gate_key, gate_policy=policy,
        consumption_receipt_hash=handoff['receiptDigest'], witness_client_factory=factory,
        registered_binding=binding, tls_server_context=server, tls_client_context=client,
        server_certificate_sha256=pin, docker_socket=root/'docker.sock',
        control_timeout=_left(deadline), startup_fence=SceneFirstStopFenceV3(
            handoff, receipts, pins['nextOperationDigest'], through_delete=through_delete, full_recovery=full_recovery))
    last = 4 if full_recovery else 2 if through_delete else 1
    lineage = [handoff['parentTail']]
    for index in range(1, last+1):
        result = executor.execute(operations[index], phase_index=index, receipts=receipts, completed_operations=operations[:index])
        view = factory(result['binding']).read()
        if view['active'] is not True or view['phase'] != 'closed' or view['seq'] != 6 or view['lineage'] != lineage:
            reject()
        lineage.append(dict(binding=result['binding'], seq=6, head=view['head']))
    terminal_digest = None
    if full_recovery:
        terminal_digest = verify_readiness(bundle, capsule, rows, receipts, daemon, pins, context['version'], deadline)
    return view['head'], result['status'], terminal_digest


def verify_readiness(bundle, capsule, rows, receipts, daemon, pins, version, deadline):
    from deployment_compose_live_worker_v3_host import readiness
    from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3

    operations = bundle.resolve_operations(receipts)
    if len(receipts) != 1 or operations[-1]['phase'] != 'readiness':
        reject()
    candidate = next(iter(receipts.values()))
    protected = bundle.to_dict()['protectedContainers']
    paths = frozenset({'/v1.45/containers/'+cid+'/json' for cid in [candidate, *(row['containerId'] for row in protected)]}
                      | {'/v1.45/images/'+row['Id']+'/json' for row in capsule['imageCatalog']})
    budget = [16*1024*1024]
    observer = ObservedRecoveryDaemonV3(daemon['root'], daemon['daemonId'], kernel_boot=daemon['kernelBoot'],
                                        timeout=min(5, _left(deadline)))
    try:
        if canonical(observer.binding()) != canonical(daemon):
            reject()
        producer = SimpleNamespace(_get=lambda path: observer._request(path, deadline, budget, phase_paths=paths))
        session = SimpleNamespace(raw_rows=capsule['rawRows'], producer=producer,
            enrolled_images=capsule['imageCatalog'], project=bundle.to_dict()['identity']['project'])
        if readiness(session, candidate) is not True:
            reject()
        context = dict(phase_index=5, operation=None, receipts=receipts, completed_operations=operations)
        phase, endpoint = observer.capture_recovery_phase(bundle, rows, context, expected_version=version,
                                                           timeout=min(15, _left(deadline)), terminal=True)
        if hashlib.sha256(endpoint).hexdigest() != pins['endpointBindingDigest']:
            reject()
        return hashlib.sha256(phase).hexdigest()
    finally:
        observer.close()

def worker_statement(handoff, nonce, expiry):
    return dict(handoffDigest=digest(handoff), nonce=nonce, expiresAt=expiry,
                requestDigest=RequestV2.from_json(canonical(handoff['request']).decode('ascii')).digest(),
                activeBinding=handoff['firstBinding'], parentTail=handoff['parentTail'],
                activeSeq=0, activeHead=ZERO, activePhase='empty', consumed=True)


def verify_worker_proof(proof, *, handoff, nonce, intent_key, witness_key):
    if type(proof) is not dict or set(proof) != {'intent', 'witness'} or not hex_value(nonce):
        reject()
    verify_signature(proof['intent'], intent_key, namespace=INTENT_NAMESPACE)
    verify_signature(proof['witness'], witness_key, namespace=WITNESS_NAMESPACE)
    statement = proof['intent']['payload']
    if type(statement) is not dict:
        reject()
    expiry = statement.get('expiresAt')
    if (type(expiry) is not int or not 0 < expiry - time.time() <= 20 or expiry > handoff['expiresAt']
            or canonical(statement) != canonical(worker_statement(handoff, nonce, expiry))
            or canonical(proof['witness']['payload']) != canonical(statement)):
        reject()
    request = RequestV2.from_json(canonical(handoff['request']).decode('ascii'))
    request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=1800)
    if expiry > int(datetime.strptime(request.expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()):
        reject()
    return digest(statement)


class SceneRecoveryStartupUnitV3(OwnedRecoveryUnitV3):
    def __init__(self, archive_digest, source_sha):
        super().__init__(archive_digest, source_sha)
        worker = 'deployment_compose_owned_recovery_worker_v3_host'
        if self._code.count(worker) != 2:
            reject()
        self._code = self._code.replace(worker, 'deployment_compose_scene_recovery_worker_v3_host')


def _ready(config, proof_digest):
    return dict(kind='scene-recovery-worker-startup-v3', channelNonce=config['channelNonce'],
                sourceSha=config['sourceSha'], archiveDigest=config['archiveDigest'],
                daemonBindingDigest=digest(config['daemonBinding']), workerProofDigest=proof_digest,
                runtimePermit=False, authorityGranted=False, productionReady=False)


def run(config, stdin, stdout):
    """Fixed startup process. Exit after verifying the handoff and daemon identity."""
    from deployment_compose_scene_create_worker_v3_host import _fresh

    if (type(config) is not dict or set(config) not in (_CONFIG, _CONFIG|{'relayWorker'}, _CONFIG|{'relayWorker', 'stopContext'})
            or config.get('relayWorker', True) is not True or config['entrypoint'] != ENTRYPOINT
            or not hex_value(config['channelNonce'])):
        reject()
    relay = 'relayWorker' in config
    if not relay:
        with selectors.DefaultSelector() as selector:
            selector.register(stdin, selectors.EVENT_READ)
            if not selector.select(3) or os.read(stdin.fileno(), 1):
                reject()
    intent_key = base64.b64decode(config['intentKey'], validate=True)
    witness_key = base64.b64decode(config['witnessKey'], validate=True)
    certificate = config['handoff']
    verify_signature(certificate, intent_key)
    handoff = certificate['payload']
    if handoff['request']['source']['source_sha'] != config['sourceSha']:
        reject()
    checks = dict(handoff=handoff, nonce=config['nonce'], intent_key=intent_key, witness_key=witness_key)
    proof_digest = verify_worker_proof(config['proof'], **checks)
    _fresh(config['daemonBinding'])
    if time.time() >= config['proof']['intent']['payload']['expiresAt']:
        reject()
    if relay:
        from deployment_compose_intent_status_v3 import IntentStatusClientV3
        from deployment_compose_live_worker_v3_host import Channel, ENTRYPOINT as LIVE_ENTRYPOINT
        from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3

        request = RequestV2.from_json(canonical(handoff['request']).decode('ascii'))
        channel = Channel(dict(entrypoint=LIVE_ENTRYPOINT, channelNonce=config['channelNonce'],
            sourceSha=config['sourceSha'], archiveDigest=config['archiveDigest'], hostId=request.host_id), stdin, stdout)
        stop = 'stopContext' in config
        expiry = datetime.strptime(request.expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
        through_delete = stop and config['stopContext'].get('throughDelete') is True
        full_recovery = stop and config['stopContext'].get('fullRecovery') is True
        limit = 180 if full_recovery else 150 if through_delete else 90
        remaining = min(limit, expiry-time.time()) if stop else config['proof']['intent']['payload']['expiresAt'] - time.time()
        deadline = time.monotonic() + remaining
        with channel.operation_scope(deadline):
            intent = IntentStatusClientV3(request, intent_key, lambda rpc: channel.rpc('intent', 'check', rpc),
                                          scene_recovery=True)
            def factory(binding):
                return OperationWitnessClientV3(binding, witness_key, lambda method, rpc: channel.rpc('witness', method, rpc))
            witness = factory(handoff['firstBinding'])
            intent.check_consumed_intent(request)
            empty = witness.check(expected_seq=0, expected_head=ZERO)
            if empty['active'] is not True or empty['phase'] != 'empty' or empty['lineage'] != [handoff['parentTail']]:
                reject()
            if stop:
                head, status, terminal_digest = execute_stop(config, request, handoff, intent, factory, deadline)
                terminal = stop_terminal(config['channelNonce'], proof_digest, head, status,
                                         through_delete=through_delete, terminal_digest=terminal_digest)
            else:
                terminal = relay_terminal(config['channelNonce'], proof_digest)
            write_frame(stdout, terminal, timeout=channel.timeout())
    else:
        write_frame(stdout, _ready(config, proof_digest), timeout=3)


def send_startup(unit, archive, *, daemon_binding, certificate, proof, nonce, intent_key,
                 witness_key, deadline, relay=False, stop_context=None):
    if (type(unit) is not SceneRecoveryStartupUnitV3 or type(archive) is not bytes
            or not 0 < len(archive) <= 2*1024*1024
            or hashlib.sha256(archive).hexdigest() != unit._archive_digest):
        reject()
    unit._check()
    process = unit._process
    if process is None or process.poll() is not None:
        reject()
    config = dict(entrypoint=ENTRYPOINT, sourceSha=unit._source_sha, archiveDigest=unit._archive_digest,
                  channelNonce=secrets.token_hex(32), daemonBinding=decode(canonical(daemon_binding)),
                  handoff=certificate, proof=proof, nonce=nonce,
                  intentKey=base64.b64encode(intent_key).decode('ascii'),
                  witnessKey=base64.b64encode(witness_key).decode('ascii'))
    if relay:
        config['relayWorker'] = True
    if stop_context is not None:
        config['stopContext'] = stop_context
    write_frame(process.stdin, dict(config, archiveBase64=base64.b64encode(archive).decode('ascii')),
                timeout=_left(deadline))
    return config


def run_startup(unit, archive, *, proof_digest, deadline, **inputs):
    config = send_startup(unit, archive, deadline=deadline, **inputs)
    process = unit._process
    process.stdin.close()
    record = dict(process=process, stderr_eof=False, stderr_bytes=0)
    value = _receive(record, deadline)
    _finish(record, deadline)
    if canonical(value) != canonical(_ready(config, proof_digest)):
        reject()
    return value
