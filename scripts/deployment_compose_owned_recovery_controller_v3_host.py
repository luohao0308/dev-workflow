"""Private recovery protocol driver, with no launcher or remote lifetime proof.

The trusted embedding authenticates worker/source/observer origin and transfers
an actual local Popen and its private binary pipes. Popen identity and protocol
pins do not authenticate an SSH host. Local termination never proves remote stop.
"""
import base64
from dataclasses import asdict
import hashlib
import json
import os
import re
import secrets
import selectors
import struct
import subprocess
import threading
import time

import deployment_compose_live_ssh_v3_host as live
from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_phase_guard_v3_host import baseline_state_bytes
from deployment_compose_profile3_prepare_ssh_probe import _private_root
from deployment_compose_recovery_phase_capsule_v3_host import verify_captured_recovery_phase
from deployment_compose_v3_channel_worker import LIMIT, write_frame
from deployment_compose_history_v3_host import pairs
from deployment_contract_v2 import RequestV2
from deployment_gateway import GatePolicy
from deployment_gate_witness import key_material


def reject():
    raise ValueError('compose-owned-recovery-controller-v3-rejected') from None


def _receive(stream, deadline, errors):
    """A single frame deadline, with prompt private stderr failure detection."""
    def exact(size):
        result = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(stream,selectors.EVENT_READ)
            while len(result) < size:
                left = deadline-time.monotonic()
                if left <= 0 or errors:reject()
                if not selector.select(min(left,.1)):continue
                chunk = os.read(stream.fileno(),size-len(result))
                if not chunk:reject()
                result.extend(chunk)
        return bytes(result)
    size = struct.unpack('!I',exact(4))[0]
    if not 0 < size <= LIMIT:reject()
    raw = exact(size)
    value = json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:reject())
    if live.encode(value) != raw:reject()
    return value


def _completed_history(admission):
    entry = admission._current
    root = admission._root
    if (entry is None or root is None or entry is root or admission._pending is not None
            or entry['request'].operation != 'recovery'):
        reject()
    parent = entry['parentSnapshot']
    original = json.loads(parent.canonical)
    snapshot = admission._history(entry).capture()
    value = json.loads(snapshot.canonical)
    operations = [op for op in entry['bundle'].resolve_operations(value['receiptMap']) if op['method'] != 'GET']
    expected = dict(historyDigest=parent.digest, originalRequestHash=root['request'].digest(),
        bundleDigest=root['bundle'].digest, tail=original['closedTail'], scopeCount=1, startWriteIndex=1)
    status = value['chainStatus']
    if (value['schemaVersion'] != 2 or value.get('parent') != expected
            or entry['request'].history_hash != parent.digest
            or original['originalRequestHash'] != root['request'].digest()
            or original['bundleDigest'] != root['bundle'].digest
            or len(original['scopes']) != 1 or len(original['knownPrefix']) != 1
            or value['originalRequestHash'] != entry['request'].digest()
            or value['bundleDigest'] != entry['bundle'].digest
            or value['blocker'] is not None or value['pending'] is not None
            or len(operations) != 5 or value['knownPrefix'] != operations
            or len(value['scopes']) != 4 or any(s['seq'] != 6 for s in value['scopes'])
            or value['receiptMap'] != original['receiptMap']
            or status['activePhase'] != 'closed' or status['activeSeq'] != 6
            or value['closedTail'] != {k:value['scopes'][-1][k] for k in ('binding','seq','head')}
            or value['closedTail'] != dict(binding=status['activeBinding'],seq=6,head=status['activeHead'])):
        reject()
    return snapshot


def _drive_recovery_protocol(private_root, *, process, channel_nonce, source_sha,
        archive_digest, host_id, normalization_version, review, on_review,
        trusted_boot_id, trusted_bind_digest, expected_root, expected_daemon_id,
        expected_project, timeout=3600):
    """Consume exactly deploy and recovery; callbacks only notify.

    Origin authentication is an embedding precondition, including the supplied
    observer pins. No serialized ownership assertion or worker cleanup flag is
    accepted as proof of origin or remote wrapper shutdown. No protocol retries.
    """
    if type(process) is not subprocess.Popen:
        reject()
    store = thread = None
    errors = []
    stop_drain = threading.Event()
    try:
        if (any(p is None or p.closed for p in (process.stdin,process.stdout,process.stderr))
                or process.text_mode or process.poll() is not None
                or not callable(on_review)
                or type(timeout) not in (int,float) or not 0 < timeout <= 3600
                or not isinstance(channel_nonce,str) or not re.fullmatch('[0-9a-f]{64}',channel_nonce)
                or not isinstance(source_sha,str) or not re.fullmatch('[0-9a-f]{40}',source_sha)
                or not isinstance(archive_digest,str) or not re.fullmatch('[0-9a-f]{64}',archive_digest)
                or not isinstance(trusted_boot_id,str) or not re.fullmatch('[0-9a-f]{32}',trusted_boot_id)
                or trusted_bind_digest is not None
                or type(normalization_version) is not dict
                or set(normalization_version) != {'Version','GitCommit'}
                or any(type(v) is not str or not v for v in normalization_version.values())
                or type(expected_root) is not str or not re.fullmatch('/var/tmp/dw-engine-[0-9a-f]{16}',expected_root)
                or type(expected_daemon_id) is not str or not expected_daemon_id
                or type(host_id) is not str or not host_id
                or type(expected_project) is not str or not expected_project.startswith('dw-restore-')):
            reject()
        version = json.loads(live.encode(normalization_version))
        root = _private_root(private_root)
        case = root/('owned-recovery-'+secrets.token_hex(12));case.mkdir(mode=0o700)
        signer, public = live._live_key(case,'witness-signing')
        status_signer, status_public = live._live_key(case,'status-signing')
        keys = {k:secrets.token_bytes(32) for k in ('config','image','declaration','archive','target')}
        gate_key, store_key = secrets.token_bytes(32), secrets.token_bytes(32)
        state = case/'witness';state.mkdir(mode=0o700)
        store = OperationWitnessStoreV3(state,key=store_key)
        stderr = case/'stderr.private.txt'
        fd = os.open(stderr,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        def drain():
            size = 0
            try:
                with os.fdopen(fd,'wb',buffering=0) as output, selectors.DefaultSelector() as selector:
                    selector.register(process.stderr,selectors.EVENT_READ)
                    while not stop_drain.is_set():
                        if not selector.select(.1):continue
                        chunk = os.read(process.stderr.fileno(),65536)
                        if not chunk:return
                        if size < 1024*1024:output.write(chunk[:1024*1024-size])
                        size += len(chunk)
                        if size > 1024*1024:errors.append('stderr-bound');return
            except Exception:
                errors.append('stderr-io')
        thread = threading.Thread(target=drain,daemon=True);thread.start()
        deadline = time.monotonic()+timeout
        def remaining(limit=900):
            left = deadline-time.monotonic()
            if left <= 0 or errors:reject()
            return min(limit,left)
        def send(kind,**data):
            write_frame(process.stdin,dict(kind=kind,channelNonce=channel_nonce,**data),timeout=remaining(30))
        stage = 'hello'
        admission = hello = policy = baseline = None
        last_rpc = count = 0
        nonces = set()
        total_bytes = 0
        for _ in range(4096):
            frame = _receive(process.stdout,time.monotonic()+remaining(),errors)
            if type(frame) is not dict or frame.get('channelNonce') != channel_nonce:reject()
            total_bytes += len(live.encode(frame))
            if total_bytes > 64*1024*1024:reject()
            kind = frame.get('kind')
            data = {k:v for k,v in frame.items() if k not in ('kind','channelNonce')}
            if kind == 'hello' and stage == 'hello':
                if (set(data) != {'root','daemonId','writerCertificateSha256','serverCertificateSha256','sourceSha','archiveDigest','hostId'}
                        or any(data[k] != v for k,v in dict(root=expected_root,daemonId=expected_daemon_id,
                            sourceSha=source_sha,archiveDigest=archive_digest,hostId=host_id).items())
                        or any(type(data[k]) is not str or not re.fullmatch('[0-9a-f]{64}',data[k])
                            for k in ('writerCertificateSha256','serverCertificateSha256'))):reject()
                hello = data
                policy = GatePolicy(case.name,'recovery-gate-v3',live.digest(hello),
                    hello['writerCertificateSha256'],True,'0'*64,
                    hashlib.sha256(key_material(public)).hexdigest(),operation_profile='compose-v3')
                admission = MacLiveAdmissionV3(store=store,gate_policy=policy,gate_key=gate_key,
                    witness_signer=signer,witness_public_key=public,intent_signer=status_signer,intent_public_key=status_public)
                send('configure',policy=asdict(policy),epoch=admission._epoch,
                    witnessPublicKey=base64.b64encode(public).decode(),statusPublicKey=base64.b64encode(status_public).decode(),
                    keys={k:base64.b64encode(v).decode() for k,v in keys.items()},gateKey=base64.b64encode(gate_key).decode())
                stage = 'observer'
            elif kind == 'observer-facts' and stage == 'observer':
                expected = dict(operation='deploy',root=expected_root,daemonId=expected_daemon_id,
                    sourceSha=source_sha,archiveDigest=archive_digest,bootId=trusted_boot_id,bindDigest=trusted_bind_digest)
                if data != expected:reject()
                stage = 'prepared'
            elif kind == 'prepared-private' and stage == 'prepared':
                if set(data) != {'bundle','request','publicReview','sourceModel','rawRows','sourceFacts',
                        'targetInputs','baselineArtifacts','scopePolicy','imageCatalog','phaseSnapshot','observationMaterial'}:reject()
                raw = live.encode(data)
                frozen = json.loads(raw)
                bundle, request = live.verify_private_capsule(frozen,hello=hello,source_sha=source_sha,
                    ssh_alias=host_id,policy=policy,keys=keys,trusted_boot_id=trusted_boot_id,trusted_bind_digest=trusted_bind_digest)
                if request.operation != 'deploy' or request.target.namespace != expected_project:reject()
                baseline = baseline_state_bytes({r['Id']:r for r in frozen['rawRows'].values()})
                approval,consumption,_ = review.consume_prepared(bundle,request,on_review)
                remaining()
                if process.poll() is not None:reject()
                binding = admission.register_intent(bundle,request,approval,consumption)
                send('consume-intent',requestHash=request.digest(),receiptHash=live.digest(asdict(consumption)),firstBinding=binding)
                count = 1;stage = 'create'
            elif kind == 'recovery-prepared-private' and stage == 'create':
                if set(data) != {'request','context'}:reject()
                raw = live.encode(data)
                entry = admission._root
                verified = verify_captured_recovery_phase(raw,original_history=admission._history(entry),
                    baseline_bytes=baseline,expected_daemon_version=version,expected_source=entry['request'].source,
                    expected_host_id=host_id,expected_daemon_id=expected_daemon_id,expected_target=entry['request'].target,
                    expected_policy_hash=policy.identity_hash())
                request = RequestV2.from_json(verified.request_bytes.decode('ascii'))
                approval,consumption,_ = review.consume_prepared(entry['bundle'],request,on_review)
                remaining()
                if process.poll() is not None:reject()
                binding = admission.register_recovery(raw,approval,consumption,baseline_bytes=baseline,expected_daemon_version=version)
                send('consume-intent',requestHash=request.digest(),receiptHash=live.digest(asdict(consumption)),firstBinding=binding)
                count = 2;stage = 'recovery'
            elif kind == 'rpc' and stage in ('create','recovery'):
                if (set(data) != {'rpcId','service','method','request'} or type(data['rpcId']) is not int
                        or data['rpcId'] <= last_rpc or type(data['request']) is not dict):reject()
                service, method = data['service'],data['method']
                allowed = {'intent':{'check'},'witness':{'read','check','events_after','chain_status','append_event'}}
                if stage == 'recovery':allowed['witness'].add('transition_successor')
                if type(service) is not str or service not in allowed or type(method) is not str or method not in allowed[service]:reject()
                nonce = data['request'].get('rpcNonce')
                if type(nonce) is not str or not re.fullmatch('[0-9a-f]{64}',nonce) or nonce in nonces:reject()
                nonces.add(nonce);last_rpc = data['rpcId']
                response = live._authorize_rpc(admission,service,method,data['request'],case)
                send('reply',rpcId=last_rpc,response=response)
            elif kind == 'final' and stage == 'recovery':
                flags = ('success','cleanupCompleted','daemonStopped','productionSnapshotUnchanged')
                if (set(data) != {'result','history','productionReady',*flags}
                        or data['productionReady'] is not False or any(data[k] is not True for k in flags)):reject()
                snapshot = _completed_history(admission)
                if live.encode(data['history']) != snapshot.canonical:reject()
                result = data['result']
                if (type(result) is not dict or result.get('receipts') != snapshot.snapshot['receiptMap']
                        or type(result.get('initialWriteCount')) is not int
                        or result['initialWriteCount'] != 1 or result.get('productionReady') is not False):reject()
                process.stdin.close()
                if process.wait(timeout=remaining(30)) != 0:reject()
                thread.join(timeout=remaining(5))
                if thread.is_alive() or errors:reject()
                return dict(protocolCompleted=True,historyCompleted=True,localTransportExited=True,
                    requestCount=count,workerReport={k:data[k] for k in flags},
                    remoteWrapperStoppedVerified=False,productionReady=False)
            else:
                reject()
        reject()
    finally:
        # Only this transferred LOCAL process is affected. Preserve primary errors.
        import sys
        primary = sys.exc_info()[0] is not None
        cleanup_error = None
        def cleanup(action):
            nonlocal cleanup_error
            try:action()
            except Exception as error:
                if cleanup_error is None:cleanup_error = error
        if process.poll() is None:
            cleanup(process.terminate)
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cleanup(process.kill);cleanup(lambda:process.wait(timeout=5))
            except Exception as error:cleanup_error = error
        stop_drain.set()
        if thread is not None:cleanup(lambda:thread.join(timeout=1))
        for stream in (process.stdin,process.stdout,process.stderr):
            if stream is not None:cleanup(stream.close)
        if store is not None:cleanup(store.close)
        cleanup(lambda:live._close_review(review))
        if not primary and cleanup_error is not None:raise cleanup_error
