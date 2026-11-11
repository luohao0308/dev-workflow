"""Activate an empty successor scope on the original scene witness ledger."""
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import time
import weakref

from deployment_compose_approval_v3_host import GitHubSceneRecoveryApprovalV3
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_restart_checkpoint_v3_host import _sealed_reader, read_file
from deployment_compose_restart_material_v3_host import _prefix
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_scene_live_phase_v3_host import _observe_authenticated_scene
from deployment_compose_scene_phase_snapshot_v3_host import _first_write_pins, digest
from deployment_compose_scene_recovery_intent_v3_host import (
    PROFILE, scene_recovery_public_review, verify_scene_recovery_intent)
from deployment_compose_witness_budget_v3_host import check_witness_byte_capacity
from deployment_compose_witness_store import ZERO, canonical, hex_value
from deployment_contract_v2 import RequestV2

_SESSIONS = weakref.WeakKeyDictionary()


def reject():
    raise ValueError('compose-scene-recovery-admission-v3-rejected') from None


class SceneRecoverySessionV3:
    """In-process handle for the original admitted scene and its empty scope."""
    __slots__ = ('__weakref__',)

    def __copy__(self): reject()
    def __deepcopy__(self, memo): reject()
    def __reduce_ex__(self, protocol): reject()

    def recheck_first_write(self, *, handle):
        return self._recheck_first_write(handle=handle, intent_signer=None)

    def stage_first_write(self, *, handle, intent_signer):
        if not isinstance(intent_signer, Path):
            reject()
        return self._recheck_first_write(handle=handle, intent_signer=intent_signer)

    def prepare_first_worker(self, *, handle, intent_signer):
        if not isinstance(intent_signer, Path):
            reject()
        return self._recheck_first_write(handle=handle, intent_signer=intent_signer, prepare_worker=True)

    def launch_first_worker(self, *, handle, intent_signer):
        """Launch and drain the fixed Linux worker's read-only startup check."""
        if not isinstance(intent_signer, Path):
            reject()
        return self._recheck_first_write(handle=handle, intent_signer=intent_signer,
                                         prepare_worker=True, launch_worker=True)

    def verify_worker_relay(self, *, handle, intent_signer):
        """Run the fixed worker against this session's scoped Mac RPC channel."""
        authorize = self.open_first_stop_rpc(intent_signer=intent_signer)
        return self._recheck_first_write(handle=handle, intent_signer=intent_signer,
                                         prepare_worker=True, relay_rpc=authorize)

    def execute_first_stop(self, *, handle, intent_signer):
        """Execute one reviewed stop in the already activated witness scope."""
        authorize = self.open_first_stop_rpc(intent_signer=intent_signer)
        return self._recheck_first_write(handle=handle, intent_signer=intent_signer,
            prepare_worker=True, relay_rpc=authorize, stop_verifier=authorize.verify_stop)

    def execute_through_delete(self, *, handle, intent_signer):
        """Execute the reviewed stop, then its sole allowed delete successor."""
        authorize = self.open_first_stop_rpc(intent_signer=intent_signer, through_delete=True)
        result = self._recheck_first_write(handle=handle, intent_signer=intent_signer,
            prepare_worker=True, relay_rpc=authorize, stop_verifier=authorize.verify_delete, through_delete=True)
        result['deleteReceipt'] = result.pop('stopReceipt')
        result['stopReceipt'] = authorize.verify_stop()
        return result

    def execute_recovery(self, *, handle, intent_signer):
        """Execute the remaining reviewed writes and verify terminal readiness."""
        authorize = self.open_first_stop_rpc(intent_signer=intent_signer, through_delete=True, full_recovery=True)
        result = self._recheck_first_write(handle=handle, intent_signer=intent_signer, prepare_worker=True,
            relay_rpc=authorize, stop_verifier=authorize.verify_start, through_delete=True, full_recovery=True)
        result['startReceipt'] = result.pop('stopReceipt')
        result['stopReceipt'] = authorize.verify_stop()
        result['deleteReceipt'] = authorize.verify_delete()
        result['renameReceipt'] = authorize.verify_rename()
        result['recoveryComplete'] = True
        return result

    def open_first_stop_rpc(self, *, intent_signer, through_delete=False, full_recovery=False):
        """Open one private RPC handler for the embedding's authenticated worker."""
        from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3, SSH_KEYGEN
        from deployment_gate_witness import key_material

        record = _SESSIONS.get(self)
        if (type(self) is not SceneRecoverySessionV3 or record is None or record.get('rpc_opened')
                or type(through_delete) is not bool or type(full_recovery) is not bool
                or full_recovery and not through_delete):
            reject()
        _authenticate_session(record)
        approval, request, receipt = record['consent']
        GitHubSceneRecoveryApprovalV3.verify_consumption_receipt(approval, request, receipt)
        native = record['reader']()._reader
        guard = native._guard
        if not isinstance(intent_signer, Path) or intent_signer.parent != guard.case:
            reject()
        _, identity = read_file(guard.dirs[guard.case][0], intent_signer.name, 65536)
        public = key_material(subprocess.run([SSH_KEYGEN, '-y', '-f', str(intent_signer)],
            capture_output=True, check=True, timeout=3, env={'PATH': '/usr/bin:/bin'}).stdout)
        if digest(public) != record['reader_seal'][4]:
            reject()
        history = native._context.history
        host = MacLiveAdmissionV3(store=native._store, gate_policy=history._policy, gate_key=history._key,
            witness_signer=guard.case/'witness-signing', witness_public_key=history._client._public,
            intent_signer=intent_signer, intent_public_key=public)
        _authenticate_session(record)
        if read_file(guard.dirs[guard.case][0], intent_signer.name, 65536)[1] != identity:
            reject()
        record['rpc_opened'] = True
        return _first_stop_rpc(dict(record), host, intent_signer, identity,
                               through_delete=through_delete, full_recovery=full_recovery)

    def _recheck_first_write(self, *, handle, intent_signer, prepare_worker=False, launch_worker=False,
                             relay_rpc=None, stop_verifier=None, through_delete=False, full_recovery=False):
        record = _SESSIONS.get(self)
        if type(self) is not SceneRecoverySessionV3 or record is None:
            reject()
        authenticate = lambda: _authenticate_session(record)
        approval, request, receipt = record['consent']
        authenticate()
        GitHubSceneRecoveryApprovalV3.verify_consumption_receipt(approval, request, receipt)
        pins = decode(record['first_write'])
        handoff_digest = None
        worker_proof_digest = None

        def make_handoff(nonce):
            from deployment_compose_scene_recovery_handoff_v3_host import issue

            nonlocal handoff_digest
            payload, _, _ = authenticate()
            guard = record['reader']()._reader._guard
            if intent_signer.parent != guard.case:
                reject()
            directory = guard.dirs[guard.case][0]
            _, signer_identity = read_file(directory, intent_signer.name, 65536)
            status = decode(record['status'])
            handoff = dict(sceneId=payload['closure']['payload']['sceneId'], nonce=nonce,
                           expiresAt=int(time.time()) + 45, request=asdict(request),
                           receiptDigest=digest(canonical(asdict(receipt))), firstBinding=status['activeBinding'],
                           parentTail=status['lineage'][0], firstWriteBindingDigest=digest(canonical(pins)),
                           writerStopObservationDigest=record['writer_stop'])
            certificate = issue(handoff, intent_signer, record['reader_seal'][4])
            if read_file(directory, intent_signer.name, 65536)[1] != signer_identity:
                reject()
            authenticate()
            handoff_digest = digest(canonical(handoff))
            return certificate

        def confirm_worker(handoff, nonce):
            from deployment_compose_scene_recovery_handoff_v3_host import issue
            from deployment_compose_scene_recovery_worker_v3_host import (
                INTENT_NAMESPACE, WITNESS_NAMESPACE, worker_statement)

            nonlocal worker_proof_digest
            GitHubSceneRecoveryApprovalV3.verify_consumption_receipt(approval, request, receipt)
            authenticate()
            guard = record['reader']()._reader._guard
            directory = guard.dirs[guard.case][0]
            _, signer_identity = read_file(directory, intent_signer.name, 65536)
            request_expiry = datetime.strptime(request.expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
            expiry = min(int(time.time()) + 20, int(approval._expires), int(request_expiry.timestamp()),
                         handoff['expiresAt'])
            if expiry <= time.time():
                reject()
            statement = worker_statement(handoff, nonce, expiry)
            proof = dict(intent=issue(statement, intent_signer, record['reader_seal'][4], namespace=INTENT_NAMESPACE),
                         witness=issue(statement, guard.case/'witness-signing', decode(record['descriptor'])['witnessKeyHash'],
                                       namespace=WITNESS_NAMESPACE))
            if read_file(directory, intent_signer.name, 65536)[1] != signer_identity:
                reject()
            authenticate()
            worker_proof_digest = digest(canonical(statement))
            return proof

        live, writer_stop, startup_digest, relay_digest = _observe_authenticated_scene(authenticate, decode(record['descriptor']),
            handle=handle, first_write=pins, make_handoff=make_handoff if intent_signer is not None else None,
            confirm_worker=confirm_worker if prepare_worker else None, launch_worker=launch_worker,
            relay_rpc=relay_rpc, stop_verifier=stop_verifier, through_delete=through_delete, full_recovery=full_recovery)
        if (live.phase_digest != pins['phaseDigest'] or live.endpoint_binding_digest != pins['endpointBindingDigest']
                or live.history_digest != request.history_hash or writer_stop != record['writer_stop']):
            reject()
        if stop_verifier is None:
            GitHubSceneRecoveryApprovalV3.verify_consumption_receipt(approval, request, receipt)
            authenticate()
            request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=1800)
        result = dict(requestDigest=request.digest(), firstBinding=decode(record['status'])['activeBinding'],
                    nextOperationDigest=pins['nextOperationDigest'], liveObservationDigest=digest(live.observation_bytes),
                    runtimePermit=False, authorityGranted=False, productionReady=False)
        if handoff_digest is not None:
            result['recoveryHandoffDigest'] = handoff_digest
        if worker_proof_digest is not None:
            result['workerProofDigest'] = worker_proof_digest
        if startup_digest is not None:
            result['workerStartupDigest'] = startup_digest
        if relay_digest is not None:
            result['workerRelayDigest'] = relay_digest
        if stop_verifier is not None:
            result['stopReceipt'] = stop_verifier()
        return result


def _authenticate_session(record):
    from deployment_compose_scene_checkpoint_v3_host import _READERS

    reader = record['reader']()
    if reader is None or _READERS.get(reader) is not record['reader_seal']:
        reject()
    native = reader._reader
    if _sealed_reader(native, expected_witness_state=record['state']) is not record['native_seal']:
        reject()
    if canonical(native._store.chain_status(decode(record['status'])['activeBinding'])) != record['status']:
        reject()
    _sealed_reader(native, expected_witness_state=record['state'])
    return decode(record['payload']), record['origin'], record['archive']


def _first_stop_rpc(record, host, intent_signer, signer_identity, *, through_delete=False, full_recovery=False):
    from deployment_compose_intent_status_v3 import issue_intent_status
    from deployment_compose_operation_witness_client_v3 import decode_material, dispatch_request, validate_request

    approval, request, receipt = record['consent']
    status = decode(record['status'])
    binding = status['activeBinding']
    scope = dict(binding=binding, descriptor=decode(record['scope']),
                 entry=dict(approval=approval, request=request, receiptHash=record['receipt_hash']))
    seen = set()
    blocked = False
    completed = {}
    continuation = decode(record['continuation'])
    steps = [dict(phase='stop', status=record['stop_status'])]
    if through_delete:
        steps.extend(continuation if full_recovery else continuation[:1])
    index = 0

    def acknowledge(payload, guard):
        nonlocal blocked
        value = payload['result']
        if value['lineage'] != status['lineage'] or value['binding'] != binding:
            reject()
        status.update(activeSeq=value['seq'], activeHead=value['head'], activePhase=value['phase'])
        record['status'] = canonical(status)
        _, record['state'] = read_file(guard.dirs[host._store.root][0], 'state.json',
                                       guard.files[(host._store.root, 'state.json')][0])
        _authenticate_session(record)
        envelope = host._sign(payload)
        _authenticate_session(record)
        blocked = False
        return envelope

    def authorize(service, method, rpc):
        nonlocal blocked, binding, scope, index
        if blocked or type(rpc) is not dict or len(seen) >= (256 if full_recovery else 128):
            reject()
        _authenticate_session(record)
        nonce = rpc.get('rpcNonce')
        if not hex_value(nonce) or nonce in seen:
            reject()
        seen.add(nonce)
        guard = record['reader']()._reader._guard
        if service == 'intent' and method == 'check':
            payload = issue_intent_status(approval, request, rpc, scene_recovery=True)
            directory = guard.dirs[guard.case][0]
            if read_file(directory, intent_signer.name, 65536)[1] != signer_identity:
                reject()
            envelope = host._sign(payload, intent=True)
            if read_file(directory, intent_signer.name, 65536)[1] != signer_identity:
                reject()
        else:
            methods = ('read', 'check', 'chain_status', 'events_after', 'append_event', 'transition_successor')
            if service != 'witness' or method not in methods:
                reject()
            validate_request(method, rpc)
            if rpc['binding'] != binding:
                reject()
            if method == 'transition_successor':
                if index + 1 >= len(steps):
                    reject()
                previous = verify_current(steps[index]['status'])
                following = steps[index+1]
                child = following['binding']
                if (rpc['childBinding'] != child or rpc['expectedSeq'] != 6
                        or rpc['expectedHead'] != previous['head']):
                    reject()
                GitHubSceneRecoveryApprovalV3.verify_consumption_receipt(approval, request, receipt)
                _authenticate_session(record)
                blocked = True
                payload = dispatch_request(host._store, method, rpc, expected_state_identity=record['state'][:2])
                status['lineage'].append(dict(binding=binding, seq=6, head=previous['head']))
                binding = child
                status['activeBinding'] = child
                scope = dict(binding=child, descriptor=following['scope'], entry=scope['entry'])
                completed[steps[index]['phase']] = canonical(previous)
                index += 1
                return acknowledge(payload, guard)
            if method == 'append_event':
                # An uncertain commit or signing failure burns this channel.
                blocked = True
                payload = host._append(rpc, scope, expected_state_identity=record['state'][:2])
                return acknowledge(payload, guard)
            envelope = host._sign(dispatch_request(host._store, method, rpc))
        _authenticate_session(record)
        return envelope

    def verify_current(expected_status):
        if blocked or status['activeSeq'] != 6 or status['activePhase'] != 'closed':
            reject()
        _authenticate_session(record)
        records = host._store.events_after(binding, seq=0, head=ZERO)
        if len(records) != 6 or records[-1]['head'] != status['activeHead']:
            reject()
        finish = host._unseal(decode(decode_material(records[3]['externalMaterialBase64'])), 'event')
        data = finish['data']
        if finish['kind'] != 'finish' or data['definitive'] is not True or data['status'] != expected_status:
            reject()
        _authenticate_session(record)
        return dict(binding=decode(canonical(binding)), head=status['activeHead'], status=data['status'])

    def verify_phase(phase):
        if phase in completed:
            _authenticate_session(record)
            return decode(completed[phase])
        if steps[index]['phase'] != phase:
            reject()
        return verify_current(steps[index]['status'])

    authorize.verify_stop = lambda: verify_phase('stop')
    authorize.verify_delete = lambda: verify_phase('delete')
    authorize.verify_rename = lambda: verify_phase('rename')
    authorize.verify_start = lambda: verify_phase('start')
    return authorize


def admit_scene_recovery(reader, *, snapshot, expected_draft_digest, handle,
                         expected_request_digest, request, context_bytes, approval, receipt):
    """Controller-only CAS after fresh scene checks and exact consumed approval."""
    from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3, _READERS

    if (type(reader) is not SceneCheckpointReaderV3 or type(request) is not RequestV2
            or request.profile_id != PROFILE or request.digest() != expected_request_digest
            or type(approval) is not GitHubSceneRecoveryApprovalV3):
        reject()
    GitHubSceneRecoveryApprovalV3.verify_consumption_receipt(approval, request, receipt)
    payload, origin, archive = SceneCheckpointReaderV3._authenticate(reader)
    reader_seal = _READERS[reader]
    native_reader = reader._reader
    store = native_reader._store
    pins = payload.get('witnessStore')
    if (pins is None or tuple(pins['directory']) != store._root_id
            or tuple(pins['lock']) != store._lock_id
            or tuple(pins['state']) != native_reader._guard.files[(store.root, 'state.json')][1][:2]):
        reject()
    review = verify_scene_recovery_intent(reader, snapshot=snapshot,
        expected_draft_digest=expected_draft_digest, handle=handle,
        expected_request_digest=expected_request_digest, request=request, context_bytes=context_bytes)
    if approval.policy.expected_scene_review_hash != digest(canonical(scene_recovery_public_review(review))):
        reject()

    checkpoint = reader.context
    history = checkpoint.history
    parent_snapshot = history.capture()
    prefix = _prefix(history, parent_snapshot)
    if parent_snapshot.digest != request.history_hash or parent_snapshot.canonical != checkpoint.snapshot.canonical:
        reject()
    tail = prefix['closedTail']
    receipts = prefix['receiptMap']
    bundle = history._bundle
    operation = bundle.resolve_operations(receipts)[1]
    if operation['phase'] != 'stop' or operation['requestDigest'] != review['nextOperationDigest']:
        reject()
    receipt_hash = digest(canonical(asdict(receipt)))
    scope = Profile3StepExecutor.scope_descriptor(bundle, request, receipt_hash, operation, 1, receipts)
    binding = dict(tail['binding'], generation=scope['generation'], scopeHash=scope['scopeHash'])
    remaining = bundle.resolve_operations(receipts)[2:]
    if [step['phase'] for step in remaining] != ['delete', 'rename', 'start', 'readiness']:
        reject()
    continuation = []
    for index, step in enumerate(remaining[:-1], start=2):
        descriptor = Profile3StepExecutor.scope_descriptor(bundle, request, receipt_hash, step, index, receipts)
        child = dict(tail['binding'], generation=descriptor['generation'], scopeHash=descriptor['scopeHash'])
        continuation.append(dict(phase=step['phase'], status=step['expectedStatus'], binding=child, scope=descriptor))
    check_witness_byte_capacity(bundle, request, history._policy, receipt_hash, binding, parent_snapshot)

    GitHubSceneRecoveryApprovalV3.verify_consumption_receipt(approval, request, receipt)
    if history.capture().canonical != parent_snapshot.canonical:
        reject()
    native_seal = _sealed_reader(native_reader)
    request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=1800)
    # The locked compare-and-swap is the only mutation. Competing successors
    # and ambiguous acknowledgements cannot open a second empty scope.
    result = store.transition_successor(tail['binding'], expected_seq=tail['seq'],
        expected_head=tail['head'], childBinding=binding, expected_state_identity=tuple(pins['state']))
    expected = dict(binding=binding, seq=0, head=ZERO, phase='empty', lineage=[tail],
                    active=True, authorityGranted=False, productionReady=False)
    if canonical(result) != canonical(expected):
        reject()
    guard = native_reader._guard
    _, new_state = read_file(guard.dirs[store.root][0], 'state.json', guard.files[(store.root, 'state.json')][0])
    status = dict(epoch=binding['epoch'], policyHash=binding['policyHash'], activeBinding=binding,
                  activeSeq=0, activeHead=ZERO, activePhase='empty', lineage=[tail],
                  authorityGranted=False, productionReady=False)
    descriptor = decode(reader_seal[2])
    descriptor['intentKeyHash'] = reader_seal[4]
    record = dict(reader=weakref.ref(reader), reader_seal=reader_seal, native_seal=native_seal,
                  state=new_state, status=canonical(status), descriptor=canonical(descriptor),
                  payload=canonical(payload), origin=origin, archive=archive, consent=(approval, request, receipt),
                  first_write=canonical(_first_write_pins(review)), writer_stop=review['writerStopObservationDigest'],
                  scope=canonical(scope), receipt_hash=receipt_hash, stop_status=operation['expectedStatus'],
                  continuation=canonical(continuation))
    _authenticate_session(record)
    session = SceneRecoverySessionV3()
    _SESSIONS[session] = record
    return dict(requestDigest=request.digest(), receiptDigest=receipt_hash, firstBinding=binding,
                parentTail=tail, startWriteIndex=1, nextOperationDigest=operation['requestDigest'],
                successorActivated=True, authorityGranted=False, runtimePermit=False, productionReady=False,
                session=session)
