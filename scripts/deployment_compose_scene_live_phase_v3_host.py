"""Authenticated scene issuer's live phase summary, never an execution context.

The service validates its original baseline with native endpoint pins and two
PhaseGuard scans. Without raw phase bytes this observation cannot construct the
existing recovery preparation context. No continuity or future fence is granted.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import secrets
import time

from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical, hex_value
from deployment_compose_scene_create_certificate_v3_host import CHALLENGE

_FALSE = {'phaseFreshnessVerified', 'daemonContinuityVerified', 'writerQuiescenceVerified',
          'authorityGranted', 'executionAvailable', 'runtimePermit', 'recoveryAuthorized',
          'productionReady', 'sourceRevalidated'}
_FIELDS = {'schemaVersion', 'kind', 'requestNonce', 'closure', 'phaseIndex', 'baselineDigest',
           'phaseDigest', 'endpointBinding', 'endpointBindingDigest', 'normalizationVersion', 'readOnly'} | _FALSE
_ENDPOINT = {'daemonBinding', 'pidNamespace', 'daemonPidNamespace', 'networkNamespace',
             'mountNamespace', 'normalizationVersion', 'rootIdentity', 'socketIdentity', 'pidFileIdentity'}


def reject():
    raise ValueError('compose-scene-live-phase-v3-rejected') from None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class SceneLivePhaseSummaryV3:
    observation_bytes: bytes = field(repr=False)
    scene_id: str
    history_digest: str
    baseline_digest: str
    phase_digest: str
    endpoint_binding_digest: str
    phaseApplicabilityVerified: bool = field(default=True, init=False)
    liveReadsVerified: bool = field(default=True, init=False)
    currentDaemonIdentityVerified: bool = field(default=True, init=False)
    rawPhaseAvailable: bool = field(default=False, init=False)
    phaseFreshnessVerified: bool = field(default=False, init=False)
    daemonContinuityVerified: bool = field(default=False, init=False)
    writerQuiescenceVerified: bool = field(default=False, init=False)
    sourceRevalidated: bool = field(default=False, init=False)
    authorityGranted: bool = field(default=False, init=False)
    executionAvailable: bool = field(default=False, init=False)
    runtimePermit: bool = field(default=False, init=False)
    recoveryAuthorized: bool = field(default=False, init=False)
    productionReady: bool = field(default=False, init=False)

    def public_summary(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if name != 'observation_bytes'}


def _status(client, payload, descriptor):
    from deployment_compose_scene_control_ssh_v3_host import _issued_scene_ssh_client
    _issued_scene_ssh_client(client)
    status = client.status(); business = status['business']; closure = payload['closure']['payload']
    if (status['sceneId'] != closure['sceneId'] or status['slotState'] != 'drained'
            or type(status['slotGeneration']) is not int
            or status['slotGeneration'] != closure['slotGeneration']
            or status['preparation']['preparationId'] != closure['preparationId']
            or status['preparation']['capsuleDigest'] != closure['capsuleDigest']
            or business['businessState'] != 'reconciled' or business['closureReconciled'] is not True
            or canonical(business['closureChallenge']) != canonical({key: closure[key] for key in CHALLENGE})
            or business['witnessKeyHash'] != descriptor['witnessKeyHash']
            or business['intentKeyHash'] != descriptor['intentKeyHash']
            or canonical(status['daemonBinding']) != canonical(payload['evidence']['daemonBinding'])
            or canonical(business['checkpointEvidence']) != canonical(payload['evidence'])):
        reject()


def _validate_observation(value, nonce, payload, origin):
    context = payload['context']; closure = payload['closure']['payload']
    if (type(value) is not dict or set(value) != _FIELDS
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['kind'] != 'scene-live-phase-summary-v3' or value['requestNonce'] != nonce
            or type(value['phaseIndex']) is not int or value['phaseIndex'] != 1
            or canonical(value['closure']) != canonical(closure)
            or value['baselineDigest'] != context['baselineStateDigest'] or value['readOnly'] is not True
            or any(value[key] is not False for key in _FALSE)
            or any(not hex_value(value[key]) for key in ('phaseDigest', 'endpointBindingDigest'))):
        reject()
    endpoint = value['endpointBinding']; version = value['normalizationVersion']
    if (type(endpoint) is not dict or set(endpoint) != _ENDPOINT
            or canonical(endpoint['daemonBinding']) != canonical(payload['evidence']['daemonBinding'])
            or digest(canonical(endpoint)) != value['endpointBindingDigest']
            or type(version) is not dict or set(version) != {'Version', 'GitCommit'}
            or any(type(v) is not str or not v for v in version.values())
            or canonical(endpoint['normalizationVersion']) != canonical(version)
            or canonical(endpoint['pidNamespace']) != canonical([decode(origin)['pidNamespaceDevice'], decode(origin)['pidNamespaceInode']])
            or canonical(endpoint['pidNamespace']) != canonical(endpoint['daemonPidNamespace'])):
        reject()


def observe_scene_live_phase(reader, *, handle):
    summary, _ = _observe_scene_live_phase(reader, handle=handle)
    return summary


def _observe_scene_live_phase(reader, *, handle, first_write=None):
    from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3, _READERS

    # Preserve the original historical reader identity across the relay.
    seal = _READERS.get(reader)
    if seal is None:
        reject()
    descriptor = decode(seal[2]); descriptor['intentKeyHash'] = seal[4]

    def authenticate():
        value = SceneCheckpointReaderV3._authenticate(reader)
        if _READERS.get(reader) is not seal:
            reject()
        return value

    summary, stopped, _, _ = _observe_authenticated_scene(authenticate, descriptor, handle=handle, first_write=first_write)
    return summary, stopped


def _observe_authenticated_scene(authenticate, descriptor, *, handle, first_write=None,
                                 make_handoff=None, confirm_worker=None, launch_worker=False, relay_rpc=None,
                                 stop_verifier=None, through_delete=False, full_recovery=False):
    from deployment_compose_scene_control_ssh_v3_host import (
        SceneSSHClientV3, SceneSSHHandleV3, _issued_scene_ssh_client)
    from deployment_compose_scene_service_v3_host import SceneClientV3
    payload, origin, archive = authenticate()
    context = payload['context']; closure = payload['closure']['payload']
    if (type(handle) is not SceneSSHHandleV3 or handle.sceneId != closure['sceneId']
            or handle.hostAlias != context['hostId'] or handle.sourceSha != context['sourceSha']
            or handle.archiveBytes != archive):
        reject()
    client = SceneSSHClientV3(handle)
    try:
        _status(client, payload, descriptor)
        nonce = secrets.token_hex(32)
        writer_stop_digest = None
        startup_digest = None
        relay_digest = None
        if first_write is not None:
            handoff = make_handoff(nonce) if make_handoff is not None else None
            if handoff is not None:
                _status(client, payload, descriptor)
            reply = SceneClientV3.observe_stopped_writer_phase(client, nonce, first_write,
                recovery_handoff=handoff)['writerPhaseObservation']
            fields = {'phaseObservation', 'writerOriginDigest', 'writerStopObservationDigest', 'firstWriteBindingDigest'}
            if handoff is not None:
                fields.update(('recoveryHandoffDigest', 'recoveryWorkerNonce'))
            if (type(reply) is not dict
                    or set(reply) != fields
                    or reply['writerOriginDigest'] != digest(origin)
                    or reply['firstWriteBindingDigest'] != digest(canonical(first_write))
                    or (handoff is not None and (reply['recoveryHandoffDigest'] != digest(canonical(handoff['payload']))
                                                or not hex_value(reply['recoveryWorkerNonce'])))
                    or not hex_value(reply['writerStopObservationDigest'])):
                reject()
            writer_stop_digest = reply['writerStopObservationDigest']
        else:
            reply = SceneClientV3.observe_closed_phase(client, nonce)
        value = reply['phaseObservation']
        _validate_observation(value, nonce, payload, origin)
        _issued_scene_ssh_client(client)
        if confirm_worker is not None:
            if handoff is None or value['phaseDigest'] != first_write['phaseDigest'] or (
                    value['endpointBindingDigest'] != first_write['endpointBindingDigest']
                    or writer_stop_digest != handoff['payload']['writerStopObservationDigest']):
                reject()
            proof = confirm_worker(handoff['payload'], reply['recoveryWorkerNonce'])
            _status(client, payload, descriptor)
            confirmation = SceneClientV3.confirm_recovery_worker(client, proof, launch=launch_worker,
                relay=relay_rpc is not None and stop_verifier is None, execute=stop_verifier is not None,
                through_delete=through_delete, full_recovery=full_recovery)['workerConfirmation']
            expected = dict(workerProofDigest=digest(canonical(proof['intent']['payload'])),
                            recoveryHandoffDigest=reply['recoveryHandoffDigest'])
            if launch_worker:
                startup_digest = confirmation.get('workerStartupDigest')
                if not hex_value(startup_digest):
                    reject()
                expected['workerStartupDigest'] = startup_digest
            if relay_rpc is not None:
                relay = confirmation.get('workerRelay')
                if (type(relay) is not dict or set(relay) != {'attemptId', 'channelNonce'}
                        or any(not hex_value(pin) for pin in relay.values())):
                    reject()
                expected['workerRelay'] = relay
            if canonical(confirmation) != canonical(expected):
                reject()
            _issued_scene_ssh_client(client)
            if relay_rpc is not None:
                relay_digest = _drive_recovery_relay(client, relay, proof, expected['workerProofDigest'], relay_rpc,
                    stop_verifier=stop_verifier, through_delete=through_delete, full_recovery=full_recovery)
        # Close and verify the owned relay before doing expensive local signing
        # and history checks, so no idle scene lease is assumed to survive them.
        SceneSSHClientV3.detach(client)
    finally:
        import sys
        from deployment_compose_restart_checkpoint_v3_host import note_cleanup
        primary = sys.exc_info()[1]
        try:
            SceneSSHClientV3.close(client)
        except BaseException:
            if primary is None: raise
            note_cleanup(primary)
    if stop_verifier is None:
        if authenticate() != (payload, origin, archive):
            reject()
    else:
        stop_verifier()
    summary = SceneLivePhaseSummaryV3(canonical(value), closure['sceneId'], context['historyDigest'],
        context['baselineStateDigest'], value['phaseDigest'], value['endpointBindingDigest'])
    return summary, writer_stop_digest, startup_digest, relay_digest


def _drive_recovery_relay(client, relay, proof, proof_digest, authorize, *, stop_verifier=None,
                          through_delete=False, full_recovery=False):
    from deployment_compose_scene_control_ssh_v3_host import _issued_scene_ssh_client
    from deployment_compose_scene_recovery_worker_v3_host import relay_terminal, stop_terminal
    from deployment_compose_scene_service_v3_host import SceneClientV3

    attempt, nonce = relay['attemptId'], relay['channelNonce']
    expected_terminal = digest(canonical(relay_terminal(nonce, proof_digest)))
    expiry = proof['intent']['payload']['expiresAt']
    started = time.monotonic()
    deadline = started + expiry - time.time()
    if stop_verifier is not None:
        deadline = started + (180 if full_recovery else 150 if through_delete else 90)
    exchanges = (('intent', 'check'), ('witness', 'check'))
    allowed = {'intent': {'check'}, 'witness': {'read', 'check', 'chain_status', 'events_after', 'append_event'}}
    if through_delete:
        allowed['witness'].add('transition_successor')
    message_limit = 4*1024*1024 if stop_verifier is not None else 8192
    next_rpc = 0
    authorization_seconds = {'intent': 0.0, 'witness': 0.0}

    def check_deadline(stage):
        now = time.monotonic()
        if now >= deadline:
            elapsed = now - started
            intent = authorization_seconds['intent']
            witness = authorization_seconds['witness']
            other = max(0.0, elapsed - intent - witness)
            raise ValueError(
                f'compose-scene-live-phase-v3-rejected: relay deadline at {stage} '
                f'after {next_rpc} completed RPCs '
                f'(elapsed={elapsed:.3f}s, intent={intent:.3f}s, '
                f'witness={witness:.3f}s, other={other:.3f}s)'
            ) from None

    while True:
        check_deadline('worker poll')
        _issued_scene_ssh_client(client)
        state = SceneClientV3.poll_worker(client)['business']
        if state['attemptId'] != attempt or state['pendingNonce'] != nonce:
            reject()
        phase = state['businessState']
        if phase in ('failed', 'frozen'):
            reject()
        if phase == 'transport-exited':
            if stop_verifier is not None:
                receipt = stop_verifier()
                head_key = 'startHead' if full_recovery else 'deleteHead' if through_delete else 'stopHead'
                terminal_digest = state.get('terminalPhaseDigest') if full_recovery else None
                if state.get(head_key) != receipt['head'] or (full_recovery and not hex_value(terminal_digest)):
                    reject()
                expected_terminal = digest(canonical(stop_terminal(nonce, proof_digest, receipt['head'], receipt['status'],
                    through_delete=through_delete, terminal_digest=terminal_digest)))
            elif next_rpc != len(exchanges):
                reject()
            if state.get('relayDigest') != expected_terminal:
                reject()
            closed = SceneClientV3.finish_worker(client, attempt)['business']
            if (closed['businessState'] != 'closed' or closed['attemptId'] != attempt
                    or closed['pendingNonce'] != nonce):
                reject()
            return expected_terminal
        message = state.get('message')
        if message is None:
            time.sleep(.01)
            continue
        size = message['totalBytes']
        pair = (message['service'], message['method'])
        if stop_verifier is None:
            valid_rpc = next_rpc < len(exchanges) and pair == exchanges[next_rpc]
        else:
            valid_rpc = next_rpc < (256 if full_recovery else 128) and pair[1] in allowed.get(pair[0], set())
        if (not valid_rpc
                or message['attemptId'] != attempt or type(message['rpcId']) is not int
                or message['rpcId'] != next_rpc+1 or type(size) is not int or not 0 < size <= message_limit
                or not hex_value(message['messageDigest'])):
            reject()
        raw = bytearray()
        while len(raw) < size:
            check_deadline('request read')
            chunk = SceneClientV3.read_worker_chunk(client, attempt, message['messageDigest'], len(raw), 4096)['business']
            data = base64.b64decode(chunk['dataBase64'], validate=True)
            if (chunk['attemptId'] != attempt or chunk['messageDigest'] != message['messageDigest']
                    or type(chunk['totalBytes']) is not int or chunk['totalBytes'] != size
                    or type(chunk['offset']) is not int or chunk['offset'] != len(raw)
                    or not 0 < len(data) <= min(4096, size-len(raw))):
                reject()
            raw.extend(data)
        frame = decode(bytes(raw))
        if (digest(raw) != message['messageDigest'] or type(frame) is not dict
                or set(frame) != {'kind', 'channelNonce', 'rpcId', 'service', 'method', 'request'}
                or frame['kind'] != 'rpc' or frame['channelNonce'] != nonce or type(frame['rpcId']) is not int
                or frame['rpcId'] != next_rpc+1 or (frame['service'], frame['method']) != pair):
            reject()
        _issued_scene_ssh_client(client)
        authorization_started = time.monotonic()
        response = authorize(frame['service'], frame['method'], frame['request'])
        authorization_seconds[pair[0]] += time.monotonic() - authorization_started
        reply = canonical(dict(kind='reply', channelNonce=nonce, rpcId=frame['rpcId'], response=response))
        check_deadline(f'reply preparation for {pair[0]}.{pair[1]}')
        if len(reply) > message_limit:
            raise ValueError(
                f'compose-scene-live-phase-v3-rejected: relay reply exceeds {message_limit} bytes'
            ) from None
        SceneClientV3.begin_worker_reply(client, attempt, len(reply), digest(reply), frame['rpcId'])
        for offset in range(0, len(reply), 4096):
            check_deadline(f'reply transfer for {pair[0]}.{pair[1]}')
            SceneClientV3.worker_reply_chunk(client, attempt, offset, base64.b64encode(reply[offset:offset+4096]).decode('ascii'))
        SceneClientV3.commit_worker_reply(client, attempt)
        next_rpc += 1
