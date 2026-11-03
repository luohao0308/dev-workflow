"""Authenticated scene issuer's live phase summary, never an execution context.

The service validates its original baseline with native endpoint pins and two
PhaseGuard scans. Without raw phase bytes this observation cannot construct the
existing recovery preparation context. No continuity or future fence is granted.
"""
from dataclasses import dataclass, field
import hashlib
import secrets

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


def observe_scene_live_phase(reader, *, handle):
    from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3, _READERS
    from deployment_compose_scene_control_ssh_v3_host import (
        SceneSSHClientV3, SceneSSHHandleV3, _issued_scene_ssh_client)
    from deployment_compose_scene_service_v3_host import SceneClientV3
    payload, origin, archive = SceneCheckpointReaderV3._authenticate(reader)
    seal = _READERS[reader]; descriptor = decode(seal[2]); descriptor['intentKeyHash'] = seal[4]
    context = payload['context']; closure = payload['closure']['payload']
    if (type(handle) is not SceneSSHHandleV3 or handle.sceneId != closure['sceneId']
            or handle.hostAlias != context['hostId'] or handle.sourceSha != context['sourceSha']
            or handle.archiveBytes != archive):
        reject()
    client = SceneSSHClientV3(handle)
    try:
        _status(client, payload, descriptor)
        nonce = secrets.token_hex(32)
        reply = SceneClientV3.observe_closed_phase(client, nonce)
        value = reply['phaseObservation']
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
        _issued_scene_ssh_client(client)
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
    if (SceneCheckpointReaderV3._authenticate(reader) != (payload, origin, archive)
            or _READERS.get(reader) is not seal):
        reject()
    return SceneLivePhaseSummaryV3(canonical(value), closure['sceneId'], context['historyDigest'],
        context['baselineStateDigest'], value['phaseDigest'], value['endpointBindingDigest'])
