"""Bounded full phase downloads as sealed historical observations, never permits.

The download deadline is an acceptance budget. Existing individual SSH waits,
source/Git checks, filesystem/crypto/flock and cleanup retain their own limits.
"""
import base64
from dataclasses import dataclass, field
import hashlib
import math
import os
import secrets
import sys
import threading
import time
import weakref

from deployment_compose_scene_live_phase_v3_host import _status, _validate_observation
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical, hex_value

MAX_PHASE = 4 * 1024 * 1024
CHUNK = 4096
_SNAPSHOTS = weakref.WeakKeyDictionary()


def reject():
    raise ValueError('compose-scene-phase-snapshot-v3-rejected') from None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, eq=False)
class ScenePhaseSnapshotV3:
    phase_bytes: bytes = field(repr=False)
    descriptor_bytes: bytes = field(repr=False)
    material_digest: str
    scene_binding_digest: str
    scene_id: str
    snapshot_id: str
    history_digest: str
    baseline_digest: str
    phase_digest: str
    endpoint_binding_digest: str
    rawPhaseAvailable: bool = field(default=True, init=False)
    historicalSnapshotVerified: bool = field(default=True, init=False)
    phaseFreshnessVerified: bool = field(default=False, init=False)
    daemonContinuityVerified: bool = field(default=False, init=False)
    writerQuiescenceVerified: bool = field(default=False, init=False)
    authorityGranted: bool = field(default=False, init=False)
    executionAvailable: bool = field(default=False, init=False)
    runtimePermit: bool = field(default=False, init=False)
    recoveryAuthorized: bool = field(default=False, init=False)
    productionReady: bool = field(default=False, init=False)

    def __copy__(self): reject()
    def __deepcopy__(self, memo): reject()
    def __reduce_ex__(self, protocol): reject()

    def public_summary(self):
        _snapshot_record(self)
        return {name: getattr(self, name) for name in self.__dataclass_fields__
                if name not in ('phase_bytes', 'descriptor_bytes')}


def _fingerprint(value):
    return tuple((type(getattr(value, key)), getattr(value, key))
                 for key in ScenePhaseSnapshotV3.__dataclass_fields__)


def _snapshot_record(value, reader=None):
    from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3, _READERS
    if type(value) is not ScenePhaseSnapshotV3: reject()
    seal = _SNAPSHOTS.get(value)
    if (seal is None or seal[0] != (os.getpid(), threading.get_ident())
            or _fingerprint(value) != seal[3]):
        reject()
    original = seal[1]()
    if original is None or reader is not None and original is not reader: reject()
    if _READERS.get(original) is not seal[2]: reject()
    SceneCheckpointReaderV3._authenticate(original)
    return seal


def validate_scene_phase_snapshot(value, *, reader):
    """For future draft-only consumers; reauthenticate the original issuer seal."""
    _snapshot_record(value, reader)
    return value.phase_bytes, value.descriptor_bytes


def _phase_shape(raw, bundle, baseline, payload):
    value = decode(raw)
    if (canonical(value) != raw or type(value) is not dict or set(value) != {'rows', 'resources'}
            or type(value['rows']) is not dict or type(value['resources']) is not dict): reject()
    expected = {row['containerId'] for row in bundle['protectedContainers']}
    expected.update(row['baselineContainerId'] for row in bundle['services'])
    expected.update(payload['closure']['payload']['receiptMap'].values())
    if set(value['rows']) != expected: reject()
    for cid, row in value['rows'].items():
        if (type(row) is not dict or row.get('Id') != cid
                or row.get('Config', {}).get('Labels', {}).get('com.docker.compose.project') != bundle['identity']['project']):
            reject()
    resources = {'network:' + name for name in bundle['networks']}
    resources.update('volume:' + mount['Name'] for row in baseline.values()
                     for mount in row['Mounts'] if mount['Type'] == 'volume')
    if set(value['resources']) != resources: reject()


def capture_scene_phase_snapshot(reader, *, handle, download_timeout=120):
    from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3, _READERS
    from deployment_compose_scene_control_ssh_v3_host import (
        SceneSSHClientV3, SceneSSHHandleV3, _issued_scene_ssh_client)
    from deployment_compose_scene_service_v3_host import SceneClientV3
    from deployment_compose_restart_checkpoint_v3_host import note_cleanup
    if (type(download_timeout) not in (int, float) or not math.isfinite(download_timeout)
            or not 0 < download_timeout <= 120): reject()
    payload, origin, archive = SceneCheckpointReaderV3._authenticate(reader)
    seal = _READERS[reader]; descriptor = decode(seal[2]); descriptor['intentKeyHash'] = seal[4]
    context = payload['context']; closure = payload['closure']['payload']
    authenticated = reader.context
    bundle = authenticated.history._bundle.to_dict()
    baseline = decode(authenticated.baseline_bytes)
    if (type(handle) is not SceneSSHHandleV3 or handle.sceneId != closure['sceneId']
            or handle.hostAlias != context['hostId'] or handle.sourceSha != context['sourceSha']
            or handle.archiveBytes != archive): reject()
    client = SceneSSHClientV3(handle)
    end = time.monotonic() + download_timeout
    def within():
        if time.monotonic() >= end: reject()
    heartbeat_due = 0
    def heartbeat():
        nonlocal heartbeat_due
        within()
        if time.monotonic() >= heartbeat_due:
            started = time.monotonic()
            _status(client, payload, descriptor)
            heartbeat_due = started + 10
            within()
    try:
        heartbeat()
        nonce = secrets.token_hex(32)
        reply = SceneClientV3.capture_closed_phase_snapshot(client, nonce)
        within()
        snapshot = reply['phaseSnapshot']
        if (type(snapshot) is not dict or set(snapshot) != {'observation', 'snapshotId', 'totalBytes', 'chunkBytes'}
                or not hex_value(snapshot['snapshotId']) or type(snapshot['totalBytes']) is not int
                or not 0 < snapshot['totalBytes'] <= MAX_PHASE
                or type(snapshot['chunkBytes']) is not int or snapshot['chunkBytes'] != CHUNK): reject()
        observation = snapshot['observation']
        _validate_observation(observation, nonce, payload, origin)
        raw = bytearray()
        while len(raw) < snapshot['totalBytes']:
            heartbeat()
            offset = len(raw); length = min(CHUNK, snapshot['totalBytes'] - offset)
            reply = SceneClientV3.read_closed_phase_chunk(client, snapshot['snapshotId'],
                observation['phaseDigest'], offset, length)
            within(); chunk = reply['phaseChunk']
            if (type(chunk) is not dict or set(chunk) != {'snapshotId', 'phaseDigest', 'totalBytes', 'offset', 'dataBase64'}
                    or chunk['snapshotId'] != snapshot['snapshotId'] or chunk['phaseDigest'] != observation['phaseDigest']
                    or type(chunk['totalBytes']) is not int or chunk['totalBytes'] != snapshot['totalBytes']
                    or type(chunk['offset']) is not int or chunk['offset'] != offset
                    or type(chunk['dataBase64']) is not str): reject()
            decoded = base64.b64decode(chunk['dataBase64'], validate=True)
            if len(decoded) != length or base64.b64encode(decoded).decode('ascii') != chunk['dataBase64']: reject()
            raw.extend(decoded)
        raw = bytes(raw)
        if digest(raw) != observation['phaseDigest']: reject()
        _phase_shape(raw, bundle, baseline, payload); within()
        _issued_scene_ssh_client(client)
        SceneSSHClientV3.detach(client)
        within()
    finally:
        primary = sys.exc_info()[1]
        try: SceneSSHClientV3.close(client)
        except BaseException:
            if primary is None: raise
            note_cleanup(primary)
    if (SceneCheckpointReaderV3._authenticate(reader) != (payload, origin, archive)
            or _READERS.get(reader) is not seal): reject()
    within()
    value = ScenePhaseSnapshotV3(raw, canonical(snapshot), payload['materialDigest'], seal[3],
        closure['sceneId'], snapshot['snapshotId'], context['historyDigest'], context['baselineStateDigest'],
        observation['phaseDigest'], observation['endpointBindingDigest'])
    _SNAPSHOTS[value] = ((os.getpid(), threading.get_ident()), weakref.ref(reader), seal, _fingerprint(value))
    return value
