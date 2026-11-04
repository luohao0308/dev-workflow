"""Scene-bound historical writer and source custody, never recovery permission.

The original controller captures authenticated broker facts. Separate external
artifact and intent-key pins bind cold readers; an adjacent public key or JSON
record cannot establish trust. Linux freshness and writer fencing remain separate.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import weakref

from deployment_compose_checkpoint_source_v3_host import _verify_archive, VerifiedCheckpointPublishedSourceV3
from deployment_compose_cold_writer_v3_host import validate_origin
from deployment_compose_restart_checkpoint_v3_host import (
    RestartCheckpointReaderV3, _Guard, _sealed_reader, publish, read_file, note_cleanup)
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_scene_create_certificate_v3_host import verify_create_closure
from deployment_compose_witness_store import canonical, hex_value
from deployment_gate_witness import key_material

NAMESPACE = 'dev-workflow-scene-checkpoint-v3'
PRINCIPAL = 'scene-checkpoint-v3'
MAX_BINDING = 32768
MAX_ARCHIVE = 2 * 1024 * 1024
_CAPTURES = weakref.WeakKeyDictionary()
_READERS = weakref.WeakKeyDictionary()
_BASE = {'casePath', 'materialDigest', 'custodyDigest', 'context', 'witnessKeyHash'}
_PAYLOAD = {'schemaVersion', 'kind', 'materialDigest', 'custodyDigest', 'witnessKeyHash',
            'context', 'hello', 'closure', 'evidence', 'sourceManifestDigest'}
_DAEMON = {'root', 'daemonId', 'unit', 'kernelBoot', 'invocationId', 'cgroupDevice',
           'cgroupInode', 'mainPid', 'mainStartTicks', 'daemonPid', 'daemonStartTicks'}


def reject():
    raise ValueError('compose-scene-checkpoint-v3-rejected') from None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _source(controller):
    from deployment_compose_scene_control_ssh_v3_host import (
        SceneSSHClientV3, SceneSSHHandleV3, _issued_scene_ssh_client)
    from deployment_compose_scene_create_controller_v3_host import SceneCreateControllerV3
    if type(controller) is not SceneCreateControllerV3:
        reject()
    SceneCreateControllerV3._owned(controller)
    handle = controller._handle
    if (controller._client_type is not SceneSSHClientV3 or type(handle) is not SceneSSHHandleV3
            or handle.sourceSha != controller._hello['sourceSha']
            or handle.hostAlias != controller._hello['hostId']
            or type(handle.archiveBytes) is not bytes or not 0 < len(handle.archiveBytes) <= MAX_ARCHIVE
            or digest(handle.archiveBytes) != controller._hello['archiveDigest']):
        reject()
    _issued_scene_ssh_client(controller._client)
    return handle.archiveBytes


def validate_scene_checkpoint_source(controller):
    """Before dispatch, compare the original handle archive to pinned Git bytes."""
    import deployment_compose_profile3_prepare_ssh_probe as source
    raw = _source(controller)
    return _verify_archive(raw, repository=source.ROOT, source_sha=controller._hello['sourceSha'],
                           archive_digest=controller._hello['archiveDigest'], timeout=30)


def _evidence(value, hello, context):
    if (type(value) is not dict or set(value) != {'writerOrigin', 'stopObservationDigest', 'daemonBinding'}
            or not hex_value(value['stopObservationDigest'])):
        reject()
    origin = validate_origin(canonical(value['writerOrigin']))
    daemon = value['daemonBinding']
    if (type(daemon) is not dict or set(daemon) != _DAEMON
            or type(hello) is not dict or hello.get('sourceSha') != context['sourceSha']
            or hello.get('archiveDigest') != context['archiveDigest']
            or hello.get('hostId') != context['hostId'] or hello.get('daemonId') != context['daemonId']
            or daemon['root'] != hello.get('root') or daemon['daemonId'] != context['daemonId']
            or type(daemon['root']) is not str or re.fullmatch('/var/tmp/dw-engine-[0-9a-f]{16}', daemon['root']) is None
            or daemon['unit'] != Path(daemon['root']).name + '.service'
            or daemon['kernelBoot'] != origin['kernelBoot']
            or type(daemon['invocationId']) is not str or re.fullmatch('[0-9a-f]{32}', daemon['invocationId']) is None
            or origin['sourceSha'] != context['sourceSha'] or origin['archiveDigest'] != context['archiveDigest']):
        reject()
    for name in _DAEMON - {'root', 'daemonId', 'unit', 'kernelBoot', 'invocationId'}:
        if (type(daemon[name]) is not int or not 0 <= daemon[name] < 2**64
                or name != 'cgroupDevice' and daemon[name] == 0):
            reject()
    if any(daemon[name] >= 2**31 for name in ('mainPid', 'daemonPid')):
        reject()
    return canonical(origin)


class _SceneCapture:
    pass


def capture_scene_checkpoint(controller, certificate, final):
    """Capture original authenticated facts; no caller-supplied evidence API."""
    try:
        raw = _source(controller)
        admission = controller._admission
        entry = admission._root
        if entry is None or admission._current is not entry or admission._pending is not None:
            reject()
        snapshot = admission._history(entry).capture()
        from deployment_compose_scene_create_controller_v3_host import SceneCreateControllerV3
        current = SceneCreateControllerV3._status(controller)['business']
        if (canonical(current) != canonical(final) or current['businessState'] != 'reconciled'
                or current.get('closureReconciled') is not True
                or certificate['payload']['historyDigest'] != snapshot.digest
                or canonical(certificate['payload']['receiptMap']) != canonical(dict(snapshot.snapshot['receiptMap']))
                or any(certificate['payload'][key] != current['closureChallenge'][key]
                       for key in current['closureChallenge'])):
            reject()
        verify_create_closure(certificate, public_key=admission._public[1], expected=certificate['payload'])
        hello = decode(canonical(controller._hello))
        context = dict(sourceSha=hello['sourceSha'], archiveDigest=hello['archiveDigest'],
                       hostId=hello['hostId'], daemonId=hello['daemonId'], historyDigest=snapshot.digest,
                       baselineStateDigest=entry['bundle'].to_dict()['baselineStateDigest'])
        evidence = decode(canonical(current['checkpointEvidence']))
        origin = _evidence(evidence, hello, context)
        # controller._boot pins the TLS gateway instance, not the Linux boot.
        # _evidence independently binds the writer and daemon kernel identities.
        if digest(canonical(hello)) != admission._policy.scope_hash:
            reject()
        SceneCreateControllerV3._owned(controller)
        if canonical(SceneCreateControllerV3._status(controller)['business']) != canonical(current):
            reject()
        result = _SceneCapture()
        _CAPTURES[result] = dict(owner=(os.getpid(), threading.get_ident()), controller=weakref.ref(controller),
            admission=id(admission), entry=id(entry), snapshot=snapshot.canonical, raw=raw,
            context=canonical(context), hello=canonical(hello), closure=canonical(certificate),
            evidence=canonical(evidence), final=canonical(current), attempted=False)
        return result
    except Exception:
        reject()


def _capture(token):
    record = _CAPTURES.get(token)
    if type(token) is not _SceneCapture or record is None or record['owner'] != (os.getpid(), threading.get_ident()):
        reject()
    controller = record['controller']()
    if controller is None or _source(controller) != record['raw']:
        reject()
    admission = controller._admission
    entry = admission._root
    if (id(admission) != record['admission'] or id(entry) != record['entry']
            or admission._current is not entry or admission._pending is not None
            or canonical(controller._hello) != record['hello']
            or admission._history(entry).capture().canonical != record['snapshot']):
        reject()
    return record, controller, admission


def _verify_signature(artifact, expected_key_hash):
    if type(artifact) is not dict or set(artifact) != {'payload', 'intentPublicKey', 'signature'}:
        reject()
    payload = artifact['payload']
    if (type(payload) is not dict or set(payload) != _PAYLOAD
            or type(payload['schemaVersion']) is not int or payload['schemaVersion'] != 1
            or payload['kind'] != 'compose-scene-checkpoint-binding-v3'
            or any(not hex_value(payload[k]) for k in
                   ('materialDigest', 'custodyDigest', 'witnessKeyHash', 'sourceManifestDigest'))
            or type(artifact['intentPublicKey']) is not str or type(artifact['signature']) is not str
            or len(artifact['intentPublicKey']) > 4096 or len(artifact['signature']) > 8192):
        reject()
    public = key_material(base64.b64decode(artifact['intentPublicKey'], validate=True))
    if digest(public) != expected_key_hash:
        reject()
    signature = base64.b64decode(artifact['signature'], validate=True)
    if not 0 < len(signature) <= 4096:
        reject()
    with tempfile.TemporaryDirectory(prefix='scene-checkpoint-verify-') as temporary:
        root = Path(temporary)
        signers, sig = root / 'signers', root / 'signature'
        signers.write_bytes(PRINCIPAL.encode() + b' ' + public + b'\n'); signers.chmod(0o600)
        sig.write_bytes(signature); sig.chmod(0o600)
        result = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(signers),
            '-I', PRINCIPAL, '-n', NAMESPACE, '-s', str(sig)], input=canonical(payload),
            capture_output=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
        if result.returncode:
            reject()
    return payload, public


def retain_scene_checkpoint(token, descriptor):
    """Publish once from a sealed controller capture, while its lease is detached."""
    guard = None
    try:
        record, controller, admission = _capture(token)
        if record['attempted']:
            reject()
        record['attempted'] = True
        descriptor = decode(canonical(descriptor))
        case = admission._store.root.parent
        if (type(descriptor) is not dict or set(descriptor) != _BASE or descriptor['casePath'] != str(case)
                or canonical(descriptor['context']) != record['context']
                or descriptor['witnessKeyHash'] != digest(admission._public[0])):
            reject()
        manifest = validate_scene_checkpoint_source(controller)
        with _open_material(case, descriptor) as reader:
            if reader.context.snapshot.canonical != record['snapshot']:
                reject()
        payload = dict(schemaVersion=1, kind='compose-scene-checkpoint-binding-v3',
            **{k: descriptor[k] for k in ('materialDigest', 'custodyDigest', 'witnessKeyHash', 'context')},
            hello=decode(record['hello']), closure=decode(record['closure']),
            evidence=decode(record['evidence']), sourceManifestDigest=digest(manifest))
        _capture(token)
        guard = _Guard(case)
        signer = admission._signers[1]
        if signer.parent != case:
            reject()
        guard.add_file(case, signer.name, 65536)
        public = subprocess.run(['/usr/bin/ssh-keygen', '-y', '-f', str(signer)], capture_output=True,
            check=True, timeout=10, env={'PATH': '/usr/bin:/bin'}).stdout
        if key_material(public) != admission._public[1]:
            reject()
        guard.check()
        signed = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(signer), '-n', NAMESPACE],
            input=canonical(payload), capture_output=True, check=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
        guard.check(); _capture(token)
        artifact = canonical(dict(payload=payload, intentPublicKey=base64.b64encode(admission._public[1]).decode('ascii'),
                                  signature=base64.b64encode(signed.stdout).decode('ascii')))
        if not 0 < len(artifact) <= MAX_BINDING:
            reject()
        _verify_signature(decode(artifact), digest(admission._public[1]))
        os.mkdir('scene-checkpoint', 0o700, dir_fd=guard.dirs[case][0]); os.fsync(guard.dirs[case][0])
        guard.add_dir(case / 'scene-checkpoint')
        fd = guard.dirs[case / 'scene-checkpoint'][0]
        publish(fd, 'binding.private.json', artifact)
        publish(fd, 'archive.private.zip', record['raw'])
        guard.close(); guard = None
        result = dict(descriptor, sceneBindingDigest=digest(artifact), intentKeyHash=digest(admission._public[1]))
        with SceneCheckpointReaderV3(case, **_arguments(result)) as reader:
            if reader.read_source_archive() != record['raw']:
                reject()
        _capture(token)
        return result
    except Exception:
        reject()
    finally:
        if guard is not None:
            primary = sys.exc_info()[1]
            try:
                guard.close()
            except Exception:
                if primary is None:
                    reject()
                note_cleanup(primary)


def _arguments(descriptor):
    return dict(expected_material_digest=descriptor['materialDigest'], expected_custody_digest=descriptor['custodyDigest'],
        expected_context=descriptor['context'], expected_witness_key_hash=descriptor['witnessKeyHash'],
        expected_scene_binding_digest=descriptor['sceneBindingDigest'], expected_intent_key_hash=descriptor['intentKeyHash'])


def _open_material(case, descriptor):
    return RestartCheckpointReaderV3(case, expected_material_digest=descriptor['materialDigest'],
        expected_custody_digest=descriptor['custodyDigest'], expected_context=descriptor['context'],
        expected_witness_key_hash=descriptor['witnessKeyHash'])


class SceneCheckpointReaderV3:
    def __copy__(self): reject()
    def __deepcopy__(self, memo): reject()
    def __reduce_ex__(self, protocol): reject()

    def __init__(self, case, *, expected_material_digest, expected_custody_digest, expected_context,
                 expected_witness_key_hash, expected_scene_binding_digest, expected_intent_key_hash):
        self._reader = None
        self._closed = False
        self._owner = (os.getpid(), threading.get_ident())
        try:
            if not hex_value(expected_scene_binding_digest) or not hex_value(expected_intent_key_hash):
                reject()
            descriptor = dict(casePath=str(case), materialDigest=expected_material_digest,
                custodyDigest=expected_custody_digest, context=decode(canonical(expected_context)),
                witnessKeyHash=expected_witness_key_hash)
            self._reader = RestartCheckpointReaderV3(case, expected_material_digest=expected_material_digest,
                expected_custody_digest=expected_custody_digest, expected_context=descriptor['context'],
                expected_witness_key_hash=expected_witness_key_hash)
            guard = self._reader._guard
            guard.add_dir(case / 'scene-checkpoint')
            guard.add_file(case / 'scene-checkpoint', 'binding.private.json', MAX_BINDING)
            guard.add_file(case / 'scene-checkpoint', 'archive.private.zip', MAX_ARCHIVE)
            _READERS[self] = (self._owner, id(self._reader), canonical(descriptor),
                             expected_scene_binding_digest, expected_intent_key_hash)
            self._authenticate()
        except Exception:
            if self._reader is not None:
                self._reader.close()
            _READERS.pop(self, None)
            self._closed = True
            reject()

    def _authenticate(self):
        record = _READERS.get(self)
        if (type(self) is not SceneCheckpointReaderV3 or record is None or self._closed
                or self._owner != (os.getpid(), threading.get_ident()) or self._owner != record[0]
                or id(self._reader) != record[1]):
            reject()
        reader = self._reader
        seal = _sealed_reader(reader)
        descriptor = decode(record[2]); case = Path(descriptor['casePath'])
        guard = reader._guard; fd = guard.dirs[case / 'scene-checkpoint'][0]
        if set(os.listdir(fd)) != {'binding.private.json', 'archive.private.zip'}:
            reject()
        raw, _ = read_file(fd, 'binding.private.json', MAX_BINDING)
        archive, _ = read_file(fd, 'archive.private.zip', MAX_ARCHIVE)
        if digest(raw) != record[3] or digest(archive) != descriptor['context']['archiveDigest']:
            reject()
        payload, public = _verify_signature(decode(raw), record[4])
        if any(canonical(payload[k]) != canonical(descriptor[k]) for k in
               ('materialDigest', 'custodyDigest', 'witnessKeyHash', 'context')):
            reject()
        context = reader.context
        history = context.history
        snapshot = history.capture()
        if (snapshot.canonical != context.snapshot.canonical
                or payload['context']['historyDigest'] != snapshot.digest
                or digest(canonical(payload['hello'])) != history._policy.scope_hash):
            reject()
        closure = payload['closure']
        verified = verify_create_closure(closure, public_key=public, expected=closure['payload'])
        if (verified['requestHash'] != history._request.digest() or verified['bundleDigest'] != history._bundle.digest
                or verified['historyDigest'] != snapshot.digest
                or canonical(verified['receiptMap']) != canonical(dict(snapshot.snapshot['receiptMap']))):
            reject()
        origin = _evidence(payload['evidence'], payload['hello'], descriptor['context'])
        if _sealed_reader(reader) != seal:
            reject()
        guard.check()
        return payload, origin, archive

    @property
    def context(self):
        self._authenticate()
        return self._reader.context

    @property
    def writer_origin(self):
        return self._authenticate()[1]

    def read_source_archive(self):
        return self._authenticate()[2]

    def verify_published_source(self, *, repository, timeout=15):
        import deployment_compose_profile3_prepare_ssh_probe as source
        payload, origin, raw = self._authenticate()
        context = payload['context']
        identity = self._reader.context.history._request.source
        if (identity.provider_id != 'github.com' or identity.origin != source.ORIGIN
                or identity.source_sha != context['sourceSha']):
            reject()
        manifest = _verify_archive(raw, repository=repository, source_sha=context['sourceSha'],
                                   archive_digest=context['archiveDigest'], timeout=timeout)
        if digest(manifest) != payload['sourceManifestDigest'] or self._authenticate() != (payload, origin, raw):
            reject()
        return VerifiedCheckpointPublishedSourceV3(manifest, context['sourceSha'], context['archiveDigest'],
            payload['materialDigest'], digest(manifest), len(json.loads(manifest)))

    def observe_writer_stopped(self, *, verifier_source_sha, timeout=30):
        """Fresh read-only SSH observation; no future writer fence or permit.

        The origin-material pin names this scene's signed binding artifact.
        Only the SSH phase is timed; original filesystem/crypto/flock limits
        also apply to the authentication before and after that phase.
        """
        from deployment_compose_cold_writer_ssh_v3_host import (
            observe_origin_over_ssh, RemoteWriterStopObservationV3)
        payload, origin, archive = SceneCheckpointReaderV3._authenticate(self)
        seal = _READERS[self]
        context = payload['context']
        binding = dict(materialDigest=payload['materialDigest'],
            originMaterialDigest=seal[3], historyDigest=context['historyDigest'])
        result = observe_origin_over_ssh(origin, expected_origin_digest=digest(origin),
            host_id=context['hostId'], producer_source_sha=context['sourceSha'],
            producer_archive_digest=context['archiveDigest'], verifier_source_sha=verifier_source_sha,
            checkpoint_binding=binding, timeout=timeout)
        if (SceneCheckpointReaderV3._authenticate(self) != (payload, origin, archive)
                or _READERS.get(self) is not seal
                or type(result) is not RemoteWriterStopObservationV3
                or result.checkpoint_binding != canonical(binding) or result.checkpointBound is not True
                or result.writerStoppedObserved is not True or result.sshDeliveryVerified is not True
                or result.origin_digest != digest(origin) or result.host_id != context['hostId']
                or result.producer_source_sha != context['sourceSha']
                or result.producer_archive_digest != context['archiveDigest']
                or result.verifier_source_sha != verifier_source_sha):
            reject()
        return result

    def observe_live_phase(self, *, handle):
        """Observe original scene applicability; no raw phase or recovery permit."""
        from deployment_compose_scene_live_phase_v3_host import observe_scene_live_phase
        return observe_scene_live_phase(self, handle=handle)

    def capture_live_phase_snapshot(self, *, handle, download_timeout=120):
        """Receive a sealed historical phase snapshot; no recovery authority."""
        from deployment_compose_scene_phase_snapshot_v3_host import capture_scene_phase_snapshot
        return capture_scene_phase_snapshot(self, handle=handle, download_timeout=download_timeout)

    def close(self):
        if self._closed:
            if self._owner != (os.getpid(), threading.get_ident()): reject()
            return
        record = _READERS.get(self)
        if (record is None or record[0] != (os.getpid(), threading.get_ident())
                or id(self._reader) != record[1]):
            reject()
        self._closed = True
        _READERS.pop(self, None)
        self._reader.close()

    def __enter__(self):
        try:
            self._authenticate()
            return self
        except BaseException as primary:
            try:
                self.close()
            except Exception:
                note_cleanup(primary)
            raise

    def __exit__(self, exc_type, primary, traceback):
        try:
            self.close()
        except Exception:
            if primary is None: reject()
            note_cleanup(primary)
