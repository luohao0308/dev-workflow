"""Private read-only restart custody, under trusted exclusive POSIX storage.

Digest/context/key pins come from the embedding, never an adjacent manifest.
This is not Keychain/KMS, global rollback resistance, or execution recovery.
Original witness flock and individual crypto timeouts retain their boundaries.
"""
import base64
import hashlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import threading

from deployment_compose_restart_material_v3_host import capture_material, reopen_material, MAX_MATERIAL
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_operation_witness_client_v3 import dispatch_request, encode, NAMESPACE, hex_value
from deployment_compose_witness_store import canonical
from deployment_gate_witness import key_material

ROOT = Path(__file__).resolve().parents[1]
_READS = {'read', 'check', 'events_after', 'chain_status'}


def reject():
    raise ValueError('compose-restart-checkpoint-v3-rejected') from None


def note_cleanup(primary):
    try:
        if hasattr(primary, 'add_note'):
            primary.add_note('restart checkpoint cleanup incomplete')
    except Exception:
        pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def directory(path):
    if (os.name != 'posix' or not isinstance(path, Path)
            or not path.is_absolute() or '..' in path.parts or path.is_relative_to(ROOT)):
        reject()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            reject()
        return fd, (info.st_dev, info.st_ino)
    except BaseException:
        os.close(fd)
        raise


def read_file(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
    try:
        def identity():
            s = os.fstat(fd)
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid()
                    or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1 or s.st_size > limit):
                reject()
            return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        before = identity()
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                reject()
        raw = b''.join(chunks)
        if identity() != before or len(raw) != before[2]:
            reject()
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != before[:2]:
            reject()
        return raw, before + (digest(raw),)
    finally:
        os.close(fd)


class _Guard:
    def __init__(self, case):
        self.dirs, self.files = {}, {}
        self.case = case
        try:
            self.add_dir(case)
            self.add_dir(case / 'witness')
            witness = self.dirs[case / 'witness'][0]
            if set(os.listdir(witness)) != {'witness.lock', 'state.json'}:
                reject()
            self.add_file(case / 'witness', 'witness.lock', 4096)
            self.add_file(case / 'witness', 'state.json', 2 * 1024 * 1024)
            self.add_file(case, 'witness-signing', 65536)
        except BaseException as primary:
            try:
                self.close()
            except Exception:
                note_cleanup(primary)
            raise

    def add_dir(self, path):
        fd, ident = directory(path)
        self.dirs[path] = (fd, ident)

    def add_file(self, parent, name, limit):
        raw, ident = read_file(self.dirs[parent][0], name, limit)
        self.files[(parent, name)] = (limit, ident)
        return raw

    def check(self):
        for path, (fd, expected) in self.dirs.items():
            fresh, actual = directory(path)
            try:
                s = os.fstat(fd)
                if actual != expected or (s.st_dev, s.st_ino) != expected:
                    reject()
            finally:
                os.close(fresh)
        for (parent, name), (limit, expected) in self.files.items():
            if read_file(self.dirs[parent][0], name, limit)[1] != expected:
                reject()
        witness = self.dirs[self.case / 'witness'][0]
        if set(os.listdir(witness)) != {'witness.lock', 'state.json'}:
            reject()
        read_file(witness, 'witness.lock', 4096)
        read_file(witness, 'state.json', 2 * 1024 * 1024)
        for child, name in (('restart-material', 'material.private.json'), ('restart-custody', 'keys.private.json'),
                            ('writer-origin', 'origin.private.json')):
            path = self.case / child
            if path in self.dirs and set(os.listdir(self.dirs[path][0])) != {name}:
                reject()

    def close(self):
        failed = False
        for fd, _ in self.dirs.values():
            try:
                os.close(fd)
            except OSError:
                failed = True
        self.dirs.clear()
        if failed:
            reject()


def public_key(guard):
    guard.check()
    reply = subprocess.run(['/usr/bin/ssh-keygen', '-y', '-f', str(guard.case / 'witness-signing')],
                           capture_output=True, check=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
    guard.check()
    return key_material(reply.stdout)


def transport(guard, store, owned):
    def call(method, request):
        owned()
        if type(method) is not str or method not in _READS:
            reject()
        guard.check()
        payload = dispatch_request(store, method, request)
        signed = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(guard.case / 'witness-signing'),
                                 '-n', NAMESPACE], input=encode(payload), capture_output=True,
                                check=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
        guard.check()
        return dict(payload=payload, signature=base64.b64encode(signed.stdout).decode('ascii'))
    return call


def publish(parent, name, raw):
    temporary = '.checkpoint-' + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
    finally:
        os.unlink(temporary, dir_fd=parent)
        os.fsync(parent)


class RestartCheckpointReaderV3:
    def __copy__(self):
        reject()

    def __deepcopy__(self, memo):
        reject()

    def __reduce_ex__(self, protocol):
        reject()

    def __init__(self, case, *, expected_material_digest, expected_custody_digest,
                 expected_context, expected_witness_key_hash,
                 expected_origin_material_digest=None, expected_origin_digest=None):
        self._owner = (os.getpid(), threading.get_ident())
        self._issuer = self
        self._closed = False
        self._guard = self._store = None
        self._writer_origin = None
        try:
            pins = decode(canonical(expected_context))
            if not all(hex_value(x) for x in (expected_material_digest, expected_custody_digest, expected_witness_key_hash)):
                reject()
            if (expected_origin_material_digest is None) != (expected_origin_digest is None):
                reject()
            if expected_origin_material_digest is not None and not all(hex_value(x) for x in
                    (expected_origin_material_digest, expected_origin_digest)):
                reject()
            self._guard = guard = _Guard(case)
            for child in ('restart-material', 'restart-custody'):
                guard.add_dir(case / child)
            raw = guard.add_file(case / 'restart-material', 'material.private.json', MAX_MATERIAL)
            custody = guard.add_file(case / 'restart-custody', 'keys.private.json', 16384)
            if digest(raw) != expected_material_digest or digest(custody) != expected_custody_digest:
                reject()
            value = decode(custody)
            if (type(value) is not dict or set(value) != {'schemaVersion', 'kind', 'gateKeyBase64', 'storeKeyBase64'}
                    or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                    or value['kind'] != 'compose-restart-read-keys-v3'):
                reject()
            keys = []
            for name in ('gateKeyBase64', 'storeKeyBase64'):
                key = base64.b64decode(value[name], validate=True)
                if not 32 <= len(key) <= 4096 or base64.b64encode(key).decode('ascii') != value[name]:
                    reject()
                keys.append(key)
            public = public_key(guard)
            if digest(public) != expected_witness_key_hash:
                reject()
            guard.check()
            self._store = OperationWitnessStoreV3(case / 'witness', key=keys[1], create_lock=False)
            guard.check()
            self._context = reopen_material(raw, expected_digest=expected_material_digest, expected_context=pins,
                gate_key=keys[0], witness_public_key=public,
                witness_transport=transport(guard, self._store, self._owned))
            if expected_origin_material_digest is not None:
                guard.add_dir(case / 'writer-origin')
                artifact = guard.add_file(case / 'writer-origin', 'origin.private.json', 32768)
                if digest(artifact) != expected_origin_material_digest:
                    reject()
                self._writer_origin = validate_writer_artifact(artifact,
                    material_digest=expected_material_digest, custody_digest=expected_custody_digest,
                    witness_key_hash=expected_witness_key_hash, context=pins,
                    hello_digest=self._context.history._policy.scope_hash,
                    origin_digest=expected_origin_digest)
            guard.check()
        except Exception:
            try:
                self.close()
            except Exception:
                pass
            reject()

    def _owned(self):
        if self._issuer is not self or self._owner != (os.getpid(), threading.get_ident()) or self._closed:
            reject()

    @property
    def context(self):
        self._owned()
        try:
            self._guard.check()
            return self._context
        except Exception:
            reject()

    @property
    def writer_origin(self):
        self._owned()
        try:
            self._guard.check()
            parent = self._guard.case / 'writer-origin'
            if parent not in self._guard.dirs:
                return None
            raw, identity = read_file(self._guard.dirs[parent][0], 'origin.private.json', 32768)
            if identity != self._guard.files[(parent, 'origin.private.json')][1]:
                reject()
            if canonical(decode(raw)['origin']) != self._writer_origin:
                reject()
            return self._writer_origin
        except Exception:
            reject()

    def close(self):
        if self._issuer is not self or self._owner != (os.getpid(), threading.get_ident()):
            reject()
        if self._closed:
            return
        self._closed = True
        failed = False
        for resource in (self._store, self._guard):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    failed = True
        if failed:
            reject()

    def __enter__(self):
        self._owned()
        return self

    def __exit__(self, exc_type, primary, traceback):
        try:
            self.close()
        except Exception:
            if primary is None:
                reject()
            note_cleanup(primary)


def save_checkpoint(case, *, original_history, baseline_bytes, authenticated_image_defaults,
                    archive_digest, witness_store, witness_signer):
    guard = None
    try:
        if (type(witness_store) is not OperationWitnessStoreV3 or witness_store.root != case / 'witness'
                or witness_signer != case / 'witness-signing'):
            reject()
        guard = _Guard(case)
        raw = capture_material(original_history, baseline_bytes=baseline_bytes,
            authenticated_image_defaults=authenticated_image_defaults, archive_digest=archive_digest)
        value = decode(raw)
        pins = dict(sourceSha=original_history._request.source.source_sha, hostId=original_history._request.host_id,
                    daemonId=original_history._request.daemon_id, archiveDigest=archive_digest,
                    historyDigest=digest(canonical(value['snapshot'])),
                    baselineStateDigest=digest(baseline_bytes))
        keys = (original_history._key, witness_store._key)
        if any(type(key) is not bytes or not 32 <= len(key) <= 4096 for key in keys):
            reject()
        public = key_material(original_history._client._public)
        if public_key(guard) != public:
            reject()
        reopen_material(raw, expected_digest=digest(raw), expected_context=pins, gate_key=keys[0],
                        witness_public_key=public, witness_transport=transport(guard, witness_store, lambda: None))
        custody = canonical(dict(schemaVersion=1, kind='compose-restart-read-keys-v3',
            gateKeyBase64=base64.b64encode(keys[0]).decode('ascii'), storeKeyBase64=base64.b64encode(keys[1]).decode('ascii')))
        for child, name, data in (('restart-material', 'material.private.json', raw),
                                  ('restart-custody', 'keys.private.json', custody)):
            os.mkdir(child, 0o700, dir_fd=guard.dirs[case][0])
            os.fsync(guard.dirs[case][0])
            guard.add_dir(case / child)
            publish(guard.dirs[case / child][0], name, data)
        guard.close()
        guard = None
        result = dict(casePath=str(case), materialDigest=digest(raw), custodyDigest=digest(custody),
                      context=pins, witnessKeyHash=digest(public))
        with RestartCheckpointReaderV3(case, expected_material_digest=result['materialDigest'],
                expected_custody_digest=result['custodyDigest'], expected_context=pins,
                expected_witness_key_hash=result['witnessKeyHash']) as reader:
            if reader.context.snapshot.canonical != canonical(value['snapshot']):
                reject()
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


_ORIGIN_FIELDS = {'schemaVersion', 'kind', 'materialDigest', 'custodyDigest', 'witnessKeyHash',
                  'context', 'managerBinding', 'channelNonce', 'helloDigest', 'origin'}
_BINDING_FIELDS = {'unit', 'kernelBoot', 'invocationId', 'sourceSha', 'archiveDigest', 'hostId'}


def validate_writer_artifact(raw, *, material_digest, custody_digest, witness_key_hash,
                             context, hello_digest, origin_digest):
    from deployment_compose_cold_writer_v3_host import validate_origin
    if type(raw) is not bytes or not 0 < len(raw) <= 32768:
        reject()
    value = decode(raw)
    if (type(value) is not dict or set(value) != _ORIGIN_FIELDS
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['kind'] != 'compose-checkpoint-writer-origin-v3'
            or value['materialDigest'] != material_digest or value['custodyDigest'] != custody_digest
            or value['witnessKeyHash'] != witness_key_hash or canonical(value['context']) != canonical(context)
            or not hex_value(value['channelNonce']) or value['helloDigest'] != hello_digest
            or not hex_value(value['helloDigest'])):
        reject()
    binding = value['managerBinding']
    if type(binding) is not dict or set(binding) != _BINDING_FIELDS:
        reject()
    origin = canonical(value['origin'])
    physical = validate_origin(origin)
    if (digest(origin) != origin_digest
            or any(binding[key] != physical[key] for key in
                   ('unit', 'kernelBoot', 'invocationId', 'sourceSha', 'archiveDigest'))
            or any(binding[key] != context[key] for key in ('sourceSha', 'archiveDigest', 'hostId'))):
        reject()
    return origin


def bind_writer_origin(case, *, session, admission, checkpoint_descriptor):
    """Bind only original live session/admission inputs; descriptor is never authority."""
    from deployment_compose_owned_recovery_session_v3_host import issued, writer_origin_record
    from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
    guard = None
    try:
        descriptor = decode(canonical(checkpoint_descriptor))
        if (type(descriptor) is not dict or set(descriptor) !=
                {'casePath', 'materialDigest', 'custodyDigest', 'context', 'witnessKeyHash'}):
            reject()
        def seal():
            issued(session)
            origin, binding, hello = writer_origin_record(session)
            if (session.diagnostic_profile is not None or not session._started or session._finished
                    or session._closed or session._early_terminal is not None
                    or session._process.poll() is not None or hello is None
                    or type(admission) is not MacLiveAdmissionV3 or admission._owner_pid != os.getpid()
                    or admission._issuer is not admission or admission._root is None
                    or admission._current is not admission._root or admission._pending is not None
                    or admission._store.root.parent != case or descriptor['casePath'] != str(case)
                    or descriptor['witnessKeyHash'] != digest(key_material(admission._public[0]))
                    or admission._policy.scope_hash != digest(hello)):
                reject()
            parsed = decode(hello)
            if any(parsed[key] != descriptor['context'][key] for key in
                   ('sourceSha', 'archiveDigest', 'hostId', 'daemonId')):
                reject()
            entry = admission._root
            return (origin, binding, hello, id(entry), entry['request'].digest(),
                    entry['bundle'].canonical_bytes, admission._policy.identity_hash(),
                    digest(key_material(admission._public[0])), digest(admission._key),
                    id(admission._store), digest(admission._store._key))
        frozen = seal()
        with RestartCheckpointReaderV3(case, expected_material_digest=descriptor['materialDigest'],
                expected_custody_digest=descriptor['custodyDigest'], expected_context=descriptor['context'],
                expected_witness_key_hash=descriptor['witnessKeyHash']) as reader:
            history = reader.context.history
            if history._request.digest() != frozen[4] or history._bundle.canonical_bytes != frozen[5]:
                reject()
        origin, binding, hello = frozen[:3]
        raw = canonical(dict(schemaVersion=1, kind='compose-checkpoint-writer-origin-v3',
            materialDigest=descriptor['materialDigest'], custodyDigest=descriptor['custodyDigest'],
            witnessKeyHash=descriptor['witnessKeyHash'], context=descriptor['context'],
            managerBinding=decode(binding), channelNonce=session.nonce,
            helloDigest=digest(hello), origin=decode(origin)))
        validate_writer_artifact(raw, material_digest=descriptor['materialDigest'],
            custody_digest=descriptor['custodyDigest'], witness_key_hash=descriptor['witnessKeyHash'],
            context=descriptor['context'], hello_digest=digest(hello), origin_digest=digest(origin))
        if seal() != frozen:
            reject()
        guard = _Guard(case)
        os.mkdir('writer-origin', 0o700, dir_fd=guard.dirs[case][0])
        os.fsync(guard.dirs[case][0])
        guard.add_dir(case / 'writer-origin')
        publish(guard.dirs[case / 'writer-origin'][0], 'origin.private.json', raw)
        guard.close(); guard = None
        with RestartCheckpointReaderV3(case, expected_material_digest=descriptor['materialDigest'],
                expected_custody_digest=descriptor['custodyDigest'], expected_context=descriptor['context'],
                expected_witness_key_hash=descriptor['witnessKeyHash'],
                expected_origin_material_digest=digest(raw), expected_origin_digest=digest(origin)) as reader:
            if reader.writer_origin != origin or seal() != frozen:
                reject()
        return dict(descriptor, writerOriginMaterialDigest=digest(raw), writerOriginDigest=digest(origin))
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
