"""Host-owned authenticated history, with no JSON-to-capability or key loader.

Hosts inject a random key of at least 32 bytes and keep this directory outside
all candidate checkouts. POSIX directories/files must be owned by the effective
user with modes 0700/0600. Windows hosts must provision equivalent private ACLs
on the directory AND its ancestors; stdlib cannot establish or audit those ACLs.
Locks coordinate one host/shared filesystem, never distributed hosts. They have
no TTL, PID recovery, or unlink/steal path. Lock order: target, history, gate.
History capture alone does not start an operation.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
import threading

import deployment_runtime as runtime
import deployment_maintenance_state as _maintenance


class StoreError(runtime.RuntimeCollectionError):
    """Authenticated history is unavailable or its trust checks failed."""


@dataclass(frozen=True)
class StorePolicy:
    repository_id: int
    store_id: str
    key_id: str
    runtime_policy: runtime.RuntimePolicy

    def __post_init__(self):
        if (type(self.repository_id) is not int or self.repository_id <= 0
                or type(self.runtime_policy) is not runtime.RuntimePolicy
                or any(type(v) is not str or not runtime.NAME.fullmatch(v)
                       for v in (self.store_id, self.key_id))):
            raise StoreError('Invalid host store policy')

    def _scope(self):
        p = self.runtime_policy
        return dict(repository=p.repository, repositoryId=self.repository_id,
                    environment=p.environment, target=p.target, production=p.production,
                    daemon=p.daemon_id, project=p.project, components=sorted(p.components))

    def identity_hash(self):
        """Stable signer/target identity; excludes catalog, recipes and transport."""
        return runtime.digest(dict(domain='deployment-store-policy-v1', storeId=self.store_id,
                                   keyId=self.key_id, scope=self._scope()))


@dataclass(frozen=True)
class HistoricalSnapshot:
    """Only HostStore.load_history can issue authority; construction is inert.

    All public evidence access revalidates the signature and bound live baseline.
    to_dict returns the original observation payload; snapshot the planner shape.
    """
    _store: HostStore = field(repr=False, compare=False)
    _ref: str
    _collector: runtime.TrustedDockerCollector = field(repr=False, compare=False)
    _before: runtime.RuntimeObservation = field(repr=False, compare=False)

    def __deepcopy__(self, memo):
        return replace(self)

    def _record(self):
        return HostStore._validate(self, collector=self._collector, before=self._before)

    def to_dict(self):
        return self._record()['observation']

    def snapshot(self):
        return self.to_dict()['snapshot']

    @property
    def evidence_hash(self):
        return self._record()['observation']['evidenceHash']

    @property
    def policy_hash(self):
        return self._record()['producerPolicyHash']

    @property
    def captured_at(self):
        return self._record()['capturedAt']

    @property
    def proof_hash(self):
        return runtime.digest(self._store._envelope(self._record()))

    @property
    def store_policy_hash(self):
        return self._record()['storePolicyHash']

    @property
    def current_policy_hash(self):
        self._record()
        return self._collector.policy.identity_hash()


_LOCKS = {}
_LOCKS_GUARD = threading.Lock()
_REF = re.compile(r'history-[0-9a-f]{64}\.json\Z')
_DOMAIN = b'dev-workflow/deployment-store/history/v1\x00'
_MAX_RECORD = 8 * 1024 * 1024


def _utc(value):
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None or dt.utcoffset().total_seconds() != 0:
            raise ValueError
        return dt
    except (TypeError, ValueError, AttributeError):
        raise StoreError('Invalid history UTC timestamp') from None


def _private(info, *, directory=False):
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise StoreError('Store path has an unsafe type')
    if not directory and info.st_nlink != 1:
        raise StoreError('Store files must have exactly one link')
    if os.name == 'posix' and (info.st_uid != os.geteuid()
                              or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)):
        raise StoreError('Store path must be privately owned with restrictive permissions')
    if getattr(info, 'st_file_attributes', 0) & 0x400:  # Windows reparse point
        raise StoreError('Store reparse points are forbidden')


def _validate_source_identity(value):
    if (type(value) is not dict
            or set(value) != {'storeId', 'keyId', 'storePolicyHash', 'recordHash'}
            or any(type(value[k]) is not str or not runtime.NAME.fullmatch(value[k])
                   for k in ('storeId', 'keyId'))
            or any(type(value[k]) is not str or not runtime.HEX.fullmatch(value[k])
                   for k in ('storePolicyHash', 'recordHash'))):
        raise StoreError('Invalid history provenance identity')


def _validate_provenance(value):
    if type(value) is not dict or set(value) != {'original', 'immediate', 'archiveHash', 'importedAt'}:
        raise StoreError('Invalid history provenance')
    _validate_source_identity(value['original'])
    _validate_source_identity(value['immediate'])
    if type(value['archiveHash']) is not str or not runtime.HEX.fullmatch(value['archiveHash']):
        raise StoreError('Invalid archive provenance hash')
    _utc(value['importedAt'])


def imported_history_record(source_record, source_identity, archive_hash, new_policy, new_ref, imported_at):
    """Build an import attestation from an already authenticated source record."""
    _validate_source_identity(source_identity)
    if (type(new_policy) is not StorePolicy or type(new_ref) is not str or not _REF.fullmatch(new_ref)
            or source_identity != dict(storeId=source_record['storeId'], keyId=source_record['keyId'],
                                      storePolicyHash=source_record['storePolicyHash'], recordHash=runtime.digest(source_record))
            or source_record['scope'] != new_policy._scope()):
        raise StoreError('Imported history source mismatch')
    original = source_identity
    if source_record['schemaVersion'] == 2:
        _validate_provenance(source_record['provenance'])
        original = source_record['provenance']['original']
    provenance = dict(original=original, immediate=source_identity, archiveHash=archive_hash, importedAt=imported_at)
    _validate_provenance(provenance)
    if _utc(imported_at) < _utc(source_record['capturedAt']):
        raise StoreError('Import precedes historical capture')
    record = dict(source_record, schemaVersion=2, reference=new_ref, storeId=new_policy.store_id,
                  keyId=new_policy.key_id, storePolicyHash=new_policy.identity_hash(), provenance=provenance)
    # Detach from caller-owned dictionaries, retaining original evidence exactly.
    return runtime.parse_json(runtime.canonical(record))


def authenticate_history(raw, policy, key, reference):
    """Verify a bounded envelope without opening or constructing a source store."""
    if (type(raw) is not bytes or len(raw) > _MAX_RECORD
            or type(policy) is not StorePolicy or type(key) is not bytes or len(key) < 32
            or type(reference) is not str or not _REF.fullmatch(reference)):
        raise StoreError('Invalid history verification input')
    try:
        envelope = runtime.parse_json(raw.decode('ascii'))
        if len(raw) > _MAX_RECORD or set(envelope) != {'record', 'signature'}:
            raise ValueError
        record = envelope['record']
        signature = hmac.new(key, _DOMAIN + runtime.canonical(record).encode(), hashlib.sha256).hexdigest()
        if (type(envelope['signature']) is not str
                or not hmac.compare_digest(envelope['signature'], signature)
                or runtime.canonical(envelope).encode() != raw):
            raise ValueError
        fields = {'schemaVersion', 'kind', 'reference', 'storeId', 'keyId', 'storePolicyHash',
                  'scope', 'producerPolicyHash', 'capturedAt', 'observation', 'entries'}
        if record.get('schemaVersion') == 2:
            fields.add('provenance')
        if (set(record) != fields
                or type(record['schemaVersion']) is not int or record['schemaVersion'] not in (1, 2)
                or record['kind'] != 'authenticated-deployment-history' or record['reference'] != reference
                or record['storeId'] != policy.store_id or record['keyId'] != policy.key_id
                or record['storePolicyHash'] != policy.identity_hash()
                or record['scope'] != policy._scope()):
            raise ValueError
        if record['schemaVersion'] == 2:
            _validate_provenance(record['provenance'])
            if _utc(record['provenance']['importedAt']) < _utc(record['capturedAt']):
                raise ValueError
        payload = dict(record['observation'])
        evidence = payload.pop('evidenceHash')
        if (payload['complete'] is not True or runtime.digest(payload) != evidence
                or payload['policyHash'] != record['producerPolicyHash']
                or not runtime.HEX.fullmatch(record['producerPolicyHash'])
                or _utc(payload['capturedAt']) > _utc(record['capturedAt'])):
            raise ValueError
        return record
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        raise StoreError('History authentication or record validation failed') from None


class HostStore:
    """Concrete store. root must be absolute with NO symlink path components.

    For trusted macOS temporary parents, resolve the parent explicitly before
    appending the store directory (system /var and /tmp are often symlinks).
    The embedding host owns candidate boundaries beyond this source checkout.
    """
    def __init__(self, policy: StorePolicy, root: Path, *, key: bytes):
        if type(policy) is not StorePolicy or type(key) is not bytes or len(key) < 32:
            raise StoreError('Explicit store policy and at least 32 random key bytes are required')
        if not isinstance(root, Path) or not root.is_absolute() or '..' in root.parts:
            raise StoreError('An absolute private host directory is required')
        # This source checkout is a known candidate boundary. Embedders must also
        # keep the host directory outside any other candidate checkout they admit.
        candidate = Path(__file__).resolve().parents[3]
        if root == candidate or candidate in root.parents:
            raise StoreError('Host store must be outside the candidate checkout')
        self.policy, self.root, self._key = policy, root, key
        self._policy_hash = policy.identity_hash()
        self._issued = {}
        self._captures = {}
        self._issuance_lock = threading.Lock()
        self._history_identity = None
        self._history_pin = None
        self._root_identity = None
        try:
            with self._directory(create=True) as directory:
                info = os.fstat(directory) if directory is not None else root.lstat()
                self._root_identity = (info.st_dev, info.st_ino)
        except OSError:
            raise StoreError('Private host directory is unavailable') from None
        with self.history_lock():
            pass

    def __del__(self):
        fd = getattr(self, '_history_pin', None)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    @contextmanager
    def _directory(self, *, create=False):
        """Walk without following links; pin POSIX operations to directory FDs."""
        fd = None
        try:
            if os.name == 'posix':
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                fd = os.open(self.root.anchor, flags)
                for index, part in enumerate(self.root.parts[1:]):
                    if create and index == len(self.root.parts) - 2:
                        try:
                            os.mkdir(part, 0o700, dir_fd=fd)
                            os.fsync(fd)
                        except FileExistsError:
                            pass
                    new = os.open(part, flags, dir_fd=fd)
                    os.close(fd)
                    fd = new
                info = os.fstat(fd)
            else:
                for path in (*reversed(self.root.parents), self.root):
                    if create and path == self.root and not path.exists():
                        path.mkdir(mode=0o700)
                    info = path.lstat()
                    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                        raise StoreError('Store links are forbidden')
                info = self.root.lstat()
            _private(info, directory=True)
            if self._root_identity is not None and (info.st_dev, info.st_ino) != self._root_identity:
                raise StoreError('Host directory identity changed')
            yield fd
        except OSError:
            raise StoreError('Secure host store access failed') from None
        finally:
            if fd is not None:
                os.close(fd)

    def _open(self, directory, name, flags):
        flags |= getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
        fd = os.open(name if directory is not None else self.root / name, flags, 0o600,
                     **({'dir_fd': directory} if directory is not None else {}))
        try:
            info = os.fstat(fd)
            _private(info)
            path_info = os.stat(name, dir_fd=directory, follow_symlinks=False) if directory is not None else (self.root / name).lstat()
            if (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino):
                raise StoreError('Store file identity changed')
            _private(path_info)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextmanager
    def target_lock(self):
        """Non-reentrant target mutex; acquire before history and gate locks."""
        with self._mutex('target.lock'):
            yield

    def _maintenance_guard(self):
        try:
            _maintenance._guard(self.root, self._policy_hash, self._key, 'store')
        except (OSError, _maintenance.MaintenanceStateError):
            raise StoreError('History maintenance authority unavailable') from None

    @contextmanager
    def history_lock(self):
        """Fixed non-reentrant history mutex shared by all store instances."""
        try:
            with self._mutex('history.lock'):
                self._maintenance_guard()
                yield
        except _maintenance.MaintenanceStateError:
            raise StoreError('History maintenance authority unavailable') from None

    @contextmanager
    def _mutex(self, name):
        """Block on the kernel mutex until its live owner releases or exits.

        Non-reentrant. Never delete/replace the lock file or infer expiry from PID
        or time. Public entry points select a fixed mutex name.
        """
        with self._directory() as directory:
            fd = self._open(directory, name, os.O_RDWR | os.O_CREAT)
            info = os.fstat(fd)
            if name == 'history.lock':
                identity = (info.st_dev, info.st_ino)
                with self._issuance_lock:
                    if self._history_identity is None:
                        self._history_identity = identity
                        if os.name == 'posix':
                            self._history_pin = os.dup(fd)
                    elif self._history_identity != identity:
                        os.close(fd)
                        raise StoreError('History mutex identity changed')
            with _LOCKS_GUARD:
                local = _LOCKS.setdefault((info.st_dev, info.st_ino), threading.Lock())
            try:
                with local:
                    if os.name == 'posix':
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX)
                    else:
                        import msvcrt
                        # msvcrt.locking has a bounded retry loop, so implement
                        # blocking acquisition explicitly without a lease timeout.
                        import time
                        import errno
                        if info.st_size == 0:
                            os.write(fd, b'\x00')
                            os.fsync(fd)
                        while True:
                            try:
                                os.lseek(fd, 0, os.SEEK_SET)
                                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                                break
                            except OSError as exc:
                                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                                    raise
                                time.sleep(0.05)
                    try:
                        # Revalidate the path after waiting, before entering.
                        with self._directory() as current_directory:
                            check = self._open(current_directory, name, os.O_RDWR)
                            try:
                                current = os.fstat(check)
                                if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                                    raise StoreError('Store mutex identity changed')
                            finally:
                                os.close(check)
                            if name == 'history.lock':
                                binding = _maintenance._binding(self.root, self._policy_hash, self._key, 'store')
                                with _maintenance._held(binding, fd):
                                    yield
                            else:
                                yield
                    finally:
                        if os.name == 'posix':
                            fcntl.flock(fd, fcntl.LOCK_UN)
                        else:
                            os.lseek(fd, 0, os.SEEK_SET)
                            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)

    def _envelope(self, record):
        signature = hmac.new(self._key, _DOMAIN + runtime.canonical(record).encode(), hashlib.sha256).hexdigest()
        return dict(record=record, signature=signature)

    def _check_policy(self, collector):
        if (type(collector) is not runtime.TrustedDockerCollector
                or type(collector.policy) is not runtime.RuntimePolicy
                or self.policy.identity_hash() != self._policy_hash
                or StorePolicy(self.policy.repository_id, self.policy.store_id,
                               self.policy.key_id, collector.policy).identity_hash() != self._policy_hash):
            raise StoreError('History collector stable scope mismatch')

    @staticmethod
    def _entries(policy, payload):
        catalog = runtime._catalog(policy)
        specs = (runtime.deployment_spec.parse_specifications(policy.specifications_json)
                 if policy.specifications_json is not None else {})
        instances = {item['component']: item['imageId'] for item in payload['instances']}
        components = payload['snapshot']['components']
        if (set(instances) != set(policy.components) or len(instances) != len(payload['instances'])
                or sorted(x['name'] for x in components) != sorted(policy.components)):
            raise StoreError('Historical component set mismatch')
        entries = []
        for component in sorted(components, key=lambda x: x['name']):
            name = component['name']
            lookup = (name, instances[name])
            entry, spec = catalog.get(lookup), specs.get(lookup)
            if (entry is None or spec is None or component['sourceSha'] != entry['sourceSha']
                    or component['artifact'] != entry['artifact']
                    or component['configurationDigest'] != spec.configuration_digest()
                    or payload['versions'][name] != entry['version']):
                raise StoreError('Historical image/source/artifact/specification is unavailable')
            # Hash the complete trusted recipe: no raw Env/Config in history.
            entries.append(dict(catalog=entry, specificationHash=runtime.digest(spec.to_dict())))
        return entries

    def capture_history(self, collector, observation) -> str:
        self._check_policy(collector)
        if (collector.policy.identity_hash() != self.policy.runtime_policy.identity_hash()
                or type(observation) is not runtime.RuntimeObservation):
            raise StoreError('Capture requires the configured live runtime policy')
        collector.validate(observation)
        payload = observation.to_dict()
        entries = self._entries(collector.policy, payload)
        collector.recheck(observation)
        with self.history_lock():
            collector.validate(observation)
            ref = 'history-' + secrets.token_hex(32) + '.json'
            record = dict(schemaVersion=1, kind='authenticated-deployment-history', reference=ref,
                          storeId=self.policy.store_id, keyId=self.policy.key_id,
                          storePolicyHash=self._policy_hash, scope=self.policy._scope(),
                          producerPolicyHash=observation.policy_hash,
                          capturedAt=datetime.now(timezone.utc).isoformat(),
                          observation=payload, entries=entries)
            raw = runtime.canonical(self._envelope(record)).encode()
            if len(raw) > _MAX_RECORD:
                raise StoreError('History record exceeds size limit')
            with self._directory() as directory:
                fd = self._open(directory, ref, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                try:
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    if directory is not None:
                        os.fsync(directory)
                except OSError:
                    # A partial record stays invalid; never overwrite or repair it.
                    raise StoreError('History record persistence failed') from None
            with self._issuance_lock:
                self._captures[ref] = (collector, observation)
            return ref

    def _read(self, ref):
        if type(ref) is not str or not _REF.fullmatch(ref):
            raise StoreError('Unknown history reference')
        with self._directory() as directory:
            fd = self._open(directory, ref, os.O_RDONLY)
            with os.fdopen(fd, 'rb') as stream:
                raw = stream.read(_MAX_RECORD + 1)
        return authenticate_history(raw, self.policy, self._key, ref)

    def _compatible(self, ref, collector, before):
        self._check_policy(collector)
        if type(before) is not runtime.RuntimeObservation:
            raise StoreError('History requires an actual live baseline')
        collector.validate(before)
        record = self._read(ref)
        with self._issuance_lock:
            capture = self._captures.get(ref)
        if capture is not None and capture[0] is collector:
            # Preserve the collector's issuance order for same-process history.
            collector.validate_history(capture[1], before=before)
        if _utc(record['capturedAt']) >= _utc(before.captured_at):
            raise StoreError('History must strictly precede the live baseline UTC')
        if self._entries(collector.policy, record['observation']) != record['entries']:
            raise StoreError('Historical trusted catalog or specification changed')
        # History remains proof of the past during an authorized intermediate
        # replacement state. The executor separately guards each live stage.
        collector.validate(before)
        return record

    def load_history(self, ref: str, *, collector, before) -> HistoricalSnapshot:
        self._compatible(ref, collector, before)
        collector.recheck(before)
        with self.history_lock():
            self._compatible(ref, collector, before)
            history = HistoricalSnapshot(self, ref, collector, before)
            with self._issuance_lock:
                self._issued[id(history)] = (history, collector, before)
            return history

    @classmethod
    def _validate(cls, observation, *, collector, before):
        if type(observation) is not HistoricalSnapshot or type(getattr(observation, '_store', None)) is not HostStore:
            raise StoreError('History was not issued by a host store')
        store = observation._store
        with store._issuance_lock:
            issued = store._issued.get(id(observation))
        if (issued is None or issued[0] is not observation or issued[1] is not collector
                or issued[2] is not before or observation._collector is not collector
                or observation._before is not before):
            raise StoreError('History capability identity or baseline binding mismatch')
        with store.history_lock():
            return store._compatible(observation._ref, collector, before)

    @classmethod
    def validate_history(cls, observation, *, collector, before):
        cls._validate(observation, collector=collector, before=before)
        return observation
