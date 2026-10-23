"""Host-owned single-filesystem Docker admission fence; no HTTP service or CLI.

The trusted host supplies the key, private root OUTSIDE every candidate checkout,
verified grant/receipt digests and exact operations. A forwarding mTLS proxy must
check the authenticated writer fingerprint, admit BEFORE forwarding, and finish
only after reading the FULL upstream response, BEFORE replying to its observer.
An interrupted admission or unknown upstream outcome blocks recovery forever;
there is deliberately no PID, lease, timeout, retry or administrative drain API.
Windows requires host-protected ACLs: stdlib has no directory-relative handles.
Checks detect replacement at operation boundaries, not a malicious same-UID/admin
copy or rollback of authority records (including the entire directory). Host exclusion of such writers
and filesystem rename/power-loss guarantees remain provisioning duties.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading

_HEX = re.compile(r'[0-9a-f]{64}')
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
_ZERO = '0' * 64
_MAX_RECORD = 4 * 1024 * 1024


class GateError(ValueError):
    """Fixed diagnostic without request, response or key material."""


def _hex(value):
    return type(value) is str and _HEX.fullmatch(value) is not None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _pairs(items):
    result = {}
    for name, value in items:
        if name in result:
            raise ValueError
        result[name] = value
    return result


@dataclass(frozen=True)
class GatePolicy:
    store_id: str
    key_id: str
    scope_hash: str
    writer_certificate_sha256: str

    def __post_init__(self):
        if (not all(type(x) is str and _ID.fullmatch(x) for x in (self.store_id, self.key_id))
                or not _hex(self.scope_hash) or not _hex(self.writer_certificate_sha256)):
            raise GateError('invalid-gate-policy')

    def identity_hash(self):
        return _digest(self._binding())

    def _binding(self):
        return dict(store_id=self.store_id, key_id=self.key_id, scope_hash=self.scope_hash,
                    writer_certificate_sha256=self.writer_certificate_sha256)


class _Issued:
    def __copy__(self):
        raise GateError('capability-not-copyable')

    def __deepcopy__(self, memo):
        raise GateError('capability-not-copyable')

    def __reduce_ex__(self, protocol):
        raise GateError('capability-not-serializable')


@dataclass(frozen=True, eq=False)
class Attempt(_Issued):
    generation: str
    ref: str
    method: str
    path: str
    body_sha256: str


@dataclass(frozen=True, eq=False)
class AdmissionTicket(_Issued):
    generation: str
    attempt_ref: str
    admitted_head: str


@dataclass(frozen=True, eq=False)
class QuiescenceProof(_Issued):
    generation: str
    head: str
    envelope_json: str

    def to_json(self):
        """Export is evidence, never an importable capability."""
        return self.envelope_json


@dataclass(frozen=True, eq=False)
class WriterSession(_Issued):
    generation: str
    _gate: FileWriterGate

    def prepare_attempt(self, method, path, body: bytes):
        return self._gate._prepare(self, method, path, body)

    def headers(self, attempt):
        # Recheck authority identity at this last capability emission boundary.
        with self._gate._locked():
            if (self._gate._sessions.get(self.generation) is not self
                    or type(attempt) is not Attempt
                    or self._gate._attempts.get(attempt.ref) is not attempt
                    or attempt.generation != self.generation):
                raise GateError('unissued-attempt')
            return {'X-Dev-Workflow-Generation': self.generation,
                    'X-Dev-Workflow-Attempt': attempt.ref}


def _operation(method, path, body_hash):
    if type(method) is not str or type(path) is not str or not _hex(body_hash):
        raise GateError('writer-operation-rejected')
    prefix = r'/v1\.45/containers/'
    allowed = ((method == 'POST' and re.fullmatch(
        prefix + r'create\?name=(?:dwf-[0-9a-f]{64}|dev-workflow-[a-z0-9][a-z0-9_.-]{0,127})', path))
        or (method == 'POST' and re.fullmatch(
            prefix + r'[0-9a-f]{64}/(?:start|stop\?t=(?:[1-9]|[1-5][0-9]|60))', path))
        or (method == 'DELETE' and re.fullmatch(
            prefix + r'[0-9a-f]{64}\?force=false&v=false', path)))
    if not allowed or ('/create?' not in path and body_hash != hashlib.sha256(b'').hexdigest()):
        raise GateError('writer-operation-rejected')
    return (method, path, body_hash)


class FileWriterGate:
    """Kernel-serialized durable authority. One host/shared filesystem only.

    Do not put the root in a candidate-controlled directory. All callers are
    trusted host embeddings; opening a generation does not itself verify an SDK
    receipt. The embedding MUST verify it first. Kernel locks are never stolen.
    """
    def __init__(self, policy, root: Path, *, key: bytes):
        if type(policy) is not GatePolicy or type(key) is not bytes or len(key) < 32:
            raise GateError('invalid-gate-policy')
        if not isinstance(root, Path) or not root.is_absolute() or '..' in root.parts:
            raise GateError('private-root-required')
        self.policy, self.root, self._key = policy, root, key
        self._sessions, self._attempts, self._tickets, self._proofs = {}, {}, {}, {}
        self._thread_lock = threading.RLock()
        try:
            # The library's own checkout is always a candidate-unsafe location.
            if root.is_relative_to(Path(__file__).resolve().parents[3]):
                raise GateError('private-root-required')
            self._ancestors(root.parent)
            self._ancestor_ids = {p: self._identity(p) for p in root.parents}
            created = False
            parent_fd = None
            try:
                if os.name == 'nt':
                    root.mkdir(mode=0o700)
                else:
                    parent_fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY)
                    current = root.__class__(root.anchor)
                    for part in root.parent.parts[1:]:
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=parent_fd)
                        os.close(parent_fd)
                        parent_fd = child
                        current = current / part
                        item = os.fstat(parent_fd)
                        if (item.st_dev, item.st_ino) != self._ancestor_ids[current]:
                            self._fail()
                    os.mkdir(root.name, mode=0o700, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                created = True
            except FileExistsError:
                pass
            finally:
                if parent_fd is not None:
                    os.close(parent_fd)
            self._check(root, directory=True)
            self._root_identity = self._identity(root)
            self._root_fd = None
            self._generation_fds = {}
            self._generation_ids = {}
            self._mutex_identity = None
            self._mutex_pin = None
            self._root_pin = None
            # Only a freshly created root can initialize an authority. A partial
            # initialization is a blocker; never repair it by inventing a lock.
            self._initializing = created
            if os.name != 'nt':
                self._root_pin = self._open_root()
            with self._locked():
                binding = root / 'policy.json'
                if created:
                    self._write(binding, self._seal('policy', self._storage_binding()))
                if self._read(binding, 'policy') != self._storage_binding():
                    self._fail()
                self._initializing = False
        except OSError:
            raise GateError('gate-storage-rejected') from None

    def __del__(self):
        # Lifetime pins prevent inode-number reuse from passing identity checks.
        for fd in (getattr(self, '_mutex_pin', None), getattr(self, '_root_pin', None),
                   *getattr(self, '_generation_fds', {}).values()):
            if fd is not None:
                os.close(fd)

    @staticmethod
    def _fail():
        raise GateError('gate-storage-rejected')

    @staticmethod
    def _identity(path):
        item = path.lstat()
        if not item.st_ino:
            FileWriterGate._fail()
        return item.st_dev, item.st_ino

    @staticmethod
    def _check(path, *, directory=False):
        item = path.lstat()
        FileWriterGate._check_item(item, directory=directory)
        return item

    @staticmethod
    def _check_item(item, *, directory=False):
        if (not item.st_ino
                or stat.S_ISLNK(item.st_mode)
                or getattr(item, 'st_file_attributes', 0) & 0x400
                or not (stat.S_ISDIR(item.st_mode) if directory else stat.S_ISREG(item.st_mode))
                or (not directory and item.st_nlink != 1)):
            raise GateError('gate-storage-rejected')
        if os.name != 'nt' and (item.st_uid != os.getuid() or
                stat.S_IMODE(item.st_mode) != (0o700 if directory else 0o600)):
            raise GateError('gate-storage-rejected')
        return item

    @staticmethod
    def _ancestors(path):
        for parent in (path, *path.parents):
            item = parent.lstat()
            if (not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode)
                    or getattr(item, 'st_file_attributes', 0) & 0x400):
                raise GateError('gate-storage-rejected')

    @staticmethod
    def _fsync_dir(path):
        if os.name != 'nt':
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)
                         | getattr(os, 'O_NOFOLLOW', 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        # Windows stdlib cannot fsync a directory. File fsync still applies;
        # power-loss rename durability requires host/filesystem guarantees.

    def _storage_binding(self):
        return dict(binding=self.policy._binding(), root=list(self._root_identity),
                    mutex=list(self._mutex_identity))

    def _open_root(self):
        # Walk every component with O_NOFOLLOW, relative to its pinned parent.
        # This also catches ancestor swaps between lstat and open.
        fd = os.open(self.root.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            # Compare each traversed ancestor as well as the final root.
            current = self.root.__class__(self.root.anchor)
            for part in self.root.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                current = current / part
                expected = (self._root_identity if current == self.root
                            else self._ancestor_ids[current])
                item = os.fstat(fd)
                if (item.st_dev, item.st_ino) != expected:
                    self._fail()
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != self._root_identity:
                self._fail()
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _live(self):
        self._ancestors(self.root.parent)
        for path, identity in self._ancestor_ids.items():
            if self._identity(path) != identity:
                self._fail()
        self._check(self.root, directory=True)
        if self._identity(self.root) != self._root_identity:
            self._fail()
        if self._root_fd is not None:
            fd = self._open_root()
            os.close(fd)
        if self._mutex_identity is not None:
            self._check(self.root / 'mutex')
            if self._identity(self.root / 'mutex') != self._mutex_identity:
                self._fail()
        for generation, identity in self._generation_ids.items():
            path = self.root / generation
            self._check(path, directory=True)
            if self._identity(path) != identity:
                self._fail()

    def _parent(self, path):
        self._live()
        if path.parent == self.root:
            return self._root_fd
        if path.parent.parent != self.root or not _hex(path.parent.name):
            self._fail()
        self._directory(path.parent.name)
        return self._generation_fds.get(path.parent.name)

    def _stat_record(self, path, parent):
        item = (os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if parent is not None else path.lstat())
        self._check_item(item)
        return item

    def _open_record(self, path, flags, parent):
        return os.open(path.name if parent is not None else path,
                       flags | getattr(os, 'O_NOFOLLOW', 0), 0o600,
                       **({'dir_fd': parent} if parent is not None else {}))

    @contextmanager
    def _locked(self):
        with self._thread_lock:
            fd = None
            locked = False
            try:
                self._live()
                if os.name != 'nt':
                    self._root_fd = self._open_root()
                path = self.root / 'mutex'
                flags = os.O_RDWR
                if self._initializing:
                    flags |= os.O_CREAT | os.O_EXCL
                fd = self._open_record(path, flags, self._root_fd)
                item = os.fstat(fd)
                self._check_item(item)
                identity = (item.st_dev, item.st_ino)
                if self._mutex_identity is None:
                    self._mutex_identity = identity
                    if os.name != 'nt':
                        self._mutex_pin = os.dup(fd)
                if identity != self._mutex_identity:
                    self._fail()
                self._live()
                # Authenticate the inode BEFORE waiting on it: a replacement
                # mutex must never serialize a second, independent authority.
                if not self._initializing:
                    if self._read(self.root / 'policy.json', 'policy') != self._storage_binding():
                        self._fail()
                if os.name == 'nt':
                    import msvcrt
                    if os.fstat(fd).st_size == 0:
                        os.write(fd, b'\0')
                        os.fsync(fd)
                    os.lseek(fd, 0, os.SEEK_SET)
                    import errno
                    import time
                    while True:
                        try:
                            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                            break
                        except OSError as error:
                            if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                                raise
                            time.sleep(0.01)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX)
                locked = True
                self._live()
                if not self._initializing:
                    if self._read(self.root / 'policy.json', 'policy') != self._storage_binding():
                        self._fail()
                yield
                self._live()
            except OSError:
                raise GateError('gate-storage-rejected') from None
            finally:
                if fd is not None:
                    try:
                        if locked:
                            if os.name == 'nt':
                                import msvcrt
                                os.lseek(fd, 0, os.SEEK_SET)
                                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                            else:
                                import fcntl
                                fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)
                if self._root_fd is not None:
                    os.close(self._root_fd)
                    self._root_fd = None

    def _seal(self, domain, payload):
        value = dict(version=1, domain='dev-workflow.writer-gate.' + domain,
                     policy=self.policy._binding(), payload=payload)
        value['mac'] = hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest()
        return value

    def _verify(self, value, domain):
        try:
            if (type(value) is not dict or set(value) != {'version', 'domain', 'policy', 'payload', 'mac'}
                    or type(value['version']) is not int or value['version'] != 1
                    or value['domain'] != 'dev-workflow.writer-gate.' + domain
                    or value['policy'] != self.policy._binding() or not _hex(value['mac'])):
                raise ValueError
            unsigned = {k: v for k, v in value.items() if k != 'mac'}
            mac = hmac.new(self._key, _canonical(unsigned), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, value['mac']):
                raise ValueError
            return value['payload']
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise GateError('gate-signature-rejected') from None

    def _read(self, path, domain):
        parent = self._parent(path)
        before = self._stat_record(path, parent)
        fd = self._open_record(path, os.O_RDONLY, parent)
        try:
            item = os.fstat(fd)
            self._check_item(item)
            if (item.st_dev, item.st_ino) != (before.st_dev, before.st_ino) or item.st_size > _MAX_RECORD:
                self._fail()
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(_MAX_RECORD + 1)
            value = json.loads(raw, object_pairs_hook=_pairs,
                               parse_constant=lambda _: self._fail())
            if _canonical(value) != raw:
                self._fail()
            after = self._stat_record(path, parent)
            if (after.st_dev, after.st_ino) != (item.st_dev, item.st_ino):
                self._fail()
            self._live()
            return self._verify(value, domain)
        except (ValueError, UnicodeError, RecursionError):
            raise GateError('gate-record-rejected') from None
        finally:
            os.close(fd)

    def _write(self, path, envelope):
        parent = self._parent(path)
        # Keep the reservation open until replacement; an unlinked inode cannot
        # be recycled and mistaken for our reservation.
        reservation = self._open_record(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, parent)
        temporary = path.parent / ('.pending-' + secrets.token_hex(32))
        fd = None
        try:
            reserved = os.fstat(reservation)
            self._check_item(reserved)
            self._sync_parent(path.parent, parent)
            fd = self._open_record(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, parent)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(_canonical(envelope))
                stream.flush()
                os.fsync(fd)
            self._live()
            current = self._stat_record(path, parent)
            pending = self._stat_record(temporary, parent)
            written = os.fstat(fd)
            if ((current.st_dev, current.st_ino) != (reserved.st_dev, reserved.st_ino)
                    or (pending.st_dev, pending.st_ino) != (written.st_dev, written.st_ino)):
                self._fail()
            if parent is None:
                # Windows CRT handles do not promise delete sharing. Close only
                # at the rename boundary, then recheck under host-protected ACLs.
                os.close(fd)
                fd = None
                os.close(reservation)
                reservation = None
                current = self._stat_record(path, parent)
                pending = self._stat_record(temporary, parent)
                if ((current.st_dev, current.st_ino) != (reserved.st_dev, reserved.st_ino)
                        or (pending.st_dev, pending.st_ino) != (written.st_dev, written.st_ino)):
                    self._fail()
                self._live()
                os.replace(temporary, path)
            else:
                os.replace(temporary.name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            self._sync_parent(path.parent, parent)
            installed = self._stat_record(path, parent)
            if (installed.st_dev, installed.st_ino) != (written.st_dev, written.st_ino):
                self._fail()
            self._live()
        finally:
            if fd is not None:
                os.close(fd)
            if reservation is not None:
                os.close(reservation)
        # Interrupted reservations and .pending files deliberately block reads.

    def _sync_parent(self, path, fd):
        if fd is None:
            self._fsync_dir(path)
        else:
            os.fsync(fd)

    def _directory(self, generation):
        if not _hex(generation):
            raise GateError('invalid-generation')
        self._live()
        path = self.root / generation
        item = self._check(path, directory=True)
        identity = (item.st_dev, item.st_ino)
        if generation in self._generation_ids and self._generation_ids[generation] != identity:
            self._fail()
        self._generation_ids[generation] = identity
        if self._root_fd is not None and generation not in self._generation_fds:
            fd = os.open(generation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=self._root_fd)
            self._generation_fds[generation] = fd
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != identity:
                self._fail()
        self._live()
        return path

    def _state(self, generation):
        directory = self._directory(generation)
        fd = self._generation_fds.get(generation)
        names = sorted(os.listdir(fd) if fd is not None else os.listdir(directory))
        self._live()
        if not names or names[0] != '00000000.json':
            self._fail()
        events = [n for n in names if re.fullmatch(r'[0-9]{8}\.json', n)]
        markers = [n for n in names if re.fullmatch(r'admitted-[0-9a-f]{64}', n)]
        if len(names) != len(events) + len(markers):
            self._fail()
        state = dict(head=_ZERO, count=0, closed=False, proof=None, attempts={}, admissions={})
        for index, name in enumerate(events):
            if name != f'{index:08d}.json':
                self._fail()
            event = self._read(directory / name, 'event')
            if (type(event) is not dict or set(event) != {'generation', 'directory', 'previous', 'kind', 'data'}
                    or event['generation'] != generation
                    or event['directory'] != list(self._generation_ids[generation])
                    or event['previous'] != state['head']):
                self._fail()
            kind, data = event['kind'], event['data']
            if index == 0:
                if (kind != 'open' or type(data) is not dict
                        or set(data) != {'request_hash', 'receipt_hash', 'operations'}
                        or not _hex(data['request_hash']) or not _hex(data['receipt_hash'])):
                    self._fail()
                state['operations'] = self._operations(tuple(tuple(x) for x in data['operations']))
            elif kind == 'prepare':
                if (state['closed'] or type(data) is not dict
                        or set(data) != {'ref', 'operation'} or not _hex(data['ref'])
                        or data['ref'] in state['attempts']
                        or tuple(data['operation']) not in state['operations']
                        or data['operation'] in list(state['attempts'].values())):
                    self._fail()
                state['attempts'][data['ref']] = data['operation']
            elif kind == 'admit':
                if (state['closed'] or type(data) is not str or data not in state['attempts']
                        or data in state['admissions']):
                    self._fail()
                state['admissions'][data] = dict(status='pending', head=_digest(event))
            elif kind == 'finish':
                if (type(data) is not dict or set(data) != {'ref', 'definitive', 'response_hash'}
                        or data['ref'] not in state['admissions']
                        or state['admissions'][data['ref']]['status'] != 'pending'
                        or type(data['definitive']) is not bool
                        or (not _hex(data['response_hash']) if data['definitive']
                            else data['response_hash'] is not None)):
                    self._fail()
                state['admissions'][data['ref']]['status'] = 'done' if data['definitive'] else 'unknown'
                state['admissions'][data['ref']]['response_hash'] = data['response_hash']
            elif kind == 'close':
                if state['closed'] or data is not None:
                    self._fail()
                state['closed'] = True
            elif kind == 'proof':
                if (not state['closed'] or state['proof'] is not None
                        or any(x['status'] != 'done' for x in state['admissions'].values())
                        or data != self._seal('proof', dict(generation=generation, head=state['head']))):
                    self._fail()
                state['proof'] = data
            else:
                self._fail()
            state['head'], state['count'] = _digest(event), index + 1
        if set(markers) != {'admitted-' + ref for ref in state['admissions']}:
            self._fail()
        for name in markers:
            if self._read(directory / name, 'admission') != dict(generation=generation, ref=name[9:]):
                self._fail()
        return state

    def _append(self, generation, state, kind, data):
        self._directory(generation)
        event = dict(generation=generation, directory=list(self._generation_ids[generation]),
                     previous=state['head'], kind=kind, data=data)
        self._write(self._directory(generation) / f'{state["count"]:08d}.json',
                    self._seal('event', event))
        return _digest(event)

    @staticmethod
    def _operations(operations):
        if type(operations) is not tuple or not 1 <= len(operations) <= 256:
            raise GateError('approved-operations-required')
        result = []
        for item in operations:
            if type(item) is not tuple or len(item) != 3:
                raise GateError('approved-operations-required')
            result.append(_operation(*item))
        if len(set(result)) != len(result):
            raise GateError('duplicate-approved-operation')
        return tuple(result)

    def open_generation(self, *, generation: str, request_hash: str, receipt_hash: str,
                        operations: tuple[tuple[str, str, str], ...]) -> WriterSession:
        approved = self._operations(operations)
        if not all(_hex(x) for x in (generation, request_hash, receipt_hash)):
            raise GateError('invalid-generation')
        with self._locked():
            directory = self.root / generation
            try:
                if self._root_fd is None:
                    directory.mkdir(mode=0o700)
                else:
                    os.mkdir(generation, mode=0o700, dir_fd=self._root_fd)
            except FileExistsError:
                raise GateError('generation-already-used') from None
            self._sync_parent(self.root, self._root_fd)
            self._append(generation, dict(head=_ZERO, count=0), 'open',
                         dict(request_hash=request_hash, receipt_hash=receipt_hash, operations=approved))
            session = WriterSession(generation, self)
            self._sessions[generation] = session
            return session

    def _prepare(self, session, method, path, body):
        if type(session) is not WriterSession or self._sessions.get(session.generation) is not session:
            raise GateError('unissued-session')
        if type(body) is not bytes or len(body) > 1024 * 1024:
            raise GateError('writer-body-rejected')
        operation = _operation(method, path, hashlib.sha256(body).hexdigest())
        with self._locked():
            state = self._state(session.generation)
            if state['closed'] or operation not in state['operations']:
                raise GateError('writer-operation-rejected')
            if list(operation) in state['attempts'].values():
                raise GateError('operation-already-prepared')
            attempt = Attempt(session.generation, secrets.token_hex(32), *operation)
            self._append(session.generation, state, 'prepare',
                         dict(ref=attempt.ref, operation=operation))
            self._attempts[attempt.ref] = attempt
            return attempt

    def admit(self, generation, attempt_ref, *, method, path, body: bytes,
              writer_certificate_sha256) -> AdmissionTicket:
        if (not _hex(attempt_ref) or type(body) is not bytes or len(body) > 1024 * 1024
                or writer_certificate_sha256 != self.policy.writer_certificate_sha256):
            raise GateError('writer-admission-rejected')
        operation = _operation(method, path, hashlib.sha256(body).hexdigest())
        with self._locked():
            state = self._state(generation)
            if (state['closed'] or state['attempts'].get(attempt_ref) != list(operation)
                    or attempt_ref in state['admissions']):
                raise GateError('writer-admission-rejected')
            self._write(self._directory(generation) / ('admitted-' + attempt_ref),
                        self._seal('admission', dict(generation=generation, ref=attempt_ref)))
            head = self._append(generation, state, 'admit', attempt_ref)
            ticket = AdmissionTicket(generation, attempt_ref, head)
            self._tickets[(generation, attempt_ref)] = ticket
            return ticket

    def finish(self, ticket, *, definitive: bool, response_hash: str | None):
        if (type(ticket) is not AdmissionTicket
                or self._tickets.get((ticket.generation, ticket.attempt_ref)) is not ticket
                or type(definitive) is not bool
                or (not _hex(response_hash) if definitive else response_hash is not None)):
            raise GateError('invalid-admission-ticket')
        with self._locked():
            state = self._state(ticket.generation)
            admission = state['admissions'].get(ticket.attempt_ref)
            if (admission is None or admission['head'] != ticket.admitted_head
                    or admission['status'] != 'pending'):
                raise GateError('admission-already-finished')
            self._append(ticket.generation, state, 'finish',
                         dict(ref=ticket.attempt_ref, definitive=definitive, response_hash=response_hash))

    def diagnose_generation(self, generation):
        """Read verified state without fencing writers or issuing authority.

        Codes describe operator actions, never permission to modify records or
        synthesize an upstream outcome. Unknown outcomes remain blocked.
        """
        with self._locked():
            state = self._state(generation)
            counts = {status: sum(item['status'] == status
                                  for item in state['admissions'].values())
                      for status in ('pending', 'unknown', 'done')}
            if counts['unknown']:
                blocker, next_step = 'upstream-outcome-unknown', 'investigate-upstream-outcome'
                summary = '上游写入结果未知；保持阻塞，核查上游证据，不得用超时或修改记录解除。'
            elif counts['pending']:
                blocker, next_step = 'upstream-write-pending', 'await-original-writer-completion'
                summary = '上游写入仍待完成；等待原写入者登记确定结果，重启不能接管或伪造完成。'
            elif not state['closed']:
                blocker, next_step = 'generation-open', 'close-generation'
                summary = '尚未关闭写入代次；由可信协调器执行关闭并重新验证静止状态。'
            else:
                blocker = None
                next_step = 'load-proof' if state['proof'] is not None else 'close-generation'
                summary = '写入代次已关闭且无未决写入；由可信协调器获取静止证明后继续独立授权流程。'
            return dict(closed=state['closed'], **counts, blocker=blocker, nextStep=next_step,
                        summary=summary, authorityGranted=False)

    def close_generation(self, generation) -> QuiescenceProof:
        with self._locked():
            state = self._state(generation)
            if not state['closed']:
                self._append(generation, state, 'close', None)
                state = self._state(generation)
            if any(x['status'] != 'done' for x in state['admissions'].values()):
                raise GateError('writer-not-quiescent')
            if state['proof'] is None:
                envelope = self._seal('proof', dict(generation=generation, head=state['head']))
                self._append(generation, state, 'proof', envelope)
                state = self._state(generation)
            return self._issue_proof(generation, state)

    def _issue_proof(self, generation, state):
        envelope = state['proof']
        proof = QuiescenceProof(generation, envelope['payload']['head'], _canonical(envelope).decode('ascii'))
        self._proofs[id(proof)] = proof
        return proof

    def load_proof(self, generation) -> QuiescenceProof:
        with self._locked():
            state = self._state(generation)
            if state['proof'] is None:
                raise GateError('writer-not-quiescent')
            return self._issue_proof(generation, state)

    def validate_proof(self, proof):
        if type(proof) is not QuiescenceProof or self._proofs.get(id(proof)) is not proof:
            raise GateError('unissued-quiescence-proof')
        with self._locked():
            state = self._state(proof.generation)
            if (state['proof'] is None or not state['closed']
                    or any(x['status'] != 'done' for x in state['admissions'].values())
                    or _canonical(state['proof']).decode('ascii') != proof.envelope_json
                    or state['proof']['payload']['head'] != proof.head):
                raise GateError('invalid-quiescence-proof')
            self._verify(state['proof'], 'proof')
            return True

    def info(self):
        with self._locked():
            return self._seal('info', dict(policy_hash=self.policy.identity_hash()))

    def verify_info(self, info):
        if self._verify(info, 'info') != dict(policy_hash=self.policy.identity_hash()):
            raise GateError('invalid-gate-info')
        return True
