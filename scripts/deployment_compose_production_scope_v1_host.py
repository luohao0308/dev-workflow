"""Durable exclusion for workers sharing one registered production host directory.

This journal coordinates cooperating writers. The embedding provisions the
directory once on persistent local storage and pins its identity and the journal
inode. A terminal digest binds the worker's verification to the journal; the
journal itself confers no Docker authority and does not verify that proof.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import weakref

from deployment_compose_witness_store import canonical, hex_value, pairs

if os.name == 'posix':
    import fcntl

MAX_BYTES = 1024 * 1024
_REPOSITORY = Path(__file__).resolve().parents[1]
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
_DAEMON = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}')
_FD_LOCK = threading.Lock()
_LOCK_FDS = set()
_LEASES = weakref.WeakKeyDictionary()


class ScopeBlocked(ValueError):
    """A deployment must stop before any further writes."""


@dataclass(frozen=True)
class ScopeRegistrationV1:
    root: Path
    root_identity: tuple[int, int]
    journal_identity: tuple[int, int]
    host_id: str
    project: str
    daemon_id: str


def _block(reason):
    raise ScopeBlocked(reason)


def _identity(info):
    return info.st_dev, info.st_ino


def _directory(path):
    if (os.name != 'posix' or not isinstance(path, Path) or not path.is_absolute()
            or '..' in path.parts or path.is_relative_to(_REPOSITORY)):
        _block('An absolute private production scope directory is required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            _block('Unsafe production scope directory')
        return fd, _identity(info)
    except BaseException:
        os.close(fd)
        raise


def _header(host_id, project, daemon_id):
    if (type(host_id) is not str or _NAME.fullmatch(host_id) is None
            or type(project) is not str or _NAME.fullmatch(project) is None
            or type(daemon_id) is not str or _DAEMON.fullmatch(daemon_id) is None):
        _block('Invalid registered deployment scope')
    return dict(version=1, host=host_id, project=project, daemon=daemon_id)


def _name(project):
    # One key per project within the registered host directory. Source, daemon,
    # host aliases and individual attempts cannot allocate alternative locks.
    return 'project-' + hashlib.sha256(project.encode('ascii')).hexdigest() + '.journal'


def _open_journal(root_fd, name, flags):
    with _FD_LOCK:
        fd = os.open(name, flags | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=root_fd)
        _LOCK_FDS.add(fd)
        return fd


def _close_journal(fd):
    with _FD_LOCK:
        _LOCK_FDS.remove(fd)
        os.close(fd)


def _after_fork():
    try:
        for fd in _LOCK_FDS:
            # flock is associated with the shared open file description. Close
            # the child's reference without issuing LOCK_UN on the parent's lock.
            try:
                os.close(fd)
            except OSError:
                continue
        _LOCK_FDS.clear()
    finally:
        _FD_LOCK.release()


if os.name == 'posix':
    os.register_at_fork(before=_FD_LOCK.acquire, after_in_parent=_FD_LOCK.release,
                        after_in_child=_after_fork)


def _file_info(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size > MAX_BYTES):
        _block('Unsafe production scope journal')
    return info


def _pin_pair(value):
    return type(value) is tuple and len(value) == 2 and all(
        type(item) is int and item >= 0 for item in value)


@contextmanager
def _bound_root(registration, fd):
    root_fd, identity = _directory(registration.root)
    try:
        info = _file_info(fd)
        current = os.stat(_name(registration.project), dir_fd=root_fd, follow_symlinks=False)
        if (identity != registration.root_identity
                or _identity(info) != registration.journal_identity
                or _identity(current) != registration.journal_identity):
            _block('Production scope path or inode changed')
        yield info
    finally:
        os.close(root_fd)


def _read(registration, fd):
    with _bound_root(registration, fd) as before:
        data = bytearray()
        while len(data) < before.st_size:
            chunk = os.pread(fd, min(65536, before.st_size - len(data)), len(data))
            if not chunk:
                _block('Incomplete production scope journal read')
            data.extend(chunk)
    with _bound_root(registration, fd) as after:
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            _block('Production scope journal changed during read')
    return bytes(data)


def _line(record):
    return canonical(record) + b'\n'


def _append(fd, data):
    if os.write(fd, data) != len(data):
        _block('Incomplete production scope journal write')
    os.fsync(fd)


def provision_scope(root, *, host_id, project, daemon_id):
    """Create an initial registry file once. Never use provisioning as recovery."""
    header = _header(host_id, project, daemon_id)
    root_fd, identity = _directory(root)
    try:
        fd = _open_journal(root_fd, _name(project), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            registration = ScopeRegistrationV1(
                root, identity, _identity(_file_info(fd)), host_id, project, daemon_id)
            with _bound_root(registration, fd):
                _append(fd, _line(header))
                os.fsync(root_fd)
            with _bound_root(registration, fd):
                return registration
        finally:
            _close_journal(fd)
    finally:
        os.close(root_fd)


def _history(raw, registration):
    header = _line(_header(registration.host_id, registration.project, registration.daemon_id))
    if not raw.startswith(header) or not raw.endswith(b'\n'):
        _block('Invalid production scope journal header or torn record')
    records = raw[len(header):].split(b'\n')[:-1]
    if len(records) % 2:
        _block('Unresolved production scope attempt')
    requests = set()
    try:
        for offset in range(0, len(records), 2):
            start, end = [json.loads(line, object_pairs_hook=pairs)
                          for line in records[offset:offset + 2]]
            request = start['request']
            generation = offset // 2 + 1
            proof = end['proof']
            terminal = dict(state=end['state'], generation=generation, request=request, proof=proof)
            if end['state'] == 'operator-reconciled':
                if not all(hex_value(end[field]) for field in ('evidence', 'observation', 'signer')):
                    _block('Invalid production reconciliation evidence')
                terminal.update(evidence=end['evidence'], observation=end['observation'], signer=end['signer'])
            elif end['state'] != 'verified':
                _block('Invalid production scope disposition')
            if (not hex_value(request) or request in requests or not hex_value(proof)
                    or records[offset] != canonical(dict(state='started', generation=generation,
                                                         request=request))
                    or records[offset + 1] != canonical(terminal)):
                _block('Invalid production scope transaction history')
            requests.add(request)
    except (ValueError, TypeError, KeyError, RecursionError):
        _block('Invalid production scope transaction history')
    return len(records) // 2 + 1, requests


@contextmanager
def _locked_pending_scope(registration, request_digest, *, writable=False):
    if (type(registration) is not ScopeRegistrationV1 or not hex_value(request_digest)
            or not _pin_pair(registration.root_identity) or not _pin_pair(registration.journal_identity)):
        _block('Independent production scope and request pins required')
    _header(registration.host_id, registration.project, registration.daemon_id)
    root_fd, identity = _directory(registration.root)
    try:
        if identity != registration.root_identity:
            _block('Production scope directory changed')
        fd = _open_journal(root_fd, _name(registration.project), os.O_RDWR if writable else os.O_RDONLY)
    finally:
        os.close(root_fd)
    try:
        with _bound_root(registration, fd):
            try:
                fcntl.flock(fd, (fcntl.LOCK_EX if writable else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            except BlockingIOError:
                _block('Production scope already has a live writer')
        raw = _read(registration, fd)
        if not raw.endswith(b'\n'):
            _block('Invalid production scope journal tail')
        prefix, _, tail = raw[:-1].rpartition(b'\n')
        generation, requests = _history(prefix + b'\n', registration)
        if request_digest in requests or tail != canonical(dict(
                state='started', generation=generation, request=request_digest)):
            _block('Production scope tail differs from requested attempt')
        if _read(registration, fd) != raw:
            _block('Production scope journal changed during review')
        yield fd, raw, dict(generation=generation, requestHash=request_digest,
                            journalDigest=hashlib.sha256(raw).hexdigest())
    finally:
        _close_journal(fd)


def inspect_pending_scope(registration, request_digest):
    """Read an exact, abandoned journal tail under the registered inode lock."""
    with _locked_pending_scope(registration, request_digest) as (_, _, pending):
        return pending


@dataclass
class _Session:
    fd: int
    owner: tuple[int, threading.Thread]
    registration: ScopeRegistrationV1
    request: str
    generation: int
    expected: bytes
    state: str = 'started'
    cleanup: weakref.finalize | None = None


def _session(lease):
    value = _LEASES.get(lease)
    if (type(lease) is not ScopeLeaseV1 or value is None
            or value.owner != (os.getpid(), threading.current_thread())):
        _block('Production scope lease belongs to its original owner')
    return value


def _check_started(value):
    if value.state != 'started':
        _block('Production scope attempt is no longer active')
    try:
        if _read(value.registration, value.fd) != value.expected:
            _block('Production scope journal differs from owned attempt')
    except BaseException:
        value.state = 'uncertain'
        raise


class ScopeLeaseV1:
    __slots__ = ('__weakref__',)

    def __init__(self):
        _block('Acquire a registered production scope')

    def __copy__(self):
        _block('Production scope leases cannot be copied')

    def __deepcopy__(self, memo):
        _block('Production scope leases cannot be copied')

    def __reduce_ex__(self, protocol):
        _block('Production scope leases cannot be serialized')

    @property
    def generation(self):
        return _session(self).generation

    def check(self):
        """Recheck the active journal immediately before each worker write."""
        _check_started(_session(self))

    def complete(self, terminal_proof_digest):
        """Record the original worker's terminal verification digest."""
        value = _session(self)
        if not hex_value(terminal_proof_digest):
            _block('Invalid terminal proof digest')
        _check_started(value)
        line = _line(dict(state='verified', generation=value.generation,
                          request=value.request, proof=terminal_proof_digest))
        value.state = 'uncertain'
        _append(value.fd, line)
        if _read(value.registration, value.fd) != value.expected + line:
            _block('Production scope completion could not be verified')
        value.state = 'verified'

    def close(self):
        value = _session(self)
        value.cleanup()
        del _LEASES[self]

    def __enter__(self):
        ScopeLeaseV1.check(self)
        return self

    def __exit__(self, exc_type, exc, traceback):
        ScopeLeaseV1.close(self)


def acquire_scope(registration, request_digest):
    """Acquire an existing scope and persist its start before returning."""
    if (type(registration) is not ScopeRegistrationV1 or not hex_value(request_digest)
            or not _pin_pair(registration.root_identity) or not _pin_pair(registration.journal_identity)):
        _block('Independent production scope and request pins required')
    _header(registration.host_id, registration.project, registration.daemon_id)
    root_fd, identity = _directory(registration.root)
    try:
        if identity != registration.root_identity:
            _block('Production scope directory changed')
        fd = _open_journal(root_fd, _name(registration.project), os.O_RDWR)
    finally:
        os.close(root_fd)
    try:
        with _bound_root(registration, fd):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _block('Production scope already has a live writer')
        raw = _read(registration, fd)
        generation, requests = _history(raw, registration)
        if request_digest in requests:
            _block('Production scope request already recorded')
        start = _line(dict(state='started', generation=generation, request=request_digest))
        finish = _line(dict(state='verified', generation=generation, request=request_digest,
                            proof='0' * 64))
        if len(raw) + len(start) + len(finish) > MAX_BYTES:
            _block('Production scope journal capacity exhausted')
        _append(fd, start)
        expected = raw + start
        if _read(registration, fd) != expected:
            _block('Production scope start could not be verified')
        lease = object.__new__(ScopeLeaseV1)
        pid = os.getpid()
        value = _Session(fd, (pid, threading.current_thread()), registration,
                         request_digest, generation, expected)
        _LEASES[lease] = value
        value.cleanup = weakref.finalize(lease, _close_owned_journal, pid, fd)
        return lease
    except BaseException:
        _close_journal(fd)
        raise


def _close_owned_journal(pid, fd):
    if os.getpid() == pid:
        _close_journal(fd)
