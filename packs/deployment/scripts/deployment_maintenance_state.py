"""Private maintenance storage primitives. No authority objects are constructed.

Callers own transaction validation and lock ordering (target, history, gate).
Transition requires the corresponding fixed mutex held by the caller. A latch
in that mutex makes missing metadata fail closed after maintenance begins.
Privileged rollback of an entire filesystem is outside this storage contract.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading


class MaintenanceStateError(ValueError):
    pass


@dataclass(frozen=True)
class _Binding:
    root: Path
    policy_hash: str
    key: bytes = field(repr=False)
    kind: str
    root_identity: tuple
    mutex_identity: tuple


_LATCH = b'\x00maintenance-v1\n'
_MARKER = 'maintenance.json'
_HELD = threading.local()
_HEX = re.compile(r'[0-9a-f]{64}\Z')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _identity(path, directory=False):
    info = path.lstat()
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or getattr(info, 'st_file_attributes', 0) & 0x400
            or (not directory and info.st_nlink != 1)
            or (os.name == 'posix' and (info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)))):
        raise MaintenanceStateError('maintenance-private-storage-required')
    return info.st_dev, info.st_ino


def _ancestors(root):
    if not isinstance(root, Path) or not root.is_absolute() or '..' in root.parts:
        raise MaintenanceStateError('maintenance-private-storage-required')
    for path in root.parents:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise MaintenanceStateError('maintenance-private-storage-required')


def _mutex_name(kind):
    if kind not in ('store', 'gate'):
        raise MaintenanceStateError('maintenance-kind-invalid')
    return 'history.lock' if kind == 'store' else 'mutex'


def _binding(root, policy_hash, key, kind):
    _ancestors(root)
    if type(key) is not bytes or len(key) < 32 or type(policy_hash) is not str or not _HEX.fullmatch(policy_hash):
        raise MaintenanceStateError('maintenance-policy-invalid')
    return _Binding(root, policy_hash, key, kind, _identity(root, True),
                    _identity(root / _mutex_name(kind)))


def _check(binding):
    actual = _binding(binding.root, binding.policy_hash, binding.key, binding.kind)
    if actual != binding:
        raise MaintenanceStateError('maintenance-storage-identity-changed')


@contextmanager
def _directory(root, *, private=True):
    _ancestors(root)
    def identity_now():
        if private:
            return _identity(root, True)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise MaintenanceStateError('maintenance-private-storage-required')
        return info.st_dev, info.st_ino
    identity = identity_now()
    fd = None
    try:
        if os.name == 'posix':
            fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            for part in root.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != identity:
                raise MaintenanceStateError('maintenance-storage-identity-changed')
        yield fd
        _ancestors(root)
        if identity_now() != identity:
            raise MaintenanceStateError('maintenance-storage-identity-changed')
    finally:
        if fd is not None:
            os.close(fd)


def _open_at(root, directory, name, flags):
    return os.open(name if directory is not None else root / name,
                   flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600,
                   **({'dir_fd': directory} if directory is not None else {}))


def _stat_at(root, directory, name):
    return (os.stat(name, dir_fd=directory, follow_symlinks=False)
            if directory is not None else (root / name).lstat())


def _bytes(path, maximum):
    with _directory(path.parent) as directory:
        identity = _identity(path)
        fd = _open_at(path.parent, directory, path.name, os.O_RDONLY)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (info.st_dev, info.st_ino) != identity:
                raise MaintenanceStateError('maintenance-storage-identity-changed')
            value = stream.read(maximum + 1)
            after = _stat_at(path.parent, directory, path.name)
            if (after.st_dev, after.st_ino) != identity:
                raise MaintenanceStateError('maintenance-storage-identity-changed')
        if len(value) > maximum:
            raise MaintenanceStateError('maintenance-record-too-large')
        return value


def _sync(root):
    # Parent directories need not themselves be mode 0700.
    if os.name == 'posix':
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _write(root, name, value):
    if type(name) is not str or Path(name).name != name or name in ('.', '..'):
        raise MaintenanceStateError('maintenance-record-name-invalid')
    with _directory(root) as directory:
        temporary = '.maintenance-' + secrets.token_hex(16)
        fd = _open_at(root, directory, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
            identity = os.fstat(stream.fileno())
        if directory is not None:
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        else:
            os.replace(root / temporary, root / name)
        after = _stat_at(root, directory, name)
        if (after.st_dev, after.st_ino) != (identity.st_dev, identity.st_ino):
            raise MaintenanceStateError('maintenance-storage-identity-changed')


def _holder(binding):
    holder = getattr(_HELD, 'values', {}).get((binding.root_identity, binding.kind))
    if holder is None or holder[:2] != (os.getpid(), threading.get_ident()):
        raise MaintenanceStateError('maintenance-lock-required')
    fd = holder[2]
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino) != binding.mutex_identity:
        raise MaintenanceStateError('maintenance-lock-identity-changed')
    _check(binding)
    return fd


def _has_holder(binding):
    return (binding.root_identity, binding.kind) in getattr(_HELD, 'values', {})


@contextmanager
def _held(binding, fd):
    """Register an already acquired kernel lock, only for internal lock owners."""
    _check(binding)
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino) != binding.mutex_identity:
        raise MaintenanceStateError('maintenance-lock-identity-changed')
    values = getattr(_HELD, 'values', None)
    if values is None:
        values = _HELD.values = {}
    index = (binding.root_identity, binding.kind)
    if index in values:
        raise MaintenanceStateError('maintenance-lock-non-reentrant')
    values[index] = (os.getpid(), threading.get_ident(), fd)
    try:
        yield
    finally:
        del values[index]


def _latch(binding):
    fd = _holder(binding)
    os.lseek(fd, 0, os.SEEK_SET)
    return os.read(fd, 65)


def _payload(binding, transaction, phase):
    return dict(version=1, kind=binding.kind, policyHash=binding.policy_hash,
                root=list(binding.root_identity), mutex=list(binding.mutex_identity),
                transaction=transaction, phase=phase)


def _seal(binding, payload):
    return dict(payload=payload, mac=hmac.new(binding.key, b'deployment-maintenance-v1\0' + _canonical(payload), hashlib.sha256).hexdigest())


def _read(binding):
    _check(binding)
    if not _has_holder(binding):
        with _locked_binding(binding):
            return _read(binding)
    latch = _latch(binding)
    marker = binding.root / _MARKER
    if latch in (b'', b'\0') and not os.path.lexists(marker):
        return None
    if latch != _LATCH:
        raise MaintenanceStateError('maintenance-latch-invalid')
    try:
        raw = _bytes(marker, 4096)
        value = json.loads(raw)
        payload = value['payload']
        if (raw != _canonical(value) or set(value) != {'payload', 'mac'}
                or type(value['mac']) is not str
                or not hmac.compare_digest(value['mac'], _seal(binding, payload)['mac'])
                or type(payload['transaction']) is not str or not _HEX.fullmatch(payload['transaction'])
                or payload['phase'] not in ('pending', 'active', 'retired')
                or payload != _payload(binding, payload['transaction'], payload['phase'])):
            raise ValueError
        return payload
    except (OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        raise MaintenanceStateError('maintenance-record-invalid') from None


def _guard(root, policy_hash, key, kind):
    """Legacy roots without a latch remain valid; partial metadata never does."""
    mutex = root / _mutex_name(kind)
    if not os.path.lexists(mutex):
        if os.path.lexists(root / _MARKER):
            raise MaintenanceStateError('maintenance-mutex-missing')
        return
    state = _read(_binding(root, policy_hash, key, kind))
    if state is not None and state['phase'] != 'active':
        raise MaintenanceStateError('maintenance-authority-unavailable')


def _transition(binding, transaction, phase):
    """Caller holds fixed mutex; activation evidence belongs to orchestrator."""
    if type(transaction) is not str or not _HEX.fullmatch(transaction):
        raise MaintenanceStateError('maintenance-transaction-invalid')
    _holder(binding)
    state = _read(binding)
    if state is not None and state['phase'] == 'retired':
        if state['transaction'] == transaction and phase == 'retired':
            return state
        raise MaintenanceStateError('maintenance-permanently-retired')
    if phase == 'active':
        if state is None or state['transaction'] != transaction or state['phase'] not in ('pending', 'active'):
            raise MaintenanceStateError('maintenance-activation-mismatch')
    elif phase == 'retired':
        if state is not None and state['phase'] != 'active':
            raise MaintenanceStateError('maintenance-retirement-mismatch')
    else:
        raise MaintenanceStateError('maintenance-transition-invalid')
    # Latch first: a crash before the signed marker conservatively blocks use.
    fd = _holder(binding)
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, _LATCH)
    os.ftruncate(fd, len(_LATCH))
    os.fsync(fd)
    payload = _payload(binding, transaction, phase)
    _write(binding.root, _MARKER, _canonical(_seal(binding, payload)))
    _check(binding)
    return payload


def _publish_pending(parent, directory, source, destination):
    """Atomic publication without replacing any existing destination."""
    if os.name == 'nt':
        os.rename(parent / source, parent / destination)
        return
    if directory is None or sys.platform not in ('linux', 'darwin'):
        raise MaintenanceStateError('maintenance-atomic-publication-unsupported')
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    name, flags = ('renameat2', 1) if sys.platform == 'linux' else ('renameatx_np', 4)
    try:
        rename = getattr(libc, name)
    except AttributeError:
        raise MaintenanceStateError('maintenance-atomic-publication-unsupported') from None
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(directory, os.fsencode(source), directory, os.fsencode(destination), flags) != 0:
        raise MaintenanceStateError('maintenance-atomic-publication-rejected')


def _initialize_pending(root, policy, key, kind, transaction):
    """Only publish fully durable pending state, using atomic no-replace rename."""
    _ancestors(root)
    if os.path.lexists(root) or type(transaction) is not str or not _HEX.fullmatch(transaction):
        raise MaintenanceStateError('maintenance-destination-invalid')
    with _directory(root.parent, private=False) as parent:
        stage = root.parent / ('.maintenance-pending-' + secrets.token_hex(16))
        if parent is not None:
            os.mkdir(stage.name, mode=0o700, dir_fd=parent)
        else:
            stage.mkdir(mode=0o700)
        _write(stage, _mutex_name(kind), _LATCH)
        binding = _binding(stage, policy.identity_hash(), key, kind)
        _write(stage, _MARKER, _canonical(_seal(binding, _payload(binding, transaction, 'pending'))))
        if kind == 'gate':
            value = dict(version=1, domain='dev-workflow.writer-gate.policy', policy=policy._binding(),
                         payload=dict(binding=policy._binding(), root=list(binding.root_identity), mutex=list(binding.mutex_identity)))
            value['mac'] = hmac.new(key, _canonical(value), hashlib.sha256).hexdigest()
            _write(stage, 'policy.json', _canonical(value))
        _check(binding)
        try:
            _publish_pending(root.parent, parent, stage.name, root.name)
        except (OSError, MaintenanceStateError):
            # No retry or fallback: inspect possible publication once. Even an
            # ambiguous outcome only leaves the authenticated destination pending.
            if os.path.lexists(root):
                if _identity(root, True) == binding.root_identity:
                    published = _binding(root, policy.identity_hash(), key, kind)
                    if _read(published) != _payload(published, transaction, 'pending'):
                        raise MaintenanceStateError('maintenance-publication-state-invalid') from None
            raise MaintenanceStateError('maintenance-atomic-publication-rejected') from None
        if parent is not None:
            os.fsync(parent)
        published = _binding(root, policy.identity_hash(), key, kind)
        if published.root_identity != binding.root_identity or published.mutex_identity != binding.mutex_identity:
            raise MaintenanceStateError('maintenance-publication-identity-changed')
        return published



@contextmanager
def _locked_binding(binding):
    """Raw lock usable for exact resume even when public authority is fenced."""
    _check(binding)
    with _directory(binding.root) as directory:
        fd = _open_at(binding.root, directory, _mutex_name(binding.kind), os.O_RDWR)
        locked = False
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != binding.mutex_identity:
                raise MaintenanceStateError('maintenance-storage-identity-changed')
            if os.name == 'posix':
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                import msvcrt
                import errno
                import time
                while True:
                    try:
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as exc:
                        if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                            raise
                        time.sleep(0.05)
            locked = True
            _check(binding)
            with _held(binding, fd):
                yield
        finally:
            if locked:
                if os.name == 'posix':
                    fcntl.flock(fd, fcntl.LOCK_UN)
                else:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            os.close(fd)


def _complete_latched_retirement(binding, transaction):
    """Exact-resume primitive after independently authenticated intent checks.

    Caller holds the fixed mutex and proves the original transaction/inventory.
    This can only finish a retirement, never initialize or activate authority.
    """
    _check(binding)
    if (type(transaction) is not str or not _HEX.fullmatch(transaction)
            or _latch(binding) != _LATCH):
        raise MaintenanceStateError('maintenance-resume-mismatch')
    if os.path.lexists(binding.root / _MARKER):
        return _transition(binding, transaction, 'retired')
    payload = _payload(binding, transaction, 'retired')
    _write(binding.root, _MARKER, _canonical(_seal(binding, payload)))
    return _read(binding)
