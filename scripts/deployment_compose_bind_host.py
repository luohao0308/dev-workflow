"""Read-only evidence for Docker bind files on the daemon host.

This helper must run beside the Docker socket, where bind source paths exist. It
never grants execution authority. A future GET-only gateway may expose only the
digest or a finite failure status, never the path, file bytes, or file metadata.
Directories, symlinks, and mutable file snapshots are outside the first profile.
Only host-controlled local regular files are supported: timeout checks happen
between syscalls and cannot interrupt a stalled filesystem syscall.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import stat
import time

_DOMAIN = b'dev-workflow:compose-bind-file:v1\0'
_CHUNK = 64 * 1024


class BindSnapshot:
    __slots__ = ('_path', '_identity', '_digest', '_expires', '_policy')

    def __init__(self, path: str, identity: tuple, digest: str, expires: float, policy: tuple):
        self._path, self._identity, self._digest, self._expires, self._policy = (
            path, identity, digest, expires, policy)

    @property
    def digest(self) -> str:
        return self._digest

    def __repr__(self) -> str:
        return '<BindSnapshot>'

    def __reduce__(self):
        raise TypeError('bind-snapshot-not-serializable')


def _valid_path(path: object) -> bool:
    if (type(path) is not str or not path.startswith('/') or '\x00' in path or
            any(part in ('.', '..') for part in path.split('/'))):
        return False
    try:
        return len(path.encode('utf-8')) <= 4096
    except UnicodeEncodeError:
        return False


def _identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _open_nofollow(path: str) -> int:
    if any(type(getattr(os, flag, None)) is not int
           for flag in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK')):
        raise ValueError('bind-platform-unsupported')
    parts = [part for part in path.split('/') if part]
    if not parts:
        raise ValueError('bind-file-unavailable')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                       dir_fd=directory)
    finally:
        os.close(directory)


def snapshot(path: str, *, allowed_paths: tuple[str, ...], key: bytes, max_bytes: int = 1024 * 1024,
             timeout_seconds: float = 2.0) -> BindSnapshot:
    """Hash one exact allowlisted regular file; fail closed on races or deadlines."""
    if (not _valid_path(path) or type(allowed_paths) is not tuple or
            not allowed_paths or any(not _valid_path(item) for item in allowed_paths) or
            len(allowed_paths) != len(set(allowed_paths)) or path not in allowed_paths or
            type(key) is not bytes or len(key) < 32 or
            type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024 or
            type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30):
        raise ValueError('invalid-bind-policy')
    deadline = time.monotonic() + timeout_seconds
    try:
        fd = _open_nofollow(path)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError('bind-file-not-regular')
            if before.st_size > max_bytes:
                raise ValueError('bind-file-too-large')
            path_bytes = path.encode('utf-8')
            hasher = hmac.new(key, _DOMAIN + len(path_bytes).to_bytes(4, 'big') + path_bytes,
                              hashlib.sha256)
            total = 0
            while True:
                if time.monotonic() >= deadline:
                    raise ValueError('bind-file-deadline')
                chunk = os.read(fd, min(_CHUNK, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError('bind-file-too-large')
                hasher.update(chunk)
            after = os.fstat(fd)
            if (_identity(before) != _identity(after) or total != after.st_size or
                    time.monotonic() >= deadline):
                raise ValueError('bind-file-changed')
            # A path replacement while the descriptor stayed open must also fail.
            verify = _open_nofollow(path)
            try:
                if _identity(os.fstat(verify)) != _identity(after):
                    raise ValueError('bind-file-changed')
            finally:
                os.close(verify)
            if time.monotonic() >= deadline:
                raise ValueError('bind-file-deadline')
            return BindSnapshot(path, _identity(after), hasher.hexdigest(), deadline,
                                (allowed_paths, max_bytes, float(timeout_seconds)))
        finally:
            os.close(fd)
    except OSError:
        raise ValueError('bind-file-unavailable') from None


def recheck(evidence: BindSnapshot, *, allowed_paths: tuple[str, ...], key: bytes,
            max_bytes: int = 1024 * 1024, timeout_seconds: float = 2.0) -> bool:
    """Return false after expiry, policy drift, replacement, or content change."""
    if (type(evidence) is not BindSnapshot or
            type(timeout_seconds) not in (int, float) or
            not 0 < timeout_seconds <= 30 or
            time.monotonic() >= evidence._expires or
            evidence._policy != (allowed_paths, max_bytes, float(timeout_seconds))):
        return False
    try:
        current = snapshot(evidence._path, allowed_paths=allowed_paths, key=key,
                           max_bytes=max_bytes, timeout_seconds=timeout_seconds)
    except ValueError:
        return False
    return (time.monotonic() < evidence._expires and
            current._identity == evidence._identity and current.digest == evidence.digest)
