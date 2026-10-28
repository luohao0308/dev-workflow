"""Private immutable recovery bytes. Integrity/retention only; no authority or freshness."""
import base64
import hashlib
import hmac
import json
import os
import re
import stat
import sys

MAX_PAYLOAD = 8 * 1024 * 1024
MAX_ENVELOPE = 12 * 1024 * 1024
_DOMAIN = b'compose-recovery-archive-v1\0'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


class ComposeRecoveryStore:
    """Preprovisioned Linux host-private archive; never repairs existing entries."""
    def __init__(self, root, *, key):
        self._fd = None
        try:
            path = os.fspath(root)
            if (sys.platform != 'linux' or type(path) is not str
                    or not path.startswith('/') or type(key) is not bytes or len(key) < 32
                    or any(x in ('.', '..') for x in path.split('/'))):
                raise ValueError()
            self._root = path
            self._key = key
            self._fd = self._open_root()
            self._identity = self._check_root(self._fd)
        except Exception:
            self.close()
            raise ValueError('recovery-store-rejected') from None

    def _open_root(self):
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in self._root.split('/'):
                if part:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
            return fd
        except Exception:
            os.close(fd)
            raise

    def _check_root(self, fd):
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
            raise ValueError()
        return info.st_dev, info.st_ino

    def _validate_root(self):
        if self._fd is None or self._check_root(self._fd) != self._identity:
            raise ValueError()
        fd = self._open_root()
        try:
            if self._check_root(fd) != self._identity:
                raise ValueError()
        finally:
            os.close(fd)

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __del__(self):
        self.close()

    def _envelope(self, payload):
        body = {'schemaVersion': 1, 'kind': 'compose-recovery-archive',
                'payload': base64.b64encode(payload).decode('ascii')}
        return _canonical({**body, 'hmac': hmac.new(self._key, _DOMAIN + _canonical(body), hashlib.sha256).hexdigest()})

    def _read(self, reference):
        fd = os.open(reference, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > MAX_ENVELOPE):
                raise ValueError()
            chunks, size = [], 0
            while True:
                chunk = os.read(fd, min(65536, MAX_ENVELOPE + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ENVELOPE:
                    raise ValueError()
                chunks.append(chunk)
            raw = b''.join(chunks)
            if hashlib.sha256(raw).hexdigest() != reference:
                raise ValueError()
            value = json.loads(raw)
            if type(value) is not dict or set(value) != {'schemaVersion', 'kind', 'payload', 'hmac'}:
                raise ValueError()
            payload = base64.b64decode(value['payload'], validate=True)
            if len(payload) > MAX_PAYLOAD or not hmac.compare_digest(raw, self._envelope(payload)):
                raise ValueError()
            return raw, payload
        finally:
            os.close(fd)

    def put(self, payload):
        """Return sha256 reference of authenticated canonical envelope."""
        try:
            if type(payload) is not bytes or len(payload) > MAX_PAYLOAD:
                raise ValueError()
            self._validate_root()
            raw = self._envelope(payload)
            reference = hashlib.sha256(raw).hexdigest()
            try:
                fd = os.open(reference, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self._fd)
            except FileExistsError:
                if self._read(reference)[0] != raw:
                    raise ValueError()
            else:
                try:
                    os.fchmod(fd, 0o600)
                    remaining = memoryview(raw)
                    while remaining:
                        count = os.write(fd, remaining)
                        if count <= 0:
                            raise ValueError()
                        remaining = remaining[count:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(self._fd)
            self._validate_root()
            if self._read(reference)[0] != raw:
                raise ValueError()
            return reference
        except Exception:
            raise ValueError('recovery-store-rejected') from None

    def get(self, reference):
        try:
            if type(reference) is not str or re.fullmatch('[0-9a-f]{64}', reference) is None:
                raise ValueError()
            self._validate_root()
            payload = self._read(reference)[1]
            self._validate_root()
            return payload
        except Exception:
            raise ValueError('recovery-store-rejected') from None
