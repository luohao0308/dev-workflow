"""One-scope POSIX CAS witness outside the subject Linux rollback domain.

This authenticates local state and persists reservations before acknowledgement.
It does not resist rollback of this witness itself or grant production approval.
The host provisions a private directory and supplies the key separately.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import threading
import uuid

if os.name == 'posix':
    import fcntl

ZERO = '0' * 64
MAX_RESERVATIONS = 4096
MAX_BYTES = 2 * 1024 * 1024
DOMAIN = b'dev-workflow:compose-independent-witness:v1\0'
HEX = re.compile('[0-9a-f]{64}\\Z')
BINDING_FIELDS = {'scopeHash', 'epoch', 'generation', 'policyHash'}


def fail():
    raise ValueError('compose-witness-rejected')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def hex_value(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def binding_value(value):
    if type(value) is not dict or set(value) != BINDING_FIELDS or not all(hex_value(x) for x in value.values()):
        fail()
    return deepcopy(value)


def pairs(items):
    result = {}
    for k, v in items:
        if k in result:
            fail()
        result[k] = v
    return result


class ComposeWitnessStore:
    """Preprovisioned private directory; registration is never reset or repaired."""
    def __init__(self, root, *, key):
        self._dir = self._lock = None
        try:
            if (os.name != 'posix' or not isinstance(root, Path) or not root.is_absolute()
                    or '..' in root.parts or '.' in root.parts
                    or root.is_relative_to(Path(__file__).resolve().parents[1])
                    or type(key) is not bytes or len(key) < 32):
                fail()
            self.root, self._key = root, key
            self._thread = threading.RLock()
            self._dir = self._open_root()
            self._root_id = self._directory_id(self._dir)
            self._lock = os.open('witness.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                                 0o600, dir_fd=self._dir)
            self._lock_id = self._file_id(self._lock)
            os.fsync(self._dir)
        except Exception:
            self.close()
            raise ValueError('compose-witness-rejected') from None

    def _open_root(self):
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in self.root.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _directory_id(fd):
        s = os.fstat(fd)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
            fail()
        return s.st_dev, s.st_ino

    @staticmethod
    def _file_id(fd):
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid()
                or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1):
            fail()
        return s.st_dev, s.st_ino

    def _validate_paths(self):
        if self._dir is None or self._directory_id(self._dir) != self._root_id:
            fail()
        fresh = self._open_root()
        try:
            if self._directory_id(fresh) != self._root_id:
                fail()
        finally:
            os.close(fresh)
        fd = os.open('witness.lock', os.O_RDWR | os.O_NOFOLLOW, dir_fd=self._dir)
        try:
            if self._file_id(fd) != self._lock_id or self._file_id(self._lock) != self._lock_id:
                fail()
        finally:
            os.close(fd)
        if set(os.listdir(self._dir)) - {'witness.lock', 'state.json'}:
            fail()  # Includes an unacknowledged failed temporary write.

    @contextmanager
    def _locked(self):
        try:
            with self._thread:
                self._validate_paths()
                fcntl.flock(self._lock, fcntl.LOCK_EX)
                try:
                    self._validate_paths()
                    yield
                    self._validate_paths()
                finally:
                    fcntl.flock(self._lock, fcntl.LOCK_UN)
        except Exception:
            raise ValueError('compose-witness-rejected') from None

    def close(self):
        for name in ('_lock', '_dir'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd); setattr(self, name, None)

    def __del__(self):
        self.close()

    def _seal(self, state):
        return canonical({'state': state, 'hmac': hmac.new(self._key, DOMAIN + canonical(state), hashlib.sha256).hexdigest()})

    def _read(self):
        fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._dir)
        try:
            self._file_id(fd)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                fail()
            value = json.loads(raw, object_pairs_hook=pairs)
            if type(value) is not dict or set(value) != {'state', 'hmac'}:
                fail()
            state = value['state']
            if (type(state) is not dict or set(state) != {'schemaVersion', 'binding', 'seq', 'head', 'usedNonces'}
                    or type(state['schemaVersion']) is not int or state['schemaVersion'] != 1
                    or type(state['seq']) is not int or not 0 <= state['seq'] <= MAX_RESERVATIONS
                    or not hex_value(state['head']) or type(state['usedNonces']) is not list
                    or len(state['usedNonces']) != state['seq']):
                fail()
            binding_value(state['binding'])
            seen, heads = set(), set()
            for nonce in state['usedNonces']:
                if (type(nonce) is not dict or set(nonce) != {'bootNonce', 'rpcNonce', 'nextHead'}
                        or not all(hex_value(x) for x in nonce.values()) or nonce['rpcNonce'] in seen
                        or nonce['nextHead'] == ZERO or nonce['nextHead'] in heads):
                    fail()
                seen.add(nonce['rpcNonce']); heads.add(nonce['nextHead'])
            if ((state['seq'] == 0) != (state['head'] == ZERO)
                    or state['usedNonces'] and state['usedNonces'][-1]['nextHead'] != state['head']
                    or not hmac.compare_digest(raw, self._seal(state))):
                fail()
            return state
        finally:
            os.close(fd)

    def _persist(self, state):
        raw = self._seal(state)
        if len(raw) > MAX_BYTES:
            fail()
        name = '.pending-' + uuid.uuid4().hex
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._dir)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(raw); stream.flush(); os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(name, 'state.json', src_dir_fd=self._dir, dst_dir_fd=self._dir)
        os.fsync(self._dir)

    @staticmethod
    def _view(state):
        return {'binding': deepcopy(state['binding']), 'seq': state['seq'], 'head': state['head'],
                'authorityGranted': False, 'productionReady': False}

    def register_once(self, binding):
        binding = binding_value(binding)
        with self._locked():
            if 'state.json' in os.listdir(self._dir):
                fail()
            state = {'schemaVersion': 1, 'binding': binding, 'seq': 0, 'head': ZERO, 'usedNonces': []}
            self._persist(state)
            return self._view(state)

    def read(self, binding):
        binding = binding_value(binding)
        with self._locked():
            state = self._read()
            if canonical(state['binding']) != canonical(binding):
                fail()
            return self._view(state)

    def check(self, binding, *, expected_seq, expected_head):
        if type(expected_seq) is not int or not 0 <= expected_seq <= MAX_RESERVATIONS or not hex_value(expected_head):
            fail()
        value = self.read(binding)
        if value['seq'] != expected_seq or value['head'] != expected_head:
            fail()
        return value

    def reserve(self, binding, *, expected_seq, expected_head, next_head, event_digest, boot_nonce, rpc_nonce):
        binding = binding_value(binding)
        if (type(expected_seq) is not int or not 0 <= expected_seq < MAX_RESERVATIONS
                or not all(hex_value(x) for x in (expected_head, next_head, event_digest, boot_nonce, rpc_nonce))
                or next_head != event_digest or next_head in (expected_head, ZERO)):
            fail()
        with self._locked():
            state = self._read()
            if (canonical(state['binding']) != canonical(binding) or state['seq'] != expected_seq
                    or state['head'] != expected_head
                    or any(x['rpcNonce'] == rpc_nonce or x['nextHead'] == next_head for x in state['usedNonces'])):
                fail()
            state['seq'] += 1; state['head'] = next_head
            state['usedNonces'].append({'bootNonce': boot_nonce, 'rpcNonce': rpc_nonce, 'nextHead': next_head})
            self._persist(state)
            return dict(self._view(state), previousHead=expected_head, eventDigest=event_digest,
                        bootNonce=boot_nonce, rpcNonce=rpc_nonce)
