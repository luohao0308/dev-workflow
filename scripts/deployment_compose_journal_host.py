"""Host-private phase evidence for a Compose batch; never an execution authority.

The caller must hold its writer gate and verify the plan independently. A pending
attempt is deliberately irreversible here: inspection/recovery needs a separate
fresh decision, not a retry inferred from this journal.
The HMAC head cannot detect restoration of an older valid event prefix together
with its old head. A separate writer-gate history/monotonic anchor is required
before these records can support replay-safe recovery or actual writes.
"""
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat


_HEX = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[A-Za-z0-9_-]{1,80}\Z')
_MAX_EVENTS = 512


class JournalError(ValueError):
    pass


def _fail():
    raise JournalError('journal-rejected')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


class BatchJournal:
    def __init__(self, root: Path, plan_hash: str, request_hash: str,
                 action_digests: tuple[str, ...], key: bytes):
        if (not isinstance(root, Path) or not root.is_absolute() or '..' in root.parts
                or not isinstance(plan_hash, str) or not _HEX.fullmatch(plan_hash)
                or not isinstance(request_hash, str) or not _HEX.fullmatch(request_hash)
                or type(action_digests) is not tuple or not 1 <= len(action_digests) <= 256
                or any(type(x) is not str or not _HEX.fullmatch(x) for x in action_digests)
                or type(key) is not bytes or len(key) < 32 or os.name == 'nt'):
            _fail()
        self.root, self.plan_hash, self.request_hash = root, plan_hash, request_hash
        self.action_digests, self._key = action_digests, key
        self._actions_hash = hashlib.sha256(_canonical(action_digests)).hexdigest()
        self._dir = None
        try:
            # All ancestors must be real directories; the root must already be
            # provisioned privately by the trusted host (never created by a plan).
            for ancestor in (root, *root.parents):
                s = ancestor.lstat()
                if not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode):
                    _fail()
            self._dir = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            s = os.fstat(self._dir)
            if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
                _fail()
            self._root_id = (s.st_dev, s.st_ino)
            # A pre-provisioned lock file is unnecessary: it is pinned after creation.
            try:
                fd = os.open('journal.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                             0o600, dir_fd=self._dir)
                os.fsync(self._dir)
            except OSError:
                _fail()
            try:
                s = os.fstat(fd)
                if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or
                        s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600):
                    _fail()
                self._lock_id = (s.st_dev, s.st_ino)
                self._lock_fd = fd
            except BaseException:
                os.close(fd)
                raise
        except (OSError, JournalError):
            self.close()
            _fail()

        try:
            if 'journal.head' not in os.listdir(self._dir):
                if any(n != 'journal.lock' for n in os.listdir(self._dir)):
                    _fail()
                self._write_file('journal.head', self._head(0, '0' * 64), replace=False)
        except (OSError, JournalError):
            self.close()
            _fail()

    def close(self):
        for attr in ('_lock_fd', '_dir'):
            fd = getattr(self, attr, None)
            if fd is not None:
                os.close(fd)
                setattr(self, attr, None)

    def __del__(self):
        self.close()

    def _check_root(self):
        s = self.root.lstat()
        if (not stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode)
                or (s.st_dev, s.st_ino) != self._root_id):
            _fail()
        s = os.stat('journal.lock', dir_fd=self._dir, follow_symlinks=False)
        if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or
                (s.st_dev, s.st_ino) != self._lock_id or
                s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600):
            _fail()

    def _scan(self):
        self._check_root()
        names = os.listdir(self._dir)
        event_names = [n for n in names if n not in ('journal.lock', 'journal.head')]
        if len(event_names) > _MAX_EVENTS or any(not re.fullmatch(r'[0-9]{4}\.json', n) for n in event_names):
            _fail()
        if sorted(event_names) != [f'{i:04d}.json' for i in range(len(event_names))]:
            _fail()
        previous = '0' * 64
        completed, pending = [], None
        for seq, name in enumerate(sorted(event_names)):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._dir)
            try:
                s = os.fstat(fd)
                if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid()
                        or stat.S_IMODE(s.st_mode) != 0o600 or s.st_size > 2048):
                    _fail()
                body = os.read(fd, 2049)
            finally:
                os.close(fd)
            try:
                record = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                _fail()
            if type(record) is not dict or set(record) != {'event', 'mac'}:
                _fail()
            event, mac = record['event'], record['mac']
            if (type(event) is not dict or type(mac) is not str or not _HEX.fullmatch(mac)
                    or _canonical(record) != body or event.get('seq') != seq
                    or event.get('plan') != self.plan_hash
                    or event.get('request') != self.request_hash
                    or event.get('actions') != self._actions_hash
                    or event.get('previous') != previous):
                _fail()
            expected = hmac.new(self._key, b'dev-workflow-compose-journal-v1\0' + _canonical(event), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, expected):
                _fail()
            previous = mac
            kind, index, digest, attempt = (event.get(k) for k in ('kind', 'index', 'action', 'attempt'))
            if (type(index) is not int or type(digest) is not str or not _HEX.fullmatch(digest)
                    or type(attempt) is not str or not _ID.fullmatch(attempt)):
                _fail()
            if index >= len(self.action_digests) or digest != self.action_digests[index]:
                _fail()
            if kind == 'attempt':
                if set(event) != {'seq', 'plan', 'request', 'actions', 'previous', 'kind', 'index', 'action', 'attempt'} or pending is not None or index != len(completed):
                    _fail()
                pending = (index, digest, attempt)
            elif kind == 'complete':
                if (set(event) != {'seq', 'plan', 'request', 'actions', 'previous', 'kind', 'index', 'action', 'attempt', 'response'}
                        or pending != (index, digest, attempt)
                        or type(event['response']) is not str or not _HEX.fullmatch(event['response'])):
                    _fail()
                completed.append(dict(index=index, action=digest, attempt=attempt, response=event['response']))
                pending = None
            else:
                _fail()
        fd = os.open('journal.head', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._dir)
        try:
            s = os.fstat(fd)
            if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid()
                    or stat.S_IMODE(s.st_mode) != 0o600 or s.st_size > 512):
                _fail()
            head = os.read(fd, 513)
        finally:
            os.close(fd)
        if head != self._head(len(event_names), previous):
            _fail()
        return completed, pending, previous, len(event_names)

    def _head(self, count, tail):
        state = {'count': count, 'tail': tail, 'plan': self.plan_hash,
                 'request': self.request_hash, 'actions': self._actions_hash}
        mac = hmac.new(self._key, b'dev-workflow-compose-journal-head-v1\0' + _canonical(state), hashlib.sha256).hexdigest()
        return _canonical({'state': state, 'mac': mac})

    def _write_file(self, name, body, *, replace):
        target = 'journal.head.tmp' if replace else name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self._dir)
        try:
            if os.write(fd, body) != len(body):
                _fail()
            os.fsync(fd)
        finally:
            os.close(fd)
        if replace:
            os.replace(target, name, src_dir_fd=self._dir, dst_dir_fd=self._dir)
        os.fsync(self._dir)

    def snapshot(self):
        fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        try:
            done, pending, _, _ = self._scan()
            return {'completed': done,
                    'unknown': (dict(index=pending[0], action=pending[1], attempt=pending[2])
                                if pending else None),
                    'replaySafe': False, 'quiescenceProven': False,
                    'authorityGranted': False, 'executionAvailable': False}
        except OSError:
            _fail()
        finally:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    def reconcile_gate(self, gate, generation, operations):
        """Compare with a live gate, without granting recovery/write authority.

        Trusted host supplies the index-to-concrete-operation mapping. This
        checks that mapping against the gate but cannot prove its plan origin.
        An intact gate detects a restored journal prefix; restoring both stores
        remains undetectable. No returned JSON can be imported as authority.
        """
        from deployment_gateway import FileWriterGate, GateError
        if type(gate) is not FileWriterGate:
            _fail()
        try:
            approved = FileWriterGate._operations(operations)
            if len(approved) != len(self.action_digests):
                _fail()
            evidence = FileWriterGate.generation_evidence(gate, generation)
            snapshot = self.snapshot()
        except (GateError, OSError):
            _fail()
        matched = (evidence['binding']['request_hash'] == self.request_hash
                   and evidence['binding']['operations'] == [list(x) for x in approved])
        expected = []
        for item in snapshot['completed']:
            ref = item['attempt']
            expected.extend([
                dict(kind='prepare', data=dict(ref=ref, operation=list(approved[item['index']]))),
                dict(kind='admit', data=ref),
                dict(kind='finish', data=dict(ref=ref, definitive=True,
                                             response_hash=item['response']))])
        pending = snapshot['unknown']
        events = [e for e in evidence['events'] if e['kind'] not in ('close', 'proof')]
        if pending:
            ref = pending['attempt']
            tail = events[len(expected):]
            prefix = [dict(kind='prepare', data=dict(ref=ref, operation=list(approved[pending['index']]))),
                      dict(kind='admit', data=ref)]
            # A definitive response missing in the journal is still an unknown
            # journal outcome. Comparison never fills in or retries that result.
            matched = matched and events[:len(expected)] == expected and (
                tail == prefix[:1] or tail == prefix or
                (len(tail) == 3 and tail[:2] == prefix and tail[2]['kind'] == 'finish'
                 and tail[2]['data']['ref'] == ref))
        else:
            matched = matched and events == expected
        return dict(matched=bool(matched), blocked=True,
                    blocker=('journal-gate-mismatch' if not matched else
                             'writer-outcome-unknown' if pending else 'independent-anchor-required'),
                    replaySafe=False, quiescenceProven=False,
                    authorityGranted=False, executionAvailable=False)

    def _append(self, event, seq, previous):
        if seq >= _MAX_EVENTS:
            _fail()
        event.update(seq=seq, plan=self.plan_hash, request=self.request_hash,
                     actions=self._actions_hash, previous=previous)
        mac = hmac.new(self._key, b'dev-workflow-compose-journal-v1\0' + _canonical(event), hashlib.sha256).hexdigest()
        body = _canonical({'event': event, 'mac': mac})
        fd = os.open(f'{seq:04d}.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self._dir)
        try:
            if os.write(fd, body) != len(body):
                _fail()
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self._dir)
        # A crash between event and head durability leaves a mismatch and blocks.
        self._write_file('journal.head', self._head(seq + 1, mac), replace=True)

    def _transition(self, kind, index, action, attempt, response=None):
        if (type(index) is not int or index < 0 or type(action) is not str or not _HEX.fullmatch(action)
                or index >= len(self.action_digests) or action != self.action_digests[index]
                or type(attempt) is not str or not _ID.fullmatch(attempt)
                or (kind == 'complete' and (type(response) is not str or not _HEX.fullmatch(response)))):
            _fail()
        fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        try:
            done, pending, previous, seq = self._scan()
            if (kind == 'attempt' and (pending is not None or index != len(done))) or (kind == 'complete' and pending != (index, action, attempt)):
                _fail()
            event = dict(kind=kind, index=index, action=action, attempt=attempt)
            if kind == 'complete':
                event['response'] = response
            self._append(event, seq, previous)
        except OSError:
            _fail()
        finally:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    def record_attempt(self, index, action_digest, attempt_id):
        self._transition('attempt', index, action_digest, attempt_id)

    def record_complete(self, index, action_digest, attempt_id, response_digest):
        """Caller asserts a complete definitive response; this does not prove quiescence."""
        self._transition('complete', index, action_digest, attempt_id, response_digest)
