import copy
import hashlib
from dataclasses import replace
import gc
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import deployment_compose_production_scope_v1_host as scope


@unittest.skipUnless(os.name == 'posix', 'POSIX descriptor and flock tests')
class ProductionScopeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.registration = scope.provision_scope(
            self.root, host_id='host-a', project='blog-prod', daemon_id='docker-1')
        self.path, = self.root.iterdir()
        self.first, self.second, self.proof = 'a' * 64, 'b' * 64, 'c' * 64

    def _child_args(self):
        reg = self.registration
        return [sys.executable, '-B', '-c', '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from deployment_compose_production_scope_v1_host import acquire_scope, ScopeRegistrationV1
reg = ScopeRegistrationV1(Path(sys.argv[2]), tuple(map(int, sys.argv[3:5])),
                          tuple(map(int, sys.argv[5:7])), 'host-a', 'blog-prod', 'docker-1')
lease = acquire_scope(reg, 'a' * 64)
print('durable', flush=True)
sys.stdin.buffer.read(1)
''', str(ROOT / 'scripts'), str(reg.root),
                *map(str, reg.root_identity), *map(str, reg.journal_identity)]

    def test_real_process_competition_and_killed_owner_leave_blocked_record(self):
        with subprocess.Popen(self._child_args(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as child:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(10), 'child did not start')
                self.assertEqual(child.stdout.readline(), b'durable\n')
                with self.assertRaisesRegex(scope.ScopeBlocked, 'live writer'):
                    scope.acquire_scope(self.registration, self.second)
            finally:
                child.kill()
                child.wait(timeout=5)
        with self.assertRaisesRegex(scope.ScopeBlocked, 'Unresolved'):
            scope.acquire_scope(self.registration, self.second)

    def test_verified_operation_releases_scope_without_allowing_replay(self):
        with scope.acquire_scope(self.registration, self.first) as lease:
            self.assertEqual(lease.generation, 1)
            lease.check()
            with self.assertRaises(scope.ScopeBlocked):
                lease.complete('invalid')
            lease.complete(self.proof)
            with self.assertRaises(scope.ScopeBlocked):
                lease.check()
            with self.assertRaises(scope.ScopeBlocked):
                lease.complete(self.proof)
        with self.assertRaisesRegex(scope.ScopeBlocked, 'already recorded'):
            scope.acquire_scope(self.registration, self.first)
        with scope.acquire_scope(self.registration, self.second) as lease:
            self.assertEqual(lease.generation, 2)
            lease.complete(self.proof)

    def test_daemon_and_host_aliases_cannot_allocate_another_project_journal(self):
        for changes in ({'host_id': 'alias'}, {'daemon_id': 'docker-2'}):
            changed = replace(self.registration, **changes)
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(scope.ScopeBlocked, 'header'):
                    scope.acquire_scope(changed, self.first)
                with self.assertRaises(FileExistsError):
                    scope.provision_scope(self.root, host_id=changed.host_id,
                                          project=changed.project, daemon_id=changed.daemon_id)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_missing_torn_and_replaced_journal_never_recreate_scope(self):
        original = self.path.read_bytes()
        self.path.write_bytes(original + b'{"state":')
        with self.assertRaises(scope.ScopeBlocked):
            scope.acquire_scope(self.registration, self.first)
        self.assertEqual(self.path.read_bytes(), original + b'{"state":')
        self.path.rename(self.root / 'old')
        with self.assertRaises(FileNotFoundError):
            scope.acquire_scope(self.registration, self.first)
        self.path.write_bytes(original)
        self.path.chmod(0o600)
        with self.assertRaisesRegex(scope.ScopeBlocked, 'inode changed'):
            scope.acquire_scope(self.registration, self.first)

    def test_close_or_collection_without_proof_releases_fd_but_keeps_unresolved_record(self):
        lease = scope.acquire_scope(self.registration, self.first)
        fd = scope._session(lease).fd
        del lease
        gc.collect()
        with self.assertRaises(OSError):
            os.fstat(fd)
        with self.assertRaisesRegex(scope.ScopeBlocked, 'Unresolved'):
            scope.acquire_scope(self.registration, self.second)

    def test_review_pending_scope_requires_quiescent_exact_tail_and_preserves_bytes(self):
        with scope.acquire_scope(self.registration, self.first) as lease:
            lease.complete(self.proof)
        with scope.acquire_scope(self.registration, self.second):
            with self.assertRaisesRegex(scope.ScopeBlocked, 'live writer'):
                scope.inspect_pending_scope(self.registration, self.second)
        raw = self.path.read_bytes()
        with self.assertRaises(scope.ScopeBlocked):
            scope.inspect_pending_scope(self.registration, self.first)
        self.assertEqual(scope.inspect_pending_scope(self.registration, self.second),
                         dict(generation=2, requestHash=self.second,
                              journalDigest=hashlib.sha256(raw).hexdigest()))
        self.assertEqual(self.path.read_bytes(), raw)
        with self.assertRaisesRegex(scope.ScopeBlocked, 'Unresolved'):
            scope.acquire_scope(self.registration, 'd' * 64)

    def test_copy_thread_and_fork_ownership_and_child_does_not_keep_flock(self):
        lease = scope.acquire_scope(self.registration, self.first)
        try:
            with self.assertRaises(scope.ScopeBlocked):
                copy.copy(lease)
            errors = []
            def foreign():
                try:
                    lease.complete(self.proof)
                except scope.ScopeBlocked:
                    errors.append(True)
            thread = threading.Thread(target=foreign)
            thread.start()
            thread.join(timeout=5)
            self.assertEqual(errors, [True])

            read_end, write_end = os.pipe()
            ready_read, ready_write = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(write_end)
                os.close(ready_read)
                try:
                    lease.close()
                except scope.ScopeBlocked:
                    os.write(ready_write, b'1')
                    os.close(ready_write)
                    os.read(read_end, 1)
                    os._exit(0)
                os._exit(1)
            os.close(read_end)
            os.close(ready_write)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(ready_read, selectors.EVENT_READ)
                    self.assertTrue(selector.select(10), 'child did not finish its fork cleanup')
                    self.assertEqual(os.read(ready_read, 1), b'1')
                with self.assertRaisesRegex(scope.ScopeBlocked, 'live writer'):
                    scope.acquire_scope(self.registration, self.second)
                lease.complete(self.proof)
                lease.close()
                with scope.acquire_scope(self.registration, self.second) as next_lease:
                    next_lease.complete(self.proof)
            finally:
                os.close(ready_read)
                os.close(write_end)
                _, result = os.waitpid(pid, 0)
                self.assertEqual(result, 0)
        finally:
            if lease in scope._LEASES:
                lease.close()

    def test_torn_write_reports_no_success_and_releases_lock(self):
        real_write = os.write
        with patch.object(scope.os, 'write', side_effect=lambda fd, raw: real_write(fd, raw[:-1])):
            with self.assertRaisesRegex(scope.ScopeBlocked, 'Incomplete'):
                scope.acquire_scope(self.registration, self.first)
        with self.assertRaisesRegex(scope.ScopeBlocked, 'torn record'):
            scope.acquire_scope(self.registration, self.second)

    def test_failed_start_fsync_releases_lock_but_never_returns_lease(self):
        with patch.object(scope.os, 'fsync', side_effect=OSError('fixture fsync failure')):
            with self.assertRaisesRegex(OSError, 'fixture fsync failure'):
                scope.acquire_scope(self.registration, self.first)
        with self.assertRaisesRegex(scope.ScopeBlocked, 'Unresolved'):
            scope.acquire_scope(self.registration, self.second)

    def test_changed_bytes_poison_current_lease_before_terminal_record(self):
        with scope.acquire_scope(self.registration, self.first) as lease:
            original = self.path.read_bytes()
            self.path.write_bytes(original + b'unknown\n')
            with self.assertRaisesRegex(scope.ScopeBlocked, 'differs'):
                lease.check()
            self.path.write_bytes(original)
            with self.assertRaisesRegex(scope.ScopeBlocked, 'no longer active'):
                lease.complete(self.proof)
        with self.assertRaisesRegex(scope.ScopeBlocked, 'Unresolved'):
            scope.acquire_scope(self.registration, self.second)
