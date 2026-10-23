"""Portable ownership and concurrent recovery checks, including Windows CI."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('workflow_lock_test_subject', Path(__file__).resolve().parents[1] / 'core/scripts/workflow_lock.py')
LOCK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOCK)


class WorkflowLockTests(unittest.TestCase):
    def test_live_owner_is_never_recovered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with LOCK.LifecycleLock(root, 'upgrade', transaction='record') as first:
                with self.assertRaises(ValueError):
                    with LOCK.LifecycleLock(root, 'rollback', transaction='record', recover=True):
                        self.fail('stole live owner')
                self.assertEqual(json.loads(first.path.read_text())['token'], first.token)
            self.assertFalse(first.path.exists())

    def test_concurrent_recoverer_cannot_unlink_new_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = root / '.dev-workflow/lifecycle.lock/owner.json'
            owner.parent.mkdir(parents=True)
            owner.write_text(json.dumps(dict(pid=123456, transaction='record')))
            read_dead = threading.Event()
            continue_first = threading.Event()
            first = LOCK.LifecycleLock(root, 'rollback', transaction='record', recover=True)
            errors = []

            def dead(_):
                read_dead.set()
                if not continue_first.wait(5):
                    raise AssertionError('test synchronization timed out')
                return False

            def acquire_first():
                try:
                    first.__enter__()
                except Exception as error:
                    errors.append(error)

            with patch.object(LOCK, 'process_alive', side_effect=dead):
                thread = threading.Thread(target=acquire_first)
                thread.start()
                try:
                    self.assertTrue(read_dead.wait(5))
                    with self.assertRaisesRegex(ValueError, 'recovery is locked'):
                        LOCK.LifecycleLock(root, 'rollback', transaction='record', recover=True).__enter__()
                finally:
                    continue_first.set()
                    thread.join(5)
            try:
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertTrue(first.owned)
                self.assertEqual(json.loads(owner.read_text())['token'], first.token)
            finally:
                first.__exit__()

    def test_unknown_recovery_guard_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guard = root / '.dev-workflow/lifecycle.lock/recovery.lock'
            guard.parent.mkdir(parents=True)
            guard.write_bytes(b'unknown')
            with self.assertRaises(ValueError):
                LOCK.LifecycleLock(root, 'rollback', transaction='record', recover=True).__enter__()
            self.assertEqual(guard.read_bytes(), b'unknown')

    def test_recovery_checks_exact_attested_owner_inside_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = root / '.dev-workflow/lifecycle.lock/owner.json'
            owner.parent.mkdir(parents=True)
            expected = dict(pid=123456, token='a' * 32, operation='deployment-execution', transaction='record')
            replacement = dict(expected, token='b' * 32)
            owner.write_text(json.dumps(expected))
            lock = LOCK.LifecycleLock(root, 'recovery', transaction='record', recover=True,
                                      expected_owner=expected)
            expected['token'] = 'caller mutation must not change frozen expectation'
            original = lock._acquire
            def substituted():
                self.assertTrue((owner.parent / 'recovery.lock').exists())
                owner.write_text(json.dumps(replacement))
                return original()
            with patch.object(lock, '_acquire', side_effect=substituted), \
                    patch.object(LOCK, 'process_alive', return_value=False), \
                    self.assertRaisesRegex(ValueError, 'attested owner'):
                lock.__enter__()
            self.assertEqual(json.loads(owner.read_text()), replacement)
            self.assertFalse(lock.owned)

    def test_replacement_while_checking_pid_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = root / '.dev-workflow/lifecycle.lock/owner.json'
            owner.parent.mkdir(parents=True)
            expected = dict(pid=123456, token='a' * 32, operation='deployment-execution', transaction='record')
            replacement = dict(expected, token='b' * 32)
            owner.write_text(json.dumps(expected))
            def replaced(pid):
                owner.write_text(json.dumps(replacement))
                return False
            with patch.object(LOCK, 'process_alive', side_effect=replaced), \
                    self.assertRaisesRegex(ValueError, 'attested owner changed'):
                LOCK.LifecycleLock(root, 'recovery', transaction='record', recover=True,
                                   expected_owner=expected).__enter__()
            self.assertEqual(json.loads(owner.read_text()), replacement)

    def test_recovery_expected_owner_accepts_only_exact_dead_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner = root / '.dev-workflow/lifecycle.lock/owner.json'
            owner.parent.mkdir(parents=True)
            expected = dict(pid=123456, token='a' * 32, operation='deployment-execution', transaction='record')
            owner.write_text(json.dumps(expected))
            with patch.object(LOCK, 'process_alive', return_value=False):
                with LOCK.LifecycleLock(root, 'recovery', transaction='record', recover=True,
                                         expected_owner=expected) as lock:
                    self.assertNotEqual(json.loads(owner.read_text())['token'], expected['token'])
                    self.assertTrue(lock.owned)
            self.assertFalse(owner.exists())
            with self.assertRaisesRegex(ValueError, 'attested owner'):
                LOCK.LifecycleLock(root, 'recovery', transaction='record', recover=True,
                                   expected_owner=expected).__enter__()

    def test_current_process_is_alive(self):
        self.assertIs(LOCK.process_alive(os.getpid()), True)
