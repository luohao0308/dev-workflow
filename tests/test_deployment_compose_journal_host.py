"""Host-only batch phase journal; no Docker invocation."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import deployment_compose_journal_host as journal


H = 'a' * 64
R = 'b' * 64
KEY = b'host-only-compose-journal-secret-32-bytes'


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / 'private'
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.j = journal.BatchJournal(self.root, H, R, (H, R), KEY)
        self.addCleanup(self.j.close)

    def test_reload_and_completed_prefix(self):
        self.j.record_attempt(0, H, 'try-1')
        initial = self.j.snapshot()
        self.assertEqual(0, len(initial['completed']))
        self.assertFalse(initial['replaySafe'])
        self.assertFalse(initial['quiescenceProven'])
        self.assertFalse(initial['authorityGranted'])
        self.j.record_complete(0, H, 'try-1', R)
        self.j.close()
        reopened = journal.BatchJournal(self.root, H, R, (H, R), KEY)
        self.addCleanup(reopened.close)
        self.assertEqual(None, reopened.snapshot()['unknown'])
        self.assertEqual(R, reopened.snapshot()['completed'][0]['response'])
        reopened.record_attempt(1, R, 'try-2')
        self.assertEqual(1, len(reopened.snapshot()['completed']))
        self.assertEqual(1, reopened.snapshot()['unknown']['index'])

    def test_crash_after_attempt_blocks_advance(self):
        self.j.record_attempt(0, H, 'first')
        self.j.close()
        reopened = journal.BatchJournal(self.root, H, R, (H, R), KEY)
        self.addCleanup(reopened.close)
        for index in (0, 1):
            with self.assertRaises(journal.JournalError):
                reopened.record_attempt(index, H, 'retry')

    def test_out_of_order_and_wrong_completion(self):
        with self.assertRaises(journal.JournalError):
            self.j.record_attempt(1, H, 'x')
        self.j.record_attempt(0, H, 'x')
        with self.assertRaises(journal.JournalError):
            self.j.record_complete(0, R, 'x', R)
        with self.assertRaises(journal.JournalError):
            self.j.record_complete(0, H, 'y', R)

    def test_tamper_truncate_replay(self):
        self.j.record_attempt(0, H, 'x')
        path = self.root / '0000.json'
        original = path.read_bytes()
        for corrupt in (original[:-1], original.replace(b'"attempt":"x"', b'"attempt":"y"'), b'{}'):
            path.write_bytes(corrupt)
            with self.assertRaises(journal.JournalError):
                self.j.snapshot()
        path.write_bytes(original)
        self.j.record_complete(0, H, 'x', R)
        (self.root / '0002.json').write_bytes(original)
        os.chmod(self.root / '0002.json', 0o600)
        with self.assertRaises(journal.JournalError):
            self.j.snapshot()

    def test_file_permissions_and_symlinks(self):
        self.j.record_attempt(0, H, 'x')
        path = self.root / '0000.json'
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        os.chmod(path, 0o644)
        with self.assertRaises(journal.JournalError):
            self.j.snapshot()
        path.unlink()
        path.symlink_to(self.root / 'journal.lock')
        with self.assertRaises((journal.JournalError, OSError)):
            self.j.snapshot()

    def test_plan_and_key_binding(self):
        self.j.record_attempt(0, H, 'x')
        for plan, key in ((R, KEY), (H, b'other-host-secret-with-at-least-32-bytes')):
            other = journal.BatchJournal(self.root, plan, R, (H, R), key)
            self.addCleanup(other.close)
            with self.assertRaises(journal.JournalError):
                other.snapshot()

    def test_request_and_ordered_actions_binding(self):
        self.j.record_attempt(0, H, 'x')
        for request, actions in ((H, (H, R)), (R, (R, H)), (R, (H,))):
            other = journal.BatchJournal(self.root, H, request, actions, KEY)
            self.addCleanup(other.close)
            with self.assertRaises(journal.JournalError):
                other.snapshot()
        with self.assertRaises(journal.JournalError):
            self.j.record_complete(0, R, 'x', R)

    def test_lock_replacement_blocks(self):
        (self.root / 'journal.lock').unlink()
        (self.root / 'journal.lock').write_bytes(b'')
        os.chmod(self.root / 'journal.lock', 0o600)
        with self.assertRaises(journal.JournalError):
            self.j.record_attempt(0, H, 'x')

    def test_deleted_tail_blocks_reload(self):
        self.j.record_attempt(0, H, 'x')
        (self.root / '0000.json').unlink()
        self.j.close()
        reopened = journal.BatchJournal(self.root, H, R, (H, R), KEY)
        self.addCleanup(reopened.close)
        with self.assertRaises(journal.JournalError):
            reopened.snapshot()

    def test_valid_prefix_rollback_is_explicitly_not_replay_safe(self):
        initial_head = (self.root / 'journal.head').read_bytes()
        self.j.record_attempt(0, H, 'x')
        self.j.record_complete(0, H, 'x', R)
        self.j.close()
        (self.root / '0000.json').unlink()
        (self.root / '0001.json').unlink()
        (self.root / 'journal.head').write_bytes(initial_head)
        reopened = journal.BatchJournal(self.root, H, R, (H, R), KEY)
        self.addCleanup(reopened.close)
        state = reopened.snapshot()
        self.assertEqual(state['completed'], [])
        self.assertFalse(state['replaySafe'])
        self.assertFalse(state['executionAvailable'])

    def test_torn_head_blocks_reload(self):
        self.j.record_attempt(0, H, 'x')
        (self.root / 'journal.head').write_bytes(b'{')
        self.j.close()
        reopened = journal.BatchJournal(self.root, H, R, (H, R), KEY)
        self.addCleanup(reopened.close)
        with self.assertRaises(journal.JournalError):
            reopened.snapshot()


if __name__ == '__main__':
    unittest.main()
