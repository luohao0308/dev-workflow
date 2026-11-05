import os
import pickle
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from deployment_compose_bind_host import snapshot, recheck
ROOT = Path(__file__).resolve().parents[1]
KEY = b'host-private-test-key-' + b'x' * 32


class BindHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / 'secret.env'
        self.file.write_bytes(b'API_KEY=secret-material\n')
        self.allowed = (str(self.file),)

    def test_snapshot_and_recheck_do_not_disclose_content_or_path(self):
        evidence = snapshot(str(self.file), allowed_paths=self.allowed, key=KEY)
        self.assertRegex(evidence.digest, r'^[0-9a-f]{64}$')
        self.assertTrue(recheck(evidence, allowed_paths=self.allowed, key=KEY))
        self.assertNotIn('secret', repr(evidence))
        self.assertNotIn(str(self.file), repr(evidence))
        self.assertNotIn('secret', evidence.digest)
        with self.assertRaises(TypeError):
            pickle.dumps(evidence)
        self.assertFalse(recheck(evidence, allowed_paths=self.allowed, key=b'y' * 32))

    def test_content_change_and_atomic_replacement_fail_recheck(self):
        first = snapshot(str(self.file), allowed_paths=self.allowed, key=KEY)
        self.file.write_bytes(b'API_KEY=changed\n')
        self.assertFalse(recheck(first, allowed_paths=self.allowed, key=KEY))
        second = snapshot(str(self.file), allowed_paths=self.allowed, key=KEY)
        replacement = self.root / 'replacement'
        replacement.write_bytes(self.file.read_bytes())
        os.replace(replacement, self.file)
        self.assertFalse(recheck(second, allowed_paths=self.allowed, key=KEY))

    def test_same_content_at_different_allowed_path_has_distinct_digest(self):
        alternate = self.root / 'other.env'
        alternate.write_bytes(self.file.read_bytes())
        first = snapshot(str(self.file), allowed_paths=(str(self.file), str(alternate)), key=KEY)
        second = snapshot(str(alternate), allowed_paths=(str(self.file), str(alternate)), key=KEY)
        self.assertNotEqual(first.digest, second.digest)

    def test_unsupported_platform_is_finite_failure(self):
        with mock.patch.object(__import__('deployment_compose_bind_host').os, 'O_NOFOLLOW',
                               new=None):
            # A platform without the flag must fail closed, including if a caller
            # attempts to replace it with a sentinel rather than removing it.
            with self.assertRaisesRegex(ValueError, '^bind-platform-unsupported$'):
                snapshot(str(self.file), allowed_paths=self.allowed, key=KEY)

    def test_symlink_leaf_and_parent_rejected(self):
        leaf = self.root / 'link'
        leaf.symlink_to(self.file)
        with self.assertRaisesRegex(ValueError, '^bind-file-unavailable$'):
            snapshot(str(leaf), allowed_paths=(str(leaf),), key=KEY)
        parent = self.root / 'parent-link'
        parent.symlink_to(self.root, target_is_directory=True)
        through = parent / self.file.name
        with self.assertRaisesRegex(ValueError, '^bind-file-unavailable$'):
            snapshot(str(through), allowed_paths=(str(through),), key=KEY)

    def test_directory_fifo_and_oversize_rejected(self):
        with self.assertRaisesRegex(ValueError, '^bind-file-not-regular$'):
            snapshot(str(self.root), allowed_paths=(str(self.root),), key=KEY)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, '^bind-file-not-regular$'):
            snapshot(str(fifo), allowed_paths=(str(fifo),), key=KEY)
        with self.assertRaisesRegex(ValueError, '^bind-file-too-large$'):
            snapshot(str(self.file), allowed_paths=self.allowed, key=KEY, max_bytes=4)

    def test_exact_allowlist_and_policy_validation(self):
        for allowed in ((), (str(self.root / 'other'),), (str(self.file), str(self.file))):
            with self.assertRaisesRegex(ValueError, '^invalid-bind-policy$'):
                snapshot(str(self.file), allowed_paths=allowed, key=KEY)
        with self.assertRaisesRegex(ValueError, '^invalid-bind-policy$'):
            snapshot(str(self.root / '..' / self.file.name),
                     allowed_paths=(str(self.root / '..' / self.file.name),), key=KEY)
        evidence = snapshot(str(self.file), allowed_paths=self.allowed, key=KEY)
        self.assertFalse(recheck(evidence, allowed_paths=(str(self.root / 'other'),), key=KEY))
        self.assertFalse(recheck(evidence, allowed_paths=self.allowed + (str(self.root / 'other'),), key=KEY))
        self.assertFalse(recheck(evidence, allowed_paths=self.allowed, key=KEY, max_bytes=4096))
        self.assertFalse(recheck(evidence, allowed_paths=self.allowed, key=KEY, timeout_seconds=3))
        self.assertFalse(recheck(evidence, allowed_paths=self.allowed, key=KEY, timeout_seconds='bad'))
        self.assertFalse(recheck(evidence, allowed_paths=self.allowed, key=KEY, timeout_seconds=10**1000))
        bad = '/tmp/\ud800'
        with self.assertRaisesRegex(ValueError, '^invalid-bind-policy$'):
            snapshot(bad, allowed_paths=(bad,), key=KEY)

    def test_expiry_and_in_read_mutation_fail_closed(self):
        evidence = snapshot(str(self.file), allowed_paths=self.allowed, key=KEY, timeout_seconds=0.001)
        time.sleep(0.003)
        self.assertFalse(recheck(evidence, allowed_paths=self.allowed, key=KEY))
        real_read = os.read
        def changing_read(fd, amount):
            data = real_read(fd, amount)
            if data:
                self.file.write_bytes(b'changed in read')
            return data
        with mock.patch('deployment_compose_bind_host.os.read', side_effect=changing_read):
            with self.assertRaisesRegex(ValueError, '^bind-file-changed$'):
                snapshot(str(self.file), allowed_paths=self.allowed, key=KEY)

    def test_errors_do_not_echo_secret_path(self):
        missing = str(self.root / 'secret-missing')
        try:
            snapshot(missing, allowed_paths=(missing,), key=KEY)
        except ValueError as error:
            self.assertNotIn('secret', str(error))
            self.assertNotIn(missing, str(error))
        else:
            self.fail('missing file accepted')


if __name__ == '__main__':
    unittest.main()
