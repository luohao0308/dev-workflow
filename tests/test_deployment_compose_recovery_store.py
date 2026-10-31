"""Archive mechanics run on POSIX; Linux platform gate is tested separately."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('recovery_store_tests_module',
    Path(__file__).resolve().parents[1] / 'scripts/deployment_compose_recovery_store.py')
store = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(store)


@unittest.skipUnless(os.name == 'posix', 'POSIX descriptor mechanics')
class RecoveryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'private'
        self.root.mkdir(mode=0o700)
        # Darwin exercises mechanics only, without claiming Linux acceptance.
        patch = mock.patch.object(store.sys, 'platform', 'linux')
        patch.start()
        self.addCleanup(patch.stop)
        self.archive = store.ComposeRecoveryStore(self.root, key=b'k' * 32)
        self.addCleanup(self.archive.close)

    def rejected(self, fn, *args):
        with self.assertRaisesRegex(ValueError, '^recovery-store-rejected$'):
            fn(*args)

    def test_roundtrip_and_repeat_preserve_inode(self):
        payload = b'\x00private\xff'
        ref = self.archive.put(payload)
        inode = (self.root / ref).stat().st_ino
        self.assertEqual(self.archive.put(payload), ref)
        self.assertEqual((self.root / ref).stat().st_ino, inode)
        self.assertEqual(self.archive.get(ref), payload)
        self.assertEqual((self.root / ref).stat().st_mode & 0o777, 0o600)

    def test_invalid_inputs_unknown_and_oversize(self):
        for ref in ('../secret', 'a' * 64, 'A' * 64, None):
            self.rejected(self.archive.get, ref)
        for payload in ('secret', bytearray(b'x'), b'x' * (store.MAX_PAYLOAD + 1)):
            self.rejected(self.archive.put, payload)

    def test_tamper_not_repaired(self):
        ref = self.archive.put(b'secret')
        (self.root / ref).write_bytes(b'tampered')
        self.rejected(self.archive.get, ref)
        self.rejected(self.archive.put, b'secret')
        self.assertEqual((self.root / ref).read_bytes(), b'tampered')

    def test_forged_and_noncanonical_envelope(self):
        for raw in (self.archive._envelope(b'secret').replace(b'"hmac":"', b'"hmac":"0'),
                    b' ' + self.archive._envelope(b'secret')):
            ref = hashlib.sha256(raw).hexdigest()
            path = self.root / ref
            path.write_bytes(raw)
            path.chmod(0o600)
            self.rejected(self.archive.get, ref)

    def test_interrupted_write_is_retained_and_rejected(self):
        payload = b'interrupted'
        ref = hashlib.sha256(self.archive._envelope(payload)).hexdigest()
        with mock.patch.object(store.os, 'write', side_effect=OSError('private diagnostic')):
            self.rejected(self.archive.put, payload)
        self.assertTrue((self.root / ref).exists())
        self.rejected(self.archive.get, ref)
        self.rejected(self.archive.put, payload)

    def test_symlink_ancestor_is_rejected(self):
        link = self.root.with_name('ancestor')
        link.symlink_to(self.root.parent, target_is_directory=True)
        self.rejected(lambda: store.ComposeRecoveryStore(link / self.root.name, key=b'k' * 32))

    def test_links_and_modes(self):
        ref = self.archive.put(b'private')
        path = self.root / ref
        other = self.root / 'other'
        os.link(path, other)
        self.rejected(self.archive.get, ref)
        other.unlink()
        path.chmod(0o640)
        self.rejected(self.archive.get, ref)
        path.chmod(0o600)
        path.rename(other)
        path.symlink_to(other)
        self.rejected(self.archive.get, ref)
        self.rejected(self.archive.put, b'private')

    def test_root_replacement_and_mode_change(self):
        ref = self.archive.put(b'x')
        self.root.chmod(0o750)
        self.rejected(self.archive.get, ref)
        self.root.chmod(0o700)
        self.root.rename(self.root.with_name('old'))
        self.root.mkdir(mode=0o700)
        self.rejected(self.archive.get, ref)
        self.rejected(self.archive.put, b'y')

    def test_constructor_rejects_symlink_and_bad_key(self):
        link = self.root.with_name('link')
        link.symlink_to(self.root, target_is_directory=True)
        self.rejected(lambda: store.ComposeRecoveryStore(link, key=b'k' * 32))
        self.rejected(lambda: store.ComposeRecoveryStore(self.root, key=b'k'))
        with mock.patch.object(store.sys, 'platform', 'win32'):
            self.rejected(lambda: store.ComposeRecoveryStore(self.root, key=b'k' * 32))


if __name__ == '__main__':
    unittest.main()
