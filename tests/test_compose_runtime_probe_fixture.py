import errno
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

MODULE = pathlib.Path(__file__).parent / 'support' / 'compose_runtime_probe.py'
spec = importlib.util.spec_from_file_location('runtime_probe_fixture', MODULE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class RuntimeProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.volume = self.base / 'volume'
        self.volume.mkdir()
        self.bind = self.base / 'config.txt'
        self.bind.write_text('token\n')
        self.root = self.base / 'root'
        self.include = self.base / 'include'
        self.include.mkdir()
        (self.include / 'Python.h').write_text('header')

    def check(self, role):
        return probe.startup_check(role, 'token', volume=self.volume, bind=self.bind,
                                   root=self.root, image_include=self.include)

    def test_backend_seeds_only_empty_volume(self):
        with patch.object(probe, '_deny_write', return_value=True):
            checks = self.check('backend')
            self.assertTrue(all(checks.values()))
            self.assertNotIn('volume_readonly', checks)
            self.assertNotIn('image_include_present', checks)
            self.assertEqual((self.volume / 'sentinel.txt').read_text(), 'token\n')
            with self.assertRaises(RuntimeError):
                self.check('backend')

    def test_frontend_preserves_sentinel(self):
        (self.volume / 'sentinel.txt').write_text('token\n')
        with patch.object(probe, '_deny_write', return_value=True):
            checks = self.check('frontend')
            self.assertTrue(all(checks.values()))
            self.assertNotIn('volume_initial_empty', checks)
            (self.include / 'Python.h').unlink()
            with self.assertRaises(RuntimeError):
                self.check('frontend')

    def test_wrong_bind_or_sentinel_fails(self):
        (self.volume / 'sentinel.txt').write_text('wrong\n')
        with patch.object(probe, '_deny_write', return_value=True):
            with self.assertRaises(RuntimeError):
                self.check('frontend')
            (self.volume / 'sentinel.txt').write_text('token\n')
            self.bind.write_text('wrong\n')
            with self.assertRaises(RuntimeError):
                self.check('frontend')

    def test_only_erofs_is_accepted(self):
        with patch('builtins.open', side_effect=OSError(errno.EROFS, 'readonly')):
            self.assertTrue(probe._deny_write(self.root))
        with patch('builtins.open', side_effect=PermissionError(errno.EACCES, 'denied')):
            with self.assertRaises(PermissionError):
                probe._deny_write(self.root)
        with self.assertRaises(RuntimeError):
            probe._deny_write(self.root)

    def test_health_rechecks_sentinel(self):
        sentinel = self.volume / 'sentinel.txt'
        sentinel.write_text('token\n')
        with patch.object(probe.pathlib, 'Path', side_effect=lambda _: self.volume):
            self.assertTrue(probe._response('backend', 'token', dict.fromkeys(probe.CHECKS['backend'], True))['checks']['sentinel_preserved'])
            sentinel.write_text('changed\n')
            with self.assertRaises(RuntimeError):
                probe._response('backend', 'token', dict.fromkeys(probe.CHECKS['backend'], True))

    def test_generated_code_compiles_and_does_not_serve_on_import(self):
        for role in ('backend', 'frontend'):
            compile(probe.make_server_code(role, 'token'), '<server>', 'exec')
            compile(probe.make_health_code(role, 'token'), '<health>', 'exec')
            compile(probe.make_peer_code(role, 'token'), '<peer>', 'exec')
        for token in ('', 'a' * 257, 'a\x00b'):
            with self.assertRaises(ValueError):
                probe.make_server_code('backend', token)
        for invalid in ('', 'localhost', 'backend/evil'):
            with self.assertRaises(ValueError):
                probe.make_peer_code(invalid, 'token')


if __name__ == '__main__':
    unittest.main()
