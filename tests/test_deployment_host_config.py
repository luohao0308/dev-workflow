import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import deployment_host_config as config

def platform_template(root):
    template = json.loads((Path(__file__).resolve().parents[1]/'examples/deployment-host/host.example.json').read_text())
    for name in config.PATHS:
        template[name] = str(root/name)
    template['github']['credential_file'] = str(root/'credential')
    return template

class ConfigurationTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'POSIX private-file permission contract')
    def test_private_read_bounds(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve()/'secret'
            path.write_bytes(b'secret-marker')
            path.chmod(0o600)
            self.assertEqual(config.read_private_bytes(path, maximum=20), b'secret-marker')
            with self.assertRaisesRegex(config.ConfigurationError, '^invalid-host-configuration$'):
                config.read_private_bytes(path, maximum=2)
    def test_duplicate_and_unknown_sanitized(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'config'
            for raw in ('{"secret-marker":1,"secret-marker":2}', '{"plugin":"secret-marker"}'):
                with patch.object(config, 'read_private_bytes', return_value=raw.encode()), self.assertRaisesRegex(config.ConfigurationError, '^invalid-host-configuration$'):
                    config.load_host_config(path)
    @unittest.skipIf(os.name == 'nt', 'symlink creation requires Windows privilege')
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve()/'secret'; path.write_bytes(b'value'); path.chmod(0o600)
            link = Path(root)/'link'; link.symlink_to(path)
            with self.assertRaises(config.ConfigurationError):
                config.read_private_bytes(link, maximum=100)
    def test_template_load_and_binding(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root).resolve()
            raw = json.dumps(platform_template(root)).encode()
            with patch.object(config, 'read_private_bytes', return_value=raw):
                bundle = config.load_host_config(root/'config')
            self.assertEqual(bundle.github['deployment_policy'].target_repository, bundle.runtime_policy.repository)
            self.assertNotEqual(bundle.github['host_repository'], bundle.runtime_policy.repository)
            self.assertEqual(bundle.github['recovery_policy'].gate_policy_hash, bundle.gate_policy.identity_hash())
            self.assertNotIn('credential_file', repr(bundle))
            with self.assertRaises(TypeError):
                bundle.github['host_repository'] = 'bad'
    def test_policy_and_path_mutations(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve()/'config'
            template = platform_template(path.parent)
            with patch.object(config, 'read_private_bytes', return_value=json.dumps(template).encode()):
                config.load_host_config(path)  # Prove the unmutated platform fixture passes.
            mutations = [lambda d: d['gate'].update(store_id='different-store'), lambda d: d['gate'].update(key_id='different-key'), lambda d: d.update(plugin='bad'), lambda d: d.update(store_root=d['candidate_root']),
                         lambda d: d.update(reader_key_file='relative'), lambda d: d['execution'].update(gateway_policy_hash='0'*64),
                         lambda d: d['github'].update(reviewer_ids=[]), lambda d: d['runtime'].update(maximum_age=True)]
            for mutate in mutations:
                value = json.loads(json.dumps(template)); mutate(value)
                with patch.object(config, 'read_private_bytes', return_value=json.dumps(value).encode()), self.assertRaisesRegex(config.ConfigurationError, '^invalid-host-configuration$'):
                    config.load_host_config(path)
    @unittest.skipIf(os.name == 'nt', 'POSIX private ownership checks')
    def test_hardlink_and_public_modes_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve()/'key'; path.write_bytes(b'value'); path.chmod(0o644)
            with self.assertRaises(config.ConfigurationError):
                config.read_private_bytes(path, maximum=100)
            path.chmod(0o600); os.link(path, path.with_name('other'))
            with self.assertRaises(config.ConfigurationError):
                config.read_private_bytes(path, maximum=100)

    def test_nonfinite_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve()/'config'
            for value in ('NaN', 'Infinity', '-Infinity'):
                raw = ('{"schemaVersion":'+value+'}').encode()
                with patch.object(config, 'read_private_bytes', return_value=raw), self.assertRaisesRegex(config.ConfigurationError, '^invalid-host-configuration$'):
                    config.load_host_config(path)
