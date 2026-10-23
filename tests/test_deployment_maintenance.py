"""History maintenance executes import and reload using real authenticated records."""
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import shutil
import subprocess
import os
import io
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import deployment_host_maintenance as maintenance
from tests.test_deployment_store import fixture, KEY
store = maintenance.store

class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.collector, _, _, _ = fixture()
        self.policy = store.StorePolicy(42, 'source', 'key-source', self.collector.policy)
        self.source = maintenance.MaintenanceHost(SimpleNamespace(store_root=self.root / 'source', store_policy=self.policy), KEY, b'g' * 32)
        self.destination = maintenance.MaintenanceHost(SimpleNamespace(store_root=self.root / 'destination', gate_root=self.root / 'gate', store_policy=replace(self.policy, store_id='destination', key_id='key-destination')), b'd' * 32, b'h' * 32)
        self.backend = store.HostStore(self.policy, self.source.config.store_root, key=KEY)
        self.ref = self.backend.capture_history(self.collector, self.collector.collect())

    def test_backup_restore_without_source_and_reload(self):
        raw = maintenance.backup(self.source)
        original = self.backend._read(self.ref)
        shutil.rmtree(self.source.config.store_root)
        self.assertEqual(len(maintenance.verify(self.source, raw).records), 1)
        result = maintenance.restore(self.source, self.destination, raw)
        self.assertEqual(result['status'], 'complete')
        backend = store.HostStore(self.destination.config.store_policy, self.destination.config.store_root, key=self.destination.store_key)
        record = backend._read(self.ref)
        self.assertEqual(record['capturedAt'], original['capturedAt'])
        self.assertEqual(record['observation'], original['observation'])
        self.assertEqual(record['schemaVersion'], 2)
        backend.load_history(self.ref, collector=self.collector, before=self.collector.collect()).snapshot()
        self.assertFalse(self.destination.config.gate_root.exists())
        self.assertEqual(len(maintenance.verify(self.destination, maintenance.backup(self.destination)).records), 1)
        with self.assertRaises(ValueError):
            maintenance.restore(self.source, self.destination, raw)

    def test_wrong_key_tamper_and_unknown_history(self):
        raw = maintenance.backup(self.source)
        with self.assertRaises(ValueError):
            maintenance.verify(replace(self.source, store_key=b'x' * 32), raw)
        with self.assertRaises(ValueError):
            maintenance.verify(self.source, raw.replace(b'authenticated', b'corrupted', 1))
        (self.source.config.store_root / 'history-invalid.json').write_bytes(b'{}')
        with self.assertRaises(ValueError):
            maintenance.backup(self.source)

    def test_interrupted_restore_cannot_issue(self):
        raw = maintenance.backup(self.source)
        with patch.object(maintenance, '_write_new', side_effect=OSError('injected')):
            with self.assertRaises(OSError):
                maintenance.restore(self.source, self.destination, raw)
        with self.assertRaises(ValueError):
            store.HostStore(self.destination.config.store_policy, self.destination.config.store_root, key=self.destination.store_key)

    def test_fresh_process_uses_only_destination_key(self):
        raw = maintenance.backup(self.source)
        maintenance.restore(self.source, self.destination, raw)
        shutil.rmtree(self.source.config.store_root)
        program = """
from pathlib import Path
import sys
from tests.test_deployment_store import fixture, store
collector, _, _, _ = fixture()
policy = store.StorePolicy(42, 'destination', 'key-destination', collector.policy)
backend = store.HostStore(policy, Path(sys.argv[1]), key=b'd' * 32)
history = backend.load_history(sys.argv[2], collector=collector, before=collector.collect())
assert history.snapshot()
"""
        result = subprocess.run([sys.executable, '-B', '-c', program,
                                 str(self.destination.config.store_root), self.ref],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_process_exit_leaves_destination_pending(self):
        program = """
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import os, sys
sys.path.insert(0, 'scripts')
import deployment_host_maintenance as m
from tests.test_deployment_store import fixture, KEY
collector, _, _, _ = fixture()
root = Path(sys.argv[1])
source = m.MaintenanceHost(SimpleNamespace(store_root=root/'source', store_policy=m.store.StorePolicy(42, 'source', 'key-source', collector.policy)), KEY, b'g'*32)
destination = m.MaintenanceHost(SimpleNamespace(store_root=root/'destination', gate_root=root/'gate', store_policy=m.store.StorePolicy(42, 'destination', 'key-destination', collector.policy)), b'd'*32, b'h'*32)
raw = m.backup(source)
with patch.object(m, '_write_new', side_effect=lambda *args: os._exit(73)):
    m.restore(source, destination, raw)
"""
        result = subprocess.run([sys.executable, '-B', '-c', program, str(self.root)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 73, result.stderr)
        with self.assertRaises(ValueError):
            store.HostStore(self.destination.config.store_policy, self.destination.config.store_root,
                            key=self.destination.store_key)
        with self.assertRaises(ValueError):
            maintenance.restore(self.source, self.destination, maintenance.backup(self.source))

    def test_exclusive_write_rejects_symlink_and_existing_file(self):
        target = self.root / 'artifact'
        target.write_bytes(b'unchanged')
        with self.assertRaises(OSError):
            maintenance._write_new(self.root, 'artifact', b'replacement')
        self.assertEqual(target.read_bytes(), b'unchanged')
        if os.name != 'nt':
            (self.root / 'alias').symlink_to(target)
            with self.assertRaises(OSError):
                maintenance._write_new(self.root, 'alias', b'replacement')
            self.assertEqual(target.read_bytes(), b'unchanged')

    def test_output_and_restore_path_boundaries(self):
        candidate = self.root / 'candidate'
        source_config = SimpleNamespace(**vars(self.source.config), candidate_root=candidate,
                                        gate_root=self.root / 'source-gate')
        source = replace(self.source, config=source_config)
        for root in (candidate, source_config.gate_root, source_config.store_root, maintenance._DISTRIBUTION):
            with self.subTest(root=root):
                with self.assertRaises(maintenance.MaintenanceError):
                    maintenance.backup_to(source, root / 'archive.json')
                target = SimpleNamespace(store_root=root / 'nested', store_policy=self.destination.config.store_policy)
                with self.assertRaises(maintenance.MaintenanceError):
                    maintenance.restore(source, replace(self.destination, config=target), maintenance.backup(source))
        ancestor = SimpleNamespace(store_root=self.root, store_policy=self.destination.config.store_policy)
        with self.assertRaises(maintenance.MaintenanceError):
            maintenance.restore(source, replace(self.destination, config=ancestor), maintenance.backup(source))
        self.assertFalse(candidate.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions')
    def test_private_output_directory_and_file(self):
        output = self.root / 'backup.json'
        maintenance.backup_to(self.source, output)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(maintenance.verify(self.source, output.read_bytes()).records), 1)
        public = self.root / 'public'
        public.mkdir(mode=0o755)
        with self.assertRaises(ValueError):
            maintenance.backup_to(self.source, public / 'backup.json')
        self.assertFalse((public / 'backup.json').exists())
        with self.assertRaises(ValueError):
            maintenance._write_new(self.root, '../escape', b'no')

    def test_policy_and_sanitized_error_codes(self):
        invalid = replace(self.source, config=SimpleNamespace(store_root=self.source.config.store_root,
                                                            store_policy=object()))
        with self.assertRaisesRegex(maintenance.MaintenanceError, '^invalid-host-policy$'):
            maintenance.backup(invalid)
        self.assertEqual(maintenance._error_code(OSError('SECRET/PATH')), 'maintenance-validation-failed')
        self.assertEqual(maintenance._error_code(maintenance.MaintenanceError('SECRET/PATH')), 'maintenance-validation-failed')
        with patch.object(maintenance, '_load', return_value=self.source), patch('sys.stdout', new_callable=io.StringIO) as output:
            status = maintenance.main(['backup', '--config', 'unused', '--output', str(self.source.config.store_root / 'archive')])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output.getvalue())['code'], 'output-path-overlap')

    @unittest.skipUnless(os.name == 'posix', 'CLI private-file verification requires POSIX')
    def test_cli_archive_restore_without_either_gate_key(self):
        template_path = Path(__file__).resolve().parents[1] / 'examples/deployment-host/host.example.json'
        template = json.loads(template_path.read_text())
        from deployment_host_config import PATHS, load_host_config
        configs = []
        for label, key in (('archive-source', KEY), ('archive-destination', b'd' * 32)):
            data = json.loads(json.dumps(template))
            for name in PATHS:
                data[name] = str(self.root / (label + '-' + name))
            data['github']['credential_file'] = str(self.root / (label + '-github-token'))
            path = self.root / (label + '.json')
            path.write_text(json.dumps(data)); path.chmod(0o600)
            base = load_host_config(path)
            policy = replace(base.store_policy, store_id=label, key_id=label + '-key')
            gate = replace(base.gate_policy, store_id=label, key_id=label + '-key')
            data['store'].update(store_id=policy.store_id, key_id=policy.key_id)
            data['gate'].update(store_id=gate.store_id, key_id=gate.key_id)
            data['execution'].update(history_policy_hash=policy.identity_hash(), gateway_policy_hash=gate.identity_hash())
            path.write_text(json.dumps(data))
            config = load_host_config(path)
            config.store_key_file.write_bytes(key); config.store_key_file.chmod(0o600)
            self.assertFalse(config.gate_key_file.exists())
            configs.append((path, config))
        archive_path = self.root / 'offline-archive.json'
        archive_path.write_bytes(maintenance.archive.build_archive(configs[0][1].store_policy, {}, KEY, created_at=maintenance._now()))
        archive_path.chmod(0o600)
        cli = str(template_path.parents[2] / 'scripts/deployment_host_maintenance.py')
        for command in ('verify', 'restore'):
            args = [sys.executable, '-B', cli, command, '--config', str(configs[0][0]), '--archive', str(archive_path)]
            if command == 'restore':
                args += ['--destination-config', str(configs[1][0])]
            result = subprocess.run(args, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        store.HostStore(configs[1][1].store_policy, configs[1][1].store_root, key=b'd' * 32)
        self.assertFalse(configs[1][1].gate_root.exists())
        self.assertIsNone(maintenance._load(configs[0][0]).gate_key)
        with self.assertRaises(maintenance.ConfigurationError):
            maintenance._load(configs[0][0], require_gate=True)

    def test_rotation_diagnostics_are_fixed_and_not_raw_exception_reflection(self):
        from io import StringIO
        from contextlib import redirect_stdout
        import deployment_host_rotation as rotation
        for code in ('rotation-source-inventory-drift', 'rotation-writer-not-drained',
                     'rotation-resume-existing-transaction'):
            out = StringIO()
            with patch.object(maintenance, '_load', return_value=self.source), patch.object(
                    rotation, 'rotate', side_effect=maintenance.MaintenanceError(code)), redirect_stdout(out):
                result = maintenance.main(['rotate', '--config', 'source', '--destination-config', 'destination'])
            self.assertEqual(result, 1)
            self.assertEqual(__import__('json').loads(out.getvalue())['code'], code)
        self.assertEqual(maintenance._error_code(maintenance.MaintenanceError('/private/secret-marker')),
                         'maintenance-validation-failed')

    def test_reused_key_rejected_before_creation(self):
        with self.assertRaises(ValueError):
            maintenance.restore(self.source, replace(self.destination, store_key=KEY), maintenance.backup(self.source))
        self.assertFalse(self.destination.config.store_root.exists())

if __name__ == '__main__':
    unittest.main()
