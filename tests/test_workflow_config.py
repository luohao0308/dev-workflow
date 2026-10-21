import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'core/scripts'
sys.path.insert(0, str(CORE))
import workflow_config as config
import workflow_check as doctor


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / '.dev-workflow').mkdir()
        self.manifest = self.root / '.dev-workflow/manifest.json'
        self.original = dict(schemaVersion=5, managedBy='dev-workflow', installedPacks=['delivery'],
                             enabledCapabilities=['cicd:github-actions'], gitPolicy={'pushMode': 'manual', 'pushActor': 'ai'})
        self.write(self.manifest, self.original)
        self.project = self.root / 'workflow.config.json'
        self.declaration = dict(schemaVersion=1, enabledCapabilities=['release'], commands={}, documents={},
                                extensions={'release': {'strategy': 'commit-sha', 'components': ['backend', 'frontend']}})

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, value):
        path.write_text(json.dumps(value), encoding='utf-8')

    def cli(self, *args, success=True):
        proc = subprocess.run([sys.executable, '-B', str(CORE / 'workflow_config.py'), *args, '--repo', str(self.root)], capture_output=True, text=True)
        self.assertEqual(proc.returncode == 0, success, proc.stdout + proc.stderr)
        return proc

    def adopt(self):
        self.write(self.project, self.declaration)
        self.cli('adopt')

    def test_pending_upgrades_block_configuration_mutations(self):
        self.adopt()
        transaction = 'a' * 32
        journal = self.root / '.dev-workflow/upgrades' / transaction / 'journal.json'
        journal.parent.mkdir(parents=True)
        for status in ('prepared', 'interrupted', 'rolling-back'):
            self.write(journal, dict(schemaVersion=1, target=str(self.root.resolve()),
                                     transaction=transaction, status=status))
            for arguments in (('adopt',), ('sync',), ('withdraw',),
                              ('update', '--enable', 'containers:compose'), ('installer-sync',)):
                with self.subTest(status=status, action=arguments[0]):
                    before = self.manifest.read_bytes(), self.project.read_bytes()
                    result = self.cli(*arguments, success=False)
                    self.assertIn('Incomplete upgrade transaction', result.stderr)
                    self.assertEqual(before, (self.manifest.read_bytes(), self.project.read_bytes()))
        for status in ('committed', 'rolled-back'):
            self.write(journal, dict(schemaVersion=1, target=str(self.root.resolve()),
                                     transaction=transaction, status=status))
            self.cli('sync')

    def test_malformed_upgrade_history_blocks_configuration(self):
        journal = self.root / '.dev-workflow/upgrades' / ('a' * 32) / 'journal.json'
        journal.parent.mkdir(parents=True)
        self.write(journal, {'status': 'committed'})
        before = self.manifest.read_bytes()
        self.cli('adopt', '--create', success=False)
        self.assertEqual(before, self.manifest.read_bytes())
        self.assertFalse(self.project.exists())

    def test_legacy_configuration_remains_supported(self):
        value = config.resolve_configuration(self.root)
        self.assertFalse(value['errors'])
        self.assertEqual(value['capabilities'], ['cicd:github-actions'])
        self.assertEqual(value['source'], 'manifest')

    def test_machine_json_remains_valid_with_non_utf8_stdout(self):
        self.declaration['commands'] = {'测试': {'command': 'echo test', 'cwd': '.'}}
        self.adopt()
        env = dict(os.environ, PYTHONIOENCODING='cp1252')
        for tool, arguments in [('workflow_config.py', ['check']), ('workflow_check.py', ['--json'])]:
            result = subprocess.run([sys.executable, '-B', str(CORE / tool), *arguments, '--repo', str(self.root)],
                                    capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            decoded = json.loads(result.stdout.decode('ascii'))
            self.assertIsInstance(decoded, dict)

    def test_adoption_preview_is_read_only_and_preserves_policy(self):
        self.write(self.project, self.declaration)
        before = self.manifest.read_bytes(), self.project.read_bytes()
        self.cli('adopt', '--dry-run')
        self.assertEqual(before, (self.manifest.read_bytes(), self.project.read_bytes()))
        self.cli('adopt')
        value = config.resolve_configuration(self.root)
        self.assertFalse(value['errors'] + value['warnings'])
        self.assertEqual(value['source'], 'project')
        self.assertNotIn(b'\r\n', self.project.read_bytes())
        self.assertEqual(json.loads(self.manifest.read_text())['projectConfiguration']['sha256'], config.fingerprint(self.project))
        self.assertEqual(value['capabilities'], ['release'])
        self.assertEqual(json.loads(self.manifest.read_text())['gitPolicy'], self.original['gitPolicy'])

    def test_unadopted_configuration_is_not_authoritative(self):
        self.write(self.project, self.declaration)
        self.assertEqual(config.resolve_configuration(self.root)['errors'][0]['code'], 'config.unadopted')
        self.cli('update', '--enable', 'release', success=False)

    def test_invalid_configuration_never_falls_back(self):
        self.adopt()
        before = self.manifest.read_bytes()
        self.project.write_text('{"schemaVersion":1,}', encoding='utf-8')
        result = config.resolve_configuration(self.root)
        self.assertEqual(result['capabilities'], [])
        self.cli('sync', success=False)
        self.assertEqual(before, self.manifest.read_bytes())

    def test_drift_is_reported_and_sync_is_explicit(self):
        self.adopt()
        declaration = self.declaration | {'enabledCapabilities': ['release', 'containers:compose']}
        self.write(self.project, declaration)
        before = self.manifest.read_bytes(), self.project.read_bytes()
        result = config.resolve_configuration(self.root)
        self.assertEqual(result['capabilities'], declaration['enabledCapabilities'])
        self.assertEqual(result['warnings'][0]['code'], 'config.drift')
        self.assertEqual(before, (self.manifest.read_bytes(), self.project.read_bytes()))
        self.cli('sync')
        self.assertFalse(config.resolve_configuration(self.root)['warnings'])

    def test_update_and_withdraw_keep_current_declarations(self):
        self.adopt()
        self.cli('update', '--enable', 'containers:compose', '--disable', 'release')
        self.assertEqual(config.resolve_configuration(self.root)['capabilities'], ['containers:compose'])
        self.cli('withdraw')
        value = config.resolve_configuration(self.root)
        self.assertEqual(value['source'], 'manifest')
        self.assertEqual(value['capabilities'], ['containers:compose'])
        self.assertTrue(self.project.exists())
        self.cli('adopt')
        self.assertEqual(config.resolve_configuration(self.root)['source'], 'project')

    def test_missing_adopted_configuration_does_not_activate_snapshot(self):
        self.adopt()
        self.project.unlink()
        value = config.resolve_configuration(self.root)
        self.assertEqual(value['capabilities'], [])
        self.cli('update', '--enable', 'release', success=False)

    def test_withdrawn_file_is_detached_even_if_later_invalid(self):
        self.adopt()
        self.cli('withdraw')
        self.project.write_text('{bad', encoding='utf-8')
        value = config.resolve_configuration(self.root)
        self.assertEqual(value['source'], 'manifest')
        self.assertFalse(value['errors'])
        self.cli('update', '--enable', 'containers:compose')
        self.cli('adopt', success=False)

    def test_reinstall_cannot_silently_sync_configuration_drift(self):
        self.adopt()
        self.write(self.project, self.declaration | {'enabledCapabilities': ['containers:compose']})
        before = self.manifest.read_bytes(), self.project.read_bytes()
        self.cli('installer-capabilities', success=False)
        self.assertEqual(before, (self.manifest.read_bytes(), self.project.read_bytes()))

    def test_malformed_adoption_marker_does_not_activate_legacy_capabilities(self):
        for marker in ({}, {'adopted': 'broken'}, True):
            self.write(self.manifest, self.original | {'projectConfiguration': marker})
            result = config.resolve_configuration(self.root)
            self.assertEqual(result['errors'][0]['code'], 'config.state_invalid')
            self.assertEqual(result['capabilities'], [])

    def test_new_config_creation_is_explicit(self):
        self.cli('adopt', success=False)
        self.cli('adopt', '--create')
        self.assertEqual(json.loads(self.project.read_text())['enabledCapabilities'], self.original['enabledCapabilities'])

    def test_unknown_capabilities_and_permission_fields_rejected(self):
        self.write(self.project, self.declaration | {'gitPolicy': {'pushMode': 'auto'}})
        self.cli('adopt', success=False)
        self.cli('update', '--enable', 'unknown', success=False)

    def test_symlink_and_existing_lock_cannot_mutate(self):
        outside = self.root / 'outside.json'
        self.write(outside, self.declaration)
        try:
            self.project.symlink_to(outside)
        except OSError:
            self.skipTest('symlinks unavailable')
        self.cli('adopt', success=False)
        self.project.unlink()
        self.write(self.project, self.declaration)
        lock = self.root / '.dev-workflow/configuration.lock'
        lock.write_text('other process')
        self.cli('adopt', success=False)
        self.assertEqual(lock.read_text(), 'other process')

    def test_doctor_reports_known_conflicts_without_running_commands(self):
        self.adopt()
        (self.root / 'backend').mkdir()
        (self.root / 'AGENTS.md').write_text('当前为空仓库阶段\n<!-- AI-WORKFLOW:PROJECT:START -->\n gitPolicy 为 manual + user\n', encoding='utf-8')
        declaration = self.declaration | {'commands': {'dangerous': {'command': 'touch SHOULD_NOT_EXIST', 'cwd': 'missing'}}}
        self.write(self.project, declaration)
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        report = doctor.check(self.root)
        codes = {i['code'] for i in report['issues']}
        self.assertTrue({'rules.stale_scaffold', 'rules.policy_conflict', 'command.cwd_missing', 'config.drift'} <= codes)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.assertFalse((self.root / 'SHOULD_NOT_EXIST').exists())
        self.assertEqual(report['production'], 'unknown')

    def test_doctor_detects_local_baseline_divergence(self):
        def git(*args):
            return subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True)
        git('init', '-q')
        git('config', 'user.email', 'test@example.test')
        git('config', 'user.name', 'Test')
        git('add', '.')
        git('commit', '-qm', 'initial')
        git('branch', '-M', 'main')
        git('checkout', '-qb', 'feature')
        (self.root / 'change').write_text('new')
        git('add', 'change')
        git('commit', '-qm', 'change')
        report = doctor.check(self.root)
        self.assertIn('git.baseline_differs', {i['code'] for i in report['issues']})
        self.assertEqual(report['git']['baselineRef'], 'main')

    def test_project_root_is_a_valid_command_working_directory(self):
        self.declaration['commands'] = {'check': {'command': 'never execute this', 'cwd': '.'}}
        self.adopt()
        self.assertNotIn('command.cwd_missing', {i['code'] for i in doctor.check(self.root)['issues']})


if __name__ == '__main__':
    unittest.main()
