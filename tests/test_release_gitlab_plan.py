from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'packs/release/scripts/release_gitlab_plan.py'
SPEC = importlib.util.spec_from_file_location('release_gitlab_plan_under_test', SCRIPT)
planning = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = planning
SPEC.loader.exec_module(planning)


class GitLabOfflinePlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.root / 'README').write_text('test\n', encoding='utf-8')
        self.git('add', 'README')
        self.git('commit', '-qm', 'initial')
        self.sha = self.git('rev-parse', 'HEAD')
        self.saved = {'strategy': 'semver-tag', 'tag': 'v1.2.3', 'targetSha': self.sha}

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def add_remote(self, url='https://gitlab.com/group/subgroup/project.git'):
        self.git('remote', 'add', 'origin', url)

    def build(self, project_id=42):
        with mock.patch.object(planning, 'validate_preparation') as validate:
            result = planning.build_intent(self.root, self.saved, remote='origin', project_id=project_id)
            validate.assert_called_once_with(self.root, self.saved)
        return result

    def test_https_intent_is_read_only(self):
        for url in ('https://gitlab.com/group/subgroup/project.git',):
            with self.subTest(url=url):
                self.add_remote(url)
                result = self.build()
                self.assertEqual((result['schemaVersion'], result['kind'], result['platform']),
                                 (2, 'release-platform-intent', 'gitlab.com'))
                self.assertEqual(result['remote']['project'], 'group/subgroup/project')
                self.assertEqual(result['projectIdDeclaration'], 42)
                self.assertEqual(result['tag'], {'name': 'v1.2.3', 'targetSha': self.sha,
                                                 'remoteStatus': 'unknown'})
                self.assertFalse(result['authorityGranted'])
                self.assertFalse(result['executionAvailable'])
                self.assertFalse(any(key in result for key in ('grant', 'request', 'host', 'expiresAt', 'release')))
                self.git('remote', 'remove', 'origin')

    def test_rejects_foreign_credentials_and_ambiguous_remote(self):
        for url in ('https://github.com/group/project.git',
                    'https://token@gitlab.com/group/project.git',
                    'git@gitlab.com:group/project.git',
                    'ssh://git@gitlab.com/group/project.git',
                    'ssh://other@gitlab.com/group/project.git',
                    'https://gitlab.com/group/project',
                    'https://gitlab.com/group/../project.git'):
            with self.subTest(url=url):
                self.add_remote(url)
                with self.assertRaises(planning.ExecutionError):
                    self.build()
                self.git('remote', 'remove', 'origin')
        self.add_remote()
        self.git('remote', 'set-url', '--push', 'origin', 'https://gitlab.com/other/project.git')
        with self.assertRaises(planning.ExecutionError):
            self.build()

    def test_v2_identity_rejects_unusable_project_paths(self):
        for project in ('group/project.lock', 'g/a/b/c/d/e/f/g/h', 'group/' + 'a' * 250):
            with self.subTest(project=project):
                self.add_remote('https://gitlab.com/' + project + '.git')
                with self.assertRaises(planning.ExecutionError):
                    self.build()
                self.git('remote', 'remove', 'origin')

    def test_rejects_project_id_strategy_and_invalid_preparation(self):
        self.add_remote()
        for value in (0, -1, True, '42'):
            with self.subTest(value=value), self.assertRaises(planning.ExecutionError):
                self.build(value)
        self.saved['strategy'] = 'commit-sha'
        with self.assertRaises(planning.ExecutionError):
            self.build()
        self.saved['strategy'] = 'semver-tag'
        self.saved['tag'] = 'x' * 256
        with self.assertRaisesRegex(planning.ExecutionError, 'v2 contract'):
            self.build()
        self.saved['tag'] = 'v1.2.3'
        with mock.patch.object(planning, 'validate_preparation', side_effect=planning.ExecutionError('dirty')):
            with self.assertRaisesRegex(planning.ExecutionError, 'dirty'):
                planning.build_intent(self.root, self.saved, remote='origin', project_id=42)

    def test_cli_requires_declarations_and_does_not_write(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--repo', str(self.root)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['.git', 'README'])

    def test_cli_real_preparation_and_safe_file_boundary(self):
        self.add_remote()
        manifest = self.root / '.dev-workflow/manifest.json'
        manifest.parent.mkdir()
        manifest.write_text(json.dumps({'managedBy': 'dev-workflow', 'schemaVersion': 5,
                                        'enabledCapabilities': []}), encoding='utf-8')
        config = {'schemaVersion': 1, 'enabledCapabilities': ['release'], 'commands': {},
                  'documents': {}, 'extensions': {'release': {'strategy': 'semver-tag',
                  'tagPrefix': 'v', 'components': []}}}
        (self.root / 'workflow.config.json').write_text(json.dumps(config), encoding='utf-8')
        adopt = Path(__file__).resolve().parents[1] / 'core/scripts/workflow_config.py'
        result = subprocess.run([sys.executable, str(adopt), 'adopt', '--repo', str(self.root)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.git('add', '.')
        self.git('commit', '-qm', 'configuration')
        import release_prepare
        preparation = release_prepare.prepare(self.root, 'HEAD', '1.2.3', [], [])
        records = self.root / '.dev-workflow/releases'
        records.mkdir()
        plan = records / 'plan.json'
        plan.write_text(json.dumps(preparation), encoding='utf-8')
        command = [sys.executable, str(SCRIPT), '--repo', str(self.root), '--preparation',
                   '.dev-workflow/releases/plan.json', '--remote', 'origin', '--project-id', '42']
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['tag']['remoteStatus'], 'unknown')
        original_linked = planning.linked
        with mock.patch.object(planning, 'linked', side_effect=lambda path: path == records or original_linked(path)):
            with self.assertRaisesRegex(planning.ExecutionError, 'Linked preparation path'):
                planning.read_preparation(self.root, Path('.dev-workflow/releases/plan.json'))
        with mock.patch.object(Path, 'is_symlink', return_value=False), mock.patch.object(
                Path, 'lstat', return_value=mock.Mock(st_file_attributes=0x400)):
            self.assertTrue(original_linked(records))
        (self.root / 'README').write_text('dirty\n', encoding='utf-8')
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.git('checkout', '--', 'README')
        with mock.patch.object(planning, 'validate_preparation'):
            copied = planning.build_intent(self.root, preparation, remote='origin', project_id=42)
        preparation['tag'] = 'changed'
        self.assertEqual(copied['preparation']['tag'], 'v1.2.3')
        plan.write_text('{"a":1,"a":2}', encoding='utf-8')
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        plan.unlink()
        plan.symlink_to(self.root / 'README')
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.assertNotEqual(subprocess.run(command[:command.index('--preparation') + 1] +
                                          ['README', '--remote', 'origin', '--project-id', '42'],
                                          capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
