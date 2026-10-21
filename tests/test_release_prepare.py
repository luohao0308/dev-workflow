from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'packs/release/scripts/release_prepare.py'


class ReleasePrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.root / '.git/info/exclude').write_text('.dev-workflow/\n')
        (self.root / '.dev-workflow').mkdir()
        (self.root / '.dev-workflow/manifest.json').write_text(json.dumps({'managedBy': 'dev-workflow', 'schemaVersion': 5, 'enabledCapabilities': []}))
        self.config = {'schemaVersion': 1, 'enabledCapabilities': ['release'], 'commands': {}, 'documents': {},
                       'extensions': {'release': {'strategy': 'none', 'tagPrefix': 'v', 'components': ['web', 'api']}}}
        self.save_config()
        self.sha = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True, text=True, capture_output=True).stdout.strip()

    def save_config(self):
        (self.root / 'workflow.config.json').write_text(json.dumps(self.config))
        adopted = subprocess.run([sys.executable, str(SCRIPT.parents[3] / 'core/scripts/workflow_config.py'), 'adopt', '--repo', str(self.root)], capture_output=True, text=True)
        self.assertEqual(adopted.returncode, 0, adopted.stderr)
        self.git('add', '.')
        self.git('commit', '-qm', 'configuration', '--allow-empty')

    def run_cli(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(SCRIPT), '--repo', str(self.root), '--json', *args], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0 if ok else 1, result.stderr)
        return json.loads(result.stdout) if ok else result.stderr

    def test_none_and_sha_do_not_create_tags_or_write_files(self):
        before = self.git('status', '--porcelain')
        plan = self.run_cli()
        self.assertEqual(plan['strategy'], 'none')
        self.assertIsNone(plan['version'])
        self.assertEqual(set(plan['states'].values()), {'unknown'})
        self.config['extensions']['release']['strategy'] = 'commit-sha'
        self.save_config()
        plan = self.run_cli()
        self.assertEqual(plan['targetSha'], self.git('rev-parse', 'HEAD'))
        self.assertEqual(self.git('tag'), '')
        self.assertEqual(before, self.git('status', '--porcelain'))
        self.assertFalse((self.root / '.dev-workflow/releases').exists())

    def test_semver_and_tag_conflicts(self):
        self.config['extensions']['release']['strategy'] = 'semver-tag'
        self.save_config()
        for version in ['1.2', '01.2.3', '1.2.3-01', '1.2.3-']:
            self.run_cli('--version', version, ok=False)
        plan = self.run_cli('--version', 'v1.2.3-rc.1+build.2')
        self.assertEqual(plan['tag'], 'v1.2.3-rc.1+build.2')
        self.assertEqual(self.git('tag'), '')
        self.git('tag', plan['tag'])
        self.assertEqual(self.run_cli('--version', plan['version'])['tagStatus'], 'already_exists_same_commit')
        self.git('commit', '--allow-empty', '-qm', 'next')
        self.assertIn('Tag conflict', self.run_cli('--version', plan['version'], ok=False))

    def test_read_only_preparation_does_not_refresh_git_index(self):
        index = self.root / '.git/index'
        before = index.read_bytes()
        path = self.root / 'workflow.config.json'
        metadata = path.stat()
        os.utime(path, (metadata.st_atime, metadata.st_mtime + 5))
        self.run_cli()
        self.assertEqual(index.read_bytes(), before)

    def test_unsynchronized_configuration_blocks_release_preparation(self):
        self.config['extensions']['release']['strategy'] = 'semver-tag'
        (self.root / 'workflow.config.json').write_text(json.dumps(self.config))
        self.git('add', 'workflow.config.json')
        self.git('commit', '-qm', 'configuration edited without local sync')
        self.assertIn('drift', self.run_cli('--version', '1.0.0', ok=False))
        self.assertEqual(self.git('tag'), '')

    def test_saved_plan_cannot_change_tag_components_or_verification(self):
        self.config['extensions']['release']['strategy'] = 'semver-tag'
        self.save_config()
        output = self.root / '.dev-workflow/releases/check.json'
        original = self.run_cli('--version', '1.0.0', '--output', str(output))
        for field, value in [('tag', 'v2.0.0'), ('tagStatus', 'already_exists_same_commit'),
                             ('strategy', 'none'), ('components', []), ('environment', 'production'),
                             ('configurationVersion', 'invented'), ('migrationVersion', 1),
                             ('previousDeployment', {'verification': 'passed'}),
                             ('states', {'ci': 'passed', 'image': 'unknown', 'deployment': 'unknown', 'live': 'unknown'})]:
            changed = dict(original, **{field: value})
            output.write_text(json.dumps(changed))
            self.run_cli('--check-plan', '.dev-workflow/releases/check.json', ok=False)
        output.write_text(json.dumps(original))
        self.assertTrue(self.run_cli('--check-plan', '.dev-workflow/releases/check.json')['valid'])

    def test_dirty_tree_and_missing_release_config_fail(self):
        (self.root / 'user-change').write_text('keep me')
        self.assertIn('dirty', self.run_cli(ok=False))
        (self.root / 'user-change').unlink()
        self.config['enabledCapabilities'] = []
        self.save_config()
        self.assertIn('explicitly', self.run_cli(ok=False))

    def test_component_sources_are_independent_and_unverified(self):
        self.git('commit', '--allow-empty', '-qm', 'next')
        head = self.git('rev-parse', 'HEAD')
        plan = self.run_cli('--component-source', 'web=' + self.sha, '--component-source', 'api=' + head,
                            '--component-build', 'web=local build, CI passed (user declaration)')
        self.assertEqual([x['sourceSha'] for x in plan['components']], [self.sha, head])
        self.assertEqual(set(plan['states'].values()), {'unknown'})
        self.assertTrue(all(x['verification'] == 'unknown' for x in plan['components']))
        self.run_cli('--component-source', 'other=HEAD', ok=False)

    def test_explicit_output_and_stale_plan(self):
        output = Path('.dev-workflow/releases/test.json')
        self.run_cli('--output', str(output))
        self.assertTrue(self.run_cli('--check-plan', str(self.root / output))['valid'])
        self.run_cli('--output', str(output), ok=False)
        self.run_cli('--output', '../outside.json', ok=False)
        self.git('commit', '--allow-empty', '-qm', 'new head')
        self.assertIn('Stale', self.run_cli('--check-plan', str(self.root / output), ok=False))

    def test_target_and_configuration_changes_invalidate_plan(self):
        self.git('branch', 'release-target')
        output = self.root / '.dev-workflow/releases/target.json'
        self.run_cli('--sha', 'release-target', '--output', str(output))
        self.run_cli('--check-plan', str(output), '--sha', 'HEAD', ok=True)
        self.config['extensions']['release']['strategy'] = 'commit-sha'
        (self.root / 'workflow.config.json').write_text(json.dumps(self.config))
        self.assertIn('configuration drift', self.run_cli('--check-plan', str(output), ok=False))

    def test_changed_target_with_unchanged_head_invalidates_plan(self):
        self.git('commit', '--allow-empty', '-qm', 'next')
        self.git('branch', 'release-target', self.sha)
        output = self.root / '.dev-workflow/releases/target.json'
        self.run_cli('--sha', 'release-target', '--output', str(output))
        self.git('branch', '-f', 'release-target', 'HEAD')
        self.assertIn('Stale', self.run_cli('--check-plan', str(output), ok=False))

    def test_unadopted_configuration_and_malformed_plans_fail(self):
        manifest = self.root / '.dev-workflow/manifest.json'
        state = json.loads(manifest.read_text())
        del state['projectConfiguration']
        manifest.write_text(json.dumps(state))
        self.assertIn('adoption', self.run_cli(ok=False))
        invalid = self.root / '.dev-workflow/invalid.json'
        invalid.write_text('[]')
        self.assertIn('Invalid release plan', self.run_cli('--check-plan', str(invalid), ok=False))

    def test_output_cannot_escape_through_symlink(self):
        with tempfile.TemporaryDirectory() as external:
            (self.root / '.dev-workflow/releases').symlink_to(external, target_is_directory=True)
            self.assertIn('--output must be inside', self.run_cli('--output', '.dev-workflow/releases/out.json', ok=False))
            self.assertFalse((Path(external) / 'out.json').exists())


if __name__ == '__main__':
    unittest.main()
