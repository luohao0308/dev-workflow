"""Upgrade CLI regressions run entirely in isolated distributions and projects."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'DEV_WORKFLOW_NON_INTERACTIVE': '1'}
EXAMPLE = 'docs/UPGRADE-EXAMPLE.md'
OLD_TEXT = ''.join(f'Original independent line {number:02d}\n' for number in range(30))


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


class UpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed_temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.seed_temp.cleanup)
        cls.seed_root = Path(cls.seed_temp.name).resolve()
        cls.baseline = cls.seed_root / 'baseline'
        cls.baseline.mkdir()
        for directory in ('core', 'packs', 'scripts'):
            shutil.copytree(ROOT / directory, cls.baseline / directory,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        (cls.baseline / 'VERSION').write_text('0.8.0\n')
        (cls.baseline / 'core' / EXAMPLE).write_text(OLD_TEXT)
        cls.seed_project = cls.seed_root / 'installed'
        cls.seed_project.mkdir()
        result = subprocess.run(['bash', str(cls.baseline / 'scripts/install.sh'),
                                 '--target', str(cls.seed_project), '--packs', 'delivery',
                                 '--non-interactive'], capture_output=True, text=True, env=ENV)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'new-distribution'
        shutil.copytree(self.baseline, self.source)
        # Refresh the engine under development rather than relying on a stale seed.
        if (ROOT / 'scripts/upgrade.py').exists():
            shutil.copy2(ROOT / 'scripts/upgrade.py', self.source / 'scripts/upgrade.py')
        (self.source / 'VERSION').write_text('0.9.0\n')
        self.target = self.root / 'project'
        shutil.copytree(self.seed_project, self.target)
        self.manifest_path = self.target / '.dev-workflow/manifest.json'
        self.plan_path = self.root / 'plan.json'

    def cli(self, *args):
        return subprocess.run([sys.executable, str(self.source / 'scripts/upgrade.py'),
                               *map(str, args)], capture_output=True, text=True, env=ENV)

    def manifest(self):
        return json.loads(self.manifest_path.read_text())

    def new_text(self, text, path=EXAMPLE):
        (self.source / 'core' / path).write_text(text)

    def plan(self, baseline=None):
        result = self.cli('plan', '--target', self.target, '--baseline', baseline or self.baseline,
                          '--output', self.plan_path)
        self.assertTrue(self.plan_path.exists(), result.stdout + result.stderr)
        return json.loads(self.plan_path.read_text())

    def apply(self, success=True):
        result = self.cli('apply', '--target', self.target, '--plan', self.plan_path)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            value = json.loads(result.stdout)
            self.assertRegex(value['transaction'], r'^[0-9a-f]{32}$')
            self.assertTrue((self.target / '.dev-workflow/upgrades' / value['transaction'] / 'journal.json').is_file())
            return value['transaction']
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def rollback(self, transaction):
        return self.cli('rollback', '--target', self.target, '--transaction', transaction)

    def test_unmodified_update_has_reviewable_plan_and_preserves_policy(self):
        self.new_text(OLD_TEXT + 'New distribution guidance\n')
        before = snapshot(self.target)
        policy = self.manifest()['gitPolicy']
        plan = self.plan()
        self.assertEqual(snapshot(self.target), before)
        self.assertEqual(plan['schemaVersion'], 1)
        self.assertEqual(plan['kind'], 'workflow-upgrade-plan')
        self.assertEqual(plan['fromVersion'], '0.8.0')
        self.assertEqual(plan['toVersion'], '0.9.0')
        self.assertEqual(plan['target'], str(self.target))
        self.assertEqual(plan['source'], str(self.source))
        self.assertEqual(plan['baseline'], str(self.baseline))
        self.assertEqual(plan['manifestSha256'], hashlib.sha256(before['.dev-workflow/manifest.json']).hexdigest())
        self.assertIn('configurationSha256', plan)
        self.assertTrue(plan['ready'], plan)
        self.assertEqual(plan['conflicts'], [])
        self.apply()
        self.assertEqual((self.target / EXAMPLE).read_text(), OLD_TEXT + 'New distribution guidance\n')
        self.assertEqual(self.manifest()['gitPolicy'], policy)
        self.assertEqual(self.manifest()['workflowVersion'], '0.9.0')
        self.assertEqual(self.manifest()['installedPacks'], ['delivery'])
        self.assertFalse((self.target / 'scripts/upgrade.py').exists())

    def test_nonoverlapping_user_and_distribution_edits_merge(self):
        (self.target / EXAMPLE).write_text(OLD_TEXT.replace('line 02', 'user line 02'))
        self.new_text(OLD_TEXT.replace('line 27', 'distribution line 27'))
        plan = self.plan()
        self.assertTrue(plan['ready'], plan)
        self.apply()
        merged = (self.target / EXAMPLE).read_text()
        self.assertIn('user line 02', merged)
        self.assertIn('distribution line 27', merged)

    def test_conflict_rejects_entire_apply_without_partial_updates(self):
        (self.target / EXAMPLE).write_text(OLD_TEXT.replace('line 02', 'user line 02'))
        self.new_text(OLD_TEXT.replace('line 02', 'distribution line 02'))
        other = 'docs/WORKFLOW-ADOPTION.md'
        self.new_text((self.source / 'core' / other).read_text() + '\nNew adoption reference\n', other)
        before = snapshot(self.target)
        plan = self.plan()
        self.assertFalse(plan['ready'])
        self.assertTrue(plan['conflicts'])
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)

    def test_forged_baseline_does_not_establish_ownership(self):
        fake = self.root / 'fake-baseline'
        shutil.copytree(self.baseline, fake)
        (fake / 'core' / EXAMPLE).write_text('fabricated ancestor\n')
        self.new_text('new edition\n')
        before = snapshot(self.target)
        plan = self.plan(baseline=fake)
        self.assertFalse(plan['ready'], plan)
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)

    def test_unknown_core_block_cannot_be_automatically_migrated(self):
        path = self.target / 'AGENTS.md'
        path.write_text(path.read_text().replace('<!-- AI-WORKFLOW:CORE:END -->',
                                                'User core customization\n<!-- AI-WORKFLOW:CORE:END -->'))
        source = self.source / 'core/AGENTS.md'
        source.write_text(source.read_text().replace('<!-- AI-WORKFLOW:CORE:END -->',
                                                    'New core guidance\n<!-- AI-WORKFLOW:CORE:END -->'))
        before = snapshot(self.target)
        plan = self.plan()
        self.assertFalse(plan['ready'], plan)
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)

    def test_missing_baseline_does_not_modify_project(self):
        before = snapshot(self.target)
        result = self.cli('plan', '--target', self.target, '--baseline', self.root / 'missing',
                          '--output', self.plan_path)
        if self.plan_path.exists():
            self.assertFalse(json.loads(self.plan_path.read_text())['ready'])
            self.apply(success=False)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(snapshot(self.target), before)

    def test_unanchored_appended_core_is_not_proven_by_matching_text(self):
        manifest = self.manifest()
        entry = next(item for item in manifest['files'] if item['path'] == 'AGENTS.md')
        entry['action'] = 'appended'
        entry['installedSha256'] = None
        write_json(self.manifest_path, manifest)
        source = self.source / 'core/AGENTS.md'
        source.write_text(source.read_text().replace('<!-- AI-WORKFLOW:CORE:END -->',
                                                    'New core guidance\n<!-- AI-WORKFLOW:CORE:END -->'))
        before = snapshot(self.target)
        plan = self.plan()
        self.assertFalse(plan['ready'], plan)
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)

    def test_conflict_flags_cannot_be_cleared_to_authorize_apply(self):
        (self.target / EXAMPLE).write_text(OLD_TEXT.replace('line 02', 'user line 02'))
        self.new_text(OLD_TEXT.replace('line 02', 'distribution line 02'))
        plan = self.plan()
        self.assertFalse(plan['ready'])
        plan['ready'] = True
        plan['conflicts'] = []
        write_json(self.plan_path, plan)
        before = snapshot(self.target)
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)

    def test_proven_core_block_migrates_and_records_its_baseline(self):
        source = self.source / 'core/AGENTS.md'
        source.write_text(source.read_text().replace('<!-- AI-WORKFLOW:CORE:END -->',
                                                    'New core guidance\n<!-- AI-WORKFLOW:CORE:END -->'))
        plan = self.plan()
        self.assertTrue(plan['ready'], plan)
        self.apply()
        self.assertIn('New core guidance', (self.target / 'AGENTS.md').read_text())
        state = self.manifest()['upgradeState']['coreBlock']
        self.assertEqual(state['version'], '0.9.0')
        for key in ('baselineSha256', 'installedSha256'):
            self.assertRegex(state[key], r'^[0-9a-f]{64}$')

    def test_target_change_after_plan_is_rejected(self):
        self.new_text(OLD_TEXT + 'new\n')
        self.assertTrue(self.plan()['ready'])
        (self.target / EXAMPLE).write_text('user edit after planning\n')
        before = snapshot(self.target)
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)

    def test_source_change_after_plan_is_rejected(self):
        self.new_text(OLD_TEXT + 'new\n')
        self.assertTrue(self.plan()['ready'])
        self.new_text('unexpected distribution edit\n')
        before = snapshot(self.target)
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)

    def test_plan_path_tampering_is_rejected(self):
        self.new_text(OLD_TEXT + 'new\n')
        plan = self.plan()
        next(entry for entry in plan['entries'] if entry['path'] == EXAMPLE)['path'] = '../escaped.txt'
        write_json(self.plan_path, plan)
        before = snapshot(self.target)
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)
        self.assertFalse((self.root / 'escaped.txt').exists())

    def test_manifest_and_configuration_changes_after_plan_are_rejected(self):
        for name in ('manifest', 'configuration'):
            with self.subTest(name=name):
                self.plan()
                if name == 'manifest':
                    value = self.manifest()
                    value['gitPolicy']['pushActor'] = 'ai'
                    write_json(self.manifest_path, value)
                else:
                    (self.target / 'workflow.config.json').write_text('{}\n')
                before = snapshot(self.target)
                self.apply(success=False)
                self.assertEqual(snapshot(self.target), before)

    def test_modified_delivery_guard_is_always_a_conflict(self):
        guard = self.target / 'scripts/delivery_guard.py'
        guard.write_text(guard.read_text() + '\n# user guard modification\n')
        source = self.source / 'core/scripts/delivery_guard.py'
        source.write_text(source.read_text().replace('import argparse', 'import argparse\n# distribution guard revision', 1))
        before = snapshot(self.target)
        plan = self.plan()
        self.assertFalse(plan['ready'], plan)
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)

    def test_removed_source_is_conflict_not_deletion(self):
        (self.source / 'core' / EXAMPLE).unlink()
        before = snapshot(self.target)
        plan = self.plan()
        self.assertFalse(plan['ready'], plan)
        self.apply(success=False)
        self.assertEqual(snapshot(self.target), before)

    def test_rollback_restores_before_images_and_is_idempotent(self):
        self.new_text(OLD_TEXT + 'new\n')
        original_manifest = self.manifest_path.read_bytes()
        self.plan()
        transaction = self.apply()
        for _ in range(2):
            result = self.rollback(transaction)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((self.target / EXAMPLE).read_text(), OLD_TEXT)
            self.assertEqual(self.manifest_path.read_bytes(), original_manifest)

    def test_rollback_preserves_user_changes_after_apply(self):
        self.new_text(OLD_TEXT + 'new\n')
        self.plan()
        transaction = self.apply()
        (self.target / EXAMPLE).write_text('user edit after upgrade\n')
        result = self.rollback(transaction)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.target / EXAMPLE).read_text(), 'user edit after upgrade\n')

    def test_document_transfer_dry_run_and_preserved_ownership(self):
        relative = 'docs/PROJECT-SUMMARY.md'
        before = snapshot(self.target)
        result = self.cli('transfer', '--target', self.target, '--paths', relative, '--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(snapshot(self.target), before)
        policy = self.manifest()['gitPolicy']
        result = self.cli('transfer', '--target', self.target, '--paths', relative)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = self.manifest()
        self.assertEqual(manifest['gitPolicy'], policy)
        self.assertIn(relative, manifest['upgradeState']['projectOwned'])
        record = next(item for item in manifest['files'] if item['path'] == relative)
        self.assertEqual(record['action'], 'preserved')
        self.assertIsNone(record['installedSha256'])
        custom = 'Project owns this adopted summary\n'
        (self.target / relative).write_text(custom)
        self.new_text('New template must not replace project knowledge\n', relative)
        plan = self.plan()
        self.assertTrue(plan['ready'], plan)
        self.apply()
        self.assertEqual((self.target / relative).read_text(), custom)

    def test_transfer_rejects_protected_and_outside_paths_atomically(self):
        for relative in ('docs/TASKS.md', 'docs/WORKING-CONTEXT.md', 'AGENTS.md',
                         'scripts/delivery_guard.py', '.dev-workflow/manifest.json',
                         '../outside.md', 'docs/project-memory/README.md'):
            with self.subTest(path=relative):
                before = snapshot(self.target)
                result = self.cli('transfer', '--target', self.target, '--paths',
                                  'docs/PROJECT-SUMMARY.md', relative)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(snapshot(self.target), before)

    def test_symlink_target_file_is_rejected_without_touching_outside(self):
        outside = self.root / 'outside.md'
        outside.write_text('private outside content\n')
        path = self.target / EXAMPLE
        path.unlink()
        path.symlink_to(outside)
        self.new_text(OLD_TEXT + 'new\n')
        result = self.cli('plan', '--target', self.target, '--baseline', self.baseline,
                          '--output', self.plan_path)
        if self.plan_path.exists():
            self.assertFalse(json.loads(self.plan_path.read_text())['ready'])
            self.apply(success=False)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(path.is_symlink())
        self.assertEqual(outside.read_text(), 'private outside content\n')

    def test_tracked_metadata_in_nested_project_blocks_private_backups(self):
        subprocess.run(['git', '-C', str(self.root), 'init', '-q'], check=True, capture_output=True, env=ENV)
        subprocess.run(['git', '-C', str(self.root), 'add', '-f', '--',
                        'project/.dev-workflow/manifest.json'], check=True, capture_output=True, env=ENV)
        before = snapshot(self.target)
        result = self.cli('plan', '--target', self.target, '--baseline', self.baseline,
                          '--output', self.plan_path)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Git tracks local workflow metadata', result.stderr)
        self.assertEqual(snapshot(self.target), before)
        self.assertFalse((self.target / '.dev-workflow/upgrades').exists())

    def test_unknown_metadata_and_local_authorizations_survive_upgrade(self):
        sentinel = self.target / '.dev-workflow/authorizations.json'
        sentinel.write_text('{"local": "keep exactly"}\n')
        configuration = self.target / 'workflow.config.json'
        # Explicit adoption belongs to fixture setup, never to the upgrade.
        configuration.write_text('{"schemaVersion": 1, "enabledCapabilities": []}\n')
        adopted = subprocess.run([sys.executable, str(self.target / 'scripts/workflow_config.py'),
                                  'adopt', '--repo', str(self.target)],
                                 capture_output=True, text=True, env=ENV)
        self.assertEqual(adopted.returncode, 0, adopted.stdout + adopted.stderr)
        configuration_before = configuration.read_bytes()
        adoption_before = self.manifest()['projectConfiguration']
        for args in (['init', '-q'], ['add', '--', 'docs/PROJECT-SUMMARY.md']):
            result = subprocess.run(['git', '-C', str(self.target), *args],
                                    capture_output=True, text=True, env=ENV)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        index = self.target / '.git/index'
        if index.parent.is_dir():
            index_before = index.read_bytes() if index.exists() else None
        else:
            index_before = None
        self.new_text(OLD_TEXT + 'new\n')
        plan = self.plan()
        self.assertTrue(plan['ready'], plan)
        self.apply()
        self.assertEqual(sentinel.read_text(), '{"local": "keep exactly"}\n')
        self.assertEqual(configuration.read_bytes(), configuration_before)
        self.assertEqual(self.manifest()['projectConfiguration'], adoption_before)
        self.assertEqual(index.read_bytes() if index.exists() else None, index_before)


if __name__ == '__main__':
    unittest.main()
