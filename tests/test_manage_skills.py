"""Skill lifecycle tests use only isolated destinations, never user installs."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('manage_skills', Path(__file__).resolve().parents[1] / 'scripts/manage_skills.py')
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)


class SkillLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.dest = self.root / '.agents/skills'
        self.name = 'workflow-doctor'
        self.addCleanup(self.temp.cleanup)

    def run_manager(self, action, *extra):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return manager.main([action, '--skills', self.name, '--target', str(self.root), *extra])

    def test_install_and_uninstall(self):
        self.assertEqual(self.run_manager('install'), 0)
        self.assertTrue((self.dest / self.name / 'SKILL.md').is_file())
        self.assertEqual(self.run_manager('uninstall'), 0)
        self.assertFalse((self.dest / self.name).exists())

    def test_dry_run_has_no_writes(self):
        self.assertEqual(self.run_manager('install', '--dry-run'), 0)
        self.assertFalse(self.dest.exists())
        self.run_manager('install')
        self.assertEqual(self.run_manager('uninstall', '--dry-run'), 0)
        self.assertTrue((self.dest / self.name).exists())

    def test_conflict_never_overwrites(self):
        target = self.dest / self.name
        target.mkdir(parents=True)
        (target / 'SKILL.md').write_text('custom')
        self.assertEqual(self.run_manager('install'), 1)
        self.assertEqual((target / 'SKILL.md').read_text(), 'custom')
        self.assertEqual(self.run_manager('uninstall'), 1)

    def test_changed_files_and_extra_files_preserved(self):
        self.run_manager('install')
        target = self.dest / self.name
        original = (target / 'SKILL.md').read_text()
        (target / 'SKILL.md').write_text('changed')
        self.assertEqual(self.run_manager('uninstall'), 1)
        (target / 'SKILL.md').write_text(original)
        (target / 'notes.txt').write_text('user content')
        self.assertEqual(self.run_manager('uninstall'), 1)
        self.assertTrue((target / 'notes.txt').exists())

    def test_added_empty_directory_preserved(self):
        self.run_manager('install')
        (self.dest / self.name / 'custom').mkdir()
        self.assertEqual(self.run_manager('uninstall'), 1)
        self.assertTrue((self.dest / self.name / 'custom').is_dir())

    def test_corrupt_ownership_preserved(self):
        self.run_manager('install')
        (self.dest / self.name / manager.MARKER).write_text('[]')
        self.assertEqual(self.run_manager('uninstall'), 1)
        self.assertTrue((self.dest / self.name).exists())

    def test_traversal_rejected(self):
        self.assertEqual(self.run_manager('install', '--skills', '../outside'), 1)
        self.assertFalse(self.dest.exists())

    def test_self_consistent_forged_ownership_never_deletes_user_content(self):
        target = self.dest / self.name
        target.mkdir(parents=True)
        (target / 'SKILL.md').write_text('custom user workflow', encoding='utf-8')
        (target / 'private-notes.txt').write_text('keep this', encoding='utf-8')
        (target / manager.MARKER).write_text(json.dumps({
            'owner': manager.OWNER, 'skill': self.name, 'files': manager.inventory(target),
        }), encoding='utf-8')
        self.assertEqual(self.run_manager('uninstall'), 1)
        self.assertEqual((target / 'private-notes.txt').read_text(encoding='utf-8'), 'keep this')

    def test_symlink_destination_rejected(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.root / '.agents').symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.run_manager('install'), 1)
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlink_content_preserved(self):
        self.run_manager('install')
        target = self.dest / self.name
        outside = self.root / 'outside'
        outside.write_text('keep')
        (target / 'link').symlink_to(outside)
        self.assertEqual(self.run_manager('uninstall'), 1)
        self.assertEqual(outside.read_text(), 'keep')

    def test_explicit_user_scope_isolated(self):
        with contextlib.redirect_stdout(io.StringIO()):
            result = manager.main(['install', '--skills', self.name, '--scope', 'user', '--skills-dir', str(self.root / 'isolated')])
        self.assertEqual(result, 0)
        self.assertTrue((self.root / 'isolated' / self.name / 'SKILL.md').exists())
        self.assertFalse(self.dest.exists())

    def test_batch_conflict_preflight(self):
        (self.dest / 'workflow-release').mkdir(parents=True)
        self.assertEqual(self.run_manager('install', '--skills', self.name, 'workflow-release'), 1)
        self.assertFalse((self.dest / self.name).exists())


class UpgradeSkillLifecycleTests(SkillLifecycleTests):
    """The optional upgrade entry point obeys the existing lifecycle boundaries."""

    def setUp(self):
        super().setUp()
        self.name = 'workflow-upgrade'

    def test_install_only_requested_upgrade_skill(self):
        self.assertEqual(self.run_manager('install'), 0)
        self.assertEqual({item.name for item in self.dest.iterdir()}, {self.name})
        self.assertFalse((self.root / 'scripts').exists())
        self.assertFalse((self.root / '.dev-workflow').exists())


class DeploySkillLifecycleTests(SkillLifecycleTests):
    """Deployment planning is an independently selected optional Skill."""

    def setUp(self):
        super().setUp()
        self.name = 'workflow-deploy'

    def test_install_only_requested_deploy_skill(self):
        self.assertEqual(self.run_manager('install'), 0)
        self.assertEqual({item.name for item in self.dest.iterdir()}, {self.name})
        self.assertFalse((self.root / 'scripts').exists())
        self.assertFalse((self.root / '.dev-workflow').exists())


if __name__ == '__main__':
    unittest.main()
