"""Real interrupted writes, dead-process locks and cached ancestor regressions."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest

from tests import test_upgrade as support

# The fault happens after the atomic target replacement, never during fixture setup.
FAULT_DRIVER = r'''
import importlib.util
import os
from pathlib import Path
import sys

engine, target, plan, failure = sys.argv[1:]
spec = importlib.util.spec_from_file_location('isolated_upgrade', engine)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original = module.write_bytes
fired = False

def faulty_write(path, data, mode=0o600):
    global fired
    original(path, data, mode)
    if not fired and path == Path(target) / 'docs/UPGRADE-EXAMPLE.md':
        fired = True
        if failure == 'crash':
            os._exit(73)
        raise OSError('injected after successful target replacement')

module.write_bytes = faulty_write
sys.argv = [engine, 'apply', '--target', target, '--plan', plan]
sys.exit(module.main())
'''

ROLLBACK_RACE_DRIVER = r'''
import importlib.util
import json
from pathlib import Path
import sys

engine, target, transaction = sys.argv[1:]
spec = importlib.util.spec_from_file_location('isolated_upgrade', engine)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original = module.write_bytes
fired = False

def racing_write(path, data, mode=0o600):
    global fired
    original(path, data, mode)
    if (not fired and path.name == 'journal.json'
            and json.loads(data).get('status') == 'rolling-back'):
        fired = True
        (Path(target) / 'docs/UPGRADE-EXAMPLE.md').write_text('User edit during rollback\n')

module.write_bytes = racing_write
sys.argv = [engine, 'rollback', '--target', target, '--transaction', transaction]
sys.exit(module.main())
'''


class UpgradeRecoveryTests(unittest.TestCase):
    # Reuse only fixture helpers. Inheriting UpgradeTests would rerun all 21 cases.
    @classmethod
    def setUpClass(cls):
        support.UpgradeTests.setUpClass.__func__(cls)

    setUp = support.UpgradeTests.setUp
    cli = support.UpgradeTests.cli
    manifest = support.UpgradeTests.manifest
    new_text = support.UpgradeTests.new_text
    plan = support.UpgradeTests.plan
    apply = support.UpgradeTests.apply
    rollback = support.UpgradeTests.rollback

    def interrupt(self, failure):
        self.new_text(support.OLD_TEXT + 'Distribution recovery revision\n')
        before = support.snapshot(self.target)
        self.assertTrue(self.plan()['ready'])
        result = subprocess.run([sys.executable, '-c', FAULT_DRIVER,
                                 str(self.source / 'scripts/upgrade.py'), str(self.target),
                                 str(self.plan_path), failure],
                                capture_output=True, text=True, env=support.ENV)
        self.assertEqual(result.returncode, 73 if failure == 'crash' else 1,
                         result.stdout + result.stderr)
        self.assertEqual((self.target / support.EXAMPLE).read_text(),
                         support.OLD_TEXT + 'Distribution recovery revision\n')
        journals = list((self.target / '.dev-workflow/upgrades').glob('*/journal.json'))
        self.assertEqual(len(journals), 1)
        journal_path = journals[0]
        journal = json.loads(journal_path.read_text())
        self.assertEqual(journal['status'], 'prepared' if failure == 'crash' else 'interrupted')
        return before, journal_path, journal['transaction']

    def assert_restored(self, before):
        after = support.snapshot(self.target)
        for name, value in before.items():
            with self.subTest(restored=name):
                self.assertEqual(after.get(name), value)
        self.assertEqual({name for name in after if not name.startswith('.dev-workflow/upgrades/')},
                         set(before))
        self.assertFalse((self.target / '.dev-workflow/lifecycle.lock/owner.json').exists())
        self.assertFalse((self.target / '.dev-workflow/configuration.lock').exists())

    def test_oserror_after_replacement_blocks_operations_until_idempotent_rollback(self):
        before, journal_path, transaction = self.interrupt('error')
        diagnostic = self.cli('check', '--target', self.target, '--operation', 'audit', '--json')
        self.assertNotEqual(diagnostic.returncode, 0, diagnostic.stdout + diagnostic.stderr)
        self.assertIn(transaction, diagnostic.stdout + diagnostic.stderr)
        for _ in range(2):
            result = self.rollback(transaction)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(journal_path.read_text())['status'], 'rolled-back')
            self.assert_restored(before)
        result = self.cli('check', '--target', self.target, '--operation', 'audit', '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_interrupted_upgrade_blocks_config_then_remains_recoverable(self):
        before, _, transaction = self.interrupt('error')
        original = self.manifest_path.read_bytes()
        result = subprocess.run([sys.executable, str(self.target / 'scripts/workflow_config.py'),
                                 'update', '--enable', 'release', '--repo', str(self.target)],
                                capture_output=True, text=True, env=support.ENV)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Incomplete upgrade transaction', result.stderr)
        self.assertEqual(self.manifest_path.read_bytes(), original)
        result = self.rollback(transaction)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_restored(before)

    def test_hard_exit_retains_two_locks_then_recovers_dead_transaction(self):
        before, journal_path, transaction = self.interrupt('crash')
        lifecycle = self.target / '.dev-workflow/lifecycle.lock/owner.json'
        configuration = self.target / '.dev-workflow/configuration.lock'
        owner = json.loads(lifecycle.read_text())
        config_owner = json.loads(configuration.read_text())
        self.assertEqual(owner['transaction'], transaction)
        self.assertEqual(config_owner['transaction'], transaction)
        self.assertEqual(owner['pid'], config_owner['pid'])
        if os.name == 'posix':
            with self.assertRaises(ProcessLookupError):
                os.kill(owner['pid'], 0)
        diagnostic = self.cli('check', '--target', self.target, '--operation', 'audit')
        self.assertNotEqual(diagnostic.returncode, 0, diagnostic.stdout + diagnostic.stderr)
        result = self.rollback(transaction)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(journal_path.read_text())['status'], 'rolled-back')
        self.assert_restored(before)
        again = self.rollback(transaction)
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assert_restored(before)

    def test_live_lifecycle_owner_and_configuration_lock_cannot_be_stolen(self):
        _, _, transaction = self.interrupt('error')
        lifecycle = self.target / '.dev-workflow/lifecycle.lock/owner.json'
        lifecycle.parent.mkdir(parents=True, exist_ok=True)
        configuration = self.target / '.dev-workflow/configuration.lock'
        support.write_json(lifecycle, {'pid': os.getpid(), 'transaction': transaction,
                                       'operation': 'upgrade', 'token': 'live-test-owner'})
        support.write_json(configuration, {'pid': os.getpid(), 'transaction': transaction})
        before = support.snapshot(self.target)
        result = self.rollback(transaction)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(support.snapshot(self.target), before)

    def test_live_configuration_owner_alone_cannot_be_stolen(self):
        _, _, transaction = self.interrupt('error')
        configuration = self.target / '.dev-workflow/configuration.lock'
        support.write_json(configuration, {'pid': os.getpid(), 'transaction': transaction})
        before = support.snapshot(self.target)
        result = self.rollback(transaction)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(support.snapshot(self.target), before)

    def test_readonly_mode_change_after_apply_prevents_rollback(self):
        self.new_text(support.OLD_TEXT + 'Distribution mode revision\n')
        self.assertTrue(self.plan()['ready'])
        transaction = self.apply()
        path = self.target / support.EXAMPLE
        original_mode = stat.S_IMODE(path.stat().st_mode)
        try:
            path.chmod(stat.S_IRUSR)
            readonly_mode = stat.S_IMODE(path.stat().st_mode)
            self.assertFalse(readonly_mode & stat.S_IWUSR)
            before = support.snapshot(self.target)
            result = self.rollback(transaction)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), readonly_mode)
            self.assertEqual(support.snapshot(self.target), before)
        finally:
            path.chmod(original_mode | stat.S_IWUSR)

    def test_user_edit_after_rollback_preflight_stops_before_overwrite(self):
        self.new_text(support.OLD_TEXT + 'Distribution race revision\n')
        self.assertTrue(self.plan()['ready'])
        transaction = self.apply()
        result = subprocess.run([sys.executable, '-c', ROLLBACK_RACE_DRIVER,
                                 str(self.source / 'scripts/upgrade.py'), str(self.target),
                                 transaction], capture_output=True, text=True, env=support.ENV)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.target / support.EXAMPLE).read_text(), 'User edit during rollback\n')
        journal = self.target / '.dev-workflow/upgrades' / transaction / 'journal.json'
        self.assertEqual(json.loads(journal.read_text())['status'], 'rolling-back')
        diagnostic = self.cli('check', '--target', self.target, '--operation', 'audit')
        self.assertNotEqual(diagnostic.returncode, 0, diagnostic.stdout + diagnostic.stderr)
        self.assertIn(transaction, diagnostic.stdout + diagnostic.stderr)

    def first_merged_upgrade(self):
        current = support.OLD_TEXT.replace('line 02', 'user line 02')
        first_distribution = support.OLD_TEXT.replace('line 27', 'distribution line 27')
        (self.target / support.EXAMPLE).write_text(current)
        self.new_text(first_distribution)
        self.assertTrue(self.plan()['ready'])
        transaction = self.apply()
        state = self.manifest()['upgradeState']
        self.assertEqual(state['baselineSnapshot'], transaction)
        baseline = self.target / '.dev-workflow/upgrades' / transaction / 'baseline'
        self.assertEqual((baseline / 'VERSION').read_text().strip(), '0.9.0')
        self.assertEqual((baseline / 'core' / support.EXAMPLE).read_text(), first_distribution)
        self.assertNotIn('user line 02', (baseline / 'core' / support.EXAMPLE).read_text())
        self.assertIn('user line 02', (self.target / support.EXAMPLE).read_text())
        self.plan_path.unlink()
        (self.source / 'VERSION').write_text('1.0.0\n')
        return baseline, first_distribution

    def test_second_upgrade_uses_raw_cached_distribution_and_preserves_user_merge(self):
        baseline, previous_distribution = self.first_merged_upgrade()
        self.new_text(previous_distribution.replace('line 20', 'second distribution line 20'))
        before = support.snapshot(self.target)
        result = self.cli('plan', '--target', self.target, '--output', self.plan_path)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        plan = json.loads(self.plan_path.read_text())
        self.assertEqual(plan['baseline'], str(baseline))
        self.assertEqual(plan['fromVersion'], '0.9.0')
        self.assertEqual(plan['toVersion'], '1.0.0')
        self.assertTrue(plan['ready'], plan)
        self.assertEqual(support.snapshot(self.target), before)
        transaction = self.apply()
        merged = (self.target / support.EXAMPLE).read_text()
        self.assertIn('user line 02', merged)
        self.assertIn('distribution line 27', merged)
        self.assertIn('second distribution line 20', merged)
        self.assertEqual(self.manifest()['upgradeState']['baselineSnapshot'], transaction)

    def test_tampered_cached_ancestor_is_rejected_without_project_writes(self):
        baseline, previous_distribution = self.first_merged_upgrade()
        (baseline / 'core' / support.EXAMPLE).write_text(previous_distribution + 'forged cached ancestor\n')
        self.new_text(previous_distribution.replace('line 20', 'second distribution line 20'))
        before = support.snapshot(self.target)
        result = self.cli('plan', '--target', self.target, '--output', self.plan_path)
        self.assertTrue(self.plan_path.exists(), result.stdout + result.stderr)
        plan = json.loads(self.plan_path.read_text())
        self.assertFalse(plan['ready'], plan)
        self.assertIn(support.EXAMPLE, plan['conflicts'])
        self.apply(success=False)
        self.assertEqual(support.snapshot(self.target), before)


if __name__ == '__main__':
    unittest.main()
