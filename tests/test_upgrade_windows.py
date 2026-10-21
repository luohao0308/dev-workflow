"""Native Windows lifecycle tests using PowerShell installs and the real upgrade CLI.

Versions 0.8.0 and 0.9.0 are intentional synthetic distributions, not release archives.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUTF8': '1',
       'DEV_WORKFLOW_NON_INTERACTIVE': '1'}
EXAMPLE = 'docs/UPGRADE-WINDOWS-EXAMPLE.md'
OLD_TEXT = ''.join(f'Original independent line {number:02d}\n' for number in range(30))
CORE_START = b'<!-- AI-WORKFLOW:CORE:START -->'
CORE_END = b'<!-- AI-WORKFLOW:CORE:END -->'


def write_utf8(path, value):
    # Bytes prevent Windows newline translation from changing fixture hashes.
    path.write_bytes(value.encode('utf-8'))


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob('*') if path.is_file()}


def outside_core(data):
    start = data.index(CORE_START)
    finish = data.index(CORE_END) + len(CORE_END)
    if data[finish:finish + 2] == b'\r\n':
        finish += 2
    elif data[finish:finish + 1] == b'\n':
        finish += 1
    return data[:start], data[finish:]


@unittest.skipUnless(os.name == 'nt', 'requires native Windows PowerShell lifecycle')
class WindowsUpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pwsh = shutil.which('pwsh')
        if cls.pwsh is None:
            raise AssertionError('Native Windows integration requires PowerShell 7 (pwsh)')
        cls.seed_temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.seed_temp.cleanup)
        seed = Path(cls.seed_temp.name).resolve()
        cls.baseline = seed / 'baseline'
        cls.baseline.mkdir()
        for directory in ('core', 'packs', 'scripts'):
            shutil.copytree(ROOT / directory, cls.baseline / directory,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        write_utf8(cls.baseline / 'VERSION', '0.8.0\n')
        write_utf8(cls.baseline / 'core' / EXAMPLE, OLD_TEXT)
        # Deliberately model Windows CRLF content regardless of checkout settings.
        agents = cls.baseline / 'core/AGENTS.md'
        agents.write_bytes(agents.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
        cls.seed_project = seed / 'installed'
        cls.seed_project.mkdir()
        result = cls.run_command([cls.pwsh, '-NoProfile', '-NonInteractive', '-File',
                                  str(cls.baseline / 'scripts/install.ps1'),
                                  '-TargetPath', str(cls.seed_project), '-Packs', 'delivery',
                                  '-NonInteractiveInstall'])
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @staticmethod
    def run_command(arguments):
        return subprocess.run(list(map(str, arguments)), capture_output=True,
                              encoding='utf-8', errors='strict', env=ENV, timeout=180)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / 'current-distribution'
        shutil.copytree(self.baseline, self.source)
        write_utf8(self.source / 'VERSION', '0.9.0\n')
        self.target = self.root / 'project'
        shutil.copytree(self.seed_project, self.target)
        self.manifest_path = self.target / '.dev-workflow/manifest.json'
        self.plan_path = self.root / 'reviewed-plan.json'

    def cli(self, *arguments):
        return self.run_command([sys.executable, self.source / 'scripts/upgrade.py', *arguments])

    def powershell(self, name, *arguments):
        return self.run_command([self.pwsh, '-NoProfile', '-NonInteractive', '-File',
                                 self.source / 'scripts' / (name + '.ps1'),
                                 '-TargetPath', self.target, *arguments])

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def manifest(self):
        return json.loads(self.manifest_path.read_text(encoding='utf-8'))

    def plan(self):
        result = self.cli('plan', '--target', self.target, '--baseline', self.baseline,
                          '--output', self.plan_path)
        self.assert_success(result)
        return json.loads(self.plan_path.read_text(encoding='utf-8'))

    def apply(self):
        result = self.assert_success(self.cli('apply', '--target', self.target,
                                              '--plan', self.plan_path))
        transaction = json.loads(result.stdout)['transaction']
        self.assertRegex(transaction, r'^[0-9a-f]{32}$')
        return transaction

    def change_example(self):
        write_utf8(self.source / 'core' / EXAMPLE, OLD_TEXT + 'Distribution addition\n')

    def test_crlf_core_upgrade_preserves_outside_bytes_and_rolls_back(self):
        agents = self.target / 'AGENTS.md'
        installed = agents.read_bytes()
        self.assertIn(CORE_START + b'\r\n', installed)
        self.assertEqual(installed, (self.baseline / 'core/AGENTS.md').read_bytes())
        agents.write_bytes('项目规则\r\n\r\n'.encode('utf-8') + installed
                           + '\r\n项目备注\r\n'.encode('utf-8'))
        source_agents = self.source / 'core/AGENTS.md'
        source_agents.write_bytes(source_agents.read_bytes().replace(
            CORE_END, b'Windows distribution core addition\r\n' + CORE_END))
        before = snapshot(self.target)
        manifest_before = self.manifest()
        plan = self.plan()
        self.assertTrue(plan['ready'], plan)
        self.assertEqual((plan['fromVersion'], plan['toVersion']), ('0.8.0', '0.9.0'))
        self.assertEqual(snapshot(self.target), before)
        transaction = self.apply()
        self.assertIn(b'Windows distribution core addition\r\n', agents.read_bytes())
        self.assertEqual(outside_core(agents.read_bytes()), outside_core(before['AGENTS.md']))
        self.assertEqual(self.manifest()['workflowVersion'], '0.9.0')
        for key in ('gitPolicy', 'projectConfiguration', 'enabledCapabilities', 'installedPacks'):
            self.assertEqual(self.manifest().get(key), manifest_before.get(key))
        for _ in range(2):
            self.assert_success(self.cli('rollback', '--target', self.target,
                                         '--transaction', transaction))
            restored = {name: data for name, data in snapshot(self.target).items()
                        if not name.startswith('.dev-workflow/upgrades/')}
            self.assertEqual(restored, before)
        journal = self.target / '.dev-workflow/upgrades' / transaction / 'journal.json'
        self.assertEqual(json.loads(journal.read_text(encoding='utf-8'))['status'], 'rolled-back')

    def test_nonoverlapping_three_way_edits_merge(self):
        write_utf8(self.target / EXAMPLE, OLD_TEXT.replace('line 02', 'user line 02'))
        write_utf8(self.source / 'core' / EXAMPLE,
                   OLD_TEXT.replace('line 27', 'distribution line 27'))
        plan = self.plan()
        self.assertTrue(plan['ready'], plan)
        row = next(item for item in plan['entries'] if item['path'] == EXAMPLE)
        self.assertEqual(row['action'], 'merge')
        self.apply()
        merged = (self.target / EXAMPLE).read_text(encoding='utf-8')
        self.assertIn('user line 02', merged)
        self.assertIn('distribution line 27', merged)

    def test_conflict_rejects_apply_without_any_project_writes(self):
        write_utf8(self.target / EXAMPLE, OLD_TEXT.replace('line 02', 'user line 02'))
        write_utf8(self.source / 'core' / EXAMPLE,
                   OLD_TEXT.replace('line 02', 'distribution line 02'))
        other = self.source / 'core/docs/WORKFLOW-ADOPTION.md'
        write_utf8(other, other.read_text(encoding='utf-8') + '\nIndependent update\n')
        before = snapshot(self.target)
        plan = self.plan()
        self.assertFalse(plan['ready'], plan)
        self.assertTrue(plan['conflicts'])
        result = self.cli('apply', '--target', self.target, '--plan', self.plan_path)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(snapshot(self.target), before)

    def test_transfer_upgrade_reinstall_uninstall_preserve_document_and_history(self):
        relative = 'docs/PROJECT-SUMMARY.md'
        before = snapshot(self.target)
        self.assert_success(self.cli('transfer', '--target', self.target,
                                     '--paths', relative, '--dry-run'))
        self.assertEqual(snapshot(self.target), before)
        self.assert_success(self.cli('transfer', '--target', self.target, '--paths', relative))
        document = self.target / relative
        write_utf8(document, 'Project-owned summary: 项目知识\n')
        expected_document = document.read_bytes()
        write_utf8(self.source / 'core' / relative, 'New upstream template\n')
        self.change_example()
        self.assertTrue(self.plan()['ready'])
        self.apply()
        state = self.manifest()['upgradeState']
        self.assertIn(relative, state['projectOwned'])
        history = snapshot(self.target / '.dev-workflow/upgrades')
        self.assertTrue(history)
        self.assert_success(self.powershell('install', '-Packs', 'delivery', '-NonInteractiveInstall'))
        self.assertEqual(self.manifest()['upgradeState'], state)
        self.assertEqual(document.read_bytes(), expected_document)
        self.assert_success(self.powershell('uninstall', '-Packs', 'delivery'))
        self.assertEqual(self.manifest()['upgradeState'], state)
        self.assert_success(self.powershell('uninstall'))
        self.assertFalse(self.manifest_path.exists())
        self.assertEqual(document.read_bytes(), expected_document)
        self.assertEqual(snapshot(self.target / '.dev-workflow/upgrades'), history)

    def test_rollback_refuses_to_overwrite_user_edit(self):
        self.change_example()
        self.assertTrue(self.plan()['ready'])
        transaction = self.apply()
        write_utf8(self.target / EXAMPLE, 'User edit after upgrade: 保留\n')
        before = snapshot(self.target)
        result = self.cli('rollback', '--target', self.target, '--transaction', transaction)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(snapshot(self.target), before)

    def test_unknown_baseline_cannot_authorize_upgrade(self):
        self.change_example()
        before = snapshot(self.target)
        result = self.cli('plan', '--target', self.target, '--output', self.plan_path)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('baseline', result.stderr.lower())
        self.assertFalse(self.plan_path.exists())
        self.assertEqual(snapshot(self.target), before)

    def test_fresh_powershell_install_rejects_existing_unrelated_runtime_helper(self):
        self.target = self.root / 'fresh-project'
        helper = self.target / 'scripts/workflow_lock.py'
        helper.parent.mkdir(parents=True)
        write_utf8(helper, '# Unrelated project helper: 保留\n')
        before = snapshot(self.target)
        result = self.powershell('install', '-Packs', 'delivery', '-NonInteractiveInstall')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('workflow_lock.py', result.stdout + result.stderr)
        self.assertIn('conflict', (result.stdout + result.stderr).lower())
        self.assertEqual(snapshot(self.target), before)
        self.assertFalse((self.target / '.dev-workflow').exists())

    def test_upgrade_rejects_unowned_runtime_helper_without_project_writes(self):
        # Model a legacy project helper lacking an installer ownership record.
        manifest = self.manifest()
        manifest['files'] = [entry for entry in manifest['files']
                             if entry['path'] != 'scripts/workflow_lock.py']
        write_utf8(self.manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
        write_utf8(self.target / 'scripts/workflow_lock.py', '# Project-owned helper: 保留\n')
        self.change_example()
        before = snapshot(self.target)
        plan = self.plan()
        self.assertFalse(plan['ready'], plan)
        row = next(entry for entry in plan['entries'] if entry['path'] == 'scripts/workflow_lock.py')
        self.assertEqual(row['action'], 'conflict')
        self.assertIn('helper', row['reason'].lower())
        result = self.cli('apply', '--target', self.target, '--plan', self.plan_path)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(snapshot(self.target), before)

    def test_powershell_rechecks_history_appearing_after_preflight_under_lock(self):
        # This exercises lifecycle concurrency within the installed version.
        write_utf8(self.source / 'VERSION', '0.8.0\n')
        transaction = 'a' * 32
        relative = '.dev-workflow/upgrades/' + transaction + '/journal.json'
        for name in ('install', 'uninstall'):
            with self.subTest(entrypoint=name):
                self.target = self.root / ('race-project-' + name)
                shutil.copytree(self.seed_project, self.target)
                self.assertFalse((self.target / '.dev-workflow/upgrades').exists())
                self.assertNotIn('upgradeState', json.loads(
                    (self.target / '.dev-workflow/manifest.json').read_text(encoding='utf-8')))
                before = snapshot(self.target)
                journal = {'schemaVersion': 1, 'target': str(self.target),
                           'transaction': transaction, 'status': 'prepared', 'items': []}
                journal_text = json.dumps(journal, ensure_ascii=False) + '\n'
                # Inject into the copied distribution only: preflight has completed
                # and owner.json is held, but the current-history check has not run.
                script = self.source / 'scripts' / (name + '.ps1')
                content = script.read_text(encoding='utf-8')
                anchor = '        $currentFingerprint = '
                self.assertEqual(content.count(anchor), 1)
                injection = (
                    "        $raceJournal = Join-Path $targetRoot '" + relative + "'\n"
                    "        [IO.Directory]::CreateDirectory((Split-Path -Parent $raceJournal)) | Out-Null\n"
                    "        [IO.File]::WriteAllText($raceJournal, '"
                    + journal_text.replace("'", "''") + "', [Text.UTF8Encoding]::new($false))\n"
                )
                write_utf8(script, content.replace(anchor, injection + anchor, 1))
                arguments = ('-NonInteractiveInstall',) if name == 'install' else ()
                result = self.powershell(name, *arguments)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Incomplete transaction', result.stdout + result.stderr)
                self.assertEqual((self.target / relative).read_bytes(), journal_text.encode('utf-8'))
                after = {path: data for path, data in snapshot(self.target).items() if path != relative}
                self.assertEqual(after, before)
                self.assertFalse((self.target / '.dev-workflow/lifecycle.lock/owner.json').exists())

    def test_post_apply_strict_audit_warning_and_shared_lock_rejection(self):
        self.change_example()
        self.assertTrue(self.plan()['ready'])
        self.apply()
        agents = self.target / 'AGENTS.md'
        agents.write_bytes(agents.read_bytes().replace(CORE_END, b'User core edit\r\n' + CORE_END))
        before = snapshot(self.target)
        # Adoption is still pending; assert the specific upgrade warning, not audit success.
        audit = self.powershell('audit', '-Strict')
        self.assertNotEqual(audit.returncode, 0, audit.stdout + audit.stderr)
        self.assertIn('core-customized-since-upgrade', audit.stdout + audit.stderr)
        self.assertEqual(snapshot(self.target), before)
        lock = self.target / '.dev-workflow/lifecycle.lock/owner.json'
        lock.parent.mkdir(exist_ok=True)
        write_utf8(lock, json.dumps({'pid': os.getpid(), 'operation': 'upgrade',
                                    'transaction': None}) + '\n')
        locked = snapshot(self.target)
        for name, arguments in (('install', ('-NonInteractiveInstall',)),
                                ('uninstall', ()), ('audit', ('-Strict',))):
            with self.subTest(entrypoint=name):
                result = self.powershell(name, *arguments)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('lock', (result.stdout + result.stderr).lower())
                self.assertEqual(snapshot(self.target), locked)
        result = self.cli('transfer', '--target', self.target, '--paths', 'docs/PROJECT-SUMMARY.md')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('lock', (result.stdout + result.stderr).lower())
        self.assertEqual(snapshot(self.target), locked)


if __name__ == '__main__':
    unittest.main()
