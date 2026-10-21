"""Lifecycle gates use temporary projects and preserve upgrade ownership/history."""
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'DEV_WORKFLOW_NON_INTERACTIVE': '1'}


def run_script(name, target, *args):
    return subprocess.run(['bash', str(ROOT / 'scripts' / (name + '.sh')), '--target', str(target), *args], capture_output=True, text=True, env=ENV)


def fingerprint(target):
    return {str(p.relative_to(target)): p.read_bytes() for p in target.rglob('*') if p.is_file()}


class LifecycleLockTests(unittest.TestCase):
    def test_existing_owner_blocks_all_entrypoints_without_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            lock = target / '.dev-workflow/lifecycle.lock'
            lock.mkdir(parents=True)
            (lock / 'owner.json').write_text(json.dumps({'pid': 987654, 'operation': 'upgrade', 'transaction': None}))
            before = fingerprint(target)
            for name in ('install', 'uninstall', 'audit'):
                with self.subTest(name=name):
                    result = run_script(name, target, '--dry-run' if name != 'audit' else '--strict')
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('lock', result.stdout + result.stderr)
                    self.assertEqual(before, fingerprint(target))

    def test_fresh_install_rejects_conflicting_runtime_helper_before_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            helper = target / 'scripts/workflow_lock.py'
            helper.parent.mkdir()
            helper.write_bytes(b'PROJECT_HELPER = True\n')
            before = fingerprint(target)
            result = run_script('install', target, '--non-interactive')
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('runtime helper conflicts', result.stdout + result.stderr)
            self.assertEqual(before, fingerprint(target))

    def test_new_pending_history_is_checked_after_lock_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'distribution'
            source.mkdir()
            for name in ('core', 'packs', 'scripts'):
                shutil.copytree(ROOT / name, source / name,
                                ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            shutil.copy2(ROOT / 'VERSION', source / 'VERSION')
            for name in ('install', 'uninstall'):
                with self.subTest(name=name):
                    target = root / name
                    target.mkdir()
                    installed = run_script('install', target, '--non-interactive')
                    self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                    before = fingerprint(target)
                    script = source / 'scripts' / (name + '.sh')
                    original = script.read_text(encoding='utf-8')
                    injection = """  python3 - "$target_root" <<'HISTORY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
transaction = 'a' * 32
journal = root / '.dev-workflow/upgrades' / transaction / 'journal.json'
journal.parent.mkdir(parents=True)
journal.write_text(json.dumps(dict(schemaVersion=1, target=str(root), transaction=transaction, status='interrupted')), encoding='utf-8')
HISTORY
"""
                    marker = '  current_manifest_fingerprint="missing"'
                    self.assertIn(marker, original)
                    script.write_text(original.replace(marker, injection + marker, 1), encoding='utf-8')
                    result = subprocess.run(['bash', str(script), '--target', str(target)],
                                            capture_output=True, text=True, env=ENV)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('transaction', result.stdout + result.stderr)
                    after = {key: value for key, value in fingerprint(target).items()
                             if not key.startswith('.dev-workflow/upgrades/')}
                    self.assertEqual(before, after)

    def test_fresh_dry_run_does_not_create_metadata_or_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            result = run_script('install', target, '--dry-run', '--non-interactive')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((target / '.dev-workflow').exists())


class AuditUpgradeStrictTests(unittest.TestCase):
    def test_audit_forwards_strict_only_when_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            target = temporary / 'project'
            (target / '.dev-workflow/upgrades').mkdir(parents=True)
            commands = temporary / 'bin'
            commands.mkdir()
            log = temporary / 'upgrade-arguments.json'
            interpreter = commands / 'python3'
            interpreter.write_text(
                '#!' + sys.executable + '\n'
                'import json, os, sys\n'
                'from pathlib import Path\n'
                'if len(sys.argv) > 1 and Path(sys.argv[1]).name == "upgrade.py":\n'
                '    Path(os.environ["UPGRADE_ARGUMENT_LOG"]).write_text(json.dumps(sys.argv[2:]))\n'
                '    print("{\\"status\\":\\"warning\\"}")\n'
                '    raise SystemExit(1 if "--strict" in sys.argv else 0)\n'
                'os.execv(' + repr(sys.executable) + ', [' + repr(sys.executable) + '] + sys.argv[1:])\n'
            )
            interpreter.chmod(0o755)
            environment = {**ENV, 'PATH': str(commands) + os.pathsep + ENV['PATH'], 'UPGRADE_ARGUMENT_LOG': str(log)}
            for strict in (False, True):
                with self.subTest(strict=strict):
                    arguments = ['bash', str(ROOT / 'scripts/audit.sh'), '--target', str(target)]
                    if strict:
                        arguments.append('--strict')
                    result = subprocess.run(arguments, capture_output=True, text=True, env=environment)
                    self.assertTrue(log.exists(), result.stdout + result.stderr)
                    forwarded = json.loads(log.read_text())
                    self.assertEqual('--strict' in forwarded, strict)
                    self.assertEqual(forwarded[:1], ['check'])
                    if strict:
                        self.assertEqual(result.returncode, 1)
                        self.assertNotIn('dev-workflow audit', result.stdout)
                    log.unlink()


class UpgradeLifecycleTests(unittest.TestCase):
    def assert_success(self, name, target, *args):
        result = run_script(name, target, *args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((target / '.dev-workflow/lifecycle.lock/owner.json').exists())
        return result

    def test_reinstall_and_uninstall_preserve_transferred_documents_and_history(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            subprocess.run(['git', '-C', str(target), 'init', '-q'], check=True, env=ENV)
            self.assert_success('install', target, '--packs', 'delivery', '--non-interactive')
            manifest_path = target / '.dev-workflow/manifest.json'
            manifest = json.loads(manifest_path.read_text())
            agents = (ROOT / 'core/AGENTS.md').read_bytes()
            start = agents.index(b'<!-- AI-WORKFLOW:CORE:START -->')
            end = agents.index(b'<!-- AI-WORKFLOW:CORE:END -->') + len(b'<!-- AI-WORKFLOW:CORE:END -->')
            if agents[end:end + 2] == b'\r\n':
                end += 2
            elif agents[end:end + 1] == b'\n':
                end += 1
            block_hash = hashlib.sha256(agents[start:end]).hexdigest()
            state = {
                'schemaVersion': 1,
                'coreBlock': {'version': manifest['workflowVersion'], 'baselineSha256': block_hash, 'installedSha256': block_hash},
                'projectOwned': ['docs/PROJECT-SUMMARY.md'],
                'lastTransaction': 'a' * 32,
            }
            manifest['upgradeState'] = state
            entry = next(item for item in manifest['files'] if item['path'] == 'docs/PROJECT-SUMMARY.md')
            entry.update(action='preserved', installedSha256=None)
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
            transferred = target / 'docs/PROJECT-SUMMARY.md'
            transferred.unlink()
            history = target / '.dev-workflow/upgrades'
            history.mkdir()
            transaction = history / ('a' * 32)
            transaction.mkdir()
            journal = transaction / 'journal.json'
            journal.write_text(json.dumps({'schemaVersion': 1, 'target': str(target.resolve()), 'transaction': 'a' * 32, 'status': 'committed', 'items': []}))
            journal_bytes = journal.read_bytes()
            release = target / '.dev-workflow/releases/retained.json'
            release.parent.mkdir()
            release.write_text('{"fixture":true}')

            # Both stale versions and unfinished transactions fail before product writes.
            saved_manifest = manifest_path.read_bytes()
            manifest['workflowVersion'] = '0.0.1'
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
            before = fingerprint(target)
            for name in ('install', 'uninstall'):
                result = run_script(name, target)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('upgrade', result.stdout + result.stderr)
                self.assertEqual(before, fingerprint(target))
            manifest_path.write_bytes(saved_manifest)
            pending_journal = json.loads(journal.read_text())
            pending_journal['status'] = 'prepared'
            journal.write_text(json.dumps(pending_journal))
            before = fingerprint(target)
            for name in ('install', 'uninstall', 'audit'):
                result = run_script(name, target)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Incomplete transaction', result.stdout + result.stderr)
                self.assertEqual(before, fingerprint(target))
            journal.write_bytes(journal_bytes)

            self.assert_success('install', target, '--non-interactive')
            self.assertFalse(transferred.exists(), 'same-version installation must not resurrect project-owned documents')
            current = json.loads(manifest_path.read_text())
            self.assertEqual(current['upgradeState'], state)
            self.assertEqual(next(item for item in current['files'] if item['path'] == 'docs/PROJECT-SUMMARY.md')['action'], 'preserved')
            self.assert_success('uninstall', target, '--packs', 'delivery')
            self.assertEqual(json.loads(manifest_path.read_text())['upgradeState'], state)
            self.assert_success('uninstall', target)
            self.assertFalse(manifest_path.exists())
            self.assertTrue(history.is_dir())
            self.assertEqual(journal.read_bytes(), journal_bytes)
            self.assertEqual(release.read_text(), '{"fixture":true}')
            exclude = (target / '.git/info/exclude').read_text()
            self.assertIn('/.dev-workflow/', exclude)
            self.assert_success('install', target, '--non-interactive')
            self.assertTrue(history.is_dir())
            self.assertEqual(journal.read_bytes(), journal_bytes)
            self.assertEqual(release.read_text(), '{"fixture":true}')


if __name__ == '__main__':
    unittest.main()
