"""Exercise the actual local v0.8.0 distribution, without synthetic old sources."""
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'DEV_WORKFLOW_NON_INTERACTIVE': '1'}
CORE_START = b'<!-- AI-WORKFLOW:CORE:START -->'
CORE_END = b'<!-- AI-WORKFLOW:CORE:END -->'


def snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob('*') if path.is_file() and not path.is_symlink()}


def archive_baseline(destination):
    result = subprocess.run(['git', '-C', str(ROOT), 'archive', '--format=tar', 'v0.8.0'],
                            capture_output=True, env=ENV)
    if result.returncode:
        raise AssertionError(result.stderr.decode('utf-8', errors='replace'))
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode='r:') as archive:
        members = archive.getmembers()
        # Validate every member before extracting any of the historical distribution.
        for member in members:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or '..' in name.parts or '\\' in member.name
                    or ':' in member.name or not name.parts
                    or not (member.isfile() or member.isdir())
                    or not (destination / member.name).resolve().is_relative_to(destination)):
                raise AssertionError('Unsafe historical archive member: ' + member.name)
        for member in members:
            path = destination / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, path.open('wb') as target:
                    shutil.copyfileobj(source, target)
                path.chmod(stat.S_IMODE(member.mode) & 0o777)


def outside_core(data):
    start = data.index(CORE_START)
    finish = data.index(CORE_END) + len(CORE_END)
    return data[:start], data[finish:]


class HistoricalUpgradeTests(unittest.TestCase):
    def test_historical_upgrade_preserves_and_rejects_conflicting_runtime_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            baseline = root / 'v0.8.0'
            archive_baseline(baseline)
            target = root / 'project'
            target.mkdir()
            installed = subprocess.run(['bash', str(baseline / 'scripts/install.sh'),
                                        '--target', str(target), '--non-interactive'],
                                       capture_output=True, text=True, env=ENV)
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            helper = target / 'scripts/workflow_lock.py'
            helper.write_bytes(b'PROJECT_HELPER = True\n')
            before = snapshot(target)
            plan_path = root / 'plan.json'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/upgrade.py'),
                                     'plan', '--target', str(target), '--baseline', str(baseline),
                                     '--output', str(plan_path)], capture_output=True, text=True, env=ENV)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            plan = json.loads(plan_path.read_text(encoding='utf-8'))
            self.assertFalse(plan['ready'])
            self.assertIn('scripts/workflow_lock.py', plan['conflicts'])
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/upgrade.py'),
                                     'apply', '--target', str(target), '--plan', str(plan_path)],
                                    capture_output=True, text=True, env=ENV)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(snapshot(target), before)

    def test_local_v080_archive_upgrades_and_rolls_back_preserving_project_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            baseline = root / 'v0.8.0'
            archive_baseline(baseline)
            self.assertEqual((baseline / 'VERSION').read_text().strip(), '0.8.0')
            source = root / 'current-distribution'
            source.mkdir()
            for name in ('core', 'packs', 'scripts'):
                shutil.copytree(ROOT / name, source / name,
                                ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            shutil.copy2(ROOT / 'VERSION', source / 'VERSION')
            current_version = (source / 'VERSION').read_text().strip()
            self.assertNotEqual(current_version, '0.8.0')
            target = root / 'project'
            target.mkdir()
            install = subprocess.run(['bash', str(baseline / 'scripts/install.sh'),
                                      '--target', str(target), '--packs', 'delivery',
                                      '--non-interactive'],
                                     capture_output=True, text=True, env=ENV)
            self.assertEqual(install.returncode, 0, install.stdout + install.stderr)
            manifest_path = target / '.dev-workflow/manifest.json'
            initial_manifest = json.loads(manifest_path.read_text())
            self.assertEqual(initial_manifest['workflowVersion'], '0.8.0')
            self.assertEqual(initial_manifest['gitPolicy']['pushActor'], 'user')
            adopt = subprocess.run([sys.executable, str(target / 'scripts/workflow_config.py'),
                                    'adopt', '--create', '--repo', str(target)],
                                   capture_output=True, text=True, env=ENV)
            self.assertEqual(adopt.returncode, 0, adopt.stdout + adopt.stderr)
            agents = target / 'AGENTS.md'
            agents.write_bytes(b'Project-specific preamble: preserve my rules.\n\n'
                               + agents.read_bytes()
                               + b'\nProject-specific trailing notes: keep this evidence.\n')
            before = snapshot(target)
            manifest = json.loads(manifest_path.read_text())
            outside_before = outside_core(before['AGENTS.md'])
            plan_path = root / 'reviewed-plan.json'

            def cli(*args):
                return subprocess.run([sys.executable, str(source / 'scripts/upgrade.py'),
                                       *map(str, args)], capture_output=True, text=True, env=ENV)

            planned = cli('plan', '--target', target, '--baseline', baseline, '--output', plan_path)
            self.assertEqual(planned.returncode, 0, planned.stdout + planned.stderr)
            plan = json.loads(plan_path.read_text())
            self.assertEqual(plan['fromVersion'], '0.8.0')
            self.assertEqual(plan['toVersion'], current_version)
            self.assertEqual(plan['baseline'], str(baseline))
            self.assertTrue(plan['ready'], plan)
            self.assertEqual(plan['conflicts'], [])
            self.assertTrue(any(entry['action'] in ('update', 'merge', 'create')
                                for entry in plan['entries']), 'Historical test must apply actual changes')
            self.assertEqual(snapshot(target), before)
            applied = cli('apply', '--target', target, '--plan', plan_path)
            self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
            transaction = json.loads(applied.stdout)['transaction']
            after_manifest = json.loads(manifest_path.read_text())
            self.assertEqual(after_manifest['workflowVersion'], current_version)
            self.assertEqual(after_manifest['gitPolicy'], manifest['gitPolicy'])
            self.assertEqual(after_manifest['projectConfiguration'], manifest['projectConfiguration'])
            self.assertEqual(after_manifest['enabledCapabilities'], manifest['enabledCapabilities'])
            self.assertEqual(after_manifest['installedPacks'], manifest['installedPacks'])
            self.assertEqual((target / 'workflow.config.json').read_bytes(), before['workflow.config.json'])
            self.assertEqual(outside_core(agents.read_bytes()), outside_before)
            self.assertFalse((target / 'scripts/upgrade.py').exists())
            rolled_back = cli('rollback', '--target', target, '--transaction', transaction)
            self.assertEqual(rolled_back.returncode, 0, rolled_back.stdout + rolled_back.stderr)
            restored = {name: data for name, data in snapshot(target).items()
                        if not name.startswith('.dev-workflow/upgrades/')}
            self.assertEqual(restored, before)
            journal = target / '.dev-workflow/upgrades' / transaction / 'journal.json'
            self.assertEqual(json.loads(journal.read_text())['status'], 'rolled-back')


if __name__ == '__main__':
    unittest.main()
