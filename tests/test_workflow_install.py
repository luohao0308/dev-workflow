"""Exercise adopted configuration through the actual Bash distribution tools."""
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt', 'Bash install coverage runs on Linux/macOS; PowerShell has integration.ps1')
class ConfigInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, DEV_WORKFLOW_NON_INTERACTIVE='1', PYTHONDONTWRITEBYTECODE='1', LC_ALL='C')

    def install(self, *args, ok=True):
        result = subprocess.run(['bash', str(ROOT / 'scripts/install.sh'), '--target', str(self.root), *args], capture_output=True, text=True, env=self.env)
        self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
        return result

    def cfg(self, action):
        result = subprocess.run([sys.executable, '-B', str(self.root / 'scripts/workflow_config.py'), action, '--repo', str(self.root)], capture_output=True, text=True, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}

    def declaration(self):
        return dict(schemaVersion=1, enabledCapabilities=['release'], commands={}, documents={}, extensions={'release': {'strategy': 'commit-sha'}})

    def test_adopted_installer_updates_configuration_and_preserves_policy(self):
        self.install('--packs', 'release')
        project = self.root / 'workflow.config.json'
        manifest = self.root / '.dev-workflow/manifest.json'
        project.write_text(json.dumps(self.declaration()))
        self.cfg('adopt')
        policy = json.loads(manifest.read_text())['gitPolicy']
        before = self.snapshot()
        self.install('--enable-capabilities', 'containers:compose', '--dry-run')
        self.assertEqual(before, self.snapshot())
        self.install('--enable-capabilities', 'containers:compose')
        current = json.loads(manifest.read_text())
        self.assertEqual(current['enabledCapabilities'], ['release', 'containers:compose'])
        self.assertEqual(current['enabledCapabilities'], json.loads(project.read_text())['enabledCapabilities'])
        self.assertTrue(current['projectConfiguration']['adopted'])
        self.assertEqual(current['gitPolicy'], policy)
        self.assertFalse((self.root / '.agents').exists())
        project.write_text('{bad')
        before = self.snapshot()
        self.install(ok=False)
        self.assertEqual(before, self.snapshot())
        result = subprocess.run(['bash', str(ROOT / 'scripts/audit.sh'), '--target', str(self.root)], capture_output=True, text=True, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('config.invalid', result.stdout)

    def test_clone_with_valid_unadopted_configuration_can_bootstrap(self):
        project = self.root / 'workflow.config.json'
        project.write_text(json.dumps(self.declaration()))
        before = project.read_bytes()
        self.install()
        self.assertEqual(before, project.read_bytes())
        manifest = json.loads((self.root / '.dev-workflow/manifest.json').read_text())
        self.assertEqual(manifest['enabledCapabilities'], [])
        self.assertIsNone(manifest.get('projectConfiguration'))
        self.cfg('adopt')
        self.assertEqual(json.loads((self.root / '.dev-workflow/manifest.json').read_text())['enabledCapabilities'], ['release'])

    def test_all_packs_never_installs_skills_or_active_project_configuration(self):
        self.install('--all-packs')
        self.assertFalse((self.root / '.agents').exists())
        self.assertFalse((self.root / 'workflow.config.json').exists())
        self.assertTrue((self.root / 'scripts/release_prepare.py').exists())

    def test_installed_read_only_commands_never_create_bytecode(self):
        def git(*args):
            subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True)
        git('init', '-q')
        git('config', 'user.name', 'Test')
        git('config', 'user.email', 'test@example.test')
        self.install('--packs', 'release')
        (self.root / 'workflow.config.json').write_text(json.dumps(self.declaration()))
        self.cfg('adopt')
        git('add', 'workflow.config.json')
        git('commit', '-qm', 'project configuration')
        before = self.snapshot()
        env = dict(self.env)
        env.pop('PYTHONDONTWRITEBYTECODE', None)
        for name in ('workflow_check.py', 'release_prepare.py'):
            result = subprocess.run([sys.executable, str(self.root / 'scripts' / name), '--repo', str(self.root), '--json'],
                                    capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, self.snapshot())
        self.assertFalse((self.root / 'scripts/__pycache__').exists())

    def test_audit_detects_missing_new_core_tool(self):
        self.install()
        (self.root / 'scripts/workflow_check.py').unlink()
        result = subprocess.run(['bash', str(ROOT / 'scripts/audit.sh'), '--target', str(self.root)],
                                capture_output=True, text=True, env=self.env)
        self.assertEqual(result.returncode, 1)
        self.assertIn('scripts/workflow_check.py', result.stdout)

    def test_published_v070_can_add_new_tools_without_overwriting_rules(self):
        archive = subprocess.run(['git', '-C', str(ROOT), 'archive', '--format=tar', 'v0.7.0',
                                  'core', 'packs', 'scripts', 'VERSION'], capture_output=True)
        self.assertEqual(archive.returncode, 0, 'Compatibility fixture requires local v0.7.0 tag; CI checks out full history.')
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve()
            with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode='r:') as content:
                for member in content.getmembers():
                    destination = source / member.name
                    self.assertTrue(destination.resolve().is_relative_to(source))
                    if member.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                    else:
                        self.assertTrue(member.isfile(), 'Unexpected link in historical fixture')
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(content.extractfile(member).read())
                        destination.chmod(member.mode)
            old = subprocess.run(['bash', str(source / 'scripts/install.sh'), '--target', str(self.root)],
                                 capture_output=True, text=True, env=self.env)
            self.assertEqual(old.returncode, 0, old.stdout + old.stderr)
        before = (self.root / 'AGENTS.md').read_bytes()
        previous = json.loads((self.root / '.dev-workflow/manifest.json').read_text())
        self.assertEqual(previous['workflowVersion'], '0.7.0')
        self.install('--packs', 'release')
        current = json.loads((self.root / '.dev-workflow/manifest.json').read_text())
        self.assertEqual(current['workflowVersion'], (ROOT / 'VERSION').read_text().strip())
        self.assertNotEqual(current['workflowVersion'], previous['workflowVersion'])
        self.assertEqual((self.root / 'AGENTS.md').read_bytes(), before)
        self.assertEqual(current['gitPolicy'], previous['gitPolicy'])
        self.assertTrue((self.root / 'scripts/workflow_check.py').is_file())
        self.assertTrue((self.root / 'scripts/release_prepare.py').is_file())


if __name__ == '__main__':
    unittest.main()
