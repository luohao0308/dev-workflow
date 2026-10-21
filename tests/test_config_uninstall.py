"""Project-owned settings and release records survive package removal."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ConfigurationUninstallTests(unittest.TestCase):
    def run_command(self, *args):
        proc = subprocess.run(args, text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_partial_then_full_preserves_configuration_and_records(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self.run_command('git', '-C', str(repo), 'init', '-q')
            self.run_command('bash', str(ROOT / 'scripts/install.sh'), '--target', str(repo), '--packs', 'release,delivery', '--non-interactive')
            project = repo / 'workflow.config.json'
            project.write_text(json.dumps(dict(schemaVersion=1, enabledCapabilities=['release'], commands={}, documents={}, extensions={'release': {'strategy': 'commit-sha'}})))
            self.run_command(sys.executable, str(ROOT / 'core/scripts/workflow_config.py'), 'adopt', '--repo', str(repo))
            manifest = repo / '.dev-workflow/manifest.json'
            marker = json.loads(manifest.read_text())['projectConfiguration']
            record = repo / '.dev-workflow/releases/local.json'
            record.parent.mkdir()
            record.write_text('{"keep": true}')
            original = project.read_bytes(), record.read_bytes()
            self.run_command('bash', str(ROOT / 'scripts/uninstall.sh'), '--target', str(repo), '--packs', 'release')
            remaining = json.loads(manifest.read_text())
            self.assertEqual(remaining['projectConfiguration'], marker)
            self.assertEqual(remaining['enabledCapabilities'], ['release'])
            self.assertNotIn('release', remaining['installedPacks'])
            self.assertEqual(original, (project.read_bytes(), record.read_bytes()))
            self.run_command('bash', str(ROOT / 'scripts/uninstall.sh'), '--target', str(repo))
            self.assertFalse(manifest.exists())
            self.assertEqual(original, (project.read_bytes(), record.read_bytes()))
            self.run_command('bash', str(ROOT / 'scripts/install.sh'), '--target', str(repo), '--non-interactive')
            self.assertEqual(original, (project.read_bytes(), record.read_bytes()))
            self.assertIsNone(json.loads(manifest.read_text()).get('projectConfiguration'))


if __name__ == '__main__':
    unittest.main()
