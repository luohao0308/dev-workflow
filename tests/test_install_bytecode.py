"""Distribution caches must never become installed workflow inventory."""
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BytecodeInstallTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt' and not shutil.which('pwsh'), 'PowerShell runtime unavailable')
    def test_distribution_caches_are_excluded_and_user_cache_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            distribution = root / '__pycache__' / 'distribution'
            distribution.mkdir(parents=True)
            for name in ('core', 'packs', 'scripts', 'extensions'):
                shutil.copytree(ROOT / name, distribution / name,
                                ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
            shutil.copy2(ROOT / 'VERSION', distribution / 'VERSION')
            excluded = ('scripts/__pycache__/sentinel.pyc',
                        'scripts/__pycache__/nested/source.py',
                        'scripts/standalone.pyc', 'scripts/standalone.pyo')
            for overlay in ('core', 'packs/release'):
                for relative in excluded:
                    path = distribution / overlay / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'not a distribution source')
                (distribution / overlay / 'scripts' / (overlay.replace('/', '_') + '_source.py')).write_text('# source\n')
            ordinary = distribution / 'packs/release/docs/__pycache__'
            ordinary.parent.mkdir(parents=True, exist_ok=True)
            ordinary.write_text('ordinary file, not a cache directory')
            target = root / 'project'
            user_cache = target / 'scripts/__pycache__/user.pyc'
            user_cache.parent.mkdir(parents=True)
            user_cache.write_bytes(b'user owned')
            if os.name == 'nt':
                install = ['pwsh', '-NoProfile', '-File', str(distribution / 'scripts/install.ps1'),
                           '-TargetPath', str(target), '-Packs', 'release', '-NonInteractiveInstall']
                audit_command = ['pwsh', '-NoProfile', '-File', str(distribution / 'scripts/audit.ps1'),
                                 '-TargetPath', str(target)]
            else:
                install = ['bash', str(distribution / 'scripts/install.sh'),
                           '--target', str(target), '--packs', 'release', '--non-interactive']
                audit_command = ['bash', str(distribution / 'scripts/audit.sh'), '--target', str(target)]
            result = subprocess.run(install,
                                    capture_output=True, text=True,
                                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', LC_ALL='C'))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            audit = subprocess.run(audit_command,
                                   capture_output=True, text=True, env=dict(os.environ, LC_ALL='C'))
            self.assertEqual(audit.returncode, 2, audit.stdout + audit.stderr)
            self.assertNotIn('[error]', audit.stdout)
            inventory = json.loads((target / '.dev-workflow/manifest.json').read_text(encoding="utf-8"))['files']
            for relative in excluded:
                self.assertFalse((target / relative).exists(), relative)
                self.assertNotIn(relative, [entry['path'] for entry in inventory])
            self.assertEqual(user_cache.read_bytes(), b'user owned')
            self.assertEqual((target / 'docs/__pycache__').read_text(encoding="utf-8"), 'ordinary file, not a cache directory')
            for source in ('core_source.py', 'packs_release_source.py'):
                self.assertTrue((target / 'scripts' / source).is_file())
                self.assertIn('scripts/' + source, [entry['path'] for entry in inventory])

    def test_powershell_filters_relative_paths_before_inventory_and_copy(self):
        source = (ROOT / 'scripts/install.ps1').read_text(encoding="utf-8")
        self.assertIn("$RelativePath -cmatch '(^|/)__pycache__/|\\.py[co]$'", source)
        pattern = re.search(r"-cmatch '([^']+)'", source).group(1)
        self.assertIsNone(re.search(pattern, 'docs/__pycache__'))
        self.assertIsNotNone(re.search(pattern, 'scripts/__pycache__/module.pyc'))
        self.assertEqual(source.count('if (Test-DistributionBytecode $relativePath) { continue }'), 2)
        for name, variable in (('audit', 'relativePath'), ('uninstall', 'relative')):
            source = (ROOT / 'scripts' / (name + '.ps1')).read_text(encoding="utf-8")
            self.assertIn("$RelativePath -cmatch '(^|/)__pycache__/|\\.py[co]$'", source)
            self.assertIn('if (Test-DistributionBytecode $' + variable + ') { continue }', source)
            shell = (ROOT / 'scripts' / (name + '.sh')).read_text(encoding="utf-8")
            self.assertIn("-type d -name __pycache__ -prune -o -type f ! -name '*.pyc' ! -name '*.pyo' -print", shell)


if __name__ == '__main__':
    unittest.main()
