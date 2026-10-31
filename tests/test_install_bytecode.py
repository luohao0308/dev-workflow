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


def instrument_private_uninstaller(distribution):
    """Failure-only Windows path evidence, confined to the disposable fixture."""
    script = distribution / 'scripts/uninstall.ps1'
    source = script.read_text(encoding='utf-8')
    marker = '        throw "Manifest path escapes the target directory: $RelativePath"'
    diagnostic = r'''        [Console]::Error.WriteLine(('uninstall-path-diagnostic: ' + (@{
            Root = $Root
            Resolved = $resolved
            Prefix = ($Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar)
            Location = (Get-Location).Path
            ProcessDirectory = [Environment]::CurrentDirectory
        } | ConvertTo-Json -Compress)))
'''
    if source.count(marker) != 1:
        raise AssertionError('Uninstaller diagnostic hook must match exactly once')
    script.write_text(source.replace(marker, diagnostic + marker), encoding='utf-8')


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
            if os.name == 'nt':
                instrument_private_uninstaller(distribution)
            excluded = ('scripts/__pycache__/sentinel.pyc',
                        'scripts/__pycache__/nested/source.py',
                        'scripts/standalone.pyc', 'scripts/standalone.pyo', '.DS_Store', 'docs/.DS_Store')
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
            user_metadata = target / '.DS_Store'
            user_metadata.write_bytes(b'project metadata')
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
                if relative == '.DS_Store':
                    self.assertEqual((target / relative).read_bytes(), b'project metadata')
                else:
                    self.assertFalse((target / relative).exists(), relative)
                self.assertNotIn(relative, [entry['path'] for entry in inventory])
            self.assertEqual(user_cache.read_bytes(), b'user owned')
            self.assertEqual(user_metadata.read_bytes(), b'project metadata')
            self.assertEqual((target / 'docs/__pycache__').read_text(encoding="utf-8"), 'ordinary file, not a cache directory')
            for source in ('core_source.py', 'packs_release_source.py'):
                self.assertTrue((target / 'scripts' / source).is_file())
                self.assertIn('scripts/' + source, [entry['path'] for entry in inventory])
            uninstall = (['pwsh', '-NoProfile', '-File', str(distribution / 'scripts/uninstall.ps1'), '-TargetPath', str(target)]
                         if os.name == 'nt' else ['bash', str(distribution / 'scripts/uninstall.sh'), '--target', str(target)])
            removed = subprocess.run(uninstall, capture_output=True, text=True, env=dict(os.environ, LC_ALL='C'))
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            self.assertEqual(user_metadata.read_bytes(), b'project metadata')

    @unittest.skipUnless(os.name == 'nt' and shutil.which('pwsh'), 'Windows PowerShell runtime unavailable')
    def test_windows_powershell_install_audit_uninstall_preserves_project_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            distribution = root / 'distribution'
            distribution.mkdir()
            for name in ('core', 'packs', 'scripts', 'extensions'):
                shutil.copytree(ROOT / name, distribution / name,
                                ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
            shutil.copy2(ROOT / 'VERSION', distribution / 'VERSION')
            if os.name == 'nt':
                instrument_private_uninstaller(distribution)
            for overlay, nested in (('core', 'core-metadata'), ('packs/release', 'release-metadata')):
                for relative in ('.DS_Store', 'docs/' + nested + '/.DS_Store'):
                    path = distribution / overlay / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'distribution-only metadata')
            ordinary = distribution / 'packs/release/docs/.DS_Store.keep'
            ordinary.write_bytes(b'ordinary distribution file')
            target = root / 'project'
            sentinels = {'.DS_Store': b'project root metadata',
                         'docs/release-metadata/.DS_Store': b'project nested metadata'}
            for relative, data in sentinels.items():
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            def run(script, *arguments):
                return subprocess.run([shutil.which('pwsh'), '-NoProfile', '-File',
                                       str(distribution / 'scripts' / script),
                                       '-TargetPath', str(target), *arguments],
                                      capture_output=True, text=True, timeout=90,
                                      env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))

            installed = run('install.ps1', '-Packs', 'release', '-NonInteractiveInstall')
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            inventory = json.loads((target / '.dev-workflow/manifest.json').read_text(encoding='utf-8'))['files']
            self.assertFalse(any(Path(entry['path']).name == '.DS_Store' for entry in inventory))
            self.assertFalse((target / 'docs/core-metadata/.DS_Store').exists())
            self.assertEqual((target / 'docs/.DS_Store.keep').read_bytes(), b'ordinary distribution file')
            for relative, data in sentinels.items():
                self.assertEqual((target / relative).read_bytes(), data)
            audited = run('audit.ps1')
            self.assertEqual(audited.returncode, 2, audited.stdout + audited.stderr)
            self.assertNotIn('[error]', audited.stdout + audited.stderr)
            removed = run('uninstall.ps1')
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            self.assertFalse((target / 'docs/.DS_Store.keep').exists())
            for relative, data in sentinels.items():
                self.assertEqual((target / relative).read_bytes(), data)
            self.assertFalse((target / 'docs/core-metadata/.DS_Store').exists())

    @unittest.skipUnless(os.name == 'nt' and shutil.which('pwsh'), 'Windows PowerShell runtime unavailable')
    def test_windows_short_directory_alias_keeps_strict_uninstall_boundary(self):
        import ctypes
        from ctypes import wintypes
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / 'project'
            target.mkdir()
            get_short = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
            get_short.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
            get_short.restype = wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            length = get_short(str(target), buffer, len(buffer))
            self.assertGreater(length, 0)
            self.assertLess(length, len(buffer))
            short = buffer.value
            if short.lower() == str(target).lower():
                self.skipTest('Filesystem has no distinct 8.3 alias for the test directory')
            source = (ROOT / 'scripts/uninstall.ps1').read_text(encoding='utf-8')
            helper = root / 'boundary.ps1'
            code = source.split('function Write-Utf8NoBom', 1)[0]
            code += r'''
$canonical = Resolve-FullPath $TargetPath
$expected = [Environment]::GetEnvironmentVariable('DEV_WORKFLOW_TEST_LONG_ROOT')
if (-not [StringComparer]::OrdinalIgnoreCase.Equals($canonical, $expected)) { throw 'Root alias was not expanded' }
$inside = Resolve-TargetFile -Root $canonical -RelativePath 'AGENTS.md'
if (-not (Test-IsWithin -Parent $canonical -Candidate $inside)) { throw 'Descendant rejected' }
if (Test-IsWithin -Parent $canonical -Candidate ($canonical + '-sibling/AGENTS.md')) { throw 'Sibling boundary accepted' }
foreach ($unsafe in @('../project-sibling/AGENTS.md', '../project/AGENTS.md', $canonical, ($canonical + '-sibling/AGENTS.md'))) {
    $rejected = $false
    try { Resolve-TargetFile -Root $canonical -RelativePath $unsafe | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unsafe manifest path accepted' }
}
'''
            helper.write_text(code, encoding='utf-8')
            result = subprocess.run([shutil.which('pwsh'), '-NoProfile', '-File', str(helper), '-TargetPath', short],
                                    capture_output=True, text=True, timeout=60,
                                    env=dict(os.environ, DEV_WORKFLOW_TEST_LONG_ROOT=str(target)))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_powershell_filters_relative_paths_before_inventory_and_copy(self):
        source = (ROOT / 'scripts/install.ps1').read_text(encoding="utf-8")
        self.assertIn("$RelativePath -cmatch '(^|/)__pycache__/|\\.py[co]$'", source)
        pattern = re.search(r"-cmatch '([^']+)'", source).group(1)
        self.assertIsNone(re.search(pattern, 'docs/__pycache__'))
        self.assertIsNotNone(re.search(pattern, 'scripts/__pycache__/module.pyc'))
        self.assertIn("-or $RelativePath -cmatch '(^|/)\\.DS_Store$'", source)
        self.assertEqual(source.count('if (Test-DistributionBytecode $relativePath) { continue }'), 2)
        for name, variable in (('audit', 'relativePath'), ('uninstall', 'relative')):
            source = (ROOT / 'scripts' / (name + '.ps1')).read_text(encoding="utf-8")
            self.assertIn("$RelativePath -cmatch '(^|/)__pycache__/|\\.py[co]$'", source)
            self.assertIn("-or $RelativePath -cmatch '(^|/)\\.DS_Store$'", source)
            self.assertIn('if (Test-DistributionBytecode $' + variable + ') { continue }', source)
            shell = (ROOT / 'scripts' / (name + '.sh')).read_text(encoding="utf-8")
            self.assertIn("-type d -name __pycache__ -prune -o -type f ! -name '*.pyc' ! -name '*.pyo' ! -name '.DS_Store' -print", shell)


if __name__ == '__main__':
    unittest.main()
