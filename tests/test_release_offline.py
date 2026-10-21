from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'packs/release/scripts/release_prepare.py'
SPEC = importlib.util.spec_from_file_location('release_offline_prepare', SCRIPT)
preparation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preparation)
EXEC_SPEC = importlib.util.spec_from_file_location('release_offline_execute', SCRIPT.with_name('release_execute.py'))
execution = importlib.util.module_from_spec(EXEC_SPEC)
sys.modules[EXEC_SPEC.name] = execution
EXEC_SPEC.loader.exec_module(execution)


class ReleaseOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'repo'
        self.root.mkdir()
        self.marker = Path(self.temp.name) / 'callback'
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.root / '.git/info/exclude').write_text('.dev-workflow/\n')
        (self.root / '.dev-workflow').mkdir()
        (self.root / '.dev-workflow/manifest.json').write_text(json.dumps(
            {'managedBy': 'dev-workflow', 'schemaVersion': 5, 'enabledCapabilities': []}))
        (self.root / 'workflow.config.json').write_text(json.dumps({
            'schemaVersion': 1, 'enabledCapabilities': ['release'], 'commands': {}, 'documents': {},
            'extensions': {'release': {'strategy': 'none', 'components': []}}}))
        result = subprocess.run([sys.executable, '-B', str(SCRIPT.parents[3] / 'core/scripts/workflow_config.py'),
                                 'adopt', '--repo', str(self.root)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.git('add', '.')
        self.git('commit', '-qm', 'initial')
        self.plan = self.root / '.dev-workflow/plan.json'
        self.plan.write_text(json.dumps(preparation.prepare(self.root, 'HEAD', None, [], [])))

    def git(self, *args, **kwargs):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              capture_output=True, text=True, **kwargs).stdout.strip()

    def assert_refused(self, message):
        for call in (lambda: preparation.prepare(self.root, 'HEAD', None, [], []),
                     lambda: preparation.check_plan(self.root, self.plan, 'HEAD')):
            with self.assertRaisesRegex(preparation.PreparationError, message):
                call()
        self.assertFalse(self.marker.exists())

    def test_partial_clone_keys_are_rejected_before_object_or_worktree_inspection(self):
        for key in ('remote.origin.promisor', 'remote.origin.partialclonefilter', 'extensions.partialclone',
                    'remote.line\nbreak.promisor', 'remote.line\nbreak.partialclonefilter'):
            with self.subTest(key=key):
                config_path = self.root / '.git/config'
                original = config_path.read_bytes()
                if '\n' in key:
                    field = key.rsplit('.', 1)[1]
                    with config_path.open('a') as stream:
                        stream.write('[remote \"line\\nbreak\"]\n\t' + field + ' = false\n')
                else:
                    self.git('config', key, 'false')
                actual_git = preparation.git
                seen = []
                def inspect(root, *arguments, **kwargs):
                    seen.append(arguments)
                    return actual_git(root, *arguments, **kwargs)
                with mock.patch.object(preparation, 'git', side_effect=inspect):
                    self.assert_refused('Partial-clone or promisor')
                self.assertTrue(seen)
                self.assertTrue(all(arguments[0] == 'config' for arguments in seen), seen)
                config_path.write_bytes(original)

    def test_gitlinks_are_rejected(self):
        self.git('update-index', '--add', '--cacheinfo', '160000,' + self.git('rev-parse', 'HEAD') + ',nested')
        self.assert_refused('Submodule')

    def test_execution_plan_output_requires_exact_ignored_path_and_untracked_metadata(self):
        output = self.root / '.dev-workflow/releases/private.json'
        before = self.plan.read_bytes()
        self.git('remote', 'add', 'origin', 'https://github.com/example/approved.git')
        spec = self.root / '.dev-workflow/spec.json'
        spec.write_text(json.dumps({'endpoint': 'https://api.github.com', 'repository': 'example/approved',
                                    'repositoryId': 42, 'name': 'Private release', 'body': 'PRIVATE_TEST_NOTES',
                                    'draft': True, 'prerelease': False}))
        spec_before = spec.read_bytes()
        cases = ('.dev-workflow/manifest.json\n.dev-workflow/plan.json\n.dev-workflow/spec.json\n',
                 '.dev-workflow/*\n!.dev-workflow/releases/\n.dev-workflow/releases/*\n!.dev-workflow/releases/private.json\n')
        for ignored in cases:
            with self.subTest(ignored=ignored):
                (self.root / '.git/info/exclude').write_text(ignored)
                self.assertEqual(execution.main(['plan', '--repo', str(self.root),
                                                 '--preparation', str(self.plan), '--remote', 'origin',
                                                 '--release-spec', str(spec), '--output', str(output)]), 1)
                self.assertFalse(output.parent.exists())
                self.assertEqual(self.plan.read_bytes(), before)
                self.assertEqual(spec.read_bytes(), spec_before)
        (self.root / '.git/info/exclude').write_text('.dev-workflow/\n')
        self.assertEqual(execution.main(['plan', '--repo', str(self.root),
                                         '--preparation', str(self.plan), '--remote', 'origin',
                                                 '--release-spec', str(spec), '--output', str(output)]), 0)
        self.assertEqual(json.loads(output.read_text())['release']['body'], 'PRIVATE_TEST_NOTES')
        output.unlink()
        self.git('add', '-f', '.dev-workflow/manifest.json')
        with self.assertRaises(execution.ExecutionError):
            execution.assert_private_output(self.root, '.dev-workflow/releases/private.json')
        self.assertFalse(output.exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX executable callback fixture')
    def test_fsmonitor_is_disabled_for_preparation_and_execution_inspection(self):
        callback = self.callback('monitor')
        self.git('config', 'core.fsmonitor', str(callback))
        self.git('status', '--porcelain')
        self.assertTrue(self.marker.exists(), 'positive control must execute fsmonitor')
        self.marker.unlink()
        preparation.prepare(self.root, 'HEAD', None, [], [])
        preparation.check_plan(self.root, self.plan, 'HEAD')
        execution.run_git(self.root, 'ls-files', '--stage')
        self.assertFalse(self.marker.exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX executable callback fixture')
    def test_active_clean_and_process_filters_are_rejected_without_execution(self):
        for mode in ('clean', 'process'):
            with self.subTest(mode=mode):
                callback = self.callback('filter-' + mode)
                (self.root / '.gitattributes').write_text('workflow.config.json filter=sentinel\n')
                # Commit the attribute without configuring its callback yet.
                self.git('add', '.gitattributes')
                self.git('commit', '-qm', 'filter attribute', '--allow-empty')
                self.plan.write_text(json.dumps({'schemaVersion': 1, 'kind': 'release-preparation',
                                                'headSha': self.git('rev-parse', 'HEAD'),
                                                'targetSha': self.git('rev-parse', 'HEAD'),
                                                'configurationHash': preparation.fingerprint(preparation.configuration(self.root)),
                                                'components': [], 'version': None}))
                self.git('config', 'filter.sentinel.' + mode, str(callback))
                subprocess.run(['git', '-C', str(self.root), 'hash-object',
                                '--path=workflow.config.json', '--stdin'], input='control',
                               capture_output=True, text=True, timeout=10)
                self.assertTrue(self.marker.exists(), 'positive control must execute filter')
                self.marker.unlink()
                self.assert_refused('External Git content filters')
                self.git('config', '--unset', 'filter.sentinel.' + mode)

    @unittest.skipIf(os.name == 'nt', 'POSIX control-character filename fixture')
    def test_carriage_return_filename_cannot_bypass_filter_inspection(self):
        name = 'danger\r.txt'
        (self.root / name).write_text('original')
        (self.root / '.gitattributes').write_text('"danger\\r.txt" filter=sentinel\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'control-character filename')
        # Preserve an otherwise current plan to reach the worktree guard on check.
        self.plan.write_text(json.dumps({'schemaVersion': 1, 'kind': 'release-preparation',
                                        'headSha': self.git('rev-parse', 'HEAD'),
                                        'targetSha': self.git('rev-parse', 'HEAD'),
                                        'configurationHash': preparation.fingerprint(preparation.configuration(self.root)),
                                        'components': [], 'version': None}))
        self.git('config', 'filter.sentinel.clean', str(self.callback('cr-filter')))
        (self.root / name).write_text('modified')
        self.git('status', '--porcelain')
        self.assertTrue(self.marker.exists(), 'positive control must execute CR-path filter')
        self.marker.unlink()
        self.assertIn(name, execution.run_git(self.root, 'ls-files', '-z').split('\0'))
        self.assert_refused('External Git content filters')

    @unittest.skipIf(os.name == 'nt', 'POSIX executable transport fixture')
    def test_missing_attribute_blob_in_promisor_repository_never_fetches(self):
        (self.root / '.gitattributes').write_text('*.txt text\n')
        self.git('add', '.gitattributes')
        self.git('commit', '-qm', 'attributes')
        self.plan.write_text(json.dumps(preparation.prepare(self.root, 'HEAD', None, [], [])))
        blob = self.git('rev-parse', 'HEAD:.gitattributes')
        (self.root / '.gitattributes').unlink()
        (self.root / '.git/objects' / blob[:2] / blob[2:]).unlink()
        self.git('config', 'remote.origin.promisor', 'true')
        self.git('config', 'remote.origin.url', 'ext::' + str(self.callback('transport')))
        self.git('config', 'protocol.ext.allow', 'always')
        env = dict(os.environ)
        env.pop('GIT_NO_LAZY_FETCH', None)
        control = subprocess.run(['git', '-C', str(self.root), 'check-attr', 'filter', '--', 'workflow.config.json'],
                                 capture_output=True, text=True, timeout=10, env=env)
        self.assertTrue(self.marker.exists(), control.stderr)
        self.marker.unlink()
        self.assert_refused('Partial-clone or promisor')

    def callback(self, name):
        path = Path(self.temp.name) / name
        # The marker lives outside the worktree and cannot influence status.
        path.write_text('#!/bin/sh\nprintf callback > "' + str(self.marker) + '"\nexit 1\n')
        path.chmod(0o755)
        return path


if __name__ == '__main__':
    unittest.main()
