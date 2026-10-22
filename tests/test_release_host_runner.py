from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_host_runner_under_test', SOURCE / 'scripts/release_host_runner.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ReleaseHostRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.root = self.base / 'candidate'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('remote', 'add', 'origin', 'https://github.com/example/target.git')
        config = dict(schemaVersion=1, enabledCapabilities=['release'], commands={}, documents={},
                      extensions=dict(release=dict(strategy='semver-tag', tagPrefix='v', components=[])))
        (self.root / 'workflow.config.json').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        # These candidate modules must never be imported by the trusted runner.
        (self.root / 'release_host.py').write_text('raise RuntimeError("candidate imported")\n', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic fixture')
        self.policy = self.base / 'policy.json'
        self.config = dict(hostRepository='example/host', hostRepositoryId=1,
                           workflowRef='example/host/.github/workflows/release.yml@refs/heads/main',
                           environment='release', reviewerIds=[21], targetRepository='example/target',
                           targetRepositoryId=2, candidatePath=str(self.root.resolve()),
                           preventSelfReview=False, operations=list(runner.execution.OPERATIONS),
                           release=dict(name='Synthetic release', body='Exact notes\n', draft=False, prerelease=True))
        self.policy.write_text(json.dumps(self.config), encoding='utf-8')
        self.record = self.base / 'preview.json'
        self.environment = mock.patch.dict(os.environ, {'GITHUB_RUN_ID': '123', 'RELEASE_TOKEN': 'synthetic-token'})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              capture_output=True, encoding='utf-8').stdout.strip()

    def run_host(self, action, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return runner.main([action, '--policy', str(self.policy), '--repo', str(self.root),
                                '--record', str(self.record), *args])

    def fresh_checkout(self):
        old = self.base / 'original'
        self.root.rename(old)
        subprocess.run(['git', 'clone', '-q', str(old), str(self.root)], check=True, capture_output=True)
        self.git('remote', 'set-url', 'origin', 'https://github.com/example/target.git')

    def test_preview_exact_scope_no_mutations_and_candidate_code_not_imported(self):
        head = self.git('rev-parse', 'HEAD')
        with mock.patch.object(runner, 'oidc_token', side_effect=AssertionError('Preview requested identity')):
            self.assertEqual(self.run_host('prepare', '--version', '1.2.3'), 0)
        saved = json.loads(self.record.read_text(encoding='utf-8'))
        self.assertEqual(saved['plan']['preparation']['targetSha'], head)
        self.assertEqual(saved['operations'], list(runner.execution.OPERATIONS))
        self.assertEqual(saved['approvalComment'], 'dev-workflow approve ' + saved['bundleHash'])
        self.assertEqual(self.git('tag'), '')
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_forged_identity_cannot_execute_preview(self):
        self.assertEqual(self.run_host('prepare', '--version', '1.2.3'), 0)
        self.fresh_checkout()
        output = self.base / 'failure.json'
        with mock.patch.object(runner, 'oidc_token', return_value='forged-identity') as identity, \
                mock.patch.object(runner.GitHubClient, 'request', side_effect=AssertionError('No API expected')):
            self.assertEqual(self.run_host('execute', '--output', str(output)), 1)
            identity.assert_called_once()
        failure = json.loads(output.read_text(encoding='utf-8'))
        self.assertEqual(failure['phase'], 'authority-verification')
        self.assertEqual(failure['errorType'], 'AuthorizationUnavailable')
        self.assertNotIn('forged-identity', output.read_text(encoding='utf-8'))
        self.assertEqual(self.git('tag'), '')

    def test_preview_preserves_noncanonical_configuration_bytes(self):
        path = self.root / 'workflow.config.json'
        raw = json.dumps(json.loads(path.read_text(encoding='utf-8')), separators=(',', ':')).encode('utf-8')
        path.write_bytes(raw)
        self.git('add', 'workflow.config.json')
        self.git('commit', '-qm', 'compact configuration')
        self.assertEqual(self.run_host('prepare', '--version', '1.2.3'), 0)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_changed_release_notes_in_preview_denied_before_identity(self):
        self.assertEqual(self.run_host('prepare', '--version', '1.2.3'), 0)
        saved = json.loads(self.record.read_text(encoding='utf-8'))
        saved['plan']['release']['body'] = 'Unreviewed content'
        self.record.write_text(json.dumps(saved), encoding='utf-8')
        self.fresh_checkout()
        with mock.patch.object(runner, 'oidc_token', side_effect=AssertionError('Changed bundle requested identity')):
            self.assertEqual(self.run_host('execute'), 1)
        self.assertEqual(self.git('tag'), '')

    def test_candidate_path_cannot_override_host_policy(self):
        self.config['candidatePath'] = str(self.base / 'different')
        self.policy.write_text(json.dumps(self.config), encoding='utf-8')
        self.assertEqual(self.run_host('prepare', '--version', '1.2.3'), 1)
        self.assertFalse((self.root / '.dev-workflow').exists())

    def test_oidc_bootstrap_refuses_redirectable_or_arbitrary_endpoint(self):
        for endpoint in ('https://example.org/token', 'http://pipelines.actions.githubusercontent.com/token',
                         'https://user@pipelines.actions.githubusercontent.com/token'):
            with self.subTest(endpoint=endpoint), mock.patch.dict(os.environ, {
                    'ACTIONS_ID_TOKEN_REQUEST_URL': endpoint, 'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'secret'}):
                with self.assertRaises(runner.execution.AuthorizationUnavailable):
                    runner.oidc_token()


if __name__ == '__main__':
    unittest.main()
