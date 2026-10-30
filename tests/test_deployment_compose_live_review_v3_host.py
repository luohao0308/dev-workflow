"""No network: live adapter transport boundaries are replaced privately."""
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'packs/deployment/scripts'),str(ROOT/'packs/release/scripts')]
import deployment_compose_live_review_v3_host as live


class ReadRetryTests(unittest.TestCase):
    def test_get_transport_failure_then_success_rechecks_guard_and_does_not_cache(self):
        transport=Mock(side_effect=[OSError(), (200, {}, {'fresh': 1}), (200, {}, {'fresh': 2})])
        client=live._ReadRetryGitHubClient('test-token', transport=transport)
        guard=Mock()
        with patch.object(live.time, 'sleep') as sleep:
            self.assertEqual(client.request('GET', '/repos/sample/target', before_send=guard)[0], {'fresh': 1})
            self.assertEqual(client.request('GET', '/repos/sample/target', before_send=guard)[0], {'fresh': 2})
        self.assertEqual(transport.call_count, 3)
        self.assertEqual(guard.call_count, 3)
        sleep.assert_called_once_with(1)

    def test_get_failure_is_bounded_without_nested_adapter_retries(self):
        transport=Mock(side_effect=OSError())
        client=live._ReadRetryGitHubClient('test-token', transport=transport)
        host=object.__new__(live.GitHubLiveReviewV3);host.client=client
        guard=Mock()
        with patch.object(live.time, 'sleep') as sleep:
            with self.assertRaises(live.GitHubUnavailable):
                client.request('GET', '/repos/sample/target', before_send=guard)
        self.assertEqual(transport.call_count, 3);self.assertEqual(guard.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])
        transport.reset_mock()
        with patch.object(live.time, 'sleep'):
            with self.assertRaises(live.GitHubUnavailable): host._get('/approvals')
        self.assertEqual(transport.call_count, 3)

    def test_unknown_post_is_never_retried(self):
        transport=Mock(side_effect=OSError())
        client=live._ReadRetryGitHubClient('test-token', transport=transport)
        guard=Mock()
        with patch.object(live.time, 'sleep') as sleep:
            with self.assertRaises(live.GitHubUnavailable):
                client.request('POST', '/repos/sample/target/git/refs', {'ref': 'test'}, before_send=guard)
        transport.assert_called_once();guard.assert_called_once();sleep.assert_not_called()

    def test_guard_denial_propagates_before_transport(self):
        transport=Mock();client=live._ReadRetryGitHubClient('test-token', transport=transport)
        guard=Mock(side_effect=ValueError('denied'))
        with patch.object(live.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'denied'):
                client.request('GET', '/repos/sample/target', before_send=guard)
        guard.assert_called_once();transport.assert_not_called();sleep.assert_not_called()

    def test_unavailable_guard_is_not_retried_as_a_transport_error(self):
        transport=Mock();client=live._ReadRetryGitHubClient('test-token', transport=transport)
        guard=Mock(side_effect=live.GitHubUnavailable('authority unavailable'))
        with patch.object(live.time, 'sleep') as sleep:
            with self.assertRaises(live.GitHubUnavailable):
                client.request('GET', '/repos/sample/target', before_send=guard)
        guard.assert_called_once();transport.assert_not_called();sleep.assert_not_called()


@unittest.skipUnless(os.name == 'posix', 'private POSIX host credentials and file permissions')
class LiveReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.key = self.root / 'key.pem'
        self.key.write_text('private test fixture')
        self.key.chmod(0o600)
        with patch.object(live.GitHubLiveReviewV3, '_client', return_value=Mock()):
            self.host = live.GitHubLiveReviewV3(self.root, source_sha='a'*40,
                                               recipient_private_key=self.key)

    def test_reject_permissions_symlink_repository(self):
        self.key.chmod(0o644)
        with self.assertRaises(live.LiveReviewBlocked):
            live._private(self.key, 0o600)
        link = self.root / 'link'
        link.symlink_to(self.key)
        with self.assertRaises(live.LiveReviewBlocked):
            live._private(link, 0o600)
        with self.assertRaises(live.LiveReviewBlocked):
            live._private(live.REPO_ROOT, 0o700, True)

    def test_adapter_and_approval_share_read_retry_client(self):
        with patch.object(self.host, '_command', return_value=Mock(returncode=0, stdout=b'test-token')):
            client = self.host._client()
        self.assertIsInstance(client, live._ReadRetryGitHubClient)
        self.host.client = client
        transport = Mock(side_effect=[OSError(), (200, {}, {'ok': True})])
        client._transport = transport
        with patch.object(live.time, 'sleep'):
            self.assertEqual(self.host._get('/approvals'), {'ok': True})
        self.assertEqual(transport.call_count, 2)
        with patch.object(live, 'GitHubFullBodyApprovalV3') as approval:
            self.host._approval('a.b.c', 'request', 'policy')
        self.assertIs(approval.call_args.args[0], client)

    def test_approval_uses_default_verifier(self):
        with patch.object(live, 'GitHubFullBodyApprovalV3') as approval:
            self.host._approval('a.b.c', 'request', 'policy')
            approval.assert_called_once_with(self.host.client, 'a.b.c', ['request'], 'policy')

    def archive(self, name, raw=b'public'):
        target = io.BytesIO()
        with zipfile.ZipFile(target, 'w') as archive:
            archive.writestr(name, raw)
        return target.getvalue()

    def test_artifact_bounded_no_extraction(self):
        self.host._get = Mock(return_value=dict(total_count=1, artifacts=[
            dict(id=4, name='public', expired=False, size_in_bytes=100)]))
        self.host._command = Mock(return_value=Mock(returncode=0, stdout=self.archive('bundle.json')))
        self.assertEqual(self.host._artifact(dict(id=2), 'public', 'bundle.json', 65536,
                                           self.root / 'public'), b'public')
        self.host._command.return_value.stdout = self.archive('../bundle.json')
        with self.assertRaises(live.LiveReviewBlocked):
            self.host._artifact(dict(id=2), 'public', 'bundle.json', 65536, self.root / 'other')
        self.assertFalse((self.root / 'bundle.json').exists())

    def test_configuration_fail_closed(self):
        env = dict(name='compose-review', can_admins_bypass=False,
                   protection_rules=[dict(type='required_reviewers', prevent_self_review=True,
                       reviewers=[dict(type='User', reviewer=dict(id=84822776))])])
        def get(suffix):
            if suffix == '': return dict(id=live.REPOSITORY_ID, full_name=live.REPOSITORY)
            if suffix.startswith('/actions/variables/'):
                return dict(value=live.CONFIG[suffix.rsplit('/', 1)[1]])
            return env
        self.host._get = Mock(side_effect=get)
        self.host._environment()
        env['can_admins_bypass'] = True
        with self.assertRaises(live.LiveReviewBlocked): self.host._environment()
        env['can_admins_bypass'] = False
        env['protection_rules'][0]['reviewers'][0]['reviewer']['id'] = 1
        with self.assertRaises(live.LiveReviewBlocked): self.host._environment()

    def prepared(self):
        from tests.test_deployment_compose_full_body_review_contract import FullBodyReviewTests
        from dataclasses import asdict
        from deployment_compose_full_body_review_contract import prepare, canonical
        fixture = FullBodyReviewTests()
        fixture.setUp()
        env = dict(fixture.env, **live.CONFIG)
        run = dict(id=int(env['GITHUB_RUN_ID']), head_sha=env['GITHUB_SHA'], path=live.WORKFLOW,
                   run_attempt=1, event='workflow_dispatch', actor=dict(login='github-actions[bot]'),
                   created_at=live.datetime.now(live.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                   html_url='https://github.com/' + live.REPOSITORY + '/actions/runs/123',
                   status='in_progress')
        self.host.source_sha = run['head_sha']
        raw = canonical(prepare(canonical(dict(request=asdict(fixture.request),
                                review=fixture.bundle.public_review())), env)).encode('ascii')
        return fixture, run, raw

    def test_exact_artifact_callback_once_consumption_and_cipher_only(self):
        fixture, run, raw = self.prepared()
        self.host._environment = Mock()
        self.host._get = Mock(side_effect=lambda path: dict(workflow_runs=[run])
            if '/runs?' in path else [] if path.endswith('/approvals')
            else dict(object=dict(sha=self.host.source_sha)) if '/git/ref/' in path else run)
        def artifact(actual_run, name, filename, limit, directory):
            data = raw if filename == 'bundle.json' else b'encrypted-evidence'
            directory.mkdir(mode=0o700)
            (directory / filename).write_bytes(data)
            return data
        self.host._artifact = Mock(side_effect=artifact)
        self.host._command = Mock(side_effect=[Mock(returncode=0), Mock(returncode=0, stdout=b'a.b.c')])
        approval = Mock()
        approval.consume.return_value = 'receipt'
        self.host._approval = Mock(return_value=approval)
        callback = Mock(return_value=False)  # Notification cannot grant or deny consent.
        result = self.host.consume_prepared(fixture.bundle, fixture.request, callback)
        self.assertEqual(result[1], 'receipt')
        callback.assert_called_once()
        self.assertTrue(callback.call_args.args[0]['comment'].startswith('dev-workflow approve '))
        approval.consume.assert_called_once_with(approval.validate.return_value, fixture.request)
        for path in self.root.rglob('*'):
            if path.is_file(): self.assertNotIn(b'a.b.c', path.read_bytes())
        with self.assertRaises(FileExistsError):
            self.host.consume_prepared(fixture.bundle, fixture.request, callback)
        self.assertEqual(self.host._command.call_count, 2)

    def test_unknown_dispatch_never_retried(self):
        fixture, _, _ = self.prepared()
        self.host._environment = Mock()
        self.host._get = Mock(return_value=dict(object=dict(sha=self.host.source_sha)))
        self.host._command = Mock(return_value=Mock(returncode=1))
        callback = Mock()
        with self.assertRaises(live.LiveReviewBlocked):
            self.host.consume_prepared(fixture.bundle, fixture.request, callback)
        with self.assertRaises(FileExistsError):
            self.host.consume_prepared(fixture.bundle, fixture.request, callback)
        self.host._command.assert_called_once()
        callback.assert_not_called()


if __name__ == '__main__': unittest.main()
