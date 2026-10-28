import sys
import json
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/release/scripts'))
import release_execute as execution
import release_gitlab as gitlab

SHA = 'a' * 40
OTHER = 'b' * 40


def request(operation='remote-tag-push'):
    return execution.Request(operation, '/repo', SHA, 'main', SHA, 'cfg', 'v1.0.0', SHA,
                             'origin', 'https://gitlab.com/group/project.git', None, 'plan')


class Fake:
    def __init__(self):
        self.calls = []
        self.tag = None
        self.commit = SHA
        self.release = None
        self.on_call = lambda method, path: None

    def __call__(self, method, path, payload):
        self.calls.append((method, path, payload))
        self.on_call(method, path)
        if path == '/projects/123':
            return 200, {}, dict(id=123, path_with_namespace='group/project')
        if path.endswith('/repository/commits/' + SHA):
            return 200, {}, dict(id=self.commit)
        if path.endswith('/repository/tags/v1.0.0') and method == 'GET':
            return (404, {}, None) if self.tag is None else (200, {}, self.tag)
        if path.endswith('/repository/tags') and method == 'POST':
            self.tag = dict(name='v1.0.0', target=SHA, message=None, commit=dict(id=SHA))
            return 201, {}, self.tag
        if path.endswith('/releases/v1.0.0'):
            return (404, {}, None) if self.release is None else (200, {}, self.release)
        raise AssertionError((method, path, payload))


class GitLabProviderTests(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.guards = []
        self.client = gitlab.GitLabClient('host-token', transport=self.fake)
        self.tag = gitlab.GitLabTagProvider(self.client, 'group/project', 123,
                                            before_mutation=self.guards.append)

    def test_tag_creation_is_exact_lightweight_and_idempotent(self):
        self.tag.push(request())
        posts = [x for x in self.fake.calls if x[0] == 'POST']
        self.assertEqual(posts, [('POST', '/projects/123/repository/tags',
                                  dict(tag_name='v1.0.0', ref=SHA))])
        self.assertEqual(self.guards, [request()])
        self.assertEqual(self.tag.inspect(request()), dict(objectSha=SHA, targetSha=SHA))
        self.tag.push(request())
        self.assertEqual(len([x for x in self.fake.calls if x[0] == 'POST']), 1)

    def test_wrong_remote_and_annotated_or_moved_tag_rejected(self):
        for remote in ('https://evil.test/group/project', 'https://user@gitlab.com/group/project',
                       'https://gitlab.com:443/group/project', 'https://gitlab.com/group/other'):
            with self.assertRaises(execution.IdentityConflict):
                self.tag.inspect(replace(request(), remote_url=remote))
        self.assertFalse(self.fake.calls)
        for value in (dict(name='v1.0.0', target=OTHER, message=None, commit=dict(id=OTHER)),
                      dict(name='v1.0.0', target=SHA, message='annotated', commit=dict(id=SHA)),
                      dict(name='v1.0.0', target=SHA, commit=dict(id=SHA))):
            self.fake.tag = value
            with self.assertRaises(execution.IdentityConflict):
                self.tag.push(request())
        self.assertFalse(any(x[0] == 'POST' for x in self.fake.calls))

    def test_absent_or_wrong_commit_rejects_before_mutation(self):
        self.fake.commit = OTHER
        with self.assertRaises(execution.IdentityConflict):
            self.tag.push(request())
        self.assertFalse(self.guards)

    def test_mutation_guard_runs_last(self):
        self.fake.on_call = lambda method, path: None
        def deny(_):
            raise execution.AuthorizationUnavailable('expired')
        guarded = gitlab.GitLabTagProvider(self.client, 'group/project', 123, before_mutation=deny)
        with self.assertRaises(execution.AuthorizationUnavailable):
            guarded.push(request())
        self.assertFalse(any(x[0] == 'POST' for x in self.fake.calls))

    def test_timeout_after_post_is_unknown_and_never_retried(self):
        def timeout(method, path, payload):
            if method == 'POST':
                raise TimeoutError('lost reply')
            return self.fake(method, path, payload)
        self.client._transport = timeout
        with self.assertRaises(gitlab.GitLabUnavailable):
            self.tag.push(request())
        self.assertEqual(len(self.guards), 1)

    def test_release_creation_fails_closed_without_network_or_guard(self):
        release = gitlab.GitLabReleaseProvider(self.client, 'group/project', 123,
                                                before_mutation=self.guards.append)
        with self.assertRaises(execution.ProviderRejected):
            release.create(request('remote-release-create'))
        self.assertFalse(self.fake.calls)
        self.assertFalse(self.guards)

    def test_release_readback_checks_approved_content_and_commit(self):
        release = gitlab.GitLabReleaseProvider(self.client, 'group/project', 123,
                                                before_mutation=self.guards.append)
        self.fake.tag = dict(name='v1.0.0', target=SHA, message=None, commit=dict(id=SHA))
        spec = dict(endpoint=gitlab.API, project='group/project', projectId=123,
                    name='Release v1', description='Notes')
        approved = replace(request('remote-release-create'), release_json=json.dumps(spec))
        self.assertIsNone(release.inspect(approved))
        self.fake.release = dict(tag_name='v1.0.0', name='Release v1', description='Notes', commit=dict(id=SHA))
        self.assertEqual(release.inspect(approved)['description'], 'Notes')
        self.fake.release['description'] = 'Changed'
        with self.assertRaises(execution.IdentityConflict):
            release.inspect(approved)

    def test_transport_rejects_redirect_status_and_untrusted_path(self):
        self.client._transport = lambda *args: (302, {}, None)
        with self.assertRaises(gitlab.GitLabUnavailable):
            self.client.request('GET', '/projects/123')
        with self.assertRaisesRegex(execution.ExecutionError, 'Invalid GitLab API request'):
            self.client.request('GET', '/projects/123/../../evil')


if __name__ == '__main__':
    unittest.main()
