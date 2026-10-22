from __future__ import annotations

from dataclasses import replace
import copy
from http.client import IncompleteRead
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

SCRIPT = Path(__file__).resolve().parents[1] / 'packs/release/scripts'
sys.path.insert(0, str(SCRIPT))
import release_execute as execution
import release_github as github

SHA = 'a' * 40
OTHER = 'b' * 40
SPEC = dict(endpoint=github.API, repository='example/approved', repositoryId=123,
            name='Version one', body='Approved release notes\n', draft=False, prerelease=False)


def request(operation='remote-tag-push'):
    return execution.Request(operation, '/approved/repository', SHA, 'main', SHA,
                             'c' * 64, 'v1.0.0', SHA, 'origin',
                             'https://github.com/example/approved.git', json.dumps(SPEC), 'd' * 64)


class FakeGitHub:
    def __init__(self):
        self.repo = dict(id=123, full_name='example/approved', permissions=dict(push=True))
        self.tag = None
        self.releases = []
        self.calls = []
        self.commit = SHA
        self.on_request = None
        self.post_status = 201
        self.created_payload = None
        self.rulesets = [dict(id=77, source_type='Repository', source='example/approved',
                              target='tag', enforcement='active', bypass_actors=[],
                              conditions=dict(ref_name=dict(include=['~ALL'], exclude=[])),
                              rules=[dict(type='update'), dict(type='deletion')])]

    def __call__(self, method, path, payload):
        self.calls.append((method, path, copy.deepcopy(payload)))
        if self.on_request:
            result = self.on_request(method, path, payload)
            if result is not None:
                return result
        base = '/repos/example/approved'
        if method == 'POST' and self.post_status != 201:
            return self.post_status, {}, dict(message='sensitive response details')
        if path == base:
            value = self.repo
        elif path == base + '/git/ref/tags/v1.0.0':
            if self.tag is None:
                return 404, {}, None
            value = dict(ref='refs/tags/v1.0.0', object=dict(type='commit', sha=self.tag))
        elif path == base + '/git/commits/' + SHA:
            value = dict(sha=self.commit)
        elif path == base + '/git/refs' and method == 'POST':
            self.tag = payload['sha']
            value = dict(ref=payload['ref'], object=dict(type='commit', sha=self.tag))
        elif '/rulesets?includes_parents=false&per_page=100&page=' in path:
            page = int(path.rsplit('=', 1)[1])
            value = self.rulesets[(page - 1) * 100:page * 100]
        elif '/rulesets/' in path:
            value = next(x for x in self.rulesets if x['id'] == int(path.rsplit('/', 1)[1]))
        elif '/releases?per_page=100&page=' in path:
            page = int(path.rsplit('=', 1)[1])
            value = self.releases[(page - 1) * 100:page * 100]
        elif path == base + '/releases' and method == 'POST':
            self.created_payload = copy.deepcopy(payload)
            value = {key: payload[key] for key in ('name', 'body', 'draft', 'prerelease', 'tag_name')}
            value['id'] = 456
            self.releases.append(value)
        elif path.startswith(base + '/releases/'):
            value = next(x for x in self.releases if x['id'] == int(path.rsplit('/', 1)[1]))
        else:
            raise AssertionError('Unexpected API request: ' + path)
        return (201 if method == 'POST' else 200), {}, copy.deepcopy(value)

    def existing_release(self, **changes):
        value = {key: SPEC[key] for key in ('name', 'body', 'draft', 'prerelease')}
        value.update(id=456, tag_name='v1.0.0')
        value.update(changes)
        self.releases.append(value)


class GitHubProviderTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeGitHub()
        self.client = github.GitHubClient('test-secret', transport=self.fake)
        self.guarded = []
        self.tag = github.GitHubTagProvider(self.client, 'example/approved', 123,
                                           before_mutation=self.guarded.append)
        self.release = github.GitHubReleaseProvider(self.client, 'example/approved', 123,
                                                   before_mutation=self.guarded.append)

    def posts(self):
        return [call for call in self.fake.calls if call[0] == 'POST']

    def test_real_ref_protocol_creates_absent_only_and_verifies(self):
        self.tag.push(request())
        self.assertEqual(self.posts(), [('POST', '/repos/example/approved/git/refs',
                                        dict(ref='refs/tags/v1.0.0', sha=SHA))])
        self.assertEqual(self.guarded, [request()])
        self.assertEqual(self.tag.inspect(request()), dict(objectSha=SHA, targetSha=SHA))
        self.tag.push(request())
        self.assertEqual(len(self.posts()), 1)

    def test_tag_rejects_wrong_remote_repo_id_permissions_and_commit(self):
        cases = [('id', 999), ('permissions', dict(push=False)), ('permissions', {}),
                 ('full_name', 'example/renamed')]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                self.fake.repo = dict(id=123, full_name='example/approved', permissions=dict(push=True))
                self.fake.repo[key] = value
                with self.assertRaises(execution.IdentityConflict):
                    self.tag.push(request())
        self.fake.repo = dict(id=123, full_name='example/approved', permissions=dict(push=True))
        self.fake.commit = OTHER
        with self.assertRaises(execution.IdentityConflict):
            self.tag.push(request())
        self.assertFalse(self.posts())

    def test_remote_alias_and_endpoint_mismatch_rejected_before_network(self):
        for remote in ('https://github.com/evil/project.git', 'https://user@github.com/example/approved.git',
                       'https://github.com:443/example/approved.git', 'ssh://evil/example/approved.git'):
            with self.assertRaises(execution.IdentityConflict):
                self.tag.inspect(replace(request(), remote_url=remote))
        bad = dict(SPEC, endpoint='https://evil.invalid')
        with self.assertRaises(execution.IdentityConflict):
            self.tag.inspect(replace(request(), release_json=json.dumps(bad)))
        self.assertEqual(self.fake.calls, [])

    def test_all_supported_canonical_remotes(self):
        for remote in ('git@github.com:example/approved.git', 'ssh://git@github.com/example/approved.git',
                       'https://github.com/example/approved'):
            self.assertIsNone(self.tag.inspect(replace(request(), remote_url=remote)))

    def test_invalid_tag_and_oid_do_not_reach_network(self):
        for tag in ('x/../v1', 'x//v1', 'x.lock', '.secret', 'x..y', 'v1?bad', 'v1\n'):
            with self.assertRaises(execution.IdentityConflict):
                self.tag.inspect(replace(request(), tag=tag))
        with self.assertRaises(execution.IdentityConflict):
            self.tag.inspect(replace(request(), tag_object_sha='A' * 40))
        self.assertFalse(self.fake.calls)

    def test_existing_tag_conflict_cannot_be_retargeted(self):
        self.fake.tag = OTHER
        with self.assertRaises(execution.IdentityConflict):
            self.tag.push(request())
        self.assertFalse(self.posts())

    def test_annotation_peeling_checks_raw_object_and_commit(self):
        self.fake.tag = OTHER
        original = self.fake.__call__
        def annotated(method, path, payload):
            if '/git/ref/tags/' in path:
                return 200, {}, dict(ref='refs/tags/v1.0.0', object=dict(type='tag', sha=OTHER))
            if '/git/tags/' in path:
                return 200, {}, dict(sha=OTHER, object=dict(type='commit', sha=SHA))
            return original(method, path, payload)
        self.client._transport = annotated
        approved = replace(request(), tag_object_sha=OTHER)
        self.assertEqual(self.tag.inspect(approved), dict(objectSha=OTHER, targetSha=SHA))
        with self.assertRaises(execution.IdentityConflict):
            self.tag.inspect(request())
        with self.assertRaises(execution.ProviderRejected):
            self.tag.push(approved)

    def test_annotation_cycle_is_bounded(self):
        def cycle(method, path, payload):
            if '/git/ref/' in path:
                return 200, {}, dict(ref='refs/tags/v1.0.0', object=dict(type='tag', sha=OTHER))
            if '/git/tags/' in path:
                return 200, {}, dict(sha=OTHER, object=dict(type='tag', sha=OTHER))
            return 200, {}, self.fake.repo
        self.client._transport = cycle
        with self.assertRaises(execution.IdentityConflict):
            self.tag.inspect(replace(request(), tag_object_sha=OTHER))

    def test_guard_runs_after_slow_reads_and_immediately_before_post(self):
        state = dict(valid=True)
        def reads(method, path, payload):
            if '/git/commits/' in path:
                state['valid'] = False
        self.fake.on_request = reads
        def guard(approved):
            if not state['valid']:
                raise execution.AuthorizationUnavailable('expired')
        provider = github.GitHubTagProvider(self.client, 'example/approved', 123, before_mutation=guard)
        with self.assertRaises(execution.AuthorizationUnavailable):
            provider.push(request())
        self.assertFalse(self.posts())

    def test_release_create_exact_payload_then_fresh_read_not_response_echo(self):
        self.fake.tag = SHA
        approved = request('remote-release-create')
        self.release.create(approved)
        expected = {key: SPEC[key] for key in ('name', 'body', 'draft', 'prerelease')}
        expected.update(tag_name='v1.0.0', target_commitish=SHA, make_latest='false', generate_release_notes=False)
        self.assertEqual(self.fake.created_payload, expected)
        self.assertEqual(self.guarded, [approved, approved])
        observation = self.release.inspect(approved)
        self.assertTrue(execution.verified_release(observation, approved))
        self.release.create(approved)
        self.assertEqual(len(self.posts()), 1)
        self.assertTrue(any(path.endswith('/releases/456') for _, path, _ in self.fake.calls))

    def test_release_requires_active_tag_rules_without_bypass_and_both_restrictions(self):
        self.fake.tag = SHA
        baseline = copy.deepcopy(self.fake.rulesets[0])
        cases = [dict(enforcement='disabled'), dict(enforcement='evaluate'),
                 dict(target='branch'), dict(source_type='Organization'),
                 dict(bypass_actors=[dict(actor_type='RepositoryRole', actor_id=5, bypass_mode='always')]),
                 dict(rules=[dict(type='update')]), dict(rules=[dict(type='deletion')]),
                 dict(conditions=dict(ref_name=dict(include=['refs/tags/other'], exclude=[]))),
                 dict(conditions=dict(ref_name=dict(include=['refs/tags/v*'], exclude=[]))),
                 dict(conditions=dict(ref_name=dict(include=['~ALL'], exclude=['refs/tags/other'])))]
        for changes in cases:
            with self.subTest(changes=changes):
                self.fake.rulesets = [dict(copy.deepcopy(baseline), **changes)]
                with self.assertRaises(execution.ProviderRejected):
                    self.release.create(request('remote-release-create'))
        self.fake.rulesets = [copy.deepcopy(baseline)]
        del self.fake.rulesets[0]['bypass_actors']
        with self.assertRaises(execution.ProviderRejected):
            self.release.create(request('remote-release-create'))
        self.fake.rulesets = []
        with self.assertRaises(execution.ProviderRejected):
            self.release.create(request('remote-release-create'))
        self.assertFalse(self.posts())

    def test_exact_tag_protection_and_later_page_ruleset_are_supported(self):
        self.fake.tag = SHA
        self.fake.rulesets[0]['conditions']['ref_name']['include'] = ['refs/tags/v1.0.0']
        self.release.require_tag_protection(request('remote-release-create'))
        self.fake.rulesets = [dict(id=i) for i in range(1000, 1100)] + self.fake.rulesets
        self.release.require_tag_protection(request('remote-release-create'))
        self.assertTrue(any('/rulesets?' in path and 'page=2' in path for _, path, _ in self.fake.calls))

    def test_tag_protection_listing_and_detail_must_be_complete_and_fresh(self):
        self.fake.tag = SHA
        self.fake.rulesets = [dict(id=i) for i in range(1, 101)]
        self.release.MAX_PAGES = 1
        with self.assertRaises(github.GitHubUnavailable):
            self.release.create(request('remote-release-create'))
        self.release.MAX_PAGES = 100
        self.fake.rulesets = [dict(id=77)]
        self.fake.on_request = lambda method, path, payload: ((200, {}, dict(id=78)) if '/rulesets/' in path else None)
        with self.assertRaises(github.GitHubUnavailable):
            self.release.create(request('remote-release-create'))
        self.assertFalse(self.posts())

    def test_tag_removed_inside_authorization_guard_does_not_trigger_implicit_creation(self):
        self.fake.tag = SHA
        def deleted(approved):
            self.fake.tag = None
        provider = github.GitHubReleaseProvider(self.client, 'example/approved', 123, before_mutation=deleted)
        with self.assertRaises(execution.IdentityConflict):
            provider.create(request('remote-release-create'))
        self.assertFalse(self.posts())
        self.assertEqual(self.fake.releases, [])

    def test_release_observation_rejects_each_wrong_payload_field(self):
        self.fake.tag = SHA
        for field, value in [('name', 'wrong'), ('body', 'wrong'), ('draft', True), ('prerelease', True), ('draft', 0)]:
            with self.subTest(field=field, value=value):
                self.fake.releases = []
                self.fake.existing_release(**{field: value})
                with self.assertRaises(execution.IdentityConflict):
                    self.release.inspect(request('remote-release-create'))
        self.assertFalse(self.posts())

    def test_draft_on_later_page_is_seen_and_blocks_duplicate_create(self):
        self.fake.tag = SHA
        self.fake.releases = [dict(id=i, tag_name='other-' + str(i)) for i in range(1, 101)]
        self.fake.existing_release(draft=True)
        with self.assertRaises(execution.IdentityConflict):
            self.release.create(request('remote-release-create'))
        self.assertTrue(any('page=2' in path for _, path, _ in self.fake.calls))
        self.assertFalse(self.posts())

    def test_duplicate_releases_and_pagination_bound_fail_closed(self):
        self.fake.tag = SHA
        self.fake.existing_release()
        self.fake.existing_release(id=457)
        with self.assertRaises(execution.IdentityConflict):
            self.release.inspect(request('remote-release-create'))
        self.fake.releases = [dict(id=i, tag_name='other') for i in range(1, 101)]
        self.release.MAX_PAGES = 1
        with self.assertRaises(github.GitHubUnavailable):
            self.release.create(request('remote-release-create'))
        self.assertFalse(self.posts())

    def test_release_ref_change_during_listing_blocks_create(self):
        self.fake.tag = SHA
        def change(method, path, payload):
            if '/releases?' in path:
                self.fake.tag = OTHER
        self.fake.on_request = change
        with self.assertRaises(execution.IdentityConflict):
            self.release.create(request('remote-release-create'))
        self.assertFalse(self.posts())

    def test_mutation_http_failures_are_never_retried(self):
        for status in (403, 404, 409, 422, 429, 408, 500, 503, 302):
            with self.subTest(status=status):
                self.fake.calls = []
                self.fake.post_status = status
                expected = execution.ProviderRejected if 400 <= status < 500 and status != 408 else github.GitHubUnavailable
                with self.assertRaises(expected):
                    self.tag.push(request())
                self.assertEqual(len(self.posts()), 1)
                self.assertIsNone(self.fake.tag)

    def test_lost_response_is_uncertain_even_if_remote_created(self):
        def lost(method, path, payload):
            if method == 'POST':
                self.fake.tag = SHA
                raise TimeoutError('secret token or URL')
        self.fake.on_request = lost
        with self.assertRaises(github.GitHubUnavailable) as caught:
            self.tag.push(request())
        self.assertNotIn('secret', str(caught.exception))
        self.assertEqual(self.tag.inspect(request()), dict(objectSha=SHA, targetSha=SHA))
        self.assertEqual(len(self.posts()), 1)

    def test_release_guard_rejects_expiry_after_pagination_before_any_mutation(self):
        self.fake.tag = SHA
        state = dict(valid=True)
        def reads(method, path, payload):
            if '/releases?' in path:
                state['valid'] = False
        self.fake.on_request = reads
        def guard(approved):
            if not state['valid']:
                raise execution.AuthorizationUnavailable('expired')
        provider = github.GitHubReleaseProvider(self.client, 'example/approved', 123, before_mutation=guard)
        with self.assertRaises(execution.AuthorizationUnavailable):
            provider.create(request('remote-release-create'))
        self.assertFalse(self.posts())

    def test_changed_fresh_release_identity_and_repeated_page_fail_closed(self):
        self.fake.tag = SHA
        self.fake.existing_release()
        def changed(method, path, payload):
            if path.endswith('/releases/456'):
                return 200, {}, dict(id=457, tag_name='v1.0.0')
        self.fake.on_request = changed
        with self.assertRaises(execution.IdentityConflict):
            self.release.inspect(request('remote-release-create'))
        self.fake.on_request = lambda method, path, payload: (
            (200, {'Link': '<ignored>; rel="next"'}, [dict(id=1, tag_name='other')])
            if '/releases?' in path else None)
        with self.assertRaises(github.GitHubUnavailable):
            self.release.inspect(request('remote-release-create'))
        self.assertFalse(self.posts())

    def test_network_rejects_oversized_and_incomplete_responses_without_secret_text(self):
        client = github.GitHubClient('test-secret')
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = {}
        response.read.side_effect = IncompleteRead(b'test-secret', 100)
        with mock.patch.object(client._opener, 'open', return_value=response):
            with self.assertRaises(github.GitHubUnavailable) as caught:
                client.request('GET', '/repos/example/approved')
            self.assertNotIn('test-secret', str(caught.exception))
        response.read.side_effect = None
        response.read.return_value = b'X' * (github.MAX_RESPONSE + 1)
        with mock.patch.object(client._opener, 'open', return_value=response):
            with self.assertRaises(github.GitHubUnavailable):
                client.request('GET', '/repos/example/approved')

    def test_client_rejects_bad_timeout_token_and_path(self):
        for timeout in (0, 61, float('inf'), float('nan'), True):
            with self.assertRaises(execution.ExecutionError):
                github.GitHubClient('token', timeout=timeout)
        for token in ('', 'token\n', 'token secret'):
            with self.assertRaises(execution.ExecutionError):
                github.GitHubClient(token)
        for path in ('https://evil.invalid', '//evil.invalid', '/repos/x\ny'):
            with self.assertRaises(execution.ExecutionError):
                self.client.request('GET', path)

    def test_network_uses_auth_timeout_no_redirect_and_safe_http_errors(self):
        client = github.GitHubClient('test-secret', timeout=9)
        error = HTTPError('https://api.github.com/repos/example/approved', 403, 'secret', {}, io.BytesIO(b'private error body'))
        with mock.patch.object(client._opener, 'open', side_effect=error) as opened:
            with self.assertRaises(execution.ProviderRejected) as caught:
                client.request('POST', '/repos/example/approved/releases', {})
            sent = opened.call_args.args[0]
            self.assertEqual(sent.get_header('Authorization'), 'Bearer test-secret')
            self.assertEqual(opened.call_args.kwargs, dict(timeout=9))
            self.assertNotIn('secret', str(caught.exception))
        self.assertIsNone(github.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.invalid'))
        with mock.patch.object(client._opener, 'open', side_effect=URLError('test-secret')):
            with self.assertRaises(github.GitHubUnavailable) as caught:
                client.request('GET', '/repos/example/approved')
            self.assertNotIn('test-secret', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
