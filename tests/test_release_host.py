from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'packs/release/scripts'
sys.path.insert(0, str(SCRIPTS))
import release_host as host
from release_execute import Request, AuthorizationUnavailable

SHA = 'a' * 40


def request(operation='remote-tag-push'):
    return Request(operation, '/tmp/dev-workflow-target', SHA, 'HEAD', SHA, 'b' * 64,
                   'v1.0.0', SHA, 'origin', 'https://github.com/sample/target.git', None, 'c' * 64)


def policy(**changes):
    values = dict(host_repository='sample/host', host_repository_id=1,
                  workflow_ref='sample/host/.github/workflows/release.yml@refs/heads/main',
                  workflow_sha=SHA, run_id=123, environment='release', reviewer_ids=(21,),
                  target_repository='sample/target', target_repository_id=2,
                  ledger_repository='sample/ledger', ledger_repository_id=3, ledger_sha=SHA,
                  expires_at=(datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    return host.HostPolicy(**dict(values, **changes))


def claims(p):
    now = int(time.time())
    return dict(iss=host.ISSUER, aud=host.AUDIENCE, exp=now + 300, iat=now - 1, nbf=now - 1,
                repository=p.host_repository, repository_id=str(p.host_repository_id),
                workflow_ref=p.workflow_ref, workflow_sha=p.workflow_sha, run_id=str(p.run_id),
                run_attempt='1', environment=p.environment, actor_id='20',
                sub='repo:' + p.host_repository + ':environment:' + p.environment)


class Client:
    def __init__(self, p, requests):
        self.policy, self.markers, self.lock = p, {}, threading.Lock()
        self.data = {
            '/repos/sample/host': {'id': 1, 'full_name': 'sample/host', 'owner': {'id': 10}},
            '/repos/sample/host/actions/oidc/customization/sub': {'use_default': True},
            '/repos/sample/target': {'id': 2, 'full_name': 'sample/target'},
            '/repos/sample/ledger': {'id': 3, 'full_name': 'sample/ledger'},
            '/repos/sample/host/actions/runs/123': dict(id=123, run_attempt=1, head_sha=SHA,
                status='in_progress', event='workflow_dispatch', repository={'id': 1}, actor={'id': 20}),
            '/repos/sample/host/environments/release': dict(id=50, name='release', can_admins_bypass=False,
                protection_rules=[dict(type='required_reviewers', prevent_self_review=p.prevent_self_review,
                    reviewers=[dict(type='User', reviewer={'id': 21})])]),
            '/repos/sample/host/actions/runs/123/approvals': [dict(state='approved', user={'id': 21},
                comment='dev-workflow approve ' + host.bundle_digest(requests, p.expires_at, p.bundle_context()),
                environments=[dict(id=50, name='release')])],
        }
        self.after_post = None
        self.posts = 0

    def request(self, method, path, payload=None, *, before_send=lambda: None):
        before_send()
        if method == 'GET' and '/git/ref/' in path:
            return copy.deepcopy(self.markers[path.split('/git/ref/')[1]]), {}
        if method == 'GET':
            return copy.deepcopy(self.data[path]), {}
        if method == 'POST':
            with self.lock:
                self.posts += 1
                ref = payload['ref'].removeprefix('refs/')
                if ref in self.markers:
                    raise RuntimeError('Already exists')
                value = dict(ref=payload['ref'], object={'sha': payload['sha']})
                self.markers[ref] = value
            if self.after_post:
                self.after_post()
            return copy.deepcopy(value), {}
        raise AssertionError(method)


class ReleaseHostTests(unittest.TestCase):
    def setUp(self):
        self.req = request()
        self.policy = policy()
        self.claims = claims(self.policy)
        self.client = Client(self.policy, [self.req])

    def make_host(self):
        return host.GitHubActionsApproval(self.client, 'opaque-signed-token', [self.req], self.policy,
                                         verifier=lambda token: copy.deepcopy(self.claims))

    def test_grant_consumption_and_dispatch_guard(self):
        approval = self.make_host()
        grant = approval.validate(self.req)
        with self.assertRaises(AuthorizationUnavailable):
            approval.guard(self.req)
        receipt = approval.consume(grant, self.req)
        self.assertEqual(receipt.request_hash, self.req.digest())
        self.assertEqual(receipt.use_number, 1)
        approval.guard(self.req)
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(grant, self.req)
        self.assertEqual(self.client.posts, 1)

    def test_release_host_defaults_remain_bound(self):
        approval = self.make_host()
        self.assertIs(approval.request_type, Request)
        self.assertEqual(approval.operations, host.OPERATIONS)
        self.assertEqual(approval.audience, 'dev-workflow-release-host')
        self.assertEqual(approval.ledger_namespace, 'workflow-grants')
        self.assertEqual(approval._approval_environment(), self.policy.environment)
        grant = approval.validate(self.req)
        self.assertIs(type(grant), host.Grant)
        self.assertEqual(grant.grant_id, 'github-actions:123:remote-tag-push')
        receipt = approval.consume(grant, self.req)
        self.assertIs(type(receipt), host.Receipt)
        self.assertTrue(next(iter(self.client.markers)).startswith('tags/workflow-grants/123/'))

    def test_before_consume_runs_after_last_authority_reads_at_before_send(self):
        approval = self.make_host()
        grant = approval.validate(self.req)
        events = []
        original = self.client.request
        def request(method, path, payload=None, **kwargs):
            if method == 'GET':
                events.append('authority')
            return original(method, path, payload, **kwargs)
        def guard():
            self.assertEqual(self.client.posts, 0)
            self.assertEqual(events[-1], 'authority')
            events.append('sdk')
        with mock.patch.object(self.client, 'request', side_effect=request):
            approval.consume(grant, self.req, before_consume=guard)
        self.assertEqual(events[-1], 'sdk')
        self.assertEqual(self.client.posts, 1)

    def test_before_send_guard_failure_never_posts_or_refunds_attempt(self):
        approval = self.make_host()
        grant = approval.validate(self.req)
        original = self.client.request
        state = {'runtime': 'approved'}
        def request(method, path, payload=None, **kwargs):
            value = original(method, path, payload, **kwargs)
            if method == 'GET' and path.endswith('/approvals'):
                state['runtime'] = 'drifted'
            return value
        def guard():
            if state['runtime'] != 'approved':
                raise RuntimeError('runtime changed during authority reads')
        with mock.patch.object(self.client, 'request', side_effect=request):
            with self.assertRaises(AuthorizationUnavailable):
                approval.consume(grant, self.req, before_consume=guard)
        self.assertEqual(self.client.posts, 0)
        self.assertIn(self.req.digest(), approval._consumed)
        self.assertNotIn(self.req.digest(), approval._verified_consumptions)
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(grant, self.req)
        with self.assertRaises(AuthorizationUnavailable):
            approval.guard(self.req)
        self.assertEqual(self.client.posts, 0)

    def test_callback_expiry_rejected_without_post_or_refund(self):
        approval = self.make_host()
        grant = approval.validate(self.req)
        def guard():
            approval._expires = 0
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(grant, self.req, before_consume=guard)
        self.assertEqual(self.client.posts, 0)
        self.assertIn(self.req.digest(), approval._consumed)

    def test_noncallable_consumption_guard_denied(self):
        approval = self.make_host()
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(approval.validate(self.req), self.req, before_consume=True)
        self.assertEqual(self.client.posts, 0)

    def test_request_subclasses_cannot_replace_frozen_domain(self):
        class OtherRequest(Request):
            pass
        other = OtherRequest(**vars(self.req))
        with self.assertRaises(AuthorizationUnavailable):
            host.GitHubActionsApproval(self.client, 'token', [other], self.policy,
                                      verifier=lambda token: self.claims)
        with self.assertRaises(AuthorizationUnavailable):
            self.make_host().validate(other)

    def test_wrong_grant_types_cannot_consume_even_with_matching_equality(self):
        class OtherGrant(host.Grant):
            def __eq__(self, other):
                return True
        approval = self.make_host()
        expected = approval.validate(self.req)
        for grant in (OtherGrant(**vars(expected)),
                      host.Receipt(expected.grant_id, expected.request_hash, 1, expected.expires_at)):
            with self.subTest(kind=type(grant)), self.assertRaises(AuthorizationUnavailable):
                approval.consume(grant, self.req)
        self.assertEqual(self.client.posts, 0)

    def test_bundle_binds_order_and_expiry(self):
        second = request('local-tag-create')
        self.assertNotEqual(host.bundle_digest([self.req, second], self.policy.expires_at),
                            host.bundle_digest([second, self.req], self.policy.expires_at))
        self.assertNotEqual(host.bundle_digest([self.req], self.policy.expires_at),
                            host.bundle_digest([self.req], '2099-01-01T00:00:00+00:00'))

    def test_oidc_claims_are_exact_and_time_bounded(self):
        bad = dict(iss='https://example.com', aud='other', exp=0, iat=int(time.time()) + 100,
                   nbf=int(time.time()) + 100, repository='attacker/repo', repository_id='9',
                   workflow_ref='other', workflow_sha='f' * 40, run_id='124', run_attempt='2',
                   environment='other', sub='other', actor_id='999')
        for key, value in bad.items():
            with self.subTest(key=key):
                original = self.claims[key]
                self.claims[key] = value
                with self.assertRaises(AuthorizationUnavailable):
                    self.make_host()
                self.claims[key] = original

    def test_missing_approval_wrong_digest_and_reviewer_rejected(self):
        path = '/repos/sample/host/actions/runs/123/approvals'
        original = copy.deepcopy(self.client.data[path])
        variants = [[], [dict(original[0], comment='dev-workflow approve forged')],
                    [dict(original[0], user={'id': 999})], [dict(original[0], state='rejected')],
                    [dict(original[0], environments=[dict(id=999, name='release')])],
                    original + [dict(original[0], state='rejected')]]
        for value in variants:
            with self.subTest(value=value):
                self.client.data[path] = value
                with self.assertRaises(AuthorizationUnavailable):
                    self.make_host()

    def test_environment_bypass_self_review_and_team_reviewer_rejected(self):
        path = '/repos/sample/host/environments/release'
        original = copy.deepcopy(self.client.data[path])
        for key in ('bypass', 'self-review', 'team', 'empty'):
            value = copy.deepcopy(original)
            if key == 'bypass':
                value['can_admins_bypass'] = True
            elif key == 'self-review':
                value['protection_rules'][0]['prevent_self_review'] = False
            elif key == 'team':
                value['protection_rules'][0]['reviewers'][0]['type'] = 'Team'
            else:
                value['protection_rules'] = []
            self.client.data[path] = value
            with self.subTest(key=key), self.assertRaises(AuthorizationUnavailable):
                self.make_host()

    def test_explicit_single_user_policy_permits_real_self_review(self):
        self.policy = replace(self.policy, prevent_self_review=False)
        self.client = Client(self.policy, [self.req])
        self.client.data['/repos/sample/host/actions/runs/123']['actor']['id'] = 21
        self.claims['actor_id'] = '21'
        self.make_host()

    def test_run_changed_or_no_longer_in_progress_rejected(self):
        path = '/repos/sample/host/actions/runs/123'
        original = copy.deepcopy(self.client.data[path])
        for key, value in dict(id=999, run_attempt=2, head_sha='f' * 40, status='completed', event='push',
                               repository={'id': 999}, actor={'id': 999}).items():
            self.client.data[path] = dict(original, **{key: value})
            with self.subTest(key=key), self.assertRaises(AuthorizationUnavailable):
                self.make_host()

    def test_target_repository_identity_rechecked(self):
        approval = self.make_host()
        self.client.data['/repos/sample/target']['id'] = 999
        with self.assertRaises(AuthorizationUnavailable):
            approval.validate(self.req)

    def test_modified_request_rejected(self):
        approval = self.make_host()
        for key, value in dict(tag='v2.0.0', target_sha='f' * 40, plan_hash='d' * 64,
                               remote_url='https://github.com/other/repo.git').items():
            with self.subTest(key=key), self.assertRaises(AuthorizationUnavailable):
                approval.validate(replace(self.req, **{key: value}))

    def test_expired_bundle_rejected(self):
        self.policy = replace(self.policy, expires_at='2020-01-01T00:00:00+00:00')
        with self.assertRaises(AuthorizationUnavailable):
            self.make_host()

    def test_host_restart_cannot_consume_same_operation_again(self):
        first = self.make_host()
        first.consume(first.validate(self.req), self.req)
        second = self.make_host()
        with self.assertRaises(AuthorizationUnavailable):
            second.consume(second.validate(self.req), self.req)
        with self.assertRaises(AuthorizationUnavailable):
            second.guard(self.req)

    def test_consumption_response_loss_never_authorizes_dispatch(self):
        approval = self.make_host()
        self.client.after_post = lambda: (_ for _ in ()).throw(TimeoutError('lost response'))
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(approval.validate(self.req), self.req)
        self.assertEqual(len(self.client.markers), 1)
        with self.assertRaises(AuthorizationUnavailable):
            approval.guard(self.req)
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(approval.validate(self.req), self.req)
        self.assertEqual(self.client.posts, 1)

    def test_concurrent_hosts_cannot_double_consume(self):
        approvals = [self.make_host(), self.make_host()]
        results = []
        def consume(approval):
            try:
                approval.consume(approval.validate(self.req), self.req)
                results.append('consumed')
            except AuthorizationUnavailable:
                results.append('denied')
        threads = [threading.Thread(target=consume, args=(approval,)) for approval in approvals]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertCountEqual(results, ['consumed', 'denied'])

    def test_consumed_marker_revalidated_before_dispatch(self):
        approval = self.make_host()
        approval.consume(approval.validate(self.req), self.req)
        next(iter(self.client.markers.values()))['object']['sha'] = 'f' * 40
        with self.assertRaises(AuthorizationUnavailable):
            approval.guard(self.req)

    def test_expiry_revalidated_before_dispatch(self):
        approval = self.make_host()
        approval.consume(approval.validate(self.req), self.req)
        self.claims['exp'] = 0
        with self.assertRaises(AuthorizationUnavailable):
            approval.guard(self.req)

    def test_bundle_binds_trusted_host_policy(self):
        first = host.bundle_digest([self.req], self.policy.expires_at, self.policy.bundle_context())
        other = replace(self.policy, run_id=124)
        self.assertNotEqual(first, host.bundle_digest([self.req], other.expires_at, other.bundle_context()))

    def test_expiry_during_slow_authority_read_rejected(self):
        calls = []
        now = time.time()
        def advancing_time():
            calls.append(True)
            return now if len(calls) == 1 else now + 600
        with mock.patch.object(host.time, 'time', side_effect=advancing_time):
            with self.assertRaises(AuthorizationUnavailable):
                self.make_host()

    def test_immutable_subject_uses_authenticated_owner_and_repository_ids(self):
        path = '/repos/sample/host/actions/oidc/customization/sub'
        prefix = 'repo:sample@10/host@1'
        self.client.data[path] = dict(use_default=True, use_immutable_subject=True, sub_claim_prefix=prefix)
        self.claims['sub'] = prefix + ':environment:release'
        self.make_host()
        self.client.data[path].pop('sub_claim_prefix')
        self.make_host()

    def test_legacy_subject_explicit_and_omitted_mode(self):
        path = '/repos/sample/host/actions/oidc/customization/sub'
        self.make_host()
        self.client.data[path] = dict(use_default=True, use_immutable_subject=False, sub_claim_prefix='repo:sample/host')
        self.make_host()

    def test_immutable_subject_wrong_ids_and_legacy_downgrade_rejected(self):
        path = '/repos/sample/host/actions/oidc/customization/sub'
        self.client.data[path] = dict(use_default=True, use_immutable_subject=True)
        for subject in ('repo:sample@999/host@1:environment:release',
                        'repo:sample@10/host@999:environment:release',
                        'repo:other@10/host@1:environment:release',
                        'repo:sample/host:environment:release',
                        'repo:sample@10/host@1:environment:other'):
            with self.subTest(subject=subject):
                self.claims['sub'] = subject
                with self.assertRaises(AuthorizationUnavailable):
                    self.make_host()

    def test_immutable_owner_identity_required(self):
        path = '/repos/sample/host/actions/oidc/customization/sub'
        self.client.data[path] = dict(use_default=True, use_immutable_subject=True)
        self.claims['sub'] = 'repo:sample@10/host@1:environment:release'
        for owner in (None, {}, {'id': 0}, {'id': '10'}, {'id': True}):
            with self.subTest(owner=owner):
                self.client.data['/repos/sample/host']['owner'] = owner
                with self.assertRaises(AuthorizationUnavailable):
                    self.make_host()

    def test_subject_settings_reject_custom_malformed_and_conflicting_prefix(self):
        path = '/repos/sample/host/actions/oidc/customization/sub'
        variants = [[], {}, dict(use_default=False), dict(use_default=1),
                    dict(use_default=True, use_immutable_subject='true'),
                    dict(use_default=True, use_immutable_subject=1),
                    dict(use_default=True, use_immutable_subject=None),
                    dict(use_default=True, include_claim_keys=['repo', 'job_workflow_ref']),
                    dict(use_default=True, sub_claim_prefix='repo:other/host'),
                    dict(use_default=True, sub_claim_prefix=None),
                    dict(use_default=True, use_immutable_subject=True, sub_claim_prefix='repo:sample/host')]
        for settings in variants:
            with self.subTest(settings=settings):
                self.client.data[path] = settings
                with self.assertRaises(AuthorizationUnavailable):
                    self.make_host()

    def test_immutable_token_cannot_select_format_when_settings_are_legacy(self):
        self.claims['sub'] = 'repo:sample@10/host@1:environment:release'
        for mode in ({'use_default': True}, {'use_default': True, 'use_immutable_subject': False}):
            self.client.data['/repos/sample/host/actions/oidc/customization/sub'] = mode
            with self.subTest(mode=mode), self.assertRaises(AuthorizationUnavailable):
                self.make_host()

    def test_default_verifier_does_not_accept_unsigned_claims(self):
        for token in ('anything', 'e30.e30.fake', 'eyJhbGciOiJub25lIn0.e30.fake'):
            with self.subTest(token=token), self.assertRaises(AuthorizationUnavailable):
                host.GitHubActionsApproval(self.client, token, [self.req], self.policy)


class OIDCSignatureTests(unittest.TestCase):
    @unittest.skipUnless(Path('/usr/bin/openssl').is_file(), 'Production Linux OpenSSL verifier unavailable')
    def test_real_rsa_signature_and_tampering(self):
        encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip('=')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['/usr/bin/openssl', 'genrsa', '-out', str(root / 'key.pem'), '2048'],
                           check=True, capture_output=True)
            modulus = subprocess.run(['/usr/bin/openssl', 'rsa', '-in', str(root / 'key.pem'), '-modulus', '-noout'],
                                     check=True, capture_output=True, text=True).stdout.strip().split('=')[1]
            header = encode(json.dumps(dict(alg='RS256', kid='test')).encode())
            body = encode(json.dumps(dict(iss=host.ISSUER, test=True)).encode())
            signed = (header + '.' + body).encode()
            signature = subprocess.run(['/usr/bin/openssl', 'dgst', '-sha256', '-sign', str(root / 'key.pem')],
                                       input=signed, check=True, capture_output=True).stdout
            token = header + '.' + body + '.' + encode(signature)
            keyset = json.dumps(dict(keys=[dict(kty='RSA', kid='test', n=encode(bytes.fromhex(modulus)), e=encode(b'\x01\x00\x01'))])).encode()
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = keyset
            opener = mock.Mock()
            opener.open.return_value = response
            with mock.patch.object(host.urllib.request, 'build_opener', return_value=opener):
                self.assertTrue(host.verify_oidc(token)['test'])
                with self.assertRaises(AuthorizationUnavailable):
                    host.verify_oidc(header + '.' + encode(b'{"test":false}') + '.' + encode(signature))
                with self.assertRaises(AuthorizationUnavailable):
                    host.verify_oidc(header + '.' + body + '.' + encode(bytes(len(signature))))
                self.assertEqual(opener.open.call_args.args[0], host.ISSUER + '/.well-known/jwks')


if __name__ == '__main__':
    unittest.main()
