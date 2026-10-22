from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(1, str(ROOT / 'packs/deployment/scripts'))
import deployment_host as host
import deployment_authorize as execution
import release_host as release
from release_execute import Grant as ReleaseGrant, Receipt as ReleaseReceipt, AuthorizationUnavailable
from tests.test_release_host import Client, SHA, claims, policy, request as release_request


def deadline(minutes=20):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def request(operation='deployment-deploy', **changes):
    values = dict(operation=operation, repository='/tmp/dev-workflow-target',
                  repository_slug='sample/target', repository_id=2, head_sha=SHA,
                  configuration_hash='b' * 64, environment='staging', target='docker',
                  production=False, components=('api',), before_json='{}', after_json='{}',
                  conditions_json='{}', plan_hash='c' * 64, observation_hash='d' * 64,
                  state_hash='e' * 64, runtime_policy_hash='f' * 64,
                  expires_at=deadline(), max_uses=1)
    return execution.Request(**dict(values, **changes))


def deployment_policy(**changes):
    values = dict(vars(policy()), deployment_environment='staging', deployment_target='docker',
                  production=False, runtime_policy_hash='f' * 64,
                  allowed_components=('api', 'web'), approval_environment='deployment-review',
                  environment='observer')
    return host.DeploymentHostPolicy(**dict(values, **changes))


class DeploymentHostTests(unittest.TestCase):
    def setUp(self):
        self.req = request()
        self.policy = deployment_policy()
        self.claims = claims(self.policy)
        self.claims['aud'] = host.AUDIENCE
        self.client = self.client_for([self.req])

    def client_for(self, requests):
        client = Client(self.policy, requests)
        environment = client.data.pop('/repos/sample/host/environments/release')
        environment['name'] = self.policy.approval_environment
        client.data['/repos/sample/host/environments/' + self.policy.approval_environment] = environment
        client.data['/repos/sample/host/actions/runs/123/approvals'][0]['environments'][0]['name'] = self.policy.approval_environment
        return client

    def make_host(self, requests=None, client=None):
        return host.GitHubDeploymentApproval(client or self.client, 'opaque-signed-token',
            requests or [self.req], self.policy, verifier=lambda token: copy.deepcopy(self.claims))

    def test_deployment_grant_receipt_and_separate_ledger(self):
        approval = self.make_host()
        grant = approval.validate(self.req)
        self.assertIs(type(grant), execution.Grant)
        self.assertEqual(grant.grant_id, 'github-deployment:123:deployment-deploy')
        self.assertEqual(grant.max_uses, 1)
        with self.assertRaises(AuthorizationUnavailable):
            approval.guard(self.req)
        receipt = approval.consume(grant, self.req)
        self.assertIs(type(receipt), execution.Receipt)
        self.assertEqual(receipt.request_hash, self.req.digest())
        self.assertEqual(receipt.use_number, 1)
        marker = next(iter(self.client.markers))
        self.assertTrue(marker.startswith('tags/workflow-deployment-grants/123/'))
        approval.guard(self.req)
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(grant, self.req)
        self.assertEqual(self.client.posts, 1)

    def test_execution_requires_a_separately_bound_host_policy(self):
        binding = execution.canonical(dict(profile='docker-container-replace-v1',
                                             policyHash='1' * 64, component='api'))
        self.req = replace(self.req, execution_json=binding)
        self.client = self.client_for([self.req])
        with self.assertRaises(AuthorizationUnavailable):
            self.make_host()
        self.policy = replace(self.policy, execution_policy_hash='1' * 64)
        self.claims = dict(claims(self.policy), aud=host.AUDIENCE)
        self.client = self.client_for([self.req])
        self.assertEqual(self.make_host().validate(self.req).request_hash, self.req.digest())
        for binding in (dict(profile='docker-container-replace-v1', policyHash='2' * 64, component='api'),
                        dict(profile='docker-container-replace-v1', policyHash='1' * 64, component='web')):
            req = replace(self.req, execution_json=execution.canonical(binding))
            with self.subTest(binding=binding), self.assertRaises(AuthorizationUnavailable):
                self.make_host([req])

    def test_execution_policy_changes_the_exact_review_digest(self):
        configured = replace(self.policy, execution_policy_hash='1' * 64)
        self.assertNotEqual(release.bundle_digest([self.req], self.policy.expires_at, self.policy.bundle_context()),
                            release.bundle_digest([self.req], configured.expires_at, configured.bundle_context()))
        for value in ('bad', 1, True):
            with self.subTest(value=value), self.assertRaises(AuthorizationUnavailable):
                replace(self.policy, execution_policy_hash=value)

    def test_both_deployment_operations(self):
        rollback = request('deployment-rollback')
        requests = [self.req, rollback]
        client = self.client_for(requests)
        approval = self.make_host(requests, client)
        for req in requests:
            approval.consume(approval.validate(req), req)
            approval.guard(req)
        self.assertEqual(client.posts, 2)

    def test_grant_deadline_is_minimum_of_host_token_and_request(self):
        self.req = replace(self.req, expires_at=deadline(1))
        self.client = self.client_for([self.req])
        grant = self.make_host().validate(self.req)
        self.assertEqual(release.timestamp(grant.expires_at), release.timestamp(self.req.expires_at))
        self.req = replace(self.req, expires_at=deadline(10))
        self.client = self.client_for([self.req])
        grant = self.make_host().validate(self.req)
        self.assertEqual(release.timestamp(grant.expires_at).timestamp(), self.claims['exp'])

    def test_host_deadline_can_shorten_request_deadline(self):
        self.policy = replace(self.policy, expires_at=deadline(1))
        self.client = self.client_for([self.req])
        grant = self.make_host().validate(self.req)
        self.assertEqual(release.timestamp(grant.expires_at), release.timestamp(self.policy.expires_at))

    def test_scope_mismatch_is_denied_before_api_access(self):
        variants = dict(repository_slug='other/target', repository_id=99, environment='production',
                        target='other', production=True, runtime_policy_hash='0' * 64,
                        components=('unapproved',), max_uses=2, expires_at=deadline(-1))
        for key, value in variants.items():
            with self.subTest(field=key):
                client = mock.Mock()
                with self.assertRaises((AuthorizationUnavailable, execution.AuthorizationError)):
                    req = replace(self.req, **{key: value})
                    self.make_host([req], client)
                client.request.assert_not_called()

    def test_strict_identity_production_and_use_types(self):
        for key, value in (('repository_id', True), ('production', 0), ('max_uses', True),
                           ('components', ['api']), ('components', ()), ('components', ('api', 'api'))):
            with self.subTest(field=key, value=value):
                with self.assertRaises((AuthorizationUnavailable, execution.AuthorizationError)):
                    req = replace(self.req, **{key: value})
                    self.make_host([req])

    def test_request_lifetime_and_timestamp_rejected(self):
        for value in (deadline(61), 'invalid', '2026-10-22T00:00:00', None):
            with self.subTest(value=value):
                with self.assertRaises((AuthorizationUnavailable, execution.AuthorizationError, ValueError)):
                    self.make_host([replace(self.req, expires_at=value)])

    def test_modified_frozen_request_denied(self):
        approval = self.make_host()
        for key, value in (('head_sha', '0' * 40), ('plan_hash', '0' * 64),
                           ('state_hash', '0' * 64), ('components', ('web',))):
            with self.subTest(field=key), self.assertRaises(AuthorizationUnavailable):
                approval.validate(replace(self.req, **{key: value}))

    def test_release_requests_and_approvals_do_not_cross_domains(self):
        with self.assertRaises(AuthorizationUnavailable):
            self.make_host([release_request()])
        p = policy()
        client = Client(p, [self.req])
        with self.assertRaises(AuthorizationUnavailable):
            release.GitHubActionsApproval(client, 'token', [self.req], p,
                                          verifier=lambda token: claims(p))
        self.claims['aud'] = release.AUDIENCE
        with self.assertRaises(AuthorizationUnavailable):
            self.make_host()

    def test_wrong_domain_grants_and_receipts_rejected_without_cas(self):
        approval = self.make_host()
        grant = approval.validate(self.req)
        for value in (ReleaseGrant(grant.grant_id, grant.request_hash, grant.expires_at, 1),
                      ReleaseReceipt(grant.grant_id, grant.request_hash, 1, deadline()),
                      execution.Receipt(grant.grant_id, grant.request_hash, 1, deadline())):
            with self.subTest(kind=type(value)), self.assertRaises(AuthorizationUnavailable):
                approval.consume(value, self.req)
        self.assertEqual(self.client.posts, 0)
        p, req = policy(), release_request()
        other = release.GitHubActionsApproval(Client(p, [req]), 'token', [req], p,
                                              verifier=lambda token: claims(p))
        with self.assertRaises(AuthorizationUnavailable):
            other.consume(grant, req)

    def test_caller_environment_and_gate_cannot_substitute_for_each_other(self):
        self.make_host()  # No observer environment API entry exists in this fixture.
        self.claims['environment'] = self.policy.approval_environment
        self.claims['sub'] = 'repo:sample/host:environment:' + self.policy.approval_environment
        with self.assertRaises(AuthorizationUnavailable):
            self.make_host()

    def test_gate_approval_and_protection_are_required(self):
        original = copy.deepcopy(self.client.data)
        for kind in ('approval-name', 'approval-digest', 'gate-name', 'bypass', 'reviewer'):
            self.client.data = copy.deepcopy(original)
            gate = self.client.data['/repos/sample/host/environments/deployment-review']
            review = self.client.data['/repos/sample/host/actions/runs/123/approvals'][0]
            if kind == 'approval-name':
                review['environments'][0]['name'] = 'observer'
            elif kind == 'approval-digest':
                review['comment'] = 'dev-workflow approve release-digest'
            elif kind == 'gate-name':
                gate['name'] = 'observer'
            elif kind == 'bypass':
                gate['can_admins_bypass'] = True
            else:
                review['user']['id'] = 999
            with self.subTest(kind=kind), self.assertRaises(AuthorizationUnavailable):
                self.make_host()

    def test_all_deployment_policy_fields_bind_review_digest(self):
        original = release.bundle_digest([self.req], self.policy.expires_at, self.policy.bundle_context())
        for key, value in dict(deployment_environment='other', deployment_target='other', production=True,
                               runtime_policy_hash='0' * 64, allowed_components=('api',),
                               approval_environment='other', environment='other').items():
            p = replace(self.policy, **{key: value})
            with self.subTest(field=key):
                self.assertNotEqual(original, release.bundle_digest([self.req], p.expires_at, p.bundle_context()))

    def test_existing_portable_deployment_identifiers_are_supported(self):
        p = replace(self.policy, deployment_environment='stage.eu', deployment_target='docker.local',
                    allowed_components=('api.v1',))
        req = replace(self.req, environment=p.deployment_environment, target=p.deployment_target,
                      components=p.allowed_components)
        self.policy = p
        client = self.client_for([req])
        self.make_host([req], client).validate(req)

    def test_invalid_deployment_policy(self):
        for key, value in (('production', 1), ('runtime_policy_hash', 'bad'),
                           ('allowed_components', []), ('allowed_components', ('api', 'api')),
                           ('deployment_target', ''), ('approval_environment', 'bad/env')):
            with self.subTest(field=key), self.assertRaises(AuthorizationUnavailable):
                replace(self.policy, **{key: value})
        with self.assertRaises(AuthorizationUnavailable):
            host.GitHubDeploymentApproval(self.client, 'token', [self.req], policy())

    def test_expiry_during_authority_read_denies_grant(self):
        now = release.time.time()
        self.req = replace(self.req, expires_at=datetime.fromtimestamp(now + 10, timezone.utc).isoformat())
        self.client = self.client_for([self.req])
        original = self.client.request
        def slow_read(method, path, *args, **kwargs):
            value = original(method, path, *args, **kwargs)
            if path.endswith('/approvals'):
                clock.return_value = now + 11
            return value
        self.client.request = slow_read
        with mock.patch.object(host.time, 'time', return_value=now) as clock:
            with self.assertRaises(AuthorizationUnavailable):
                self.make_host()

    def test_expiry_rechecked_before_cas_and_guard(self):
        approval = self.make_host()
        grant = approval.validate(self.req)
        expired = release.timestamp(self.req.expires_at).timestamp() + 1
        with mock.patch.object(host.time, 'time', return_value=expired):
            with self.assertRaises(AuthorizationUnavailable):
                approval.consume(grant, self.req)
        self.assertEqual(self.client.posts, 0)
        approval.consume(grant, self.req)
        with mock.patch.object(host.time, 'time', return_value=expired):
            with self.assertRaises(AuthorizationUnavailable):
                approval.guard(self.req)

    def test_restart_and_ledger_tampering_deny(self):
        first = self.make_host()
        first.consume(first.validate(self.req), self.req)
        second = self.make_host()
        with self.assertRaises(AuthorizationUnavailable):
            second.consume(second.validate(self.req), self.req)
        next(iter(self.client.markers.values()))['object']['sha'] = '0' * 40
        with self.assertRaises(AuthorizationUnavailable):
            first.guard(self.req)


if __name__ == '__main__':
    unittest.main()
