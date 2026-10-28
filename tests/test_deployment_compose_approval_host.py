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
import deployment_compose_approval_host as host
from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity
from release_execute import AuthorizationUnavailable, Grant
from tests.test_release_host import Client, SHA, claims, policy as release_policy


def deadline(minutes=20):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ')


def policy(**changes):
    values = dict(vars(release_policy()), environment='observer', approval_environment='compose-review',
                  operation='deploy', profile_version='1', source_sha=SHA,
                  target=TargetIdentity('compose', 'blog', 'stack'), deployment_environment='staging',
                  production=False, daemon_id='daemon-1', host_id='host-one',
                  components=('api', 'web'), protected_components=('db', 'redis'), policy_hash='f' * 64)
    return host.ComposeApprovalPolicy(**dict(values, **changes))


def request(**changes):
    values = dict(schema_version=2, operation='deploy', profile_id=host.PROFILE, profile_version='1',
                  source=SourceIdentity('github.com', 'https://github.com/sample/target.git', 2, 'sample/target', SHA),
                  target=TargetIdentity('compose', 'blog', 'stack'), environment='staging', production=False,
                  daemon_id='daemon-1', components=('api', 'web'), protected_components=('db', 'redis'),
                  before_hash='a' * 64, after_hash='b' * 64, artifact_digest='c' * 64,
                  observation_hash='d' * 64, history_hash=None, host_id='host-one',
                  plan_hash='e' * 64, policy_hash='f' * 64, expires_at=deadline(), max_uses=1)
    return RequestV2(**dict(values, **changes))


class ComposeApprovalTests(unittest.TestCase):
    def setUp(self):
        self.req = request()
        self.policy = policy()
        self.claims = dict(claims(self.policy), aud=host.AUDIENCE)
        self.client = self.client_for([self.req])

    def client_for(self, requests):
        client = Client(self.policy, requests)
        env = client.data.pop('/repos/sample/host/environments/release')
        env['name'] = self.policy.approval_environment
        client.data['/repos/sample/host/environments/' + self.policy.approval_environment] = env
        client.data['/repos/sample/host/actions/runs/123/approvals'][0]['environments'][0]['name'] = self.policy.approval_environment
        return client

    def approval(self, requests=None, client=None):
        return host.GitHubComposeApproval(client or self.client, 'signed', requests or [self.req],
                                          self.policy, verifier=lambda _: copy.deepcopy(self.claims))

    def test_exact_review_consumes_independent_evidence_only(self):
        approval = self.approval()
        grant = approval.validate(self.req)
        self.assertIs(type(grant), host.ComposeAuthorizationEvidence)
        self.assertNotIsInstance(grant, Grant)
        receipt = approval.consume(grant, self.req)
        self.assertIs(type(receipt), host.ComposeConsumptionEvidence)
        self.assertEqual(receipt.request_hash, self.req.digest())
        self.assertTrue(next(iter(self.client.markers)).startswith('tags/workflow-compose-authorization-v2/'))
        with self.assertRaises(AuthorizationUnavailable):
            approval.guard(self.req)
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(grant, self.req)

    def test_deploy_and_rollback_require_fresh_operation_policy_and_review(self):
        rollback = replace(self.req, operation='rollback', history_hash='1' * 64)
        with self.assertRaises(AuthorizationUnavailable):
            self.approval([rollback], mock.Mock())
        self.policy = replace(self.policy, operation='rollback', approval_environment='compose-rollback-review')
        self.claims = dict(claims(self.policy), aud=host.AUDIENCE)
        self.client = self.client_for([rollback])
        self.assertEqual(self.approval([rollback]).consume(self.approval([rollback]).validate(rollback), rollback).request_hash, rollback.digest())

    def test_scope_and_profile_rejected_before_network(self):
        cases = [replace(self.req, profile_id='docker-container-replace-v1'),
                 replace(self.req, production=True),
                 replace(self.req, components=('api',)),
                 replace(self.req, protected_components=('db',)),
                 replace(self.req, daemon_id='other'),
                 replace(self.req, target=TargetIdentity('compose', 'elsewhere', 'stack')),
                 replace(self.req, source=replace(self.req.source, project_id=99)),
                 replace(self.req, source=replace(self.req.source, source_sha='b' * 40)),
                 replace(self.req, policy_hash='0' * 64)]
        for req in cases:
            with self.subTest(req=req.digest()):
                client = mock.Mock()
                with self.assertRaises(AuthorizationUnavailable):
                    self.approval([req], client)
                client.request.assert_not_called()

    def test_v1_grant_replay_and_wrong_review_denied(self):
        approval = self.approval()
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(Grant('x', self.req.digest(), deadline(), 1), self.req)
        self.client.data['/repos/sample/host/actions/runs/123/approvals'][0]['comment'] = 'dev-workflow approve ' + '0' * 64
        with self.assertRaises(AuthorizationUnavailable):
            self.approval()

    def test_oidc_audience_must_be_compose_specific(self):
        self.claims['aud'] = 'dev-workflow-deployment-host'
        with self.assertRaises(AuthorizationUnavailable):
            self.approval()


if __name__ == '__main__':
    unittest.main()
