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
import deployment_compose_approval_v3_host as host
from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity
from release_execute import AuthorizationUnavailable, Grant
from tests.test_release_host import Client, SHA, claims, policy as release_policy


def deadline(minutes=20):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ')


def policy(**changes):
    values = dict(vars(release_policy()), environment='observer', approval_environment='compose-review',
                  operation='deploy', profile_version='3', source_sha=SHA,
                  target=TargetIdentity('compose', 'dw-blog', 'stack'), deployment_environment='staging',
                  production=False, daemon_id='daemon-1', host_id='host-one',
                  components=('api', 'web'), protected_components=('db', 'redis'), policy_hash='f' * 64, bundle_hash='e' * 64)
    return host.FullBodyApprovalPolicyV3(**dict(values, **changes))


def request(**changes):
    values = dict(schema_version=2, operation='deploy', profile_id=host.PROFILE, profile_version='3',
                  source=SourceIdentity('github.com', 'https://github.com/sample/target.git', 2, 'sample/target', SHA),
                  target=TargetIdentity('compose', 'dw-blog', 'stack'), environment='staging', production=False,
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
        return host.GitHubFullBodyApprovalV3(client or self.client, 'signed', requests or [self.req],
                                          self.policy, verifier=lambda _: copy.deepcopy(self.claims))

    def test_exact_review_consumes_independent_evidence_only(self):
        approval = self.approval()
        grant = approval.validate(self.req)
        self.assertIs(type(grant), host.FullBodyAuthorizationEvidenceV3)
        self.assertNotIsInstance(grant, Grant)
        receipt = approval.consume(grant, self.req)
        self.assertIs(type(receipt), host.FullBodyConsumptionEvidenceV3)
        self.assertEqual(receipt.request_hash, self.req.digest())
        self.assertTrue(next(iter(self.client.markers)).startswith('tags/workflow-compose-full-body-authorization-v3/'))
        with self.assertRaises(AuthorizationUnavailable):
            approval.guard(self.req)
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(grant, self.req)

    def test_deploy_and_rollback_require_fresh_operation_policy_and_review(self):
        rollback = replace(self.req, operation='rollback', history_hash='1' * 64)
        with self.assertRaises(AuthorizationUnavailable):
            self.approval([rollback], mock.Mock())
        self.policy = replace(self.policy, operation='rollback', approval_environment='compose-rollback-review',
                              expected_history_hash=rollback.history_hash)
        self.claims = dict(claims(self.policy), aud=host.AUDIENCE)
        self.client = self.client_for([rollback])
        self.assertEqual(self.approval([rollback]).consume(self.approval([rollback]).validate(rollback), rollback).request_hash, rollback.digest())

    def test_scope_and_profile_rejected_before_network(self):
        cases = [replace(self.req, profile_version='1'), replace(self.req, profile_version='2'),
                 replace(self.req, plan_hash='0' * 64), replace(self.req, host_id='other'),
                 replace(self.req, profile_id='docker-container-replace-v1'),
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


class FullBodyBoundaryTests(ComposeApprovalTests):
    def test_consumed_intent_is_not_runtime_admission(self):
        approval = self.approval()
        with self.assertRaises(AuthorizationUnavailable):
            approval.check_consumed_intent(self.req)
        approval.consume(approval.validate(self.req), self.req)
        self.assertIsNone(approval.check_consumed_intent(self.req))
        with self.assertRaisesRegex(AuthorizationUnavailable, 'runtimePermit'):
            approval.guard(self.req)
        self.client.data['/repos/sample/host/actions/runs/123/approvals'][0]['comment'] = 'changed'
        with self.assertRaises(AuthorizationUnavailable):
            approval.check_consumed_intent(self.req)

    def test_unsafe_policy_rejected(self):
        for changes in (dict(production=True), dict(production=0), dict(bundle_hash=True),
                        dict(target=TargetIdentity('compose', 'production', 'stack')),
                        dict(profile_version='1'), dict(profile_version='2'),
                        dict(components=('web', 'api')), dict(protected_components=('api',))):
            with self.subTest(changes=changes), self.assertRaises(AuthorizationUnavailable):
                policy(**changes)

    def test_recovery_and_pinned_history(self):
        for operation in ('rollback', 'recovery'):
            with self.subTest(operation=operation), self.assertRaises(AuthorizationUnavailable):
                policy(operation=operation)
            self.req = request(operation=operation, history_hash='1' * 64)
            self.policy = policy(operation=operation, expected_history_hash='1' * 64)
            self.claims = dict(claims(self.policy), aud=host.AUDIENCE)
            self.client = self.client_for([self.req])
            approval = self.approval()
            approval.consume(approval.validate(self.req), self.req)
            self.assertIsNone(approval.check_consumed_intent(self.req))
            with self.assertRaises(AuthorizationUnavailable):
                self.approval([replace(self.req, history_hash='2' * 64)], mock.Mock())
        with self.assertRaises(ValueError):
            request(operation='recovery')

    def test_exact_human_digest_and_environment_rules(self):
        for change in ('image', 'host', 'bundle', 'bypass', 'environment'):
            self.setUp()
            if change == 'image':
                self.req = replace(self.req, artifact_digest='0' * 64)
            elif change == 'host':
                self.policy = replace(self.policy, host_id='other')
                self.req = replace(self.req, host_id='other')
            elif change == 'bundle':
                self.policy = replace(self.policy, bundle_hash='0' * 64)
                self.req = replace(self.req, plan_hash='0' * 64)
            elif change == 'bypass':
                self.client.data['/repos/sample/host/environments/compose-review']['can_admins_bypass'] = True
            else:
                self.client.data['/repos/sample/host/actions/runs/123/approvals'][0]['environments'][0]['name'] = 'other'
            with self.subTest(change=change), self.assertRaises(AuthorizationUnavailable):
                self.approval()

    def test_ledger_replay_tampering_and_expiry(self):
        approval = self.approval()
        approval.consume(approval.validate(self.req), self.req)
        replay = self.approval()
        with self.assertRaises(AuthorizationUnavailable):
            replay.consume(replay.validate(self.req), self.req)
        marker = next(iter(self.client.markers))
        self.client.markers[marker]['object']['sha'] = '0' * 40
        with self.assertRaises(AuthorizationUnavailable):
            approval.check_consumed_intent(self.req)
        with mock.patch.object(host.time, 'time', return_value=datetime.now(timezone.utc).timestamp() + 7200):
            with self.assertRaises(AuthorizationUnavailable):
                approval.check_consumed_intent(self.req)
        with self.assertRaises(AuthorizationUnavailable):
            self.approval([replace(self.req, expires_at=deadline(61))], mock.Mock())

    def test_default_real_verifier_and_isolated_types(self):
        import release_host
        with mock.patch.object(release_host, 'verify_oidc', side_effect=AuthorizationUnavailable('no token')) as verifier:
            with self.assertRaises(AuthorizationUnavailable):
                host.GitHubFullBodyApprovalV3(self.client, 'signed', [self.req], self.policy)
            verifier.assert_called_once_with('signed')
        import deployment_compose_approval_host as old
        approval = self.approval()
        grant = approval.validate(self.req)
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(old.ComposeAuthorizationEvidence(**vars(grant)), self.req)
        self.assertEqual(self.policy.bundle_context()['bundle_hash'], self.req.plan_hash)


if __name__ == '__main__':
    unittest.main()
