"""Recovery GitHub audience, reviewed scope and absent-only CAS separation."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import deployment_recovery_host as host
from tests import test_deployment_host as deployment
from tests.test_release_host import Client, claims
from release_execute import AuthorizationUnavailable


def request(**changes):
    original = deployment.request()
    fields = ('repository', 'repository_slug', 'repository_id', 'head_sha', 'configuration_hash',
              'environment', 'target', 'production', 'components', 'runtime_policy_hash', 'expires_at')
    values = {key: getattr(original, key) for key in fields}
    values.update(repository=str(Path(original.repository).resolve()), operation='deployment-recover', execution_policy_hash='a' * 64, request_id='1' * 64,
                  operation_id='2' * 64, journal_hash='3' * 64, partial_hash='4' * 64, fence_hash='5' * 64,
                  actions_json='[]', store_policy_hash='6' * 64, gate_policy_hash='7' * 64)
    return host.recovery.RecoveryRequest(**dict(values, **changes))


def policy(**changes):
    values = dict(vars(deployment.deployment_policy()), execution_policy_hash='a' * 64,
                  store_policy_hash='6' * 64, gate_policy_hash='7' * 64)
    return host.RecoveryHostPolicy(**dict(values, **changes))


class RecoveryHostTests(unittest.TestCase):
    def setUp(self):
        self.req, self.policy = request(), policy()
        self.claims = claims(self.policy)
        self.claims['aud'] = host.AUDIENCE
        self.client = deployment.DeploymentHostTests.client_for(self, [self.req])

    def make(self, req=None, client=None):
        return host.GitHubRecoveryApproval(client or self.client, 'opaque-signed-token',
            [req or self.req], self.policy, verifier=lambda token: deepcopy(self.claims))

    def test_host_flow_exact_types_guard_and_cas_namespace(self):
        approval = self.make()
        grant = approval.validate(self.req)
        self.assertIs(type(grant), host.recovery.RecoveryGrant)
        self.assertEqual(grant.grant_id, 'github-recovery:123:deployment-recover')
        with self.assertRaises(AuthorizationUnavailable):
            approval.guard(self.req)
        called = []
        receipt = approval.consume(grant, self.req, before_consume=lambda: called.append('checked'))
        self.assertEqual(called, ['checked'])
        self.assertIs(type(receipt), host.recovery.RecoveryReceipt)
        self.assertEqual(receipt.request_hash, self.req.digest())
        self.assertTrue(next(iter(self.client.markers)).startswith('tags/workflow-recovery-grants/123/'))
        approval.guard(self.req)
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(grant, self.req)

    def test_audience_and_normal_request_cross_domain_refused(self):
        self.claims['aud'] = deployment.host.AUDIENCE
        with self.assertRaises(AuthorizationUnavailable):
            self.make()
        self.claims['aud'] = host.AUDIENCE
        with self.assertRaises(AuthorizationUnavailable):
            self.make(req=deployment.request())
        with self.assertRaises(AuthorizationUnavailable):
            host.GitHubRecoveryApproval(self.client, 'token', [self.req], deployment.deployment_policy())

    def test_all_host_scope_hashes_components_and_identity_checked(self):
        cases = dict(repository_slug='other/repo', repository_id=99, environment='other', target='other',
                     production=True, components=('unknown',), runtime_policy_hash='0' * 64,
                     execution_policy_hash='0' * 64, store_policy_hash='0' * 64, gate_policy_hash='0' * 64)
        for name, value in cases.items():
            with self.subTest(field=name), self.assertRaises(AuthorizationUnavailable):
                self.make(req=replace(self.req, **{name: value}))

    def test_wrong_grant_type_and_before_consume_failure_do_not_create_marker(self):
        approval = self.make()
        normal = deployment.execution.Grant('normal', self.req.digest(), self.req.expires_at, 1)
        with self.assertRaises(AuthorizationUnavailable):
            approval.consume(normal, self.req)
        self.assertEqual(self.client.markers, {})
        approval = self.make()
        def fail():
            raise ValueError('fresh state changed')
        with self.assertRaises((ValueError, AuthorizationUnavailable)):
            approval.consume(approval.validate(self.req), self.req, before_consume=fail)
        self.assertEqual(self.client.markers, {})

    def test_reviewed_binding_changes_refused_after_approval(self):
        approval = self.make()
        changed = replace(self.req, fence_hash='9' * 64)
        with self.assertRaises(AuthorizationUnavailable):
            approval.validate(changed)
        with self.assertRaises(host.recovery.RecoveryError):
            request(max_uses=True)
        with self.assertRaises(host.recovery.RecoveryError):
            request(operation='deployment-deploy')


if __name__ == '__main__':
    unittest.main()
