"""Symbolic phase coverage remains data-only and is exactly rederived."""
from copy import deepcopy
import hashlib
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_prepare_v2_host import setup, two_service_setup
from tests.test_deployment_compose_approval_host import deadline
from deployment_compose_prepare_v2_host import (
    ComposePreparationHostV2, DOMAIN, SYMBOLIC_PLAN_DOMAIN, encode)


class SymbolicPlanTests(unittest.TestCase):
    def prepare(self, factory=setup):
        inputs, _, live = factory()
        host = ComposePreparationHostV2(**inputs)
        observation = inputs['observer'].issue()
        expires = deadline()
        result = host.prepare_with_symbolic_plan(observation, operation_nonce='9' * 64, expires_at=expires)
        return host, observation, expires, result, live

    def verify(self, host, observation, expires, result):
        return host.verify_with_symbolic_plan(result, observation, operation_nonce='9' * 64, expires_at=expires)

    def test_single_service_complete_phases_without_authority(self):
        host, obs, expiry, result, _ = self.prepare()
        review = result['review']
        plan = review['symbolicPlan']
        self.assertEqual([x['phase'] for x in plan['steps']],
            ['create', 'stop-old', 'remove-old', 'rename-candidate', 'start-candidate', 'readiness'])
        self.assertEqual(review['symbolicPlanHash'], hashlib.sha256(SYMBOLIC_PLAN_DOMAIN + encode(plan)).hexdigest())
        self.assertTrue(review['symbolicPhaseCoverageComplete'])
        for field in ('authorityGranted', 'executionAvailable', 'scopeIsApprovalRequest',
                      'completeOperationPlan', 'nextGenerationAuthorized', 'sequencingEnforced', 'productionReady'):
            self.assertIs(review[field], False)
        self.assertEqual(review['scope']['plan_hash'], '0' * 64)
        self.assertEqual(plan['protectedIdentities']['containerNames'], {'db': 'blog-db-1'})
        self.assertEqual(plan['protectedIdentities']['observationHash'], review['scope']['observation_hash'])
        self.assertIn('receipt-bound-generation-required', review['blockers'])
        self.assertIsNone(self.verify(host, obs, expiry, result))

    def test_two_services_topological_start_and_reverse_teardown(self):
        host, obs, expiry, result, _ = self.prepare(two_service_setup)
        steps = result['review']['symbolicPlan']['steps']
        self.assertEqual([x['service'] for x in steps], ['web', 'api', 'api', 'web',
            'api', 'web', 'web', 'api', 'web', 'web', 'api', 'api'])
        self.assertEqual([(x['phase'],x['service']) for x in steps[-4:]],
            [('start-candidate','web'),('readiness','web'),('start-candidate','api'),('readiness','api')])
        for index, step in enumerate(steps):
            self.assertEqual(step['globalIndex'], index)
            self.assertEqual(step['predecessorIndex'], index - 1 if index else None)
            if step['phase'] in ('stop-old', 'remove-old'):
                self.assertEqual(step['oldContainerId'], ('1' if step['service'] == 'web' else '3') * 64)
            if step['phase'] == 'remove-old':
                self.assertIs(step['force'],False)
                self.assertIs(step['removeVolumes'],False)
            if 'candidateReference' in step:
                entry = next(x for x in result['review']['createEntries'] if x['service'] == step['service'])
                ref = step['candidateReference']
                for key in ('createIndex', 'candidateDigest', 'derivationDigest', 'canonicalBodySha256'):
                    self.assertEqual(ref[key], entry[key])
                self.assertNotIn('method', step)
                self.assertNotIn('path', step)
        self.assertIsNone(self.verify(host, obs, expiry, result))

    def test_rehashed_tampering_and_type_changes_rejected(self):
        host, obs, expiry, result, _ = self.prepare()
        mutations = [lambda p: p['steps'][0].update(globalIndex=False),
            lambda p: p['steps'][1].update(oldContainerId='f' * 64),
            lambda p: p['steps'][3]['candidateReference'].update(derivationDigest='f' * 64),
            lambda p: p['dependencies'].update(web=['db']),
            lambda p: p['protectedIdentities']['containerNames'].update(db='other'),
            lambda p: p['steps'].reverse()]
        for mutate in mutations:
            changed = deepcopy(result)
            review = changed['review']
            mutate(review['symbolicPlan'])
            review['symbolicPlanHash'] = hashlib.sha256(SYMBOLIC_PLAN_DOMAIN + encode(review['symbolicPlan'])).hexdigest()
            review.pop('preparationDigest')
            review['preparationDigest'] = hashlib.sha256(DOMAIN + encode(review)).hexdigest()
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.verify(host, obs, expiry, changed)

    def test_stale_observation_expiry_and_live_drift_rejected(self):
        host, obs, expiry, result, live = self.prepare()
        with self.assertRaises(ValueError):
            host.prepare_with_symbolic_plan(obs, operation_nonce='9' * 64, expires_at='2020-01-01T00:00:00Z')
        live['serviceContainerIds']['web'] = 'f' * 64
        with self.assertRaises(ValueError):
            self.verify(host, obs, expiry, result)
        host, obs, expiry, result, _ = self.prepare()
        with patch('deployment_compose_observation_host.time.monotonic', return_value=obs._expires + 1):
            with self.assertRaises(ValueError):
                self.verify(host, obs, expiry, result)

    def test_final_reprepare_detects_drift(self):
        host, obs, expiry, _, live = self.prepare()
        original = host.prepare
        calls = []
        def drift(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                live['serviceContainerIds']['web'] = 'f' * 64
            return original(*args, **kwargs)
        with patch.object(host, 'prepare', side_effect=drift):
            with self.assertRaises(ValueError):
                host.prepare_with_symbolic_plan(obs, operation_nonce='9' * 64, expires_at=expiry)
        self.assertEqual(len(calls), 2)

    def test_public_plan_excludes_private_environment(self):
        host, obs, expiry, result, _ = self.prepare()
        raw = encode(result['review'])
        for value in result['derivations']['web']['candidate']['body']['Env']:
            self.assertNotIn(value.encode(), raw)
        self.assertNotIn(b'API_KEY', raw)
        self.assertNotIn(b'"body":', raw)
        changed = deepcopy(result)
        changed['derivations']['web']['candidate']['body']['Env'].append('EXTRA=secret')
        with self.assertRaises(ValueError):
            self.verify(host, obs, expiry, changed)


if __name__ == '__main__':
    unittest.main()
