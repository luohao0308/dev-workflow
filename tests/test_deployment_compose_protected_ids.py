"""Host-selected protected IDs reject replacement with otherwise equal metadata."""
from copy import deepcopy
import unittest

from tests.test_deployment_compose_prepare_v2_host import setup
from tests.test_deployment_compose_approval_host import deadline
from tests.test_deployment_compose_observation_host import Reader, artifacts
from deployment_compose_observation_host import ComposeObservationHost, _TEST_SEAM
from deployment_compose_prepare_v2_host import ComposePreparationHostV2


class ProtectedIdTests(unittest.TestCase):
    def setup(self):
        inputs, reader, live = setup()
        inputs['observer']._policy['protectedContainerIds'] = {'db': '2' * 64}
        return inputs, reader, live

    def test_replaced_id_rejected_before_issue_and_during_recheck(self):
        inputs, _, live = self.setup()
        observer = inputs['observer']
        obs = observer.issue()
        self.assertIsNotNone(obs)
        self.assertTrue(observer.recheck(obs))
        live['serviceContainerIds']['db'] = '3' * 64
        self.assertIsNone(observer.issue())
        self.assertFalse(observer.recheck(obs))

    def test_complete_live_ids_required_only_when_pinned(self):
        for ids in ({'web': '1' * 64}, {'web': '1' * 64, 'db': True},
                    {'web': '2' * 64, 'db': '2' * 64},
                    {'web': '1' * 64, 'db': '2' * 64, 'extra': '3' * 64}):
            inputs, _, live = self.setup()
            live['serviceContainerIds'] = ids
            with self.subTest(ids=ids):
                self.assertIsNone(inputs['observer'].issue())

    def test_malformed_policy_rejected_by_test_seam_and_read(self):
        pins = [None, True, [], {}, {'db': True}, {'db': '2'},
                {'db': '2' * 64, 'extra': '3' * 64}, {'db': '1' * 64}]
        for pin in pins:
            inputs, _, live = setup()
            scope = inputs['observer']._policy
            scope['protectedContainerIds'] = pin
            with self.subTest(pin=pin):
                self.assertIsNone(inputs['observer'].issue())
                with self.assertRaises(ValueError):
                    ComposeObservationHost._test_host(Reader(), scope, lambda *a: deepcopy(live),
                        artifacts(), _token=_TEST_SEAM)
        inputs, _, _ = self.setup()
        scope = inputs['observer']._policy
        scope['protectedServices'].append('cache')
        scope['protectedContainerIds']['cache'] = '2' * 64
        self.assertIsNone(inputs['observer'].issue())
        with self.assertRaises(ValueError):
            ComposeObservationHost._test_host(Reader(), scope, lambda *a: {}, artifacts(), _token=_TEST_SEAM)

    def test_symbolic_hash_binds_pinned_ids_and_remains_non_authority(self):
        inputs, _, live = self.setup()
        host = ComposePreparationHostV2(**inputs)
        obs = inputs['observer'].issue()
        expiry = deadline()
        result = host.prepare_with_symbolic_plan(obs, operation_nonce='9' * 64, expires_at=expiry)
        review = result['review']
        self.assertEqual(review['symbolicPlan']['protectedIdentities']['containerIds'], {'db': '2' * 64})
        self.assertIs(review['symbolicPlan']['protectedContainerIdsVerified'], True)
        self.assertNotIn('protected-container-ids-required', review['blockers'])
        for field in ('completeOperationPlan', 'scopeIsApprovalRequest', 'authorityGranted', 'executionAvailable', 'productionReady'):
            self.assertIs(review[field], False)
        altered = deepcopy(result)
        altered['review']['symbolicPlan']['protectedIdentities']['containerIds']['db'] = '3' * 64
        with self.assertRaises(ValueError):
            host.verify_with_symbolic_plan(altered, obs, operation_nonce='9' * 64, expires_at=expiry)
        live['serviceContainerIds']['db'] = '3' * 64
        with self.assertRaises(ValueError):
            host.verify_with_symbolic_plan(result, obs, operation_nonce='9' * 64, expires_at=expiry)

    def test_malformed_selected_pins_fail_closed_when_protection_enabled(self):
        for selected in (True, None, [], {'web':True}, {'other':'3'*64}):
            inputs,_,_=self.setup()
            inputs['observer']._policy['selectedContainerIds']=selected
            self.assertIsNone(inputs['observer'].issue())

    def test_absent_policy_keeps_unverified_blocker(self):
        inputs, _, _ = setup()
        host = ComposePreparationHostV2(**inputs)
        result = host.prepare_with_symbolic_plan(inputs['observer'].issue(), operation_nonce='9' * 64, expires_at=deadline())
        self.assertIs(result['review']['symbolicPlan']['protectedContainerIdsVerified'], False)
        self.assertEqual(result['review']['symbolicPlan']['protectedIdentities']['containerIds'], {})
        self.assertIn('protected-container-ids-required', result['review']['blockers'])


if __name__ == '__main__':
    unittest.main()
