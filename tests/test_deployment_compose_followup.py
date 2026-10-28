"""Pure followup proposals cannot authorize writes or accept altered protocols."""
from dataclasses import asdict, replace
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_operations import fixtures, HASH, OBSERVATION
from deployment_compose_operations import compile_operations, DOMAIN
from deployment_compose_followup import compile_followup, DOMAIN as FOLLOWUP_DOMAIN


def rehash(plan):
    envelope = {'schemaVersion': plan.schema_version, 'operationNonce': plan.operation_nonce,
                'baselineObservationHash': plan.baseline_observation_hash,
                'baselineDigest': plan.baseline_digest, 'targetDigest': plan.target_digest,
                'selectedServices': plan.selected_services, 'protectedServices': plan.protected_services,
                'unverifiedConstraints': plan.unverified_constraints, 'dependencies': plan.dependencies,
                'operations': [asdict(op) for op in plan.operations]}
    digest = hashlib.sha256(DOMAIN + json.dumps(envelope, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()
    return replace(plan, plan_hash=digest)


class FollowupTests(unittest.TestCase):
    def setUp(self):
        candidate, baseline, old, target, deps = fixtures()
        self.args = dict(candidate=candidate, baseline=baseline, old_artifacts=old,
            target_artifacts=target, operation_nonce=HASH, dependencies=deps,
            baseline_observation_hash=OBSERVATION,
            candidate_ids={'api': '7' * 64, 'web': '8' * 64},
            forbidden_container_ids=('9' * 64,), stop_timeout=10)
        self.plan = compile_operations(candidate, baseline, old, target, HASH, deps, OBSERVATION)

    def compile(self, plan=None, **changes):
        return compile_followup(self.plan if plan is None else plan, **(self.args | changes))

    def test_deterministic_without_mutating_inputs(self):
        before = copy.deepcopy(self.args)
        self.assertEqual(self.compile(), self.compile())
        self.assertEqual(self.args, before)
        result = self.compile()
        digest = result.pop('proposalDigest')
        self.assertEqual(digest, hashlib.sha256(FOLLOWUP_DOMAIN + json.dumps(result,
            sort_keys=True, separators=(',', ':'), ensure_ascii=True,
            allow_nan=False).encode('ascii')).hexdigest())

    def test_dependency_order_and_readiness_barriers(self):
        candidate = copy.deepcopy(self.args['candidate'])
        candidate['startOrder'] = ['web', 'api']
        candidate['stopOrder'] = ['api', 'web']
        deps = {'api': ('web',), 'web': ()}
        plan = compile_operations(candidate, self.args['baseline'], self.args['old_artifacts'],
            self.args['target_artifacts'], HASH, deps, OBSERVATION)
        result = self.compile(plan, candidate=candidate, dependencies=deps)
        steps = result['steps']
        expected = [('stop-old', 'api'), ('stop-old', 'web'),
                    ('remove-old', 'api'), ('remove-old', 'web'),
                    ('rename-candidate', 'web'), ('rename-candidate', 'api'),
                    ('start-candidate', 'web'), ('check-readiness', 'web'),
                    ('start-candidate', 'api'), ('check-readiness', 'api')]
        self.assertEqual([(step['phase'], step['service']) for step in steps], expected)
        for index, step in enumerate(steps):
            self.assertEqual(step['index'], index + len(plan.selected_services))
            self.assertEqual(step['predecessorIndex'], step['index'] - 1)
            self.assertEqual(step['expectedStatuses'],
                             [200] if step['phase'] == 'check-readiness' else [204])
            if step['phase'] == 'check-readiness':
                self.assertEqual(step['kind'], 'readiness-barrier')
                self.assertEqual(step['requiredChecks'],
                    ['running', 'healthy', 'dns', 'business', 'protected-scope-unchanged'])
            self.assertRegex(step['bodySha256'], r'^[0-9a-f]{64}$')
            self.assertEqual(step['method'], 'GET' if step['phase'] == 'check-readiness'
                             else 'DELETE' if step['phase'] == 'remove-old' else 'POST')
            expected_id = ({item.service: item.container_id for item in self.args['baseline']}
                           if step['phase'] in ('stop-old', 'remove-old')
                           else self.args['candidate_ids'])[step['service']]
            self.assertEqual(step['targetId'], expected_id)
            self.assertTrue(step['path'].startswith('/v1.45/containers/' + expected_id +
                            ('?' if step['phase'] == 'remove-old' else '/')))
        self.assertEqual(result['createActionIndexes'], [0, 1])
        self.assertEqual(result['candidateIdVerification'], 'host-asserted-unverified')
        for flag in ('authorityGranted', 'executionAvailable', 'productionReady',
                     'nextGenerationAuthorized', 'sequencingEnforced', 'replaySafe', 'quiescenceProven'):
            self.assertIs(result[flag], False)
        self.assertRegex(result['proposalDigest'], r'^[0-9a-f]{64}$')

    def test_tampered_protocol_rejected_even_after_rehash(self):
        for index, fields in ((2, {'container_ref': '9' * 64}),
                              (4, {'force': True}), (4, {'remove_volumes': True}),
                              (6, {'name': 'unrelated'}),
                              (8, {'container_ref': 'candidate:web'})):
            with self.subTest(index=index, fields=fields):
                ops = list(self.plan.operations)
                ops[index] = replace(ops[index], **fields)
                with self.assertRaises(ValueError):
                    self.compile(rehash(replace(self.plan, operations=tuple(ops))))
        with self.assertRaises(ValueError):
            self.compile(rehash(replace(self.plan, dependencies=(('api', ()), ('web', ())))))

    def test_false_flags_require_bool_type(self):
        for field in ('authority_granted', 'execution_available', 'production_ready'):
            for value in (0, True, None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.compile(replace(self.plan, **{field: value}))
        ops = list(self.plan.operations)
        ops[4] = replace(ops[4], force=0)
        with self.assertRaises(ValueError):
            self.compile(rehash(replace(self.plan, operations=tuple(ops))))

    def test_candidate_ids_exact_scope_and_disjoint_identities(self):
        for ids in ({'api': '1' * 64, 'web': '8' * 64},
                    {'api': '9' * 64, 'web': '8' * 64},
                    {'api': '7' * 64, 'web': '7' * 64},
                    {'api': '7' * 64},
                    {'api': '7' * 64, 'web': '8' * 64, 'db': '6' * 64},
                    {'api': 'short', 'web': '8' * 64}, (), None):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                self.compile(candidate_ids=ids)

    def test_forbidden_ids_are_exact_unique_tuple(self):
        for ids in (['9' * 64], ('9' * 64, '9' * 64), ('bad',), ('1' * 64,), None):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                self.compile(forbidden_container_ids=ids)

    def test_stop_timeout_bounds_and_types(self):
        for timeout in (0, 61, True, False, 1.0, '10', None):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.compile(stop_timeout=timeout)
        self.compile(stop_timeout=1)
        self.compile(stop_timeout=60)

    def test_protected_scope_limit_and_unverified_constraints_fail_before_compile(self):
        candidate = copy.deepcopy(self.args['candidate'])
        candidate['protectedServices'] = [f'db{i:03d}' for i in range(128)]
        plan = compile_operations(candidate, self.args['baseline'], self.args['old_artifacts'],
            self.args['target_artifacts'], HASH, self.args['dependencies'], OBSERVATION)
        result = self.compile(plan, candidate=candidate)
        self.assertEqual(result['protectedServices'], candidate['protectedServices'])
        oversized = copy.deepcopy(candidate)
        oversized['protectedServices'].append('db128')
        unverified = copy.deepcopy(self.args['candidate'])
        unverified['unverifiedConstraints'] = ['bind-create-host-path']
        for invalid in (oversized, unverified):
            with self.subTest(candidate=invalid), patch(
                    'deployment_compose_followup.compile_operations') as compile_mock:
                with self.assertRaises(ValueError):
                    self.compile(candidate=invalid)
                compile_mock.assert_not_called()

    def test_tuple_list_protocol_distinction_rejected(self):
        with self.assertRaises(ValueError):
            self.compile(replace(self.plan, selected_services=list(self.plan.selected_services)))

    def test_changed_candidate_and_timeout_change_proposal(self):
        original = self.compile()
        self.assertNotEqual(original['proposalDigest'], self.compile(stop_timeout=11)['proposalDigest'])
        self.assertNotEqual(original['proposalDigest'],
            self.compile(candidate_ids={'api': '6' * 64, 'web': '8' * 64})['proposalDigest'])


if __name__ == '__main__':
    unittest.main()
