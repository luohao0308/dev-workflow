"""Symbolic Compose operation protocol; no Docker writes or authority."""
import sys
from pathlib import Path
import unittest
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))

from deployment_compose_artifacts import ComposeArtifacts, ServiceArtifact
from deployment_compose_target_artifacts import ComposeTargetArtifacts, ServiceTargetArtifact
from deployment_compose_operations import BaselineContainer, CANDIDATE_DOMAIN
from deployment_compose_operations import compile_operations as _compile_operations
from deployment_compose_batch import assess as assess_batch
from tests.test_deployment_compose_batch import fixture as compose_fixture


SHA = 'a' * 40
HASH = 'b' * 64
OBSERVATION = 'a' * 64
IMAGE = 'sha256:' + 'c' * 64
REGISTRY = 'example.com/app@sha256:' + 'd' * 64


def compile_operations(candidate, baseline, old, target, nonce, deps, observation=OBSERVATION):
    return _compile_operations(candidate, baseline, old, target, nonce, deps, observation)


def fixtures():
    names = ('api', 'web')
    old = ComposeArtifacts(1, tuple(ServiceArtifact(n, SHA, REGISTRY, IMAGE, 'linux',
                          'amd64', 'key', 'e' * 64, 'f' * 64, 'none') for n in names))
    target = ComposeTargetArtifacts(1, tuple(ServiceTargetArtifact(n, '1' * 40,
                          REGISTRY, IMAGE, 'linux', 'amd64', 'key', '2' * 64,
                          'f' * 64, 'none') for n in names))
    baseline = tuple(BaselineContainer(n, str(i) * 64, n + '-1', IMAGE)
                     for i, n in enumerate(names, start=1))
    candidate = {'schemaVersion': 1, 'kind': 'compose-batch-offline-plan',
                 'structuralStatus': 'candidate-unverified', 'reasons': [],
                 'selectedServices': list(names), 'protectedServices': ['db'],
                 'unverifiedConstraints': [],
                 'startOrder': list(names), 'stopOrder': list(reversed(names)),
                 'authorityGranted': False, 'executionAvailable': False,
                 'productionReady': False}
    deps = {'api': (), 'web': ('api',)}
    return candidate, baseline, old, target, deps


class OperationTests(unittest.TestCase):
    def test_real_c1_six_service_candidate_connects_to_two_service_protocol(self):
        model, policy = compose_fixture()
        candidate = assess_batch(model, policy)
        names = ('backend', 'frontend')
        old = ComposeArtifacts(1, tuple(ServiceArtifact(n, SHA, REGISTRY, IMAGE,
            'linux', 'amd64', 'key', 'e' * 64, 'f' * 64, 'none') for n in names))
        target = ComposeTargetArtifacts(1, tuple(ServiceTargetArtifact(n, '1' * 40,
            REGISTRY, IMAGE, 'linux', 'amd64', 'key', '2' * 64, 'f' * 64, 'none')
            for n in names))
        baseline = tuple(BaselineContainer(n, str(i) * 64, 'sample-' + n + '-1', IMAGE)
                         for i, n in enumerate(names, start=1))
        plan = compile_operations(candidate, baseline, old, target, HASH,
                                  {'backend': (), 'frontend': ('backend',)})
        self.assertEqual(plan.selected_services, names)
        self.assertEqual(plan.protected_services, ('caddy', 'db', 'es', 'redis'))
        self.assertEqual([op.service for op in plan.operations if op.phase == 'stop-old'],
                         ['frontend', 'backend'])

    def test_two_service_order_and_bounded_flags(self):
        candidate, baseline, old, target, deps = fixtures()
        plan = compile_operations(candidate, baseline, old, target, HASH, deps)
        self.assertEqual([(x.phase, x.service) for x in plan.operations], [
            ('precreate-stopped', 'api'), ('precreate-stopped', 'web'),
            ('stop-old', 'web'), ('stop-old', 'api'),
            ('remove-old', 'web'), ('remove-old', 'api'),
            ('rename-candidate', 'api'), ('rename-candidate', 'web'),
            ('start-candidate', 'api'), ('check-readiness', 'api'),
            ('start-candidate', 'web'), ('check-readiness', 'web')])
        self.assertTrue(all(x.force is False and x.remove_volumes is False
                            for x in plan.operations if x.phase == 'remove-old'))
        self.assertEqual(plan.operations[0].container_ref, 'candidate:api')
        self.assertEqual(plan.operations[0].recipe_hmac, '2' * 64)
        self.assertEqual(plan.operations[0].image_id, IMAGE)
        self.assertFalse(plan.execution_available or plan.authority_granted or plan.production_ready)
        self.assertEqual(plan.structural_status, 'candidate-unverified')
        self.assertEqual(plan.network_alias_safety, 'unverified-engine-test-required')
        self.assertEqual(plan.plan_hash, compile_operations(candidate, baseline, old, target, HASH, deps).plan_hash)

    def test_operation_nonce_changes_candidate_names_and_plan(self):
        candidate, baseline, old, target, deps = fixtures()
        one = compile_operations(candidate, baseline, old, target, HASH, deps)
        two = compile_operations(candidate, baseline, old, target, 'a' * 64, deps)
        self.assertNotEqual(one.operations[0].name, two.operations[0].name)
        self.assertNotEqual(one.plan_hash, two.plan_hash)
        expected = 'dwc-' + hashlib.sha256(CANDIDATE_DOMAIN + HASH.encode('ascii') + b'\0api').hexdigest()
        self.assertEqual(one.operations[0].name, expected)
        self.assertEqual(one.operation_nonce, HASH)

    def test_dependency_edges_and_observation_bound_even_with_same_order(self):
        candidate, baseline, old, target, deps = fixtures()
        original = compile_operations(candidate, baseline, old, target, HASH, deps)
        no_edge = compile_operations(candidate, baseline, old, target, HASH,
                                     {'api': (), 'web': ()})
        self.assertEqual(original.operations, no_edge.operations)
        self.assertNotEqual(original.dependencies, no_edge.dependencies)
        self.assertNotEqual(original.plan_hash, no_edge.plan_hash)
        new_observation = compile_operations(candidate, baseline, old, target, HASH,
                                             deps, '9' * 64)
        self.assertEqual(original.operations, new_observation.operations)
        self.assertNotEqual(original.plan_hash, new_observation.plan_hash)
        self.assertEqual(original.baseline_observation_hash, OBSERVATION)
        with self.assertRaisesRegex(ValueError, 'observation hash'):
            compile_operations(candidate, baseline, old, target, HASH, deps, 'invalid')

    def test_baseline_image_id_matches_artifact(self):
        candidate, baseline, old, target, deps = fixtures()
        changed = (BaselineContainer('api', '1' * 64, 'api-1', 'sha256:' + '9' * 64), baseline[1])
        with self.assertRaisesRegex(ValueError, 'image differs'):
            compile_operations(candidate, changed, old, target, HASH, deps)

    def test_unverified_constraints_bound_to_hash(self):
        candidate, baseline, old, target, deps = fixtures()
        original = compile_operations(candidate, baseline, old, target, HASH, deps)
        candidate['unverifiedConstraints'] = ['bind-create-host-path']
        changed = compile_operations(candidate, baseline, old, target, HASH, deps)
        self.assertEqual(changed.unverified_constraints, ('bind-create-host-path',))
        self.assertNotEqual(changed.plan_hash, original.plan_hash)
        candidate['unverifiedConstraints'] = ['bind-create-host-path', 'bind-create-host-path']
        with self.assertRaisesRegex(ValueError, 'constraint'):
            compile_operations(candidate, baseline, old, target, HASH, deps)

    def test_mixed_baseline_source_blocked(self):
        candidate, baseline, old, target, deps = fixtures()
        mixed = ComposeArtifacts(1, (old.services[0], ServiceArtifact(
            'web', '3' * 40, REGISTRY, IMAGE, 'linux', 'amd64', 'key',
            'e' * 64, 'f' * 64, 'none')))
        with self.assertRaisesRegex(ValueError, 'recoverable'):
            compile_operations(candidate, baseline, mixed, target, HASH, deps)

    def test_scope_must_match_baseline_and_artifacts(self):
        candidate, baseline, old, target, deps = fixtures()
        for broken in (baseline[:1], baseline + (BaselineContainer('extra', '3' * 64, 'extra-1', IMAGE),),
                       (baseline[0], baseline[0])):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                compile_operations(candidate, broken, old, target, HASH, deps)
        candidate['selectedServices'] = ['api']
        with self.assertRaises(ValueError):
            compile_operations(candidate, baseline, old, target, HASH, deps)

    def test_duplicate_names_and_bad_order_blocked(self):
        candidate, baseline, old, target, deps = fixtures()
        duplicate = (baseline[0], BaselineContainer('web', '2' * 64, baseline[0].final_name, IMAGE))
        with self.assertRaisesRegex(ValueError, 'Baseline identity'):
            compile_operations(candidate, duplicate, old, target, HASH, deps)
        candidate['startOrder'] = ['web', 'api']
        with self.assertRaisesRegex(ValueError, 'order'):
            compile_operations(candidate, baseline, old, target, HASH, deps)

    def test_nondeterministic_dependencies_and_cycle_blocked(self):
        candidate, baseline, old, target, deps = fixtures()
        for broken in ({'api': (), 'web': ('api', 'api')},
                       {'api': ('web',), 'web': ('api',)}):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                compile_operations(candidate, baseline, old, target, HASH, broken)

    def test_candidate_cannot_claim_authority(self):
        candidate, baseline, old, target, deps = fixtures()
        candidate['authorityGranted'] = True
        with self.assertRaisesRegex(ValueError, 'non-executable'):
            compile_operations(candidate, baseline, old, target, HASH, deps)


if __name__ == '__main__':
    unittest.main()
