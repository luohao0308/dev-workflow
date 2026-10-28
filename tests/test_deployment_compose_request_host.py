"""Host recomputation binds exact intent; no Docker mutations or permits."""
from dataclasses import replace
import unittest

from tests.test_deployment_compose_observation_host import host
from tests.test_deployment_compose_approval_host import policy, deadline
from tests.test_deployment_compose_target_prepare import fixture, KEY
from deployment_compose_operations import BaselineContainer
from deployment_compose_request_host import ComposeRequestHost
from deployment_compose_proof_host import ComposeProofHost


def setup():
    observer, reader, result = host()
    scope = observer._policy
    scope.update(project='blog', daemonId='daemon-1',
                 containerNames={'web': 'blog-web-1'}, selectedContainerIds={'web': '1' * 64})
    result['serviceContainerIds'] = {'web': '1' * 64, 'db': '2' * 64}
    _, target, recipes = fixture()
    p = policy(components=('web',), protected_components=('db',), source_sha='a' * 40)
    candidate = dict(schemaVersion=1, kind='compose-batch-offline-plan',
        structuralStatus='candidate-unverified', reasons=[], selectedServices=['web'],
        protectedServices=['db'], unverifiedConstraints=[], startOrder=['web'],
        stopOrder=['web'], authorityGranted=False, executionAvailable=False, productionReady=False)
    baseline = (BaselineContainer('web', '1' * 64, 'blog-web-1',
                                  observer._baseline_artifacts.services[0].image_id),)
    inputs = dict(policy=p, observer=observer, candidate=candidate, baseline=baseline,
                  target=target, recipes=recipes, recipe_keys={'host-key-1': KEY},
                  dependencies={'web': ()}, proof_host=ComposeProofHost(
                      keys={k: (k, k.encode() * 32) for k in ('provenance', 'migration', 'backup')},
                      schema_digest='4' * 64, backup_digest='5' * 64, restore_test_digest='6' * 64))
    return inputs, reader, result


class RequestHostTests(unittest.TestCase):
    def test_recompute_and_exact_match(self):
        inputs, _, _ = setup()
        issuer = ComposeRequestHost(**inputs)
        observation = inputs['observer'].issue()
        request = issuer.prepare_intent(observation, operation_nonce='9' * 64, expires_at=deadline())
        self.assertIsNone(issuer.verify_intent(request, observation, operation_nonce='9' * 64))
        self.assertEqual(request.before_hash, inputs['observer']._baseline_artifacts.digest())
        self.assertEqual(request.after_hash, inputs['target'].digest())
        self.assertEqual(request.artifact_digest, inputs['target'].digest())
        self.assertFalse(hasattr(issuer, 'guard'))
        self.assertIsNone(request.history_hash)
        for field in ('before_hash', 'after_hash', 'artifact_digest', 'observation_hash',
                      'plan_hash', 'policy_hash'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                issuer.verify_intent(replace(request, **{field: '0' * 64}), observation,
                              operation_nonce='9' * 64)
        for changed in (replace(request, production=True),
                        replace(request, protected_components=()),
                        replace(request, operation='rollback', history_hash='7' * 64),
                        replace(request, source=replace(request.source, project_id=99))):
            with self.assertRaises(ValueError):
                issuer.verify_intent(changed, observation, operation_nonce='9' * 64)
        with self.assertRaises(ValueError):
            issuer.verify_intent(request, observation, operation_nonce='8' * 64)

    def test_imported_cross_issuer_and_drift_rejected(self):
        inputs, reader, result = setup()
        issuer = ComposeRequestHost(**inputs)
        observation = inputs['observer'].issue()
        other, _, _ = setup()
        for bad in ({}, other['observer'].issue()):
            with self.assertRaises(ValueError):
                issuer.prepare_intent(bad, operation_nonce='9' * 64, expires_at=deadline())
        result['serviceContainerIds']['web'] = '3' * 64
        with self.assertRaises(ValueError):
            issuer.prepare_intent(observation, operation_nonce='9' * 64, expires_at=deadline())

    def test_host_captures_recipe_and_candidate_and_rejects_unknown_constraints(self):
        inputs, _, _ = setup()
        issuer = ComposeRequestHost(**inputs)
        observation = inputs['observer'].issue()
        inputs['recipes']['web']['process']['env'] = ['SECRET=changed']
        inputs['candidate']['unverifiedConstraints'] = ['existing-volume-nocopy']
        issuer.prepare_intent(observation, operation_nonce='9' * 64, expires_at=deadline())
        with self.assertRaises(ValueError):
            ComposeRequestHost(**inputs).prepare_intent(observation, operation_nonce='9' * 64,
                                                expires_at=deadline())

    def test_missing_identity_wrong_scope_and_rollback_rejected(self):
        inputs, _, _ = setup()
        for changes in (dict(policy=replace(inputs['policy'], operation='rollback')),
                        dict(policy=replace(inputs['policy'], daemon_id='other')),
                        dict(baseline=(replace(inputs['baseline'][0], container_id='3' * 64),))):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                ComposeRequestHost(**dict(inputs, **changes))
        inputs['observer']._policy.pop('selectedContainerIds')
        with self.assertRaises(ValueError):
            ComposeRequestHost(**inputs)

    def test_final_preparation_requires_retained_archive(self):
        inputs, _, _ = setup()
        issuer = ComposeRequestHost(**inputs)
        observation = inputs['observer'].issue()
        with self.assertRaisesRegex(ValueError, '^retained-recovery-archive-required$'):
            issuer.prepare(observation, operation_nonce='9' * 64,
                           expires_at=deadline(), proofs={})

    def test_expiry_and_recipe_tampering_rejected(self):
        inputs, _, _ = setup()
        observation = inputs['observer'].issue()
        with self.assertRaises(ValueError):
            ComposeRequestHost(**inputs).prepare_intent(observation, operation_nonce='9' * 64,
                                                expires_at='2020-01-01T00:00:00Z')
        inputs['recipes']['web']['process']['env'] = ['SECRET=changed']
        with self.assertRaises(ValueError):
            ComposeRequestHost(**inputs).prepare_intent(observation, operation_nonce='9' * 64,
                                                expires_at=deadline())


    def test_retention_source_view_cannot_prepare_authorization(self):
        import sys
        from pathlib import Path
        sys.path.insert(0,str(Path(__file__).parent/'support'))
        from compose_observation_scope_fixture import source_view
        inputs,reader,live=setup()
        inputs['observer']=source_view(inputs['observer'],reader,live)
        with self.assertRaisesRegex(ValueError,'deploy-host-policy-required'):
            ComposeRequestHost(**inputs)


if __name__ == '__main__':
    unittest.main()
