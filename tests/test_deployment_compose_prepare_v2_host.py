"""Host-bound v3 preparation is private, exact and cannot authorize writes."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import unittest

from tests.test_deployment_compose_request_host import setup as legacy_setup
from tests.test_deployment_compose_create import fixture
from tests.test_deployment_compose_target_prepare import KEY
from tests.test_deployment_compose_approval_host import deadline, policy
from deployment_compose_prepare_v2_host import ComposePreparationHostV2, DOMAIN, encode
from deployment_compose_recipe_v3 import commit_recipe_v3
from deployment_compose_target_v2 import ComposeTargetArtifactsV2, ServiceTargetArtifactV2, PROFILE, PROFILE_VERSION
from deployment_contract_v2 import RequestV2, SourceIdentity


def setup():
    legacy, reader, result = legacy_setup()
    recipe, creation = fixture()
    image = legacy['baseline'][0].image_id
    recipe['imageId'] = image
    creation['baseline_image_id'] = image
    creation['image_defaults']['ImageId'] = image
    creation['identity']['daemonId'] = 'daemon-1'
    item = ServiceTargetArtifactV2('web', 'a' * 40,
        'registry.example.test/team/web@sha256:' + 'a' * 64, image, 'linux', 'amd64',
        'host-key-1', commit_recipe_v3(recipe, 'host-key-1', KEY)['hmac'], '0' * 64, 'none', 3)
    inputs = dict(observer=legacy['observer'], baseline=legacy['baseline'],
        target=ComposeTargetArtifactsV2(2, PROFILE, PROFILE_VERSION, (item,)),
        recipes={'web': recipe}, recipe_keys={'host-key-1': KEY}, creation_inputs={'web': creation},
        dependencies={'web': ()}, source=SourceIdentity('github.com',
            'https://github.com/sample/target.git', 2, 'sample/target', 'a' * 40),
        target_identity=legacy['policy'].target, host_id='host-one', daemon_id='daemon-1',
        environment='staging', production=False, policy_hash='f' * 64,
        protected_names={'db': 'blog-db-1'})
    return inputs, reader, result


def two_service_setup(*, collision=False):
    from deployment_compose_artifacts import ComposeArtifacts
    inputs, reader, live = setup()
    observer = inputs['observer']
    artifacts = observer._baseline_artifacts
    api = replace(artifacts.services[0], service='api')
    observer._baseline_artifacts = ComposeArtifacts(1, (api, artifacts.services[0]))
    scope = observer._policy
    scope['selectedServices'] = ['api', 'web']
    scope['selectedContainerIds']['api'] = '3' * 64
    scope['containerNames']['api'] = 'blog-api-1'
    scope['imageIds']['api'] = api.image_id
    scope['baselineSourceShas']['api'] = api.source_sha
    live['serviceContainerIds']['api'] = '3' * 64
    live['serviceConfigHmacs']['api'] = live['serviceConfigHmacs']['web']
    live['serviceImages']['api'] = api.image_id
    live['serviceState']['api'] = deepcopy(live['serviceState']['web'])
    inputs['baseline'] = (replace(inputs['baseline'][0], service='api',
        container_id='3' * 64, final_name='blog-api-1'), inputs['baseline'][0])
    recipe = deepcopy(inputs['recipes']['web'])
    recipe.update(service='api', containerName='blog-api-1')
    recipe['networks'][0]['aliases'] = ['web' if collision else 'api']
    inputs['recipes']['api'] = recipe
    creation = deepcopy(inputs['creation_inputs']['web'])
    creation['identity'].update(service='api', containerName='blog-api-1')
    inputs['creation_inputs']['api'] = creation
    target = inputs['target']
    item = replace(target.services[0], service='api',
        recipe_hmac=commit_recipe_v3(recipe, 'host-key-1', KEY)['hmac'])
    inputs['target'] = replace(target, services=(item, target.services[0]))
    inputs['dependencies'] = {'api': ('web',), 'web': ()}
    return inputs, reader, live


class PreparationV2Tests(unittest.TestCase):
    def prepare(self, inputs=None):
        if inputs is None:
            inputs, _, _ = setup()
        host = ComposePreparationHostV2(**inputs)
        observation = inputs['observer'].issue()
        expires = deadline()
        result = host.prepare(observation, operation_nonce='9' * 64, expires_at=expires)
        return host, observation, expires, result

    def test_exact_public_scope_private_body_and_non_authority(self):
        inputs, _, _ = setup()
        host, observation, expires, result = self.prepare(inputs)
        review = result['review']
        entry = review['createEntries'][0]
        private = result['derivations']['web']
        self.assertEqual(review['profileVersion'], '2')
        self.assertEqual(review['recipeSchemaVersion'], 3)
        self.assertEqual(review['indexScope'], 'create-prefix-only')
        self.assertEqual((entry['createIndex'], entry['service']), (0, 'web'))
        self.assertEqual(entry['recipeHmac'], inputs['target'].services[0].recipe_hmac)
        self.assertEqual(entry['derivationDigest'], private['derivationDigest'])
        self.assertEqual(entry['candidateDigest'], private['candidate']['candidateDigest'])
        self.assertEqual(entry['canonicalBodySha256'], hashlib.sha256(encode(private['candidate']['body'])).hexdigest())
        self.assertEqual(review['scope']['plan_hash'], '0' * 64)
        self.assertEqual(review['scope']['artifact_digest'], inputs['target'].digest())
        self.assertEqual(review['scope']['protected_components'], ('db',))
        self.assertNotIn('API_KEY', json.dumps(review))
        self.assertEqual(private['candidate']['body']['Env'], inputs['recipes']['web']['process']['env'])
        for field in ('completeOperationPlan', 'scopeIsApprovalRequest', 'approvalConsumptionAvailable',
                      'authorityGranted', 'executionAvailable', 'productionReady', 'replaySafe',
                      'reconstructionValidated', 'quiescenceProven', 'nextGenerationAuthorized', 'sequencingEnforced'):
            self.assertIs(review[field], False)
        self.assertFalse(any(hasattr(host, x) for x in ('consume', 'guard', 'execute')))
        self.assertIsNone(host.verify(result, observation, operation_nonce='9' * 64, expires_at=expires))

    def test_private_inputs_are_captured_and_returned_values_are_detached(self):
        inputs, _, _ = setup()
        host, observation, expires, original = self.prepare(inputs)
        inputs['recipes']['web']['process']['env'] = ['API_KEY=changed']
        inputs['creation_inputs']['web']['hostname'] = 'changed'
        inputs['dependencies']['web'] = ('db',)
        inputs['protected_names']['db'] = 'changed'
        self.assertEqual(original, host.prepare(observation, operation_nonce='9' * 64, expires_at=expires))
        original['derivations']['web']['candidate']['body']['Env'].append('EXTRA=x')
        self.assertNotEqual(original, host.prepare(observation, operation_nonce='9' * 64, expires_at=expires))

    def test_recipe_hmac_key_service_and_image_mismatch_rejected(self):
        mutations = [lambda i: i['recipes']['web']['process'].update(env=['API_KEY=changed']),
            lambda i: i['recipe_keys'].update({'host-key-1': b'z' * 32}),
            lambda i: i['recipes']['web'].update(service='other'),
            lambda i: i['creation_inputs']['web']['image_defaults'].update(ImageId='sha256:' + 'f' * 64)]
        for mutate in mutations:
            inputs, _, _ = setup()
            mutate(inputs)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.prepare(inputs)

    def test_constructor_rejects_missing_extra_and_cross_host_scopes(self):
        mutations = [lambda i: i.update(recipes={}), lambda i: i['recipes'].update(extra=i['recipes']['web']),
            lambda i: i.update(creation_inputs={}), lambda i: i['creation_inputs']['web'].update(extra=True),
            lambda i: i.update(recipe_keys={}), lambda i: i['recipe_keys'].update(extra=KEY),
            lambda i: i.update(source=replace(i['source'], source_sha='b' * 40)),
            lambda i: i.update(target_identity=replace(i['target_identity'], namespace='other')),
            lambda i: i.update(host_id='other'), lambda i: i.update(daemon_id='other'),
            lambda i: i.update(protected_names={}), lambda i: i.update(protected_names={'db': 'blog-web-1'}),
            lambda i: i.update(baseline=(replace(i['baseline'][0], container_id='3' * 64),)),
            lambda i: i.update(dependencies={'web': ('web',)})]
        for mutate in mutations:
            inputs, _, _ = setup()
            mutate(inputs)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                ComposePreparationHostV2(**inputs)

    def test_imported_observation_and_live_drift_rejected(self):
        inputs, _, live = setup()
        host, observation, expires, _ = self.prepare(inputs)
        other, _, _ = setup()
        for imported in ({}, other['observer'].issue()):
            with self.assertRaises(ValueError):
                host.prepare(imported, operation_nonce='9' * 64, expires_at=expires)
        live['serviceContainerIds']['web'] = '3' * 64
        with self.assertRaises(ValueError):
            host.prepare(observation, operation_nonce='9' * 64, expires_at=expires)

    def test_policy_drift_nonce_and_expiry_rejected(self):
        for nonce, expiry in [('x', deadline()), ('9' * 64, '2020-01-01T00:00:00Z'),
                              ('9' * 64, deadline(61))]:
            host, observation, _, _ = self.prepare()
            with self.subTest(nonce=nonce, expiry=expiry), self.assertRaises(ValueError):
                host.prepare(observation, operation_nonce=nonce, expires_at=expiry)
        inputs, _, _ = setup()
        host, observation, expires, _ = self.prepare(inputs)
        inputs['observer']._policy['project'] = 'other'
        with self.assertRaises(ValueError):
            host.prepare(observation, operation_nonce='9' * 64, expires_at=expires)

    def test_tampered_and_rehashed_public_or_private_results_rejected(self):
        host, observation, expires, result = self.prepare()
        for private in (False, True):
            changed = deepcopy(result)
            if private:
                changed['derivations']['web']['candidate']['body']['Env'] = ['API_KEY=changed']
            else:
                changed['review']['createEntries'][0]['createIndex'] = 1
                review = changed['review']
                review.pop('preparationDigest')
                review['preparationDigest'] = hashlib.sha256(DOMAIN + encode(review)).hexdigest()
            with self.subTest(private=private), self.assertRaises(ValueError):
                host.verify(changed, observation, operation_nonce='9' * 64, expires_at=expires)
        with self.assertRaises(ValueError):
            host.verify(result, observation, operation_nonce='8' * 64, expires_at=expires)

    def test_baseline_artifact_drift_and_temporary_name_collision_rejected(self):
        inputs, _, _ = setup()
        host, observation, expires, result = self.prepare(inputs)
        collision = result['review']['createEntries'][0]['temporaryName']
        inputs['protected_names']['db'] = collision
        with self.assertRaises(ValueError):
            self.prepare(inputs)
        artifacts = inputs['observer']._baseline_artifacts
        object.__setattr__(artifacts.services[0], 'image_id', 'sha256:' + 'f' * 64)
        with self.assertRaises(ValueError):
            host.prepare(observation, operation_nonce='9' * 64, expires_at=expires)

    def test_manifest_and_recipe_versions_cannot_be_downgraded(self):
        inputs, _, _ = setup()
        target = inputs['target']
        for changes in ({'schema_version': 1}, {'profile_version': '1'},
                        {'profile_id': 'compose-application-batch-v1'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(target, **changes)
        for version in (2, True, '3'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                replace(target.services[0], recipe_schema_version=version)
        inputs['recipes']['web']['schemaVersion'] = 2
        with self.assertRaises(ValueError):
            self.prepare(inputs)

    def test_multiservice_create_indices_follow_dependencies_not_lexical_order(self):
        inputs, _, _ = two_service_setup()
        host, observation, expires, result = self.prepare(inputs)
        self.assertEqual([(entry['service'], entry['createIndex'])
                          for entry in result['review']['createEntries']], [('web', 0), ('api', 1)])
        self.assertEqual(result['review']['scope']['components'], ('api', 'web'))
        self.assertEqual(result['review']['dependencies'], {'api': ['web'], 'web': []})
        self.assertEqual(set(result['derivations']), {'api', 'web'})
        for entry in result['review']['createEntries']:
            candidate = result['derivations'][entry['service']]['candidate']
            self.assertEqual(entry['candidateDigest'], candidate['candidateDigest'])
            self.assertEqual(candidate['identity']['service'], entry['service'])
        self.assertIsNone(host.verify(result, observation, operation_nonce='9' * 64, expires_at=expires))

    def test_individually_signed_multiservice_alias_collision_rejected(self):
        inputs, _, _ = two_service_setup(collision=True)
        with self.assertRaises(ValueError):
            self.prepare(inputs)

    def test_legacy_policy_and_target_host_reject_profile2(self):
        from deployment_compose_request_host import ComposeRequestHost
        with self.assertRaises(ValueError):
            policy(profile_version='2')
        legacy, _, _ = legacy_setup()
        inputs, _, _ = setup()
        legacy['target'] = inputs['target']
        legacy_host = ComposeRequestHost(**legacy)
        with self.assertRaises(ValueError):
            legacy_host.prepare_intent(legacy['observer'].issue(), operation_nonce='9' * 64,
                                       expires_at=deadline())
        host, observation, expires, result = self.prepare(inputs)
        scope = result['review']['scope']
        typed = RequestV2.from_json(json.dumps(scope, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
        self.assertEqual(typed.profile_id, PROFILE)


if __name__ == '__main__':
    unittest.main()
