"""Retained private projections are authenticated data, not recovery approval."""
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_deployment_compose_request_host import setup as request_setup
from tests.test_deployment_compose_private import fixture as private_projection
from tests.test_deployment_compose_baseline_recipe import fixture as supported_fixture
from deployment_compose_private import commit
from deployment_compose_recovery_host import ComposeRecoveryHost
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_request_host import ComposeRequestHost


_TEMP_ROOTS = []
PRIVATE_KEY = b'inspect-private-key-' + b'x' * 32


def setup(*, supported=True):
    inputs, reader, result = request_setup()
    observer = inputs['observer']
    projection, recipe = supported_fixture()
    recipe['imageId'] = inputs['baseline'][0].image_id
    if not supported:
        projection = private_projection()
        recipe = None
    projection['Config']['Labels'] = {'com.docker.compose.project': 'blog',
                                      'com.docker.compose.service': 'web'}
    commitment = commit('blog', 'web', projection, 'host-key-1', PRIVATE_KEY)
    old = observer._baseline_artifacts
    observer._baseline_artifacts = replace(old, services=(
        replace(old.services[0], config_hmac=commitment['configHmac']),))
    result['serviceConfigHmacs']['web'] = commitment['configHmac']
    temporary = tempfile.TemporaryDirectory()
    _TEMP_ROOTS.append(temporary)
    # Exercise local filesystem mechanics; this is not Linux acceptance.
    with mock.patch('deployment_compose_recovery_store.sys.platform', 'linux'):
        store = ComposeRecoveryStore(Path(temporary.name).resolve(), key=b'archive-key-' + b'z' * 32)
    recovery = ComposeRecoveryHost(store=store, observer=observer, baseline=inputs['baseline'],
                projections={'web': projection}, private_keys={'host-key-1': PRIVATE_KEY},
                recipes={'web': recipe} if supported else None)
    observation = observer.issue()
    reference = recovery.retain(observation)
    inputs.update(recovery_host=recovery, recovery_reference=reference)
    return inputs, reader, result, observation, store, projection


@unittest.skipIf(os.name == 'nt', 'private recovery archive requires supported Linux host semantics')
class RecoveryHostTests(unittest.TestCase):
    def test_authenticated_exact_specs_retained_without_execution_claim(self):
        inputs, _, _, observation, store, projection = setup()
        reference = inputs['recovery_reference']
        archive = store.get(reference)
        self.assertIn(b'private-value', archive)
        self.assertNotIn('private-value', reference)
        import json
        payload = json.loads(archive)
        self.assertEqual(payload['privateProjections']['web'], projection)
        self.assertFalse(payload['reconstructionValidated'])
        self.assertFalse(payload['executionAvailable'])
        self.assertEqual(inputs['recovery_host'].verify(reference, inputs['observer'], observation), reference)

    def test_read_source_exact_verified_bytes_identity_and_copy(self):
        import json
        from copy import deepcopy
        inputs, _, _, observation, store, projection = setup(supported=False)
        recovery = inputs['recovery_host'];reference = inputs['recovery_reference'];baseline = inputs['baseline'][0]
        identity = dict(project='blog', service='web', containerId=baseline.container_id,
            containerName=baseline.final_name,imageId=baseline.image_id,daemonId=recovery._daemon,
            hostId='host-one',requestedApiVersion='1.45',engineVersion='29.8.2')
        saved = store.get(reference)
        raw, artifact = recovery.read_source(reference,inputs['observer'],observation,service='web',identity=identity)
        self.assertEqual(raw['Config'],projection['Config']);self.assertEqual(artifact.service,'web')
        raw['Config']['Env'].append('MUTATED=local')
        self.assertEqual(store.get(reference),saved)
        self.assertEqual(recovery.verify(reference,inputs['observer'],observation),reference)
        for field, value in [('service','other'),('containerId','f'*64),('imageId','sha256:'+'f'*64),
            ('hostId',True),('requestedApiVersion','1.46'),('engineVersion',False),('extra','bad')]:
            changed = dict(identity,**{field:value})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError,'^recovery-source-rejected$'):
                recovery.read_source(reference,inputs['observer'],observation,service='web',identity=changed)
        unrelated = store.put(b'{}')
        with self.assertRaises(ValueError):recovery.read_source(unrelated,inputs['observer'],observation,service='web',identity=identity)
        for error in (None, FileNotFoundError('private/archive/path')):
            options = {'return_value':b'{}'} if error is None else {'side_effect':error}
            with mock.patch.object(store,'get',**options):
                with self.assertRaisesRegex(ValueError,'^recovery-source-rejected$'):
                    recovery.read_source(reference,inputs['observer'],observation,service='web',identity=identity)

    def test_read_source_uses_single_verified_read_and_rejects_projection_identity_override(self):
        inputs, _, _, observation, store, _ = setup(supported=False)
        recovery = inputs['recovery_host'];reference = inputs['recovery_reference'];baseline = inputs['baseline'][0]
        identity = dict(project='blog', service='web', containerId=baseline.container_id,
            containerName=baseline.final_name,imageId=baseline.image_id,daemonId=recovery._daemon,
            hostId='host-one',requestedApiVersion='1.45',engineVersion='29.8.2')
        saved = store.get(reference)
        with mock.patch.object(store,'get',side_effect=[saved,b'{}']) as get:
            recovery.read_source(reference,inputs['observer'],observation,service='web',identity=identity)
            self.assertEqual(get.call_count,1)
        recovery._projections['web']['Id'] = 'f'*64
        changed = store.put(recovery._payload(inputs['observer'],observation))
        with self.assertRaises(ValueError):
            recovery.read_source(changed,inputs['observer'],observation,service='web',identity=identity)

    def test_secret_config_mismatch_cannot_be_retained(self):
        inputs, _, _, _, store, projection = setup()
        projection['Config']['Env'] = ['TOKEN=wrong-secret']
        with self.assertRaisesRegex(ValueError, '^recovery-config-rejected$'):
            ComposeRecoveryHost(store=store, observer=inputs['observer'], baseline=inputs['baseline'],
                projections={'web': projection}, private_keys={'host-key-1': PRIVATE_KEY})

    def test_scope_and_container_identity_mismatch_rejected(self):
        inputs, _, _, observation, store, projection = setup()
        for changes in (dict(container_id='3' * 64), dict(final_name='other'),
                        dict(image_id='sha256:' + '3' * 64), dict(service='other')):
            baseline = (replace(inputs['baseline'][0], **changes),)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                ComposeRecoveryHost(store=store, observer=inputs['observer'], baseline=baseline,
                    projections={'web': projection}, private_keys={'host-key-1': PRIVATE_KEY})
        other, _, _, other_observation, _, _ = setup()
        with self.assertRaises(ValueError):
            inputs['recovery_host'].verify(inputs['recovery_reference'], other['observer'], other_observation)

    def test_archive_cannot_be_replaced_by_other_authenticated_payload(self):
        inputs, _, _, observation, store, projection = setup()
        unrelated = store.put(b'{"kind":"unrelated"}')
        with self.assertRaisesRegex(ValueError, '^recovery-archive-mismatch$'):
            inputs['recovery_host'].verify(unrelated, inputs['observer'], observation)

    def test_input_mutation_does_not_change_retained_specs(self):
        inputs, _, _, observation, store, projection = setup()
        projection['Config']['Env'] = ['TOKEN=mutated']
        inputs['recovery_host'].verify(inputs['recovery_reference'], inputs['observer'], observation)

    def test_retention_only_archive_is_not_enough_for_final_review(self):
        inputs, _, _, observation, store, _ = setup(supported=False)
        inputs['recovery_host'].verify(inputs['recovery_reference'], inputs['observer'], observation)
        with self.assertRaisesRegex(ValueError, '^verified-baseline-recipes-required$'):
            inputs['recovery_host'].verify(inputs['recovery_reference'], inputs['observer'], observation,
                                          require_recipe_equivalence=True)

    def test_recipe_mismatch_rejected_after_config_authentication(self):
        inputs, _, _, observation, store, projection = setup()
        _, recipe = supported_fixture()
        recipe['imageId'] = inputs['baseline'][0].image_id
        recipe['process']['env'][0] = 'API_KEY=changed'
        with self.assertRaisesRegex(ValueError, '^baseline-recipe-not-representable$'):
            ComposeRecoveryHost(store=store, observer=inputs['observer'], baseline=inputs['baseline'],
                projections={'web': projection}, private_keys={'host-key-1': PRIVATE_KEY}, recipes={'web': recipe})

    def test_target_configuration_can_only_change_image_identity(self):
        inputs, _, _, _, _, _ = setup()
        from copy import deepcopy
        target = deepcopy(inputs['recipes'])
        inputs['recovery_host'].verify_target_configuration(target)
        target['web']['process']['env'][0] = 'API_KEY=changed'
        with self.assertRaisesRegex(ValueError, '^target-config-change-not-supported$'):
            inputs['recovery_host'].verify_target_configuration(target)

    def test_freshness_required(self):
        inputs, _, result, observation, store, _ = setup()
        result['serviceContainerIds']['web'] = '3' * 64
        with self.assertRaises(ValueError):
            inputs['recovery_host'].verify(inputs['recovery_reference'], inputs['observer'], observation)


    def test_source_view_is_retention_only_and_explicit_in_archive(self):
        import json,sys
        from copy import deepcopy
        sys.path.insert(0,str(Path(__file__).parent/'support'))
        from compose_observation_scope_fixture import source_view
        inputs,reader,live,_,store,projection=setup()
        observer=source_view(inputs['observer'],reader,live)
        recovery=ComposeRecoveryHost(store=store,observer=observer,baseline=inputs['baseline'],
            projections={'web':projection},private_keys={'host-key-1':PRIVATE_KEY})
        observation=observer.issue();self.assertIsNotNone(observation)
        with self.assertRaisesRegex(ValueError,'whole-project-observation-required'):
            observer.commitment(observation)
        reference=recovery.retain(observation);payload=json.loads(store.get(reference))
        self.assertEqual(payload['observationScope'],{'kind':'pinned-containers',
            'containerIds':['1'*64,'2'*64],'projectCompletenessVerified':False})
        self.assertEqual(recovery.verify(reference,observer,observation),reference)
        identity=dict(project='blog',daemonId='daemon-1',service='web',containerId='1'*64,
            containerName='blog-web-1',imageId=inputs['baseline'][0].image_id,
            hostId='host-one',requestedApiVersion='1.45',engineVersion='29.8.2')
        raw,_=recovery.read_source(reference,observer,observation,service='web',identity=identity)
        self.assertEqual(raw['Config'],projection['Config'])
        with self.assertRaises(ValueError):recovery.verify(reference,observer,observation,require_recipe_equivalence=True)
        with self.assertRaisesRegex(ValueError,'whole-project-observation-required'):
            recovery.verify_target_configuration(inputs['recipes'])
        with self.assertRaisesRegex(ValueError,'whole-project-observation-required'):
            ComposeRecoveryHost(store=store,observer=observer,baseline=inputs['baseline'],
                projections={'web':projection},private_keys={'host-key-1':PRIVATE_KEY},recipes=inputs['recipes'])


if __name__ == '__main__':
    unittest.main()
