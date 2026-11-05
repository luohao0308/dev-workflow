"""Authenticated v3 retention binds preparation but never grants recovery authority."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_deployment_compose_prepare_v2_host import setup
from tests.test_deployment_compose_baseline_recipe import fixture
from tests.test_deployment_compose_approval_host import deadline
from tests.test_deployment_compose_target_prepare import KEY
from deployment_compose_private import commit
from deployment_compose_recipe_v3 import commit_recipe_v3
from deployment_compose_recovery_host import ComposeRecoveryHost
from deployment_compose_recovery_v3_host import ComposeRecoveryHostV3
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_prepare_v2_host import ComposePreparationHostV2, DOMAIN, encode

PRIVATE_KEY = b'inspect-private-key-' + b'x' * 32


@unittest.skipIf(os.name == 'nt', 'private archive requires POSIX host semantics')
class RecoveryV3HostTests(unittest.TestCase):
    def context(self, mutate=None):
        inputs, reader, live = setup()
        projection, _ = fixture()
        recipe = inputs['recipes']['web']
        projection['Config']['ExposedPorts'] = {}
        host = projection['HostConfig']
        host['PortBindings'] = {}
        host['RestartPolicy'] = {'Name': recipe['hostConfig']['restartPolicy']['name'],
            'MaximumRetryCount': recipe['hostConfig']['restartPolicy']['maximumRetryCount']}
        log = recipe['hostConfig']['logConfig']
        host['LogConfig'] = {'Type': log['type'], 'Config': deepcopy(log['config'])}
        for observed, declared in {'Memory': 'memoryBytes', 'MemorySwap': 'memorySwapBytes',
                                  'NanoCpus': 'nanoCpus', 'PidsLimit': 'pidsLimit'}.items():
            host[observed] = recipe['hostConfig']['resources'][declared]
        if mutate:
            mutate(projection)
        signature = commit('blog', 'web', projection, 'host-key-1', PRIVATE_KEY)
        observer = inputs['observer']
        artifacts = observer._baseline_artifacts
        observer._baseline_artifacts = replace(artifacts, services=(
            replace(artifacts.services[0], config_hmac=signature['configHmac']),))
        live['serviceConfigHmacs']['web'] = signature['configHmac']
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        with mock.patch('deployment_compose_recovery_store.sys.platform', 'linux'):
            store = ComposeRecoveryStore(str(Path(temporary.name).resolve()), key=b'z' * 32)
        self.addCleanup(store.close)
        args = dict(store=store, observer=observer, baseline=inputs['baseline'],
            projections={'web': projection}, private_keys={'host-key-1': PRIVATE_KEY},
            recipes=deepcopy(inputs['recipes']))
        return inputs, live, projection, store, args

    def retained(self):
        inputs, live, projection, store, args = self.context()
        recovery = ComposeRecoveryHostV3(**args)
        observation = inputs['observer'].issue()
        reference = recovery.retain(observation)
        return inputs, live, projection, store, args, recovery, observation, reference

    def test_original_values_retained_without_normalization_or_authority(self):
        inputs, _, projection, store, _, recovery, observation, reference = self.retained()
        payload = json.loads(store.get(reference))
        self.assertEqual(payload['original']['privateProjections']['web'], projection)
        self.assertEqual(payload['recoveryRecipesV3'], inputs['recipes'])
        self.assertEqual(payload['kind'], 'compose-committed-baseline-v3')
        self.assertEqual(payload['recipeValueComparison'], 'closed-v3-subset')
        for field in ('reconstructionValidated', 'replaySafe', 'authorityGranted',
                      'executionAvailable', 'productionReady'):
            self.assertIs(payload[field], False)
        self.assertEqual(recovery.verify(reference, inputs['observer'], observation), reference)

    def test_signed_unknown_config_and_resource_mismatch_rejected(self):
        for mutate in (lambda p: p['Config'].update(Unknown=True),
                       lambda p: p['HostConfig'].update(Memory=12345)):
            _, _, _, _, args = self.context(mutate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                ComposeRecoveryHostV3(**args)

    def test_bad_original_hmac_rejected(self):
        _, _, _, _, args = self.context()
        args['private_keys']['host-key-1'] = b'wrong-key-' + b'x' * 32
        with self.assertRaises(ValueError):
            ComposeRecoveryHostV3(**args)

    def test_input_copy_preserves_original_and_recipe(self):
        inputs, _, projection, store, args, recovery, observation, reference = self.retained()
        before = store.get(reference)
        projection['Config']['Env'] = ['TOKEN=changed']
        args['recipes']['web']['hostConfig']['resources']['memoryBytes'] = 1
        self.assertEqual(recovery.verify(reference, inputs['observer'], observation), reference)
        self.assertEqual(store.get(reference), before)

    def test_missing_wrong_and_modified_archives_rejected(self):
        inputs, _, _, store, _, recovery, observation, reference = self.retained()
        for wrong in ('0' * 64, store.put(b'{"kind":"unrelated"}')):
            with self.subTest(reference=wrong), self.assertRaises(ValueError):
                recovery.verify(wrong, inputs['observer'], observation)
        path = Path(store._root) / reference
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            recovery.verify(reference, inputs['observer'], observation)

    def test_live_drift_and_foreign_observer_rejected(self):
        inputs, live, _, _, _, recovery, observation, reference = self.retained()
        foreign, _, _, _, _, _, foreign_observation, _ = self.retained()
        with self.assertRaises(ValueError):
            recovery.verify(reference, foreign['observer'], foreign_observation)
        live['serviceContainerIds']['web'] = '3' * 64
        with self.assertRaises(ValueError):
            recovery.verify(reference, inputs['observer'], observation)

    def test_only_image_identity_may_change_in_target_values(self):
        inputs, _, _, _, _, recovery, _, _ = self.retained()
        target = deepcopy(inputs['recipes'])
        target['web']['imageId'] = 'sha256:' + 'f' * 64
        self.assertIsNone(recovery.verify_target_configuration(target))
        for mutate in (lambda r: r['process'].update(env=['API_KEY=changed']),
                       lambda r: r['hostConfig']['resources'].update(memoryBytes=134217728),
                       lambda r: r['hostConfig']['restartPolicy'].update(name='no')):
            target = deepcopy(inputs['recipes'])
            mutate(target['web'])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                recovery.verify_target_configuration(target)

    def test_preparation_binds_archive_and_keeps_engine_gate_closed(self):
        inputs, _, _, _, _, recovery, observation, reference = self.retained()
        host = ComposePreparationHostV2(**inputs)
        params = dict(operation_nonce='9' * 64, expires_at=deadline(), recovery=recovery, reference=reference)
        result = host.prepare_with_recovery(observation, **params)
        self.assertEqual(result['review']['recoveryArchiveReference'], reference)
        self.assertIs(result['review']['completeOperationPlan'], False)
        self.assertIn('v3-baseline-reconstruction-required', json.dumps(result['review']))
        self.assertIsNone(host.verify_with_recovery(result, observation, **params))
        for private in (False, True):
            changed = deepcopy(result)
            if private:
                changed['derivations']['web']['candidate']['body']['Env'] = ['TOKEN=wrong']
            else:
                review = changed['review']
                review['recoveryArchiveReference'] = '0' * 64
                review.pop('preparationDigest')
                review['preparationDigest'] = hashlib.sha256(DOMAIN + encode(review)).hexdigest()
            with self.subTest(private=private), self.assertRaises(ValueError):
                host.verify_with_recovery(changed, observation, **params)

    def test_properly_signed_target_config_changes_still_rejected(self):
        for mutate in (lambda r: r['process']['env'].__setitem__(0, 'API_KEY=changed'),
                       lambda r: r['hostConfig']['resources'].update(memoryBytes=33554432, memorySwapBytes=33554432),
                       lambda r: r['hostConfig']['restartPolicy'].update(name='no')):
            inputs, _, _, _, _, recovery, observation, reference = self.retained()
            recipe = inputs['recipes']['web']
            mutate(recipe)
            item = inputs['target'].services[0]
            inputs['target'] = replace(inputs['target'], services=(replace(item,
                recipe_hmac=commit_recipe_v3(recipe, 'host-key-1', KEY)['hmac']),))
            host = ComposePreparationHostV2(**inputs)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                host.prepare_with_recovery(observation, operation_nonce='9' * 64,
                    expires_at=deadline(), recovery=recovery, reference=reference)

    def test_expiry_after_retention_io_rejected_at_final_boundary(self):
        inputs, _, _, _, _, recovery, observation, reference = self.retained()
        host = ComposePreparationHostV2(**inputs)
        before = datetime.now(timezone.utc).replace(microsecond=0)
        expires = before + timedelta(seconds=5)
        expiry_text = expires.strftime('%Y-%m-%dT%H:%M:%SZ')
        with mock.patch('deployment_compose_prepare_v2_host.datetime', wraps=datetime) as clock:
            clock.now.side_effect = [before, before, expires + timedelta(seconds=1)]
            with self.assertRaisesRegex(ValueError, '^compose-preparation-v2-rejected$'):
                host.prepare_with_recovery(observation, operation_nonce='9' * 64,
                    expires_at=expiry_text, recovery=recovery, reference=reference)
            self.assertEqual(clock.now.call_count, 3)

    def test_legacy_archive_and_json_cannot_substitute_typed_recovery(self):
        inputs, _, _, store, args, recovery, observation, reference = self.retained()
        legacy_args = dict(args)
        legacy_args['recipes'] = None
        legacy = ComposeRecoveryHost(**legacy_args)
        old_reference = legacy.retain(observation)
        with self.assertRaises(ValueError):
            recovery.verify(old_reference, inputs['observer'], observation)
        with self.assertRaises(ValueError):
            legacy.verify(reference, inputs['observer'], observation)
        host = ComposePreparationHostV2(**inputs)
        for substitute in (legacy, json.loads(store.get(reference)), {'pending': True}):
            with self.subTest(substitute=type(substitute)), self.assertRaises(ValueError):
                host.prepare_with_recovery(observation, operation_nonce='9' * 64,
                    expires_at=deadline(), recovery=substitute, reference=reference)


    def test_retention_source_view_cannot_enter_v3_recipe_equivalence(self):
        import sys
        sys.path.insert(0,str(Path(__file__).parent/'support'))
        from compose_observation_scope_fixture import source_view
        inputs,reader,live=setup()
        source=source_view(inputs['observer'],reader,live)
        with self.assertRaisesRegex(ValueError,'compose-v3-recovery-rejected'):
            ComposeRecoveryHostV3(store=None,observer=source,baseline=inputs['baseline'],
                projections={},private_keys={},recipes={})


if __name__ == '__main__':
    unittest.main()
