"""Authenticated composition from a single synthetic source, with no writer."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from tests.test_deployment_compose_restore_host_config import fixture as host_fixture
from tests.test_deployment_compose_snapshot import KEY, rebind
from tests.test_deployment_compose_restore_config import IMAGE_KEY
from deployment_compose_image_defaults import commit_image_config
from deployment_compose_network_declaration import commit_network_declaration
from deployment_compose_snapshot import prepare_snapshot, _encode
from deployment_compose_restore_host_config import POLICY
from deployment_compose_image_reference import POLICY as REFERENCE_POLICY
import deployment_compose_restore_body_host as host

DKEY = b'declaration-test-key-' + b'x' * 32


def fixture():
    raw, identity, artifact, networks, mounts = host_fixture()
    raw['Config']['Image'] = artifact.registry_digest
    raw['Config']['Cmd'] = ['python', '-m', 'http.server']
    artifact = rebind(raw, identity, artifact)
    image = {'Id': artifact.image_id, 'Os': 'linux', 'Architecture': artifact.architecture,
             'RepoDigests': [artifact.registry_digest], 'Config': {'Env': ['A=image']}}
    return dict(raw=raw, identity=identity, artifact=artifact, private_key=KEY,
        network_ids=networks, expected_mounts=mounts, image=image,
        image_commitment=commit_image_config(image, 'image-key', IMAGE_KEY), image_key=IMAGE_KEY,
        expected_image_key_id='image-key', declaration_key=DKEY,
        expected_declaration_key_id='declaration-key', expected_source_model_digest='e' * 64,
        host_config_policy=POLICY, metadata_policy=host.METADATA_POLICY, operation_nonce='f' * 64)


def seal(args):
    raw, artifact = args['raw'], args['artifact']
    snapshot = prepare_snapshot(raw, args['identity'], artifact, KEY, args['network_ids'], args['expected_mounts'])
    declaration = {'schemaVersion': 1, 'identity': deepcopy(args['identity']),
        'sourceSha': artifact.source_sha, 'sourceModelDigest': 'e' * 64,
        'sourceSnapshotDigest': hashlib.sha256(_encode(snapshot)).hexdigest(),
        'networks': {name: {'id': nid, 'aliases': deepcopy(raw['NetworkSettings']['Networks'][name]['Aliases']),
            'addressPolicy': 'dynamic-no-requested-addresses', 'requestedMac': None,
            'ipamConfig': None, 'links': None, 'driverOpts': None} for name, nid in args['network_ids'].items()}}
    proof = commit_network_declaration(declaration, 'declaration-key', DKEY)
    args.update(declaration=declaration, declaration_proof=proof, expected_declaration_hmac=proof['declarationHmac'])
    return args


def retained_fixture():
    from tests.test_deployment_compose_recovery_host import setup
    from deployment_compose_recovery_host import ComposeRecoveryHost
    from deployment_compose_private import MOUNT, commit
    inputs, _, observed, _, store, _ = setup(supported=False)
    args = fixture(); baseline = inputs['baseline'][0]
    args['identity'].update(project='blog', service='web', daemonId=inputs['observer']._policy['daemonId'],
        containerId=baseline.container_id, containerName=baseline.final_name, imageId=baseline.image_id)
    args['raw'].update(Id=baseline.container_id, Name='/'+baseline.final_name, Image=baseline.image_id)
    args['raw']['Config']['Labels'].update({'com.docker.compose.project':'blog', 'com.docker.compose.service':'web'})
    old_artifact = inputs['observer']._baseline_artifacts.services[0]
    args['raw']['Config']['Image'] = old_artifact.registry_digest
    args['image']['RepoDigests'] = [old_artifact.registry_digest]
    args['image']['Id'] = baseline.image_id
    args['raw']['Mounts'] = [{**{k:None for k in MOUNT}, **m} for m in args['raw']['Mounts']]
    projection = {k:deepcopy(args['raw'][k]) for k in ('Config','HostConfig','NetworkSettings','Mounts')}
    digest = commit('blog','web',projection,'inspect-key',KEY)['configHmac']
    artifact = replace(old_artifact, config_key_id='inspect-key', config_hmac=digest)
    args['artifact'] = artifact
    args['image_commitment'] = commit_image_config(args['image'],'image-key',IMAGE_KEY)
    observer = inputs['observer'];observer._baseline_artifacts = replace(observer._baseline_artifacts, services=(artifact,))
    observed['serviceConfigHmacs']['web'] = digest
    recovery = ComposeRecoveryHost(store=store,observer=observer,baseline=inputs['baseline'],
        projections={'web':projection},private_keys={'inspect-key':KEY},recipes=None)
    observation = observer.issue();reference = recovery.retain(observation)
    seal(args)
    options = {k:v for k,v in args.items() if k not in ('raw','artifact')}
    return args, options, recovery, reference, observer, observation, store


@unittest.skipIf(os.name == 'nt', 'private recovery store requires POSIX semantics')
class RetainedRestoreTests(unittest.TestCase):
    def test_candidate_matches_direct_and_binding_is_separate(self):
        args, options, recovery, reference, observer, observation, _ = retained_fixture()
        result = host.compile_retained_restore_body(recovery,reference,observer,observation,service='web',**options)
        self.assertEqual(result['candidate'],host.compile_restore_body(**args))
        binding = result['retentionBinding'];self.assertEqual(binding['archiveReference'],reference)
        self.assertEqual(binding['compositionDigest'],result['candidate']['compositionDigest'])
        self.assertNotIn('retentionBinding',result['candidate'])
        material = {k:v for k,v in binding.items() if k!='bindingDigest'}
        self.assertEqual(binding['bindingDigest'],hashlib.sha256(host.RETENTION_DOMAIN+_encode(material)).hexdigest())

    def test_archive_replacement_during_compile_rejected(self):
        _, options, recovery, reference, observer, observation, store = retained_fixture()
        original = host.compile_restore_body
        def substitute(*args, **kwargs):
            value = original(*args, **kwargs)
            store.get = lambda ref:b'{}'
            return value
        with patch.object(host,'compile_restore_body',side_effect=substitute), self.assertRaisesRegex(ValueError,'^retained-restore-body-rejected$'):
            host.compile_retained_restore_body(recovery,reference,observer,observation,service='web',**options)

    def test_observer_drift_during_compilation_rejected(self):
        _, options, recovery, reference, observer, observation, _ = retained_fixture()
        original = host.compile_restore_body
        def drift(*args, **kwargs):
            result = original(*args, **kwargs)
            observer._policy['daemonId'] = 'changed-daemon'
            return result
        with patch.object(host,'compile_restore_body',side_effect=drift), self.assertRaises(ValueError):
            host.compile_retained_restore_body(recovery,reference,observer,observation,service='web',**options)

    def test_wrong_service_or_identity_or_archive_rejected(self):
        _, options, recovery, reference, observer, observation, store = retained_fixture()
        for field, value in [('service','other'),('containerId','a'*64),('project','other'),('hostId',True),('requestedApiVersion','1.46')]:
            changed = deepcopy(options); changed['identity'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                host.compile_retained_restore_body(recovery,reference,observer,observation,service='web',**changed)
        other = store.put(b'{}')
        with self.assertRaises(ValueError):
            host.compile_retained_restore_body(recovery,other,observer,observation,service='web',**options)


class RestoreBodyTests(unittest.TestCase):
    def test_running_metadata_policy_is_explicit_and_separately_bound(self):
        args = seal(fixture()); stopped = host.compile_restore_body(**args)
        args['metadata_policy'] = host.RUNNING_METADATA_POLICY
        running = host.compile_restore_body(**args)
        self.assertEqual(running['body'], stopped['body'])
        self.assertNotEqual(running['compositionDigest'], stopped['compositionDigest'])
        self.assertFalse(running['productionReady'] or running['executionAvailable'])

    def test_complete_preservation_and_no_authority(self):
        args = seal(fixture()); before = deepcopy(args)
        result = host.compile_restore_body(**args)
        self.assertEqual(args, before)
        config = {k: v for k, v in result['body'].items() if k not in ('HostConfig', 'NetworkingConfig')}
        self.assertEqual(config, dict(args['raw']['Config'], Image=args['artifact'].image_id))
        self.assertEqual(result['body']['HostConfig'], args['raw']['HostConfig'])
        self.assertEqual(result['body']['NetworkingConfig']['EndpointsConfig'],
            {'sample_default': {'NetworkID': args['network_ids']['sample_default'], 'Aliases': ['app', 'custom']}})
        self.assertEqual(result['bodySha256'], hashlib.sha256(_encode(result['body'])).hexdigest())
        self.assertEqual(result['path'], '/v1.45/containers/create?name=dw-restore-' + 'f' * 24 + '-app')
        for flag in ('authorityGranted', 'executionAvailable', 'completeCreatePayloadAvailable',
                     'reconstructionValidated', 'productionReady', 'sourceModelProvenanceVerified', 'freshnessVerified'):
            self.assertIs(result[flag], False)
        self.assertIn('independent-engine-reconstruction-required', result['blockers'])
        args['raw']['Config']['Env'].append('LATER=value')
        self.assertEqual(result['body']['Env'], before['raw']['Config']['Env'])

    def test_wrong_authentication_source_or_scope_rejected(self):
        for field, value in [('private_key', b'z' * 32), ('expected_declaration_hmac', '0' * 64),
            ('expected_source_model_digest', '0' * 64), ('expected_image_key_id', 'foreign'),
            ('metadata_policy', None), ('metadata_policy', 'retain'), ('operation_nonce', True),
            ('operation_nonce', 'a' * 63), ('host_config_policy', 'other')]:
            args = seal(fixture()); args[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, '^compose-restore-body-diagnostic-rejected$'):
                host.compile_restore_body(**args)

    def test_tampering_and_type_substitution_rejected(self):
        for mutate in [lambda a: a['raw']['Config']['Env'].append('TAMPERED=secret'),
                       lambda a: a['declaration']['networks']['sample_default']['aliases'].append('other'),
                       lambda a: a['network_ids'].update(sample_default='a' * 64),
                       lambda a: a['raw']['HostConfig'].update(Memory=True),
                       lambda a: a['image'].update(Id='sha256:' + 'a' * 64)]:
            args = seal(fixture()); mutate(args)
            with self.assertRaises(ValueError):host.compile_restore_body(**args)

    def test_authenticated_wrong_image_or_host_values_rejected(self):
        args = fixture();args['raw']['Config']['Image'] = 'mutable:latest'
        args['artifact'] = rebind(args['raw'], args['identity'], args['artifact'])
        with self.assertRaises(ValueError):host.compile_restore_body(**seal(args))
        args = fixture();args['raw']['HostConfig']['Memory'] = 0
        args['artifact'] = rebind(args['raw'], args['identity'], args['artifact'])
        with self.assertRaises(ValueError):host.compile_restore_body(**seal(args))

    def test_nonce_and_metadata_are_bound(self):
        args = seal(fixture()); first = host.compile_restore_body(**args)
        args['operation_nonce'] = 'a' * 64; second = host.compile_restore_body(**args)
        self.assertEqual(first['body'], second['body'])
        self.assertNotEqual(first['compositionDigest'], second['compositionDigest'])
        args = fixture();args['raw']['Config']['Labels']['custom'] = 'metadata'
        args['artifact'] = rebind(args['raw'], args['identity'], args['artifact'])
        third = host.compile_restore_body(**seal(args))
        self.assertNotEqual(first['compositionDigest'], third['compositionDigest'])
        self.assertEqual(third['body']['Labels']['custom'], 'metadata')

    def test_explicit_reference_binding_no_silent_fallback(self):
        args = fixture(); short = 'python@sha256:' + 'c' * 64
        args['raw']['Config']['Image'] = short
        args['artifact'] = rebind(args['raw'], args['identity'], replace(args['artifact'], registry_digest='docker.io/library/' + short))
        args['image']['RepoDigests'] = [short]
        args['image_commitment'] = commit_image_config(args['image'], 'image-key', IMAGE_KEY)
        seal(args)
        with self.assertRaises(ValueError):host.compile_restore_body(**args)
        args.update(expected_observed_reference=short, reference_policy=REFERENCE_POLICY)
        self.assertEqual(host.compile_restore_body(**args)['body']['Image'], args['artifact'].image_id)
        args['reference_policy'] = None
        with self.assertRaises(ValueError):host.compile_restore_body(**args)

    def test_missing_empty_and_null_mount_declarations_preserved(self):
        digests = []
        for state in ('missing', None, []):
            args = fixture();args['raw']['Mounts'] = [];args['expected_mounts'] = {}
            if state == 'missing':args['raw']['HostConfig'].pop('Mounts')
            else:args['raw']['HostConfig']['Mounts'] = state
            args['artifact'] = rebind(args['raw'], args['identity'], args['artifact'])
            result = host.compile_restore_body(**seal(args))
            self.assertEqual(result['body']['HostConfig'], args['raw']['HostConfig'])
            digests.append(result['compositionDigest'])
        self.assertEqual(len(set(digests)), 3)

    def test_temporary_name_collision_and_invalid_type_rejected_before_fragments(self):
        args = seal(fixture());args['identity']['containerName'] = 'dw-restore-' + 'f' * 24 + '-app'
        with patch.object(host, 'compile_restore_config') as compile_config, self.assertRaises(ValueError):
            host.compile_restore_body(**args)
        compile_config.assert_not_called()
        for value in (True, ['app'], 'bad&injected=1'):
            args = seal(fixture());args['identity']['service'] = value
            with self.assertRaises(ValueError):host.compile_restore_body(**args)

    def test_copy_prevents_external_source_mutation_during_composition(self):
        args = seal(fixture());expected = deepcopy(args['raw']['Config']['Env'])
        original = host.compile_restore_config
        def mutate_external(*inner_args, **kwargs):
            args['raw']['Config']['Env'].append('CHANGED=external')
            return original(*inner_args, **kwargs)
        with patch.object(host, 'compile_restore_config', side_effect=mutate_external):
            result = host.compile_restore_body(**args)
        self.assertEqual(result['body']['Env'], expected)

    def test_fragment_cross_source_mismatch_fails_closed(self):
        original = host.compile_restore_host_config
        def changed(*args, **kwargs):
            value = original(*args, **kwargs);value['sourceSnapshotDigest'] = '0' * 64;return value
        with patch.object(host, 'compile_restore_host_config', side_effect=changed), self.assertRaises(ValueError):
            host.compile_restore_body(**seal(fixture()))


if __name__ == '__main__':unittest.main()
