"""Authenticated composition from a single synthetic source, with no writer."""
from copy import deepcopy
from dataclasses import replace
import hashlib
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


class RestoreBodyTests(unittest.TestCase):
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
