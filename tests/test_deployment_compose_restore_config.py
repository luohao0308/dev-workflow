"""Authenticated baseline Config fragments, including unsafe inheritance cases."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_image_defaults import commit_image_config
from deployment_compose_restore_config import compile_restore_config
from tests.test_deployment_compose_snapshot import fixture as source_fixture, rebind, KEY

IMAGE_KEY = b'image-test-key-' + b'z' * 32


def fixture():
    raw, identity, artifact, networks, mounts = source_fixture()
    raw['Config']['Image'] = artifact.registry_digest
    raw['Config']['Cmd'] = ['python', '-m', 'http.server']
    artifact = rebind(raw, identity, artifact)
    image = {'Id': artifact.image_id, 'Os': 'linux', 'Architecture': artifact.architecture,
             'RepoDigests': [artifact.registry_digest],
             'Config': {'Env': ['A=image-default'], 'Cmd': ['image-command']}}
    return raw, identity, artifact, networks, mounts, image


def build(raw, identity, artifact, networks, mounts, image, proof=None, **kwargs):
    if proof is None:
        proof = commit_image_config(image, 'image-key', IMAGE_KEY)
    return compile_restore_config(raw, identity, artifact, KEY, networks, mounts,
                                  image, proof, IMAGE_KEY,
                                  expected_image_key_id=kwargs.get('key_id', 'image-key'))


class RestoreConfigTests(unittest.TestCase):
    def test_exact_fields_only_image_reference_rewritten(self):
        args = fixture()
        raw, _, artifact, _, _, _ = args
        before = deepcopy(args)
        result = build(*args)
        self.assertEqual(args, before)
        expected = dict(raw['Config'], Image=artifact.image_id)
        self.assertEqual(result['configFragment'], expected)
        self.assertTrue(result['configFragment']['AttachStdout'])
        self.assertEqual(result['configFragment']['Env'], ['Z=last', 'A=a=b'])
        self.assertIsNone(result['configFragment']['Entrypoint'])
        self.assertEqual(result['imageReferenceRewrite'], {'from': artifact.registry_digest, 'to': artifact.image_id})
        for field in ('completeCreatePayloadAvailable', 'authorityGranted', 'executionAvailable',
                      'reconstructionValidated', 'productionReady'):
            self.assertIs(result[field], False)
        self.assertFalse({'method', 'path', 'HostConfig', 'NetworkingConfig'} & result.keys())
        raw['Config']['Labels']['custom'] = 'later mutation'
        self.assertNotEqual(result['configFragment']['Labels'], raw['Config']['Labels'])

    def test_optional_ports_absence_null_and_empty_preserved_and_bound(self):
        digests = []
        for state in ('absent', None, {}, {'8080/tcp': {}}):
            raw, identity, artifact, networks, mounts, image = fixture()
            if state != 'absent':
                raw['Config']['ExposedPorts'] = state
            result = build(raw, identity, rebind(raw, identity, artifact), networks, mounts, image)
            self.assertEqual(result['configFragment'], dict(raw['Config'], Image=artifact.image_id))
            digests.append(result['fragmentDigest'])
        self.assertEqual(len(set(digests)), 4)

    def test_source_hmac_and_cross_surface_coherence_rechecked(self):
        raw, identity, artifact, networks, mounts, image = fixture()
        raw['Config']['Env'].append('PRIVATE=value')
        with self.assertRaisesRegex(ValueError, '^invalid-compose-restore-config-fragment$'):
            build(raw, identity, artifact, networks, mounts, image)
        raw['HostConfig']['Mounts'][0]['VolumeOptions']['NoCopy'] = False
        with self.assertRaises(ValueError):
            build(raw, identity, rebind(raw, identity, artifact), networks, mounts, image)

    def test_image_commitment_key_and_identity_pins(self):
        args = fixture()
        image = args[-1]
        proof = commit_image_config(image, 'image-key', IMAGE_KEY)
        image['Config']['Env'] = ['A=tampered']
        with self.assertRaises(ValueError):
            build(*args, proof=proof)
        for mutate in (lambda i: i.update(Id='sha256:' + 'f'*64),
                       lambda i: i.update(Architecture='arm64'),
                       lambda i: i.update(RepoDigests=['other@sha256:' + 'f'*64])):
            changed = deepcopy(args); mutate(changed[-1])
            with self.assertRaises(ValueError):
                build(*changed)
        with self.assertRaises(ValueError):
            build(*args, key_id='other-key')
        foreign = commit_image_config(image, 'foreign-key', IMAGE_KEY)
        with self.assertRaises(ValueError):
            build(*args, proof=foreign)

    def test_authenticated_image_merge_hazards_rejected(self):
        for field, values in {
            'Labels': [{'image-label': 'new'}], 'Volumes': [{'/data': {}}],
            'ExposedPorts': [{'80/tcp': {}}], 'Healthcheck': [{'Test': ['NONE']}],
            'StopSignal': ['SIGTERM', None], 'User': ['1000', None],
            'Entrypoint': [[], ['sh']],
            'Env': [['MISSING=value'], ['A=x', 'A=y'], ['bad-key=x'], ['A'], ['A=bad\0value']],
        }.items():
            for value in values:
                args = fixture(); args[-1]['Config'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    build(*args)
        raw, identity, artifact, networks, mounts, image = fixture()
        raw['Config']['WorkingDir'] = ''
        image['Config']['WorkingDir'] = '/inherited'
        with self.assertRaises(ValueError):
            build(raw, identity, rebind(raw, identity, artifact), networks, mounts, image)

    def test_registry_shorthand_is_not_silently_aliased(self):
        raw, identity, artifact, networks, mounts, image = fixture()
        # Same content digest does not authorize changing the asserted registry.
        short = 'app@sha256:' + 'c' * 64
        raw['Config']['Image'] = short
        image['RepoDigests'] = [short]
        with self.assertRaises(ValueError):
            build(raw, identity, rebind(raw, identity, artifact), networks, mounts, image)
        image['RepoDigests'].append(artifact.registry_digest)
        with self.assertRaises(ValueError):
            build(raw, identity, rebind(raw, identity, artifact), networks, mounts, image)

    def test_authenticated_source_argv_ambiguity_and_foreign_image_rejected(self):
        for field, values in {'Cmd': [None, [], [''], ['python', '']],
                              'Entrypoint': [[], ['']], 'Image': ['mutable:latest', 'other@sha256:'+'c'*64]}.items():
            for value in values:
                raw, identity, artifact, networks, mounts, image = fixture()
                raw['Config'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    build(raw, identity, rebind(raw, identity, artifact), networks, mounts, image)

    def test_explicit_values_override_and_preserve_image_defaults(self):
        raw, identity, artifact, networks, mounts, image = fixture()
        raw['Config'].update(Image=artifact.image_id, Entrypoint=['python'], User='1000')
        image['Config'].update(Entrypoint=['image-entrypoint'], User='2000', WorkingDir='/other')
        result = build(raw, identity, rebind(raw, identity, artifact), networks, mounts, image)
        self.assertEqual(result['configFragment'], raw['Config'])

    def test_authenticated_metadata_and_image_proof_change_binding(self):
        args = fixture()
        first = build(*args)
        args[-1]['Config']['Cmd'] = ['different-unused-image-command']
        second = build(*args)
        self.assertEqual(first['configFragment'], second['configFragment'])
        self.assertNotEqual(first['fragmentDigest'], second['fragmentDigest'])
        raw, identity, artifact, networks, mounts, image = args
        raw['Config']['Hostname'] = 'retained-observed-host'
        raw['Config']['Labels']['com.docker.compose.config-hash'] = 'new-observed-hash'
        third = build(raw, identity, rebind(raw, identity, artifact), networks, mounts, image)
        self.assertNotEqual(second['fragmentDigest'], third['fragmentDigest'])
        self.assertEqual(third['configFragment']['Hostname'], 'retained-observed-host')


if __name__ == '__main__':
    unittest.main()
