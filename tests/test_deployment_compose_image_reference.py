"""Explicit authenticated Docker Hub official digest reference policy."""
from copy import deepcopy
from dataclasses import replace
import unittest

from tests.test_deployment_compose_restore_config import fixture, IMAGE_KEY
from tests.test_deployment_compose_snapshot import KEY, rebind
from deployment_compose_image_defaults import commit_image_config
from deployment_compose_image_reference import POLICY, derive_bound_defaults
from deployment_compose_restore_config import (compile_restore_config,
                                               compile_restore_config_with_reference)


def reference_fixture():
    raw, identity, artifact, networks, mounts, image = fixture()
    short = 'python@sha256:' + 'c' * 64
    full = 'docker.io/library/' + short
    raw['Config']['Image'] = short
    artifact = rebind(raw, identity, replace(artifact, registry_digest=full))
    image['RepoDigests'] = [short]
    return raw, identity, artifact, networks, mounts, image


def derive(image, artifact, observed, **changes):
    proof = commit_image_config(image, 'image-key', IMAGE_KEY)
    inputs = dict(expected_key_id='image-key', expected_image_id=artifact.image_id,
                  expected_artifact_reference=artifact.registry_digest,
                  expected_observed_reference=observed,
                  expected_architecture=artifact.architecture, policy=POLICY)
    inputs.update(changes)
    return derive_bound_defaults(image, proof, IMAGE_KEY, **inputs)


def compile_bound(args, **changes):
    raw, identity, artifact, networks, mounts, image = args
    inputs = dict(expected_image_key_id='image-key',
                  expected_observed_reference='python@sha256:' + 'c'*64,
                  reference_policy=POLICY)
    inputs.update(changes)
    return compile_restore_config_with_reference(raw, identity, artifact, KEY,
        networks, mounts, image, commit_image_config(image, 'image-key', IMAGE_KEY),
        IMAGE_KEY, **inputs)


class ImageReferenceTests(unittest.TestCase):
    def test_original_image_authenticated_and_not_rewritten(self):
        args = reference_fixture(); before = deepcopy(args)
        image, artifact = args[-1], args[2]
        defaults, binding = derive(image, artifact, image['RepoDigests'][0])
        self.assertEqual(args, before)
        self.assertEqual(defaults['ImageId'], artifact.image_id)
        self.assertEqual(binding['rule'], 'docker-hub-official-shorthand')
        self.assertEqual(binding['artifactReference'], artifact.registry_digest)
        self.assertEqual(binding['observedReference'], image['RepoDigests'][0])
        for field in ('registryContactVerified', 'sourceProvenanceVerified',
                      'freshnessVerified', 'authorityGranted'):
            self.assertIs(binding[field], False)
        binding['imageCommitment']['keyId'] = 'mutated'
        self.assertEqual(derive(image, artifact, image['RepoDigests'][0])[1]['imageCommitment']['keyId'], 'image-key')

    def test_exact_reference_is_supported_and_distinct(self):
        args = fixture(); image, artifact = args[-1], args[2]
        _, binding = derive(image, artifact, artifact.registry_digest)
        self.assertEqual(binding['rule'], 'exact')
        self.assertEqual(binding['observedReference'], artifact.registry_digest)

    def test_cross_registry_namespace_or_digest_is_rejected(self):
        args = reference_fixture(); image, artifact = args[-1], args[2]
        observed = image['RepoDigests'][0]
        for full in ('evil.example/library/' + observed, 'docker.io/attacker/' + observed,
                     'docker.io/library/not-' + observed, 'docker.io/library/python@sha256:'+'d'*64,
                     'index.docker.io/library/' + observed):
            with self.subTest(full=full), self.assertRaises(ValueError):
                derive(image, artifact, observed, expected_artifact_reference=full)

    def test_unsupported_spellings_are_not_guessed(self):
        args = reference_fixture(); image, artifact = args[-1], args[2]
        for name in ('library/python', 'namespace/python', 'localhost/python', 'python:latest',
                     'PYTHON', 'docker.io/python', 'index.docker.io/library/python',
                     '../python', 'python/', 'python\0', ' python'):
            changed = deepcopy(image)
            observed = name + '@sha256:' + 'c'*64
            changed['RepoDigests'] = [observed]
            with self.subTest(name=name), self.assertRaises(ValueError):
                derive(changed, artifact, observed)

    def test_original_membership_and_proof_pins_are_required(self):
        args = reference_fixture(); image, artifact = args[-1], args[2]
        observed = image['RepoDigests'][0]
        for changes in ({'expected_observed_reference': artifact.registry_digest},
                        {'expected_key_id': 'foreign-key'}, {'policy': 'implicit'},
                        {'expected_image_id': 'sha256:'+'d'*64},
                        {'expected_architecture': 'arm64'}, {'policy': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                derive(image, artifact, observed, **changes)
        proof = commit_image_config(image, 'image-key', IMAGE_KEY)
        image['RepoDigests'] = [artifact.registry_digest]
        with self.assertRaises(ValueError):
            derive_bound_defaults(image, proof, IMAGE_KEY, expected_key_id='image-key',
                expected_image_id=artifact.image_id, expected_artifact_reference=artifact.registry_digest,
                expected_observed_reference=artifact.registry_digest,
                expected_architecture=artifact.architecture, policy=POLICY)

    def test_schema2_only_image_changes_and_original_schema1_stays_closed(self):
        args = reference_fixture(); before = deepcopy(args)
        raw, identity, artifact, networks, mounts, image = args
        with self.assertRaises(ValueError):
            compile_restore_config(raw, identity, artifact, KEY, networks, mounts,
                image, commit_image_config(image, 'image-key', IMAGE_KEY), IMAGE_KEY,
                expected_image_key_id='image-key')
        result = compile_bound(args)
        self.assertEqual(args, before)
        self.assertEqual(result['schemaVersion'], 2)
        self.assertEqual(result['configFragment'], dict(raw['Config'], Image=artifact.image_id))
        self.assertEqual(result['imageReferenceRewrite']['from'], image['RepoDigests'][0])
        self.assertFalse(result['authorityGranted'] or result['executionAvailable']
                         or result['productionReady'] or result['reconstructionValidated']
                         or result['completeCreatePayloadAvailable'])
        self.assertFalse({'method', 'path', 'HostConfig', 'NetworkingConfig'} & result.keys())

    def test_full_source_hmac_and_merge_hazards_still_reject(self):
        args = reference_fixture()
        args[0]['Config']['Hostname'] = 'tampered'
        with self.assertRaises(ValueError):
            compile_bound(args)
        args = reference_fixture()
        args[-1]['Config']['Env'].append('MISSING=default')
        with self.assertRaises(ValueError):
            compile_bound(args)
        args = reference_fixture()
        args[0]['Config']['Image'] = 'other@sha256:' + 'c'*64
        args = (*args[:2], rebind(args[0], args[1], args[2]), *args[3:])
        with self.assertRaises(ValueError):
            compile_bound(args)

    def test_reference_proof_binds_whole_original_image_and_policy(self):
        args = reference_fixture()
        first = compile_bound(args)
        args[-1]['Config']['Cmd'] = ['different-unused-default']
        second = compile_bound(args)
        self.assertEqual(first['configFragment'], second['configFragment'])
        self.assertNotEqual(first['referenceBinding']['referenceBindingDigest'], second['referenceBinding']['referenceBindingDigest'])
        self.assertNotEqual(first['fragmentDigest'], second['fragmentDigest'])
        image = args[-1]
        image['RepoDigests'].append(args[2].registry_digest)
        with self.assertRaises(ValueError):
            # The source short name has not been selected in this new pin.
            compile_bound(args, expected_observed_reference=args[2].registry_digest)


if __name__ == '__main__':
    unittest.main()
