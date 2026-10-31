"""Temporary name derivations authenticate source intent but grant no write authority."""
from copy import deepcopy
import hashlib
import json
import unittest

from tests.test_deployment_compose_create import fixture
from deployment_compose_create import compile_create, DOMAIN as CREATE_DOMAIN, _encode, _digest
from deployment_compose_operations import CANDIDATE_DOMAIN
from deployment_compose_recipe_v3 import commit_recipe_v3
from deployment_compose_temporary import derive_temporary, verify_temporary, verify_temporary_operation, DOMAIN


class TemporaryTests(unittest.TestCase):
    key = b'temporary-test-only-key-material-32'

    def inputs(self):
        recipe, args = fixture()
        commitment = commit_recipe_v3(recipe, 'host-key-1', self.key)
        args.update(key=self.key, expected_key_id='host-key-1',
                    expected_recipe_hmac=commitment['hmac'], expected_project=recipe['project'],
                    expected_service=recipe['service'], expected_final_name=recipe['containerName'],
                    operation_nonce='a' * 64)
        return recipe, commitment, args

    def rejected(self, recipe, commitment, args):
        with self.assertRaisesRegex(ValueError, '^invalid-compose-temporary-derivation$'):
            derive_temporary(recipe, commitment, **args)

    def test_only_name_changes_and_original_recipe_is_retained_by_digest(self):
        recipe, commitment, args = self.inputs()
        before = deepcopy((recipe, commitment, args))
        result = derive_temporary(recipe, commitment, **args)
        source_args = {k: args[k] for k in ('baseline_image_id', 'image_defaults', 'identity',
                                           'network_ids', 'allowed_mounts', 'hostname')}
        source = compile_create(recipe, **source_args)
        temp = 'dwc-' + hashlib.sha256(CANDIDATE_DOMAIN + b'a' * 64 + b'\0' + recipe['service'].encode('ascii')).hexdigest()
        self.assertEqual(result['schemaVersion'], 1)
        self.assertEqual(result['temporaryName'], temp)
        self.assertEqual(result['finalName'], recipe['containerName'])
        self.assertEqual(result['sourceRecipeSchemaVersion'], 3)
        self.assertEqual(result['sourceRecipeCommitment'], commitment)
        self.assertEqual(result['sourceRecipeDigest'], _digest(recipe))
        self.assertEqual(result['sourceCandidateDigest'], source['candidateDigest'])
        self.assertEqual(_encode(result['candidate']['body']), _encode(source['body']))
        self.assertEqual(result['candidate']['path'], '/v1.45/containers/create?name=' + temp)
        self.assertEqual(result['candidate']['identity'], dict(args['identity'], containerName=temp))
        self.assertEqual((recipe, commitment, args), before)
        self.assertIsNone(verify_temporary(result, recipe, commitment, **args))
        self.assertEqual(result, derive_temporary(recipe, commitment, **args))

    def test_valid_distinct_final_names_share_candidate_but_not_derivation(self):
        recipe, commitment, args = self.inputs()
        first = derive_temporary(recipe, commitment, **args)
        recipe['containerName'] = 'blog-web-alternate'
        args['identity']['containerName'] = recipe['containerName']
        args['expected_final_name'] = recipe['containerName']
        commitment = commit_recipe_v3(recipe, args['expected_key_id'], self.key)
        args['expected_recipe_hmac'] = commitment['hmac']
        second = derive_temporary(recipe, commitment, **args)
        self.assertEqual(first['candidate']['candidateDigest'], second['candidate']['candidateDigest'])
        self.assertNotEqual(first['derivationDigest'], second['derivationDigest'])
        self.assertNotEqual(first['sourceCandidateDigest'], second['sourceCandidateDigest'])
        with self.assertRaises(ValueError):
            verify_temporary(first, recipe, commitment, **args)

    def test_no_authority_or_key_material_in_result(self):
        recipe, commitment, args = self.inputs()
        result = derive_temporary(recipe, commitment, **args)
        for envelope in (result, result['candidate']):
            for field in ('authorityGranted', 'executionAvailable', 'productionReady', 'reconstructionValidated'):
                self.assertIs(envelope[field], False)
        for blocker in ('v3-request-review-integration-required', 'receipt-plan-binding-required',
                        'independent-anchor-required', 'independent-write-authorization-required'):
            self.assertIn(blocker, result['blockers'])
        self.assertNotIn(self.key, _encode(result))
        # The candidate is deliberately private and may contain Env; errors must not echo it.
        args['expected_project'] = 'wrong-project'
        self.rejected(recipe, commitment, args)

    def test_wrong_independent_pins_and_key_are_rejected(self):
        for field, value in (('key', b'x' * 32), ('expected_key_id', 'other-key'),
                             ('expected_recipe_hmac', 'f' * 64), ('expected_project', 'other'),
                             ('expected_service', 'other'), ('expected_final_name', 'other')):
            with self.subTest(field=field):
                recipe, commitment, args = self.inputs()
                args[field] = value
                self.rejected(recipe, commitment, args)
        for mutate in (lambda c: c.update(keyId='other-key'), lambda c: c.update(hmac='f' * 64),
                       lambda c: c.update(extra='secret'), lambda c: c.pop('hmac')):
            recipe, commitment, args = self.inputs()
            mutate(commitment)
            self.rejected(recipe, commitment, args)

    def test_nonce_requires_exact_lowercase_hex_and_changes_derivation(self):
        for nonce in (None, True, 1, '', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, 'a' * 64 + '\n'):
            with self.subTest(nonce=nonce):
                recipe, commitment, args = self.inputs()
                args['operation_nonce'] = nonce
                self.rejected(recipe, commitment, args)
        recipe, commitment, args = self.inputs()
        first = derive_temporary(recipe, commitment, **args)
        args['operation_nonce'] = 'b' * 64
        second = derive_temporary(recipe, commitment, **args)
        self.assertNotEqual(first['temporaryName'], second['temporaryName'])
        self.assertNotEqual(first['derivationDigest'], second['derivationDigest'])

    def test_source_version_and_tampering_cannot_be_upgraded_or_ignored(self):
        for mutate in (lambda r: r.update(schemaVersion=2),
                       lambda r: r['process']['env'].append('PRIVATE=secret'),
                       lambda r: r.update(containerName='other'),
                       lambda r: r.update(unknown='private-secret')):
            recipe, commitment, args = self.inputs()
            mutate(recipe)
            self.rejected(recipe, commitment, args)

    def test_bad_image_identity_topology_and_mount_inputs_are_rejected(self):
        for mutate in (lambda a: a.update(baseline_image_id='sha256:' + 'f' * 64),
                       lambda a: a['image_defaults'].update(ImageId='sha256:' + 'f' * 64),
                       lambda a: a['image_defaults'].update(Env=['UNAPPROVED=secret']),
                       lambda a: a['identity'].update(containerName='wrong'),
                       lambda a: a['identity'].update(project='wrong'),
                       lambda a: a.update(network_ids={}),
                       lambda a: a.update(allowed_mounts=[])):
            recipe, commitment, args = self.inputs()
            mutate(args)
            self.rejected(recipe, commitment, args)

    def test_self_rehashed_forgery_never_verifies(self):
        for mutate in (lambda d: d.update(finalName='other'),
                       lambda d: d.update(sourceRecipeDigest='f' * 64),
                       lambda d: d.update(authorityGranted=True),
                       lambda d: d.update(blockers=[]),
                       lambda d: d['candidate'].update(path='/v1.45/containers/create?name=forged'),
                       lambda d: d['candidate']['body'].update(Env=['API_KEY=forged']),
                       lambda d: d['candidate']['identity'].update(daemonId='other')):
            recipe, commitment, args = self.inputs()
            result = derive_temporary(recipe, commitment, **args)
            mutate(result)
            candidate = result['candidate']
            candidate.pop('candidateDigest')
            candidate['candidateDigest'] = hashlib.sha256(CREATE_DOMAIN + _encode(candidate)).hexdigest()
            result.pop('derivationDigest')
            result['derivationDigest'] = hashlib.sha256(DOMAIN + _encode(result)).hexdigest()
            with self.assertRaisesRegex(ValueError, '^invalid-compose-temporary-derivation$'):
                verify_temporary(result, recipe, commitment, **args)

    def test_operation_requires_exact_tuple_and_canonical_body_hash(self):
        recipe, commitment, args = self.inputs()
        result = derive_temporary(recipe, commitment, **args)
        candidate = result['candidate']
        operation = (candidate['method'], candidate['path'],
                     hashlib.sha256(_encode(candidate['body'])).hexdigest())
        before = deepcopy((result, recipe, commitment, args))
        self.assertIsNone(verify_temporary_operation(result, recipe, commitment,
                                                    operation=operation, **args))
        alternate_wire_hash = hashlib.sha256(json.dumps(candidate['body'], indent=2).encode()).hexdigest()
        self.assertNotEqual(alternate_wire_hash, operation[2])
        bad_operations = [
            ('GET', operation[1], operation[2]),
            (operation[0], '/v1.45/containers/create?name=wrong', operation[2]),
            (operation[0], '/v1.45/containers/' + 'f' * 64 + '/start', operation[2]),
            (operation[0], operation[1], 'f' * 64),
            (operation[0], operation[1], alternate_wire_hash),
            list(operation), operation[:2], (*operation, 'extra'),
        ]
        for bad in bad_operations:
            with self.subTest(operation=bad), self.assertRaisesRegex(
                    ValueError, '^invalid-compose-temporary-derivation$'):
                verify_temporary_operation(result, recipe, commitment, operation=bad, **args)
        self.assertEqual((result, recipe, commitment, args), before)

    def test_matching_forged_operation_cannot_validate_rehashed_derivation(self):
        recipe, commitment, args = self.inputs()
        result = derive_temporary(recipe, commitment, **args)
        result['candidate']['body']['Env'].append('FORGED=private-value')
        candidate = result['candidate']
        candidate.pop('candidateDigest')
        candidate['candidateDigest'] = hashlib.sha256(CREATE_DOMAIN + _encode(candidate)).hexdigest()
        result.pop('derivationDigest')
        result['derivationDigest'] = hashlib.sha256(DOMAIN + _encode(result)).hexdigest()
        operation = (candidate['method'], candidate['path'],
                     hashlib.sha256(_encode(candidate['body'])).hexdigest())
        before = deepcopy((result, recipe, commitment, args))
        with self.assertRaisesRegex(ValueError, '^invalid-compose-temporary-derivation$'):
            verify_temporary_operation(result, recipe, commitment, operation=operation, **args)
        self.assertEqual((result, recipe, commitment, args), before)

    def test_output_and_verifier_do_not_mutate_or_alias_inputs(self):
        recipe, commitment, args = self.inputs()
        result = derive_temporary(recipe, commitment, **args)
        pristine = deepcopy((result, recipe, commitment, args))
        verify_temporary(result, recipe, commitment, **args)
        self.assertEqual((result, recipe, commitment, args), pristine)
        result['candidate']['body']['Env'].append('OUTPUT=changed')
        result['sourceRecipeCommitment']['hmac'] = 'f' * 64
        self.assertEqual((recipe, commitment, args), pristine[1:])
        rebuilt = derive_temporary(recipe, commitment, **args)
        recipe['process']['env'].append('INPUT=changed')
        args['identity']['daemonId'] = 'changed'
        self.assertEqual(rebuilt, pristine[0])


if __name__ == '__main__':
    unittest.main()
