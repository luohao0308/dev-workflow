"""Complete image Config commitments do not confer execution authority."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_image_defaults import commit_image_config, derive_defaults, ZERO_DEFAULTS
from deployment_compose_create import DEFAULT_FIELDS

KEY = b'k' * 32
REF = 'registry.example/team/image@sha256:' + 'a' * 64


def image():
    return {'Id': 'sha256:' + 'b' * 64, 'Os': 'linux', 'Architecture': 'amd64',
            'RepoDigests': [REF], 'Config': {'Env': ['SECRET=private'], 'Cmd': ['sh']}}


def derive(value, commitment=None, **overrides):
    args = dict(expected_image_id=value['Id'], expected_registry_digest=REF,
                expected_architecture='amd64')
    args.update(overrides)
    return derive_defaults(value, commitment or commit_image_config(value, 'host', KEY), KEY, **args)


class ImageDefaultsTests(unittest.TestCase):
    def test_key_identity_cannot_be_relabelled(self):
        value = image()
        proof = commit_image_config(value, 'host', KEY)
        self.assertNotEqual(proof['imageConfigHmac'], commit_image_config(value, 'other', KEY)['imageConfigHmac'])
        proof['keyId'] = 'other'
        with self.assertRaises(ValueError):
            derive(value, proof)

    def test_projection_uses_explicit_omission_policy(self):
        value = image()
        result = derive(value)
        self.assertEqual(set(result), DEFAULT_FIELDS)
        for field, zero in ZERO_DEFAULTS.items():
            self.assertEqual(result[field], value['Config'][field] if field in value['Config'] else zero)
        result['Env'].append('MUTATED=value')
        self.assertEqual(value['Config']['Env'], ['SECRET=private'])

    def test_short_engine_digest_is_bound_literally(self):
        value = image()
        short = 'python@sha256:' + 'a' * 64
        value['RepoDigests'] = [short]
        self.assertEqual(derive(value, expected_registry_digest=short)['ImageId'], value['Id'])
        with self.assertRaises(ValueError):
            derive(value, expected_registry_digest='docker.io/library/' + short)

    def test_null_and_empty_remain_distinct(self):
        value = image()
        for field, zero in ZERO_DEFAULTS.items():
            for candidate in (None, [] if field in ('Env', 'Cmd', 'Entrypoint') else
                              {} if field in ('Labels', 'Volumes', 'ExposedPorts', 'Healthcheck') else ''):
                value['Config'][field] = candidate
                self.assertEqual(derive(value)[field], candidate)

    def test_unknown_config_committed_but_cannot_project(self):
        value = image()
        original = commit_image_config(value, 'host', KEY)
        value['Config']['FutureMerge'] = 'private'
        changed = commit_image_config(value, 'host', KEY)
        self.assertNotEqual(original['imageConfigHmac'], changed['imageConfigHmac'])
        for proof in (original, changed):
            with self.assertRaisesRegex(ValueError, '^invalid-compose-image-defaults$'):
                derive(value, proof)

    def test_legacy_empty_image_field_is_committed_and_only_empty_string_projects(self):
        value = image()
        original = commit_image_config(value, 'host', KEY)
        value['Config']['Image'] = ''
        changed = commit_image_config(value, 'host', KEY)
        self.assertNotEqual(original['imageConfigHmac'], changed['imageConfigHmac'])
        with self.assertRaises(ValueError):
            derive(value, original)
        self.assertEqual(derive(value, changed)['ImageId'], value['Id'])
        for invalid in (None, False, 0, [], {}, 'sha256:' + 'f' * 64):
            value['Config']['Image'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                derive(value)

    def test_tamper_wrong_key_and_scope_fail(self):
        baseline = image()
        proof = commit_image_config(baseline, 'host', KEY)
        for field, replacement in [('Id', 'sha256:' + 'c' * 64), ('Os', 'windows'),
                                   ('Architecture', 'arm64'), ('RepoDigests', [REF.replace('team', 'foreign')]),
                                   ('Config', {'Env': ['SECRET=changed']})]:
            value = deepcopy(baseline); value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                derive(value, proof)
        with self.assertRaises(ValueError):
            derive_defaults(baseline, proof, b'x' * 32, expected_image_id=baseline['Id'],
                            expected_registry_digest=REF, expected_architecture='amd64')
        for override in ({'expected_image_id': 'sha256:' + 'c' * 64},
                         {'expected_registry_digest': REF.replace('team', 'foreign')},
                         {'expected_architecture': 'arm64'}):
            with self.assertRaises(ValueError):
                derive(baseline, **override)

    def test_commitment_and_errors_never_disclose_env(self):
        value = image()
        proof = commit_image_config(value, 'host', KEY)
        self.assertNotIn('SECRET', str(proof)); self.assertNotIn('private', str(proof))
        self.assertIs(proof['authorityGranted'], False)
        value['Config']['Env'] = object()
        with self.assertRaisesRegex(ValueError, '^invalid-compose-image-defaults$'):
            commit_image_config(value, 'host', KEY)

    def test_bounded_plain_json_and_inert_fields(self):
        for invalid in (float('nan'), (1,), {1: 'x'}, 'x' * 65537):
            value = image(); value['Config']['Future'] = invalid
            with self.assertRaises(ValueError):
                commit_image_config(value, 'host', KEY)
        value = image(); value['Config']['Tty'] = False
        derive(value)
        value['Config']['Tty'] = True
        with self.assertRaises(ValueError):
            derive(value)
        value['Config']['Tty'] = 0
        with self.assertRaises(ValueError):
            derive(value)

    def test_all_metadata_and_full_config_are_bound(self):
        value = image(); proof = commit_image_config(value, 'host', KEY)
        value['Config']['Labels'] = {}
        self.assertNotEqual(proof, commit_image_config(value, 'host', KEY))
        value = image(); value['UnrelatedRoot'] = object()
        self.assertEqual(proof, commit_image_config(value, 'host', KEY))


if __name__ == '__main__':
    unittest.main()
