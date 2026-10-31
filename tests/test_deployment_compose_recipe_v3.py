"""Offline v3 contract tests; these do not prove Engine reconstruction."""
from copy import deepcopy
import hashlib
import hmac
import json
import unittest

from tests.test_deployment_compose_recipe import recipe
from deployment_compose_recipe import DOMAIN as DOMAIN_V2, verify_recipe
from deployment_compose_recipe_v3 import canonical_recipe_v3, commit_recipe_v3, verify_recipe_v3


def value():
    result = recipe()
    result['schemaVersion'] = 3
    result['hostConfig'].update(
        restartPolicy={'name': 'unless-stopped', 'maximumRetryCount': 0},
        resources={'memoryBytes': 67108864, 'memorySwapBytes': 67108864,
                   'nanoCpus': 100000000, 'pidsLimit': 32},
        logConfig={'type': 'json-file', 'config': {'max-size': '10m', 'max-file': '3'}},
    )
    return result


class RecipeV3Tests(unittest.TestCase):
    key = b'k' * 32

    def test_observed_limits_and_independent_hmac(self):
        original = value()
        raw = json.dumps(original, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        self.assertEqual(canonical_recipe_v3(original), raw)
        prefix = (10).to_bytes(2, 'big') + b'host-key-1' + raw
        result = commit_recipe_v3(original, 'host-key-1', self.key)
        self.assertEqual(result['hmac'], hmac.new(self.key, b'dev-workflow:compose-target-recipe:v3\0' + prefix, hashlib.sha256).hexdigest())
        self.assertNotEqual(result['hmac'], hmac.new(self.key, DOMAIN_V2 + prefix, hashlib.sha256).hexdigest())
        self.assertTrue(verify_recipe_v3(original, result, self.key))
        with self.assertRaises(ValueError):
            verify_recipe(original, result, self.key)
        self.assertEqual(original, value())

    def test_reject_versions_and_shapes(self):
        for version in (2, True, '3', 3.0):
            candidate = value()
            candidate['schemaVersion'] = version
            with self.assertRaises(ValueError):
                canonical_recipe_v3(candidate)
        for field in ('restartPolicy', 'resources', 'logConfig'):
            for operation in ('missing', 'extra'):
                candidate = value()
                if operation == 'missing':
                    candidate['hostConfig'].pop(field)
                else:
                    candidate['hostConfig'][field]['unexpected'] = 1
                with self.assertRaises(ValueError):
                    canonical_recipe_v3(candidate)

    def test_strict_resource_bounds(self):
        for field, upper in (('memoryBytes', 1 << 30), ('memorySwapBytes', 1 << 30), ('nanoCpus', 10**9), ('pidsLimit', 256)):
            for bad in (True, False, 0, -1, upper + 1, '32', 32.0, None):
                candidate = value()
                candidate['hostConfig']['resources'][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                    canonical_recipe_v3(candidate)
            for operation in ('missing', 'extra'):
                candidate = value()
                if operation == 'missing':
                    candidate['hostConfig']['resources'].pop(field)
                else:
                    candidate['hostConfig']['resources']['extra'] = 1
                with self.assertRaises(ValueError):
                    canonical_recipe_v3(candidate)
        candidate = value()
        candidate['hostConfig']['resources']['memorySwapBytes'] += 1
        with self.assertRaises(ValueError):
            canonical_recipe_v3(candidate)

    def test_strict_restart_and_logging(self):
        for restart in ({'name': 'always', 'maximumRetryCount': 0}, {'name': 'no', 'maximumRetryCount': True}, {'name': 'unless-stopped', 'maximumRetryCount': 1}, {'name': 'no'}, {}):
            candidate = value()
            candidate['hostConfig']['restartPolicy'] = restart
            with self.assertRaises(ValueError):
                canonical_recipe_v3(candidate)
        for size in ('0m', '101m', '01m', '1g', '10M', 10, True):
            candidate = value()
            candidate['hostConfig']['logConfig']['config']['max-size'] = size
            with self.assertRaises(ValueError):
                canonical_recipe_v3(candidate)
        for count in ('0', '11', '01', 3, True):
            candidate = value()
            candidate['hostConfig']['logConfig']['config']['max-file'] = count
            with self.assertRaises(ValueError):
                canonical_recipe_v3(candidate)
        for config in ({}, {'max-size': '1m'}, {'max-size': '1m', 'max-file': '1', 'compress': 'true'}):
            candidate = value()
            candidate['hostConfig']['logConfig']['config'] = config
            with self.assertRaises(ValueError):
                canonical_recipe_v3(candidate)

    def test_every_added_surface_is_committed(self):
        original = value()
        commitment = commit_recipe_v3(original, 'host-key-1', self.key)
        changes = [lambda x: x['hostConfig']['restartPolicy'].update(name='no'),
                   lambda x: x['hostConfig']['resources'].update(pidsLimit=64),
                   lambda x: x['hostConfig']['logConfig']['config'].update({'max-size': '1m'}),
                   lambda x: x['hostConfig'].update(logConfig={'type': 'none', 'config': {}}),
                   lambda x: x['process'].update(cmd=['changed'])]
        for change in changes:
            candidate = deepcopy(original)
            change(candidate)
            self.assertFalse(verify_recipe_v3(candidate, commitment, self.key))


if __name__ == '__main__':
    unittest.main()
