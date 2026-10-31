"""Restricted value fixtures are not Engine reconstruction evidence."""
from copy import deepcopy
import unittest

from tests.test_deployment_compose_baseline_recipe import fixture as v2_fixture
from deployment_compose_baseline_recipe import verify_baseline_recipe
from deployment_compose_baseline_recipe_v3 import verify_baseline_recipe_v3


def fixture():
    projection, recipe = v2_fixture()
    recipe['schemaVersion'] = 3
    host = recipe['hostConfig']
    host['restartPolicy'] = {'name': 'unless-stopped', 'maximumRetryCount': 0}
    host['resources'] = {'memoryBytes': 67108864, 'memorySwapBytes': 67108864,
                         'nanoCpus': 100000000, 'pidsLimit': 32}
    host['logConfig'] = {'type': 'json-file', 'config': {'max-size': '2m', 'max-file': '2'}}
    projection['HostConfig'].update(
        RestartPolicy={'Name': 'unless-stopped', 'MaximumRetryCount': 0},
        LogConfig={'Type': 'json-file', 'Config': {'max-size': '2m', 'max-file': '2'}},
        Memory=67108864, MemorySwap=67108864, NanoCpus=100000000, PidsLimit=32)
    return projection, recipe


def verify(projection, recipe):
    return verify_baseline_recipe_v3(projection, recipe, project='blog', service='web',
        container_name='blog-web-1', image_id='sha256:' + 'a' * 64)


class BaselineRecipeV3Tests(unittest.TestCase):
    def test_values_match_without_mutating_originals(self):
        projection, recipe = fixture()
        before = deepcopy((projection, recipe))
        self.assertIsNone(verify(projection, recipe))
        self.assertEqual((projection, recipe), before)

    def test_no_restart_and_none_logging_also_match(self):
        projection, recipe = fixture()
        projection['HostConfig']['RestartPolicy']['Name'] = 'no'
        recipe['hostConfig']['restartPolicy']['name'] = 'no'
        projection['HostConfig']['LogConfig'] = {'Type': 'none', 'Config': {}}
        recipe['hostConfig']['logConfig'] = {'type': 'none', 'config': {}}
        self.assertIsNone(verify(projection, recipe))

    def test_v2_still_rejects_v3(self):
        projection, recipe = fixture()
        with self.assertRaises(ValueError):
            verify_baseline_recipe(projection, recipe, project='blog', service='web',
                container_name='blog-web-1', image_id='sha256:' + 'a' * 64)

    def test_missing_changed_and_type_confused_resources_rejected(self):
        for field in ('Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit'):
            for value in (None, True, 1.0, '32', 0, 999):
                projection, recipe = fixture()
                if value is None:
                    del projection['HostConfig'][field]
                else:
                    projection['HostConfig'][field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                        ValueError, '^baseline-v3-recipe-not-representable$'):
                    verify(projection, recipe)

    def test_restart_and_logging_drift_rejected(self):
        changes = [
            lambda h: h['RestartPolicy'].update(Name='no'),
            lambda h: h['RestartPolicy'].update(MaximumRetryCount=False),
            lambda h: h['RestartPolicy'].update(unknown=0),
            lambda h: h['LogConfig']['Config'].update({'max-file': '3'}),
            lambda h: h['LogConfig']['Config'].update({'max-size': 2}),
            lambda h: h['LogConfig'].update(unknown=False),
        ]
        for change in changes:
            projection, recipe = fixture()
            change(projection['HostConfig'])
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify(projection, recipe)

    def test_unknown_and_semantic_drift_on_all_surfaces_rejected(self):
        changes = [
            lambda p: p.update(unknown=False),
            lambda p: p['Config'].update(unknown=False),
            lambda p: p['Config']['Labels'].update(extra='label'),
            lambda p: p['HostConfig'].update(MemoryReservation=1),
            lambda p: p['HostConfig']['Mounts'][0]['VolumeOptions'].update(NoCopy=False),
            lambda p: p['Mounts'][0].update(unknown=False),
            lambda p: p['Mounts'][1].update(RW=True),
            lambda p: p['NetworkSettings'].update(unknown=False),
            lambda p: p['NetworkSettings']['Networks']['blog_default'].update(unknown=False),
            lambda p: p['NetworkSettings']['Networks']['blog_default'].update(Aliases=['other']),
        ]
        for change in changes:
            projection, recipe = fixture()
            change(projection)
            before = deepcopy((projection, recipe))
            with self.subTest(change=change), self.assertRaisesRegex(
                    ValueError, '^baseline-v3-recipe-not-representable$'):
                verify(projection, recipe)
            self.assertEqual((projection, recipe), before)

    def test_recipe_identity_schema_and_value_drift_rejected(self):
        changes = [
            lambda r: r.update(schemaVersion=2),
            lambda r: r.update(schemaVersion=True),
            lambda r: r.update(project='other'),
            lambda r: r.update(service='other'),
            lambda r: r.update(containerName='other'),
            lambda r: r.update(imageId='sha256:' + 'b' * 64),
            lambda r: r['hostConfig']['resources'].update(pidsLimit=True),
            lambda r: r['hostConfig']['resources'].update(pidsLimit=33),
            lambda r: r['hostConfig']['restartPolicy'].update(name='no'),
            lambda r: r['hostConfig']['logConfig']['config'].update({'max-file': '3'}),
            lambda r: r['hostConfig'].update(extra=False),
            lambda r: r['process'].update(cmd=['other']),
        ]
        for change in changes:
            projection, recipe = fixture()
            change(recipe)
            with self.subTest(change=change), self.assertRaisesRegex(
                    ValueError, '^baseline-v3-recipe-not-representable$'):
                verify(projection, recipe)


if __name__ == '__main__':
    unittest.main()
