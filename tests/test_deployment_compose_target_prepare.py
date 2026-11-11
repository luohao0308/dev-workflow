"""Host-private target preparation must bind actual recipe values to intent."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
from deployment_compose_recipe import commit_recipe
from deployment_compose_target_artifacts import ComposeTargetArtifacts, ServiceTargetArtifact
from deployment_compose_target_prepare import verify_target_recipes
from deployment_contract_v2 import TargetIdentity
from tests.test_deployment_compose_recipe import recipe as recipe_fixture
from tests.test_deployment_compose_target_artifacts import request as request_fixture


KEY = b'host-private-recipe-key-' + b'x' * 32


def fixture(operation='deploy'):
    value = recipe_fixture()
    commitment = commit_recipe(value, 'host-key-1', KEY)
    item = ServiceTargetArtifact('web', 'a' * 40,
        'registry.example.test/team/web@sha256:' + 'a' * 64,
        value['imageId'], 'linux', 'amd64', 'host-key-1',
        commitment['hmac'], '0' * 64, 'none')
    manifest = ComposeTargetArtifacts(1, (item,))
    request = replace(request_fixture(manifest, operation),
                      target=TargetIdentity('compose', 'blog', 'stack'))
    return request, manifest, {'web': value}


def two_service_fixture(*, alias='api', host_port=18081, host_ip='127.0.0.1'):
    request, manifest, recipes = fixture()
    api = deepcopy(recipes['web'])
    api.update(service='api', containerName='blog-api-1', imageId='sha256:' + 'b' * 64)
    api['networks'][0]['aliases'] = [alias]
    api['ports'][0].update(hostIp=host_ip, hostPort=host_port)
    api_hmac = commit_recipe(api, 'host-key-1', KEY)['hmac']
    api_artifact = ServiceTargetArtifact('api', 'a' * 40,
        'registry.example.test/team/api@sha256:' + 'b' * 64,
        api['imageId'], 'linux', 'amd64', 'host-key-1', api_hmac, '0' * 64, 'none')
    both = ComposeTargetArtifacts(1, (api_artifact, manifest.services[0]))
    request = replace(request_fixture(both), target=TargetIdentity('compose', 'blog', 'stack'))
    return request, both, {'api': api, 'web': recipes['web']}


class TargetPreparationTests(unittest.TestCase):
    def test_deploy_and_rollback_target_recompute_private_recipe(self):
        for operation in ('deploy', 'rollback'):
            request, manifest, recipes = fixture(operation)
            verify_target_recipes(request, manifest, recipes,
                                  container_names={'web': 'blog-web-1'},
                                  keys={'host-key-1': KEY})

    def test_recipe_value_or_key_drift_is_rejected(self):
        request, manifest, recipes = fixture()
        changed = deepcopy(recipes)
        changed['web']['process']['env'][0] = 'API_KEY=other-secret'
        with self.assertRaisesRegex(ValueError, '^target-recipe-commitment-mismatch$'):
            verify_target_recipes(request, manifest, changed,
                                  container_names={'web': 'blog-web-1'},
                                  keys={'host-key-1': KEY})
        with self.assertRaisesRegex(ValueError, '^target-recipe-commitment-mismatch$'):
            verify_target_recipes(request, manifest, recipes,
                                  container_names={'web': 'blog-web-1'},
                                  keys={'host-key-1': b'z' * 32})

    def test_target_identity_and_scope_are_host_bound(self):
        request, manifest, recipes = fixture()
        for changed in (
            {'web': dict(recipes['web'], imageId='sha256:' + 'f' * 64)},
            {'web': dict(recipes['web'], project='other')},
            {'web': dict(recipes['web'], containerName='other')},
            {'extra': recipes['web']},
        ):
            with self.subTest(changed=list(changed)), self.assertRaises(ValueError):
                verify_target_recipes(request, manifest, changed,
                                      container_names={'web': 'blog-web-1'},
                                      keys={'host-key-1': KEY})
        with self.assertRaises(ValueError):
            verify_target_recipes(request, manifest, recipes,
                                  container_names={'web': 'other'}, keys={'host-key-1': KEY})
        with self.assertRaises(ValueError):
            verify_target_recipes(request, manifest, recipes,
                                  container_names={'web': 'blog-web-1'}, keys={})

    def test_cross_type_and_wrong_target_digest_never_become_authority(self):
        request, manifest, recipes = fixture()
        with self.assertRaises(ValueError):
            verify_target_recipes(replace(request, artifact_digest='f' * 64), manifest, recipes,
                                  container_names={'web': 'blog-web-1'}, keys={'host-key-1': KEY})
        self.assertIsNone(verify_target_recipes(request, manifest, recipes,
            container_names={'web': 'blog-web-1'}, keys={'host-key-1': KEY}))

    def test_batch_level_name_alias_and_host_port_collisions(self):
        names = {'api': 'blog-api-1', 'web': 'blog-web-1'}
        request, manifest, recipes = two_service_fixture()
        verify_target_recipes(request, manifest, recipes, container_names=names,
                              keys={'host-key-1': KEY})
        with self.assertRaisesRegex(ValueError, '^invalid-target-recipe-scope$'):
            verify_target_recipes(request, manifest, recipes,
                                  container_names={'api': 'blog-web-1', 'web': 'blog-web-1'},
                                  keys={'host-key-1': KEY})
        request, manifest, recipes = two_service_fixture(alias='web')
        with self.assertRaisesRegex(ValueError, '^target-network-alias-collision$'):
            verify_target_recipes(request, manifest, recipes, container_names=names,
                                  keys={'host-key-1': KEY})
        request, manifest, recipes = two_service_fixture(host_port=18080, host_ip='0.0.0.0')
        with self.assertRaisesRegex(ValueError, '^target-host-port-collision$'):
            verify_target_recipes(request, manifest, recipes, container_names=names,
                                  keys={'host-key-1': KEY})


if __name__ == '__main__':
    unittest.main()
