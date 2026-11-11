"""Compatibility pins for already distributed release and deployment requests.

New platform/profile contracts must use a new version rather than changing the
meaning of an existing approval digest.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/release/scripts'))
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))

import release_execute as release
import deployment_authorize as deployment
import deployment_execute as execution
import deployment_runtime as runtime
import deployment_spec as specification


class ProviderContractV1Tests(unittest.TestCase):
    def test_github_release_request_digest_is_stable(self):
        request = release.Request(
            'remote-tag-push', '/candidate', 'a' * 40, 'HEAD', 'b' * 40,
            'c' * 64, 'v1.2.3', 'b' * 40, 'origin',
            'https://github.com/example/repo.git', None, 'd' * 64)
        self.assertEqual(request.digest(),
                         '17017103ce031566a5dd779beac6fd7192deda486ba0890b311c9241e57c18db')

    def test_docker_deployment_request_digest_is_stable(self):
        request = deployment.Request(
            'deployment-deploy', '/candidate', 'example/repo', 123, 'a' * 40,
            'b' * 64, 'staging', 'primary', False, ('web',), '{}', '{}', '{}',
            'c' * 64, 'd' * 64, 'e' * 64, 'f' * 64,
            '2026-10-24T00:00:00+00:00')
        self.assertEqual(request.digest(),
                         'fa29a7cfa630b58acfaf800e1f573edbe30f000df388f2cc6ba717df572cfee2')

    def test_docker_runtime_and_execution_policy_hashes_are_stable(self):
        image = {'Os': 'linux', 'Id': 'sha256:' + 'a' * 64,
                 'Config': {'Cmd': ['/server'], 'User': '10001', 'Env': [],
                            'WorkingDir': '/app', 'Labels': {}, 'ExposedPorts': {}}}
        spec = specification.ContainerSpec.from_image('web', image, network_mode='fixture_default')
        entry = {'component': 'web', 'imageId': 'sha256:' + 'a' * 64,
                 'repository': 'example/repo', 'sourceSha': 'b' * 40, 'version': '1.0.0',
                 'os': 'linux', 'architecture': 'amd64',
                 'artifact': {'kind': 'local-build', 'imageId': 'sha256:' + 'a' * 64,
                              'buildSourceSha': 'b' * 40},
                 'migration': {'mode': 'none', 'version': None}}
        policy = runtime.RuntimePolicy(
            'https://localhost:2376', 'c' * 64, 'fixture-daemon', 'example/repo',
            'staging', 'primary', False, 'fixture', ('web',),
            runtime.canonical({'schemaVersion': 1, 'images': [entry]}),
            specifications_json=specification.specifications_json((spec,)))
        self.assertEqual(policy.identity_hash(),
                         'a4d1fe1ac5764c02870f46bcd9f0a9817329bee610007bae6a69286e8213646e')
        self.assertEqual(execution.ExecutionPolicy(policy, 'd' * 64).identity_hash(),
                         '3580ba675e2ec6e30200a66a822d0ab2d60b0f5d88090317d33236fa8dd70500')
        self.assertEqual(execution.ExecutionPolicy(
            policy, 'd' * 64, verification_policy_hash='e' * 64,
            history_policy_hash='f' * 64, gateway_policy_hash='1' * 64).identity_hash(),
            '3fd44f9460b87fd1ca6ff34b0a4068b8e8cf94482ad57cd50402a7d9a40fb23d')


if __name__ == '__main__':
    unittest.main()
