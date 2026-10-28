"""Private Compose recipe value tests; no Docker execution authority."""
from copy import deepcopy
import hashlib
import hmac
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs' / 'deployment' / 'scripts'))
from deployment_compose_recipe import DOMAIN, canonical_recipe, commit_recipe, verify_recipe


def recipe():
    return {
        'schemaVersion': 2, 'project': 'blog', 'service': 'web',
        'containerName': 'blog-web-1', 'imageId': 'sha256:' + 'a' * 64,
        'process': {'user': '1000:1000', 'workingDir': '/app',
                    'entrypoint': ['/app/server'], 'cmd': ['--port=8080'],
                    'env': ['API_KEY=private-value', 'MODE=staging']},
        'hostConfig': {'privileged': False, 'readOnlyRootfs': True,
                       'capAdd': [], 'devices': [], 'pidMode': 'private', 'ipcMode': 'private',
                       'logConfig': {'type': 'none', 'config': {}}},
        'mounts': [{'type': 'volume', 'source': 'blog-data', 'target': '/data',
                    'readOnly': False, 'noCopy': True, 'createHostPath': False},
                   {'type': 'bind', 'source': '/srv/blog/config.json', 'target': '/etc/config.json',
                    'readOnly': True, 'noCopy': False, 'createHostPath': False}],
        'networks': [{'id': 'b' * 64, 'aliases': ['web']}],
        'ports': [{'hostIp': '127.0.0.1', 'hostPort': 18080,
                   'containerPort': 8080, 'protocol': 'tcp'}],
        'health': {'test': ['CMD', '/app/health'], 'intervalNs': 1000000000,
                   'timeoutNs': 1000000000, 'retries': 3},
    }


class ComposeRecipeTests(unittest.TestCase):
    def setUp(self):
        self.key = b'k' * 32

    def test_v1_and_implicit_logging_recipe_are_rejected(self):
        value = recipe()
        value['schemaVersion'] = 1
        with self.assertRaises(ValueError):
            canonical_recipe(value)
        value = recipe()
        value['hostConfig'].pop('logConfig')
        with self.assertRaises(ValueError):
            canonical_recipe(value)
        value = recipe()
        value['hostConfig']['logConfig'] = {'type': 'json-file', 'config': {}}
        with self.assertRaises(ValueError):
            canonical_recipe(value)

    def test_private_commitment_and_domain_separation(self):
        value = recipe()
        result = commit_recipe(value, 'host-key-1', self.key)
        self.assertEqual(set(result), {'keyId', 'hmac'})
        self.assertNotIn('private-value', repr(result))
        self.assertTrue(verify_recipe(value, result, self.key))
        raw = canonical_recipe(value)
        self.assertNotEqual(result['hmac'], hmac.new(self.key, raw, hashlib.sha256).hexdigest())
        self.assertNotEqual(result['hmac'], hmac.new(self.key, b'dev-workflow:runtime-private:v1\0' + raw,
                                                    hashlib.sha256).hexdigest())
        self.assertEqual(result['hmac'], hmac.new(self.key, DOMAIN + (10).to_bytes(2, 'big')
                                                 + b'host-key-1' + raw, hashlib.sha256).hexdigest())
        relabeled = dict(result, keyId='other-key')
        self.assertFalse(verify_recipe(value, relabeled, self.key))

    def test_drift_in_each_runtime_surface_changes_commitment(self):
        base = recipe()
        mutations = [
            ('image', lambda x: x.update(imageId='sha256:' + 'c' * 64)),
            ('process', lambda x: x['process']['env'].__setitem__(0, 'API_KEY=changed')),
            ('host', lambda x: x['hostConfig'].update(readOnlyRootfs=False)),
            ('mount', lambda x: x['mounts'][0].update(readOnly=True)),
            ('network', lambda x: x['networks'][0].update(id='c' * 64)),
            ('alias', lambda x: x['networks'][0].update(aliases=['other'])),
            ('port', lambda x: x['ports'][0].update(hostPort=18081)),
            ('health', lambda x: x['health'].update(retries=4)),
        ]
        first = commit_recipe(base, 'host-key-1', self.key)
        for label, change in mutations:
            with self.subTest(label=label):
                altered = deepcopy(base)
                change(altered)
                self.assertFalse(verify_recipe(altered, first, self.key))

    def test_explicit_docker_defaults_and_writable_rootfs(self):
        value = recipe()
        value['process'].update(user='', workingDir='', entrypoint=[], cmd=[])
        value['hostConfig']['readOnlyRootfs'] = False
        commitment = commit_recipe(value, 'host-key-1', self.key)
        self.assertTrue(verify_recipe(value, commitment, self.key))
        value['hostConfig']['readOnlyRootfs'] = 'false'
        with self.assertRaises(ValueError):
            commit_recipe(value, 'host-key-1', self.key)

    def test_rejects_unknown_hooks_and_mutable_image(self):
        for path, key, val in [('root', 'build', '.'), ('root', 'postDeploy', 'echo hi'),
                               ('process', 'hook', 'sh'), ('hostConfig', 'capabilities', ['ALL'])]:
            altered = recipe()
            target = altered if path == 'root' else altered[path]
            target[key] = val
            with self.subTest(path=path, key=key), self.assertRaises(ValueError):
                commit_recipe(altered, 'host-key-1', self.key)
        altered = recipe()
        altered['imageId'] = 'registry.test/blog:latest'
        with self.assertRaises(ValueError):
            commit_recipe(altered, 'host-key-1', self.key)

    def test_rejects_unsafe_mounts_networks_and_escalation(self):
        edits = [
            lambda x: x['mounts'][0].update(noCopy=False),
            lambda x: x['mounts'][1].update(readOnly=False),
            lambda x: x['mounts'][1].update(createHostPath=True),
            lambda x: x['mounts'][1].update(type='tmpfs'),
            lambda x: x['networks'][0].update(id='create-new-network'),
            lambda x: x['hostConfig'].update(privileged=True),
            lambda x: x['hostConfig'].update(capAdd=['SYS_ADMIN']),
            lambda x: x['health'].update(test=['CMD-SHELL', 'curl localhost']),
        ]
        for edit in edits:
            value = recipe()
            edit(value)
            with self.subTest(value=str(edit)), self.assertRaises(ValueError):
                commit_recipe(value, 'host-key-1', self.key)

    def test_duplicate_host_binding_even_with_different_container_port(self):
        value = recipe()
        duplicate = dict(value['ports'][0], containerPort=9090)
        value['ports'].append(duplicate)
        value['ports'].sort(key=lambda p: (p['hostIp'], p['hostPort'], p['containerPort'], p['protocol']))
        with self.assertRaises(ValueError):
            commit_recipe(value, 'host-key-1', self.key)

    def test_wildcard_and_loopback_host_binding_overlap(self):
        value = recipe()
        value['ports'].append(dict(value['ports'][0], hostIp='0.0.0.0', containerPort=9090))
        value['ports'].sort(key=lambda p: (p['hostIp'], p['hostPort'], p['containerPort'], p['protocol']))
        with self.assertRaises(ValueError):
            commit_recipe(value, 'host-key-1', self.key)

    def test_secret_free_errors_and_input_bounds(self):
        value = recipe()
        value['process']['env'] = ['API_KEY=super-secret', 'INVALID']
        with self.assertRaises(ValueError) as error:
            commit_recipe(value, 'host-key-1', self.key)
        self.assertNotIn('super-secret', str(error.exception))
        value = recipe()
        value['process']['env'] = ['SECRET=' + 'x' * 66000]
        with self.assertRaises(ValueError):
            commit_recipe(value, 'host-key-1', self.key)
        with self.assertRaises(ValueError):
            commit_recipe(recipe(), 'host-key-1', b'short')


if __name__ == '__main__':
    unittest.main()
