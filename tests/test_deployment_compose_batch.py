import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'packs/deployment/scripts/deployment_compose_batch.py'
sys.path.insert(0, str(SCRIPT.parent))
import deployment_compose_batch as batch

DIGEST = 'sha256:' + 'a' * 64


def fixture():
    services = {}
    for name, deps in [('caddy', ['frontend']), ('frontend', ['backend']),
                       ('backend', ['db', 'redis', 'es']), ('db', []), ('redis', []), ('es', [])]:
        services[name] = {'image': f'registry.example/{name}@{DIGEST}',
                          'depends_on': {dep: {'condition': 'service_healthy', 'required': True}
                                         for dep in deps},
                          'environment': {'PASSWORD': 'private-value'}}
    services['backend']['volumes'] = [
        {'type': 'volume', 'source': 'uploads', 'target': '/app/uploads', 'volume': {'nocopy': True}},
        {'type': 'bind', 'source': '/srv/config', 'target': '/app/config', 'read_only': True,
         'bind': {'create_host_path': False}}]
    model = {'name': 'sample', 'services': services, 'volumes': {'uploads': {}}}
    policy = {'project': 'sample', 'selectedServices': ['backend', 'frontend'],
              'protectedServices': ['caddy', 'db', 'redis', 'es'], 'allowInterruption': True,
              'migrations': {name: {'source': DIGEST, 'target': DIGEST}
                             for name in ('backend', 'frontend')}}
    return model, policy


class ComposeBatchTests(unittest.TestCase):
    def test_two_service_order_and_protection(self):
        model, policy = fixture()
        result = batch.assess(model, policy)
        self.assertEqual(result['structuralStatus'], 'candidate-unverified')
        self.assertEqual(result['startOrder'], ['backend', 'frontend'])
        self.assertEqual(result['stopOrder'], ['frontend', 'backend'])
        self.assertEqual(result['mountTypes'], {'namedVolume': 1, 'readOnlyBind': 1})
        self.assertEqual(result['protectedServices'], ['caddy', 'db', 'es', 'redis'])
        self.assertFalse(result['productionReady'])
        self.assertFalse(result['executionAvailable'])
        self.assertFalse(result['authorityGranted'])
        self.assertEqual(result['runtimeVerification'], 'unknown')
        self.assertNotIn('private-value', json.dumps(result))

    def test_scope_dependency_and_image_rejections(self):
        for mutate, reason in [
            (lambda m, p: p['protectedServices'].remove('db'), 'incomplete-service-scope'),
            (lambda m, p: p['protectedServices'].append('backend'), 'overlapping-service-scope'),
            (lambda m, p: m['services']['backend'].update(depends_on={'missing': {'condition': 'service_healthy'}}), 'invalid-service-dependencies'),
            (lambda m, p: m['services']['backend'].update(depends_on={'frontend': {'condition': 'service_healthy'}}), 'service-dependency-cycle'),
            (lambda m, p: m['services']['frontend'].update(image='frontend:latest'), 'immutable-image-required'),
            (lambda m, p: p['migrations']['backend'].update(target='sha256:' + 'b' * 64), 'migration-set-mismatch'),
            (lambda m, p: p.update(allowInterruption=False), 'interruption-consent-required'),
            (lambda m, p: m.update(name='other'), 'project-identity-mismatch'),
            (lambda m, p: m['services']['backend'].update(command=['sh']), 'command-override-unsupported'),
            (lambda m, p: m['services']['backend'].update(entrypoint=['sh']), 'command-override-unsupported'),
            (lambda m, p: m['services']['backend'].update(depends_on=['db']), 'invalid-service-dependencies'),
            (lambda m, p: m['services']['backend'].update(depends_on={'db': {'condition': 'service_started'}}), 'invalid-service-dependencies'),
            (lambda m, p: m['services']['backend'].update(depends_on={'db': {'condition': 'service_healthy', 'required': False}}), 'invalid-service-dependencies'),
            (lambda m, p: m['services']['backend'].update(depends_on={'db': {'condition': 'service_healthy', 'restart': True}}), 'invalid-service-dependencies'),
            (lambda m, p: m['services']['backend'].update(container_name='bad name'), 'invalid-container-name'),
        ]:
            with self.subTest(reason=reason):
                model, policy = fixture()
                mutate(model, policy)
                result = batch.assess(model, policy)
                self.assertEqual(result['structuralStatus'], 'blocked')
                self.assertIn(reason, result['reasons'])
                self.assertEqual(result['startOrder'], [])

    def test_unsafe_fields_and_mounts_are_rejected(self):
        for change, reason in [
            ({'privileged': True}, 'unsupported-service-fields'),
            ({'build': '.'}, 'unsupported-service-fields'),
            ({'devices': ['/dev/sda']}, 'unsupported-service-fields'),
            ({'post_start': ['secret']}, 'unsupported-service-fields'),
            ({'volumes': ['/anonymous']}, 'unsupported-mount'),
            ({'volumes': [{'type': 'bind', 'source': '/private', 'target': '/app/secret'}]}, 'unsupported-mount'),
            ({'volumes': [{'type': 'volume', 'source': 'missing', 'target': '/data'}]}, 'unsupported-mount'),
            ({'volumes': [{'type': 'volume', 'source': 'uploads', 'target': '/data',
                           'volume': {'nocopy': True}, 'read_only': 1}]}, 'unsupported-mount'),
            ({'volumes': [{'type': 'bind', 'source': '/private', 'target': '/data',
                           'read_only': True, 'bind': {'create_host_path': True}}]}, 'unsupported-mount'),
            ({'volumes': [{'type': 'bind', 'source': '/private', 'target': '/data',
                           'read_only': True, 'bind': {'create_host_path': False, 'propagation': 'shared'}}]},
             'unsupported-mount'),
        ]:
            model, policy = fixture()
            model['services']['backend'].update(change)
            self.assertIn(reason, batch.assess(model, policy)['reasons'])

    def test_cli_never_outputs_secret(self):
        model, policy = fixture()
        with tempfile.TemporaryDirectory() as directory:
            model_path, policy_path = Path(directory) / 'model.json', Path(directory) / 'policy.json'
            model_path.write_text(json.dumps(model))
            policy_path.write_text(json.dumps(policy))
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--model', str(model_path),
                                     '--policy', str(policy_path)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('private-value', result.stdout + result.stderr)
            policy_path.write_text('{"project":NaN}')
            rejected = subprocess.run([sys.executable, '-B', str(SCRIPT), '--model', str(model_path),
                                       '--policy', str(policy_path)], text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(json.loads(rejected.stderr)['error'], 'invalid-input')

    def test_normalized_compose_mounts_are_unverified_constraints(self):
        model, policy = fixture()
        mounts = model['services']['backend']['volumes']
        mounts[0]['volume'] = {}
        mounts[1]['bind'] = {}
        model['services']['backend']['container_name'] = 'backend-1'
        result = batch.assess(model, policy)
        self.assertEqual(result['structuralStatus'], 'candidate-unverified')
        self.assertEqual(result['unverifiedConstraints'], ['bind-create-host-path', 'existing-volume-nocopy'])
        self.assertFalse(result['executionAvailable'])
        for option in ({'create_host_path': True}, {'propagation': 'shared'}):
            mounts[1]['bind'] = option
            self.assertIn('unsupported-mount', batch.assess(model, policy)['reasons'])

    def test_large_chain_is_deterministically_blocked(self):
        model, policy = fixture()
        for i in range(1200):
            name = f'extra{i}'
            model['services'][name] = {'image': f'registry.example/{name}@{DIGEST}',
                                       'depends_on': {f'extra{i-1}': {'condition': 'service_healthy'}} if i else {}}
            policy['selectedServices'].append(name)
            policy['migrations'][name] = {'source': DIGEST, 'target': DIGEST}
        result = batch.assess(model, policy)
        self.assertIn('compose-service-limit', result['reasons'])
        self.assertIn('selected-service-limit', result['reasons'])
        self.assertEqual(result['startOrder'], [])

    def test_full_stack_container_names_must_be_unique(self):
        for left, right, name in [('backend', 'frontend', 'shared'),
                                  ('backend', 'db', 'shared'),
                                  ('backend', 'db', 'sample-db-1')]:
            model, policy = fixture()
            model['services'][left]['container_name'] = name
            if name == 'shared':
                model['services'][right]['container_name'] = name
            result = batch.assess(model, policy)
            self.assertIn('container-name-conflict', result['reasons'])
            self.assertEqual(result['structuralStatus'], 'blocked')
        model, policy = fixture()
        model['services']['db']['container_name'] = 'bad name'
        self.assertIn('invalid-container-name', batch.assess(model, policy)['reasons'])
        model, policy = fixture()
        model.pop('name')
        self.assertIn('project-identity-mismatch', batch.assess(model, policy)['reasons'])

    def test_real_compose_config_mount_normalization(self):
        if not shutil.which('docker'):
            self.skipTest('Docker Compose CLI unavailable')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'compose.yml'
            path.write_text('''name: sample
services:
  backend:
    image: registry.example/backend@sha256:''' + 'a' * 64 + '''
    volumes:
      - uploads:/app/uploads
      - type: bind
        source: /srv/config
        target: /app/config
        read_only: true
volumes:
  uploads: {}
''')
            process = subprocess.run(['docker', 'compose', '-f', str(path), 'config', '--format', 'json'],
                                     text=True, capture_output=True)
            if process.returncode != 0:
                self.skipTest('Docker Compose config unavailable')
            model = json.loads(process.stdout)
            volumes = model['services']['backend']['volumes']
            self.assertEqual(volumes[0].get('volume'), {})
            self.assertIn(volumes[1].get('bind'), (None, {}))
            # Compose assigns project-scoped volume source names; declare that normalized name.
            policy = {'project': model['name'], 'selectedServices': ['backend'],
                      'protectedServices': [], 'allowInterruption': True,
                      'migrations': {'backend': {'source': DIGEST, 'target': DIGEST}}}
            result = batch.assess(model, policy)
            self.assertEqual(result['structuralStatus'], 'candidate-unverified')
            self.assertEqual(result['unverifiedConstraints'],
                             ['bind-create-host-path', 'existing-volume-nocopy'])


if __name__ == '__main__':
    unittest.main()
