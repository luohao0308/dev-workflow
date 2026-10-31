"""Offline fixture checks; these do not grant deployment or production authority.

The collector must validate COMPOSE_SAMPLE_IMAGE as an immutable Python repo
 digest before invoking Compose. Compose's required-variable syntax only checks
that a value was supplied; it does not establish provenance or immutability.
"""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


FIXTURE = Path(__file__).parent / 'support' / 'compose_engine_sample.compose.yml'


class ComposeEngineSampleFixtureTest(unittest.TestCase):
    def setUp(self):
        # JSON syntax is a YAML subset and avoids a test-only YAML dependency.
        self.recipe = json.loads(FIXTURE.read_text())
        self.services = self.recipe['services']

    def test_disposable_scope_and_required_image(self):
        self.assertEqual(set(self.recipe), {'services', 'volumes'})
        self.assertEqual(set(self.services), {'backend', 'frontend', 'guard'})
        self.assertEqual(self.recipe['volumes'], {'sample-data': {}})
        for role, service in self.services.items():
            with self.subTest(role=role):
                self.assertEqual(service['image'], '${COMPOSE_SAMPLE_IMAGE:?immutable Python image required}')
                self.assertEqual(service['environment'], {'SAMPLE_ROLE': role})
                # Default Compose aliases and project scoping must remain intact.
                for forbidden in ('build', 'container_name', 'ports', 'networks',
                                  'secrets', 'privileged', 'network_mode', 'name'):
                    self.assertNotIn(forbidden, service)
                self.assertTrue(service['read_only'])
                self.assertEqual(service['tmpfs'], ['/tmp:size=4m'])
                self.assertEqual(service['restart'], 'unless-stopped')
                self.assertEqual(service['logging'], {
                    'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}})

    def test_shared_host_override_limits_resources_and_keeps_real_health_checks(self):
        override = json.loads(FIXTURE.with_name('compose_engine_sample.bounded.override.yml').read_text())
        self.assertEqual(set(override['services']), set(self.services))
        for service in override['services'].values():
            self.assertEqual(service['mem_limit'], '64m')
            self.assertEqual(service['memswap_limit'], '64m')
            self.assertEqual(service['cpus'], 0.1)
            self.assertEqual(service['pids_limit'], 32)
            self.assertEqual(service['healthcheck']['timeout'], '20s')
            self.assertNotIn('test', service['healthcheck'])
            self.assertNotIn('disable', service['healthcheck'])
            self.assertNotIn('volumes', service)
            self.assertNotIn('ports', service)

    def test_protected_guard_and_dependency(self):
        self.assertNotIn('volumes', self.services['guard'])
        self.assertNotIn('depends_on', self.services['guard'])
        self.assertNotIn('depends_on', self.services['backend'])
        self.assertEqual(self.services['frontend']['depends_on'], {
            'backend': {'condition': 'service_healthy'}})

    def test_volume_and_precreated_readonly_bind(self):
        for role in ('backend', 'frontend'):
            mounts = self.services[role]['volumes']
            self.assertEqual(len(mounts), 2)
            self.assertEqual(mounts[0], {
                'type': 'volume', 'source': 'sample-data', 'target': '/sample-data',
                'read_only': role == 'frontend', 'volume': {'nocopy': True}})
            self.assertEqual(mounts[1], {
                'type': 'bind',
                'source': '${COMPOSE_SAMPLE_CONFIG_DIR:?precreated sample config directory required}',
                'target': '/sample-config', 'read_only': True,
                'bind': {'create_host_path': False}})

    def test_server_probes_and_existing_sentinel_preserved(self):
        for role, service in self.services.items():
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                command = service['command']
                self.assertEqual(command[:3], ['python', '-u', '-c'])
                compile(command[3], '<sample-server>', 'exec')
                with patch.dict(os.environ, {'SAMPLE_ROLE': role}), patch('http.server.HTTPServer') as server:
                    namespace = {}
                    code = command[3].replace(repr('/sample-data/sentinel.txt'), repr(str(Path(directory) / 'sentinel.txt')))
                    exec(code, namespace)
                    server.assert_called_once_with(('0.0.0.0', 8080), namespace['Handler'])
                    server.return_value.serve_forever.assert_called_once_with()
                    handler = namespace['Handler'].__new__(namespace['Handler'])
                    handler.path = '/business/probe'
                    handler.wfile = io.BytesIO()
                    with patch.object(handler, 'send_response') as response, patch.object(handler, 'send_header'), patch.object(handler, 'end_headers'):
                        handler.do_GET()
                        response.assert_called_once_with(200)
                    self.assertEqual(json.loads(handler.wfile.getvalue()), {
                        'role': role, 'version': 'v1', 'path': '/business/probe'})
                    sentinel = Path(directory) / 'sentinel.txt'
                    if role == 'backend':
                        self.assertEqual(sentinel.read_text(), 'compose-engine-sample-sentinel-v1\n')
                        sentinel.write_text('preserve-existing-data')
                        exec(code, {})
                        self.assertEqual(sentinel.read_text(), 'preserve-existing-data')
                    else:
                        self.assertFalse(sentinel.exists())
                    health = service['healthcheck']
                    self.assertEqual(health['test'][:3], ['CMD', 'python', '-c'])
                    # Execute the healthcheck against its expected response.
                    payload = io.BytesIO(json.dumps({'role': role, 'version': 'v1', 'path': '/health'}).encode())
                    with patch('urllib.request.urlopen', return_value=payload) as request:
                        exec(health['test'][3], {})
                        request.assert_called_once_with('http://127.0.0.1:8080/health', timeout=2)


if __name__ == '__main__':
    unittest.main()
