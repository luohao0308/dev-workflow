"""Synthetic Unix Docker fixture through real mTLS and production observation checks.

Registry image JSON below is synthetic unit data, never live Engine enrollment.
"""
import copy
from dataclasses import replace
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from tests import test_deployment_compose_reader_host as gateway_tests
from tests.test_deployment_compose_observation import fixture
from deployment_compose_reader_host import ComposeReaderHostPolicy, create_gateway
from deployment_compose_reader import ComposeReadPolicy
from deployment_compose_observation_host import ComposeObservationHost
from deployment_compose_artifacts import ComposeArtifacts, ServiceArtifact
from deployment_compose_collect import collect
import deployment_compose_private as private


@unittest.skipUnless(os.name=='posix' and hasattr(socket, 'AF_UNIX') and shutil.which('openssl'), 'Linux/macOS Unix gateway fixture requires openssl')
class SourceViewIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        gateway_tests.ReaderHostTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_tls_retention_survives_candidate_but_rejects_source_drift(self):
        records, scope = fixture()
        image = records['containers'][0]['imageId']
        registry = 'syntheticregistry.example/blog@sha256:' + 'b' * 64
        key = b'synthetic-unit-private-key-only!!'
        key_id = 'unit-key'
        calls = []
        containers = {}
        for record in records['containers']:
            containers[record['id']] = {
                'Id': record['id'], 'Name': '/' + record['name'], 'Image': image,
                'Config': dict.fromkeys(private.REQUIRED_CONFIG),
                'HostConfig': dict.fromkeys(private.REQUIRED_HOST),
                'Mounts': [{**dict.fromkeys(private.MOUNT), 'Type': mount['type'],
                            'Name': mount['source'], 'Source': mount['source'],
                            'Destination': mount['target'], 'RW': not mount['readOnly']}
                           for mount in record['mounts']],
                'NetworkSettings': {'Networks': {net['name']: {'NetworkID': net['id'],
                    'Aliases': net['aliases']} for net in record['networks']}},
                'RestartCount': 0,
                'State': {'Running': True, 'Pid': 100, 'StartedAt': '2026-10-28T00:00:00Z',
                          'Health': {'Status': 'healthy'}}}
            raw = containers[record['id']]
            raw['Config'].update(Env=['UNIT=value'], Labels=record['labels'])
            raw['HostConfig'].update(Privileged=False, ReadonlyRootfs=False)
        pins = tuple(sorted(containers))
        scope['selectedServices'].sort()
        selected = scope['selectedServices']
        protected = scope['protectedServices']
        by_service = {row['Config']['Labels']['com.docker.compose.service']: cid
                      for cid, row in containers.items()}
        hmacs = {}
        for service, cid in by_service.items():
            raw = containers[cid]
            projection = {name: raw[name] for name in ('Config', 'HostConfig', 'Mounts', 'NetworkSettings')}
            hmacs[service] = private.commit('blog', service, projection, key_id, key)['configHmac']
        scope.update(imageIds={service: image for service in by_service},
                     baselineSourceShas={service: '1' * 40 for service in selected},
                     selectedContainerIds={service: by_service[service] for service in selected},
                     protectedContainerIds={service: by_service[service] for service in protected},
                     protectedConfigHmacs={service: hmacs[service] for service in protected})
        artifacts = ComposeArtifacts(1, tuple(ServiceArtifact(service, '1' * 40, registry, image,
            'linux', 'amd64', key_id, hmacs[service], 'b' * 64, 'none') for service in selected))

        class Docker(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                calls.append(self.path)
                parsed = urlsplit(self.path)
                if parsed.path == '/v1.45/containers/json':
                    query = parse_qs(parsed.query, strict_parsing=True)
                    filters = json.loads(query['filters'][0])
                    # Execute requested ID and project constraints at the upstream.
                    rows = [row for cid, row in containers.items()
                            if ('id' not in filters or cid in filters['id'])
                            and all(row['Config']['Labels'].get(label.split('=', 1)[0]) ==
                                    label.split('=', 1)[1] for label in filters['label'])]
                    value = [{'Id': row['Id'], 'ImageID': row['Image'],
                              'Labels': row['Config']['Labels']} for row in rows]
                elif self.path == '/v1.45/info':
                    value = {'ID': scope['daemonId']}
                elif self.path.startswith('/v1.45/containers/'):
                    value = containers[self.path.split('/')[3]]
                elif self.path.startswith('/v1.45/images/'):
                    value = {'Id': image, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [registry]}
                elif self.path.startswith('/v1.45/networks/'):
                    net = records['networks'][0]
                    value = {'Id': net['id'], 'Name': net['name'],
                             'Labels': {'com.docker.compose.project': 'blog'}}
                elif self.path.startswith('/v1.45/volumes/'):
                    volume = records['volumes'][0]
                    value = {'Name': volume['name'], 'Driver': 'local', 'Options': {},
                             'Labels': {'com.docker.compose.project': 'blog'}}
                else:
                    raise AssertionError(self.path)
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

        class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        socket_path = Path(temporary.name).resolve() / 'docker.sock'
        upstream = UnixServer(str(socket_path), Docker)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)

        def cert_pin(name):
            return hashlib.sha256(ssl.PEM_cert_to_DER_cert(
                (self.directory / (name + '.pem')).read_text())).hexdigest()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.directory / 'server.pem'), str(self.directory / 'server.key'))
        context.load_verify_locations(str(self.directory / 'ca.pem'))
        context.verify_mode = ssl.CERT_REQUIRED
        policy = ComposeReaderHostPolicy('blog', scope['daemonId'], cert_pin('reader'),
            tuple(sorted(by_service)), pins, (image,), (records['networks'][0]['id'],),
            ('blog_uploads',), private_key_id=key_id, source_view=True)

        def observer(host_policy, ids):
            server = create_gateway(host_policy, tls_context=context, docker_socket=socket_path,
                                    private_hmac_key=key)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            reader_policy = ComposeReadPolicy('https://localhost:' + str(server.server_port),
                cert_pin('server'), scope['daemonId'], 'blog', ('blog_uploads',),
                gateway_policy_hash=host_policy.digest(), private_key_id=key_id,
                source_container_ids=ids)
            return ComposeObservationHost(reader_policy=reader_policy, scope_policy=scope,
                baseline_artifacts=artifacts, ca_file=self.directory / 'ca.pem',
                cert_file=self.directory / 'reader.pem', key_file=self.directory / 'reader.key',
                max_age_seconds=120)

        source = observer(policy, pins)
        whole = observer(replace(policy, source_view=False), ())
        self.assertFalse(source._test_only)
        self.assertIsNone(source._reader._transport)
        self.assertIsNotNone(source._reader._context)
        observation = source.issue()
        self.assertIsNotNone(observation)
        boot = source._reader.gateway_info()
        commitment = source.retention_commitment(observation)
        self.assertIsNotNone(whole.issue())
        candidate = copy.deepcopy(containers[pins[0]])
        candidate.update(Id='f' * 64, Name='/blog-candidate-1')
        containers[candidate['Id']] = candidate
        calls.clear()
        self.assertTrue(source.recheck(observation))
        self.assertEqual(source.retention_commitment(observation), commitment)
        self.assertEqual(source._reader.gateway_info(), boot)
        self.assertEqual(source.source_container_ids, pins)
        self.assertEqual(source.scope_kind, 'pinned-containers')
        list_calls = [path for path in calls if urlsplit(path).path == '/v1.45/containers/json']
        self.assertEqual(len(list_calls), 4)  # Two production double-reads.
        for path in list_calls:
            self.assertEqual(json.loads(parse_qs(urlsplit(path).query)['filters'][0]),
                {'id': list(pins), 'label': ['com.docker.compose.project=blog']})
        self.assertIsNone(whole.issue())
        self.assertEqual(collect(whole._reader, scope)['structuralStatus'], 'blocked')
        with self.assertRaisesRegex(ValueError, 'whole-project-observation-required'):
            source.commitment(observation)
        raw = containers[pins[0]]
        for mutate in (lambda: raw['State'].update(Running=False),
                       lambda: raw.update(RestartCount=1),
                       lambda: raw['Config'].update(Env=['UNIT=changed'])):
            before = copy.deepcopy(raw)
            mutate()
            self.assertFalse(source.recheck(observation))
            with self.assertRaises(ValueError):
                source.retention_commitment(observation)
            raw.clear()
            raw.update(before)
        self.assertTrue(source.recheck(observation))
