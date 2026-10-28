"""Real loopback mTLS against a synthetic Unix Docker endpoint."""
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler
import json
from io import BytesIO
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import deployment_compose_reader_host as host
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_reader import ComposeDockerReader, ComposeReadPolicy


@unittest.skipUnless(hasattr(socket, 'AF_UNIX') and shutil.which('openssl'), 'Unix socket and openssl required')
class ReaderHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_deployment_runtime import LocalTLSRuntimeTests
        LocalTLSRuntimeTests.setUpClass.__func__(cls)
        for args in [
            ('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'reader.key', '-out', 'reader.csr', '-subj', '/CN=reader'),
            ('x509', '-req', '-in', 'reader.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
             '-out', 'reader.pem', '-days', '1', '-extfile', 'client.ext')]:
            subprocess.run(['openssl', *args], cwd=cls.directory, check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.calls = []
        self.container = 'a' * 64
        self.image = 'sha256:' + 'b' * 64
        self.network = 'c' * 64
        self.value = {'ID': 'daemon-1'}
        self.truncated = False
        self.upstream_status = 200
        self.slow = False
        self.chunked = False
        self.bad_chunk = False
        self.oversized = False
        test = self

        class DockerHandler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                test.calls.append((self.command, self.path))
                raw = b'x' * (host.MAX_RESPONSE + 1) if test.oversized else json.dumps(test.value).encode()
                self.send_response(test.upstream_status)
                if test.chunked:
                    self.send_header('Transfer-Encoding', 'chunked')
                else:
                    self.send_header('Content-Length', str(len(raw) + (10 if test.truncated else 0)))
                self.end_headers()
                if test.chunked:
                    self.wfile.write(('%x\r\n' % len(raw)).encode() + raw + b'\r\n')
                    self.wfile.flush()
                    if test.slow:
                        time.sleep(1.3)
                    if not test.bad_chunk:
                        try:
                            self.wfile.write(b'0\r\n\r\n')
                        except OSError:
                            pass
                elif test.slow:
                    self.wfile.write(raw[:1])
                    self.wfile.flush()
                    time.sleep(1.3)
                    try:
                        self.wfile.write(raw[1:])
                    except OSError:
                        pass
                else:
                    self.wfile.write(raw)
                self.close_connection = True

        class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        try:
            self.upstream = UnixServer(str(self.root / 'docker.sock'), DockerHandler)
        except PermissionError:
            self.skipTest('Unix socket unavailable')
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        def pin(name):
            return hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory / (name + '.pem')).read_text())).hexdigest()
        policy = host.ComposeReaderHostPolicy('blog', 'daemon-1', pin('reader'), ('web',),
                                             (self.container,), (self.image,), (self.network,), ('blog_data',))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.directory / 'server.pem'), str(self.directory / 'server.key'))
        context.load_verify_locations(str(self.directory / 'ca.pem'))
        context.verify_mode = ssl.CERT_REQUIRED
        self.policy, self.context = policy, context
        self.gateway = host.create_gateway(policy, tls_context=context, docker_socket=self.root / 'docker.sock', timeout=1)
        threading.Thread(target=self.gateway.serve_forever, daemon=True).start()
        self.addCleanup(self.gateway.server_close)
        self.addCleanup(self.gateway.shutdown)
        self.list_path = '/v1.45/containers/json?all=1&filters=%7B%22label%22%3A%5B%22com.docker.compose.project%3Dblog%22%5D%7D'

    def request(self, method, path, *, cert='reader', body=None, headers=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(str(self.directory / 'ca.pem'))
        context.load_cert_chain(str(self.directory / (cert + '.pem')), str(self.directory / (cert + '.key')))
        conn = http.client.HTTPSConnection('localhost', self.gateway.server_port, context=context, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_info_and_exact_get(self):
        status, raw = self.request('GET', '/v1.45/workflow/reader-info')
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(raw)['policyHash']), 64)
        self.assertFalse(self.calls)
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 200)
        self.assertEqual(self.calls, [('GET', '/v1.45/info')])

    def test_host_bind_digest_route_is_exact_and_secret_free(self):
        source = self.root / 'readonly.conf'
        source.write_text('private bind contents')
        self.gateway.shutdown()
        self.gateway.server_close()
        policy = host.ComposeReaderHostPolicy(**{**self.policy.__dict__,
                                                 'private_key_id': 'host-key-1',
                                                 'bind_paths': (str(source),)})
        self.gateway = host.create_gateway(policy, tls_context=self.context,
                                           docker_socket=self.root / 'docker.sock', timeout=1,
                                           private_hmac_key=b'k' * 32)
        threading.Thread(target=self.gateway.serve_forever, daemon=True).start()
        self.addCleanup(self.gateway.server_close)
        self.addCleanup(self.gateway.shutdown)
        reader_policy = ComposeReadPolicy('https://localhost:' + str(self.gateway.server_port),
                                          hashlib.sha256(ssl.PEM_cert_to_DER_cert(
                                              (self.directory / 'server.pem').read_text())).hexdigest(),
                                          'daemon-1', 'blog', gateway_policy_hash=policy.digest(),
                                          private_key_id='host-key-1', bind_count=1)
        reader = ComposeDockerReader(reader_policy, ca_file=self.directory / 'ca.pem',
                                     cert_file=self.directory / 'reader.pem', key_file=self.directory / 'reader.key')
        path = '/v1.45/workflow/binds/0'
        self.assertEqual(reader.gateway_info()['policyHash'], policy.digest())
        first = reader.get(path)
        self.assertEqual(set(first), {'schemaVersion', 'bindDigest', 'authorityGranted'})
        self.assertFalse(first['authorityGranted'])
        self.assertNotIn('private bind contents', json.dumps(first))
        self.assertNotIn(str(source), json.dumps(first))
        self.assertFalse(self.calls)
        source.write_text('changed private bind contents')
        self.assertNotEqual(first['bindDigest'], reader.get(path)['bindDigest'])
        for denied in ('/v1.45/workflow/binds/1', '/v1.45/workflow/binds/00',
                       '/v1.45/workflow/binds/0/', '/v1.45/workflow/binds/0?x=1'):
            self.assertEqual(self.request('GET', denied)[0], 403)
        source.unlink()
        status, raw = self.request('GET', path)
        self.assertEqual(status, 502)
        self.assertNotIn(str(source).encode(), raw)
        self.assertFalse(self.calls)

    def test_image_defaults_commitment_route(self):
        path = '/v1.45/workflow/private-image/' + self.image
        self.assertEqual(self.request('GET', path)[0], 403)
        self.assertEqual(self.calls, [])
        with self.assertRaises(host.ReaderHostError):
            host.ComposeReaderHostPolicy(**{**self.policy.__dict__, 'image_defaults_enabled': True})
        self.gateway.shutdown()
        self.gateway.server_close()
        policy = host.ComposeReaderHostPolicy(**{**self.policy.__dict__,
                                                 'private_key_id': 'host-key-1',
                                                 'image_defaults_enabled': True})
        self.assertNotEqual(policy.digest(), self.policy.digest())
        self.gateway = host.create_gateway(policy, tls_context=self.context,
                                           docker_socket=self.root / 'docker.sock', timeout=1,
                                           private_hmac_key=b'k'*32)
        threading.Thread(target=self.gateway.serve_forever, daemon=True).start()
        self.addCleanup(self.gateway.server_close)
        self.addCleanup(self.gateway.shutdown)
        self.value = {'Id': self.image, 'Os': 'linux', 'Architecture': 'amd64',
                      'RepoDigests': ['registry.example/app@sha256:' + 'b'*64],
                      'Config': {'Env': ['TOKEN=secret-image-value']}}
        status, raw = self.request('GET', path)
        self.assertEqual(status, 200)
        first = json.loads(raw)
        self.assertEqual(set(first), {'schemaVersion', 'keyId', 'imageConfigHmac', 'authorityGranted'})
        self.assertNotIn('secret-image-value', raw.decode())
        self.assertEqual(self.calls[-1], ('GET', '/v1.45/images/' + self.image + '/json'))
        self.value['Config']['Env'] = ['TOKEN=changed-secret-image-value']
        self.assertNotEqual(first['imageConfigHmac'], json.loads(self.request('GET', path)[1])['imageConfigHmac'])
        count = len(self.calls)
        for verb in ('POST', 'PUT', 'PATCH', 'DELETE'):
            self.assertEqual(self.request(verb, path)[0], 403)
        self.assertEqual(self.request('GET', path.replace('b'*64, 'd'*64))[0], 403)
        self.assertEqual(len(self.calls), count)
        self.value['Id'] = 'sha256:' + 'd'*64
        self.assertEqual(self.request('GET', path)[0], 403)

    def test_host_private_commitment_is_pinned_and_secret_free(self):
        self.gateway.shutdown()
        self.gateway.server_close()
        policy = host.ComposeReaderHostPolicy(**{**self.policy.__dict__, 'private_key_id': 'host-key-1'})
        self.gateway = host.create_gateway(policy, tls_context=self.context,
                                           docker_socket=self.root / 'docker.sock', timeout=1,
                                           private_hmac_key=b'k' * 32)
        threading.Thread(target=self.gateway.serve_forever, daemon=True).start()
        self.addCleanup(self.gateway.server_close)
        self.addCleanup(self.gateway.shutdown)
        self.value = {'Id': self.container, 'Name': '/blog-web-1', 'Image': self.image,
                      'Config': {'Image': self.image, 'Env': ['TOKEN=private-value'],
                                 'Labels': {'com.docker.compose.project': 'blog',
                                            'com.docker.compose.service': 'web'},
                                 'User': '', 'WorkingDir': '', 'Entrypoint': None, 'Cmd': None,
                                 'ExposedPorts': {}, 'Healthcheck': None},
                      'HostConfig': {'Binds': None, 'RestartPolicy': {'Name': 'no'},
                                     'Privileged': False, 'ReadonlyRootfs': False,
                                     'NetworkMode': 'blog_default', 'SecurityOpt': None,
                                     'CapAdd': None, 'CapDrop': None, 'Devices': [],
                                     'PortBindings': {}, 'Mounts': []},
                      'Mounts': [], 'NetworkSettings': {'Networks': {
                          'blog_default': {'NetworkID': self.network, 'Aliases': ['web']}}},
                      'State': {'Running': True, 'Health': None}}
        reader_policy = ComposeReadPolicy('https://localhost:' + str(self.gateway.server_port),
                                          hashlib.sha256(ssl.PEM_cert_to_DER_cert(
                                              (self.directory / 'server.pem').read_text())).hexdigest(),
                                          'daemon-1', 'blog', gateway_policy_hash=policy.digest(),
                                          private_key_id='host-key-1')
        reader = ComposeDockerReader(reader_policy, ca_file=self.directory / 'ca.pem',
                                     cert_file=self.directory / 'reader.pem',
                                     key_file=self.directory / 'reader.key')
        path = '/v1.45/workflow/private/' + self.container
        self.assertEqual(reader.gateway_info()['policyHash'], policy.digest())
        first = reader.get(path)
        self.assertFalse(first['authorityGranted'])
        self.assertNotIn('private-value', json.dumps(first))
        self.value['Config']['Env'][0] = 'TOKEN=changed-private-value'
        self.assertNotEqual(first['configHmac'], reader.get(path)['configHmac'])
        self.value['Mounts'] = [{'Type': 'volume', 'Name': 'data', 'Source': '/private/data',
                                 'Destination': '/data', 'RW': True}]
        changes = [
            ('endpoint', 'IPAMConfig', {'IPv4Address': '172.20.0.5'}),
            ('endpoint', 'Links', ['private-value']),
            ('endpoint', 'DriverOpts', {'secret': 'private-value'}),
            ('endpoint', 'FutureEndpoint', 'private-value'),
            ('network', 'SandboxKey', '/private/data'),
            ('mount', 'FutureMount', {'secret': 'private-value'}),
        ]
        previous = reader.get(path)
        for scope, key, value in changes:
            target = (self.value['Mounts'][0] if scope == 'mount' else
                      self.value['NetworkSettings']['Networks']['blog_default'] if scope == 'endpoint'
                      else self.value['NetworkSettings'])
            target[key] = value
            current = reader.get(path)
            self.assertEqual(set(current), {'schemaVersion', 'keyId', 'configHmac', 'authorityGranted'})
            self.assertNotEqual(previous['configHmac'], current['configHmac'])
            self.assertNotIn('private-value', json.dumps(current))
            self.assertNotIn('/private/data', json.dumps(current))
            previous = current
        self.value['Config'].pop('Env')
        self.assertEqual(self.request('GET', path)[0], 502)

    def test_silent_tls_peer_does_not_block_other_clients(self):
        stalled = socket.create_connection(('127.0.0.1', self.gateway.server_port), timeout=2)
        self.addCleanup(stalled.close)
        started = time.monotonic()
        status, _ = self.request('GET', '/v1.45/workflow/reader-info')
        self.assertEqual(status, 200)
        self.assertLess(time.monotonic() - started, 0.9)
        stalled.settimeout(3)
        self.assertEqual(stalled.recv(1), b'')

    def test_every_write_verb_and_body_denied_before_upstream(self):
        for verb in ('POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'):
            self.assertEqual(self.request(verb, '/v1.45/info')[0], 403)
        self.assertEqual(self.request('GET', '/v1.45/info', body=b'{}')[0], 403)
        self.assertEqual(self.request('GET', '/v1.45/info', headers={'Content-Encoding': 'gzip'})[0], 403)
        self.assertEqual(self.request('GET', '/v1.45/%69nfo')[0], 403)
        self.assertEqual(self.request('GET', '/v1.45/containers/json?all=1')[0], 403)
        self.assertEqual(self.request('GET', '/v1.45/containers/' + 'f' * 64 + '/json')[0], 403)
        self.assertEqual(self.request('GET', '/v1.45/networks/' + 'f' * 64)[0], 403)
        self.assertEqual(self.request('GET', '/v1.45/volumes/other')[0], 403)
        self.assertEqual(self.request('GET', '/v1.45/info', cert='client')[0], 403)
        self.assertFalse(self.calls)

    def test_body_rejection_shuts_down_wrapped_write_side_before_close(self):
        completed = threading.Event()
        shutdowns = []
        original = ssl.SSLSocket.shutdown
        def shutdown(connection, how):
            shutdowns.append((connection.fileno(), how))
            try:
                return original(connection, how)
            finally:
                completed.set()
        with mock.patch.object(ssl.SSLSocket, 'shutdown', shutdown):
            status, raw = self.request('GET', '/v1.45/info', body=b'{}')
            self.assertEqual((status, json.loads(raw)), (403, {'error': 'reader-request-rejected'}))
            self.assertTrue(completed.wait(1), 'wrapped socket never shut down its write side')
        self.assertEqual(len(shutdowns), 1)
        self.assertGreaterEqual(shutdowns[0][0], 0)
        self.assertEqual(shutdowns[0][1], socket.SHUT_WR)
        self.assertFalse(self.calls)

    def test_cross_project_and_unknown_inventory_denied(self):
        self.value = [{'Id': self.container, 'ImageID': self.image,
                       'Labels': {'com.docker.compose.project': 'other', 'com.docker.compose.service': 'web'}}]
        self.assertEqual(self.request('GET', self.list_path)[0], 403)
        self.value[0]['Labels']['com.docker.compose.project'] = 'blog'
        self.value[0]['Id'] = 'f' * 64
        self.assertEqual(self.request('GET', self.list_path)[0], 403)
        self.value = {'Id': self.container, 'Image': self.image,
                      'Config': {'Labels': {'com.docker.compose.project': 'other', 'com.docker.compose.service': 'web'}}}
        self.assertEqual(self.request('GET', '/v1.45/containers/' + self.container + '/json')[0], 403)
        self.value = {'Id': self.network, 'Labels': {'com.docker.compose.project': 'other'}}
        self.assertEqual(self.request('GET', '/v1.45/networks/' + self.network)[0], 403)
        self.value = {'Name': 'blog_data', 'Labels': {'com.docker.compose.project': 'other'}}
        self.assertEqual(self.request('GET', '/v1.45/volumes/blog_data')[0], 403)

    def test_truncated_and_unknown_result_fail_closed(self):
        self.truncated = True
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 502)
        self.truncated = False
        self.value = {'ID': 'different-daemon'}
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 403)
        self.value = {'ID': 'daemon-1', 'ID2': float('nan')}
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 502)

    def test_response_projection_never_exposes_raw_secrets(self):
        secret = 'private-password-123'
        self.value = {'ID': 'daemon-1', 'Name': secret}
        status, raw = self.request('GET', '/v1.45/info')
        self.assertEqual((status, json.loads(raw)), (200, {'ID': 'daemon-1'}))
        self.value = [{'Id': self.container, 'ImageID': self.image,
                       'Labels': {'com.docker.compose.project': 'blog', 'com.docker.compose.service': 'web',
                                  'secret': secret}, 'Secret': secret}]
        status, raw = self.request('GET', self.list_path)
        self.assertEqual(status, 200)
        self.assertNotIn(secret.encode(), raw)
        self.value = {'Id': self.container, 'Name': '/blog-web-1', 'Image': self.image,
                      'Config': {'Env': ['PASSWORD=' + secret], 'Labels': {
                          'com.docker.compose.project': 'blog', 'com.docker.compose.service': 'web', 'secret': secret}},
                      'HostConfig': {'Binds': [secret]}, 'NetworkSettings': {'Networks': {
                          'blog_default': {'NetworkID': self.network, 'Aliases': ['web'], 'Secret': secret}}},
                      'Mounts': [], 'RestartCount': 0,
                      'State': {'Running': True, 'Pid': 100,
                                'StartedAt': '2026-10-25T00:00:00Z',
                                'Health': {'Status': 'healthy', 'Log': [secret]}}}
        status, raw = self.request('GET', '/v1.45/containers/' + self.container + '/json')
        self.assertEqual(status, 200)
        self.assertNotIn(secret.encode(), raw)
        self.value = {'Id': self.image, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [],
                      'Config': {'Env': ['PASSWORD=' + secret]}}
        status, raw = self.request('GET', '/v1.45/images/' + self.image + '/json')
        self.assertEqual(status, 200)
        self.assertNotIn(secret.encode(), raw)
        self.value = {'Id': self.network, 'Name': 'blog_default',
                      'Labels': {'com.docker.compose.project': 'blog', 'secret': secret}, 'Containers': {secret: {}}}
        status, raw = self.request('GET', '/v1.45/networks/' + self.network)
        self.assertEqual(status, 200)
        self.assertNotIn(secret.encode(), raw)
        self.value = {'Name': 'blog_data', 'Driver': 'local', 'Options': {},
                      'Labels': {'com.docker.compose.project': 'blog', 'secret': secret}, 'Mountpoint': secret}
        status, raw = self.request('GET', '/v1.45/volumes/blog_data')
        self.assertEqual(status, 200)
        self.assertNotIn(secret.encode(), raw)

    def test_exact_404_only_and_volume_options_refused(self):
        self.upstream_status = 404
        self.value = {'Secret': 'hidden'}
        status, raw = self.request('GET', '/v1.45/containers/' + self.container + '/json')
        self.assertEqual(status, 404)
        self.assertNotIn(b'hidden', raw)
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 502)
        self.chunked = True
        self.assertEqual(self.request('GET', '/v1.45/images/' + self.image + '/json')[0], 404)
        self.bad_chunk = True
        self.assertEqual(self.request('GET', '/v1.45/images/' + self.image + '/json')[0], 502)
        self.bad_chunk = False
        self.slow = True
        self.assertEqual(self.request('GET', '/v1.45/images/' + self.image + '/json')[0], 502)
        self.slow = False
        self.chunked = False
        self.truncated = True
        self.assertEqual(self.request('GET', '/v1.45/images/' + self.image + '/json')[0], 502)
        self.truncated = False
        self.upstream_status = 200
        self.value = {'Name': 'blog_data', 'Driver': 'local', 'Options': {'password': 'hidden'},
                      'Labels': {'com.docker.compose.project': 'blog'}}
        self.assertEqual(self.request('GET', '/v1.45/volumes/blog_data')[0], 502)

    def test_slow_upstream_exceeds_total_deadline(self):
        self.slow = True
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 502)

    def test_chunked_complete_truncated_oversized_and_slow(self):
        self.chunked = True
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 200)
        self.bad_chunk = True
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 502)
        self.bad_chunk = False
        self.oversized = True
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 502)
        self.oversized = False
        self.slow = True
        self.assertEqual(self.request('GET', '/v1.45/info')[0], 502)


class ResponseFramingTests(unittest.TestCase):
    def test_content_length_complete_when_read1_does_not_auto_close(self):
        class Peer:
            def makefile(self, *args):
                return BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
        class LegacyResponse(http.client.HTTPResponse):
            def read1(self, size=-1):
                # Python 3.10-3.13 do not close the file at length == 0.
                data = self.fp.read1(min(size, self.length))
                self.length -= len(data)
                return data
        response = LegacyResponse(Peer())
        response.begin()
        self.assertEqual(host._complete_json_response(response), (b'{}', {}))
        self.assertTrue(response.isclosed())

    def test_distribution_gateway_imports_in_isolated_python(self):
        path = Path(__file__).resolve().parents[1] / 'scripts/deployment_compose_reader_host.py'
        result = subprocess.run([sys.executable, '-I', '-B', '-c',
                                 'import runpy; runpy.run_path(' + repr(str(path)) + ')'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_complete_chunked_upstream(self):
        class Peer:
            def makefile(self, *args):
                return BytesIO(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n')
        response = http.client.HTTPResponse(Peer())
        response.begin()
        self.assertEqual(host._complete_json_response(response)[1], {})


class ReaderPolicyTests(unittest.TestCase):
    def test_unhashable_policy_items_are_rejected_with_fixed_error(self):
        base = dict(project='blog', daemon_id='daemon-1', reader_certificate_sha256='a' * 64,
                    services=('web',), container_ids=('b' * 64,), image_ids=('sha256:' + 'c' * 64,),
                    network_ids=('d' * 64,), volume_names=('blog_data',))
        for field in ('services', 'container_ids', 'image_ids', 'network_ids', 'volume_names'):
            with self.subTest(field=field):
                values = dict(base, **{field: (['invalid'],)})
                with self.assertRaisesRegex(host.ReaderHostError, '^reader-host-policy-rejected$'):
                    host.ComposeReaderHostPolicy(**values)


if __name__ == '__main__': unittest.main()
