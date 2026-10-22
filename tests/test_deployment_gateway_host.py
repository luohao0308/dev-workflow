"""Real mTLS and local Unix HTTP forwarding; the Docker daemon is synthetic."""
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

from tests import test_deployment_execute as fixture
sys.path.insert(0, str(fixture.ROOT / 'scripts'))
import deployment_gateway_host as host
import deployment_gateway as gateway


class UpstreamCompletionTests(unittest.TestCase):
    def response(self, wire):
        class Peer:
            def makefile(self, *args):
                return BytesIO(wire)
        response = http.client.HTTPResponse(Peer())
        response.begin()
        return response

    def test_partial_declared_body_never_proves_completed_write(self):
        response = self.response(b'HTTP/1.1 201 Created\r\nContent-Length: 100\r\n\r\n{}')
        with self.assertRaises(host.GatewayHostError):
            host._complete_response(response, mutation=True)

    def test_complete_length_and_eof_and_empty_responses(self):
        for wire, expected in ((b'201 Created\r\nContent-Length: 2\r\n\r\n{}', b'{}'),
                               (b'201 Created\r\nConnection: close\r\n\r\n{}', b'{}'),
                               (b'204 No Content\r\n\r\n', b'')):
            self.assertEqual(host._complete_response(self.response(b'HTTP/1.1 ' + wire), mutation=True), expected)

    def test_ambiguous_framing_and_chunked_writes_refused(self):
        for header in (b'Content-Length: 2\r\nContent-Length: 2', b'Transfer-Encoding: chunked',
                       b'Content-Length: 2\r\nTransfer-Encoding: chunked'):
            with self.assertRaises(host.GatewayHostError):
                host._complete_response(self.response(b'HTTP/1.1 201 Created\r\n' + header + b'\r\n\r\n{}'), mutation=True)


@unittest.skipUnless(hasattr(socket, 'AF_UNIX') and shutil.which('openssl'), 'Unix sockets and openssl required')
class GatewayHostTests(unittest.TestCase):
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
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name).resolve()
        self.daemon = fixture.MutableDocker()
        self.calls = []
        self.lost = self.truncated = False
        self.wait = False
        self.entered, self.release = threading.Event(), threading.Event()
        test = self
        class DockerHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                test.calls.append((self.command, self.path, body))
                status, value = test.daemon.write(self.command, self.path, json.loads(body) if body else None)
                test.entered.set()
                if test.wait:
                    test.release.wait(10)
                if test.lost:
                    self.close_connection = True
                    return
                raw = json.dumps(value).encode() if value is not None else b''
                self.send_response(status)
                self.send_header('Content-Length', str(len(raw) + 100 if test.truncated else len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                self.close_connection = True
        class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        try:
            self.upstream = UnixServer(str(self.root / 'docker.sock'), DockerHandler)
        except (PermissionError, OSError) as error:
            if isinstance(error, PermissionError) or getattr(error, 'errno', None) in (1, 13, 36):
                self.skipTest('Local Unix listener unavailable; real gateway remains unverified here')
            raise
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.upstream.shutdown)
        def pin(name):
            return hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory / (name + '.pem')).read_text())).hexdigest()
        self.pin = pin
        p = fixture.runtime.RuntimePolicy(endpoint='https://localhost:2376', server_certificate_sha256=pin('server'),
            daemon_id='synthetic-daemon', repository='fixture/example', environment='staging', target='fixture',
            production=False, project='fixture', components=('web', 'api'),
            catalog_json=json.dumps(dict(schemaVersion=1, images=self.daemon.entries)),
            specifications_json=fixture.recipes.specifications_json(tuple(self.daemon.specs.values())))
        gp = gateway.GatePolicy('host', 'key', 'a' * 64, pin('client'))
        self.key = b'private-host-test-key-only-1234567890'
        self.gate = gateway.FileWriterGate(gp, self.root / 'gate', key=self.key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.directory / 'server.pem'), str(self.directory / 'server.key'))
        context.load_verify_locations(str(self.directory / 'ca.pem'))
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            self.server = host.create_gateway(p, self.gate, tls_context=context, reader_certificate_sha256=pin('reader'),
                docker_socket=self.root / 'docker.sock')
        except PermissionError:
            self.skipTest('Local TCP listener unavailable; real gateway remains unverified here')
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.path = '/v1.45/containers/create?name=dwf-' + 'b' * 64
        self.body = fixture.runtime.canonical(self.daemon.specs[('web', 'sha256:' + 'b' * 64)].to_create(
            'fixture', 'b' * 64)).encode('ascii')
        self.session = self.gate.open_generation(generation='c' * 64, request_hash='d' * 64, receipt_hash='e' * 64,
            operations=(('POST', self.path, hashlib.sha256(self.body).hexdigest()),))
        self.attempt = self.session.prepare_attempt('POST', self.path, self.body)

    def connection(self, name='client'):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(str(self.directory / 'ca.pem'))
        context.load_cert_chain(str(self.directory / (name + '.pem')), str(self.directory / (name + '.key')))
        return http.client.HTTPSConnection('localhost', self.server.server_port, context=context, timeout=10)

    def send(self, name='client', *, headers=None):
        connection = self.connection(name)
        try:
            connection.request('POST', self.path, body=self.body, headers=headers or self.session.headers(self.attempt))
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_real_gateway_requires_admission_principal_body_and_once_only(self):
        self.assertEqual(self.send('reader')[0], 403)
        self.assertFalse(self.calls)
        self.assertEqual(self.send(headers={'X-Dev-Workflow-Generation': 'c' * 64,
            'X-Dev-Workflow-Attempt': 'f' * 64})[0], 403)
        self.assertEqual(self.send()[0], 201)
        self.assertEqual(self.send()[0], 403)
        self.assertEqual(len(self.calls), 1)
        proof = self.gate.close_generation('c' * 64)
        self.gate.validate_proof(proof)
        self.assertEqual(self.send()[0], 403)

    def test_delayed_upstream_cannot_be_declared_quiescent(self):
        self.wait = True
        outcomes = []
        thread = threading.Thread(target=lambda: outcomes.append(self.send()))
        thread.start()
        try:
            self.assertTrue(self.entered.wait(5))
            with self.assertRaises(gateway.GateError):
                self.gate.close_generation('c' * 64)
        finally:
            self.release.set()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcomes[0][0], 201)
        self.gate.validate_proof(self.gate.close_generation('c' * 64))

    def test_unknown_upstream_blocks_despite_visible_success_and_restart(self):
        self.lost = True
        self.assertEqual(self.send()[0], 502)
        self.assertEqual(len(self.daemon.containers), 3)
        reopened = gateway.FileWriterGate(self.gate.policy, self.gate.root, key=self.key)
        with self.assertRaises(gateway.GateError):
            reopened.close_generation('c' * 64)

    def test_truncated_real_upstream_response_stays_unknown_after_restart(self):
        self.truncated = True
        self.assertEqual(self.send()[0], 502)
        self.assertEqual(len(self.daemon.containers), 3)
        reopened = gateway.FileWriterGate(self.gate.policy, self.gate.root, key=self.key)
        with self.assertRaises(gateway.GateError):
            reopened.close_generation('c' * 64)

    def test_signed_gate_info_uses_reader_mtls(self):
        connection = self.connection('reader')
        try:
            connection.request('GET', '/v1.45/workflow/gate-info')
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.gate.verify_info(json.loads(response.read()))
        finally:
            connection.close()


if __name__ == '__main__':
    unittest.main()
