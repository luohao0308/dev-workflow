"""Real loopback mTLS checks for the fixed-route Compose Docker reader."""
from dataclasses import replace
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import ssl
import sys
import threading
import time
import unittest
from unittest import mock

from tests.test_deployment_compose_reader import reader
from tests import test_deployment_runtime as runtime_tests


@unittest.skipUnless(shutil.which('openssl'), 'openssl required for local mTLS fixture')
class ComposeReaderLoopbackTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the existing short-lived CA, server, wrong-host and client certs.
        runtime_tests.LocalTLSRuntimeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        runtime_tests.LocalTLSRuntimeTests.tearDownClass.__func__(cls)

    def start_server(self, *, certificate='server', behavior='normal'):
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append((self.command, self.path, bool(self.connection.getpeercert())))
                if behavior == 'disconnect':
                    self.connection.shutdown(2)
                    return
                if behavior == 'slow':
                    time.sleep(2)
                body = b'{"ID":"fixture-daemon"}' if self.path == '/v1.45/info' else b'[]'
                try:
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body) + (behavior == 'slow-body')))
                    self.end_headers()
                    self.wfile.write(body)
                    if behavior == 'slow-body':
                        self.wfile.flush()
                        time.sleep(2)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass
            def log_message(self, *args):
                pass
        class Server(ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                # A pin rejection closes the TLS socket before any HTTP bytes.
                if isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError)):
                    return
                super().handle_error(request, client_address)
        try:
            server = Server(('127.0.0.1', 0), Handler)
        except PermissionError:
            self.skipTest('Loopback binding unavailable')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.directory / (certificate + '.pem')),
                                str(self.directory / (certificate + '.key')))
        context.load_verify_locations(str(self.directory / 'ca.pem'))
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 3)
        self.addCleanup(server.shutdown)
        der = ssl.PEM_cert_to_DER_cert((self.directory / (certificate + '.pem')).read_text())
        policy = reader.ComposeReadPolicy('https://localhost:' + str(server.server_port),
                                          hashlib.sha256(der).hexdigest(), 'fixture-daemon', 'blog')
        return policy, calls

    def client(self, policy, *, timeout=2):
        return reader.ComposeDockerReader(policy, ca_file=self.directory / 'ca.pem',
                                          cert_file=self.directory / 'client.pem',
                                          key_file=self.directory / 'client.key', timeout=timeout)

    def test_valid_ca_hostname_pin_and_client_certificate_use_only_exact_get_routes(self):
        policy, calls = self.start_server()
        client = self.client(policy)
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'http://invalid:1',
                                          'DOCKER_HOST': 'unix:///invalid'}):
            self.assertEqual(client.get('/v1.45/info'), {'ID': 'fixture-daemon'})
            self.assertEqual(client.get(client.list_path), [])
            with self.assertRaises(reader.ComposeReadError) as denied:
                client.get('/v1.45/containers/create')
        self.assertEqual(denied.exception.code, 'route-refused')
        self.assertEqual(calls, [('GET', '/v1.45/info', True),
                                 ('GET', client.list_path, True)])

    def test_wrong_pin_rejects_before_http_request(self):
        policy, calls = self.start_server()
        with self.assertRaises(reader.ComposeReadError) as caught:
            self.client(replace(policy, server_certificate_sha256='0' * 64)).get('/v1.45/info')
        self.assertEqual(caught.exception.code, 'pin-mismatch')
        self.assertEqual(calls, [])

    def test_wrong_hostname_rejects_before_http_request_without_certificate_detail(self):
        policy, calls = self.start_server(certificate='wronghost')
        with self.assertRaises(reader.ComposeReadError) as caught:
            self.client(policy).get('/v1.45/info')
        self.assertEqual(caught.exception.code, 'transport-unavailable')
        self.assertEqual(calls, [])
        self.assertNotIn('wrong.invalid', str(caught.exception))

    def test_timeout_and_disconnect_return_finite_secret_free_codes(self):
        for behavior, timeout, expected in (('slow', 1, 'deadline-exceeded'),
                                             ('disconnect', 2, 'transport-unavailable')):
            with self.subTest(behavior=behavior):
                policy, calls = self.start_server(behavior=behavior)
                with self.assertRaises(reader.ComposeReadError) as caught:
                    self.client(policy, timeout=timeout).get('/v1.45/info')
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(len(calls), 1)
                self.assertNotIn(str(self.directory), str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)

    def test_watchdog_shutdown_before_socket_timeout_is_deadline_exceeded(self):
        original = reader.http.client.HTTPSConnection.getresponse
        def wait_for_watchdog(connection):
            # Isolate the timer path from the competing socket timeout. A timer
            # shutdown produces RemoteDisconnected rather than socket.timeout.
            connection.sock.settimeout(4)
            return original(connection)
        for behavior in ('slow', 'slow-body'):
            with self.subTest(behavior=behavior):
                policy, calls = self.start_server(behavior=behavior)
                with mock.patch.object(reader.http.client.HTTPSConnection, 'getresponse', wait_for_watchdog):
                    with self.assertRaises(reader.ComposeReadError) as caught:
                        self.client(policy, timeout=1).get('/v1.45/info')
                self.assertEqual(caught.exception.code, 'deadline-exceeded')
                self.assertEqual(len(calls), 1)
                self.assertNotIn(str(self.directory), str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)


if __name__ == '__main__':
    unittest.main()
