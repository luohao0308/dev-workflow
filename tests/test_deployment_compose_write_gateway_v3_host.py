"""Real mTLS, Unix backend and signed independent witness integration."""
import base64
from dataclasses import replace
import hashlib
import http.client
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import subprocess
from unittest.mock import patch
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tests.test_deployment_compose_gate_witness_v3 import GateFixture, signed
import deployment_compose_write_gateway_v3_host as host
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from tests import test_deployment_runtime as tls_fixture


class ResponseTests(unittest.TestCase):
    def test_bounded_strict_completion(self):
        class Peer:
            def __init__(self, raw): self.raw = raw
            def makefile(self, *args): return BytesIO(self.raw)
        for suffix in (b'Content-Length: 9\r\n\r\nx', b'Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
                       b'Content-Length: 65537\r\n\r\n', b'Broken header\r\n\r\n',
                       b'Content-Length: 1\r\nContent-Length: 1\r\n\r\nx'):
            response = http.client.HTTPResponse(Peer(b'HTTP/1.1 200 OK\r\n' + suffix)); response.begin()
            with self.assertRaises(ValueError): host._complete_response(response)


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'), 'TLS/SSH required')
class WriteGatewayTests(GateFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tls_fixture.LocalTLSRuntimeTests.setUpClass.__func__(cls)
        for args in [('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'other.key', '-out', 'other.csr', '-subj', '/CN=other'),
                     ('x509', '-req', '-in', 'other.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'other.pem', '-days', '1', '-extfile', 'client.ext')]:
            subprocess.run(['openssl', *args], cwd=cls.directory, check=True, capture_output=True)
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def setUp(self):
        self.setup_gate_fixture()
        cert = hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'client.pem').read_text())).hexdigest()
        self.policy = replace(self.policy, writer_certificate_sha256=cert)
        self.binding = dict(self.binding, policyHash=self.policy.identity_hash())
        (self.root/'actual-witness').mkdir(mode=0o700)
        self.store = signed.OperationWitnessStoreV3(self.root/'actual-witness', key=b'w'*32)
        self.addCleanup(self.store.close); self.store.register_once(self.binding)
        self.client = signed.OperationWitnessClientV3(self.binding, self.public, self.transport)
        self.adapter = GateOperationWitnessAdapterV3(self.client)
        self.g = self.gate(); session = self.opening(self.g)
        self.attempt = session.prepare_attempt(*self.ops[0][:2], self.body)
        self.writes = []; self.mode = 'ok'; self.guard_failure = False; self.guards = []
        owner = self
        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                owner.writes.append((self.path, self.rfile.read(int(self.headers['Content-Length']))))
                if owner.mode == 'disconnect': return
                if owner.mode == 'timeout':
                    owner.release.wait(3); return
                self.send_response(201)
                self.send_header('Content-Length', '99' if owner.mode == 'truncate' else '2')
                self.end_headers(); self.wfile.write(b'{}')
        class Unix(socketserver.ThreadingMixIn, socketserver.UnixStreamServer): daemon_threads = True
        self.release = threading.Event(); self.addCleanup(self.release.set)
        self.backend = Unix(str(self.root/'docker.sock'), Backend)
        threading.Thread(target=self.backend.serve_forever, daemon=True).start()
        self.addCleanup(self.backend.server_close); self.addCleanup(self.backend.shutdown)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.directory/'server.pem', self.directory/'server.key')
        context.load_verify_locations(self.directory/'ca.pem'); context.verify_mode = ssl.CERT_REQUIRED
        def guard(*args):
            self.guards.append(args)
            if self.guard_failure: raise ValueError('guard-failed')
        self.server = host.create_gateway_v3(self.g, tls_context=context, docker_socket=self.root/'docker.sock', pre_dispatch=guard, timeout=1)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close); self.addCleanup(self.server.shutdown)

    def _owned_executor_for_cleanup(self):
        from deployment_compose_coordinator_v3_host import Profile3StepExecutor
        executor=object.__new__(Profile3StepExecutor)
        executor._owner_pid=os.getpid();executor._owned_transport=unittest.mock.Mock()
        until=time.monotonic()+2
        while self.server.owner is None and time.monotonic()<until:time.sleep(.001)
        owner=next(t for t in threading.enumerate() if t.ident==self.server.owner)
        executor._owned_gateway=(self.server,owner);executor._owned_gateway_token=None
        executor._lock=threading.Lock();executor._blocked=True
        return executor,owner

    def test_owned_expired_drain_retains_resources_for_cleanup_only_retry(self):
        executor,owner=self._owned_executor_for_cleanup()
        with self.assertRaises(host.GatewayHostError):
            executor._retry_owned_cleanup(time.monotonic()-1)
        self.assertTrue(self.server.closing)
        self.assertIsNotNone(executor._owned_gateway)
        self.assertIsNone(executor._owned_gateway_token)
        self.assertTrue(owner.is_alive())
        self.assertTrue(hasattr(self.server,'_blocked_drain'))
        executor._owned_transport.close.assert_called_once()
        token=executor.retry_owned_cleanup(time.monotonic()+2)
        self.assertIsNotNone(token)
        self.assertIsNone(executor._owned_gateway)
        self.assertFalse(owner.is_alive())
        self.assertEqual(self.server.fileno(),-1)
        self.assertTrue(executor._blocked)

    def test_owned_dispatch_lock_timeout_retains_resources_until_release(self):
        executor,owner=self._owned_executor_for_cleanup()
        self.server.dispatch_lock.acquire()
        try:
            with self.assertRaises(host.GatewayHostError):
                executor.retry_owned_cleanup(time.monotonic()+.02)
            self.assertTrue(self.server.closing)
            self.assertIsNotNone(executor._owned_gateway)
            self.assertIsNone(executor._owned_gateway_token)
            self.assertTrue(owner.is_alive())
            executor._owned_transport.close.assert_called_once()
        finally:self.server.dispatch_lock.release()
        executor.retry_owned_cleanup(time.monotonic()+2)
        self.assertIsNone(executor._owned_gateway)
        self.assertIsNotNone(executor._owned_gateway_token)
        self.assertFalse(owner.is_alive())
        self.assertEqual(self.server.fileno(),-1)
        self.assertTrue(executor._blocked)

    def test_owned_drain_before_serve_enters_has_no_shutdown_waiter(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.directory/'server.pem',self.directory/'server.key')
        context.load_verify_locations(self.directory/'ca.pem');context.verify_mode=ssl.CERT_REQUIRED
        server=host.create_gateway_v3(self.g,tls_context=context,
            docker_socket=self.root/'docker.sock',pre_dispatch=lambda *a:None,timeout=1)
        entered=threading.Event();release=threading.Event()
        def delayed():
            entered.set();release.wait(2);server.serve_forever()
        owner=threading.Thread(target=delayed,daemon=True);owner.start()
        self.assertTrue(entered.wait(1))
        timer=threading.Timer(.05,release.set);timer.start()
        try:
            server.drain_owned(owner,time.monotonic()+1)
            self.assertFalse(owner.is_alive())
            self.assertFalse(hasattr(server,'_blocked_drain'))
        finally:
            release.set();owner.join(1);timer.join(1);server.server_close()

    def test_owned_drain_blocked_handler_has_no_false_success(self):
        entered=threading.Event();release=threading.Event()
        original=self.server.RequestHandlerClass._handle
        def blocked(handler):
            entered.set();release.wait(2);return original(handler)
        self.server.RequestHandlerClass._handle=blocked
        self.server.RequestHandlerClass.do_POST=blocked
        def call():
            try:self.send(body=self.body)
            except Exception:pass
        caller=threading.Thread(target=call,daemon=True);caller.start()
        self.assertTrue(entered.wait(2))
        owner=next(t for t in threading.enumerate() if t.ident==self.server.owner)
        try:
            with self.assertRaises(host.GatewayHostError):
                self.server.drain_owned(owner,time.monotonic()+.05)
            self.assertTrue(owner.is_alive())
            self.assertTrue(hasattr(self.server,'_blocked_drain'))
        finally:
            release.set();caller.join(3);owner.join(3)
            for thread in getattr(self.server,'_blocked_drain',()):
                if thread.ident is not None:thread.join(3)

    def send(self, method='POST', path=None, extra=(), body=b'', certificate='client'):
        context = ssl.create_default_context(cafile=self.directory/'ca.pem')
        context.load_cert_chain(self.directory/(certificate+'.pem'), self.directory/(certificate+'.key'))
        client = http.client.HTTPSConnection('localhost', self.server.server_port, context=context, timeout=4)
        client.putrequest(method, path or self.ops[0][1])
        for key, value in [('Content-Length', str(len(body))), ('X-Dev-Workflow-Generation', self.gen),
                           ('X-Dev-Workflow-Attempt', self.attempt.ref), *extra]: client.putheader(key, value)
        client.endheaders(body)
        response = client.getresponse(); result = response.status, response.read(); client.close()
        return result

    def test_valid_response_persisted_and_duplicate_blocked(self):
        original_reply = self.server.RequestHandlerClass._reply
        owner = self
        def checked_reply(handler, status, body):
            if status == 201:
                local = owner.g.generation_evidence(owner.gen)
                owner.assertTrue(any(e['kind'] == 'finish' for e in local['events']))
                remote = owner.adapter.authenticated_material_after()['records']
                owner.assertTrue(any(b'bodyBase64' in base64.b64decode(r['externalMaterialBase64']) for r in remote))
            return original_reply(handler, status, body)
        with patch.object(self.server.RequestHandlerClass, '_reply', checked_reply):
            self.assertEqual(self.send(), (201, b'{}'))
        evidence = self.g.generation_evidence(self.gen)
        finish = [e['data'] for e in evidence['events'] if e['kind'] == 'finish'][0]
        self.assertEqual(base64.b64decode(finish['bodyBase64']), b'{}')
        records = self.adapter.authenticated_material_after()['records']
        self.assertTrue(any(b'bodyBase64' in base64.b64decode(r['externalMaterialBase64']) for r in records))
        self.assertEqual(self.send()[0], 403); self.assertEqual(len(self.writes), 1)

    def test_denials_never_forward(self):
        for kwargs in (dict(method='GET'), dict(path=self.ops[0][1]+'x'), dict(body=b'x'),
                       dict(extra=[('Content-Length', '0')]), dict(extra=[('Transfer-Encoding', 'chunked')]),
                       dict(extra=[('Expect', '100-continue')]), dict(extra=[('X-Dev-Workflow-Attempt', 'f'*64)])):
            self.assertEqual(self.send(**kwargs)[0], 403)
        self.guard_failure = True
        self.assertEqual(self.send()[0], 403); self.assertEqual(self.writes, [])

    def test_truncation_blocks_generation(self):
        self.mode = 'truncate'; self.assertEqual(self.send()[0], 502)
        with self.assertRaises(ValueError): self.g.close_generation(self.gen)
        self.assertEqual(self.send()[0], 403); self.assertEqual(len(self.writes), 1)

    def test_disconnect_blocks_generation(self):
        self.mode = 'disconnect'; self.assertEqual(self.send()[0], 502)
        with self.assertRaises(ValueError): self.g.close_generation(self.gen)

    def test_timeout_blocks_generation(self):
        self.mode = 'timeout'; self.assertEqual(self.send()[0], 502)
        with self.assertRaises(ValueError): self.g.close_generation(self.gen)

    def test_wrong_authenticated_certificate_is_denied(self):
        self.assertEqual(self.send(certificate='other')[0], 403)
        self.assertEqual(self.writes, [])

    def test_finish_ack_loss_never_retries_or_invents_completion(self):
        original = self.g._write
        def fail_response(path, envelope):
            if isinstance(envelope, dict) and envelope.get('payload', {}).get('kind') == 'finish':
                raise OSError('local acknowledgement lost')
            return original(path, envelope)
        with patch.object(self.g, '_write', side_effect=fail_response):
            self.assertEqual(self.send()[0], 502)
        self.assertEqual(len(self.writes), 1)
        self.assertEqual(self.send()[0], 403)
        with self.assertRaises(ValueError): self.g.close_generation(self.gen)
        records = self.adapter.authenticated_material_after()['records']
        events = [json.loads(base64.b64decode(r['externalMaterialBase64']))['payload'] for r in records]
        finishes = [e['data'] for e in events if e.get('kind') == 'finish']
        self.assertEqual(len(finishes), 1)
        self.assertEqual(finishes[0]['bodyBase64'], 'e30=')

    def test_malformed_raw_header_never_forwards(self):
        context = ssl.create_default_context(cafile=self.directory/'ca.pem')
        context.load_cert_chain(self.directory/'client.pem', self.directory/'client.key')
        with socket.create_connection(('localhost', self.server.server_port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname='localhost') as client:
                request = ('POST ' + self.ops[0][1] + ' HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n'
                           + 'X-Dev-Workflow-Generation: ' + self.gen + '\r\n'
                           + 'X-Dev-Workflow-Attempt: ' + self.attempt.ref + '\r\nBad Header: value\r\n\r\n')
                client.sendall(request.encode('ascii'))
                self.assertIn(b'403', client.recv(4096).split(b'\r\n')[0])
        self.assertEqual(self.writes, [])
