"""Real mTLS and signed witness, with a local Unix HTTP Engine double."""
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
import shutil
import socketserver
import ssl
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_gate_witness_v3 import GateFixture, signed
from tests import test_deployment_runtime as tls_fixture
from deployment_compose_host_snapshot_v3_host import HostSnapshotV3
from deployment_compose_production_cutover_v1_host import ContainerOperation
import deployment_compose_retained_write_v1_host as retained_write
from deployment_compose_retained_write_v1_host import RetainedDockerWriteUncertain, RetainedWriteV1
from deployment_compose_write_gateway_v3_host import _UnixDocker
from deployment_gateway import GatePolicy, WriterSession


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX, OpenSSL and OpenSSH required')
class RetainedWriteTests(GateFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tls_fixture.LocalTLSRuntimeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.setup_gate_fixture()
        self.pins = dict(request_hash='1'*64, receipt_hash='2'*64, plan_digest='3'*64)
        self.create = ContainerOperation('create', '/v1.45/containers/create?name=dwc-'+'a'*24+'-frontend', b'{}')
        self.stop = ContainerOperation('stop-original', '/v1.45/containers/'+'b'*64+'/stop?t=10')
        desc = RetainedWriteV1.scope_descriptor(self.create, **self.pins, index=0)
        self.policy = GatePolicy('retained-test', 'retained-key', '4'*64, self._pin('client'),
                                 True, desc['scopeHash'], self.client.key_hash, operation_profile='compose-v3')
        binding = dict(scopeHash=desc['scopeHash'], epoch='5'*64, generation=desc['generation'],
                       policyHash=self.policy.identity_hash())
        witness_root = self.root/'retained-witness'
        witness_root.mkdir(mode=0o700)
        self.store = signed.OperationWitnessStoreV3(witness_root, key=b'w'*32)
        self.addCleanup(self.store.close)
        self.store.register_once(binding)

        self.calls_engine = []
        self.disconnect = False
        self.create_status = 201
        test = self

        class Engine(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                test.calls_engine.append((self.path, self.rfile.read(int(self.headers['Content-Length']))))
                if test.disconnect:
                    return
                creating = '/create?' in self.path
                body = json.dumps(dict(Id='f'*64)).encode() if creating else b''
                self.send_response(test.create_status if creating else 204)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        socket = self.root/'retained.sock'
        server = socketserver.UnixStreamServer(str(socket), Engine)
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()
        self.addCleanup(server.server_close)
        self.addCleanup(serving.join, 3)
        self.addCleanup(server.shutdown)

        observer = object.__new__(HostSnapshotV3)
        # Only the native endpoint proof is doubled. The bound connection and
        # the mTLS handler still send actual HTTP over their respective sockets.
        socket_patch = patch.object(HostSnapshotV3, '_write_socket', return_value=socket)
        conn_patch = patch.object(HostSnapshotV3, '_bound_write_connection',
                                  side_effect=lambda timeout, expires_at=None: _UnixDocker(str(socket), timeout))
        for fixture in (socket_patch, conn_patch):
            fixture.start()
            self.addCleanup(fixture.stop)

        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.directory/'server.pem', self.directory/'server.key')
        server_tls.load_verify_locations(self.directory/'ca.pem')
        server_tls.verify_mode = ssl.CERT_REQUIRED
        client_tls = ssl.create_default_context(cafile=self.directory/'ca.pem')
        client_tls.load_cert_chain(self.directory/'client.pem', self.directory/'client.key')
        self.writer = RetainedWriteV1(gate_policy=self.policy, gate_root=self.root/'retained-gate',
            gate_key=b'g'*32, witness_client_factory=self._client, registered_binding=binding,
            tls_server_context=server_tls, tls_client_context=client_tls,
            server_certificate_sha256=self._pin('server'), observer=observer, timeout=10)
        self.guards = []

    def _client(self, binding):
        return signed.OperationWitnessClientV3(binding, self.public, self.transport)

    def _pin(self, name):
        der = ssl.PEM_cert_to_DER_cert((self.directory/(name+'.pem')).read_text())
        return hashlib.sha256(der).hexdigest()

    def _guard(self):
        self.guards.append(threading.current_thread())

    def test_two_closed_operations_and_guard_on_lease_thread(self):
        expires_at = time.time() + 60
        status, raw, digest = self.writer.write(self.create, **self.pins, index=0,
                                                before_dispatch=self._guard, expires_at=expires_at)
        self.assertEqual((status, json.loads(raw)), (201, {'Id':'f'*64}))
        self.assertRegex(digest, r'^[0-9a-f]{64}$')
        status, raw, digest2 = self.writer.write(self.stop, **self.pins, index=1,
                                                  before_dispatch=self._guard, expires_at=expires_at)
        self.assertEqual((status, raw), (204, b''))
        self.assertNotEqual(digest, digest2)
        self.assertEqual(self.calls_engine, [(self.create.path, b'{}'), (self.stop.path, b'')])
        self.assertTrue(self.guards)
        self.assertTrue(all(t is threading.current_thread() for t in self.guards))

    def test_guard_at_admission_failure_never_writes_and_blocks_retry(self):
        def guard():
            self._guard()
            if len(self.guards) == 3:
                raise ValueError('phase drift')
        with self.assertRaises(ValueError):
            self.writer.write(self.create, **self.pins, index=0, before_dispatch=guard)
        self.assertEqual(len(self.guards), 3)
        self.assertFalse(self.calls_engine)
        with self.assertRaises(ValueError):
            self.writer.write(self.create, **self.pins, index=0, before_dispatch=self._guard)
        self.assertFalse(self.calls_engine)

    def test_unknown_upstream_result_blocks_retry_and_successor(self):
        self.disconnect = True
        with self.assertRaises(RetainedDockerWriteUncertain) as error:
            self.writer.write(self.create, **self.pins, index=0, before_dispatch=self._guard)
        self.assertEqual(error.exception.stage, 'docker-response')
        for index, operation in enumerate((self.create, self.stop)):
            with self.assertRaises(ValueError):
                self.writer.write(operation, **self.pins, index=index, before_dispatch=self._guard)
        self.assertEqual(self.calls_engine, [(self.create.path, b'{}')])

    def test_connect_failure_after_admission_keeps_scope_blocked_and_reports_stage(self):
        with patch.object(HostSnapshotV3, '_bound_write_connection', side_effect=OSError('private detail')):
            with self.assertRaises(RetainedDockerWriteUncertain) as error:
                self.writer.write(self.create, **self.pins, index=0, before_dispatch=self._guard)
        self.assertEqual(error.exception.stage, 'docker-connect')
        self.assertNotIn('private detail', str(error.exception))
        self.assertFalse(self.calls_engine)
        with self.assertRaises(ValueError):
            self.writer.write(self.create, **self.pins, index=0, before_dispatch=self._guard)

    def test_definitive_failure_is_returned_but_no_more_steps(self):
        self.create_status = 409
        status, _, digest = self.writer.write(self.create, **self.pins, index=0, before_dispatch=self._guard)
        self.assertEqual(status, 409)
        self.assertRegex(digest, r'^[0-9a-f]{64}$')
        with self.assertRaises(ValueError):
            self.writer.write(self.stop, **self.pins, index=1, before_dispatch=self._guard)
        self.assertEqual(len(self.calls_engine), 1)

    def test_foreign_thread_cannot_use_the_registered_writer(self):
        errors = []

        def attempt():
            try:
                self.writer.write(self.create, **self.pins, index=0, before_dispatch=self._guard)
            except ValueError as error:
                errors.append(str(error))

        thread = threading.Thread(target=attempt)
        thread.start()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ['retained-frontend-write-blocked'])
        self.assertEqual(self.guards, [])
        self.assertEqual(self.calls_engine, [])
        status, _, _ = self.writer.write(self.create, **self.pins, index=0, before_dispatch=self._guard)
        self.assertEqual(status, 201)

    def test_expired_authorization_rejects_before_guards_and_engine(self):
        with self.assertRaises(ValueError):
            self.writer.write(self.create, **self.pins, index=0,
                              before_dispatch=self._guard, expires_at=time.time() - 1)
        self.assertEqual(self.guards, [])
        self.assertEqual(self.calls_engine, [])

    def test_dispatch_uses_fresh_signed_window_after_witness_preparation(self):
        now = time.time()
        expires_at = now + 120
        clock = SimpleNamespace(monotonic=time.monotonic, time=lambda: now)
        relay = self.writer._relay
        prepare_attempt = WriterSession.prepare_attempt
        deadlines = []

        def delayed_prepare(session, *args):
            nonlocal now
            attempt = prepare_attempt(session, *args)
            now += 31
            return attempt

        def guard():
            self._guard()
            deadlines.append(now + 30)
            return deadlines[-1]

        with (patch.object(retained_write, 'time', clock),
              patch.object(WriterSession, 'prepare_attempt', delayed_prepare),
              patch.object(self.writer, '_relay', wraps=relay) as dispatch):
            status, _, _ = self.writer.write(self.create, **self.pins, index=0,
                                            before_dispatch=guard, expires_at=expires_at)
        self.assertEqual(status, 201)
        self.assertEqual(dispatch.call_args.args[-1], deadlines[1])
        self.assertLess(deadlines[0], now)
        self.assertEqual(self.calls_engine, [(self.create.path, b'{}')])

    def test_authorization_expiring_during_final_guard_never_reaches_engine(self):
        now = time.time()
        expires_at = now + 60
        clock = SimpleNamespace(monotonic=time.monotonic, time=lambda: now)

        def guard():
            nonlocal now
            self._guard()
            if len(self.guards) == 3:
                now = expires_at

        with patch.object(retained_write, 'time', clock), self.assertRaises(ValueError):
            self.writer.write(self.create, **self.pins, index=0,
                              before_dispatch=guard, expires_at=expires_at)
        self.assertEqual(len(self.guards), 3)
        self.assertEqual(self.calls_engine, [])

    def test_definitive_post_response_closes_after_authorization_expiry(self):
        now = time.time()
        expires_at = now + 60
        clock = SimpleNamespace(monotonic=time.monotonic, time=lambda: now)
        relay = self.writer._relay

        def delivered(*args):
            nonlocal now
            result = relay(*args)
            now = expires_at
            return result

        with patch.object(retained_write, 'time', clock), patch.object(self.writer, '_relay', side_effect=delivered):
            status, _, evidence = self.writer.write(
                self.create, **self.pins, index=0, before_dispatch=self._guard, expires_at=expires_at,
            )
        self.assertEqual(status, 201)
        self.assertRegex(evidence, r'^[0-9a-f]{64}$')
        self.assertEqual(self.writer._client.read()['phase'], 'closed')
