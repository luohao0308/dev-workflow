"""Real mTLS/Unix regression: a timed-out caller must drain the writer."""
import http.client
import os
import shutil
import ssl
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_gate_witness_v3 import GateFixture
from tests import test_deployment_compose_write_gateway_v3_host as gateway_fixture


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX TLS/SSH required')
class ResponseBudgetTests(GateFixture, unittest.TestCase):
    setUpClass = classmethod(gateway_fixture.WriteGatewayTests.setUpClass.__func__)
    tearDownClass = classmethod(gateway_fixture.WriteGatewayTests.tearDownClass.__func__)
    setUp = gateway_fixture.WriteGatewayTests.setUp
    send = gateway_fixture.WriteGatewayTests.send

    def test_close_cancels_and_drains_guard_before_cleanup(self):
        entered, release, closing, closed, handler_done = (threading.Event() for _ in range(5))
        class BlockedGuardCalls(list):
            def append(self, value):
                entered.set()
                if not release.wait(5):
                    raise TimeoutError('test guard not released')
                super().append(value)
        self.guards = BlockedGuardCalls()
        original_handler = self.server.RequestHandlerClass.do_POST
        def handler(*args):
            try:
                return original_handler(*args)
            finally:
                handler_done.set()
        self.server.RequestHandlerClass.do_POST = handler
        original_response = http.client.HTTPSConnection.getresponse
        def short_response(client):
            client.sock.settimeout(.5)
            try:
                return original_response(client)
            except BaseException:
                client.close()
                raise
        caller_errors = []
        def call():
            try:
                with patch.object(http.client.HTTPSConnection, 'getresponse', short_response):
                    self.send()
            except TimeoutError:
                caller_errors.append('timeout')
        caller = threading.Thread(target=call)
        closer = None
        try:
            caller.start()
            self.assertTrue(entered.wait(3), 'request must enter the real guard')
            caller.join(3)
            self.assertFalse(caller.is_alive())
            self.assertEqual(caller_errors, ['timeout'])
            def close():
                closing.set()
                self.server.server_close()
                closed.set()
            closer = threading.Thread(target=close)
            closer.start()
            self.assertTrue(closing.wait(2), 'close must actually start before the guard releases')
            self.assertFalse(closed.wait(.1), 'close returned before handler quiescence')
            release.set()
            closer.join(3)
            self.assertFalse(closer.is_alive())
            self.assertTrue(handler_done.wait(3))
            self.assertEqual(self.writes, [], 'cancelled guard must never forward to Engine')
        finally:
            release.set()
            caller.join(3)
            if closer is not None:
                closer.join(3)
            handler_done.wait(3)

    def test_slow_control_has_headroom_beyond_engine_io_timeout(self):
        # The Engine budget is one second; control work is deliberately slower.
        self.server.shutdown()
        self.server.server_close()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.directory/'server.pem', self.directory/'server.key')
        context.load_verify_locations(self.directory/'ca.pem')
        context.verify_mode = ssl.CERT_REQUIRED
        entered, release = threading.Event(), threading.Event()
        def guard(*args):
            entered.set()
            if not release.wait(3):
                raise TimeoutError('test guard not released')
        self.server = gateway_fixture.host.create_gateway_v3(self.g, tls_context=context,
            docker_socket=self.root/'docker.sock', pre_dispatch=guard,
            timeout=1, control_timeout=3)
        worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(self.server.server_close)
        timer = threading.Timer(1.2, release.set)
        try:
            timer.start()
            self.assertEqual(self.send(), (201, b'{}'))
            self.assertTrue(entered.is_set())
            self.assertEqual(len(self.writes), 1)
        finally:
            release.set()
            timer.cancel()
            timer.join()

    def test_cancel_after_admission_prevents_engine_and_keeps_unknown_frozen(self):
        entered, release, closing, closed = (threading.Event() for _ in range(4))
        original_admit = gateway_fixture.host.FileWriterGate.admit
        def paused_admit(gate, *args, **kwargs):
            ticket = original_admit(gate, *args, **kwargs)
            entered.set()
            if not release.wait(5):
                raise TimeoutError('test admission not released')
            return ticket
        caller_errors = []
        def call():
            try:
                self.send()
            except (OSError, http.client.HTTPException) as error:
                caller_errors.append(type(error).__name__)
        caller = threading.Thread(target=call)
        closer = None
        try:
            with patch.object(gateway_fixture.host.FileWriterGate, 'admit', paused_admit):
                caller.start()
                self.assertTrue(entered.wait(3))
                def close():
                    closing.set()
                    self.server.server_close()
                    closed.set()
                closer = threading.Thread(target=close)
                closer.start()
                self.assertTrue(closing.wait(2))
                self.assertFalse(closed.wait(.1))
                release.set()
                closer.join(3)
                caller.join(3)
                self.assertFalse(closer.is_alive())
                self.assertFalse(caller.is_alive())
            self.assertEqual(self.writes, [])
            status = self.client.read()
            self.assertEqual(status['phase'], 'blocked')
            self.assertEqual(status['seq'], 4)
            with self.assertRaises(ValueError):
                self.g.close_generation(self.gen)
        finally:
            release.set()
            caller.join(3)
            if closer is not None:
                closer.join(3)

    def test_deadline_after_actual_admission_prevents_forwarding(self):
        expired = threading.Event()
        original_admit = gateway_fixture.host.FileWriterGate.admit
        monotonic = time.monotonic
        def admit_then_expire(gate, *args, **kwargs):
            ticket = original_admit(gate, *args, **kwargs)
            expired.set()
            return ticket
        clock = SimpleNamespace(monotonic=lambda: monotonic()+(181 if expired.is_set() else 0))
        with patch.object(gateway_fixture.host, 'time', clock):
            with patch.object(gateway_fixture.host.FileWriterGate, 'admit', admit_then_expire):
                self.assertEqual(self.send()[0], 403)
        self.assertTrue(expired.is_set())
        self.assertFalse(self.server.cancelled.is_set(), 'deadline must act without explicit cancellation')
        self.assertEqual(self.writes, [])
        self.assertEqual(self.client.read()['phase'], 'blocked')
        with self.assertRaises(ValueError):
            self.g.close_generation(self.gen)

    def test_forward_wins_then_response_loss_never_retries_or_unfreezes(self):
        forwarded = threading.Event()
        class ObservedWrites(list):
            def append(self, value):
                super().append(value)
                forwarded.set()
        self.writes = ObservedWrites()
        self.mode = 'timeout'
        caller_results = []
        def call():
            try:
                caller_results.append(self.send()[0])
            except (OSError, http.client.HTTPException) as error:
                caller_results.append(type(error).__name__)
        caller = threading.Thread(target=call)
        try:
            caller.start()
            self.assertTrue(forwarded.wait(3), 'actual Unix request must win before cancel')
            self.server.cancel()
            self.release.set()  # Backend closes without a response after one write.
            self.server.server_close()
            caller.join(3)
            self.assertFalse(caller.is_alive())
            self.assertEqual(len(caller_results), 1)
            self.assertEqual(len(self.writes), 1)
            self.assertEqual(self.client.read()['phase'], 'blocked')
            with self.assertRaises(ValueError):
                self.g.close_generation(self.gen)
            self.assertEqual(len(self.writes), 1)
        finally:
            self.release.set()
            caller.join(3)
