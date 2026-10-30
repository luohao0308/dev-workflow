"""Real mTLS/Unix stop responses must outlive the authorized grace interval."""
import http.client
import inspect
import os
import shutil
import ssl
import threading
import unittest

from tests.test_deployment_compose_gate_witness_v3 import GateFixture
from tests import test_deployment_compose_write_gateway_v3_host as fixture
from deployment_compose_coordinator_v3_host import Profile3StepExecutor

STOP = '/v1.45/containers/' + 'a'*64 + '/stop?t=10'


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX TLS/SSH required')
class StopBudgetTests(GateFixture, unittest.TestCase):
    setUpClass = classmethod(fixture.WriteGatewayTests.setUpClass.__func__)
    tearDownClass = classmethod(fixture.WriteGatewayTests.tearDownClass.__func__)

    def setup_gate_fixture(self, path=None):
        GateFixture.setup_gate_fixture(self, STOP)

    def setUp(self):
        fixture.WriteGatewayTests.setUp(self)
        self.delay = 0
        owner = self
        def delayed_stop(handler):
            owner.writes.append((handler.path, handler.rfile.read(int(handler.headers['Content-Length']))))
            owner.release.wait(owner.delay)
            try:
                handler.send_response(204)
                handler.send_header('Content-Length', '0')
                handler.end_headers()
            except OSError:
                pass  # The short-budget case intentionally abandons its response.
        self.backend.RequestHandlerClass.do_POST = delayed_stop

    def use_budget(self, budget):
        self.server.shutdown()
        self.server.server_close()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.directory/'server.pem', self.directory/'server.key')
        context.load_verify_locations(self.directory/'ca.pem')
        context.verify_mode = ssl.CERT_REQUIRED
        self.server = fixture.host.create_gateway_v3(self.g, tls_context=context,
            docker_socket=self.root/'docker.sock', pre_dispatch=lambda *args: None,
            timeout=budget)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.budget = budget

    def send_stop(self):
        context = ssl.create_default_context(cafile=self.directory/'ca.pem')
        context.load_cert_chain(self.directory/'client.pem', self.directory/'client.key')
        connection = http.client.HTTPSConnection('localhost', self.server.server_port,
            context=context, timeout=self.budget+5)
        try:
            connection.request('POST', STOP, body=b'', headers={
                'Content-Length': '0', 'Connection': 'close',
                'X-Dev-Workflow-Generation': self.gen,
                'X-Dev-Workflow-Attempt': self.attempt.ref})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_short_budget_leaves_one_stop_unknown_and_never_retries(self):
        self.delay = 1.2
        self.use_budget(1)
        self.assertEqual(self.send_stop()[0], 502)
        view = self.client.read()
        self.assertEqual((view['phase'], view['seq']), ('blocked', 4))
        with self.assertRaises(ValueError):
            self.g.close_generation(self.gen)
        self.assertEqual(self.send_stop()[0], 403)
        self.assertEqual(self.writes, [(STOP, b'')])

    def test_executor_default_captures_stop_after_full_ten_second_grace(self):
        # Use the real executor default, passed unchanged to its write gateway.
        budget = inspect.signature(Profile3StepExecutor).parameters['timeout'].default
        self.delay = 10.2
        self.use_budget(budget)
        self.assertEqual(self.send_stop(), (204, b''))
        proof = self.g.close_generation(self.gen)
        self.assertTrue(self.g.validate_proof(proof))
        self.assertEqual(self.writes, [(STOP, b'')])
        view = self.client.read()
        self.assertEqual((view['phase'], view['seq']), ('closed', 6))
        records = self.adapter.authenticated_material_after()['records']
        response = records[3]['event']['data']
        self.assertIs(response['definitive'], True)
        self.assertEqual(response['status'], 204)
