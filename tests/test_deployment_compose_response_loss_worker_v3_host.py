"""Fixed diagnostic leaf tests; no Docker, SSH, production or approval calls."""
import http.client
import os
import shutil
from pathlib import Path
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_response_loss_worker_v3_host as diagnostic

PATH='/v1.45/containers/create?name=dwc-'+'a'*24+'-backend'

def config():
    return dict(entrypoint=diagnostic.ENTRYPOINT,channelNonce='1'*64,sourceSha='2'*40,
                archiveDigest='3'*64,hostId='host-one')


class ConnectorTests(unittest.TestCase):
    def fake(self, fail=False):
        calls=[]
        class Connection:
            def __init__(self,*args,**kwargs):pass
            def request(self,*args,**kwargs):
                calls.append(('request',args,kwargs))
                if fail:raise RuntimeError('partial-send')
                return 'sent'
            def getresponse(self):calls.append(('response',));return 'read'
            def close(self):calls.append(('close',));raise OSError('close-secondary')
        cls,state=diagnostic._connector(Connection)
        return cls,state,calls

    def test_first_write_forwards_exact_arguments_then_never_reads_response(self):
        cls,state,calls=self.fake();c=cls()
        self.assertEqual(c.request('POST',PATH,b'body',{'x':'y'},encode_chunked=True),'sent')
        self.assertEqual(calls[0],('request',('POST',PATH,b'body',{'x':'y'}),{'encode_chunked':True}))
        for _ in range(2):
            with self.assertRaises(http.client.RemoteDisconnected):c.getresponse()
        with self.assertRaises(ValueError):cls().request('POST',PATH)
        self.assertEqual(sum(x[0]=='request' for x in calls),1)
        self.assertFalse(any(x[0]=='response' for x in calls))
        self.assertEqual(state,dict(attempts=1,dispatched=True))

    def test_partial_send_consumes_attempt_and_preserves_original_error(self):
        cls,state,calls=self.fake(True)
        with self.assertRaisesRegex(RuntimeError,'partial-send'):cls().request('POST',PATH)
        with self.assertRaises(ValueError):cls().request('POST',PATH)
        self.assertEqual(state,dict(attempts=1,dispatched=False))
        self.assertEqual(sum(x[0]=='request' for x in calls),1)

    def test_get_delegates_and_wrong_mutations_fail_before_original_request(self):
        cls,state,calls=self.fake();c=cls();c.request('GET','/v1.45/info');self.assertEqual(c.getresponse(),'read')
        for method,path in (('DELETE',PATH),('POST',PATH+'&x=1'),('POST',PATH.replace('backend','peer')),('POST','/other')):
            with self.subTest(method=method,path=path),self.assertRaises(ValueError):c.request(method,path)
        self.assertEqual(sum(x[0]=='request' for x in calls),1);self.assertEqual(state['attempts'],0)

    @unittest.skipUnless(os.name=='posix','Unix socket server required')
    def test_real_unix_request_can_apply_while_response_is_never_observed(self):
        applied=[];done=threading.Event()
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                applied.append((self.path,self.rfile.read(int(self.headers['Content-Length']))));done.set()
                try:
                    self.send_response(201);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'{}')
                except (BrokenPipeError,ConnectionResetError):pass
        with tempfile.TemporaryDirectory() as directory:
            server=socketserver.UnixStreamServer(str(Path(directory)/'engine.sock'),Handler)
            thread=threading.Thread(target=server.serve_forever);thread.start()
            try:
                cls,state=diagnostic._connector(diagnostic.gateway._UnixDocker)
                c=cls(server.server_address,2);c.request('POST',PATH,b'{}')
                with self.assertRaises(http.client.RemoteDisconnected):c.getresponse()
                self.assertTrue(done.wait(2));self.assertEqual(applied,[(PATH,b'{}')]);self.assertTrue(state['dispatched'])
            finally:server.shutdown();server.server_close();thread.join(2)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.used=patch.object(diagnostic,'_USED',False);self.used.start();self.addCleanup(self.used.stop)

    def test_config_shape_rejected_before_provisioning(self):
        for value in (None,dict(config(),faultMode='drop'),dict(config(),entrypoint=diagnostic.worker.ENTRYPOINT),dict(config(),sourceSha='bad')):
            with self.subTest(value=value),patch.object(diagnostic.worker,'run') as run:
                with self.assertRaises(ValueError):diagnostic.run(value,None,None)
                run.assert_not_called()

    def test_run_adapts_fixed_entry_and_restores_even_when_worker_raises(self):
        original=diagnostic.gateway._UnixDocker
        def run(value,stdin,stdout):
            self.assertEqual(value,dict(config(),entrypoint=diagnostic.worker.ENTRYPOINT))
            self.assertIsNot(diagnostic.gateway._UnixDocker,original)
            raise RuntimeError('original-worker-error')
        with patch.object(diagnostic.worker,'run',side_effect=run):
            with self.assertRaisesRegex(RuntimeError,'original-worker-error'):diagnostic.run(config(),None,None)
        self.assertIs(diagnostic.gateway._UnixDocker,original)
        with self.assertRaises(ValueError):diagnostic.run(config(),None,None)

    def test_worker_return_never_becomes_diagnostic_success(self):
        original=diagnostic.gateway._UnixDocker
        with patch.object(diagnostic.worker,'run',return_value={'success':True}):
            with self.assertRaises(ValueError):diagnostic.run(config(),None,None)
        self.assertIs(diagnostic.gateway._UnixDocker,original)

    def test_fork_identity_and_nonmain_thread_rejected(self):
        with patch.object(diagnostic.os,'getpid',return_value=diagnostic._PID+1),patch.object(diagnostic.worker,'run') as run:
            with self.assertRaises(ValueError):diagnostic.run(config(),None,None)
            run.assert_not_called()
        errors=[]
        def invoke():
            try:diagnostic.run(config(),None,None)
            except ValueError:errors.append(True)
        t=threading.Thread(target=invoke);t.start();t.join(2);self.assertEqual(errors,[True])

    @unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'Unix/TLS fixture required')
    def test_constructed_gateway_retains_diagnostic_connector_after_restore(self):
        from tests.test_deployment_compose_write_gateway_v3_host import WriteGatewayTests
        WriteGatewayTests.setUpClass()
        fixture=WriteGatewayTests('test_valid_response_persisted_and_duplicate_blocked')
        setup=fixture.setup_gate_fixture
        try:
            with patch.object(fixture,'setup_gate_fixture',side_effect=lambda:setup(path=PATH)):
                fixture.setUp()
            def start(value,stdin,stdout):
                server=diagnostic.gateway.create_gateway_v3(fixture.g,tls_context=fixture.tls_context,
                    docker_socket=fixture.root/'docker.sock',pre_dispatch=lambda *args:None,timeout=10)
                fixture.server=server
                threading.Thread(target=server.serve_forever,daemon=True).start()
                fixture.addCleanup(server.server_close);fixture.addCleanup(server.shutdown)
                raise RuntimeError('worker-unwind')
            original=diagnostic.gateway._UnixDocker
            with patch.object(diagnostic.worker,'run',side_effect=start):
                with self.assertRaisesRegex(RuntimeError,'worker-unwind'):diagnostic.run(config(),None,None)
            self.assertIs(diagnostic.gateway._UnixDocker,original)
            errors=[]
            def backend_error(*args):
                error=sys.exc_info()[1]
                if not isinstance(error,(BrokenPipeError,ConnectionResetError)):errors.append(type(error).__name__)
            with patch.object(fixture.backend,'handle_error',side_effect=backend_error):
                self.assertEqual(fixture.send(body=fixture.body)[0],502)
                deadline=time.monotonic()+2
                while not fixture.writes and time.monotonic()<deadline:time.sleep(.005)
            self.assertEqual(errors,[])
            self.assertEqual(len(fixture.writes),1)
            self.assertEqual(fixture.send(body=fixture.body)[0],403)
            self.assertEqual(len(fixture.writes),1)
        finally:
            fixture.doCleanups();WriteGatewayTests.tearDownClass()

if __name__=='__main__':unittest.main()
