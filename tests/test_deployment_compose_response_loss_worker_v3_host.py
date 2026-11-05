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
        self.assertEqual(state,dict(attempts=1,dispatched=True,suppressed=True))

    def test_partial_send_consumes_attempt_and_preserves_original_error(self):
        cls,state,calls=self.fake(True)
        with self.assertRaisesRegex(RuntimeError,'partial-send'):cls().request('POST',PATH,b'{}')
        with self.assertRaises(ValueError):cls().request('POST',PATH)
        self.assertEqual(state,dict(attempts=1,dispatched=False,suppressed=False))
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

    def test_observer_runs_once_after_close_and_failure_never_reads_response(self):
        calls=[];observed=[]
        class Connection:
            def __init__(self):pass
            def request(self,*args,**kwargs):calls.append('request')
            def close(self):calls.append('close')
            def getresponse(self):raise AssertionError('original-response-read')
        def observe(value):
            self.assertEqual(calls,['request','close']);observed.append(value)
            raise OSError('observation-I/O-failed')
        cls,state=diagnostic._connector(Connection,observe);connection=cls()
        connection.request('POST',PATH,b'secret-body')
        with self.assertRaisesRegex(OSError,'observation-I/O-failed'):connection.getresponse()
        with self.assertRaises(http.client.RemoteDisconnected):connection.getresponse()
        self.assertEqual(len(observed),1);self.assertNotIn('secret',repr(observed))
        self.assertTrue(state['dispatched']);self.assertTrue(state['suppressed'])

    def test_partial_send_cannot_emit_positive_observation(self):
        class Connection:
            def __init__(self):pass
            def request(self,*args,**kwargs):raise OSError('partial')
            def close(self):pass
            def getresponse(self):raise AssertionError('response')
        observed=[];cls,state=diagnostic._connector(Connection,observed.append);connection=cls()
        with self.assertRaises(OSError):connection.request('POST',PATH,b'{}')
        with self.assertRaises(http.client.RemoteDisconnected):connection.getresponse()
        self.assertEqual(observed,[]);self.assertFalse(state['dispatched'])


class ObservationChannelTests(unittest.TestCase):
    def channel(self):
        channels=[];cls=diagnostic._channel_class(diagnostic.worker.Channel,config(),channels)
        return cls(dict(config(),entrypoint=diagnostic.worker.ENTRYPOINT),None,None)

    def test_metadata_uses_actual_hello_and_consumed_request_without_body(self):
        channel=self.channel();frames=[]
        with patch.object(diagnostic.worker.live,'write_frame',side_effect=lambda stream,value,**kw:frames.append(value)):
            with self.assertRaises(ValueError):channel.observe(dict(method='POST',pathSha256='4'*64,bodySha256='5'*64))
            channel.emit('hello',root='/var/tmp/dw-engine-'+'a'*16,daemonId='actual-id')
            with patch.object(diagnostic.worker.Channel,'receive',return_value=dict(requestHash='6'*64)):
                channel.receive('consume-intent')
            channel.observe(dict(method='POST',pathSha256='4'*64,bodySha256='5'*64))
        value=frames[-1]['observation']
        self.assertEqual(value['requestHash'],'6'*64);self.assertEqual(value['daemonId'],'actual-id')
        self.assertEqual(value['sourceSha'],config()['sourceSha']);self.assertTrue(value['requestReturned'])
        self.assertFalse(value['originalResponseRead']);self.assertEqual(value['engineOutcome'],'unknown')

    def test_failed_hello_emit_does_not_capture_identity(self):
        channel=self.channel()
        with patch.object(diagnostic.worker.live,'write_frame',side_effect=OSError('hello-write-failed')):
            with self.assertRaises(OSError):channel.emit('hello',root='/var/tmp/dw-engine-'+'a'*16,daemonId='id')
        self.assertIsNone(channel._hello)
        with self.assertRaises(ValueError):channel.observe(dict(method='POST',pathSha256='4'*64,bodySha256='5'*64))

    def test_emit_serializes_with_base_rpc_and_lock_wait_is_bounded(self):
        channel=self.channel();frames=[];sent=threading.Event();release=threading.Event();errors=[]
        def write(stream,value,**kwargs):
            frames.append(value['kind'])
            if value['kind']=='rpc':sent.set()
        def read(*args,**kwargs):
            if not release.wait(2):raise TimeoutError('fixture')
            return dict(kind='reply',channelNonce=config()['channelNonce'],rpcId=1,response={})
        def rpc():
            try:channel.rpc('witness','read',{})
            except Exception as error:errors.append(error)
        with patch.object(diagnostic.worker.live,'write_frame',side_effect=write),patch.object(diagnostic.worker.live,'read_frame',side_effect=read):
            thread=threading.Thread(target=rpc);thread.start();self.assertTrue(sent.wait(2))
            emit=threading.Thread(target=lambda:channel.emit('observation'));emit.start()
            time.sleep(.03);self.assertEqual(frames,['rpc'])
            release.set();thread.join(2);emit.join(2)
        self.assertEqual(errors,[]);self.assertEqual(frames,['rpc','observation'])
        self.assertFalse(thread.is_alive());self.assertFalse(emit.is_alive())
        channel._rpc_lock.acquire()
        try:
            with patch.object(channel,'timeout',return_value=.02),patch.object(diagnostic.worker.live,'write_frame') as write:
                start=time.monotonic()
                with self.assertRaises(ValueError):channel.emit('blocked')
                self.assertLess(time.monotonic()-start,.3);write.assert_not_called()
        finally:channel._rpc_lock.release()


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

    def test_fixed_run_emits_bound_fact_after_actual_channel_capture(self):
        frames=[];calls=[];base=diagnostic.worker.Channel
        class Connection:
            def __init__(self,*args,**kwargs):pass
            def request(self,*args,**kwargs):calls.append('request')
            def close(self):calls.append('close')
            def getresponse(self):raise AssertionError('original-response-read')
        def run(value,stdin,stdout):
            channel=diagnostic.worker.Channel(value,stdin,stdout)
            channel.emit('hello',root='/var/tmp/dw-engine-'+'a'*16,daemonId='bound-daemon')
            channel.receive('consume-intent')
            connection=diagnostic.gateway._UnixDocker();connection.request('POST',PATH,b'private-body')
            connection.getresponse()
        with patch.object(diagnostic.gateway,'_UnixDocker',Connection),                patch.object(base,'receive',return_value=dict(requestHash='6'*64)),                patch.object(diagnostic.worker.live,'write_frame',side_effect=lambda stream,value,**kw:frames.append(value)),                patch.object(diagnostic.worker,'run',side_effect=run):
            with self.assertRaises(http.client.RemoteDisconnected):diagnostic.run(config(),None,None)
        self.assertIs(diagnostic.worker.Channel,base)
        self.assertEqual(calls,['request','close']);self.assertEqual(len(frames),2)
        observation=frames[-1]['observation']
        self.assertEqual(observation['daemonId'],'bound-daemon')
        self.assertEqual(observation['requestHash'],'6'*64)
        self.assertTrue(observation['responseSuppressed']);self.assertTrue(observation['requestReturned'])
        self.assertNotIn('private-body',repr(frames))

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
