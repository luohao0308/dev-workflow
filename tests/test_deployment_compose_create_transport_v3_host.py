"""Owned TLS client tests; Engine and GitHub are explicit fixtures."""
import json
import hashlib
import errno
import os
import sys
import time
import threading
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_coordinator_v3_host import ExecutorIntegrationTests
import deployment_compose_create_transport_v3_host as transport
from deployment_compose_coordinator_v3_host import Profile3StepExecutor


class CodecTests(unittest.TestCase):
    def test_fixed_leaf_compiles_and_has_no_external_program(self):
        compile(transport.LEAF,'<fixed-owned-client>','exec')

    @unittest.skipUnless(os.name=='posix', 'POSIX pipe select')
    def test_duplicate_and_nonfinite_or_expired_frames_reject(self):
        with self.assertRaises(ValueError):transport._pairs([('a',1),('a',2)])
        read,write=os.pipe()
        try:
            with os.fdopen(read,'rb') as stream:
                os.write(write,b'{"a":NaN}\n')
                with self.assertRaises(ValueError):transport._read(stream,time.monotonic()+1)
                with self.assertRaises(ValueError):transport._read(stream,time.monotonic()-1)
        finally:os.close(write)

    def test_pre_go_partial_start_cleanup_reaps_owned_process_without_proof(self):
        process=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(30)'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        owned=object.__new__(transport.OwnedCreateTransportV3)
        owned._owner=os.getpid();owned._mutex=threading.RLock();owned._closed=False
        owned._pending_terminal=owned._terminal=owned._response_fact=None
        owned._process=process;owned._go_sent=False;owned._process_proof=None
        owned._directory=None
        group=SimpleNamespace(close=unittest.mock.Mock(),kill_and_drain=unittest.mock.Mock(side_effect=AssertionError('unattached group')))
        owned._group=group
        owned.close(time.monotonic()+3)
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed)
        self.assertIsNone(owned._process_proof)
        group.kill_and_drain.assert_not_called()
        owned.close()

    def test_concurrent_requests_burn_one_shot_under_lifecycle_lock(self):
        import deployment_compose_writer_cgroup_v3_host as groups
        owned=object.__new__(transport.OwnedCreateTransportV3)
        owned._owner=os.getpid();owned._mutex=threading.RLock();owned._closed=False
        owned._pending_terminal=owned._terminal=owned._response_fact=None
        owned._used=False;owned._uid=65534;owned._gid=65534
        parent=unittest.mock.Mock()
        parent.resolve.return_value=parent
        def slow_stat():
            time.sleep(.02)
            return SimpleNamespace(st_uid=0,st_mode=0o700)
        parent.stat.side_effect=slow_stat
        raw=SimpleNamespace(parent=parent,is_absolute=lambda:True)
        errors=[]
        def call():
            try:owned.request(request_hash='a'*64,scope_hash='b'*64,port=12345,pin='c'*64,
                operation={'phase':'create','method':'POST','bodyDigest':hashlib.sha256(b'x').hexdigest()},
                body=b'x',headers={},docker_socket='/private',deadline=time.monotonic()+1)
            except ValueError:errors.append(True)
        with patch.object(transport,'Path',return_value=raw), patch.object(groups,'WriterCgroupV3',side_effect=ValueError('unsupported')) as constructor:
            threads=[threading.Thread(target=call) for _ in range(2)]
            for t in threads:t.start()
            for t in threads:t.join(2)
            self.assertTrue(all(not t.is_alive() for t in threads))
            self.assertEqual(constructor.call_count,1)
        self.assertEqual(len(errors),2)

    def test_expired_post_go_drain_still_revokes_group_without_proof(self):
        owned=object.__new__(transport.OwnedCreateTransportV3)
        owned._owner=os.getpid();owned._mutex=threading.RLock();owned._closed=False
        owned._pending_terminal=owned._terminal=owned._response_fact=None
        owned._process=unittest.mock.Mock();owned._process.poll.return_value=None
        owned._go_sent=True;owned._process_proof=None;owned._directory=None
        owned._group=SimpleNamespace(kill_and_drain=unittest.mock.Mock(side_effect=ValueError('expired')),
            close=unittest.mock.Mock(side_effect=ValueError('revoked without proof')))
        with self.assertRaisesRegex(ValueError,'^owned-create-transport-v3-rejected$'):
            owned.close(time.monotonic()-1)
        owned._group.close.assert_called_once()
        self.assertIsNone(owned._process_proof)
        self.assertFalse(owned._closed)

    @unittest.skipUnless(hasattr(os,'removexattr'),'POSIX ACL xattrs')
    def test_acl_cleanup_is_limited_and_failure_closed(self):
        with patch.object(transport.os,'removexattr') as remove:
            transport._clear_acl('/private',directory=True)
            self.assertEqual([c.args[1] for c in remove.call_args_list],
                ['system.posix_acl_access','system.posix_acl_default'])
        for code in (errno.ENODATA,errno.ENOTSUP):
            with patch.object(transport.os,'removexattr',side_effect=OSError(code,'no attributes')):
                transport._clear_acl('/private')
        with patch.object(transport.os,'removexattr',side_effect=OSError(errno.EPERM,'SECRET')):
            with self.assertRaisesRegex(ValueError,'^owned-create-transport-v3-rejected$'):
                transport._clear_acl('/private')

    def test_unsupported_host_never_starts_process(self):
        if sys.platform=='linux' and os.geteuid()==0:self.skipTest('root Linux host')
        with patch.object(transport.subprocess,'Popen',side_effect=AssertionError('spawn')):
            with self.assertRaises(ValueError):transport.OwnedCreateTransportV3(worker_uid=65534,
                worker_gid=65534,ca_pem=b'x',client_cert_pem=b'x',client_key_pem=b'x')


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0 and
    os.environ.get('DEV_WORKFLOW_PRIVILEGED_LINUX_TESTS')=='1', 'explicit Linux delegated-root fixture')
class OwnedTransportIntegrationTests(ExecutorIntegrationTests):
    def test_actual_owned_first_create_tls_and_closed_history(self):
        material=dict(ca_pem=(self.directory/'ca.pem').read_bytes(),
            client_cert_pem=(self.directory/'client.pem').read_bytes(),
            client_key_pem=(self.directory/'client.key').read_bytes())
        owned=transport.OwnedCreateTransportV3(worker_uid=65534,worker_gid=65534,**material)
        captured=[];original=Profile3StepExecutor.__init__
        def initialize(executor,*args,**kw):
            kw['owned_create_transport']=owned
            original(executor,*args,**kw);captured.append(executor)
        real_request=transport.OwnedCreateTransportV3.request
        def inspected_request(instance,**kw):
            response=real_request(instance,**kw)
            code="""import json,os,socket,sys
v=json.load(sys.stdin);d=v['directory'];key=d+'/client.key'
assert len(open(key,'rb').read())>0
for operation in ('write','rename','raw'):
 try:
  if operation=='write':fd=os.open(key,os.O_WRONLY);os.close(fd)
  elif operation=='rename':os.rename(d,d+'-moved')
  else:
   peer=socket.socket(socket.AF_UNIX);peer.connect(v['raw'])
 except PermissionError:continue
 raise AssertionError('worker access unexpectedly allowed')
print('permissions-denied')
"""
            check=subprocess.run([sys.executable,'-I','-S','-c',code],
                input=json.dumps(dict(directory=str(instance._directory),raw=str(kw['docker_socket']))).encode(),
                capture_output=True,user=65534,group=65534,extra_groups=[],env={},timeout=5)
            self.assertEqual(check.returncode,0,check.stderr.decode())
            self.assertEqual(check.stdout.strip(),b'permissions-denied')
            return response
        # Reuse the existing real TLS+signed witness fixture; its attempted
        # second operation must fail because this transport is initial-only.
        with patch.object(Profile3StepExecutor,'__init__',initialize), patch.object(transport.OwnedCreateTransportV3,'request',inspected_request):
            with self.assertRaisesRegex(ValueError,'compose-coordinator-v3-blocked'):
                super().test_actual_executor_consumed_approval_signed_gate_tls_unix()
        self.assertEqual(len(captured),1)
        executor=captured[0];evidence=executor.private_evidence()
        self.assertEqual(len(evidence),1)
        self.assertEqual(evidence[0]['status'],201)
        self.assertEqual(len(evidence[0]['witness']['records']),6)
        state=self.store.read(executor._binding)
        self.assertEqual((state['phase'],state['seq']),('closed',6))
        self.assertIsNotNone(executor.owned_gateway_token(owned))
        with self.assertRaises(ValueError):executor.owned_gateway_token(object())
        self.assertIsNotNone(owned._process.returncode)
        self.assertTrue(owned._process.stdout.closed)
        self.assertIsNotNone(owned._process_proof)

    def test_wrong_tls_pin_drains_process_but_never_closes_product_scope(self):
        owned=transport.OwnedCreateTransportV3(worker_uid=65534,worker_gid=65534,
            ca_pem=(self.directory/'ca.pem').read_bytes(),
            client_cert_pem=(self.directory/'client.pem').read_bytes(),
            client_key_pem=(self.directory/'client.key').read_bytes())
        captured=[];initialize=Profile3StepExecutor.__init__
        def init(executor,*args,**kw):
            kw['owned_create_transport']=owned
            initialize(executor,*args,**kw);captured.append(executor)
        request=transport.OwnedCreateTransportV3.request
        def wrong_pin(instance,**kw):
            kw['pin']='0'*64
            return request(instance,**kw)
        with patch.object(Profile3StepExecutor,'__init__',init), patch.object(transport.OwnedCreateTransportV3,'request',wrong_pin):
            with self.assertRaisesRegex(ValueError,'owned-create-transport-v3-rejected'):
                super().test_actual_executor_consumed_approval_signed_gate_tls_unix()
        self.assertEqual(len(captured),1)
        executor=captured[0]
        self.assertEqual(executor.private_evidence(),[])
        state=self.store.read(executor._binding)
        self.assertNotEqual(state['phase'],'closed')
        self.assertLessEqual(state['seq'],2)
        self.assertIsNotNone(owned._process.returncode)
        self.assertIsNotNone(owned._process_proof)

    def test_lost_actor_response_stays_nonclosed_after_process_and_gateway_drain(self):
        owned=transport.OwnedCreateTransportV3(worker_uid=65534,worker_gid=65534,
            ca_pem=(self.directory/'ca.pem').read_bytes(),
            client_cert_pem=(self.directory/'client.pem').read_bytes(),
            client_key_pem=(self.directory/'client.key').read_bytes())
        captured=[];initialize=Profile3StepExecutor.__init__
        def init(executor,*args,**kw):
            kw['owned_create_transport']=owned
            initialize(executor,*args,**kw);captured.append(executor)
        read=transport._read
        dropped=[]
        def lose_response(stream,deadline):
            frame=read(stream,deadline)
            if frame.get('kind')=='response':
                self.assertEqual(frame['status'],201)
                self.assertEqual(json.loads(transport.base64.b64decode(frame['body'])),{'Id':'a'*64})
                dropped.append(True)
                raise ValueError('actor-response-lost')
            return frame
        with patch.object(Profile3StepExecutor,'__init__',init), patch.object(transport,'_read',lose_response):
            with self.assertRaisesRegex(ValueError,'^owned-create-transport-v3-rejected$'):
                super().test_actual_executor_consumed_approval_signed_gate_tls_unix()
        self.assertEqual(dropped,[True])
        self.assertEqual(len(captured),1)
        executor=captured[0]
        self.assertEqual(executor.private_evidence(),[])
        state=self.store.read(executor._binding)
        # Independent witness: open/prepared/admitted/response; only the
        # parent's close_generation can append completed/closed afterward.
        self.assertEqual((state['seq'],state['phase']),(4,'response'))
        self.assertIsNotNone(owned._process.returncode)
        self.assertTrue(owned._process.stdout.closed)
        self.assertIsNotNone(owned._process_proof)
        # This is only a gateway-drain fact, never product completion authority.
        self.assertIsNotNone(executor.owned_gateway_token(owned))


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(cls(name) for cls in (CodecTests,OwnedTransportIntegrationTests)
        for name in cls.__dict__ if name.startswith('test_'))
