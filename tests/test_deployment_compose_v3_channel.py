"""Owned pipe subprocess tests only: these tests never invoke SSH or a network."""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'packs/deployment/scripts')]
import deployment_compose_v3_channel_host as host
from deployment_compose_v3_channel_worker import LIMIT, read_frame, write_frame


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH signing required')
class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.spawns=[];self.configs=[];self.channels=[]

    def local_spawn(self, argv, stderr):
        self.spawns.append(argv)
        self.assertEqual(argv[:-1],['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','ForwardX11=no','-o','PermitLocalCommand=no','-T','unit-host'])
        parts=shlex.split(argv[-1])
        self.assertEqual(parts[:5],['exec','python3','-I','-u','-c'])
        return subprocess.Popen([sys.executable,'-I','-u','-c',parts[-1]],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=stderr,bufsize=0)

    def run_probe(self, spawn=None):
        original_write=host.write_frame; original_close=host._OwnedSSHChannel.close
        def write(stream,value,**kwargs):
            if value.get('entrypoint'):self.configs.append(deepcopy(value))
            original_write(stream,value,**kwargs)
        def close(channel):
            original_close(channel);self.channels.append(channel)
        with patch.object(host,'_spawn_ssh',spawn or self.local_spawn), \
             patch.object(host,'write_frame',write),patch.object(host._OwnedSSHChannel,'close',close):
            return host.run_channel_probe(self.root,'unit-host')

    def test_real_owned_pipe_signed_six_event_roundtrip(self):
        report=self.run_probe()
        self.assertTrue(report['success']);self.assertEqual(report['sealedEventCount'],6)
        self.assertEqual(report['witnessFinal']['phase'],'closed')
        self.assertEqual(report['dockerWrites'],0)
        self.assertFalse(report['approvalAvailable']);self.assertFalse(report['runtimePermit'])
        self.assertFalse(report['liveExecutionReusable'])
        self.assertTrue(report['scratchCleaned']);self.assertTrue(report['ownedProcessStopped'])
        self.assertEqual(len(self.spawns),1)
        channel=self.channels[0]
        self.assertIsNotNone(channel._process.poll())
        with self.assertRaises(ValueError):channel.run()
        with self.assertRaises(ValueError):channel._reply_owned_frame({})
        # Only the public verifier key and synthetic Gate key cross stdio.
        config=self.configs[0]
        self.assertEqual(set(config),{'entrypoint','channelNonce','binding','publicKey','gateKey'})
        for path in self.root.rglob('*'):
            if path.is_file():self.assertEqual(path.stat().st_mode&0o777,0o600)
            elif path.is_dir():self.assertEqual(path.stat().st_mode&0o777,0o700)
        private_key=next(self.root.rglob('witness-signing')).read_bytes()
        witness_key=next(self.root.rglob('witness.key')).read_bytes()
        transmitted=json.dumps(config).encode()+self.spawns[0][-1].encode()
        self.assertNotIn(base64.b64encode(private_key),transmitted)
        self.assertNotIn(base64.b64encode(witness_key),transmitted)
        self.assertNotIn('deployment_compose_approval_v3_host.py',host.MANIFEST)

    def test_alias_root_and_entrypoint_validation_before_spawn(self):
        with patch.object(host,'_spawn_ssh') as spawn:
            for alias in ('-host','host;touch x','host/path','host name',''):
                with self.subTest(alias=alias),self.assertRaises(ValueError):host.run_channel_probe(self.root,alias)
            with self.assertRaises(ValueError):host.run_channel_probe(ROOT,'host')
            with self.assertRaises(ValueError):host.bootstrap('arbitrary-worker')
            spawn.assert_not_called()

    def malicious_spawn(self, change, *, append=False):
        def spawn(argv,stderr):
            self.spawns.append(argv)
            code=shlex.split(argv[-1])[-1]
            action="""import secrets
 request=dict(binding=config['binding'],bootNonce=secrets.token_hex(32),rpcNonce=secrets.token_hex(32))
 frame=dict(kind='rpc',channelNonce=config['channelNonce'],service='witness',method='read',request=request)
 CHANGE
 write_frame(sys.stdout.buffer,frame)
 read_frame(sys.stdin.buffer)
 raise RuntimeError('synthetic lost acknowledgement; never retry')""".replace('CHANGE',change)
            if append:
                action=action.replace("method='read'","method='append_event'")
            code=code.replace('result=diagnostic(config,sys.stdin.buffer,sys.stdout.buffer)',action)
            return subprocess.Popen([sys.executable,'-I','-u','-c',code],stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=stderr,bufsize=0)
        return spawn

    def test_foreign_binding_method_and_nonce_fail_closed(self):
        for change in ("frame['request']['binding']=dict(config['binding'],scopeHash='f'*64)",
                       "frame['method']='register_once'", "frame['method']='transition_successor'",
                       "frame['channelNonce']='f'*64", "frame['request']['rpcNonce']='bad'"):
            with self.subTest(change=change),self.assertRaises(ValueError):
                self.run_probe(self.malicious_spawn(change))
        self.assertEqual(len(self.spawns),5)
        for channel in self.channels:self.assertTrue(channel._closed)

    def test_replayed_rpc_nonce_is_rejected(self):
        change="write_frame(sys.stdout.buffer,frame)\n read_frame(sys.stdin.buffer)"
        with self.assertRaises(ValueError):self.run_probe(self.malicious_spawn(change))
        self.assertEqual(len(self.spawns),1)
        self.assertEqual(len(self.channels[0]._seen),1)

    def test_unknown_append_ack_is_not_retried(self):
        change="""request.update(expectedSeq=0,expectedHead='0'*64,externalMaterialBase64=None,
 event=dict(binding=config['binding'],sequence=1,previousHead='0'*64,kind='open',data={}))"""
        with self.assertRaises(ValueError):self.run_probe(self.malicious_spawn(change,append=True))
        self.assertEqual(len(self.spawns),1)
        channel=self.channels[0]
        self.assertEqual(len(channel._seen),1)
        # The mutation committed once; no reconnect, restart, or second append occurs.
        from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
        case=next(self.root.glob('channel-*'))
        store=OperationWitnessStoreV3(case/'witness',key=(case/'witness.key').read_bytes())
        try:self.assertEqual(store.read(self.configs[0]['binding'])['seq'],1)
        finally:store.close()

    def test_frame_bound_rejects_before_reading_payload(self):
        read,write=os.pipe()
        try:
            os.write(write,struct.pack('!I',LIMIT+1))
            with os.fdopen(read,'rb',buffering=0) as stream,self.assertRaises(ValueError):read_frame(stream,1)
        finally:os.close(write)

    def test_stalled_child_stdin_write_has_deadline(self):
        process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'],stdin=subprocess.PIPE)
        try:
            with self.assertRaises(TimeoutError):
                write_frame(process.stdin,dict(payload='x'*(1024*1024)),timeout=0.05)
        finally:
            process.terminate();process.wait(timeout=5);process.stdin.close()

    def test_optional_intent_uses_registered_approval_and_separate_namespace(self):
        from tests import test_deployment_compose_approval_v3_host as fixture
        from deployment_compose_intent_status_v3 import NAMESPACE, PRINCIPAL
        approval_fixture=fixture.ComposeApprovalTests();approval_fixture.setUp()
        authority=approval_fixture.approval();request=approval_fixture.req
        authority.consume(authority.validate(request),request)
        signer=host._key(self.root,'intent-signing')
        real_init=host._OwnedSSHChannel.__init__
        replies=[]
        real_write=host.write_frame
        def initialize(channel,**kwargs):
            real_init(channel,**dict(kwargs,approval=authority,registered_request=request,intent_signer=signer))
        def observe(stream,value,**kwargs):
            if value.get('kind')=='reply' and value['response']['payload'].get('purpose')=='consumed-intent-status-v3':
                replies.append(deepcopy(value['response']))
            real_write(stream,value,**kwargs)
        def spawn(argv,stderr):
            self.spawns.append(argv)
            code=shlex.split(argv[-1])[-1]
            action="""import secrets
 rpc=dict(schemaVersion=1,purpose='check-consumed-intent-v3',requestHash=REQUEST_HASH,bundleHash=BUNDLE_HASH,bootNonce=secrets.token_hex(32),rpcNonce=secrets.token_hex(32))
 write_frame(sys.stdout.buffer,dict(kind='rpc',channelNonce=config['channelNonce'],service='intent',method='check',request=rpc))
 read_frame(sys.stdin.buffer)
 result=diagnostic(config,sys.stdin.buffer,sys.stdout.buffer)""".replace('REQUEST_HASH',repr(request.digest())).replace('BUNDLE_HASH',repr(request.plan_hash))
            code=code.replace('result=diagnostic(config,sys.stdin.buffer,sys.stdout.buffer)',action)
            return subprocess.Popen([sys.executable,'-I','-u','-c',code],stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=stderr,bufsize=0)
        with patch.object(host._OwnedSSHChannel,'__init__',initialize),patch.object(host,'write_frame',observe):
            report=self.run_probe(spawn)
        self.assertTrue(report['success']);self.assertEqual(len(replies),1)
        response=replies[0]
        self.assertEqual(response['payload']['requestHash'],request.digest())
        self.assertFalse(response['payload']['runtimePermit'])
        sig=self.root/'status.sig';sig.write_bytes(base64.b64decode(response['signature']))
        allowed=self.root/'allowed';allowed.write_bytes(PRINCIPAL.encode()+b' '+signer.with_suffix('.pub').read_bytes())
        checked=subprocess.run(['ssh-keygen','-Y','verify','-f',str(allowed),'-I',PRINCIPAL,'-n',NAMESPACE,'-s',str(sig)],
            input=host.encode(response['payload']),capture_output=True,timeout=10)
        self.assertEqual(checked.returncode,0)
        # The witness namespace cannot validate this status signature.
        wrong=subprocess.run(['ssh-keygen','-Y','verify','-f',str(allowed),'-I',PRINCIPAL,'-n',host.NAMESPACE,'-s',str(sig)],
            input=host.encode(response['payload']),capture_output=True,timeout=10)
        self.assertNotEqual(wrong.returncode,0)

    def test_spawn_failure_closes_private_stderr(self):
        descriptors=[]
        def failed(argv,stderr):
            descriptors.append(stderr)
            raise FileNotFoundError('synthetic local spawn failure')
        with self.assertRaises(FileNotFoundError):self.run_probe(failed)
        self.assertEqual(len(descriptors),1)
        self.assertTrue(descriptors[0].closed)
