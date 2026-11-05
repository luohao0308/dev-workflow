"""Signed live reservations precede Gate tickets; test keys grant no approval."""
import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'packs/deployment/scripts')]
from deployment_compose_witness_store import ComposeWitnessStore
from deployment_gate_witness import OnlineWitnessClient,NAMESPACE,encode,key_material,opening_scope
from deployment_gateway import FileWriterGate,GatePolicy


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH witness fixture')
class GateWitnessTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        (self.root/'witness').mkdir(mode=0o700)
        self.signer=self.root/'signer'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','witness-test','-f',str(self.signer)],check=True,capture_output=True)
        self.pub=self.signer.with_suffix('.pub').read_bytes()
        self.gen='a'*64;self.request='b'*64;self.receipt='c'*64;self.cert='d'*64
        self.body=b'{}';self.ops=tuple(('POST','/v1.45/containers/create?name=dev-workflow-witness-'+name,hashlib.sha256(self.body).hexdigest()) for name in ('one','two'))
        scope=opening_scope(self.gen,self.request,self.receipt,self.ops)
        self.policy=GatePolicy('witness-store','witness-key','e'*64,self.cert,True,scope,
                               hashlib.sha256(key_material(self.pub)).hexdigest())
        self.binding={'scopeHash':scope,'epoch':'f'*64,'generation':self.gen,'policyHash':self.policy.identity_hash()}
        self.store=ComposeWitnessStore(self.root/'witness',key=b'w'*32);self.addCleanup(self.store.close)
        self.store.register_once(self.binding)
        self.requests=[];self.replies=[]
        patcher=patch.object(sys,'platform','linux');patcher.start();self.addCleanup(patcher.stop)

    def transport(self,method,request):
        self.requests.append((method,deepcopy(request)))
        args=dict(expected_seq=request['expectedSeq'],expected_head=request['expectedHead'])
        if method=='check':payload=self.store.check(request['binding'],**args)
        elif method=='reserve':
            payload=self.store.reserve(request['binding'],**args,next_head=request['nextHead'],
                event_digest=request['eventDigest'],boot_nonce=request['bootNonce'],rpc_nonce=request['rpcNonce'])
        else:raise ValueError('unknown witness method')
        payload.update(bootNonce=request['bootNonce'],rpcNonce=request['rpcNonce'])
        sig=subprocess.run(['ssh-keygen','-Y','sign','-f',str(self.signer),'-n',NAMESPACE],input=encode(payload),capture_output=True,check=True).stdout
        reply={'payload':payload,'signature':base64.b64encode(sig).decode()}
        self.replies.append(deepcopy(reply));return reply

    def client(self,transport=None):return OnlineWitnessClient(self.binding,self.pub,transport or self.transport)
    def gate(self,client=None):return FileWriterGate(self.policy,self.root/'gate',key=b'g'*32,witness=client or self.client())
    def opening(self,gate):return gate.open_generation(generation=self.gen,request_hash=self.request,receipt_hash=self.receipt,operations=self.ops)

    def test_reservations_precede_admission_and_finish(self):
        gate=self.gate();session=self.opening(gate)
        attempt=session.prepare_attempt(*self.ops[0][:2],self.body)
        ticket=gate.admit(self.gen,attempt.ref,method=self.ops[0][0],path=self.ops[0][1],body=self.body,writer_certificate_sha256=self.cert)
        self.assertEqual(self.store.read(self.binding)['seq'],3)
        gate.finish(ticket,definitive=True,response_hash='1'*64)
        evidence=gate.generation_evidence(self.gen)
        self.assertEqual(self.store.read(self.binding)['head'],evidence['head'])
        self.assertEqual(self.store.read(self.binding)['seq'],4)
        self.assertFalse(evidence['authorityGranted'])

    def test_required_witness_enforces_order_and_blocks_pending_or_unknown(self):
        gate=self.gate();session=self.opening(gate)
        with self.assertRaises(ValueError):session.prepare_attempt(*self.ops[1][:2],self.body)
        first=session.prepare_attempt(*self.ops[0][:2],self.body)
        ticket=gate.admit(self.gen,first.ref,method=self.ops[0][0],path=self.ops[0][1],body=self.body,writer_certificate_sha256=self.cert)
        with self.assertRaisesRegex(ValueError,'witness-prior-write-unresolved'):
            session.prepare_attempt(*self.ops[1][:2],self.body)
        gate.finish(ticket,definitive=False,response_hash=None)
        with self.assertRaisesRegex(ValueError,'witness-prior-write-unresolved'):
            session.prepare_attempt(*self.ops[1][:2],self.body)

    def test_missing_connector_wrong_scope_and_generation_rejected(self):
        with self.assertRaises(ValueError):FileWriterGate(self.policy,self.root/'gate',key=b'g'*32)
        gate=self.gate()
        with self.assertRaises(ValueError):gate.open_generation(generation='1'*64,request_hash=self.request,receipt_hash=self.receipt,operations=self.ops)
        with self.assertRaises(ValueError):gate.open_generation(generation=self.gen,request_hash='1'*64,receipt_hash=self.receipt,operations=self.ops)
        self.assertEqual(self.store.read(self.binding)['seq'],0)

    def test_reserved_but_local_append_failure_blocks_retry(self):
        gate=self.gate();session=self.opening(gate)
        with patch.object(gate,'_write',side_effect=OSError('local failure')):
            with self.assertRaises(ValueError):session.prepare_attempt(*self.ops[0][:2],self.body)
        self.assertEqual(self.store.read(self.binding)['seq'],2)
        with self.assertRaises(ValueError):session.prepare_attempt(*self.ops[0][:2],self.body)

    def test_lost_reply_after_mac_commit_cannot_retry(self):
        gate=self.gate();session=self.opening(gate)
        def lose(method,request):
            reply=self.transport(method,request)
            if method=='reserve':raise ConnectionError('lost acknowledgement')
            return reply
        gate._witness=self.client(lose)
        with self.assertRaises(ValueError):session.prepare_attempt(*self.ops[0][:2],self.body)
        self.assertEqual(self.store.read(self.binding)['seq'],2)
        with self.assertRaises(ValueError):gate.generation_evidence(self.gen)

    def test_cached_signed_read_and_signature_tampering_reject(self):
        client=self.client();client.check(self.gen,0,'0'*64)
        old=deepcopy(self.replies[-1])
        with self.assertRaises(ValueError):self.client(lambda *args:old).check(self.gen,0,'0'*64)
        def bad(method,request):
            reply=self.transport(method,request);reply['signature']=base64.b64encode(b'not-a-signature').decode();return reply
        with self.assertRaises(ValueError):self.client(bad).check(self.gen,0,'0'*64)

    def test_authenticated_old_local_prefix_rejected_after_restart(self):
        gate=self.gate();session=self.opening(gate)
        directory=self.root/'gate'/self.gen
        old={p.name:p.read_bytes() for p in directory.iterdir()}
        session.prepare_attempt(*self.ops[0][:2],self.body)
        for p in directory.iterdir():
            if p.name not in old:p.unlink()
        for name,data in old.items():(directory/name).write_bytes(data)
        fresh=self.gate()
        with self.assertRaises(ValueError):fresh.generation_evidence(self.gen)
        self.assertEqual(self.requests[-1][0],'check')
        self.assertEqual(self.requests[-1][1]['expectedSeq'],1)
        self.assertEqual(self.store.read(self.binding)['seq'],2)


if __name__=='__main__':unittest.main()
