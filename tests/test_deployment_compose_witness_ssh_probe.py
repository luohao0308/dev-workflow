"""Local protocol/fault execution; actual cross-host run belongs to operator."""
import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'packs/deployment/scripts')]
import deployment_compose_witness_ssh_probe as controller
import deployment_compose_witness_worker_fixture as worker
from deployment_compose_witness_store import ComposeWitnessStore

@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH witness fixture')
class WitnessSshFixtureTests(unittest.TestCase):
    def test_all_fault_cases_execute_real_gate_journal_cas_and_signatures(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory).resolve();signer=base/'signer'
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','witness-test','-f',str(signer)],check=True,capture_output=True)
            public=signer.with_suffix('.pub').read_bytes()
            for mode in worker.MODES:
                with self.subTest(mode=mode):
                    witness_root=base/mode;witness_root.mkdir(mode=0o700)
                    store=ComposeWitnessStore(witness_root,key=b'w'*32)
                    gen=secrets.token_hex(32);policy,*_=worker.material(gen,public)
                    binding={'scopeHash':policy.witness_scope_hash,'epoch':secrets.token_hex(32),'generation':gen,'policyHash':policy.identity_hash()}
                    store.register_once(binding)
                    config={'mode':mode,'publicKey':base64.b64encode(public).decode(),'gateKey':base64.b64encode(b'g'*32).decode(),'binding':binding}
                    def exchange(method,data):return controller.reply(store,signer,method,data)
                    result=None
                    try:
                        with patch.object(sys,'platform','linux'):
                            result=worker.run_case(config,exchange)
                        self.assertTrue(result['success'],result)
                        self.assertEqual(result['dockerWrites'],0)
                        self.assertFalse(result['productionReady'])
                        if mode=='joint-rollback':
                            self.assertTrue(result['restoredJournalLocallyValid']);self.assertTrue(result['restoredCasLocallyValid'])
                            self.assertGreater(store.read(binding)['seq'],result['restoredSequence'])
                    finally:
                        store.close()
                        if result:shutil.rmtree(result['root'])

    def test_rpc_cannot_register_reset_or_change_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();store=ComposeWitnessStore(root,key=b'w'*32)
            binding=dict(scopeHash='a'*64,epoch='b'*64,generation='c'*64,policyHash='d'*64)
            store.register_once(binding)
            try:
                for method in ('register','reset','new-generation'):
                    with self.assertRaises(ValueError):controller.reply(store,root/'missing',method,{})
                request=dict(binding=dict(binding,generation='e'*64),expectedSeq=0,expectedHead='0'*64,bootNonce='1'*64,rpcNonce='2'*64)
                with self.assertRaises(ValueError):controller.reply(store,root/'missing','check',request)
                bad_nonce=dict(request,binding=binding,bootNonce=True)
                with self.assertRaises(ValueError):controller.reply(store,root/'missing','check',bad_nonce)
                self.assertEqual(store.read(binding)['seq'],0)
            finally:store.close()

    def test_framing_rejects_eof_and_oversized_without_ssh(self):
        for content in (b'',b'x'*(worker.LIMIT+1),b'{}'):
            with tempfile.TemporaryFile() as stream:
                stream.write(content);stream.seek(0)
                with patch.object(worker.selectors,'DefaultSelector') as selector:
                    selector.return_value.__enter__.return_value.select.return_value=[('ready',1)]
                    with self.assertRaises(ValueError):worker.read_frame(stream)

    def test_partial_frame_has_deadline_and_buffered_frames_are_preserved(self):
        read,write=os.pipe()
        try:
            os.write(write,b'{')
            with os.fdopen(read,'rb',closefd=False) as stream:
                with self.assertRaises(TimeoutError):worker.read_frame(stream,timeout=.02)
        finally:os.close(read);os.close(write)
        with tempfile.TemporaryFile() as stream:
            stream.write(b'{}\n{\"next\":1}\n');stream.seek(0)
            with patch.object(worker.selectors,'DefaultSelector') as selector:
                selector.return_value.__enter__.return_value.select.return_value=[('ready',1)]
                self.assertEqual(worker.read_frame(stream),{})
                self.assertEqual(worker.read_frame(stream),{'next':1})

    def test_worker_rejects_mode_before_creating_subjects(self):
        with self.assertRaises(ValueError):worker.run_case({'mode':'reset'},lambda *a:None)

    def test_bootstrap_contains_no_signing_key_and_keeps_rpc_stdin(self):
        code=controller.bootstrap()
        self.assertNotIn('signer',code)
        self.assertNotIn('sys.stdin.read',code)
        self.assertIn('main()',code)
        self.assertLess(len(code),100000)

if __name__=='__main__':unittest.main()
