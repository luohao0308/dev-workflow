"""Real SSHSIG verification, context pins, purpose isolation and issuer rejection."""
import base64
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
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_completion_certificate_v3_host as certificate

@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class VerificationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.key=self.root/'key'
        subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(self.key)],check=True,capture_output=True)
        self.public=(self.root/'key.pub').read_bytes()
        self.payload={key:'a'*64 for key in certificate._DIGESTS}
        self.payload.update(schemaVersion=1,purpose=certificate.PURPOSE,sourceSha='b'*40,hostId='host-one',
            profile='managed-recovery-v3',hostProjectionProfile='linux-docker-host-projection-v1',
            parentScopeCount=1,childScopeCount=4,totalWriteCount=5,closedSequence=6,
            proofs={key:True for key in certificate._PROOFS},authorityGranted=False,runtimePermit=False,
            recoveryAuthorized=False,productionReady=False,witnessKeyHash=certificate.digest(certificate.key_material(self.public)))
        self.expected={k:self.payload[k] for k in ('sourceSha','archiveDigest','hostId','historyDigest')}
    def sign(self,payload=None,namespace=None):
        value=self.payload if payload is None else payload
        signed=subprocess.run(['/usr/bin/ssh-keygen','-Y','sign','-f',str(self.key),'-n',namespace or certificate.NAMESPACE],
            input=certificate.encode(value),capture_output=True,check=True)
        return certificate.encode(dict(payload=value,signature=base64.b64encode(signed.stdout).decode()))
    def verify(self,raw,**kwargs):
        return certificate.verify_completion(raw,public_key=kwargs.get('public_key',self.public),expected_binding=kwargs.get('expected_binding',self.expected))
    def test_pinned_historical_attestation_remains_non_authorizing(self):
        raw=self.sign();value=self.verify(raw);self.assertEqual(value,self.payload)
        self.assertFalse(value['runtimePermit']);self.assertFalse(value['recoveryAuthorized'])
        value['proofs']['historyClosed']=False;self.assertTrue(self.verify(raw)['proofs']['historyClosed'])
    def test_wrong_pin_domain_signature_and_context_rejected(self):
        raw=self.sign()
        cases=[self.sign(namespace='dev-workflow-compose-operation-witness-v3'),raw.replace(b'host-one',b'host-two')]
        env=json.loads(raw);env['signature']=base64.b64encode(b'invalid').decode();cases.append(certificate.encode(env))
        for value in cases:
            with self.assertRaises(ValueError):self.verify(value)
        with self.assertRaises(ValueError):self.verify(raw,expected_binding=dict(self.expected,historyDigest='c'*64))
        with self.assertRaises(ValueError):self.verify(raw,public_key=b'ssh-ed25519 invalid')
        with self.assertRaises(ValueError):self.verify(raw,expected_binding={})
    def test_even_signed_extra_authority_or_wrong_types_rejected(self):
        for change in (dict(totalWriteCount=True),dict(productionReady=True),dict(extra='body'),dict(purpose='other')):
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(self.sign(dict(self.payload,**change)))
        value=dict(self.payload,proofs=dict(self.payload['proofs'],historyClosed=1))
        with self.assertRaises(ValueError):self.verify(self.sign(value))
    def test_noncanonical_duplicate_and_oversized_input_rejected(self):
        raw=self.sign()
        for value in (raw+b' ',b'{"payload":{},"payload":{},"signature":""}',b'NaN',b'x'*16385):
            with self.assertRaises(ValueError):self.verify(value)
    def test_public_snapshots_booleans_and_unissued_candidates_cannot_issue(self):
        from deployment_compose_history_v3_host import AuthenticatedHistorySnapshotV3
        for value in (None,{},True,AuthenticatedHistorySnapshotV3(b'{}'),certificate._Candidate()):
            with self.subTest(value=type(value).__name__),self.assertRaises(ValueError):certificate.issue_completion(value)
        for admission,session in (({},{}),(None,None)):
            with self.assertRaises(ValueError):certificate.prepare_completion(admission,session)
