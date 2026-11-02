"""Native Mac admission/SSHSIG closed-create certificate; GitHub and Engine doubled."""
from copy import deepcopy
import hashlib
import os
import secrets
import shutil
import sys
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
from tests import test_deployment_compose_live_admission_v3_host as admission_fixture
import deployment_compose_scene_create_certificate_v3_host as certificate
from deployment_compose_witness_store import canonical


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.fixture=admission_fixture.AdmissionTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.challenge=dict(sceneId='dw-scene-'+secrets.token_hex(8),attemptId='a'*64,attemptNonce='b'*64,
            preparationId='c'*64,capsuleDigest='d'*64,slotGeneration=1,requestHash=self.fixture.request.digest(),bundleDigest=self.fixture.bundle.digest)
    def terminal(self):
        self.fixture.finish();snapshot=self.fixture.host._history(self.fixture.host._root).capture()
        return dict(requestHash=self.fixture.request.digest(),bundleDigest=self.fixture.bundle.digest,
            historyDigest=snapshot.digest,receiptMap=dict(snapshot.snapshot['receiptMap']))
    def test_original_admission_fresh_closed_history_only_then_pinned_signature(self):
        terminal=self.terminal()
        result=certificate.issue_create_closure(self.fixture.host,challenge=self.challenge,worker_terminal=terminal)
        verified=certificate.verify_create_closure(result,public_key=self.fixture.public[1],expected=result['payload'])
        self.assertEqual(verified['receiptMap'],terminal['receiptMap'])
        self.assertEqual(verified['historyDigest'],terminal['historyDigest'])
        for field in ('attemptNonce','requestHash','historyDigest','capsuleDigest'):
            changed=deepcopy(result);changed['payload'][field]='f'*64
            with self.subTest(field=field),self.assertRaises(ValueError):
                certificate.verify_create_closure(changed,public_key=self.fixture.public[1],expected=result['payload'])
        with self.assertRaises(ValueError):certificate.verify_create_closure(result,public_key=self.fixture.public[0],expected=result['payload'])
    def test_pending_or_self_declared_receipt_never_gets_signed(self):
        fake=dict(requestHash=self.fixture.request.digest(),bundleDigest=self.fixture.bundle.digest,historyDigest='e'*64,receiptMap={'web':'f'*64})
        with self.assertRaises(ValueError):certificate.issue_create_closure(self.fixture.host,challenge=self.challenge,worker_terminal=fake)
        terminal=self.terminal();terminal['receiptMap']={'web':'f'*64}
        with self.assertRaises(ValueError):certificate.issue_create_closure(self.fixture.host,challenge=self.challenge,worker_terminal=terminal)
    def test_boolean_generation_and_foreign_source_object_reject(self):
        terminal=self.terminal();challenge=dict(self.challenge,slotGeneration=True)
        with self.assertRaises(ValueError):certificate.issue_create_closure(self.fixture.host,challenge=challenge,worker_terminal=terminal)
        with self.assertRaises(ValueError):certificate.issue_create_closure(object(),challenge=self.challenge,worker_terminal=terminal)
