import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / path) for path in ('scripts', 'packs/deployment/scripts')]

import deployment_compose_production_scope_v1_host as scope
import deployment_compose_scope_reconciliation_v1_host as recovery
from deployment_compose_witness_store import canonical
from deployment_gate_witness import key_material


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX and OpenSSH required')
class ScopeReconciliationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        journal_root = root / 'scope'
        journal_root.mkdir(mode=0o700)
        self.registration = scope.provision_scope(journal_root, host_id='host-a', project='blog',
                                                  daemon_id='docker-1')
        self.journal, = journal_root.iterdir()
        self.key = root / 'operator'
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)],
                       capture_output=True, timeout=10, check=True)
        self.public = self.key.with_suffix('.pub').read_bytes()
        self.signer_digest = hashlib.sha256(key_material(self.public)).hexdigest()
        self.request, self.evidence, self.observation = 'a' * 64, 'b' * 64, '9' * 64
        with scope.acquire_scope(self.registration, self.request):
            pass
        self.original = self.journal.read_bytes()
        self.pending = scope.inspect_pending_scope(self.registration, self.request)
        self.approval = recovery.recovery_payload(
            self.registration, self.pending, self.evidence, self.observation, expires_at=int(time.time()) + 60,
        )
        self.signature = self.sign(self.approval)

    def sign(self, approval):
        return subprocess.run(
            ['/usr/bin/ssh-keygen', '-Y', 'sign', '-n', recovery.NAMESPACE, '-f', str(self.key)],
            input=canonical(approval), capture_output=True, timeout=10, check=True,
        ).stdout

    def reconcile(self, **overrides):
        args = dict(approval=self.approval, signature=self.signature, public_key=self.public,
                    trusted_signer_digest=self.signer_digest, observe_live_digest=lambda: self.observation)
        args.update(overrides)
        return recovery.reconcile_pending_scope(self.registration, self.request, **args)

    def test_approved_reconciliation_appends_and_preserves_replay_fence(self):
        record = self.reconcile()
        self.assertEqual(self.journal.read_bytes(), self.original + canonical(record) + b'\n')
        self.assertEqual(record['state'], 'operator-reconciled')
        self.assertEqual(record['evidence'], self.evidence)
        self.assertEqual(record['observation'], self.observation)
        self.assertEqual(record['signer'], self.signer_digest)
        with self.assertRaises(scope.ScopeBlocked):
            self.reconcile()
        with self.assertRaisesRegex(scope.ScopeBlocked, 'already recorded'):
            scope.acquire_scope(self.registration, self.request)
        with scope.acquire_scope(self.registration, 'c' * 64) as lease:
            self.assertEqual(lease.generation, 2)
            lease.complete('d' * 64)

    def test_mismatched_signature_signer_tail_or_observation_preserves_pending(self):
        stale = dict(self.approval, pending=dict(self.pending, journalDigest='c' * 64))
        expired = dict(self.approval, expiresAt=int(time.time()) - 1)
        other_inode = dict(self.approval, journalIdentity=[0, 0])
        for overrides in (
            dict(signature=b'invalid'), dict(trusted_signer_digest='c' * 64),
            dict(approval=stale, signature=self.sign(stale)),
            dict(approval=expired, signature=self.sign(expired)),
            dict(approval=other_inode, signature=self.sign(other_inode)),
            dict(observe_live_digest=lambda: 'c' * 64),
        ):
            with self.subTest(keys=tuple(overrides)), self.assertRaises(scope.ScopeBlocked):
                self.reconcile(**overrides)
            self.assertEqual(self.journal.read_bytes(), self.original)

    def test_observation_runs_with_exclusive_lock_and_expiry_is_rechecked(self):
        now = time.time()

        def observation():
            nonlocal now
            with self.assertRaisesRegex(scope.ScopeBlocked, 'live writer'):
                scope.inspect_pending_scope(self.registration, self.request)
            now = self.approval['expiresAt']
            return self.observation

        with patch.object(recovery.time, 'time', lambda: now), self.assertRaises(scope.ScopeBlocked):
            self.reconcile(observe_live_digest=observation)
        self.assertEqual(self.journal.read_bytes(), self.original)

    def test_change_during_evidence_observation_blocks_reconciliation(self):
        changed = self.original + b'torn-tail'

        def observation():
            self.journal.write_bytes(changed)
            return self.observation

        with self.assertRaises(scope.ScopeBlocked):
            self.reconcile(observe_live_digest=observation)
        self.assertEqual(self.journal.read_bytes(), changed)

    def test_torn_append_still_blocks_future_writes(self):
        def partial(fd, line):
            os.write(fd, line[:15])
            raise OSError('fixture interrupted append')

        with patch.object(recovery, '_append', partial), self.assertRaises(OSError):
            self.reconcile()
        self.assertTrue(self.journal.read_bytes().startswith(self.original))
        with self.assertRaises(scope.ScopeBlocked):
            scope.acquire_scope(self.registration, 'c' * 64)

    def test_complete_visible_record_is_synced_before_a_new_lease_is_issued(self):
        with patch.object(scope.os, 'fsync', side_effect=OSError('fixture fsync failure')):
            with self.assertRaises(OSError):
                self.reconcile()
        self.assertEqual(json.loads(self.journal.read_bytes().splitlines()[-1])['state'],
                         'operator-reconciled')
        with patch.object(scope.os, 'fsync', wraps=os.fsync) as sync:
            with scope.acquire_scope(self.registration, 'c' * 64) as lease:
                sync.assert_called_once()
                self.assertEqual(lease.generation, 2)
                lease.complete('d' * 64)
