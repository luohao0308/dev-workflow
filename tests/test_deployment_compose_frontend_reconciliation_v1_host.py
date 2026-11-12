import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / path) for path in (
    'scripts', 'core/scripts', 'packs/deployment/scripts', 'packs/release/scripts',
)]

import deployment_compose_frontend_reconciliation_v1_host as frontend
import deployment_compose_production_scope_v1_host as scope
from deployment_compose_witness_store import ZERO, canonical


@unittest.skipUnless(os.name == 'posix', 'POSIX scope and no-follow opens required')
class FrontendRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve() / 'scope'
        root.mkdir(mode=0o700)
        self.registration = scope.provision_scope(root, host_id='host-a', project='luohao-blog-prod',
                                                  daemon_id='docker-1')
        self.request, self.generation = 'a' * 64, 'b' * 64
        with scope.acquire_scope(self.registration, self.request):
            pass
        self.gate = root / ('gate-' + self.request)
        self.events = self.gate / self.generation
        self.events.mkdir(parents=True, mode=0o700)
        self.gate.chmod(0o700)
        for name in ('mutex', 'policy.json'):
            (self.gate / name).touch(mode=0o600)
        self.operation = ['POST', '/v1.45/containers/create?name=fixture', 'c' * 64]
        opened = dict(kind='open', generation=self.generation, previous=ZERO, directory=[1, 2],
                      data=dict(request_hash=self.request, operations=[self.operation]))
        prepared = dict(kind='prepare', generation=self.generation, directory=[1, 2],
                        previous=hashlib.sha256(canonical(opened)).hexdigest(),
                        data=dict(operation=self.operation, ref='d' * 64))
        digests = []
        for index, event in enumerate((opened, prepared)):
            raw = canonical(dict(payload=event))
            path = self.events / f'{index:08}.json'
            path.touch(mode=0o600)
            path.write_bytes(raw)
            digests.append(hashlib.sha256(raw).hexdigest())
        self.digests = tuple(digests)

    def prepared(self):
        return frontend._prepared_gate(
            self.registration, self.request, self.generation, self.digests, self.operation,
        )

    def test_exact_prepared_gate_and_reject_admission_or_drift(self):
        self.assertEqual(self.prepared(), self.digests)
        admitted = self.events / '00000002.json'
        admitted.touch(mode=0o600)
        with self.assertRaises(scope.ScopeBlocked):
            self.prepared()
        admitted.unlink()
        (self.events / '00000001.json').write_bytes(b'different prepared event')
        with self.assertRaises(scope.ScopeBlocked):
            self.prepared()

    def test_symlink_event_is_rejected(self):
        path = self.events / '00000001.json'
        path.unlink()
        path.symlink_to(self.events / '00000000.json')
        with self.assertRaises(OSError):
            self.prepared()

    def test_gate_replacement_while_reading_events_is_rejected(self):
        read = frontend._private_file

        def replace_gate(fd, name, maximum):
            raw = read(fd, name, maximum)
            if name == '00000001.json':
                self.gate.rename(self.gate.with_name('old-gate'))
                self.gate.mkdir(mode=0o700)
            return raw

        with patch.object(frontend, '_private_file', side_effect=replace_gate):
            with self.assertRaises(scope.ScopeBlocked):
                self.prepared()

    def test_read_only_payload_holds_lock_and_does_not_change_journal(self):
        journal, = self.registration.root.glob('*.journal')
        before = journal.read_bytes()

        def observe(*args, **kwargs):
            with self.assertRaisesRegex(scope.ScopeBlocked, 'live writer'):
                scope.acquire_scope(self.registration, 'c' * 64)
            return 'd' * 64

        with patch.object(frontend, '_observe', side_effect=observe):
            approval = frontend.prepare_frontend_reconciliation(
                self.registration, self.request, evidence_digest='e' * 64, expires_at=1000,
            )
        self.assertEqual(approval['observationDigest'], 'd' * 64)
        self.assertEqual(approval['pending']['requestHash'], self.request)
        self.assertEqual(journal.read_bytes(), before)

    def test_missing_independent_signer_pin_blocks_reconciliation(self):
        with self.assertRaises(FileNotFoundError):
            frontend.reconcile_frontend_scope(self.registration, self.request,
                                               approval={}, signature=b'', public_key=b'')
