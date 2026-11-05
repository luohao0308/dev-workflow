"""Real local authority reconciliation, without Docker or write authorization."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
import deployment_compose_journal_host as journal
import deployment_gateway as gateway

H, R, GEN, CERT = (c * 64 for c in 'abcd')
KEY = b'local-gate-test-key-32-bytes-long!!'
PATH = '/v1.45/containers/' + H + '/start'
OP = ('POST', PATH, hashlib.sha256(b'').hexdigest())


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.gate = gateway.FileWriterGate(gateway.GatePolicy('test', 'key', H, CERT),
                                           root / 'gate', key=KEY)
        private = root / 'journal'
        private.mkdir(mode=0o700)
        self.j = journal.BatchJournal(private, H, R, (H,), KEY)
        self.addCleanup(self.j.close)
        self.session = self.gate.open_generation(generation=GEN, request_hash=R,
                                                 receipt_hash=H, operations=(OP,))

    def reconcile(self):
        return self.j.reconcile_gate(self.gate, GEN, (OP,))

    def prepare(self):
        attempt = self.session.prepare_attempt('POST', PATH, b'')
        self.j.record_attempt(0, H, attempt.ref)
        return attempt

    def admit(self, attempt):
        return self.gate.admit(GEN, attempt.ref, method='POST', path=PATH, body=b'',
                               writer_certificate_sha256=CERT)

    def test_complete_matches_but_never_unlocks(self):
        a = self.prepare()
        self.gate.finish(self.admit(a), definitive=True, response_hash=H)
        self.j.record_complete(0, H, a.ref, H)
        self.gate.close_generation(GEN)
        result = self.reconcile()
        self.assertTrue(result['matched'])
        self.assertTrue(result['blocked'])
        self.assertEqual('independent-anchor-required', result['blocker'])
        for field in ('replaySafe', 'authorityGranted', 'executionAvailable', 'quiescenceProven'):
            self.assertFalse(result[field])

    def test_restored_valid_empty_prefix_detected(self):
        head = (self.j.root / 'journal.head').read_bytes()
        self.prepare()
        (self.j.root / '0000.json').unlink()
        (self.j.root / 'journal.head').write_bytes(head)
        self.assertIsNone(self.j.snapshot()['unknown'])
        self.assertEqual('journal-gate-mismatch', self.reconcile()['blocker'])

    def test_pending_and_unknown_remain_blocked(self):
        a = self.prepare()
        self.assertEqual('writer-outcome-unknown', self.reconcile()['blocker'])
        ticket = self.admit(a)
        self.assertTrue(self.reconcile()['matched'])
        self.gate.finish(ticket, definitive=False, response_hash=None)
        self.assertEqual('writer-outcome-unknown', self.reconcile()['blocker'])

    def test_wrong_response_detected(self):
        a = self.prepare()
        self.gate.finish(self.admit(a), definitive=True, response_hash=H)
        self.j.record_complete(0, H, a.ref, R)
        self.assertFalse(self.reconcile()['matched'])

    def test_request_binding_detected(self):
        self.j.close()
        other = self.j.root.parent / 'other'
        other.mkdir(mode=0o700)
        self.j = journal.BatchJournal(other, H, H, (H,), KEY)
        self.addCleanup(self.j.close)
        self.assertEqual('journal-gate-mismatch', self.reconcile()['blocker'])

    def test_exported_evidence_not_accepted(self):
        evidence = self.gate.generation_evidence(GEN)
        with self.assertRaises(journal.JournalError):
            self.j.reconcile_gate(evidence, GEN, (OP,))
        evidence['binding']['request_hash'] = H
        self.assertEqual(R, self.gate.generation_evidence(GEN)['binding']['request_hash'])

    def test_unjournaled_prepared_attempt_detected(self):
        self.session.prepare_attempt('POST', PATH, b'')
        self.assertEqual('journal-gate-mismatch', self.reconcile()['blocker'])

    def test_wrong_concrete_operation_detected(self):
        other = ('POST', PATH.replace('/start', '/stop?t=10'), OP[2])
        result = self.j.reconcile_gate(self.gate, GEN, (other,))
        self.assertFalse(result['matched'])

    def test_gate_corruption_rejected(self):
        event = self.gate.root / GEN / '00000000.json'
        event.write_bytes(b'{}')
        self.assertRaises(journal.JournalError, self.reconcile)


if __name__ == '__main__':
    unittest.main()
