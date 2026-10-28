"""Definitive create receipt recording with real local stores, no Docker/HTTP."""
from copy import copy, deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import pickle
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
if os.name == 'posix':
    import deployment_compose_receipts_host as receipts
    from deployment_compose_journal_host import BatchJournal
    from deployment_compose_recovery_store import ComposeRecoveryStore
    import deployment_gateway as gateway

H, R, GEN, CERT, OLD, PROTECTED = (c * 64 for c in 'abcdef')
KEY = b'local-receipts-test-secret-at-least-32-bytes'
ACTIONS = (H, R)
BODIES = (b'{"Image":"sha256:first"}', b'{"Image":"sha256:second"}')
OPERATIONS = tuple(('POST', '/v1.45/containers/create?name=dev-workflow-receipt-' + str(i),
                    hashlib.sha256(body).hexdigest()) for i, body in enumerate(BODIES))
CREATES = tuple(dict(index=i, service=service, candidateDigest=ACTIONS[i])
                for i, service in enumerate(('backend', 'frontend')))


@unittest.skipUnless(os.name == 'posix', 'POSIX host storage mechanics')
class CreateReceiptTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        # Darwin exercises descriptor mechanics only, not Linux acceptance.
        patch = mock.patch.object(sys, 'platform', 'linux')
        patch.start()
        self.addCleanup(patch.stop)
        self.policy = gateway.GatePolicy('receipt-host', 'receipt-key', H, CERT)
        self.gate = gateway.FileWriterGate(self.policy, self.root / 'gate', key=KEY)
        for name in ('journal', 'archive'):
            (self.root / name).mkdir(mode=0o700)
        self.j = BatchJournal(self.root / 'journal', H, R, ACTIONS, KEY)
        self.addCleanup(self.j.close)
        self.archive = ComposeRecoveryStore(self.root / 'archive', key=KEY)
        self.addCleanup(self.archive.close)
        self.recorder = self.new_recorder()
        self.session = self.gate.open_generation(generation=GEN, request_hash=R,
                                                receipt_hash=H, operations=OPERATIONS)

    def new_recorder(self, journal=None):
        return receipts.ComposeCreateReceipts(journal or self.j, self.archive,
            creates=CREATES, forbidden_container_ids=(OLD, PROTECTED))

    def options(self, **changes):
        result = dict(gate=self.gate, generation=GEN, operations=OPERATIONS)
        result.update(changes)
        return result

    def rejected(self, fn, *args, **kwargs):
        with self.assertRaisesRegex(ValueError, '^compose-create-receipt-rejected$'):
            fn(*args, **kwargs)

    def finish(self, index=0, identity='1' * 64, *, status=201, body=None,
               response_hash=None, definitive=True):
        if body is None:
            body = json.dumps({'Id': identity, 'Warnings': ['private-warning-marker']}).encode()
        operation = OPERATIONS[index]
        attempt = self.session.prepare_attempt(operation[0], operation[1], BODIES[index])
        self.j.record_attempt(index, ACTIONS[index], attempt.ref)
        ticket = self.gate.admit(GEN, attempt.ref, method=operation[0], path=operation[1],
            body=BODIES[index], writer_certificate_sha256=CERT)
        digest = hashlib.sha256(str(status).encode() + b'\0' + body).hexdigest()
        self.gate.finish(ticket, definitive=definitive,
                         response_hash=(response_hash or digest) if definitive else None)
        return attempt.ref, ticket, body

    def retain(self, attempt, ticket, body, index=0, status=201):
        return self.recorder.retain(index, attempt, status=status, body=body,
            admission=ticket, **self.options())

    def record(self, index, identity):
        attempt, ticket, body = self.finish(index, identity)
        token = self.retain(attempt, ticket, body, index)
        self.recorder.complete(index, attempt, token, admission=ticket, **self.options())
        return token

    def test_two_exact_ids_are_diagnostic_and_never_unlock(self):
        tokens = [self.record(i, str(i + 1) * 64) for i in range(2)]
        result = self.recorder.bindings({i: t.reference for i, t in enumerate(tokens)}, **self.options())
        self.assertEqual({'backend': '1' * 64, 'frontend': '2' * 64}, result['candidateIds'])
        self.assertTrue(result['blocked'])
        self.assertEqual('independent-anchor-required', result['blocker'])
        for field in ('replaySafe', 'authorityGranted', 'executionAvailable',
                      'productionReady', 'quiescenceProven'):
            self.assertIs(result[field], False)
        self.assertNotIn('private-warning-marker', json.dumps(result))

    def test_forbidden_baseline_and_protected_ids_rejected(self):
        for identity in (OLD, PROTECTED):
            with self.subTest(identity=identity):
                self.rejected(self.recorder._response, 201,
                              json.dumps({'Id': identity, 'Warnings': None}).encode())

    def test_malformed_responses_rejected_without_echoing_private_body(self):
        cases = [b'private-warning-marker', b'[]', b'{"Id":"short","Warnings":null}',
            ('{"Id":"' + '1'*64 + '","Id":"' + '2'*64 + '","Warnings":null}').encode(),
            json.dumps({'Id': '1'*64}).encode(),
            json.dumps({'Id': '1'*64, 'Warnings': {'private-warning-marker': True}}).encode(),
            json.dumps({'Id': '1'*64, 'Warnings': [False]}).encode(),
            json.dumps({'Id': '1'*64, 'Warnings': None, 'extra': 'private-warning-marker'}).encode(),
            b'x' * (receipts.MAX_RESPONSE + 1)]
        for body in cases:
            with self.subTest(body=body[:40]):
                self.rejected(self.recorder._response, 201, body)
        for status in (200, 204, 400, True, '201'):
            self.rejected(self.recorder._response, status, b'private-warning-marker')

    def test_status_body_hash_mismatch_leaves_pending(self):
        attempt, ticket, body = self.finish(response_hash='9' * 64)
        self.rejected(self.retain, attempt, ticket, body)
        self.assertEqual(attempt, self.j.snapshot()['unknown']['attempt'])

    def test_changed_status_is_rejected_at_recording_boundary(self):
        attempt, ticket, body = self.finish(status=200)
        self.rejected(self.retain, attempt, ticket, body, status=200)
        self.rejected(self.retain, attempt, ticket, body, status=201)

    def test_duplicate_new_identity_blocks_bindings(self):
        tokens = [self.record(i, '1' * 64) for i in range(2)]
        self.rejected(self.recorder.bindings,
                      {i: t.reference for i, t in enumerate(tokens)}, **self.options())

    def test_exported_gate_json_never_authorizes_retention(self):
        attempt, ticket, body = self.finish()
        self.rejected(self.recorder.retain, 0, attempt, status=201, body=body,
            admission=ticket, **self.options(gate=self.gate.generation_evidence(GEN)))

    def test_only_original_in_memory_ticket_and_token_can_complete(self):
        attempt, ticket, body = self.finish()
        token = self.retain(attempt, ticket, body)
        for admission in (replace(ticket), None):
            self.rejected(self.recorder.complete, 0, attempt, token,
                          admission=admission, **self.options())
        restarted = gateway.FileWriterGate(self.policy, self.root / 'gate', key=KEY)
        self.rejected(self.recorder.complete, 0, attempt, token,
                      admission=ticket, **self.options(gate=restarted))
        self.rejected(self.recorder.complete, 0, attempt,
                      receipts.RetainedCreateReceipt(token.reference),
                      admission=ticket, **self.options())
        for transform in (copy, deepcopy, pickle.dumps):
            self.rejected(transform, token)
        self.recorder.complete(0, attempt, token, admission=ticket, **self.options())

    def test_crash_after_retain_cannot_be_healed_by_new_recorder(self):
        attempt, ticket, body = self.finish()
        token = self.retain(attempt, ticket, body)
        self.j.close()
        reopened = BatchJournal(self.root / 'journal', H, R, ACTIONS, KEY)
        self.addCleanup(reopened.close)
        recorder = self.new_recorder(reopened)
        self.rejected(recorder.complete, 0, attempt, token, admission=ticket, **self.options())
        self.rejected(recorder.bindings, {0: token.reference, 1: token.reference}, **self.options())
        result = reopened.reconcile_gate(self.gate, GEN, OPERATIONS)
        self.assertTrue(result['matched'])
        self.assertEqual('writer-outcome-unknown', result['blocker'])
        self.assertTrue(result['blocked'])
        self.assertEqual(attempt, reopened.snapshot()['unknown']['attempt'])

    def test_nondefinitive_finish_blocks_even_with_body(self):
        attempt, ticket, body = self.finish(definitive=False)
        self.rejected(self.retain, attempt, ticket, body)
        self.assertEqual('writer-outcome-unknown',
                         self.j.reconcile_gate(self.gate, GEN, OPERATIONS)['blocker'])

    def test_archive_tamper_blocks_completion(self):
        attempt, ticket, body = self.finish()
        token = self.retain(attempt, ticket, body)
        (self.root / 'archive' / token.reference).write_bytes(b'private-warning-marker')
        self.rejected(self.recorder.complete, 0, attempt, token, admission=ticket, **self.options())
        self.assertIsNotNone(self.j.snapshot()['unknown'])

    def test_wrong_archive_reference_blocks_complete_bindings(self):
        tokens = [self.record(i, str(i + 1) * 64) for i in range(2)]
        for references in ({0: tokens[1].reference, 1: tokens[0].reference},
                           {0: '9' * 64, 1: tokens[1].reference},
                           {0: tokens[0].reference}):
            self.rejected(self.recorder.bindings, references, **self.options())

    def test_authenticated_archive_with_wrong_scope_cannot_supply_ids(self):
        tokens = [self.record(i, str(i + 1) * 64) for i in range(2)]
        original = json.loads(self.archive.get(tokens[0].reference))
        for field, changed in (('planHash', '9'*64), ('requestHash', '9'*64),
                ('index', 1), ('attempt', 'other-attempt'), ('generation', '9'*64),
                ('operation', list(OPERATIONS[1])), ('candidateDigest', '9'*64),
                ('service', 'other-service'), ('actionDigest', '9'*64)):
            with self.subTest(field=field):
                value = dict(original, **{field: changed})
                reference = self.archive.put(receipts.canonical(value))
                self.rejected(self.recorder.bindings,
                              {0: reference, 1: tokens[1].reference}, **self.options())

    def test_archive_write_failure_after_finish_keeps_outcome_pending(self):
        attempt, ticket, body = self.finish()
        with mock.patch.object(self.archive, 'put', side_effect=OSError('private-marker')):
            self.rejected(self.retain, attempt, ticket, body)
        self.assertEqual(attempt, self.j.snapshot()['unknown']['attempt'])
        self.rejected(self.recorder.complete, 0, attempt,
                      receipts.RetainedCreateReceipt('1'*64),
                      admission=ticket, **self.options())
        self.rejected(self.recorder.bindings, {0: '1'*64, 1: '2'*64}, **self.options())
        self.assertEqual('writer-outcome-unknown',
                         self.j.reconcile_gate(self.gate, GEN, OPERATIONS)['blocker'])

    def test_completion_write_failure_keeps_durable_receipt_nonrecoverable(self):
        attempt, ticket, body = self.finish()
        token = self.retain(attempt, ticket, body)
        archived = self.archive.get(token.reference)
        with mock.patch.object(self.j, 'record_complete', side_effect=OSError('private-marker')):
            self.rejected(self.recorder.complete, 0, attempt, token,
                          admission=ticket, **self.options())
        self.assertEqual(archived, self.archive.get(token.reference))
        self.assertEqual(attempt, self.j.snapshot()['unknown']['attempt'])
        self.rejected(self.new_recorder().complete, 0, attempt, token,
                      admission=ticket, **self.options())
        self.rejected(self.recorder.bindings,
                      {0: token.reference, 1: token.reference}, **self.options())

    def test_lost_or_corrupt_archive_after_completion_returns_no_partial_ids(self):
        tokens = [self.record(i, str(i + 1) * 64) for i in range(2)]
        references = {i: token.reference for i, token in enumerate(tokens)}
        path = self.root / 'archive' / tokens[1].reference
        original = path.read_bytes()
        path.unlink()
        self.rejected(self.recorder.bindings, references, **self.options())
        path.write_bytes(original[:-1])
        path.chmod(0o600)
        self.rejected(self.recorder.bindings, references, **self.options())
        self.assertIsNone(self.j.snapshot()['unknown'])
        self.assertEqual(2, len(self.j.snapshot()['completed']))

    def test_scope_changes_cannot_finish_retained_receipt(self):
        attempt, ticket, body = self.finish()
        token = self.retain(attempt, ticket, body)
        self.rejected(self.recorder.complete, 1, attempt, token, admission=ticket, **self.options())
        self.rejected(self.recorder.complete, 0, 'other-attempt', token,
                      admission=ticket, **self.options())
        for changes in (dict(generation='9'*64),
                        dict(operations=(OPERATIONS[1], OPERATIONS[0]))):
            self.rejected(self.recorder.complete, 0, attempt, token,
                          admission=ticket, **self.options(**changes))
        self.assertIsNotNone(self.j.snapshot()['unknown'])


if __name__ == '__main__':
    unittest.main()
