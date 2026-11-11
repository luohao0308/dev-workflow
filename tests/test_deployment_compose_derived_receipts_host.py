"""Versioned source-derivation bindings cannot be dropped or substituted."""
import json
import os
import unittest

from tests import test_deployment_compose_receipts_host as base

PINS = {'backend': '8' * 64, 'frontend': '9' * 64}


@unittest.skipUnless(os.name == 'posix', 'POSIX host receipt storage')
class DerivedReceiptTests(unittest.TestCase):
    def setUp(self):
        self.f = base.CreateReceiptTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.f.recorder = self.make(PINS)

    def make(self, pins):
        return base.receipts.ComposeCreateReceipts(self.f.j, self.f.archive,
            creates=base.CREATES, forbidden_container_ids=(base.OLD, base.PROTECTED),
            derivation_digests=pins)

    def record_pair(self):
        tokens = [self.f.record(i, str(i + 1) * 64) for i in range(2)]
        return tokens, {i: token.reference for i, token in enumerate(tokens)}

    def test_derived_payload_and_diagnostic_preserve_exact_pins(self):
        tokens, references = self.record_pair()
        for index, token in enumerate(tokens):
            payload = json.loads(self.f.archive.get(token.reference))
            self.assertEqual(payload['schemaVersion'], 2)
            self.assertEqual(payload['kind'], 'compose-derived-create-response')
            self.assertEqual(payload['sourceDerivationDigest'], PINS[base.CREATES[index]['service']])
        result = self.f.recorder.bindings(references, **self.f.options())
        self.assertEqual(result['payloadSchemaVersion'], 2)
        self.assertEqual(result['sourceDerivationDigests'], PINS)
        self.assertEqual(result['candidateIds'], {'backend': '1' * 64, 'frontend': '2' * 64})
        for key in ('authorityGranted', 'executionAvailable', 'productionReady', 'replaySafe'):
            self.assertIs(result[key], False)

    def test_valid_archive_hmac_does_not_allow_wrong_derivation(self):
        tokens, references = self.record_pair()
        value = json.loads(self.f.archive.get(tokens[0].reference))
        value['sourceDerivationDigest'] = '7' * 64
        references[0] = self.f.archive.put(base.receipts.canonical(value))
        self.f.rejected(self.f.recorder.bindings, references, **self.f.options())

    def test_legacy_locator_cannot_supply_a_derived_receipt(self):
        self.f.recorder = self.f.new_recorder()
        _, references = self.record_pair()
        self.f.rejected(self.make(PINS).bindings, references, **self.f.options())

    def test_derived_locator_cannot_be_downgraded_to_legacy(self):
        _, references = self.record_pair()
        self.f.rejected(self.f.new_recorder().bindings, references, **self.f.options())

    def test_wrong_or_swapped_expected_pin_blocks_all_ids(self):
        _, references = self.record_pair()
        for pins in ({'backend': '7' * 64, 'frontend': PINS['frontend']},
                     {'backend': PINS['frontend'], 'frontend': PINS['backend']}):
            self.f.rejected(self.make(pins).bindings, references, **self.f.options())

    def test_durable_derived_receipt_does_not_heal_pending_after_recorder_restart(self):
        attempt, ticket, body = self.f.finish()
        token = self.f.retain(attempt, ticket, body)
        payload = json.loads(self.f.archive.get(token.reference))
        self.assertEqual(payload['sourceDerivationDigest'], PINS['backend'])
        restarted = self.make(PINS)
        self.f.rejected(restarted.complete, 0, attempt, token,
                        admission=ticket, **self.f.options())
        self.f.rejected(restarted.bindings, {0: token.reference, 1: token.reference}, **self.f.options())
        self.assertEqual(self.f.j.snapshot()['unknown']['attempt'], attempt)

    def test_host_pin_map_is_captured_and_malformed_scopes_reject(self):
        pins = dict(PINS)
        self.f.recorder = self.make(pins)
        pins['backend'] = '7' * 64
        _, references = self.record_pair()
        result = self.f.recorder.bindings(references, **self.f.options())
        self.assertEqual(result['sourceDerivationDigests'], PINS)
        for invalid in ({}, {'backend': '8' * 64}, dict(PINS, extra='6' * 64),
                        {'backend': True, 'frontend': '9' * 64}, ['private-marker']):
            self.f.rejected(self.make, invalid)


if __name__ == '__main__':
    unittest.main()
