"""Schema3 source metadata cannot be retrofitted to old receipts; chronology unverified."""
import json
import os
import unittest

from tests import test_deployment_compose_receipts_host as base

DERIVATIONS = {'backend': '8'*64, 'frontend': '9'*64}


def sources():
    return {item['service']: {'sourceSha': 'a'*40, 'modelDigest': str(i+1)*64,
        'sourceAssertionDigest': str(i+3)*64, 'createBodyDigest': base.OPERATIONS[i][2]}
        for i, item in enumerate(base.CREATES)}


@unittest.skipUnless(os.name == 'posix', 'POSIX host receipt storage')
class SourcedReceiptTests(unittest.TestCase):
    def setUp(self):
        self.f = base.CreateReceiptTests(); self.addCleanup(self.f.doCleanups); self.f.setUp()
        self.f.recorder = self.make(sources())

    def make(self, pins, derivations=DERIVATIONS):
        return base.receipts.ComposeCreateReceipts(self.f.j, self.f.archive, creates=base.CREATES,
            forbidden_container_ids=(base.OLD, base.PROTECTED), derivation_digests=derivations,
            source_model_bindings=pins)

    def record_pair(self):
        tokens = [self.f.record(i, str(i+1)*64) for i in range(2)]
        return tokens, {i:t.reference for i,t in enumerate(tokens)}

    def test_exact_source_body_and_id_recorded_without_origin_claim(self):
        tokens, refs = self.record_pair()
        for i,t in enumerate(tokens):
            value = json.loads(self.f.archive.get(t.reference))
            self.assertEqual(value['schemaVersion'], 3)
            self.assertEqual(value['sourceModelBinding'], sources()[base.CREATES[i]['service']])
            self.assertEqual(value['sourceDerivationDigest'], DERIVATIONS[base.CREATES[i]['service']])
        result = self.f.recorder.bindings(refs, **self.f.options())
        self.assertEqual(result['sourceModelBindings'], sources())
        self.assertEqual(result['payloadSchemaVersion'], 3)
        for k in ('sourceModelProvenanceVerified', 'sourceBindingRecordedBeforeWriteVerified', 'replaySafe', 'authorityGranted', 'executionAvailable', 'productionReady'):
            self.assertIs(result[k], False)

    def test_old_and_new_receipts_cannot_cross_versions(self):
        _, refs = self.record_pair()
        old = base.receipts.ComposeCreateReceipts(self.f.j,self.f.archive,creates=base.CREATES,
            forbidden_container_ids=(base.OLD,base.PROTECTED),derivation_digests=DERIVATIONS)
        self.f.rejected(old.bindings, refs, **self.f.options())
        # Mutating a correctly authenticated archive cannot remove source pins.
        value = json.loads(self.f.archive.get(refs[0])); del value['sourceModelBinding']
        refs[0] = self.f.archive.put(base.receipts.canonical(value))
        self.f.rejected(self.f.recorder.bindings, refs, **self.f.options())

    def test_derived_receipt_without_source_cannot_be_upgraded(self):
        self.f.recorder = base.receipts.ComposeCreateReceipts(self.f.j,self.f.archive,creates=base.CREATES,
            forbidden_container_ids=(base.OLD,base.PROTECTED),derivation_digests=DERIVATIONS)
        _,refs = self.record_pair()
        self.f.rejected(self.make(sources()).bindings,refs,**self.f.options())

    def test_authenticated_archive_cannot_change_scalar_types(self):
        tokens,refs=self.record_pair()
        for field,value in [('schemaVersion',3.0),('index',False),('index',0.0)]:
            payload=json.loads(self.f.archive.get(tokens[0].reference));payload[field]=value
            changed=dict(refs);changed[0]=self.f.archive.put(base.receipts.canonical(payload))
            self.f.rejected(self.f.recorder.bindings,changed,**self.f.options())

    def test_body_digest_mismatch_leaves_pending(self):
        pins = sources(); pins['backend']['createBodyDigest'] = 'f'*64
        self.f.recorder = self.make(pins)
        attempt, ticket, body = self.f.finish()
        self.f.rejected(self.f.retain, attempt, ticket, body)
        self.assertIsNotNone(self.f.j.snapshot()['unknown'])

    def test_changed_source_pins_reject_even_when_archive_is_authentic(self):
        _, refs = self.record_pair()
        for field in ('sourceSha', 'modelDigest', 'sourceAssertionDigest'):
            pins = sources(); pins['backend'][field] = 'f'*(40 if field=='sourceSha' else 64)
            self.f.rejected(self.make(pins).bindings, refs, **self.f.options())

    def test_source_pin_copy_and_scope_validation(self):
        pins = sources(); self.f.recorder = self.make(pins); pins['backend']['modelDigest']='f'*64
        _,refs = self.record_pair()
        self.assertEqual(self.f.recorder.bindings(refs,**self.f.options())['sourceModelBindings'],sources())
        for value in ({}, {'backend':sources()['backend']}, dict(sources(), extra=sources()['backend'])):
            self.f.rejected(self.make,value)
        self.f.rejected(self.make, sources(), None)
        for field in sources()['backend']:
            invalid=sources();invalid['backend'][field]=True
            self.f.rejected(self.make,invalid)

    def test_sourced_archive_cannot_complete_after_recorder_restart(self):
        attempt,ticket,body=self.f.finish();token=self.f.retain(attempt,ticket,body)
        self.f.rejected(self.make(sources()).complete,0,attempt,token,admission=ticket,**self.f.options())
        self.assertIsNotNone(self.f.j.snapshot()['unknown'])


if __name__ == '__main__':
    unittest.main()
