"""Real local Gate opening commitment precedes all sourced receipt attempts."""
import json
import os
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_receipts_host as base
from tests.test_deployment_compose_sourced_receipts_host import sources, DERIVATIONS


@unittest.skipUnless(os.name == 'posix', 'POSIX Gate storage')
class GenerationSourceTests(unittest.TestCase):
    def setUp(self):
        self.f=base.CreateReceiptTests();self.addCleanup(self.f.doCleanups);self.f.setUp()
        self.legacy_session=self.f.session
        self.legacy_generation=base.GEN
        self.generation_patch=patch.object(base,'GEN','7'*64)
        self.generation_patch.start();self.addCleanup(self.generation_patch.stop)
        self.f.recorder=self.make(sources())

    def make(self,pins,**changes):
        opts=dict(derivation_digests=DERIVATIONS,source_model_bindings=pins,generation_source_binding=True)
        opts.update(changes)
        return base.receipts.ComposeCreateReceipts(self.f.j,self.f.archive,creates=base.CREATES,
            forbidden_container_ids=(base.OLD,base.PROTECTED),**opts)

    def opening(self,digest=None):
        self.f.session=self.f.gate.open_generation(generation=base.GEN,request_hash=base.R,
            receipt_hash=base.H,operations=base.OPERATIONS,
            source_context_digest=digest or self.f.recorder.source_context_digest)

    def records(self):
        tokens=[self.f.record(i,str(i+1)*64) for i in range(2)]
        return tokens,{i:t.reference for i,t in enumerate(tokens)}

    def test_opening_context_matches_exact_archived_schema4(self):
        self.opening();tokens,refs=self.records()
        evidence=self.f.gate.generation_evidence(base.GEN)
        self.assertEqual(evidence['binding']['source_context_digest'],self.f.recorder.source_context_digest)
        for token in tokens:
            value=json.loads(self.f.archive.get(token.reference))
            self.assertEqual(value['schemaVersion'],4)
            self.assertEqual(value['sourceContextDigest'],self.f.recorder.source_context_digest)
        value=self.f.recorder.bindings(refs,**self.f.options())
        self.assertTrue(value['sourceBindingRecordedBeforeWriteVerified'])
        self.assertFalse(value['sourceModelProvenanceVerified'] or value['executionAvailable'] or value['replaySafe'])

    def test_legacy_generation_cannot_be_upgraded_after_response(self):
        self.f.session=self.legacy_session
        with patch.object(base,'GEN',self.legacy_generation):
            attempt,ticket,body=self.f.finish()
            self.f.rejected(self.f.retain,attempt,ticket,body)
        self.assertIsNotNone(self.f.j.snapshot()['unknown'])

    def test_wrong_opening_context_blocks_and_keeps_pending(self):
        self.opening('f'*64)
        attempt,ticket,body=self.f.finish()
        self.f.rejected(self.f.retain,attempt,ticket,body)
        self.assertIsNotNone(self.f.j.snapshot()['unknown'])

    def test_changed_sources_or_derivation_cannot_match_original_context(self):
        self.opening();_,refs=self.records()
        for field in sources()['backend']:
            pins=sources();pins['backend'][field]='f'*(40 if field=='sourceSha' else 64)
            self.f.rejected(self.make(pins).bindings,refs,**self.f.options())
        self.f.rejected(self.make(sources(),derivation_digests={'backend':'f'*64,'frontend':'9'*64}).bindings,
                        refs,**self.f.options())

    def test_schema3_cannot_downgrade_source_committed_generation(self):
        self.opening();_,refs=self.records()
        self.f.rejected(self.make(sources(),generation_source_binding=False).bindings,refs,**self.f.options())

    def test_restarted_recorder_only_reads_completed_not_pending(self):
        self.opening();attempt,ticket,body=self.f.finish();token=self.f.retain(attempt,ticket,body)
        self.f.rejected(self.make(sources()).complete,0,attempt,token,admission=ticket,**self.f.options())
        self.f.recorder.complete(0,attempt,token,admission=ticket,**self.f.options())
        second=self.f.record(1,'2'*64)
        result=self.make(sources()).bindings({0:token.reference,1:second.reference},**self.f.options())
        self.assertTrue(result['sourceBindingRecordedBeforeWriteVerified'])

    def test_gate_reload_preserves_opening_source_commitment(self):
        self.opening();_,refs=self.records()
        reloaded=base.gateway.FileWriterGate(self.f.policy,self.f.root/'gate',key=base.KEY)
        options=self.f.options(gate=reloaded)
        result=self.make(sources()).bindings(refs,**options)
        self.assertTrue(result['sourceBindingRecordedBeforeWriteVerified'])
        self.assertEqual(result['sourceContextDigest'],self.f.recorder.source_context_digest)

    def test_invalid_context_or_version_option_rejects_before_open(self):
        for value in ('',True,'x'*64):
            with self.assertRaises(ValueError):
                self.f.gate.open_generation(generation=base.GEN,request_hash=base.R,receipt_hash=base.H,
                                           operations=base.OPERATIONS,source_context_digest=value)
        self.f.rejected(self.make,None)
        self.f.rejected(self.make,sources(),generation_source_binding=1)


if __name__=='__main__':
    unittest.main()
