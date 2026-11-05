"""Signed witness data; daemon/approval are explicit existing unit fixtures."""
from copy import deepcopy
from dataclasses import asdict, replace, FrozenInstanceError
from datetime import datetime, timedelta, timezone
import hashlib
import json
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_recovery_prepare_v3_host import RecoveryPreparationTests
from deployment_compose_witness_store import canonical
import deployment_compose_recovery_capsule_v3_host as verifier


class CapsuleTests(RecoveryPreparationTests):
    def capsule(self):
        host = self.host()
        prepared = host.prepare_intent(operation_nonce='b'*64, expires_at=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        context = host.verify_context(prepared['recovery_context_reference'], prepared['request'], prepared['reviewed_history'])
        history = self.signed.history()
        original = history._request
        self.pins = dict(original_history=history, expected_source=original.source,
            expected_host_id=original.host_id, expected_daemon_id=original.daemon_id,
            expected_target=original.target, expected_policy_hash=original.policy_hash)
        return dict(request=asdict(prepared['request']), context=context)

    def verify(self, capsule):
        return verifier.verify_recovery_capsule(canonical(capsule), **self.pins)

    def rehash(self, capsule):
        capsule['request']['observation_hash'] = hashlib.sha256(canonical(capsule['context'])).hexdigest()

    def test_matches_real_preparer_without_mutation_or_authority(self):
        capsule = self.capsule()
        state_path=self.signed.root/'history-witness'/'state.json'
        before = state_path.read_bytes()
        with patch.object(self.signed.store,'append_event',side_effect=AssertionError('mutation')), patch.object(self.signed.store,'transition_successor',side_effect=AssertionError('mutation')), patch.object(self.signed.store,'register_once',side_effect=AssertionError('mutation')):
            result = self.verify(capsule)
        self.assertEqual(json.loads(result.context_bytes), capsule['context'])
        self.assertEqual(canonical(json.loads(result.request_bytes)), canonical(capsule['request']))
        self.assertEqual(state_path.read_bytes(), before)
        for key in ('phaseFreshnessVerified','linuxQuiescenceVerified','authorityGranted','executionAvailable','runtimePermit','productionReady'):
            self.assertIs(getattr(result,key), False)
        self.assertNotIn('currentPhaseSnapshot', repr(result))
        with self.assertRaises(FrozenInstanceError):result.history_digest='x'

    def test_rehashed_trusted_fields_and_request_changes_reject(self):
        capsule = self.capsule()
        for field, bad in (('receiptMap',{'web':'c'*64}), ('startWriteIndex',True),
                ('schemaVersion',True), ('completedOperations',[]), ('baselineStateDigest','c'*64),
                ('recoveryNonce','invalid'), ('nextOperation',{})):
            changed=deepcopy(capsule);changed['context'][field]=bad;self.rehash(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):self.verify(changed)
        for field in ('policy_hash','after_hash','before_hash','artifact_digest','plan_hash','history_hash'):
            changed=deepcopy(capsule);changed['request'][field]='c'*64
            with self.subTest(field=field),self.assertRaises(ValueError):self.verify(changed)

    def test_phase_is_only_hash_bound_claim_and_extra_authority_rejects(self):
        capsule=self.capsule()
        capsule['context']['currentPhaseSnapshot']={'rows':{'declared':'unverified'},'resources':{}}
        self.rehash(capsule)
        result=self.verify(capsule)
        self.assertFalse(result.phaseFreshnessVerified)
        self.assertFalse(result.executionAvailable)
        for name in ('history','writerDrained','record'):
            changed=deepcopy(capsule);changed[name]=True
            with self.assertRaises(ValueError):self.verify(changed)
        raw=canonical(capsule)
        for bad in (b'{"request":1,"request":2}',b'{"x":NaN}',raw+b' ',b'x'*(verifier.MAX_CAPSULE+1)):
            with self.assertRaises(ValueError):verifier.verify_recovery_capsule(bad,**self.pins)

    def test_pins_pending_history_and_changed_history_reject(self):
        capsule=self.capsule()
        for key in ('expected_host_id','expected_daemon_id','expected_policy_hash'):
            pins=dict(self.pins,**{key:'wrong'})
            with self.assertRaises(ValueError):verifier.verify_recovery_capsule(canonical(capsule),**pins)
        history=self.pins['original_history'];real=history.capture;count=[]
        def advance():
            if count:
                self.signed.index=1;self.signed.open_scope()
            count.append(True);return real()
        with patch.object(history,'capture',side_effect=advance),self.assertRaises(ValueError):self.verify(capsule)
        with self.assertRaises(ValueError):self.verify(capsule)

    def test_root_only_unknown_complete_and_recursive_are_rejected(self):
        capsule=self.capsule()
        history=self.pins['original_history']
        history._parent=object()
        with self.assertRaises(ValueError):self.verify(capsule)
        history._parent=None
        self.signed.index=1;self.signed.open_scope()
        with self.assertRaises(ValueError):self.verify(capsule)
        self.signed.finish(status=0,body=b'',definitive=False)
        with self.assertRaises(ValueError):self.verify(capsule)

    def test_full_deployment_is_not_partial_recovery(self):
        capsule=self.capsule()
        for index in range(1,5):
            self.signed.index=index;self.signed.open_scope()
            self.signed.finish(status=204,body=b'')
        self.assertEqual(len(self.pins['original_history'].capture().snapshot['knownPrefix']),5)
        with self.assertRaises(ValueError):self.verify(capsule)

    def test_source_target_and_self_hashed_body_are_inherited(self):
        capsule=self.capsule()
        for key,bad in (('expected_source',replace(self.original.source,source_sha='c'*40)),
                        ('expected_target',replace(self.original.target,target_id='wrong'))):
            pins=dict(self.pins,**{key:bad})
            with self.assertRaises(ValueError):verifier.verify_recovery_capsule(canonical(capsule),**pins)
        changed=deepcopy(capsule)
        changed['context']['knownWritePrefix'][0]['body']['Env'].append('SECRET=forged')
        self.rehash(changed)
        with self.assertRaises(ValueError):self.verify(changed)

    def test_expiry_before_and_during_validation_rejects(self):
        capsule=self.capsule()
        for expires in ('2020-01-01T00:00:00Z','2099-01-01T00:00:00Z'):
            changed=deepcopy(capsule);changed['context']['expiresAt']=expires
            changed['request']['expires_at']=expires;self.rehash(changed)
            with self.assertRaises(ValueError):self.verify(changed)
        actual=datetime.now(timezone.utc)
        clock=unittest.mock.Mock();clock.now.side_effect=[actual,actual+timedelta(hours=2)]
        with patch.object(verifier,'datetime',clock),self.assertRaises(ValueError):self.verify(capsule)


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(CapsuleTests(n) for n in CapsuleTests.__dict__ if n.startswith('test_'))
