"""Real private CAS, RequestV2 and process termination; no Engine or approval."""
from copy import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_operation_witness_v4 as fixture
from deployment_compose_recovery_prepare_v4_host import RecoveryPreparationHostV4, PreparedRecoveryV4
from deployment_compose_operation_witness_v4 import digest


@unittest.skipUnless(os.name == 'posix', 'POSIX witness/CAS/process ownership')
class RecoveryPreparationV4Tests(unittest.TestCase):
    setUp = fixture.WitnessV4Tests.setUp
    open = fixture.WitnessV4Tests.open
    cursor = fixture.WitnessV4Tests.cursor
    preparer = fixture.WitnessV4Tests.preparer
    intent = fixture.WitnessV4Tests.intent
    prepared = fixture.WitnessV4Tests.prepared
    abandon = fixture.WitnessV4Tests.abandon

    def test_real_request_context_and_envelope_reference_binding(self):
        preparer=self.preparer(); prepared=preparer.prepare(operation_nonce='f'*64,
            expires_at=(datetime.now(timezone.utc)+timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        review=preparer.review(prepared); request=review['request']
        context=json.loads(self.cas.get(review['contextReference']))
        self.assertEqual(request.profile_id,'compose-recovery-v4')
        self.assertEqual((request.profile_version,request.operation),('4','recovery'))
        self.assertEqual(request.observation_hash,digest(context))
        self.assertEqual(request.history_hash,context['historyDigest'])
        self.assertEqual(request.plan_hash,self.root_request.plan_hash)
        self.assertEqual(context['originalRequestHash'],self.root_request.digest())
        self.assertEqual(context['baselineReference'],self.session['baselineReference'])
        self.assertEqual(context['baselineContentDigest'],hashlib.sha256(b'fixed baseline bytes').hexdigest())
        self.assertNotEqual(context['baselineReference'],context['baselineContentDigest'])
        self.assertEqual(context['witnessPhaseSnapshot']['phase'],'open')
        for key in ('authorityGranted','executionAvailable','productionReady'): self.assertIs(review[key],False)
        result=self.store.abandon_and_reserve(self.cursor(),supervisor=self.supervisor,actor=self.actor,
            termination=self.supervisor.stop_and_join(self.actor),recovery_intent=prepared)
        self.assertEqual(result['scopes'][-1]['phase'],'pending-authorization')

    def test_forged_copied_and_json_preparations_cannot_be_used(self):
        valid=self.intent()
        forged=PreparedRecoveryV4();forged._issuer=valid._issuer
        for supplied in (forged, copy(valid), {}, valid.request, valid.request.canonical_json()):
            with self.subTest(kind=type(supplied)),self.assertRaises(ValueError): self.abandon(recovery_intent=supplied)

    def test_v3_production_and_different_root_rejected(self):
        for request in (replace(self.root_request,profile_version='3'),replace(self.root_request,production=True),
                        replace(self.root_request,plan_hash='0'*64),replace(self.root_request,host_id='another'),
                        replace(self.root_request,operation='recovery',history_hash='0'*64)):
            with self.subTest(request=request.profile_version),self.assertRaises(ValueError):
                RecoveryPreparationHostV4(witness=self.store,root_request=request,baseline_store=self.cas,
                    supervisor=self.supervisor,actor=self.actor,termination=self.supervisor.stop_and_join(self.actor))

    def test_lost_registry_and_restarted_preparer_cannot_revive_object(self):
        valid=self.intent(); replacement=self.preparer()
        with self.assertRaises(ValueError): replacement.review(valid)
        valid._issuer._issued.clear()
        with self.assertRaises(ValueError): self.abandon(recovery_intent=valid)

    def test_state_drift_after_preparation_rejected_inside_cas_lock(self):
        prepared=self.intent();self.prepared()
        with self.assertRaises(ValueError): self.abandon(recovery_intent=prepared)
        self.assertEqual(self.store.read()['scopes'][0]['phase'],'prepared')

    def test_missing_baseline_or_context_cas_rejected(self):
        prepared=self.intent(); review=prepared._issuer.review(prepared)
        (Path(self.cas._root)/review['contextReference']).unlink()
        with self.assertRaises(ValueError): self.abandon(recovery_intent=prepared)
        (Path(self.cas._root)/self.session['baselineReference']).unlink()
        with self.assertRaises(ValueError): self.preparer()

    def test_expiry_and_nonce_validation_before_registration(self):
        preparer=self.preparer()
        for nonce,expiry in [('bad',(datetime.now(timezone.utc)+timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ')),
                             ('f'*64,'2020-01-01T00:00:00Z')]:
            with self.assertRaises(ValueError): preparer.prepare(operation_nonce=nonce,expires_at=expiry)
        self.assertEqual(preparer._issued,{})
        prepared=self.intent()
        with patch('deployment_compose_recovery_prepare_v4_host.datetime') as clock:
            clock.now.return_value=datetime.now(timezone.utc)+timedelta(seconds=600)
            with self.assertRaises(ValueError): self.abandon(recovery_intent=prepared)

    def test_admitted_unknown_never_prepares(self):
        self.prepared()
        self.view=self.store.record_admitted(self.cursor(),supervisor=self.supervisor,actor=self.actor,attempt='9'*64)
        with self.assertRaises(ValueError): self.preparer()

    def test_drift_between_preparation_reads_is_not_registered(self):
        preparer=self.preparer();read=self.store.read;calls=[]
        def drift():
            calls.append(1)
            if len(calls)==2:self.prepared()
            return read()
        with patch.object(self.store,'read',side_effect=drift),self.assertRaises(ValueError):
            preparer.prepare(operation_nonce='f'*64,
                expires_at=(datetime.now(timezone.utc)+timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.assertEqual(preparer._issued,{})

    def test_alive_actor_and_other_actor_termination_rejected(self):
        with self.assertRaises(ValueError):
            RecoveryPreparationHostV4(witness=self.store, root_request=self.root_request, baseline_store=self.cas,
                supervisor=self.supervisor, actor=self.actor, termination=fixture.ActorTermination())
        self.assertIsNone(self.supervisor._actors[id(self.actor)][1].poll())
        other=self.supervisor.start_fixed_actor(self.session['sessionHash'])
        proof=self.supervisor.stop_and_join(other)
        with self.assertRaises(ValueError):
            RecoveryPreparationHostV4(witness=self.store, root_request=self.root_request, baseline_store=self.cas,
                supervisor=self.supervisor, actor=other, termination=proof)
