"""Static declaration checks; signed history is real, Engine is a fixture."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_recovery_capsule_v3_host import CapsuleTests
from deployment_compose_witness_store import canonical
import deployment_compose_recovery_phase_capsule_v3_host as phase


class PhaseTests(CapsuleTests):
    def inputs(self):
        capsule = self.capsule()
        baseline = self.store.get(self.bundle.to_dict()['baselineStateReference'])
        return capsule, dict(self.pins, baseline_bytes=baseline,
            expected_daemon_version=self.version)

    def check(self, capsule, inputs):
        return phase.verify_captured_recovery_phase(canonical(capsule), **inputs)

    def test_valid_declaration_is_consistent_but_never_fresh_or_authority(self):
        capsule, inputs = self.inputs()
        path = self.signed.root/'history-witness'/'state.json'
        before = path.read_bytes()
        with patch.object(self.signed.store,'append_event',side_effect=AssertionError('write')), patch.object(self.signed.store,'transition_successor',side_effect=AssertionError('write')), patch.object(self.signed.store,'register_once',side_effect=AssertionError('write')), patch('deployment_compose_phase_state_v3_host.TrustedPhaseStateProducerV3._get',side_effect=AssertionError('Engine read')):
            result = self.check(capsule, inputs)
        self.assertTrue(result.phaseConsistencyVerified)
        for key in ('phaseFreshnessVerified','linuxQuiescenceVerified','authorityGranted','executionAvailable','runtimePermit','productionReady'):
            self.assertIs(getattr(result,key),False)
        self.assertEqual(before,path.read_bytes())
        self.assertNotIn('currentPhaseSnapshot',repr(result))
        with self.assertRaises(FrozenInstanceError):result.consistency_digest='x'

    def test_rehashed_container_and_resource_drift_rejects(self):
        capsule, inputs = self.inputs()
        cid='a'*64; original=self.bundle.to_dict()['services'][0]['baselineContainerId']
        peer=next(iter(self.bundle.to_dict()['protectedContainers']))['containerId']
        mutations=[lambda p:p['rows'][cid]['Config']['Env'].append('FORGED=1'),
            lambda p:p['rows'][cid].update(Image='sha256:'+'e'*64),
            lambda p:p['rows'][cid].update(Name='/wrong'),
            lambda p:p['rows'][cid]['State'].update(Pid=7),
            lambda p:p['rows'][cid]['State'].update(Pid=True),
            lambda p:p['rows'][cid]['State'].update(Status='running',Running=True,Pid=7),
            lambda p:p['rows'][original].update(Health='unhealthy'),
            lambda p:p['rows'][peer].update(Health='unhealthy'),
            lambda p:p['rows'].update({'d'*64:deepcopy(p['rows'][cid])}),
            lambda p:p['resources'].update({'unexpected':{}})]
        network=next(k for k in capsule['context']['currentPhaseSnapshot']['resources'] if k.startswith('network:'))
        volume=next(k for k in capsule['context']['currentPhaseSnapshot']['resources'] if k.startswith('volume:'))
        mutations += [lambda p:p['resources'][network]['Containers'].pop(original),
            lambda p:p['resources'][volume].update(Options={'device':'forged'}),
            lambda p:p['resources'][volume].update(Mountpoint='/wrong')]
        for i, change in enumerate(mutations):
            candidate=deepcopy(capsule);change(candidate['context']['currentPhaseSnapshot']);self.rehash(candidate)
            with self.subTest(i=i),self.assertRaises(ValueError):self.check(candidate,inputs)

    def test_baseline_is_independent_bounded_and_exactly_normalized(self):
        capsule, inputs=self.inputs()
        for raw in (b'{}',inputs['baseline_bytes']+b' ',b'x'*(phase.MAX_BASELINE+1)):
            with self.assertRaises(ValueError):self.check(capsule,dict(inputs,baseline_bytes=raw))
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
            with self.assertRaises(ValueError):phase.decode(raw)
        rows=deepcopy(capsule['context']['currentPhaseSnapshot']['rows'])
        with self.assertRaises(ValueError):self.check(capsule,dict(inputs,baseline_bytes=canonical(rows)))
        candidate=deepcopy(capsule);candidate['context']['currentPhaseSnapshot']['rows']['a'*64]['State']['Health']={'Status':'healthy'};self.rehash(candidate)
        with self.assertRaises(ValueError):self.check(candidate,inputs)

    def test_allowed_dynamic_fields_remain_declarations_and_version_is_bound(self):
        capsule, inputs=self.inputs()
        candidate=deepcopy(capsule);row=candidate['context']['currentPhaseSnapshot']['rows']['a'*64]
        row['Health']='starting'
        next(iter(row['NetworkSettings']['Networks'].values()))['IPAddress']='192.0.2.1'
        self.rehash(candidate)
        result=self.check(candidate,inputs)
        self.assertTrue(result.phaseConsistencyVerified);self.assertFalse(result.phaseFreshnessVerified)
        other=self.check(candidate,dict(inputs,expected_daemon_version={'Version':'interpretation-other','GitCommit':'other'}))
        self.assertNotEqual(result.consistency_digest,other.consistency_digest)
        for version in ({}, {'Version':True,'GitCommit':'x'}):
            with self.assertRaises(ValueError):self.check(capsule,dict(inputs,expected_daemon_version=version))

    def test_final_history_and_expiry_are_rechecked(self):
        capsule, inputs=self.inputs();history=inputs['original_history'];real=history.capture;calls=[]
        def advance():
            if len(calls)==2:self.signed.index=1;self.signed.open_scope()
            calls.append(True);return real()
        with patch.object(history,'capture',side_effect=advance),self.assertRaises(ValueError):self.check(capsule,inputs)

    def test_expiry_after_static_validation_rejects(self):
        capsule, inputs=self.inputs();clock=unittest.mock.Mock()
        clock.now.return_value=datetime.now(timezone.utc)+timedelta(hours=2)
        with patch.object(phase,'datetime',clock),self.assertRaises(ValueError):self.check(capsule,inputs)
        with patch.object(inputs['original_history'],'capture',side_effect=ValueError('signature')),self.assertRaises(ValueError):self.check(capsule,inputs)


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(PhaseTests(n) for n in PhaseTests.__dict__ if n.startswith('test_'))
