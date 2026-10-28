"""Real signed parent lineage; authority/phase callbacks are explicit unit seams."""
from copy import deepcopy
from dataclasses import replace
import unittest
import os
import shutil
from unittest.mock import Mock, patch

from tests import test_deployment_compose_history_v3_host as history_fixture
from tests.test_deployment_compose_gate_witness_v3 import GateFixture
from tests.test_deployment_compose_bundle_v3 import bind_baseline, baseline_rows
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_startup_fence_v3_host import Profile3StartupFenceV3


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class StartupFenceTests(GateFixture, unittest.TestCase):
    setUp = history_fixture.HistoryTests.setUp
    factory = history_fixture.HistoryTests.factory
    open_scope = history_fixture.HistoryTests.open_scope
    finish = history_fixture.HistoryTests.finish
    history = history_fixture.HistoryTests.history

    def completed(self):
        self.finish()
        self.receipts = {'web': 'a'*64}
        for index in range(1, 5):
            self.index = index
            self.open_scope()
            self.finish(status=204, body=b'')
        history = self.history()
        reviewed = history.capture()
        value = self.bundle.to_dict()
        value.pop('operations'); value.pop('resolverRules'); value.pop('resolverContract')
        value.pop('imageDefaultsDigests')
        value['operationNonce'] = 'e'*64
        service = value['services'][0]
        service['baselineContainerId'] = 'a'*64
        service['baselineImageId'], service['targetImageId'] = service['targetImageId'], service['baselineImageId']
        service['baselineCreateBody'], service['targetCreateBody'] = service['targetCreateBody'], service['baselineCreateBody']
        rows = bind_baseline(value)
        original = self.bundle.to_dict()
        original_rows = baseline_rows(original)
        value['protectedContainers'] = deepcopy(original['protectedContainers'])
        for protected in value['protectedContainers']:
            rows[protected['containerId']] = original_rows[protected['containerId']]
        from deployment_compose_phase_guard_v3_host import baseline_state_digest
        value['baselineStateDigest'] = baseline_state_digest(rows)
        from deployment_compose_image_defaults import ZERO_DEFAULTS
        bundle = ExecutionBundleV3(value, authenticated_image_defaults={'web': deepcopy(ZERO_DEFAULTS)})
        req = replace(self.req, operation='rollback', plan_hash=bundle.digest, history_hash=reviewed.digest)
        descriptor = Profile3StepExecutor.scope_descriptor(bundle, req, 'f'*64, bundle.creation_operations()[0], 0, {})
        binding = dict(self.binding, generation=descriptor['generation'], scopeHash=descriptor['scopeHash'])
        return history, reviewed, bundle, req, binding

    def activate(self, values, **changes):
        history, reviewed, bundle, req, binding = values
        authority = Mock()
        args = dict(bundle=bundle, request=req, binding=binding, intent_authority=authority,
                    phase_guard=lambda _:True, witness_client_factory=self.factory,
                    consumption_receipt_hash='f'*64, gate_policy=self.policy)
        args.update(changes)
        fence = Profile3StartupFenceV3(original_history=history, reviewed_history=reviewed,
                                     quiesce_writer=lambda:True)
        return fence, args

    def test_exact_closed_parent_cas_and_one_use(self):
        values = self.completed()
        fence, args = self.activate(values)
        self.assertEqual(fence.activate(**args), values[-1])
        view = self.factory(values[-1]).read()
        self.assertEqual(view['seq'], 0)
        self.assertEqual(view['lineage'][-1], dict(values[1].snapshot['closedTail']))
        with self.assertRaises(ValueError): fence.activate(**args)
        fresh, args = self.activate(values)
        with self.assertRaises(ValueError): fresh.activate(**args)

    def test_missing_consent_phase_or_history_never_transitions(self):
        values = self.completed()
        authority = Mock(); authority.check_consumed_intent.side_effect = ValueError('revoked')
        for changes in (dict(phase_guard=lambda _:False), dict(intent_authority=authority),
                        dict(request=replace(values[3], history_hash='0'*64)),
                        dict(binding=dict(values[-1], epoch='0'*64))):
            before = self.client.chain_status()
            fence, args = self.activate(values, **changes)
            with self.assertRaises(ValueError): fence.activate(**args)
            self.assertEqual(before, self.client.chain_status())

    def test_unknown_outcome_cannot_be_fenced(self):
        self.finish(status=0, body=b'', definitive=False)
        history = self.history(); reviewed = history.capture()
        req = replace(self.req, operation='rollback', history_hash=reviewed.digest)
        fence = Profile3StartupFenceV3(original_history=history, reviewed_history=reviewed,
                                     quiesce_writer=lambda:True)
        before = self.client.chain_status()
        with self.assertRaises(ValueError):
            fence.activate(bundle=self.bundle, request=req, binding=self.binding,
                intent_authority=Mock(), phase_guard=lambda _:True, witness_client_factory=self.factory,
                consumption_receipt_hash='f'*64, gate_policy=self.policy)
        self.assertEqual(before, self.client.chain_status())

    def test_rehashed_third_image_or_replacement_scope_is_not_rollback(self):
        values = self.completed()
        from deployment_compose_bundle_v3 import FIELDS
        from deployment_compose_image_defaults import ZERO_DEFAULTS
        for mutation in ('target-image', 'baseline-id', 'protected-pin'):
            value = {k:v for k,v in values[2].to_dict().items() if k in FIELDS}
            if mutation == 'target-image':
                value['services'][0]['targetImageId'] = 'sha256:'+'8'*64
                value['services'][0]['targetCreateBody']['Image'] = 'sha256:'+'8'*64
            elif mutation == 'baseline-id':
                value['services'][0]['baselineContainerId'] = 'b'*64
            else:
                value['protectedContainers'][0]['staticConfigDigest'] = '0'*64
            bundle = ExecutionBundleV3(value, authenticated_image_defaults={'web':deepcopy(ZERO_DEFAULTS)})
            req = replace(values[3], plan_hash=bundle.digest)
            desc = Profile3StepExecutor.scope_descriptor(bundle,req,'f'*64,bundle.creation_operations()[0],0,{})
            binding = dict(values[-1],generation=desc['generation'],scopeHash=desc['scopeHash'])
            before = self.client.chain_status()
            fence,args = self.activate((values[0],values[1],bundle,req,binding))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                fence.activate(**args)
            self.assertEqual(before,self.client.chain_status())

    def test_global_capacity_and_quiescence_checked_before_successor(self):
        values = self.completed()
        before = self.client.chain_status()
        fence,args = self.activate(values)
        with patch('deployment_compose_startup_fence_v3_host.MAX_SCOPES',9), self.assertRaises(ValueError):
            fence.activate(**args)
        self.assertEqual(before,self.client.chain_status())
        fence,args = self.activate(values)
        fence._quiesce = lambda:False
        with self.assertRaises(ValueError):
            fence.activate(**args)
        self.assertEqual(before,self.client.chain_status())


if __name__ == '__main__':
    unittest.main()
