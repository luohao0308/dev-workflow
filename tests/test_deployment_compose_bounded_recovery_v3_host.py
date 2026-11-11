"""Opt-in cumulative history and fresh recovery over real signed Gate/TLS fixtures."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
import shutil
import unittest
from unittest.mock import Mock, patch

from tests.test_deployment_compose_batch_restart_material_v3_host import BatchFixture
from tests import test_deployment_compose_recovery_execution_v3_host as execution
from tests import test_deployment_compose_approval_v3_host as approvals
from tests.test_release_host import claims
from deployment_compose_history_v3_host import AuthenticatedHistoryV3, ANCESTRY_PROFILE
from deployment_compose_coordinator_v3_host import Profile3StepExecutor, ComposeCoordinatorV3
from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
from deployment_compose_startup_fence_v3_host import Profile3RecoveryFenceV3
from deployment_compose_witness_store import canonical
from tests.test_deployment_compose_recovery_prepare_v3_host import expiry
import deployment_compose_approval_v3_host as approval_host


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class BoundedHistoryTests(unittest.TestCase):
    def setUp(self):
        self.f = BatchFixture()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.close_prefix(1)
        self.parent = self.f.history(witness_client=self.f.factory(self.f.first_binding), ancestry_profile=ANCESTRY_PROFILE)

    def successor(self, parent, count):
        f = self.f
        reviewed = parent.capture()
        req = replace(parent._request, operation='recovery', history_hash=reviewed.digest,
                      observation_hash=hashlib.sha256(str(count).encode()).hexdigest(), expires_at=expiry())
        f.req = req
        f.receipt = format(count+100, '064x')
        f.index = count-1
        f.open_scope()
        body = b''
        if f.op['phase'] == 'create':
            cid = ('a' if f.op['service']=='web' else 'b')*64
            f.receipts[f.op['service']] = cid
            body = canonical({'Id':cid})
        f.finish(status=f.op['expectedStatus'], body=body)
        return f.history(parent_history=parent, reviewed_parent_snapshot=reviewed, ancestry_profile=ANCESTRY_PROFILE)

    def rollback_prefix(self):
        from deployment_compose_bundle_v3 import ExecutionBundleV3
        from deployment_compose_phase_guard_v3_host import baseline_state_bytes, PhaseGuardV3
        from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
        f = BatchFixture()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.close_prefix(10)
        root = f.history(witness_client=f.factory(f.first_binding), ancestry_profile=ANCESTRY_PROFILE)
        reviewed = root.capture()
        value = f.bundle.to_dict()
        for key in ('operations', 'resolverRules', 'resolverContract', 'imageDefaultsDigests'):
            value.pop(key)
        for service in value['services']:
            old_body = deepcopy(service['baselineCreateBody'])
            service.update(baselineContainerId=f.receipts[service['name']],
                baselineImageId=service['targetImageId'], baselineCreateBody=deepcopy(service['targetCreateBody']),
                targetImageId=old_body['Image'], targetCreateBody=old_body)
        raw = baseline_state_bytes(f.rows)
        value.update(operationNonce='8'*64, baselineStateReference=f.archive_store.put(raw),
                     baselineStateDigest=hashlib.sha256(raw).hexdigest())
        bundle = ExecutionBundleV3(value, authenticated_image_defaults=f.defaults)
        request = replace(f.req, operation='rollback', history_hash=reviewed.digest, plan_hash=bundle.digest,
                          expires_at=expiry())
        receipt = 'a'*64
        operation = bundle.creation_operations()[0]
        descriptor = Profile3StepExecutor.scope_descriptor(bundle, request, receipt, operation, 0, {})
        binding = dict(f.binding, generation=descriptor['generation'], scopeHash=descriptor['scopeHash'])
        prior = f.client.read()
        f.client.transition_successor(expected_seq=prior['seq'], expected_head=prior['head'], childBinding=binding)
        policy = replace(f.policy, witness_scope_hash=descriptor['scopeHash'])
        guard = PhaseGuardV3(bundle, deepcopy(f.rows), read_json=f.read, daemon_version=f.version)
        f.bundle, f.req, f.policy = bundle, request, policy
        f.receipt, f.client = receipt, f.factory(binding)
        f.adapter = GateOperationWitnessAdapterV3(f.client)
        f.gen, f.request, f.source, f.ops = descriptor['generation'], request.digest(), descriptor['source'], descriptor['operations']
        f.body = canonical(operation['body'])
        f.current_gate = f.gate()
        f.finish(status=201, body=canonical({'Id':'c'*64}))
        row = deepcopy(f.rows['a'*64])
        row.update(Id='c'*64, Name='/dwc-'+'8'*24+'-web', Image=operation['body']['Image'])
        row['Config'] = {k:deepcopy(v) for k,v in operation['body'].items() if k not in ('HostConfig','NetworkingConfig')}
        row['HostConfig'] = deepcopy(operation['body']['HostConfig'])
        row['State'].update(Pid=0, StartedAt='', Running=False, Status='created')
        f.rows['c'*64] = row
        child = f.history(parent_history=root, reviewed_parent_snapshot=reviewed, ancestry_profile=ANCESTRY_PROFILE)
        return f, child, guard

    def test_rollback_prefix_prepares_fresh_recovery_with_current_bundle(self):
        from dataclasses import asdict
        from deployment_compose_recovery_capsule_v3_host import verify_recovery_capsule
        f, parent, guard = self.rollback_prefix()
        snapshot = parent.capture()
        self.assertEqual(len(snapshot.snapshot['scopes']), 11)
        self.assertEqual(len(snapshot.snapshot['knownPrefix']), 1)
        self.assertEqual(snapshot.snapshot['receiptMap'], {'web':'c'*64})
        prep = RecoveryPreparationHostV3(original_history=parent, store=f.archive_store,
            phase_guard=guard, readiness=lambda *_: True, ancestry_profile=ANCESTRY_PROFILE)
        prepared = prep.prepare_intent(operation_nonce='7'*64, expires_at=expiry())
        context = prep.verify_context(prepared['recovery_context_reference'], prepared['request'], prepared['reviewed_history'])
        self.assertEqual(context['startWriteIndex'], 1)
        self.assertEqual(context['nextOperation']['service'], 'api')
        self.assertEqual(prepared['bundle'].canonical_bytes, parent._bundle.canonical_bytes)
        self.assertEqual(prepared['request'].history_hash, snapshot.digest)
        self.assertEqual(context['schemaVersion'], 2)
        self.assertEqual(context['ancestryProfile'], ANCESTRY_PROFILE)
        capsule = canonical(dict(request=asdict(prepared['request']), context=context))
        with self.assertRaises(ValueError):
            verify_recovery_capsule(capsule, original_history=parent, expected_source=prepared['request'].source,
                expected_host_id=prepared['request'].host_id, expected_daemon_id=prepared['request'].daemon_id,
                expected_target=prepared['request'].target, expected_policy_hash=prepared['request'].policy_hash)

    def test_capacity_counts_deploy_ancestors_before_cas(self):
        from deployment_compose_witness_budget_v3_host import check_witness_byte_capacity
        from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
        f, parent, guard = self.rollback_prefix()
        prep = RecoveryPreparationHostV3(original_history=parent, store=f.archive_store,
            phase_guard=guard, readiness=lambda *_: True, ancestry_profile=ANCESTRY_PROFILE)
        prepared = prep.prepare_intent(operation_nonce='6'*64, expires_at=expiry())
        context = prep.verify_context(prepared['recovery_context_reference'], prepared['request'], prepared['reviewed_history'])
        descriptor = Profile3StepExecutor.scope_descriptor(f.bundle, prepared['request'], 'b'*64,
            context['nextOperation'], context['startWriteIndex'], context['receiptMap'])
        binding = dict(f.binding, generation=descriptor['generation'], scopeHash=descriptor['scopeHash'])
        result = check_witness_byte_capacity(f.bundle, prepared['request'], f.policy, 'b'*64, binding,
            prior_snapshot=prepared['reviewed_history'], ancestry_profile=ANCESTRY_PROFILE)
        self.assertEqual(result['scopeCount'], 20)
        self.assertEqual(result['eventCount'], 120)
        authority = Mock()
        with patch('deployment_compose_witness_budget_v3_host.MAX_SCOPES', 19):
            with patch.object(f.store, 'transition_successor', side_effect=AssertionError('capacity must precede CAS')) as cas:
                with self.assertRaises(ValueError):
                    fence = Profile3RecoveryFenceV3(preparation=prep,
                        context_reference=prepared['recovery_context_reference'],
                        reviewed_history=prepared['reviewed_history'], quiesce_writer=lambda: True)
                    fence.activate(bundle=f.bundle, request=prepared['request'], binding=binding,
                        intent_authority=authority, phase_guard=guard, witness_client_factory=f.factory,
                        consumption_receipt_hash='b'*64, gate_policy=f.policy)
                cas.assert_not_called()
                authority.check_consumed_intent.assert_not_called()

    def test_same_request_active_leaf_uses_logical_index_with_global_ancestors(self):
        from deployment_compose_witness_budget_v3_host import check_witness_byte_capacity
        f, parent, _ = self.rollback_prefix()
        f.receipts = {'web':'c'*64}
        f.writes = [operation for operation in f.bundle.resolve_operations({'web':'c'*64, 'api':'d'*64})
                    if operation['method'] != 'GET']
        f.index = 1
        f.open_scope()
        snapshot = parent.capture()
        self.assertEqual(len(snapshot.snapshot['scopes']), 12)
        self.assertEqual(len(snapshot.snapshot['knownPrefix']), 1)
        result = check_witness_byte_capacity(f.bundle, parent._request, f.policy, f.receipt, f.binding,
            prior_snapshot=snapshot, ancestry_profile=ANCESTRY_PROFILE)
        self.assertEqual(result['scopeCount'], 20)
        self.assertEqual(result['eventCount'], 120)

    def test_budget_rejects_forged_segment_metadata_and_boolean_counts(self):
        from deployment_compose_witness_budget_v3_host import check_witness_byte_capacity
        original = self.parent.capture()
        for key, value in (('scopeCount', True), ('scopeStart', 1), ('startWriteIndex', True),
                           ('requestHash', 'bad'), ('parentHistoryDigest', '0'*64)):
            material = json.loads(original.canonical)
            material['segments'][0][key] = value
            changed = replace(original, canonical=canonical(material))
            with self.subTest(field=key), self.assertRaises(ValueError):
                check_witness_byte_capacity(self.f.bundle, self.parent._request, self.f.policy,
                    self.f.receipt, self.f.first_binding, prior_snapshot=changed, ancestry_profile=ANCESTRY_PROFILE)

    def test_three_generations_preserve_full_scopes_and_logical_prefix(self):
        first = self.successor(self.parent, 2)
        second = self.successor(first, 3)
        value = second.capture().snapshot
        self.assertEqual(value['schemaVersion'], 3)
        self.assertEqual(len(value['scopes']), 3)
        self.assertEqual(len(value['knownPrefix']), 3)
        self.assertEqual([segment['scopeStart'] for segment in value['segments']], [0, 1, 2])
        self.assertEqual([segment['scopeCount'] for segment in value['segments']], [1, 1, 1])
        self.assertEqual([segment['startWriteIndex'] for segment in value['segments']], [0, 1, 2])
        self.assertEqual(value['segments'][-1]['parentHistoryDigest'], second._reviewed_parent.digest)

    def test_default_api_rejects_optin_parent_and_deep_history(self):
        for profile in (True, False, 0, object()):
            with self.subTest(profile=type(profile).__name__), self.assertRaises(ValueError):
                self.f.history(ancestry_profile=profile)
        first = self.successor(self.parent, 2)
        with self.assertRaises(ValueError):
            self.f.history(parent_history=first, reviewed_parent_snapshot=first.capture())
        with self.assertRaises(ValueError):
            RecoveryPreparationHostV3(original_history=first, store=self.f.archive_store,
                                     phase_guard=object(), readiness=lambda *_: True)

    def test_cycles_mixed_profiles_and_repeated_request_are_rejected(self):
        first = self.successor(self.parent, 2)
        for attribute, value in (('_parent', first), ('_ancestry_profile', None), ('_request', self.parent._request)):
            original = getattr(first, attribute)
            setattr(first, attribute, value)
            try:
                with self.subTest(attribute=attribute), self.assertRaises(ValueError):
                    first.capture()
            finally:
                setattr(first, attribute, original)

    def test_foreign_ancestor_key_policy_and_epoch_are_rejected(self):
        first = self.successor(self.parent, 2)
        with patch.object(first._client, '_public', b'foreign-key'):
            with self.assertRaises(ValueError):
                first.capture()
        with patch.object(first, '_policy', replace(first._policy, key_id='different-key')):
            with self.assertRaises(ValueError):
                first.capture()
        changed = dict(first._client._binding, epoch='e'*64)
        with patch.object(first._client, '_binding', changed):
            with self.assertRaises(ValueError):
                first.capture()

    def test_callback_cannot_replace_leaf_or_ancestor_inputs_after_final_read(self):
        child = self.successor(self.parent, 2)
        root = self.parent
        from deployment_compose_restart_material_v3_host import _bundle
        equivalent_bundle = _bundle(root._bundle.to_dict(), self.f.defaults)
        attacks = ((child, '_reviewed_parent', None),
                   (child, '_ancestry_profile', None),
                   (root, '_request', replace(root._request, observation_hash='c'*64)),
                   (root, '_bundle', equivalent_bundle),
                   (root, '_parent', child))
        for node, attribute, replacement in attacks:
            saved = getattr(node, attribute)
            transport = child._client._transport
            reads = 0

            def mutate_after_final_reply(method, request):
                nonlocal reads
                reply = transport(method, request)
                if method == 'chain_status':
                    reads += 1
                    if reads == 2:
                        setattr(node, attribute, replacement)
                return reply

            try:
                with self.subTest(attribute=attribute), patch.object(child._client, '_transport', mutate_after_final_reply):
                    with self.assertRaises(ValueError):
                        child.capture()
                    self.assertEqual(reads, 2)
            finally:
                setattr(node, attribute, saved)

    def test_default_capture_cannot_be_elevated_by_final_transport_callback(self):
        history = self.f.root_history()
        self.assertIsNone(history._ancestry_profile)
        transport = history._client._transport
        reads = 0

        def elevate_after_final_reply(method, request):
            nonlocal reads
            reply = transport(method, request)
            if method == 'chain_status':
                reads += 1
                if reads == 2:
                    history._ancestry_profile = ANCESTRY_PROFILE
            return reply

        with patch.object(history._client, '_transport', elevate_after_final_reply):
            with self.assertRaises(ValueError):
                history.capture()
        self.assertEqual(reads, 2)

    def test_depth_limit_rejects_ninth_generation(self):
        current = self.parent
        for count in range(2, 9):
            current = self.successor(current, count)
        self.assertEqual(len(current.capture().snapshot['segments']), 8)
        with self.assertRaises(ValueError):
            self.successor(current, 9)

    def test_eighth_generation_cannot_prepare_another_generation(self):
        from deployment_compose_phase_guard_v3_host import PhaseGuardV3
        current = self.parent
        for count in range(2, 9):
            current = self.successor(current, count)
        f = self.f
        guard = PhaseGuardV3(f.bundle, f.baseline, read_json=f.read, daemon_version=f.version)
        prep = RecoveryPreparationHostV3(original_history=current, store=f.archive_store,
            phase_guard=guard, readiness=lambda *_: True, ancestry_profile=ANCESTRY_PROFILE)
        before = (f.store.root/'state.json').read_bytes()
        with patch.object(guard, 'capture_phase', side_effect=AssertionError('depth must precede phase work')):
            with self.assertRaises(ValueError):
                prep.prepare_intent(operation_nonce='5'*64, expires_at=expiry())
        self.assertEqual(before, (f.store.root/'state.json').read_bytes())

    def test_changed_reviewed_ancestor_and_pending_ancestor_are_rejected(self):
        first = self.successor(self.parent, 2)
        original = first._reviewed_parent
        value = json.loads(original.canonical)
        value['receiptMap']['web'] = 'c'*64
        first._reviewed_parent = replace(original, canonical=canonical(value))
        with self.assertRaises(ValueError):
            first.capture()
        first._reviewed_parent = original
        # A successor that has not completed even one scope cannot become a recovery parent.
        reviewed = first.capture()
        req = replace(first._request, history_hash=reviewed.digest, observation_hash='e'*64)
        self.f.req = req
        self.f.receipt = '9'*64
        self.f.index = 2
        self.f.open_scope()
        pending = self.f.history(parent_history=first, reviewed_parent_snapshot=reviewed, ancestry_profile=ANCESTRY_PROFILE)
        self.assertIsNotNone(pending.capture().snapshot['pending'])
        with self.assertRaises(ValueError):
            self.successor(pending, 3)


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'), 'TLS/OpenSSH required')
class BoundedRecoveryExecutionTests(execution.history_fixture.GateFixture, unittest.TestCase):
    setUpClass = classmethod(execution.RecoveryExecutionTests.setUpClass.__func__)
    tearDownClass = classmethod(execution.RecoveryExecutionTests.tearDownClass.__func__)
    run_recovery = execution.RecoveryExecutionTests.run_recovery
    setUp = execution.RecoveryExecutionTests.setUp
    def test_two_fresh_recoveries_complete_one_deployment(self):
        self.run_two_recoveries(two_services=False)

    def test_two_services_recover_across_two_fresh_generations(self):
        self.run_two_recoveries(two_services=True)

    def run_two_recoveries(self, *, two_services):
        def continue_twice(**values):
            prep = values['preparation']
            prepared = values['prepared']
            root = prep._history
            bundle = prepared['bundle']
            req = prepared['request']
            h = values['h']
            tls = values['tls']
            first = Profile3StepExecutor(bundle, req, intent_authority=values['authority'], phase_guard=values['guard'],
                gate_root=self.root/'generation-one', gate_key=b'g'*32, gate_policy=values['gate_policy'],
                consumption_receipt_hash=values['receipt'], witness_client_factory=h.factory, registered_binding=values['binding'],
                tls_server_context=tls[0], tls_client_context=tls[1], server_certificate_sha256=tls[2],
                docker_socket=values['socket_path'], timeout=3,
                startup_fence=Profile3RecoveryFenceV3(preparation=prep, context_reference=prepared['recovery_context_reference'],
                    reviewed_history=prepared['reviewed_history'], quiesce_writer=lambda: True))
            context = values['context']
            first.execute(context['nextOperation'], phase_index=1, receipts=context['receiptMap'],
                          completed_operations=context['completedOperations'])
            parent = AuthenticatedHistoryV3(bundle, req, gate_policy=values['gate_policy'], gate_key=b'g'*32,
                consumption_receipt_hash=values['receipt'], witness_client=h.factory(values['binding']),
                witness_client_factory=h.factory, parent_history=root,
                reviewed_parent_snapshot=prepared['reviewed_history'], ancestry_profile=ANCESTRY_PROFILE)
            self.assertEqual(len(parent.capture().snapshot['knownPrefix']), 2)
            following = RecoveryPreparationHostV3(original_history=parent, store=values['store'],
                phase_guard=values['guard'], readiness=values['readiness'], ancestry_profile=ANCESTRY_PROFILE)
            next_prepared = following.prepare_intent(operation_nonce='d'*64, expires_at=expiry())
            next_request = next_prepared['request']
            approval = approvals.ComposeApprovalTests()
            approval.setUp()
            approval.req = next_request
            approval.policy = approvals.policy(operation='recovery', expected_history_hash=next_prepared['reviewed_history'].digest,
                bundle_hash=bundle.digest, host_id=next_request.host_id, daemon_id=next_request.daemon_id,
                components=next_request.components, protected_components=next_request.protected_components,
                target=next_request.target, deployment_environment=next_request.environment, policy_hash=next_request.policy_hash)
            approval.claims = dict(claims(approval.policy), aud=approval_host.AUDIENCE)
            approval.client = approval.client_for([next_request])
            authority = approval.approval()
            receipt = authority.consume(authority.validate(next_request), next_request)
            receipt_hash = hashlib.sha256(str(receipt).encode()).hexdigest()
            next_context = following.verify_context(next_prepared['recovery_context_reference'], next_request, next_prepared['reviewed_history'])
            self.assertEqual(next_context['startWriteIndex'], 2)
            descriptor = Profile3StepExecutor.scope_descriptor(bundle, next_request, receipt_hash,
                next_context['nextOperation'], 2, next_context['receiptMap'])
            binding = dict(values['binding'], generation=descriptor['generation'], scopeHash=descriptor['scopeHash'])
            policy = replace(values['gate_policy'], witness_scope_hash=descriptor['scopeHash'])
            second = Profile3StepExecutor(bundle, next_request, intent_authority=authority, phase_guard=values['guard'],
                gate_root=self.root/'generation-two', gate_key=b'g'*32, gate_policy=policy,
                consumption_receipt_hash=receipt_hash, witness_client_factory=h.factory, registered_binding=binding,
                tls_server_context=tls[0], tls_client_context=tls[1], server_certificate_sha256=tls[2],
                docker_socket=values['socket_path'], timeout=3,
                startup_fence=Profile3RecoveryFenceV3(preparation=following, context_reference=next_prepared['recovery_context_reference'],
                    reviewed_history=next_prepared['reviewed_history'], quiesce_writer=lambda: True))
            coordinator = ComposeCoordinatorV3(second, verify_candidates=lambda _: True, readiness=values['readiness'])
            result = coordinator.run()
            child = AuthenticatedHistoryV3(bundle, next_request, gate_policy=policy, gate_key=b'g'*32,
                consumption_receipt_hash=receipt_hash, witness_client=h.factory(binding), witness_client_factory=h.factory,
                parent_history=parent, reviewed_parent_snapshot=next_prepared['reviewed_history'], ancestry_profile=ANCESTRY_PROFILE)
            snapshot = child.capture().snapshot
            self.assertEqual(len(snapshot['segments']), 3)
            self.assertEqual(len(snapshot['scopes']), 10 if two_services else 5)
            self.assertEqual(result['initialWriteCount'], 2)
            return result, snapshot
        self.run_recovery(1, two_services=two_services, ancestry_profile=ANCESTRY_PROFILE, expected_initial_write_count=2,
                          continuation_runner=continue_twice)
