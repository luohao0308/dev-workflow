"""Signed Store and real Gate reconstruction, without local progress authority."""
import hashlib
import json
import os
import shutil
import unittest
from copy import deepcopy
from dataclasses import asdict, replace
from unittest.mock import patch

from tests.test_deployment_compose_gate_witness_v3 import GateFixture
from tests.test_deployment_compose_bundle_v3 import fixture
from tests.test_deployment_compose_approval_v3_host import request
from tests.test_deployment_compose_operation_witness_client_v3 import OperationWitnessStoreV3, OperationWitnessClientV3
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_coordinator_v3_host import Profile3StepExecutor, canonical
from deployment_compose_history_v3_host import AuthenticatedHistoryV3, AuthenticatedHistorySnapshotV3
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'OpenSSH required')
class HistoryTests(GateFixture, unittest.TestCase):
    def setUp(self):
        self.setup_gate_fixture()
        value, defaults = fixture()
        req = request(target=replace(request().target, namespace=value['identity']['project']))
        value['identity'].update(hostId=req.host_id, daemonId=req.daemon_id,
            project=req.target.namespace, sourceIdentity=canonical(asdict(req.source)).decode())
        self.bundle = ExecutionBundleV3(value, authenticated_image_defaults=defaults)
        self.req = replace(req, plan_hash=self.bundle.digest, components=('web',))
        self.receipts = {}; self.index = 0
        self.open_scope()

    def factory(self, binding):
        return OperationWitnessClientV3(binding, self.public, self.transport)

    def open_scope(self):
        ops = self.bundle.resolve_operations(self.receipts) if self.receipts else self.bundle.creation_operations()
        self.op = [op for op in ops if op['method'] != 'GET'][self.index]
        desc = Profile3StepExecutor.scope_descriptor(self.bundle,self.req,self.receipt,self.op,self.index,self.receipts)
        binding = dict(self.binding, generation=desc['generation'], scopeHash=desc['scopeHash'])
        self.policy = replace(self.policy,witness_scope_hash=desc['scopeHash'])
        if not hasattr(self, 'history_store_registered'):
            (self.root/'history-witness').mkdir(mode=0o700)
            self.store = OperationWitnessStoreV3(self.root/'history-witness',key=b'h'*32)
            self.addCleanup(self.store.close); self.store.register_once(binding)
            self.history_store_registered = True
        else:
            view=self.client.read()
            self.client.transition_successor(expected_seq=view['seq'],expected_head=view['head'],childBinding=binding)
        self.binding=binding; self.client=self.factory(binding)
        self.adapter=GateOperationWitnessAdapterV3(self.client)
        self.gen=desc['generation'];self.request=self.req.digest();self.source=desc['source'];self.ops=desc['operations']
        self.body=b'' if self.op['body'] is None else canonical(self.op['body'])
        self.current_gate=self.gate()

    def finish(self, status=201, body=None, definitive=True):
        ticket=self.admitted(self.current_gate)
        self.current_gate.finish_response(ticket,definitive=definitive,status=status,
            body=body if body is not None else json.dumps({'Id':'a'*64}).encode())
        if definitive:self.current_gate.close_generation(self.gen)

    def history(self, **changes):
        args=dict(gate_policy=self.policy,gate_key=b'g'*32,consumption_receipt_hash=self.receipt,
                  witness_client=self.client,witness_client_factory=self.factory)
        args.update(changes)
        return AuthenticatedHistoryV3(self.bundle,self.req,**args)

    def test_two_scopes_and_no_local_files(self):
        self.finish(); self.receipts={'web':'a'*64};self.index=1;self.open_scope()
        self.finish(status=204,body=b'')
        before=self.history().capture()
        shutil.rmtree(self.root/'gate')
        result=self.history().capture()
        self.assertEqual(before.digest,result.digest)
        self.assertEqual(len(result.snapshot['knownPrefix']),2)
        self.assertEqual(result.snapshot['receiptMap']['web'],'a'*64)
        with self.assertRaises(TypeError):result.snapshot['receiptMap']['web']='x'
        self.assertFalse(result.public_summary()['runtimePermit'])
        self.assertNotIn('bodyBase64',str(result.public_summary()))

    def test_pending_and_unknown_are_blocked(self):
        self.assertEqual(self.history().capture().snapshot['blocker'],'active-pending')
        self.finish(status=0,body=b'',definitive=False)
        result=self.history().capture().snapshot
        self.assertEqual(result['blocker'],'unknown-response')
        self.assertEqual(len(result['knownPrefix']),0)

    def test_unusable_receipt_not_registered(self):
        self.finish(body=b'{"Id":"a","Id":"b"}')
        result=self.history().capture().snapshot
        self.assertEqual(result['blocker'],'unusable-receipt')
        self.assertEqual(dict(result['receiptMap']),{})

    def test_known_http_error_blocks_normal_progress(self):
        self.finish(status=409,body=b'conflict')
        result=self.history().capture().snapshot
        self.assertEqual(result['blocker'],'known-http-failure')
        self.assertEqual(len(result['knownPrefix']),0)

    def test_unexpected_2xx_stop_is_not_a_successful_prefix(self):
        self.finish(); self.receipts={'web':'a'*64}; self.index=1; self.open_scope()
        self.finish(status=200,body=b'')
        result=self.history().capture().snapshot
        self.assertEqual(result['blocker'],'unexpected-http-status')
        self.assertEqual(len(result['knownPrefix']),1)

    def test_request_and_response_tampering_rejected(self):
        self.finish()
        altered=replace(self.req, artifact_digest='e'*64)
        history=self.history()
        history._request=altered
        with self.assertRaises(ValueError):history.capture()
        original=OperationWitnessClientV3.events_after
        def altered_material(client,**kw):
            records=original(client,**kw)
            import base64
            envelope=json.loads(base64.b64decode(records[3]['externalMaterialBase64']))
            envelope['payload']['data']['status']=204
            records[3]['externalMaterialBase64']=base64.b64encode(canonical(envelope)).decode()
            return records
        with patch.object(OperationWitnessClientV3,'events_after',altered_material):
            with self.assertRaises(ValueError):self.history().capture()

    def test_wrong_key_receipt_policy_and_material(self):
        self.finish()
        for changes in (dict(gate_key=b'z'*32),dict(consumption_receipt_hash='e'*64),
                        dict(gate_policy=replace(self.policy,key_id='other'))):
            with self.assertRaises(ValueError):self.history(**changes).capture()
        original=OperationWitnessClientV3.events_after
        def altered(client,**kw):
            records=original(client,**kw)
            records[0]['externalMaterialBase64']=None
            return records
        with patch.object(OperationWitnessClientV3,'events_after',altered):
            with self.assertRaises(ValueError):self.history().capture()

    def test_chain_advancement_during_capture_rejected(self):
        self.finish()
        original=self.client.chain_status; calls=[]
        def changing():
            status=original();calls.append(1)
            if len(calls)>1:status['activeHead']='f'*64
            return status
        with patch.object(self.client,'chain_status',changing):
            with self.assertRaises(ValueError):self.history().capture()

    def complete_deploy(self):
        self.finish()
        self.receipts = {'web': 'a'*64}
        for index in range(1, 5):
            self.index = index
            self.open_scope()
            self.finish(status=204, body=b'')
        return self.history(), self.history().capture()

    def start_child(self, reviewed):
        self.req = replace(self.req, operation='rollback', history_hash=reviewed.digest)
        self.receipts = {}; self.index = 0
        self.open_scope()

    def test_parent_prefix_and_child_segment(self):
        parent, reviewed = self.complete_deploy()
        self.assertEqual(len(reviewed.snapshot['knownPrefix']), 5)
        self.start_child(reviewed)
        self.finish(body=b'{"Id":"' + b'b'*64 + b'"}')
        self.receipts = {'web': 'b'*64}; self.index = 1; self.open_scope()
        self.finish(status=204, body=b'')
        child = self.history(parent_history=parent, reviewed_parent_snapshot=reviewed)
        result = child.capture()
        self.assertEqual(result.snapshot['schemaVersion'], 2)
        self.assertEqual(len(result.snapshot['scopes']), 2)
        self.assertEqual(len(result.snapshot['knownPrefix']), 2)
        self.assertEqual(result.snapshot['receiptMap']['web'], 'b'*64)
        self.assertEqual(result.snapshot['parent']['scopeCount'], 5)
        self.assertEqual(result.snapshot['parent']['historyDigest'], reviewed.digest)
        with self.assertRaises(ValueError): parent.capture()
        before = self.client.chain_status()
        self.assertEqual(parent.verify_prefix(reviewed, before).canonical, reviewed.canonical)
        self.assertEqual(self.client.chain_status(), before)
        altered = json.loads(reviewed.canonical)
        altered['scopes'][0]['records'][0]['externalMaterialBase64'] = ''
        with self.assertRaises(ValueError):
            parent.verify_prefix(AuthenticatedHistorySnapshotV3(canonical(altered)), before)
        with self.assertRaises(ValueError):
            self.history(parent_history=parent,
                reviewed_parent_snapshot=AuthenticatedHistorySnapshotV3(canonical(altered)))
        foreign = deepcopy(before); foreign['lineage'][0]['head'] = 'f'*64
        with self.assertRaises(ValueError): parent.verify_prefix(reviewed, foreign)

    def test_incomplete_or_stale_parent_rejected(self):
        self.finish()
        parent = self.history(); stale = parent.capture()
        self.receipts = {'web':'a'*64}; self.index = 1; self.open_scope()
        with self.assertRaises(ValueError): parent.verify_prefix(stale, self.client.chain_status())

    def test_child_requires_exact_history_hash_and_rollback(self):
        parent, reviewed = self.complete_deploy()
        for changes in (dict(operation='rollback', history_hash='f'*64),
                        dict(operation='recovery', history_hash=reviewed.digest)):
            self.req = replace(self.req, **changes)
            with self.assertRaises(ValueError):
                self.history(parent_history=parent, reviewed_parent_snapshot=reviewed)

    def recovery_from_closed_prefix(self, count):
        self.finish()
        self.receipts = {'web':'a'*64}
        for index in range(1, count):
            self.index = index; self.open_scope(); self.finish(status=204, body=b'')
        parent = self.history(); reviewed = parent.capture()
        before = self.client.chain_status()
        with self.assertRaises(ValueError): parent.verify_prefix(reviewed, before)
        self.assertEqual(parent.verify_prefix(reviewed, before, require_complete=False).digest, reviewed.digest)
        self.assertEqual(before, self.client.chain_status())
        self.req = replace(self.req, operation='recovery', history_hash=reviewed.digest,
                           observation_hash='e'*64)
        self.receipt = 'f'*64
        self.index = count; self.open_scope(); self.finish(status=204, body=b'')
        child_history = self.history(parent_history=parent, reviewed_parent_snapshot=reviewed)
        child = child_history.capture().snapshot
        self.assertEqual(child['schemaVersion'], 2)
        self.assertEqual(child['parent']['startWriteIndex'], count)
        self.assertEqual(len(child['scopes']), 1)
        self.assertEqual(len(child['knownPrefix']), count+1)
        self.assertEqual(dict(child['receiptMap']), {'web':'a'*64})
        self.assertEqual(child['knownPrefix'][:count], reviewed.snapshot['knownPrefix'])
        self.assertEqual(child['knownPrefix'][-1]['phase'], self.op['phase'])
        with self.assertRaises(ValueError): parent.capture()
        with self.assertRaises(ValueError):
            self.history(parent_history=child_history,
                         reviewed_parent_snapshot=child_history.capture())
        return parent, reviewed

    def test_recovery_after_create(self): self.recovery_from_closed_prefix(1)
    def test_recovery_after_stop(self): self.recovery_from_closed_prefix(2)
    def test_recovery_after_delete(self): self.recovery_from_closed_prefix(3)
    def test_recovery_after_rename(self): self.recovery_from_closed_prefix(4)

    def test_recovery_preserves_exact_request_and_bundle(self):
        self.finish(); parent = self.history(); reviewed = parent.capture()
        original = replace(self.req, operation='recovery', history_hash=reviewed.digest)
        for field, value in (('before_hash','e'*64), ('after_hash','e'*64),
                             ('artifact_digest','e'*64), ('policy_hash','e'*64),
                             ('environment','other-staging'),
                             ('protected_components',('changed',))):
            self.req = replace(original, **{field:value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.history(parent_history=parent, reviewed_parent_snapshot=reviewed)
        self.req = original
        value, defaults = fixture()
        value['identity'] = self.bundle.to_dict()['identity']
        value['operationNonce'] = 'e'*64
        self.bundle = ExecutionBundleV3(value, authenticated_image_defaults=defaults)
        self.req = replace(original, plan_hash=self.bundle.digest)
        with self.assertRaises(ValueError):
            self.history(parent_history=parent, reviewed_parent_snapshot=reviewed)

    def test_recovery_prefix_blocks_unknown_pending_failed(self):
        parent = self.history()
        with self.assertRaises(ValueError):
            parent.verify_prefix(parent.capture(), self.client.chain_status(), require_complete=False)
        self.finish(status=0, body=b'', definitive=False)
        with self.assertRaises(ValueError):
            parent.verify_prefix(parent.capture(), self.client.chain_status(), require_complete=False)

    def test_recovery_prefix_blocks_known_failure(self):
        self.finish(status=409, body=b'conflict')
        parent = self.history()
        with self.assertRaises(ValueError):
            parent.verify_prefix(parent.capture(), self.client.chain_status(), require_complete=False)

    def test_recovery_pending_child_uses_absolute_index(self):
        self.finish(); self.receipts = {'web':'a'*64}
        parent = self.history(); reviewed = parent.capture()
        self.req = replace(self.req, operation='recovery', history_hash=reviewed.digest)
        self.index = 1; self.open_scope()
        result = self.history(parent_history=parent, reviewed_parent_snapshot=reviewed).capture().snapshot
        self.assertEqual(result['blocker'], 'active-pending')
        self.assertEqual(len(result['knownPrefix']), 1)
        self.assertEqual(result['pending']['operation']['phase'], 'stop')
