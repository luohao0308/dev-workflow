"""Cold schema-3 ancestry with real signatures and an independent witness double.

Engine observations and the copied witness storage are explicit test doubles.
Process exit/SIGKILL covers only the checkpoint publisher, not a live coordinator.
"""
from copy import deepcopy
from dataclasses import replace
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from tests import test_deployment_compose_bounded_recovery_v3_host as ancestry
from tests.test_deployment_compose_recovery_prepare_v3_host import expiry
from deployment_compose_history_v3_host import ANCESTRY_PROFILE
from deployment_compose_phase_guard_v3_host import PhaseGuardV3
from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
from deployment_compose_restart_material_v3_host import _context
from deployment_compose_witness_store import canonical
import deployment_compose_bounded_restart_material_v3_host as material
import deployment_compose_batch_restart_material_v3_host as root_batch
import deployment_compose_restart_material_v3_host as legacy


MODULE = 'tests.test_deployment_compose_bounded_restart_material_v3_host'


def lineage_fixture(case):
    helper = ancestry.BoundedHistoryTests('test_three_generations_preserve_full_scopes_and_logical_prefix')
    helper.setUp()
    case.addCleanup(helper.doCleanups)
    first = helper.successor(helper.parent, 2)
    f = helper.f
    operation = f.writes[1]
    row = deepcopy(f.baseline['7'*64])
    row.update(Id='b'*64, Name='/dwc-'+'f'*24+'-api', Image=operation['body']['Image'])
    row['Config'] = {k:deepcopy(v) for k,v in operation['body'].items() if k not in ('HostConfig','NetworkingConfig')}
    row['HostConfig'] = deepcopy(operation['body']['HostConfig'])
    row['State'].update(Pid=0, StartedAt='', Running=False, Status='created')
    f.rows['b'*64] = row
    leaf = helper.successor(first, 3)
    f.rows['7'*64]['State'].update(Pid=0, Running=False, Status='exited')
    return helper, f, leaf


def maps(f, history):
    baselines, defaults = {}, {}
    current = history
    while current is not None:
        bundle = current._bundle
        baselines[bundle.digest] = f.archive_store.get(bundle.to_dict()['baselineStateReference'])
        defaults[bundle.digest] = deepcopy(f.defaults)
        current = current._parent
    return baselines, defaults


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class BoundedRestartMaterialTests(unittest.TestCase):
    def setUp(self):
        self.helper, self.f, self.history = lineage_fixture(self)
        self.baselines, self.defaults = maps(self.f, self.history)
        self.raw = self.capture()
        self.pins = _context(self.history, self.history.capture(), '9'*64)

    def capture(self, **changes):
        args = dict(baseline_bytes_by_bundle=self.baselines,
                    authenticated_image_defaults_by_bundle=self.defaults, archive_digest='9'*64)
        args.update(changes)
        return material.capture_material(self.history, **args)

    def reopen(self, raw=None, **changes):
        raw = self.raw if raw is None else raw
        args = dict(expected_digest=hashlib.sha256(raw).hexdigest(), expected_context=self.pins,
                    gate_key=b'g'*32, witness_public_key=self.f.public, witness_transport=self.f.transport)
        args.update(changes)
        return material.reopen_material(raw, **args)

    def test_three_generation_two_service_reopen_prepares_fresh_intent(self):
        before = (self.f.store.root/'state.json').read_bytes()
        context = self.reopen()
        self.assertEqual(len(context.snapshot.snapshot['segments']), 3)
        self.assertEqual(context.public_summary()['completedWriteCount'], 3)
        self.assertEqual(context.baseline_bytes, self.baselines[self.history._bundle.digest])
        guard = PhaseGuardV3(self.f.bundle, self.f.baseline, read_json=self.f.read, daemon_version=self.f.version)
        prep = RecoveryPreparationHostV3(original_history=context.history, store=self.f.archive_store,
            phase_guard=guard, readiness=lambda *_: True, ancestry_profile=ANCESTRY_PROFILE)
        prepared = prep.prepare_intent(operation_nonce='6'*64, expires_at=expiry())
        self.assertEqual(prepared['request'].history_hash, context.snapshot.digest)
        self.assertNotEqual(prepared['request'].digest(), context.history._request.digest())
        self.assertFalse(prepared['review']['executionAvailable'])
        self.assertEqual(before, (self.f.store.root/'state.json').read_bytes())
        for name in ('runtimePermit', 'authorityGranted', 'recoveryAuthorized', 'executionAvailable', 'productionReady'):
            self.assertIs(context.public_summary()[name], False)

    def test_rollback_prefix_reopens_with_both_bundle_baselines(self):
        f, history, guard = self.helper.rollback_prefix()
        baselines, defaults = maps(f, history)
        self.assertEqual(len(baselines), 2)
        raw = material.capture_material(history, baseline_bytes_by_bundle=baselines,
            authenticated_image_defaults_by_bundle=defaults, archive_digest='9'*64)
        context = material.reopen_material(raw, expected_digest=hashlib.sha256(raw).hexdigest(),
            expected_context=_context(history, history.capture(), '9'*64), gate_key=b'g'*32,
            witness_public_key=f.public, witness_transport=f.transport)
        self.assertEqual(context.baseline_bytes, baselines[history._bundle.digest])
        self.assertEqual(len(context.snapshot.snapshot['scopes']), 11)
        self.assertEqual(context.public_summary()['completedWriteCount'], 1)
        prep = RecoveryPreparationHostV3(original_history=context.history, store=f.archive_store,
            phase_guard=guard, readiness=lambda *_: True, ancestry_profile=ANCESTRY_PROFILE)
        prepared = prep.prepare_intent(operation_nonce='7'*64, expires_at=expiry())
        self.assertEqual(prepared['bundle'].digest, history._bundle.digest)
        self.assertEqual(prepared['review']['startWriteIndex'], 1)

    def test_first_binding_matches_its_segment_not_another_known_ancestor_scope(self):
        f, history, _ = self.helper.rollback_prefix()
        baselines, defaults = maps(f, history)
        snapshot = history.capture()
        raw = material.capture_material(history, baseline_bytes_by_bundle=baselines,
            authenticated_image_defaults_by_bundle=defaults, archive_digest='9'*64)
        wrong_binding = deepcopy(dict(snapshot.snapshot['scopes'][1]['binding']))
        value = json.loads(raw)
        value['nodes'][0]['firstBinding'] = wrong_binding
        changed = canonical(value)
        with self.assertRaises(ValueError):
            material.reopen_material(changed, expected_digest=hashlib.sha256(changed).hexdigest(),
                expected_context=_context(history, snapshot, '9'*64), gate_key=b'g'*32,
                witness_public_key=f.public, witness_transport=f.transport)
        with patch.object(history._parent, '_client', f.factory(wrong_binding)):
            with self.assertRaises(ValueError):
                material.capture_material(history, baseline_bytes_by_bundle=baselines,
                    authenticated_image_defaults_by_bundle=defaults, archive_digest='9'*64)

    def test_original_baseline_cas_remains_required(self):
        from deployment_compose_recovery_store import ComposeRecoveryStore
        context = self.reopen()
        guard = PhaseGuardV3(self.f.bundle, self.f.baseline, read_json=self.f.read, daemon_version=self.f.version)
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name).resolve()
            directory.chmod(0o700)
            empty = ComposeRecoveryStore(str(directory), key=b'new-independent-key'*2)
            try:
                with self.assertRaises(ValueError):
                    RecoveryPreparationHostV3(original_history=context.history, store=empty,
                        phase_guard=guard, readiness=lambda *_: True, ancestry_profile=ANCESTRY_PROFILE)
            finally:
                empty.close()

    def test_truncated_reordered_forged_nodes_and_metadata_rejected(self):
        original = json.loads(self.raw)
        variants = []
        for field in ('consumptionReceiptHash', 'firstBinding', 'reviewedParent'):
            value = deepcopy(original)
            if field == 'consumptionReceiptHash':
                value['nodes'][1][field] = 'c'*64
            elif field == 'firstBinding':
                value['nodes'][1][field] = deepcopy(value['nodes'][0][field])
            else:
                value['nodes'][1][field]['receiptMap']['web'] = 'c'*64
            variants.append(value)
        for nodes in ([], original['nodes'][:-1], list(reversed(original['nodes'])), original['nodes']+[original['nodes'][-1]]):
            value = deepcopy(original)
            value['nodes'] = nodes
            variants.append(value)
        value = deepcopy(original)
        value['nodes'][1]['extra'] = True
        variants.append(value)
        for value in variants:
            with self.subTest(keys=list(value)), self.assertRaises(ValueError):
                self.reopen(canonical(value))

    def test_keys_pins_maps_and_canonical_encoding_required(self):
        with self.assertRaises(ValueError):
            self.reopen(expected_digest='0'*64)
        with self.assertRaises(ValueError):
            self.reopen(gate_key=b'wrong-key'*4)
        other = self.f.root/'other-signing'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(other)], capture_output=True, check=True)
        with self.assertRaises(ValueError):
            self.reopen(witness_public_key=other.with_suffix('.pub').read_bytes())
        for name in self.pins:
            with self.subTest(pin=name), self.assertRaises(ValueError):
                self.reopen(expected_context=dict(self.pins, **{name:'wrong'}))
        for raw in (self.raw[:-1], self.raw+b' ', b'[]',
                    self.raw.replace(b'"schemaVersion":1', b'"schemaVersion":NaN', 1),
                    self.raw.replace(b'"kind":', b'"kind":"duplicate","kind":', 1)):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                self.reopen(raw)
        for key in ('baselinesByBundle', 'authenticatedImageDefaultsByBundle'):
            value = json.loads(self.raw)
            value[key] = {}
            with self.assertRaises(ValueError):
                self.reopen(canonical(value))
        for args in (dict(baseline_bytes_by_bundle={}), dict(authenticated_image_defaults_by_bundle={}),
                     dict(baseline_bytes_by_bundle=dict(self.baselines, unused=b'{}'))):
            with self.assertRaises(ValueError):
                self.capture(**args)
        for reader in (legacy, root_batch):
            with self.assertRaises(ValueError):
                reader.reopen_material(self.raw, expected_digest=hashlib.sha256(self.raw).hexdigest(),
                    expected_context=self.pins, gate_key=b'g'*32, witness_public_key=self.f.public,
                    witness_transport=self.f.transport)

    def test_all_reconstructed_clients_block_mutation_before_transport(self):
        transport = Mock(side_effect=self.f.transport)
        context = self.reopen(witness_transport=transport)
        transport.reset_mock()
        history = context.history
        while history is not None:
            for client in (history._client, history._factory(history._client.binding)):
                for method in ('append_event', 'transition_successor'):
                    with self.subTest(method=method), self.assertRaises(ValueError):
                        client._transport(method, {})
            history = history._parent
        transport.assert_not_called()

    def test_callback_mutations_of_pins_defaults_baselines_and_graph_reject(self):
        pins = deepcopy(self.pins)
        def mutate_pins(method, request):
            reply = self.f.transport(method, request)
            pins['historyDigest'] = '0'*64
            return reply
        with self.assertRaises(ValueError):
            self.reopen(expected_context=pins, witness_transport=mutate_pins)
        for field in ('defaults', 'baselines', 'graph'):
            defaults = deepcopy(self.defaults)
            baselines = dict(self.baselines)
            reviewed = self.history._reviewed_parent
            transport = self.history._client._transport
            def mutate(method, request):
                reply = transport(method, request)
                if field == 'defaults':
                    defaults.clear()
                elif field == 'baselines':
                    baselines.clear()
                else:
                    self.history._reviewed_parent = None
                return reply
            try:
                with patch.object(self.history._client, '_transport', mutate), self.assertRaises(ValueError):
                    self.capture(baseline_bytes_by_bundle=baselines, authenticated_image_defaults_by_bundle=defaults)
            finally:
                self.history._reviewed_parent = reviewed

    def test_complete_pending_and_mixed_gate_keys_reject_capture(self):
        f = ancestry.BatchFixture()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.close_prefix(10)
        root = f.history(witness_client=f.factory(f.first_binding), ancestry_profile=ANCESTRY_PROFILE)
        self.assertEqual(len(root.capture().snapshot['knownPrefix']), 10)
        baselines, defaults = maps(f, root)
        with self.assertRaises(ValueError):
            material.capture_material(root, baseline_bytes_by_bundle=baselines,
                authenticated_image_defaults_by_bundle=defaults, archive_digest='9'*64)
        with patch.object(self.history._parent, '_key', b'different-key'*3), self.assertRaises(ValueError):
            self.capture()
        self.f.index = 3
        self.f.open_scope()
        with self.assertRaises(ValueError):
            self.capture()

    def test_cold_consumer_after_producer_exit_and_sigkill(self):
        for crash in (False, True):
            with self.subTest(sigkill=crash), tempfile.TemporaryDirectory() as name:
                directory = Path(name).resolve()
                directory.chmod(0o700)
                command = [sys.executable, '-m', MODULE]
                if crash:
                    process = subprocess.Popen([*command,'produce-wait',str(directory)],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        with selectors.DefaultSelector() as selector:
                            selector.register(process.stdout, selectors.EVENT_READ)
                            self.assertTrue(selector.select(90), 'producer did not publish ready')
                        produced = json.loads(process.stdout.readline())
                        process.kill()
                        self.assertEqual(process.wait(timeout=10), -signal.SIGKILL)
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=10)
                        for pipe in (process.stdin, process.stdout, process.stderr):
                            pipe.close()
                else:
                    produced = json.loads(subprocess.run([*command,'produce',str(directory)],
                        capture_output=True, text=True, check=True, timeout=90).stdout)
                consumed = json.loads(subprocess.run([*command,'consume',str(directory)],
                    capture_output=True, text=True, check=True, timeout=90).stdout)
                self.assertNotEqual(produced['pid'], consumed['pid'])
                self.assertEqual(consumed['completedWriteCount'], 3)
                self.assertEqual(consumed['segments'], 3)
                self.assertTrue(consumed['witnessUnchanged'])
                self.assertFalse(consumed['runtimePermit'])


def process_fixture(action, directory):
    if action.startswith('produce'):
        owned = directory/'owned-temp'
        owned.mkdir(mode=0o700)
        tempfile.tempdir = str(owned)
        case = unittest.TestCase()
        _, f, history = lineage_fixture(case)
        try:
            baselines, defaults = maps(f, history)
            raw = material.capture_material(history, baseline_bytes_by_bundle=baselines,
                authenticated_image_defaults_by_bundle=defaults, archive_digest='9'*64)
            files = {'material.json':raw, 'pins.json':canonical(dict(expected_digest=hashlib.sha256(raw).hexdigest(),
                expected_context=_context(history, history.capture(), '9'*64))),
                'signing':f.key.read_bytes(), 'signing.pub':f.public}
            for name, value in files.items():
                path = directory/name
                path.write_bytes(value)
                path.chmod(0o600)
            shutil.copytree(f.store.root, directory/'witness')
            produced = dict(pid=os.getpid())
            if action == 'produce-wait':
                print(json.dumps(produced), flush=True)
                sys.stdin.readline()
            return produced
        finally:
            case.doCleanups()
    from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
    from deployment_compose_operation_witness_client_v3 import dispatch_request, encode, NAMESPACE
    store = OperationWitnessStoreV3(directory/'witness', key=b'h'*32)
    before = (directory/'witness/state.json').read_bytes()
    def transport(method, request):
        if method not in ('read','check','events_after','chain_status'):
            raise AssertionError('read-only transport')
        payload = dispatch_request(store, method, request)
        signed = subprocess.run(['ssh-keygen','-Y','sign','-f',str(directory/'signing'),'-n',NAMESPACE],
                                input=encode(payload), capture_output=True, check=True, timeout=10)
        return dict(payload=payload, signature=base64.b64encode(signed.stdout).decode('ascii'))
    try:
        pins = json.loads((directory/'pins.json').read_bytes())
        context = material.reopen_material((directory/'material.json').read_bytes(), **pins, gate_key=b'g'*32,
            witness_public_key=(directory/'signing.pub').read_bytes(), witness_transport=transport)
        return dict(context.public_summary(), pid=os.getpid(), segments=len(context.snapshot.snapshot['segments']),
                    witnessUnchanged=before==(directory/'witness/state.json').read_bytes())
    finally:
        store.close()


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1] in ('produce','produce-wait','consume'):
        print(json.dumps(process_fixture(sys.argv[1], Path(sys.argv[2]))), flush=True)
    else:
        unittest.main()
