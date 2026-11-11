"""Batch material with real signed Gate history and private CAS, Engine reads doubled.

No controller crash, process-kill, live approval or runtime recovery is claimed.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from tests.test_deployment_compose_gate_witness_v3 import GateFixture
from tests import test_deployment_compose_history_v3_host as signed
from tests.test_deployment_compose_prepare_v3_host import fixture
from tests.test_deployment_compose_recovery_prepare_v3_host import expiry
from deployment_compose_prepare_v3_host import ComposePreparationHostV3
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_image_defaults import ZERO_DEFAULTS
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, baseline_state_bytes
from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
from deployment_compose_restart_material_v3_host import _context
from deployment_compose_witness_store import canonical
import deployment_compose_batch_restart_material_v3_host as batch
import deployment_compose_restart_material_v3_host as legacy


class BatchFixture(GateFixture, unittest.TestCase):
    factory = signed.HistoryTests.factory
    history = signed.HistoryTests.history
    finish = signed.HistoryTests.finish

    def setUp(self):
        self.setup_gate_fixture()
        self.kw, observation = fixture()
        self.archive_store = self.kw['recovery']._store
        self.addCleanup(self.archive_store.close)
        prepared = ComposePreparationHostV3(**self.kw).prepare_intent(
            observation, observation, operation_nonce='f'*64, expires_at=expiry())
        value = prepared['bundle'].to_dict()
        for key in ('operations', 'resolverRules', 'resolverContract', 'imageDefaultsDigests'):
            value.pop(key)
        api = deepcopy(value['services'][0])
        api.update(name='api', finalName='dw-api-1', baselineContainerId='7'*64, dependsOn=['web'])
        for key in ('baselineCreateBody', 'targetCreateBody'):
            api[key]['Labels']['com.docker.compose.service'] = 'api'
        value['services'].append(api)
        value['mounts']['api'] = deepcopy(value['mounts']['web'])
        for network in value['networks'].values():
            network['aliases']['api'] = deepcopy(network['aliases']['web'])
        self.rows = deepcopy(self.kw['whole_observer']._unit_rows)
        row = deepcopy(self.rows[value['services'][0]['baselineContainerId']])
        row.update(Id='7'*64, Name='/dw-api-1')
        row['Config']['Labels']['com.docker.compose.service'] = 'api'
        self.rows['7'*64] = row
        self.baseline = deepcopy(self.rows)
        self.baseline_bytes = baseline_state_bytes(self.rows)
        value['baselineStateReference'] = self.archive_store.put(self.baseline_bytes)
        value['baselineStateDigest'] = hashlib.sha256(self.baseline_bytes).hexdigest()
        self.defaults = {name:deepcopy(ZERO_DEFAULTS) for name in ('web', 'api')}
        self.bundle = ExecutionBundleV3(value, authenticated_image_defaults=self.defaults)
        self.req = replace(prepared['request'], plan_hash=self.bundle.digest, components=('api', 'web'),
                           policy_hash=self.policy.identity_hash(), expires_at='2020-01-01T00:00:00Z')
        self.receipts = {}
        self.index = 0
        self.version = {'Version':'29.8.2', 'GitCommit':'8af9fe3'}
        self.operations = self.bundle.resolve_operations({'web':'a'*64, 'api':'b'*64})
        self.writes = [operation for operation in self.operations if operation['method'] != 'GET']
        self.open_scope()

    def open_scope(self):
        from deployment_compose_coordinator_v3_host import Profile3StepExecutor
        from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
        from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
        self.op = self.writes[self.index]
        descriptor = Profile3StepExecutor.scope_descriptor(self.bundle, self.req, self.receipt,
                                                          self.op, self.index, self.receipts)
        binding = dict(self.binding, generation=descriptor['generation'], scopeHash=descriptor['scopeHash'])
        self.policy = replace(self.policy, witness_scope_hash=descriptor['scopeHash'])
        if self.index == 0:
            directory = self.root/'batch-witness'
            directory.mkdir(mode=0o700)
            self.store = OperationWitnessStoreV3(directory, key=b'h'*32)
            self.addCleanup(self.store.close)
            self.store.register_once(binding)
            self.first_binding = binding
        else:
            view = self.client.read()
            self.client.transition_successor(expected_seq=view['seq'], expected_head=view['head'], childBinding=binding)
        self.binding = binding
        self.client = self.factory(binding)
        self.adapter = GateOperationWitnessAdapterV3(self.client)
        self.gen = descriptor['generation']
        self.request = self.req.digest()
        self.source = descriptor['source']
        self.ops = descriptor['operations']
        self.body = b'' if self.op['body'] is None else canonical(self.op['body'])
        self.current_gate = self.gate()

    def root_history(self):
        return self.history(witness_client=self.factory(self.first_binding))

    def close_prefix(self, count):
        for index in range(count):
            self.index = index
            if index:
                self.open_scope()
            operation = self.op
            service = next(s for s in self.bundle.to_dict()['services'] if s['name'] == operation['service'])
            cid = ('a' if service['name'] == 'web' else 'b')*64
            body = b''
            if operation['phase'] == 'create':
                row = deepcopy(self.baseline[service['baselineContainerId']])
                row.update(Id=cid, Name='/dwc-'+'f'*24+'-'+service['name'], Image=service['targetImageId'])
                row['Config'] = {k:deepcopy(v) for k,v in operation['body'].items() if k not in ('HostConfig','NetworkingConfig')}
                row['HostConfig'] = deepcopy(operation['body']['HostConfig'])
                row['State'].update(Pid=0, StartedAt='', Running=False, Status='created')
                self.rows[cid] = row
                self.receipts[service['name']] = cid
                body = canonical({'Id':cid})
            elif operation['phase'] == 'stop':
                self.rows[service['baselineContainerId']]['State'].update(Pid=0, Running=False, Status='exited')
            elif operation['phase'] == 'delete':
                del self.rows[service['baselineContainerId']]
            elif operation['phase'] == 'rename':
                self.rows[cid]['Name'] = '/'+service['finalName']
            elif operation['phase'] == 'start':
                self.rows[cid]['State'].update(Pid=999, StartedAt='restarted', Running=True, Status='running')
            self.finish(status=operation['expectedStatus'], body=body)

    def read(self, path):
        if path.endswith('/version'):
            return self.version
        if path.endswith('/info'):
            return {'ID':self.kw['daemon_id']}
        if '/containers/json?' in path:
            return [{'Id':cid} for cid in self.rows]
        if '/containers/' in path:
            return deepcopy(self.rows[path.split('/')[-2]])
        if '/networks/' in path:
            name, pin = next((n,p) for n,p in self.bundle.to_dict()['networks'].items() if p['id']==path.split('/')[-1])
            return dict(Id=pin['id'], Name=name, Labels={'com.docker.compose.project':'dw-test'}, Containers={cid:{} for cid in self.rows})
        if '/volumes/' in path:
            name = path.split('/')[-1]
            return dict(Name=name, Driver='local', Options=None, Mountpoint='/var/lib/docker/volumes/'+name+'/_data')
        raise AssertionError(path)


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class BatchRestartMaterialTests(unittest.TestCase):
    def fixture(self, count):
        f = BatchFixture()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.close_prefix(count)
        return f

    def material(self, f):
        return batch.capture_material(f.root_history(), baseline_bytes=f.baseline_bytes,
            authenticated_image_defaults=f.defaults, archive_digest='9'*64)

    def reopen(self, f, raw, **changes):
        history = f.root_history()
        args = dict(expected_digest=hashlib.sha256(raw).hexdigest(),
            expected_context=_context(history, history.capture(), '9'*64), gate_key=b'g'*32,
            witness_public_key=f.public, witness_transport=f.transport)
        args.update(changes)
        return batch.reopen_material(raw, **args)

    def test_every_incomplete_two_service_closed_prefix_reopens_and_prepares_fresh_intent(self):
        for count in range(1, 10):
            with self.subTest(count=count):
                f = self.fixture(count)
                raw = self.material(f)
                before = (f.store.root/'state.json').read_bytes()
                context = self.reopen(f, raw)
                self.assertEqual(context.public_summary()['completedWriteCount'], count)
                self.assertFalse(context.runtimePermit)
                self.assertEqual(before, (f.store.root/'state.json').read_bytes())
                guard = PhaseGuardV3(f.bundle, f.baseline, read_json=f.read, daemon_version=f.version)
                host = RecoveryPreparationHostV3(original_history=context.history, store=f.archive_store,
                                                phase_guard=guard, readiness=lambda *_: True)
                prepared = host.prepare_intent(operation_nonce='8'*64, expires_at=expiry())
                value = host.verify_context(prepared['recovery_context_reference'], prepared['request'], prepared['reviewed_history'])
                self.assertEqual(value['startWriteIndex'], count)
                self.assertEqual(prepared['request'].history_hash, context.snapshot.digest)
                self.assertNotEqual(prepared['request'].expires_at, f.req.expires_at)
                self.assertFalse(prepared['review']['executionAvailable'])

    def test_material_and_context_pins_and_schema_are_required(self):
        f = self.fixture(2)
        raw = self.material(f)
        with self.assertRaises(ValueError):
            self.reopen(f, raw, expected_digest='0'*64)
        for key in _context(f.root_history(), f.root_history().capture(), '9'*64):
            pins = _context(f.root_history(), f.root_history().capture(), '9'*64)
            pins[key] = 'wrong'
            with self.subTest(pin=key), self.assertRaises(ValueError):
                self.reopen(f, raw, expected_context=pins)
        for change in (dict(schemaVersion=True), dict(kind='compose-mac-restart-material-v3'), dict(extra=True)):
            value = dict(json.loads(raw), **change)
            with self.assertRaises(ValueError):
                self.reopen(f, canonical(value))
        with self.assertRaises(ValueError):
            legacy.reopen_material(raw, expected_digest=hashlib.sha256(raw).hexdigest(),
                expected_context=_context(f.root_history(), f.root_history().capture(), '9'*64),
                gate_key=b'g'*32, witness_public_key=f.public, witness_transport=f.transport)

    def test_rehashed_saved_history_and_receipts_are_rejected(self):
        f = self.fixture(2)
        original = json.loads(self.material(f))
        for field, value in (('receiptMap', {'web':'a'*64}),
                             ('receiptMap', {'web':'a'*64, 'api':'a'*64}),
                             ('receiptMap', {'web':'a'*64, 'api':'c'*64}),
                             ('closedTail', None)):
            material = deepcopy(original)
            material['snapshot'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.reopen(f, canonical(material))
        material = deepcopy(original)
        material['snapshot']['scopes'][0]['seq'] = True
        with self.assertRaises(ValueError):
            self.reopen(f, canonical(material))

    def test_complete_pending_unknown_and_failed_history_cannot_be_captured(self):
        for count, status, definitive in ((10, None, True), (1, None, True), (1, 0, False), (1, 500, True)):
            with self.subTest(count=count, status=status):
                f = self.fixture(count)
                if count == 1:
                    f.index = 1
                    f.open_scope()
                    if status is not None:
                        f.finish(status=status, body=b'', definitive=definitive)
                with self.assertRaises(ValueError):
                    self.material(f)

    def test_advance_during_capture_and_after_capture_is_rejected(self):
        f = self.fixture(1)
        raw = self.material(f)
        snapshot = f.root_history().capture()
        history = f.root_history()
        with patch.object(history, 'capture', side_effect=[snapshot, replace(snapshot, canonical=snapshot.canonical+b' ')]):
            with self.assertRaises(ValueError):
                batch.capture_material(history, baseline_bytes=f.baseline_bytes,
                    authenticated_image_defaults=f.defaults, archive_digest='9'*64)
        f.index = 1
        f.open_scope()
        with self.assertRaises(ValueError):
            self.reopen(f, raw)

    def test_invalid_bytes_duplicate_members_wrong_keys_and_readonly_transport(self):
        f = self.fixture(2)
        raw = self.material(f)
        for bad in (b'', b'[]', raw+b' ', raw.replace(b'"schemaVersion":1', b'"schemaVersion":NaN', 1),
                    raw.replace(b'"kind":', b'"kind":"duplicate","kind":', 1)):
            with self.subTest(raw=bad[:30]), self.assertRaises(ValueError):
                self.reopen(f, bad)
        with self.assertRaises(ValueError):
            self.reopen(f, raw, gate_key=b'wrong-gate-key'*3)
        other = f.root/'other-signing'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)],
                       check=True, capture_output=True)
        with self.assertRaises(ValueError):
            self.reopen(f, raw, witness_public_key=other.with_suffix('.pub').read_bytes())
        transport = Mock(side_effect=f.transport)
        context = self.reopen(f, raw, witness_transport=transport)
        transport.reset_mock()
        clients = (context.history._client, context.history._factory(context.history._client.binding))
        for client in clients:
            for method in ('append_event', 'transition_successor'):
                with self.subTest(method=method), self.assertRaises(ValueError):
                    client._transport(method, {})
        transport.assert_not_called()
        for key in ('runtimePermit', 'authorityGranted', 'executionAvailable', 'recoveryAuthorized', 'productionReady'):
            self.assertIs(context.public_summary()[key], False)

    def test_baseline_cas_missing_or_wrong_key_blocks_fresh_preparation(self):
        from deployment_compose_recovery_store import ComposeRecoveryStore
        f = self.fixture(2)
        context = self.reopen(f, self.material(f))
        guard = PhaseGuardV3(f.bundle, f.baseline, read_json=f.read, daemon_version=f.version)
        wrong = ComposeRecoveryStore(f.archive_store._root, key=b'wrong-key-'*4)
        self.addCleanup(wrong.close)
        with self.assertRaises(ValueError):
            RecoveryPreparationHostV3(original_history=context.history, store=wrong,
                                      phase_guard=guard, readiness=lambda *_: True)
        reference = f.bundle.to_dict()['baselineStateReference']
        (Path(f.archive_store._root)/reference).unlink()
        with self.assertRaises(ValueError):
            RecoveryPreparationHostV3(original_history=context.history, store=f.archive_store,
                                      phase_guard=guard, readiness=lambda *_: True)

    def test_producer_exit_then_fresh_consumer_reads_early_and_late_batch_prefixes(self):
        for count in (1, 9):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as name:
                directory = Path(name).resolve()
                directory.chmod(0o700)
                command = [sys.executable, '-m', 'tests.test_deployment_compose_batch_restart_material_v3_host']
                producer = subprocess.run([*command, 'produce', str(directory), str(count)],
                    capture_output=True, text=True, check=True, timeout=90)
                produced = json.loads(producer.stdout)
                consumer = subprocess.run([*command, 'consume', str(directory)],
                    capture_output=True, text=True, check=True, timeout=90)
                consumed = json.loads(consumer.stdout)
                self.assertNotEqual(produced['pid'], consumed['pid'])
                self.assertEqual(consumed['completedWriteCount'], count)
                self.assertTrue(consumed['witnessUnchanged'])
                self.assertFalse(consumed['runtimePermit'])


def process_fixture(action, directory, count=None):
    if action == 'produce':
        f = BatchFixture()
        f.setUp()
        try:
            f.close_prefix(count)
            history = f.root_history()
            raw = batch.capture_material(history, baseline_bytes=f.baseline_bytes,
                authenticated_image_defaults=f.defaults, archive_digest='9'*64)
            files = {'material.json':raw, 'pins.json':canonical(dict(expected_digest=hashlib.sha256(raw).hexdigest(),
                expected_context=_context(history, history.capture(), '9'*64))),
                'signing':f.key.read_bytes(), 'signing.pub':f.public}
            for name, value in files.items():
                path = directory/name
                path.write_bytes(value)
                path.chmod(0o600)
            shutil.copytree(f.store.root, directory/'witness')
            return dict(pid=os.getpid())
        finally:
            f.doCleanups()
    from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
    from deployment_compose_operation_witness_client_v3 import dispatch_request, encode, NAMESPACE
    import base64
    store = OperationWitnessStoreV3(directory/'witness', key=b'h'*32)
    before = (directory/'witness/state.json').read_bytes()
    def transport(method, request):
        if method not in ('read', 'check', 'events_after', 'chain_status'):
            raise AssertionError('read-only transport')
        payload = dispatch_request(store, method, request)
        signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(directory/'signing'), '-n', NAMESPACE],
                                input=encode(payload), capture_output=True, check=True, timeout=10)
        return dict(payload=payload, signature=base64.b64encode(signed.stdout).decode('ascii'))
    try:
        pins = json.loads((directory/'pins.json').read_bytes())
        context = batch.reopen_material((directory/'material.json').read_bytes(), **pins,
            gate_key=b'g'*32, witness_public_key=(directory/'signing.pub').read_bytes(), witness_transport=transport)
        return dict(context.public_summary(), pid=os.getpid(),
                    witnessUnchanged=before==(directory/'witness/state.json').read_bytes())
    finally:
        store.close()


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1] in ('produce', 'consume'):
        print(json.dumps(process_fixture(sys.argv[1], Path(sys.argv[2]), int(sys.argv[3]) if len(sys.argv)>3 else None)))
    else:
        unittest.main()
