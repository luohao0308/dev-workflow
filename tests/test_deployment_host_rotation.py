"""Execute healthy-source rotation, exact crash resume and monotonic retirement."""
from dataclasses import replace, asdict
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import os
import subprocess
import sys
import unittest
from unittest import mock
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import deployment_host_rotation as rotation
from tests import test_deployment_recover as recovery_fixtures



def wire_host(host):
    c = host.config
    return dict(runtime=asdict(c.runtime_policy), store=asdict(c.store_policy), gate=asdict(c.gate_policy),
                execution=asdict(c.execution_policy), candidate=str(c.candidate_root),
                storeRoot=str(c.store_root), gateRoot=str(c.gate_root),
                storeKey=host.store_key.hex(), gateKey=host.gate_key.hex())


def decode_host(value):
    runtime = dict(value['runtime']); runtime['components'] = tuple(runtime['components'])
    runtime = rotation.store.runtime.RuntimePolicy(**runtime)
    sp = dict(value['store']); sp['runtime_policy'] = runtime
    ep = dict(value['execution']); ep['runtime_policy'] = runtime
    return rotation.maintenance.MaintenanceHost(SimpleNamespace(runtime_policy=runtime,
        store_policy=rotation.store.StorePolicy(**sp), gate_policy=rotation.gateway.GatePolicy(**value['gate']),
        execution_policy=rotation.recovery.engine.ExecutionPolicy(**ep), candidate_root=Path(value['candidate']),
        store_root=Path(value['storeRoot']), gate_root=Path(value['gateRoot'])),
        bytes.fromhex(value['storeKey']), bytes.fromhex(value['gateKey']))


CRASH_CHILD = r"""
import json, os, sys
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack
from tests.test_deployment_host_rotation import rotation, decode_host
v = json.loads(Path(sys.argv[1]).read_text())
source, destination = decode_host(v['source']), decode_host(v['destination'])
phase = sys.argv[2]
write, signed = rotation.maintenance._write_new, rotation._write_signed
initialize, transition, retire = rotation.state._initialize_pending, rotation.state._transition, rotation._retire
state_write = rotation.state._write

def stop():
    os._exit(73)

def write_hook(root, name, raw):
    result = write(root, name, raw)
    if phase == 'import-record' and root == destination.config.store_root and name.startswith('history-'):
        stop()
    return result

def signed_hook(host, name, value):
    result = signed(host, name, value)
    if (phase == 'intent' and name == rotation.INTENT) or (phase == 'prepared' and name == rotation.PREPARED):
        stop()
    return result

def initialize_hook(root, policy, key, kind, transaction):
    result = initialize(root, policy, key, kind, transaction)
    if phase == 'pending-' + kind:
        stop()
    return result

def retire_hook(binding, transaction):
    result = retire(binding, transaction)
    if phase == binding.kind + '-retired':
        stop()
    return result

def transition_hook(binding, transaction, state):
    result = transition(binding, transaction, state)
    if phase == 'active-' + binding.kind and state == 'active':
        stop()
    return result

def state_write_hook(root, name, raw):
    if phase == 'gate-latch' and root == source.config.gate_root and name == 'maintenance.json':
        stop()
    return state_write(root, name, raw)

with ExitStack() as patches:
    for owner, name, hook in ((rotation.maintenance, '_write_new', write_hook),
        (rotation, '_write_signed', signed_hook), (rotation.state, '_initialize_pending', initialize_hook),
        (rotation, '_retire', retire_hook), (rotation.state, '_transition', transition_hook),
        (rotation.state, '_write', state_write_hook)):
        patches.enter_context(patch.object(owner, name, hook))
    rotation.rotate(source, destination)
raise AssertionError('Crash injection did not run')
"""

class RotationTests(unittest.TestCase):
    def setUp(self):
        self.f = recovery_fixtures.RecoveryTests(methodName='runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.begin('after')
        self.f.c.recover(self.f.request(), recovery_fixtures.Approval())
        self.parent = self.f.store.root.parent
        c = SimpleNamespace(candidate_root=self.f.root, runtime_policy=self.f.f.collector.policy,
            store_policy=self.f.store.policy, gate_policy=self.f.gate.policy, execution_policy=self.f.f.policy,
            store_root=self.f.store.root, gate_root=self.f.gate.root)
        self.source = rotation.maintenance.MaintenanceHost(c, b'k'*32, b'k'*32)
        self.destination = self.successor(self.source, 'b', b'b'*32, b'c'*32)

    def successor(self, source, name, skey, gkey):
        c = source.config
        policy = replace(c.store_policy, store_id='host-'+name, key_id='key-'+name)
        gate = replace(c.gate_policy, store_id=policy.store_id, key_id=policy.key_id)
        execution = replace(c.execution_policy, history_policy_hash=policy.identity_hash(), gateway_policy_hash=gate.identity_hash())
        return rotation.maintenance.MaintenanceHost(SimpleNamespace(candidate_root=c.candidate_root,
            runtime_policy=c.runtime_policy, store_policy=policy, gate_policy=gate, execution_policy=execution,
            store_root=self.parent / ('store-'+name), gate_root=self.parent / ('gate-'+name)), skey, gkey)

    def test_rotation_preserves_history_retires_old_objects_and_reloads(self):
        original = rotation.maintenance.backup(self.source)
        result = rotation.rotate(self.source, self.destination)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(rotation.rotation_status(self.source, self.destination)['status'], 'complete')
        self.assertEqual(rotation.rotation_resume(self.source, self.destination)['status'], 'complete')
        with self.assertRaises(ValueError):
            self.f.store.capture_history(self.f.f.collector, self.f.f.collector.collect())
        with self.assertRaises(ValueError):
            self.f.gate.info()
        new = rotation.store.HostStore(self.destination.config.store_policy, self.destination.config.store_root,
                                       key=self.destination.store_key)
        before = self.f.f.collector.collect()
        records = rotation.archive.verify_archive(original, self.source.config.store_policy, self.source.store_key).records
        for record in records:
            history = new.load_history(record.reference, collector=self.f.f.collector, before=before)
            self.assertEqual(history.to_dict(), rotation.maintenance._plain(record.record)['observation'])
        gate = rotation.gateway.FileWriterGate(self.destination.config.gate_policy,
            self.destination.config.gate_root, key=self.destination.gate_key)
        self.assertTrue(gate.info())

    def test_resume_after_gate_retirement_and_never_reactivate_old_successor(self):
        old = rotation._retire
        def interrupted(binding, transaction):
            value = old(binding, transaction)
            if binding.kind == 'gate':
                raise RuntimeError('synthetic-crash-after-gate-fence')
            return value
        with mock.patch.object(rotation, '_retire', interrupted), self.assertRaises(RuntimeError):
            rotation.rotate(self.source, self.destination)
        with self.assertRaises(ValueError):
            rotation.store.HostStore(self.destination.config.store_policy, self.destination.config.store_root,
                                     key=self.destination.store_key)
        self.assertEqual(rotation.rotation_resume(self.source, self.destination)['status'], 'complete')
        successor = self.successor(self.destination, 'c', b'd'*32, b'e'*32)
        rotation.rotate(self.destination, successor)
        self.assertEqual(rotation.rotation_resume(self.source, self.destination)['status'], 'complete-successor-retired')
        with self.assertRaises(ValueError):
            rotation.gateway.FileWriterGate(self.destination.config.gate_policy,
                self.destination.config.gate_root, key=self.destination.gate_key)

    def test_source_drift_after_gate_fence_blocks_without_discarding_history(self):
        old = rotation._retire
        def interrupted(binding, transaction):
            result = old(binding, transaction)
            if binding.kind == 'gate':
                raise RuntimeError('injected')
            return result
        with mock.patch.object(rotation, '_retire', interrupted), self.assertRaises(RuntimeError):
            rotation.rotate(self.source, self.destination)
        ref = self.f.store.capture_history(self.f.f.collector, self.f.f.collector.collect())
        with self.assertRaisesRegex(ValueError, 'inventory-drift'):
            rotation.rotation_resume(self.source, self.destination)
        self.assertTrue((self.source.config.store_root / ref).exists())

    def test_tampered_intent_and_reused_key_rejected(self):
        with self.assertRaises(ValueError):
            rotation.rotate(self.source, replace(self.destination, gate_key=self.source.gate_key))
        rotation.prepare_rotation(self.source, self.destination)
        path = self.source.config.store_root / rotation.INTENT
        path.write_bytes(path.read_bytes().replace(b'nonce', b'wrong'))
        with self.assertRaises(ValueError):
            rotation.rotation_resume(self.source, self.destination)
        self.assertFalse(self.destination.config.store_root.exists())

    def test_real_process_crash_after_every_durable_phase_and_bounded_multihop(self):
        source = self.source
        original_size = None
        origin = None
        for index, phase in enumerate(('gate-latch', 'intent', 'pending-store', 'pending-gate',
                'import-record', 'prepared', 'gate-retired', 'store-retired', 'active-store', 'active-gate')):
            with self.subTest(phase=phase):
                destination = self.successor(source, 'crash-' + str(index),
                    hashlib.sha256(('store-' + str(index)).encode()).digest(),
                    hashlib.sha256(('gate-' + str(index)).encode()).digest())
                config = self.parent / ('crash-' + str(index) + '.json')
                config.write_text(json.dumps(dict(source=wire_host(source), destination=wire_host(destination))))
                config.chmod(0o600)
                result = subprocess.run([sys.executable, '-B', '-c', CRASH_CHILD, str(config), phase],
                                        capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 73, result.stderr.decode())
                resumed = rotation.rotation_resume(source, destination)
                self.assertEqual(resumed['status'], 'complete')
                backend = rotation.store.HostStore(destination.config.store_policy, destination.config.store_root,
                                                    key=destination.store_key)
                ref = next(destination.config.store_root.glob('history-*.json'))
                record = backend._read(ref.name)
                if origin is None:
                    origin = record['provenance']['original']
                    original_size = ref.stat().st_size
                self.assertEqual(record['provenance']['original'], origin)
                self.assertLessEqual(ref.stat().st_size, original_size + 128)
                backend.load_history(ref.name, collector=self.f.f.collector, before=self.f.f.collector.collect())
                source = destination

    def test_pending_and_unknown_gate_writes_block_before_intent(self):
        path = '/v1.45/containers/' + '5'*64 + '/start'
        session = self.f.gate.open_generation(generation='7'*64, request_hash='8'*64, receipt_hash='9'*64,
                                             operations=(('POST', path, hashlib.sha256(b'').hexdigest()),))
        attempt = session.prepare_attempt('POST', path, b'')
        ticket = self.f.gate.admit(session.generation, attempt.ref, method='POST', path=path, body=b'',
                                  writer_certificate_sha256=self.f.gate.policy.writer_certificate_sha256)
        with self.assertRaisesRegex(ValueError, 'writer-not-drained'):
            rotation.rotate(self.source, self.destination)
        self.assertFalse((self.source.config.store_root / rotation.INTENT).exists())
        self.f.gate.finish(ticket, definitive=False, response_hash=None)
        with self.assertRaises(ValueError):
            self.f.gate.close_generation(session.generation)
        with self.assertRaisesRegex(ValueError, 'writer-not-drained'):
            rotation.rotate(self.source, self.destination)
        self.assertFalse(self.destination.config.store_root.exists())

    def test_existing_destination_and_core_owner_block(self):
        self.destination.config.store_root.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'destination-exists'):
            rotation.rotate(self.source, self.destination)
        self.destination.config.store_root.rmdir()
        from workflow_lock import LifecycleLock
        with LifecycleLock(self.f.root, 'deployment-execution', transaction='6'*64):
            with self.assertRaisesRegex(ValueError, 'core-operation-unresolved'):
                rotation.rotate(self.source, self.destination)
        self.assertFalse((self.source.config.store_root / rotation.INTENT).exists())

    @unittest.skipIf(os.name == 'nt', 'CLI cannot prove Windows private ACL; SDK rotation is tested on Windows')
    def test_real_cli_rotate_status_and_resume_use_same_typed_host(self):
        root = Path(__file__).resolve().parents[1]
        template = json.loads((root / 'examples/deployment-host/host.example.json').read_text())
        paths = []
        for index, host in enumerate((self.source, self.destination)):
            value = json.loads(json.dumps(template)); c = host.config
            value.update(runtime=asdict(c.runtime_policy),
                         execution={k: v for k, v in asdict(c.execution_policy).items() if k != 'runtime_policy'},
                         store={k: v for k, v in asdict(c.store_policy).items() if k != 'runtime_policy'},
                         gate=asdict(c.gate_policy), probe=None,
                         candidate_root=str(c.candidate_root), store_root=str(c.store_root), gate_root=str(c.gate_root))
            for name in ('ca_file', 'reader_cert_file', 'reader_key_file', 'writer_cert_file', 'writer_key_file'):
                value[name] = str(self.parent / (str(index) + '-' + name))
            for field, key in (('store_key_file', host.store_key), ('gate_key_file', host.gate_key)):
                keyfile = self.parent / (str(index) + '-' + field)
                keyfile.write_bytes(key); keyfile.chmod(0o600); value[field] = str(keyfile)
            value['github']['credential_file'] = str(self.parent / ('token-' + str(index)))
            path = self.parent / ('cli-' + str(index) + '.json')
            path.write_text(json.dumps(value)); path.chmod(0o600); paths.append(path)
        for command in ('rotate', 'rotation-status', 'rotation-resume'):
            process = subprocess.run([sys.executable, '-I', '-B', str(root / 'scripts/deployment_host_maintenance.py'),
                command, '--config', str(paths[0]), '--destination-config', str(paths[1])],
                capture_output=True, text=True, timeout=90)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertEqual(json.loads(process.stdout)['status'], 'complete')

    def test_unresolved_or_unknown_source_refused(self):
        # A signed terminal journal is required, not merely stable containers.
        journal = sorted(self.source.config.store_root.glob('journal-*'))[-1]
        journal.unlink()
        with self.assertRaisesRegex(ValueError, 'unresolved-journal'):
            rotation.rotate(self.source, self.destination)
        self.assertFalse(self.destination.config.store_root.exists())


if __name__ == '__main__':
    unittest.main()
