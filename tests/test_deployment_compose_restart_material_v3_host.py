"""Closed-history reauthentication across exited producer and fresh consumer."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'packs/deployment/scripts', 'packs/release/scripts'))]
from tests.support.compose_restart_material_fixture import RestartFixture, ARCHIVE_DIGEST, GATE_KEY
import deployment_compose_restart_material_v3_host as restart
from deployment_compose_witness_store import canonical, ZERO


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class RestartMaterialTests(unittest.TestCase):
    def setUp(self):
        self.f = RestartFixture()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.close_create()
        self.raw = self.f.material()
        self.expected = self.f.expected_context()

    def reopen(self, raw=None, **changes):
        raw = self.raw if raw is None else raw
        options = dict(expected_digest=hashlib.sha256(raw).hexdigest(),
            expected_context=self.expected, gate_key=GATE_KEY,
            witness_public_key=self.f.public, witness_transport=self.f.transport)
        options.update(changes)
        return restart.reopen_material(raw, **options)

    def test_expired_original_request_is_readonly_input_not_renewed(self):
        before = (self.f.store.root / 'state.json').read_bytes()
        with patch.object(self.f.store, 'register_once', side_effect=AssertionError('register')), \
             patch.object(self.f.store, 'append_event', side_effect=AssertionError('append')), \
             patch.object(self.f.store, 'transition_successor', side_effect=AssertionError('transition')):
            context = self.reopen()
        self.assertEqual(context.history._request.expires_at, '2020-01-01T00:00:00Z')
        self.assertEqual(context.snapshot.digest, self.expected['historyDigest'])
        self.assertEqual(context.baseline_bytes, self.f.baseline_bytes)
        self.assertEqual(before, (self.f.store.root / 'state.json').read_bytes())
        summary = context.public_summary()
        self.assertTrue(summary['historyAuthenticated'])
        self.assertEqual(summary['completedWriteCount'], 1)
        for name in ('phaseFreshnessVerified', 'linuxQuiescenceVerified', 'authorityGranted',
                     'executionAvailable', 'runtimePermit', 'recoveryAuthorized', 'productionReady'):
            self.assertIs(getattr(context, name), False)
            self.assertIs(summary[name], False)
        self.assertNotIn('Env', repr(context))
        self.assertNotIn('baseline_bytes', repr(context))
        self.assertNotIn('receiptMap', json.dumps(summary))
        with self.assertRaises(FrozenInstanceError):
            context.runtimePermit = True

    def test_external_material_pin_and_all_context_pins_required(self):
        with self.assertRaises(ValueError):
            self.reopen(expected_digest='0' * 64)
        for name in self.expected:
            wrong = dict(self.expected, **{name: '9' * (40 if name == 'sourceSha' else 64)})
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.reopen(expected_context=wrong)
        for expected in ({}, dict(self.expected, extra='x'), dict(self.expected, historyDigest=True)):
            with self.assertRaises(ValueError):
                self.reopen(expected_context=expected)

    def test_rehashed_material_still_requires_original_bundle_defaults_and_baseline(self):
        original = json.loads(self.raw)
        variants = []
        value = deepcopy(original)
        value['authenticatedImageDefaults']['web']['User'] = 'different'
        variants.append(value)
        value = deepcopy(original)
        value['bundle']['operations'][0]['expectedStatus'] = 200
        variants.append(value)
        value = deepcopy(original)
        next(iter(value['baseline'].values()))['Config']['Env'].append('FORGED=1')
        variants.append(value)
        value = deepcopy(original)
        value['snapshot']['receiptMap']['web'] = 'c' * 64
        variants.append(value)
        value = deepcopy(original)
        value['request']['policy_hash'] = '9' * 64
        variants.append(value)
        value = deepcopy(original)
        value['gatePolicy']['key_id'] = 'other'
        variants.append(value)
        for index, value in enumerate(variants):
            # Recompute the outer pin, so rejection must reach inner checks.
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.reopen(canonical(value))

    def test_closed_schema_canonical_size_and_types(self):
        original = json.loads(self.raw)
        variants = [b'', self.raw + b' ', b'{"x":1,"x":2}', b'NaN',
                    b'x' * (restart.MAX_MATERIAL + 1), canonical(dict(original, extra=True)),
                    canonical(dict(original, schemaVersion=True)), canonical(original['snapshot'])]
        for raw in variants:
            with self.subTest(length=len(raw)), self.assertRaisesRegex(ValueError, 'compose-restart-material-v3-rejected'):
                self.reopen(raw)
        with self.assertRaises(ValueError):
            restart.capture_material({}, baseline_bytes=self.f.baseline_bytes,
                authenticated_image_defaults=self.f.defaults, archive_digest=ARCHIVE_DIGEST)

    def test_wrong_gate_key_signature_and_public_key_rejected(self):
        with self.assertRaises(ValueError):
            self.reopen(gate_key=b'wrong-key' * 4)
        key = self.f.root / 'other-signing'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                       check=True, capture_output=True, timeout=10)
        with self.assertRaises(ValueError):
            self.reopen(witness_public_key=key.with_suffix('.pub').read_bytes())
        def corrupt(method, request):
            result = self.f.transport(method, request)
            result['signature'] = 'aW52YWxpZA=='
            return result
        with self.assertRaises(ValueError):
            self.reopen(witness_transport=corrupt)

    def test_unknown_and_pending_are_not_restart_material(self):
        fixture = RestartFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with self.assertRaises(ValueError):
            fixture.material()
        fixture.finish(status=0, body=b'', definitive=False)
        with self.assertRaises(ValueError):
            fixture.material()

    def test_advanced_witness_cannot_match_pinned_closed_prefix(self):
        self.f.receipts = {'web': 'a' * 64}
        self.f.index = 1
        self.f.open_scope()
        before = (self.f.store.root / 'state.json').read_bytes()
        with self.assertRaises(ValueError):
            self.reopen()
        self.assertEqual(before, (self.f.store.root / 'state.json').read_bytes())

    def test_reconstructed_clients_reject_mutations_before_transport(self):
        calls = []
        def transport(method, request):
            calls.append(method)
            return self.f.transport(method, request)
        context = self.reopen(witness_transport=transport)
        before = list(calls)
        client = context.history._client
        event = dict(binding=client.binding, sequence=1, previousHead=ZERO, kind='open', data={})
        with self.assertRaises(ValueError):
            client.append_event(expected_seq=0, expected_head=ZERO, event=event)
        child = dict(client.binding, scopeHash='8' * 64, generation='9' * 64)
        with self.assertRaises(ValueError):
            client.transition_successor(expected_seq=6,
                expected_head=json.loads(context.snapshot.canonical)['closedTail']['head'], childBinding=child)
        self.assertEqual(calls, before)
        self.assertLessEqual(set(calls), {'read', 'check', 'chain_status', 'events_after'})

    def test_defaults_are_frozen_before_history_callbacks(self):
        history = self.f.history()
        original = history.capture
        defaults = deepcopy(self.f.defaults)
        def capture():
            defaults['web']['User'] = 'changed-during-read'
            return original()
        with patch.object(history, 'capture', side_effect=capture):
            raw = restart.capture_material(history, baseline_bytes=self.f.baseline_bytes,
                authenticated_image_defaults=defaults, archive_digest=ARCHIVE_DIGEST)
        self.assertEqual(json.loads(raw)['authenticatedImageDefaults'], self.f.defaults)
        self.reopen(raw)

    def test_external_context_pin_cannot_drift_during_witness_reads(self):
        pins = dict(self.expected, sourceSha='9' * 40)
        calls = []
        def transport(method, request):
            pins.update(self.expected)
            calls.append(method)
            return self.f.transport(method, request)
        with self.assertRaises(ValueError):
            self.reopen(expected_context=pins, witness_transport=transport)
        self.assertTrue(calls)
        self.assertEqual(pins, self.expected)

    def test_witness_hmac_tampering_is_not_repaired(self):
        path = self.f.store.root / 'state.json'
        original = path.read_bytes()
        path.write_bytes(original.replace(b'"hmac":"', b'"hmac":"0', 1))
        tampered = path.read_bytes()
        with self.assertRaises(ValueError):
            self.reopen()
        self.assertEqual(path.read_bytes(), tampered)

    def test_producer_exits_before_fresh_consumer_reauthenticates_and_checks_capsule(self):
        with tempfile.TemporaryDirectory(prefix='dw-restart-process-') as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            script = ROOT / 'tests/support/compose_restart_material_fixture.py'
            producer = subprocess.run([sys.executable, str(script), 'produce', str(root)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(producer.returncode, 0, producer.stderr)
            produced = json.loads(producer.stdout)
            before = (root / 'witness/state.json').read_bytes()
            # subprocess.run already waited for producer exit; no live object or
            # inherited producer process is available to this consumer.
            consumer = subprocess.run([sys.executable, str(script), 'consume', str(root)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(consumer.returncode, 0, consumer.stderr)
            result = json.loads(consumer.stdout)
            self.assertEqual(result['producerPid'], produced['producerPid'])
            self.assertNotEqual(result['producerPid'], result['consumerPid'])
            self.assertNotEqual(result['consumerPid'], os.getpid())
            self.assertTrue(result['witnessUnchanged'])
            self.assertTrue(result['capsuleConsistencyVerified'])
            self.assertEqual(result['newApprovalConsumptions'], 0)
            self.assertEqual(result['engineRequests'], 0)
            self.assertFalse(result['executionRecovered'])
            self.assertEqual(before, (root / 'witness/state.json').read_bytes())


if __name__ == '__main__':
    unittest.main()
