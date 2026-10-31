from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3, ZERO

KEY = b'v3-operation-witness-key-' + b'x' * 32
BINDING = dict(zip(('scopeHash', 'epoch', 'generation', 'policyHash'), (x * 64 for x in 'abcd')))
ATTEMPT = 'e' * 64
CHILD = dict(BINDING, scopeHash='f' * 64, generation='1' * 64)


@unittest.skipUnless(os.name == 'posix', 'POSIX witness storage')
class OperationWitnessV3Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.store = self.open()
        self.view = self.store.register_once(BINDING)
        self.nonce = 0

    def open(self):
        store = OperationWitnessStoreV3(self.root, key=KEY)
        self.addCleanup(store.close)
        return store

    def append(self, kind, data=None, **changes):
        self.nonce += 1
        event = dict(binding=BINDING, sequence=self.view['seq'] + 1, previousHead=self.view['head'], kind=kind, data=data or {})
        values = dict(expected_seq=self.view['seq'], expected_head=self.view['head'], event=event,
                      boot_nonce='9' * 64, rpc_nonce=f'{self.nonce:064x}')
        values.update(changes)
        self.view = self.store.append_event(BINDING, **values)
        return values

    def admit(self):
        self.append('open'); self.append('prepared', {'attemptRef': ATTEMPT})
        self.append('admitted', {'attemptRef': ATTEMPT})

    def close_operation(self):
        self.admit()
        self.append('response', dict(attemptRef=ATTEMPT, definitive=True, status=200, bodyBase64='YWJj'))
        self.append('completed', {'attemptRef': ATTEMPT}); self.append('closed')

    def transition(self, store=None, **changes):
        values = dict(expected_seq=self.view['seq'], expected_head=self.view['head'], childBinding=CHILD)
        values.update(changes)
        return (store or self.store).transition_successor(BINDING, **values)

    def test_full_event_reconstructs_after_reopen_and_lost_ack_is_not_reissued(self):
        request = self.append('open')
        with self.assertRaises(ValueError):
            self.open().append_event(BINDING, **request)
        records = self.open().events_after(BINDING, seq=0, head=ZERO)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['event'], request['event'])
        self.assertEqual(json.loads(records[0]['canonicalEvent']), request['event'])
        self.assertEqual(records[0]['head'], self.view['head'])
        self.assertFalse(self.view['authorityGranted'] or self.view['productionReady'])
        self.assertEqual(self.open().check(BINDING, expected_seq=1, expected_head=self.view['head']), self.view)
        with self.assertRaises(ValueError):
            self.store.events_after(BINDING, seq=1, head=ZERO)
        with self.assertRaises(ValueError): self.open().register_once(BINDING)

    def test_unknown_response_blocks_every_forward_path(self):
        self.admit()
        self.append('response', dict(attemptRef=ATTEMPT, definitive=False, status=0, bodyBase64=''))
        self.assertEqual(self.open().read(BINDING)['phase'], 'blocked')
        for kind, data in [('completed', {'attemptRef': ATTEMPT}), ('closed', {}), ('response', dict(attemptRef=ATTEMPT, definitive=True, status=200, bodyBase64=''))]:
            with self.assertRaises(ValueError): self.append(kind, data)
        with self.assertRaises(ValueError): self.transition()

    def test_successor_lineage_and_frozen_parent(self):
        self.close_operation(); closed = deepcopy(self.view)
        child = self.transition()
        self.assertEqual((child['seq'], child['head'], child['phase']), (0, ZERO, 'empty'))
        self.assertEqual(child['lineage'], [{'binding': BINDING, 'seq': closed['seq'], 'head': closed['head']}])
        self.assertFalse(self.open().check(BINDING, expected_seq=closed['seq'], expected_head=closed['head'])['active'])
        self.assertEqual(len(self.open().events_after(BINDING, seq=0, head=ZERO)), 6)
        with self.assertRaises(ValueError): self.append('open')
        with self.assertRaises(ValueError): self.transition()

    def test_chain_status_from_old_scope_is_atomic_read_only_evidence(self):
        initial = self.store.chain_status(BINDING)
        self.assertEqual((initial['activeBinding'], initial['activeSeq'], initial['activeHead']), (BINDING, 0, ZERO))
        self.close_operation(); closed = deepcopy(self.view)
        self.transition()
        before = (self.root / 'state.json').read_bytes()
        status = self.open().chain_status(BINDING)
        self.assertEqual(status, self.store.chain_status(CHILD))
        self.assertEqual(status, dict(epoch=BINDING['epoch'], policyHash=BINDING['policyHash'],
                                     activeBinding=CHILD, activeSeq=0, activeHead=ZERO, activePhase='empty',
                                     lineage=[dict(binding=BINDING, seq=6, head=closed['head'])],
                                     authorityGranted=False, productionReady=False))
        self.assertEqual((self.root / 'state.json').read_bytes(), before)
        with self.assertRaises(ValueError): self.append('open')
        with self.assertRaises(ValueError): self.store.chain_status(dict(CHILD, scopeHash='8' * 64))

    def test_successor_cas_concurrency_has_one_winner(self):
        self.close_operation(); second = self.open()
        def run(store):
            try:
                self.transition(store); return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(run, [self.store, second])), [False, True])

    def test_stale_and_cross_scope_successor_rejected(self):
        self.close_operation()
        for changes in [dict(expected_seq=5), dict(expected_head=ZERO),
                        dict(childBinding=dict(CHILD, epoch='2' * 64)), dict(childBinding=BINDING)]:
            with self.assertRaises(ValueError): self.transition(**changes)
        self.transition()

    def test_invalid_event_state_and_nonce_replay_do_not_persist(self):
        with self.assertRaises(ValueError): self.append('completed', {'attemptRef': ATTEMPT})
        self.append('open')
        for changes in [dict(rpc_nonce=f'{self.nonce:064x}'), dict(expected_seq=True),
                        dict(event=dict(binding=CHILD, sequence=2, previousHead=self.view['head'], kind='prepared', data={'attemptRef': ATTEMPT}))]:
            with self.assertRaises(ValueError): self.append('prepared', {'attemptRef': ATTEMPT}, **changes)
        self.assertEqual(self.store.read(BINDING)['seq'], 1)
        with self.assertRaises(ValueError): self.append('prepared', {'attemptRef': ATTEMPT, 'extra': 1})
        self.append('prepared', {'attemptRef': ATTEMPT})
        with self.assertRaises(ValueError): self.append('admitted', {'attemptRef': 'f' * 64})

    def test_response_bounds_and_noncanonical_base64(self):
        self.admit()
        for updates in [dict(status=True), dict(status=0), dict(status=99), dict(status=600), dict(status=-1), dict(status=999), dict(bodyBase64='YR=='), dict(bodyBase64='x' * 100000), dict(definitive=1)]:
            data = dict(attemptRef=ATTEMPT, definitive=True, status=200, bodyBase64='')
            data.update(updates)
            with self.assertRaises(ValueError): self.append('response', data)
        self.assertEqual(self.open().read(BINDING)['phase'], 'admitted')

    def test_unknown_response_status_is_zero_or_http_status(self):
        self.admit()
        for status in (True, -1, 99, 600, 999):
            with self.assertRaises(ValueError):
                self.append('response', dict(attemptRef=ATTEMPT, definitive=False, status=status, bodyBase64=''))
        self.append('response', dict(attemptRef=ATTEMPT, definitive=False, status=503, bodyBase64=''))
        self.assertEqual(self.open().read(BINDING)['phase'], 'blocked')
        with self.assertRaises(ValueError): self.append('completed', {'attemptRef': ATTEMPT})
        with self.assertRaises(ValueError): self.transition()

    def test_maximum_body_is_preserved_and_oversize_body_rejected(self):
        self.admit()
        body = base64.b64encode(b'x' * 65536).decode('ascii')
        data = dict(attemptRef=ATTEMPT, definitive=True, status=200, bodyBase64=body)
        oversized = dict(data, bodyBase64=base64.b64encode(b'x' * 65537).decode('ascii'))
        with self.assertRaises(ValueError): self.append('response', oversized)
        self.append('response', data)
        records = self.open().events_after(BINDING, seq=0, head=ZERO)
        self.assertEqual(records[-1]['event']['data'], data)

    def test_hardlinked_state_is_rejected(self):
        outside = self.root.with_name(self.root.name + '-linked')
        os.link(self.root / 'state.json', outside)
        self.addCleanup(outside.unlink)
        with self.assertRaises(ValueError): self.open().read(BINDING)

    def append_external(self, kind, material, data=None):
        event = dict(binding=BINDING, sequence=self.view['seq'] + 1,
                     previousHead=self.view['head'], kind=kind, data=data or {},
                     materialDigest=hashlib.sha256(material).hexdigest())
        return self.append(kind, data, event=event, external_material=material)

    def test_external_material_exact_recovery_after_lost_ack(self):
        material = b'\x00sealed gate event\n' + bytes(range(256))
        request = self.append_external('open', material)
        with self.assertRaises(ValueError): self.open().append_event(BINDING, **request)
        record = self.open().events_after(BINDING, seq=0, head=ZERO)[0]
        self.assertTrue(record['hasExternalMaterial'])
        self.assertEqual(base64.b64decode(record['externalMaterialBase64'], validate=True), material)
        self.assertEqual(record['event']['materialDigest'], hashlib.sha256(material).hexdigest())
        self.assertEqual(json.loads(record['canonicalEvent']), record['event'])
        self.append_external('prepared', b'', {'attemptRef': ATTEMPT})
        empty = self.open().events_after(BINDING, seq=1, head=record['head'])[0]
        self.assertTrue(empty['hasExternalMaterial'])
        self.assertEqual(empty['externalMaterialBase64'], '')

    def test_external_material_missing_extra_replaced_and_oversized_rejected(self):
        material = b'original gate event'
        event = dict(binding=BINDING, sequence=1, previousHead=ZERO, kind='open', data={},
                     materialDigest=hashlib.sha256(material).hexdigest())
        for changes in [dict(event=event), dict(external_material=material),
                        dict(event=event, external_material=b'replaced'),
                        dict(event=event, external_material=bytearray(material))]:
            with self.assertRaises(ValueError): self.append('open', **changes)
        with self.assertRaises(ValueError): self.append_external('open', b'x' * (262144 + 1))
        self.assertEqual(self.open().read(BINDING)['seq'], 0)
        self.append('open')
        record = self.open().events_after(BINDING, seq=0, head=ZERO)[0]
        self.assertFalse(record['hasExternalMaterial'])
        self.assertIsNone(record['externalMaterialBase64'])

    def test_external_material_read_validation_even_with_valid_state_mac(self):
        self.append_external('open', b'original')
        state = json.loads((self.root / 'state.json').read_bytes())['state']
        for changes in [dict(externalMaterialBase64=None), dict(hasExternalMaterial=False),
                        dict(externalMaterialBase64=base64.b64encode(b'replaced').decode('ascii')),
                        dict(externalMaterialBase64='eA==' * 100000), dict(hasExternalMaterial=1)]:
            changed = deepcopy(state)
            changed['scopes'][0]['events'][0].update(changes)
            # The test knows its own key: resealing isolates structural validation from MAC validation.
            (self.root / 'state.json').write_bytes(self.store._seal(changed))
            with self.assertRaises(ValueError): self.open().read(BINDING)
        changed = deepcopy(state)
        del changed['scopes'][0]['events'][0]['externalMaterialBase64']
        (self.root / 'state.json').write_bytes(self.store._seal(changed))
        with self.assertRaises(ValueError): self.open().read(BINDING)

    def test_external_material_total_limit_fails_without_advancing(self):
        material = b'x' * 262144
        self.append_external('open', material)
        self.append_external('prepared', material, {'attemptRef': ATTEMPT})
        self.append_external('admitted', material, {'attemptRef': ATTEMPT})
        self.append_external('response', material, dict(attemptRef=ATTEMPT, definitive=True, status=200, bodyBase64=''))
        self.append_external('completed', material, {'attemptRef': ATTEMPT})
        before = self.open().read(BINDING)
        with self.assertRaises(ValueError): self.append_external('closed', material)
        self.assertEqual(self.open().read(BINDING), before)
        self.assertEqual(len(self.open().events_after(BINDING, seq=0, head=ZERO)), 5)
        self.assertEqual(set(p.name for p in self.root.iterdir()), {'state.json', 'witness.lock'})

    def test_pending_file_and_tampered_state_fail_closed(self):
        pending = self.root / '.pending-interrupted'
        pending.write_text('unacknowledged'); pending.chmod(0o600)
        with self.assertRaises(ValueError): self.store.read(BINDING)
        pending.unlink()
        path = self.root / 'state.json'; value = json.loads(path.read_text())
        value['state']['schemaVersion'] = 1; path.write_text(json.dumps(value))
        with self.assertRaises(ValueError): self.open().read(BINDING)

    def test_symlink_state_and_root_replacement_fail_closed(self):
        state = self.root / 'state.json'; state.rename(self.root / 'saved')
        state.symlink_to(self.root / 'saved')
        with self.assertRaises(ValueError): self.store.read(BINDING)
        state.unlink(); (self.root / 'saved').rename(state)
        moved = self.root.with_name(self.root.name + '-moved')
        self.root.rename(moved)
        self.addCleanup(lambda: moved.rename(self.root))
        self.root.mkdir(mode=0o700)
        self.addCleanup(self.root.rmdir)
        with self.assertRaises(ValueError): self.store.read(BINDING)


if __name__ == '__main__':
    unittest.main()
