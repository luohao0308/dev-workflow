from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from deployment_compose_witness_store import ComposeWitnessStore, ZERO

KEY = b'witness-test-key-' + b'x' * 32
BINDING = dict(zip(('scopeHash', 'epoch', 'generation', 'policyHash'), (x * 64 for x in 'abcd')))


@unittest.skipUnless(os.name == 'posix', 'POSIX independent witness')
class WitnessStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.store = self.open(); self.store.register_once(BINDING)

    def open(self, **kwargs):
        store = ComposeWitnessStore(self.root, key=kwargs.get('key', KEY))
        self.addCleanup(store.close)
        return store

    def reserve(self, store=None, **changes):
        values = dict(expected_seq=0, expected_head=ZERO, next_head='e'*64,
                      event_digest='e'*64, boot_nonce='f'*64, rpc_nonce='1'*64)
        values.update(changes)
        return (store or self.store).reserve(BINDING, **values)

    def test_reservation_durable_before_ack_and_reopen(self):
        ack = self.reserve()
        self.assertEqual(ack['seq'], 1); self.assertEqual(ack['previousHead'], ZERO)
        self.assertEqual(ack['head'], 'e'*64)
        self.assertFalse(ack['authorityGranted'] or ack['productionReady'])
        self.assertEqual(self.open().check(BINDING, expected_seq=1, expected_head='e'*64)['seq'], 1)
        with self.assertRaises(ValueError): self.reserve()  # A lost ack is not reissued.
        with self.assertRaises(ValueError): self.open().register_once(BINDING)
        self.assertNotIn(KEY.decode(), (self.root/'state.json').read_text())

    def test_two_client_cas_exactly_one_winner(self):
        other = self.open()
        def attempt(args):
            store, head, nonce = args
            try:
                self.reserve(store, next_head=head*64, event_digest=head*64, rpc_nonce=nonce*64)
                return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, [(self.store, 'e', '1'), (other, 'f', '2')]))
        self.assertEqual(sum(results), 1)
        self.assertEqual(self.store.read(BINDING)['seq'], 1)

    def test_bad_types_hashes_heads_and_nonce_reuse_reject(self):
        for changed in ({'expected_seq': True}, {'expected_seq': -1}, {'expected_head': 'x'*64},
                        {'next_head': ZERO}, {'event_digest': 'f'*64}, {'rpc_nonce': True},
                        {'boot_nonce': ''}):
            with self.subTest(changed=changed), self.assertRaises(ValueError): self.reserve(**changed)
        self.reserve()
        with self.assertRaises(ValueError):
            self.reserve(expected_seq=1, expected_head='e'*64, next_head='2'*64, event_digest='2'*64)
        self.reserve(expected_seq=1, expected_head='e'*64, next_head='2'*64, event_digest='2'*64, rpc_nonce='2'*64)
        self.assertEqual(self.store.read(BINDING)['seq'], 2)
        with self.assertRaises(ValueError):
            self.reserve(expected_seq=2, expected_head='2'*64, rpc_nonce='3'*64)

    def test_binding_scope_and_duplicate_registration_never_reset(self):
        for changed in ({}, dict(BINDING, extra='e'*64), dict(BINDING, scopeHash=True),
                        dict(BINDING, generation='f'*64)):
            with self.assertRaises(ValueError): self.store.read(changed)
        with self.assertRaises(ValueError): self.store.register_once(BINDING)
        value = self.store.read(BINDING); value['binding']['scopeHash'] = 'f'*64
        self.assertEqual(self.store.read(BINDING)['binding'], BINDING)
        with self.assertRaises(ValueError): self.store.check(BINDING, expected_seq=True, expected_head=ZERO)
        with self.assertRaises(ValueError): self.store.check(BINDING, expected_seq=1, expected_head=ZERO)

    def test_wrong_key_and_state_tamper_rejected(self):
        with self.assertRaises(ValueError): self.open(key=b'z'*32).read(BINDING)
        p = self.root/'state.json'; value = json.loads(p.read_text()); value['state']['head'] = 'f'*64
        p.write_text(json.dumps(value)); p.chmod(0o600)
        with self.assertRaises(ValueError): self.store.read(BINDING)

    def test_pending_fsync_failure_does_not_ack_or_repair(self):
        with patch('deployment_compose_witness_store.os.fsync', side_effect=OSError('disk')):
            with self.assertRaises(ValueError): self.reserve()
        self.assertTrue(list(self.root.glob('.pending-*')))
        with self.assertRaises(ValueError): self.store.read(BINDING)
        with self.assertRaises(ValueError): self.reserve()

    def test_directory_fsync_failure_retains_advanced_state_without_reissue(self):
        real = os.fsync
        def sync(fd):
            if fd == self.store._dir: raise OSError('directory durability unknown')
            real(fd)
        with patch('deployment_compose_witness_store.os.fsync', side_effect=sync):
            with self.assertRaises(ValueError): self.reserve()
        self.assertEqual(self.open().read(BINDING)['seq'], 1)
        with self.assertRaises(ValueError): self.reserve()

    def test_private_modes_symlink_and_lock_replacement_rejected(self):
        (self.root/'state.json').chmod(0o644)
        with self.assertRaises(ValueError): self.store.read(BINDING)
        (self.root/'state.json').chmod(0o600)
        lock=self.root/'witness.lock'; lock.unlink(); lock.write_bytes(b''); lock.chmod(0o600)
        with self.assertRaises(ValueError): self.store.read(BINDING)
        with tempfile.TemporaryDirectory() as d:
            link=Path(d)/'link'; link.symlink_to(self.root)
            with self.assertRaises(ValueError): ComposeWitnessStore(link, key=KEY)
        self.root.chmod(0o755)
        with self.assertRaises(ValueError): self.open()


if __name__ == '__main__': unittest.main()
