"""Independent persistence and genuine process contention; no GitLab writes."""
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import release_gitlab_ledger_v2_host as module
from release_gitlab_ledger_v2_host import GitLabReleaseLedgerV2

KEY = b'ledger-test-key-' + b'x'*32
ARGS = dict(request_hash='a'*64, bundle_hash='b'*64, grant_nonce='c'*64)


@unittest.skipUnless(os.name == 'posix', 'private POSIX host ledger')
class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.ledger = self.open(); self.ledger.initialize()

    def open(self, **changes):
        args = dict(key=KEY, host_id='release-host', policy_hash='d'*64); args.update(changes)
        ledger = GitLabReleaseLedgerV2(self.root, **args); self.addCleanup(ledger.close)
        return ledger

    def test_reopen_denies_repeat_and_checks_exact_record(self):
        receipt = self.ledger.burn(**ARGS)
        other = self.open()
        self.assertTrue(other.check(**ARGS, receipt_hash=receipt))
        with self.assertRaises(ValueError): other.burn(**dict(ARGS, grant_nonce='e'*64))
        with self.assertRaises(ValueError): other.burn(**dict(ARGS, request_hash='e'*64))
        with self.assertRaises(ValueError): other.check(**dict(ARGS, bundle_hash='e'*64), receipt_hash=receipt)
        with self.assertRaises(ValueError): self.open(policy_hash='e'*64).burn(**ARGS)
        with self.assertRaises(ValueError): self.open(host_id='other-host').burn(**ARGS)
        with self.assertRaises(ValueError): self.open(key=b'z'*32).burn(**ARGS)

    def test_failed_acknowledgement_after_persistence_stays_burned(self):
        persist = self.ledger._persist
        def fail_after(state): persist(state); raise OSError('lost acknowledgement')
        with patch.object(self.ledger, '_persist', side_effect=fail_after):
            with self.assertRaises(ValueError): self.ledger.burn(**ARGS)
        with self.assertRaises(ValueError): self.open().burn(**ARGS)

    def test_unacknowledged_temporary_write_blocks_future_consumption(self):
        with patch.object(module.os, 'replace', side_effect=OSError('replace failed')):
            with self.assertRaises(ValueError): self.ledger.burn(**ARGS)
        self.assertTrue(any(p.name.startswith('.pending-') for p in self.root.iterdir()))
        with self.assertRaises(ValueError): self.open().burn(**ARGS)

    def test_directory_replacement_and_tampering_rejected(self):
        state = self.root/'state.json'; state.write_bytes(state.read_bytes().replace(b'release-host', b'release-evil'))
        with self.assertRaises(ValueError): self.ledger.burn(**ARGS)
        state.unlink()
        with self.assertRaises(ValueError): self.ledger.burn(**ARGS)

    def test_directory_replacement_rejects_old_handle(self):
        moved = self.root.with_name(self.root.name + '-moved')
        self.root.rename(moved)
        self.addCleanup(shutil.rmtree, moved)
        self.root.mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.ledger.burn(**ARGS)

    def test_limits_types_and_other_schema_interfaces_fail_closed(self):
        for field in ARGS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.ledger.burn(**dict(ARGS, **{field: True}))
        for method in ('register_once', 'reserve', 'read'):
            with self.subTest(method=method), self.assertRaises(ValueError): getattr(self.ledger, method)({})
        self.ledger.burn(**ARGS)
        with patch.object(module, 'MAX_ENTRIES', 1):
            with self.assertRaises(ValueError): self.ledger.burn(request_hash='e'*64, bundle_hash='f'*64, grant_nonce='1'*64)
        with self.assertRaises(ValueError): self.ledger.initialize()

    def test_two_processes_consume_only_once(self):
        code = '''import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from release_gitlab_ledger_v2_host import GitLabReleaseLedgerV2
ledger=GitLabReleaseLedgerV2(Path(sys.argv[2]),key=b'ledger-test-key-'+b'x'*32,host_id='release-host',policy_hash='d'*64)
print('ready',flush=True);sys.stdin.readline()
try:ledger.burn(request_hash='a'*64,bundle_hash='b'*64,grant_nonce='c'*64);print('won',flush=True)
except ValueError:print('rejected',flush=True)
finally:ledger.close()
'''
        processes = [subprocess.Popen([sys.executable, '-u', '-c', code, str(ROOT/'scripts'), str(self.root)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        try:
            for p in processes:
                self.assertTrue(select.select([p.stdout], [], [], 10)[0]); self.assertEqual(p.stdout.readline().strip(), 'ready')
            for p in processes: p.stdin.write('go\n'); p.stdin.flush()
            results = []
            for p in processes:
                out, err = p.communicate(timeout=15); self.assertEqual(p.returncode, 0, err); results.append(out.strip())
            self.assertCountEqual(results, ['won', 'rejected'])
        finally:
            for p in processes:
                if p.poll() is None: p.kill(); p.wait(timeout=5)
                for stream in (p.stdin, p.stdout, p.stderr): stream.close()
