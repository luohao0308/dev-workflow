"""Process death preserves independent history; Engine/GitHub remain explicit doubles."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time
import unittest

from tests import test_deployment_compose_recovery_execution_v3_host as execution
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_gateway import GatePolicy


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'), 'POSIX TLS/SSH required')
class RecoveryProcessTests(execution.history_fixture.GateFixture, unittest.TestCase):
    setUpClass = classmethod(execution.RecoveryExecutionTests.setUpClass.__func__)
    tearDownClass = classmethod(execution.RecoveryExecutionTests.tearDownClass.__func__)
    setUp = execution.RecoveryExecutionTests.setUp
    run_recovery = execution.RecoveryExecutionTests.run_recovery

    def prefix_runner(self, h, operations, socket_path, writes, store, bundle, *, unknown=False):
        baseline = store.get(bundle.to_dict()['baselineStateReference'])
        spec = dict(root=str(h.root), public=h.public.hex(), bundle=bundle.to_dict(), request=asdict(h.req),
                    policy=asdict(h.policy), binding=h.binding, receipt=h.receipt, cert=h.cert,
                    operations=operations, socket=str(socket_path), unknown=unknown)
        helper = Path(__file__).parent/'support/compose_recovery_process_fixture.py'
        process = subprocess.Popen([sys.executable, '-u', str(helper)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup():
            if process.poll() is None: process.kill()
            process.wait(timeout=5)
            process.stdin.close(); process.stdout.close(); process.stderr.close()
        self.addCleanup(cleanup)
        process.stdin.write(json.dumps(spec)+'\n'); process.stdin.flush()
        reopened = False
        deadline = time.monotonic() + 60
        while True:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, 'historical executor total deadline')
            self.assertTrue(select.select([process.stdout], [], [], min(30, remaining))[0], 'historical executor checkpoint deadline')
            raw = process.stdout.readline()
            self.assertTrue(raw, process.stderr.read() if process.poll() is not None else 'executor pipe closed')
            frame = json.loads(raw)
            if frame['kind'] == 'checkpoint': break
            self.assertEqual(frame['kind'], 'rpc')
            if not reopened:
                h.store.close()
                h.store = OperationWitnessStoreV3(h.root/'history-witness', key=b'h'*32)
                self.addCleanup(h.store.close); reopened = True
            reply = h.transport(frame['method'], frame['request'])
            process.stdin.write(json.dumps(reply)+'\n'); process.stdin.flush()
        self.assertIsNone(process.poll())
        process.kill(); process.wait(timeout=5)
        self.assertLess(process.returncode, 0)
        h.binding = frame['binding']; h.policy = GatePolicy(**frame['policy']); h.receipts = frame['receipts']
        h.client = h.factory(h.binding)
        # New store/client objects read the independent persisted bytes after death.
        h.store.close(); h.store = OperationWitnessStoreV3(h.root/'history-witness', key=b'h'*32)
        self.addCleanup(h.store.close)
        self.assertEqual(store.get(bundle.to_dict()['baselineStateReference']), baseline)
        self.assertEqual(writes, operations)
        self.assertEqual(h.client.read()['phase'], 'admitted' if unknown else 'closed')
        self.assertEqual(h.client.read()['seq'], 3 if unknown else 6)
        self.checkpoint_reaped = True
        self.resumed_writes = writes
        return lambda: process.poll() is not None and process.returncode < 0

    def test_crash_after_closed_create(self): self.run_recovery(1, prefix_runner=self.prefix_runner)
    def test_crash_after_closed_stop(self): self.run_recovery(2, prefix_runner=self.prefix_runner)
    def test_crash_after_closed_delete(self): self.run_recovery(3, prefix_runner=self.prefix_runner)
    def test_crash_after_closed_rename(self): self.run_recovery(4, prefix_runner=self.prefix_runner)

    def test_admitted_without_response_cannot_resume_after_executor_death(self):
        def unknown(*args): self.prefix_runner(*args, unknown=True)
        with self.assertRaisesRegex(ValueError, '^compose-recovery-preparation-v3-rejected$'):
            self.run_recovery(1, prefix_runner=unknown)
        self.assertTrue(self.checkpoint_reaped)
        self.assertEqual(self.resumed_writes, [])
