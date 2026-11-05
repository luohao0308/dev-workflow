"""Real process/signature lifecycle evidence into non-authorizing V4 recovery."""
import multiprocessing
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_remote_supervisor_v4 as fixture
from tests.test_deployment_compose_approval_v3_host import request as root_request
from deployment_compose_operation_witness_v4 import OperationWitnessStoreV4, digest
from deployment_compose_recovery_prepare_v4_host import RecoveryPreparationHostV4
from deployment_compose_recovery_store import ComposeRecoveryStore


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class RemoteRecoveryTests(unittest.TestCase):
    setUp = fixture.RemoteSupervisorTests.setUp
    client = fixture.RemoteSupervisorTests.client

    def setup_session(self):
        context = multiprocessing.get_context('fork')
        parent, child = context.Pipe()
        process = context.Process(target=fixture.serve, args=(child, self.key))
        process.start(); child.close()
        def cleanup():
            if process.is_alive():
                try: parent.send(None)
                except (BrokenPipeError, EOFError): pass
            process.join(5)
            if process.is_alive(): process.kill(); process.join(5)
            parent.close()
        self.addCleanup(cleanup)
        # This is a private parent-owned startup pipe; signing key was pinned separately.
        self.assertTrue(parent.poll(5))
        hello = parent.recv()
        self.assertEqual(set(hello), {'supervisorBoot'})
        child_boot = hello['supervisorBoot']
        def rpc(request):
            parent.send(request)
            if not parent.poll(5): raise TimeoutError()
            return parent.recv()
        root = Path(self.temp.name).resolve()
        cas_root = root/'cas'; cas_root.mkdir(mode=0o700)
        witness_root = root/'witness'; witness_root.mkdir(mode=0o700)
        with patch('deployment_compose_recovery_store.sys.platform', 'linux'):
            self.cas = ComposeRecoveryStore(cas_root, key=b'c'*32)
        self.addCleanup(self.cas.close)
        self.root_request = root_request(profile_version='4')
        session = dict(bundleDigest=self.root_request.plan_hash,
                       policyHash=self.root_request.policy_hash,
                       baselineReference=self.cas.put(b'remote diagnostic baseline'),
                       rootRequestHash=self.root_request.digest(), supervisorBoot=child_boot)
        session['sessionHash'] = digest(session)
        initial_cursor = {'sequence': 1, 'head': digest(session)}
        self.remote = self.client(rpc, expected_cursor=initial_cursor, expected_boot=child_boot)
        self.addCleanup(self.remote.close)
        self.actor = self.remote.start_fixed_actor(session['sessionHash'])
        self.store = OperationWitnessStoreV4(witness_root, key=b'w'*32)
        self.addCleanup(self.store.close)
        self.view = self.store.register_once(session, supervisor=self.remote, actor=self.actor)
        self.process = process

    def cursor(self):
        return {k: self.view[k] for k in ('sequence', 'head')}

    def prepared_phase(self):
        self.view = self.store.record_prepared(self.cursor(), supervisor=self.remote,
                                              actor=self.actor, attempt='9'*64)

    def preparation(self, proof):
        return RecoveryPreparationHostV4(witness=self.store, root_request=self.root_request,
            baseline_store=self.cas, supervisor=self.remote, actor=self.actor, termination=proof)

    def test_signed_remote_join_prepares_and_atomically_reserves_pending_successor(self):
        from datetime import datetime, timedelta, timezone
        self.setup_session(); self.prepared_phase()
        proof = self.remote.stop_and_join(self.actor, expected_cursor=self.cursor())
        preparer = self.preparation(proof)
        prepared = preparer.prepare(operation_nonce='f'*64,
            expires_at=(datetime.now(timezone.utc)+timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        value = self.store.abandon_and_reserve(self.cursor(), supervisor=self.remote,
            actor=self.actor, termination=proof, recovery_intent=prepared)
        self.assertEqual([s['phase'] for s in value['scopes']], ['abandoned', 'pending-authorization'])
        self.assertFalse(value['authorityGranted'] or value['executionAvailable'] or value['productionReady'])
        self.assertEqual(self.store.read(), value)
        # The independently owned supervisor remains alive after its leaf joined.
        self.assertTrue(self.process.is_alive())

    def test_old_cursor_termination_cannot_prepare_new_witness_phase(self):
        self.setup_session()
        proof = self.remote.stop_and_join(self.actor, expected_cursor=self.cursor())
        self.prepared_phase()
        with self.assertRaises(ValueError): self.preparation(proof)
        self.assertEqual(self.store.read()['scopes'][-1]['phase'], 'prepared')

    def test_signed_join_does_not_unfreeze_admitted_unknown(self):
        self.setup_session(); self.prepared_phase()
        self.view = self.store.record_admitted(self.cursor(), supervisor=self.remote,
                                              actor=self.actor, attempt='9'*64)
        proof = self.remote.stop_and_join(self.actor, expected_cursor=self.cursor())
        with self.assertRaises(ValueError): self.preparation(proof)
        self.assertEqual(self.store.read()['scopes'][-1]['phase'], 'admitted')

    def test_protocol_shaped_supervisor_is_not_a_registered_host_type(self):
        self.setup_session()
        class Forged:
            boot = self.remote.boot
            def actor_identity(self, *args): return '0'*64
        with self.assertRaises(ValueError):
            self.store.register_once(self.view['session'], supervisor=Forged(), actor=self.actor)
