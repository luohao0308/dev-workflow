"""Diagnostic V4 process ownership and atomic non-authorizing reservations."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os
import shutil
from pathlib import Path
import sys
import tempfile
import threading
import subprocess
import venv
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from deployment_compose_actor_supervisor_v4 import ActorSupervisorV4, ActorHandle, ActorTermination
from deployment_compose_operation_witness_v4 import OperationWitnessStoreV4, digest
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_recovery_prepare_v4_host import RecoveryPreparationHostV4
from deployment_compose_recovery_store import ComposeRecoveryStore
from tests.test_deployment_compose_approval_v3_host import request as root_request


@unittest.skipUnless(os.name == 'posix', 'POSIX witness storage and process ownership')
class WitnessV4Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()/'witness'; self.root.mkdir(mode=0o700)
        cas = self.root.parent/'cas'; cas.mkdir(mode=0o700)
        with patch('deployment_compose_recovery_store.sys.platform', 'linux'):
            self.cas = ComposeRecoveryStore(cas, key=b'c'*32)
        self.addCleanup(self.cas.close)
        baseline_reference = self.cas.put(b'fixed baseline bytes')
        self.root_request = root_request(profile_version='4')
        self.supervisor = ActorSupervisorV4(); self.addCleanup(self.supervisor.close)
        self.session = dict(sessionHash='a'*64, bundleDigest=self.root_request.plan_hash, policyHash=self.root_request.policy_hash,
                            baselineReference=baseline_reference, rootRequestHash=self.root_request.digest(), supervisorBoot=self.supervisor.boot)
        self.session['sessionHash'] = digest({k:v for k,v in self.session.items() if k != 'sessionHash'})
        self.actor = self.supervisor.start_fixed_actor(self.session['sessionHash'])
        self.store = self.open()
        self.view = self.store.register_once(self.session, supervisor=self.supervisor, actor=self.actor)

    def open(self):
        store = OperationWitnessStoreV4(self.root, key=b'x'*32)
        self.addCleanup(store.close)
        return store

    def cursor(self):
        return {k:self.view[k] for k in ('sequence','head')}

    def preparer(self):
        return RecoveryPreparationHostV4(witness=self.store, root_request=self.root_request, baseline_store=self.cas,
            supervisor=self.supervisor, actor=self.actor, termination=self.supervisor.stop_and_join(self.actor))

    def intent(self):
        return self.preparer().prepare(operation_nonce='f'*64,
            expires_at=(datetime.now(timezone.utc)+timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ'))

    def prepared(self):
        self.view = self.store.record_prepared(self.cursor(), supervisor=self.supervisor, actor=self.actor, attempt='9'*64)

    def abandon(self, **changes):
        args = dict(supervisor=self.supervisor, actor=self.actor,
                    termination=self.supervisor.stop_and_join(self.actor))
        if 'recovery_intent' not in changes:
            args['recovery_intent'] = self.intent()
        args.update(changes)
        return self.store.abandon_and_reserve(self.cursor(), **args)

    def test_real_wait_and_prepared_abandon_reload_remains_pending(self):
        self.prepared(); old = self.cursor()
        proof = self.supervisor.stop_and_join(self.actor)
        self.assertIsNotNone(self.supervisor._actors[id(self.actor)][1].returncode)
        result = self.abandon(termination=proof)
        self.assertEqual([s['phase'] for s in result['scopes']], ['abandoned','pending-authorization'])
        self.assertEqual([s['planWriteIndex'] for s in result['scopes']], [0,0])
        self.assertEqual([s['scopeOrdinal'] for s in result['scopes']], [0,1])
        self.assertEqual(result, self.open().read())
        for flag in ('authorityGranted','executionAvailable','productionReady'):
            self.assertIs(result[flag], False)
        with self.assertRaises(ValueError): self.abandon(termination=proof)
        with self.assertRaises(ValueError):
            self.store.record_admitted(old, supervisor=self.supervisor, actor=self.actor, attempt='9'*64)

    def test_alive_forged_and_cross_supervisor_proofs_rejected(self):
        for proof in ({'pid': 1, 'exitCode': 0}, ActorTermination(), None):
            with self.assertRaises(ValueError):
                self.store.abandon_and_reserve(self.cursor(), supervisor=self.supervisor, actor=self.actor,
                    termination=proof, recovery_intent=self.intent())
        other = ActorSupervisorV4(); self.addCleanup(other.close)
        with self.assertRaises(ValueError): other.stop_and_join(self.actor)
        with self.assertRaises(ValueError): self.supervisor.stop_and_join(ActorHandle())
        self.assertEqual(self.store.read()['scopes'][0]['phase'], 'open')

    def test_admission_wins_and_forever_blocks_abandon(self):
        self.prepared()
        self.view = self.store.record_admitted(self.cursor(), supervisor=self.supervisor, actor=self.actor, attempt='9'*64)
        with self.assertRaises(ValueError): self.abandon()
        self.assertEqual(self.store.read()['scopes'][0]['phase'], 'admitted')

    def test_competing_admission_and_abandon_have_one_winner(self):
        self.prepared(); cursor=self.cursor(); intent=self.intent()
        proof=self.supervisor.stop_and_join(self.actor)
        def admit(): return self.store.record_admitted(cursor, supervisor=self.supervisor, actor=self.actor, attempt='9'*64)
        def abandon(): return self.store.abandon_and_reserve(cursor, supervisor=self.supervisor, actor=self.actor,
                                                           termination=proof, recovery_intent=intent)
        def run(fn):
            try: fn(); return True
            except ValueError: return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(run, (admit,abandon))), 1)
        self.assertIn(self.store.read()['scopes'][-1]['phase'], ('admitted','pending-authorization'))

    def test_intent_binding_types_freshness_and_closed_fields(self):
        original={'request':self.intent().request.canonical_json()}
        for field,value in [('bundleDigest','0'*64),('historyHead','0'*64),('actorEpoch','0'*64),
                            ('scopeOrdinal',False),('planWriteIndex',False),('schemaVersion',True),('profile','compose-v3'),
                            ('recoveryRequestHash','invalid'),('nonce','invalid'),
                            ('expiresAt','2020-01-01T00:00:00Z'),('extra','field')]:
            intent=dict(original);intent[field]=value
            with self.subTest(field=field), self.assertRaises(ValueError): self.abandon(recovery_intent=intent)
        self.assertEqual(self.store.read()['scopes'][0]['phase'], 'open')

    def test_supervisor_restart_cannot_reconstitute_proof(self):
        proof=self.supervisor.stop_and_join(self.actor)
        replacement=ActorSupervisorV4(); self.addCleanup(replacement.close)
        replacement.boot=self.supervisor.boot
        with self.assertRaises(ValueError): self.abandon(supervisor=replacement, termination=proof)
        self.supervisor.close()
        with self.assertRaises(ValueError): self.abandon(termination=proof)
        self.assertEqual(self.open().read(), self.view)

    def test_v3_reader_and_registration_reuse_rejected(self):
        old=OperationWitnessStoreV3(self.root,key=b'x'*32);self.addCleanup(old.close)
        with self.assertRaises(ValueError): old.read({})
        with self.assertRaises(ValueError): self.store.register_once(self.session,supervisor=self.supervisor,actor=self.actor)
        with self.assertRaises(ValueError): self.store.reserve({})

    def test_persist_before_and_after_commit_failures_do_not_replay(self):
        before=self.store.read()
        with patch.object(self.store,'_persist',side_effect=OSError('before commit')):
            with self.assertRaises(ValueError): self.abandon()
        self.assertEqual(self.store.read(),before)
        persist=self.store._persist
        def lost_reply(state): persist(state);raise OSError('reply lost')
        with patch.object(self.store,'_persist',side_effect=lost_reply):
            with self.assertRaises(ValueError): self.abandon()
        self.assertEqual(self.open().read()['scopes'][-1]['phase'],'pending-authorization')
        with self.assertRaises(ValueError): self.abandon()

    def test_byte_budget_rejects_before_any_write(self):
        before=self.store.read()
        with patch('deployment_compose_witness_store.MAX_BYTES',1):
            with self.assertRaises(ValueError): self.abandon()
        self.assertEqual(self.store.read(),before)

    def test_directory_replacement_does_not_reopen_identity(self):
        moved = self.root.with_name(self.root.name + '-old')
        self.root.rename(moved)
        self.addCleanup(lambda: shutil.rmtree(moved, ignore_errors=True))
        self.root.mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.store.read()

    def test_unknown_response_phases_cannot_be_abandoned(self):
        original = self.store._read()
        for phase in ('response', 'blocked', 'unknown'):
            changed = deepcopy(original); changed['scopes'][0]['phase'] = phase
            self.store._persist(changed)
            with self.subTest(phase=phase), self.assertRaises(ValueError): self.abandon()
        self.store._persist(original)

    def test_global_pth_startup_hook_cannot_run_in_fixed_actor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            venv.EnvBuilder(with_pip=False).create(root/'venv')
            executable = root/'venv/bin/python'
            packages = next((root/'venv/lib').glob('python*/site-packages'))
            marker = root/'hook-ran'
            (packages/'startup.pth').write_text("import pathlib; pathlib.Path(" + repr(str(marker)) + ").touch()\n")
            # Positive control proves this interpreter's global hook is effective.
            subprocess.run([str(executable), '-I', '-c', 'pass'], check=True, timeout=10)
            self.assertTrue(marker.exists())
            marker.unlink()
            with patch('deployment_compose_actor_supervisor_v4.sys.executable', str(executable)):
                handle = self.supervisor.start_fixed_actor(self.session['sessionHash'])
            # start_fixed_actor has observed readiness from the actual fixed code.
            self.assertFalse(marker.exists())
            self.supervisor.stop_and_join(handle)
            self.assertFalse(marker.exists())

    def test_authenticated_but_invalid_attempt_and_certificate_fields_rejected(self):
        original = self.store._read()
        changed = deepcopy(original); changed['scopes'][0]['attemptRef'] = '9'*64
        self.store._persist(changed)
        with self.assertRaises(ValueError): self.store.read()
        self.store._persist(original)
        result = self.abandon()
        for field in ('attemptRef', 'certificate'):
            changed = self.store._read()
            changed['scopes'][-1][field] = 'invalid'
            self.store._persist(changed)
            with self.assertRaises(ValueError): self.store.read()
            self.store._persist({k:v for k,v in result.items() if k not in ('authorityGranted','executionAvailable','productionReady')})

    def test_start_and_close_barrier_cannot_leave_an_owned_actor_alive(self):
        import deployment_compose_actor_supervisor_v4 as module
        entered = threading.Event(); release = threading.Event()
        close_requested = threading.Event(); closed = threading.Event()
        popen = module.subprocess.Popen
        def blocked_spawn(*args, **kwargs):
            entered.set()
            if not release.wait(5): raise RuntimeError('test barrier timeout')
            return popen(*args, **kwargs)
        def close():
            close_requested.set()
            self.supervisor.close()
            closed.set()
        with ThreadPoolExecutor(max_workers=2) as pool:
            with patch.object(module.subprocess, 'Popen', side_effect=blocked_spawn):
                start = pool.submit(self.supervisor.start_fixed_actor, self.session['sessionHash'])
                try:
                    self.assertTrue(entered.wait(5))
                    closing = pool.submit(close)
                    self.assertTrue(close_requested.wait(5))
                    self.assertFalse(closed.wait(.1))
                finally:
                    release.set()
                handle = start.result(timeout=5)
                closing.result(timeout=5)
        self.assertTrue(closed.is_set())
        self.assertIsNotNone(self.supervisor._actors[id(handle)][1].poll())
        self.supervisor.close()
