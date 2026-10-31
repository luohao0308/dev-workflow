"""Actual Popen pipes, Mac signatures/HMAC/admission/history; fixture provider only."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts','tests/support')]
import deployment_compose_owned_recovery_controller_v3_host as controller
from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'POSIX/OpenSSL/OpenSSH required')
class ControllerTests(unittest.TestCase):
    def drive(self,attack='',*,review_attack=None,timeout=60):
        temp=tempfile.TemporaryDirectory(prefix='owned-controller-');self.addCleanup(temp.cleanup)
        root=Path(temp.name).resolve();root.chmod(0o700)
        engine='/var/tmp/dw-engine-'+secrets.token_hex(8)
        self.addCleanup(lambda:shutil.rmtree(engine,ignore_errors=True))
        self.process=subprocess.Popen([sys.executable,str(ROOT/'tests/support/owned_recovery_controller_fixture.py'),attack,engine],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=-1 if attack=='buffered-stderr' else 0,
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
        def reap():
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
        self.addCleanup(reap)
        self.owner=SimpleNamespace(reviewed=[])
        base=LocalAcceptanceCase.review_adapter(self.owner)
        self.closed=0;self.notices=[];self.root=root
        owner=self
        class Review:
            def consume_prepared(self,bundle,request,on_review):
                result=base.consume_prepared(bundle,request,on_review)
                if review_attack=='mutate-candidates':
                    if request.operation=='deploy':
                        for row in owner.verified_candidate['rawRows'].values():row['State']['Pid']=999
                    else:
                        owner.last_frame['context']['startWriteIndex']=99
                if request.operation=='recovery' and review_attack=='advance-root':
                    admission=owner.admission
                    view=admission._history(admission._root).capture().snapshot
                    next_scope=admission._scope(admission._root,1,view['receiptMap'])
                    admission.authorize_rpc('witness','transition_successor',dict(
                        binding=admission._root['first'],bootNonce='8'*64,rpcNonce='9'*64,
                        expectedSeq=view['closedTail']['seq'],expectedHead=view['closedTail']['head'],
                        childBinding=next_scope['binding']))
                if review_attack=='missing':return None,result[1],{}
                if request.operation=='deploy':owner.first=result
                if request.operation=='recovery' and review_attack=='old':return owner.first
                if review_attack=='raise':raise RuntimeError('primary-review-error')
                return result
            def close(self):
                owner.closed+=1
                if review_attack=='raise':raise RuntimeError('secondary-cleanup-error')
        original_receive=controller._receive
        original_verify=controller.live.verify_private_capsule
        original_admission=controller.MacLiveAdmissionV3
        original_completed=controller._completed_history
        def receive(*args):
            frame=original_receive(*args);self.last_frame=frame;return frame
        def verify(candidate,**kwargs):
            self.verified_candidate=candidate;return original_verify(candidate,**kwargs)
        def admission(**kwargs):
            self.admission=original_admission(**kwargs);return self.admission
        def completed(admission):
            result=original_completed(admission);self.completed=json.loads(result.canonical);return result
        with patch.object(controller,'_completed_history',side_effect=completed), \
                patch.object(controller,'_receive',side_effect=receive), \
                patch.object(controller.live,'verify_private_capsule',side_effect=verify), \
                patch.object(controller,'MacLiveAdmissionV3',side_effect=admission):
            return controller._drive_recovery_protocol(root,process=self.process,channel_nonce='1'*64,
                source_sha='b'*40,archive_digest='2'*64,host_id='host-one',normalization_version={'Version':'29.8.2','GitCommit':'8af9fe3'},
                review=Review(),on_review=self.notices.append,trusted_boot_id='4'*32,trusted_bind_digest=None,
                expected_root=engine,expected_daemon_id='daemon-one',expected_project='dw-restore-'+'3'*24,timeout=timeout)

    def test_real_popen_two_consumptions_and_five_signed_operations(self):
        result=self.drive()
        self.assertEqual([r.operation for r in self.owner.reviewed],['deploy','recovery'])
        self.assertNotEqual(*[r.digest() for r in self.owner.reviewed])
        self.assertEqual(len(self.notices),2);self.assertEqual(self.closed,1)
        self.assertEqual(self.process.returncode,0)
        for flag in ('protocolCompleted','historyCompleted','localTransportExited'):self.assertIs(result[flag],True)
        self.assertEqual(result['requestCount'],2)
        self.assertEqual(self.completed['schemaVersion'],2)
        self.assertEqual(len(self.completed['knownPrefix']),5)
        self.assertEqual(len(self.completed['scopes']),4)
        self.assertEqual(self.completed['parent']['scopeCount'],1)
        self.assertEqual(self.completed['parent']['startWriteIndex'],1)
        self.assertEqual(self.completed['parent']['historyDigest'],self.owner.reviewed[1].history_hash)
        self.assertEqual(self.completed['parent']['originalRequestHash'],self.owner.reviewed[0].digest())
        self.assertEqual(self.completed['closedTail']['seq'],6)
        self.assertIs(result['remoteWrapperStoppedVerified'],False);self.assertIs(result['productionReady'],False)
        self.assertEqual(set(result['workerReport'].values()),{True})
        for path in self.root.glob('owned-recovery-*/stderr.private.txt'):self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertTrue(all(p.closed for p in (self.process.stdin,self.process.stdout,self.process.stderr)))

    def test_initial_frames_rejected_before_consumption(self):
        for attack in ('bad-nonce','bad-source','bad-archive','bad-daemon','bad-root','wrong-order','bad-observer','bad-initial','eof'):
            with self.subTest(attack=attack):
                with self.assertRaises((ValueError,BrokenPipeError)):self.drive(attack)
                self.assertEqual(self.owner.reviewed,[]);self.assertEqual(self.closed,1)
                self.assertIsNotNone(self.process.poll())

    def test_recovery_capsule_must_validate_before_second_consume(self):
        for attack in ('bad-context','extra-context','bad-phase'):
            with self.subTest(attack=attack):
                with self.assertRaises(ValueError):self.drive(attack)
                self.assertEqual([r.operation for r in self.owner.reviewed],['deploy'])

    def test_stage_and_rpc_replay_are_rejected(self):
        for attack in ('early-transition','bad-method','replay-id','replay-nonce'):
            with self.subTest(attack=attack):
                with self.assertRaises(ValueError):self.drive(attack)
                self.assertEqual([r.operation for r in self.owner.reviewed],['deploy'])

    def test_final_cannot_override_independent_history_or_exit(self):
        for attack in ('false-final','false-history','false-schema','false-count','bool-count','nonzero'):
            with self.subTest(attack=attack):
                with self.assertRaises(ValueError):self.drive(attack)
                self.assertEqual([r.operation for r in self.owner.reviewed],['deploy','recovery'])

    def test_lost_consumption_is_never_retried(self):
        for attack,count in (('lost-consume',1),('lost-second-consume',2)):
            with self.subTest(attack=attack):
                with self.assertRaises((ValueError,BrokenPipeError)):self.drive(attack)
                self.assertLessEqual(len(self.owner.reviewed),count)
                self.assertIsNotNone(self.process.poll())

    def test_actual_typed_direct_and_fresh_consumption_required(self):
        for attack,count in (('missing',1),('old',2)):
            with self.subTest(attack=attack):
                with self.assertRaises(ValueError):self.drive(review_attack=attack)
                self.assertEqual(len(self.owner.reviewed),count)

    def test_review_mutation_cannot_replace_frozen_capsules_or_baseline(self):
        self.assertTrue(self.drive(review_attack='mutate-candidates')['historyCompleted'])

    def test_actual_parent_advance_during_second_review_rejects(self):
        with self.assertRaises(ValueError):self.drive(review_attack='advance-root')
        self.assertEqual([r.operation for r in self.owner.reviewed],['deploy','recovery'])
        self.assertIsNone(self.admission._pending)

    def test_stderr_overflow_fails_promptly_and_is_bounded(self):
        started=time.monotonic()
        with self.assertRaises(ValueError):self.drive('stderr-overflow',timeout=30)
        self.assertLess(time.monotonic()-started,10)
        self.assertEqual(self.owner.reviewed,[])
        for path in self.root.glob('owned-recovery-*/stderr.private.txt'):self.assertLessEqual(path.stat().st_size,1024*1024)

    def test_buffered_stderr_close_is_bounded_when_descendant_holds_pipe(self):
        started=time.monotonic()
        with self.assertRaises(ValueError):self.drive('buffered-stderr')
        self.assertLess(time.monotonic()-started,2.5)
        self.assertIsNotNone(self.process.poll())
        self.assertTrue(self.process.stderr.closed)

    def test_local_exit_with_descendant_stderr_cannot_hang_or_prove_remote_stop(self):
        with self.assertRaises(ValueError):self.drive('held-stderr')
        self.assertIsNotNone(self.process.poll())
        self.assertTrue(all(p.closed for p in (self.process.stdin,self.process.stdout,self.process.stderr)))

    def test_timeout_terminates_only_local_process(self):
        with self.assertRaises((ValueError,TimeoutError)):self.drive('timeout',timeout=.1)
        self.assertIsNotNone(self.process.poll());self.assertEqual(self.owner.reviewed,[])

    def test_cleanup_does_not_mask_primary_error(self):
        with self.assertRaisesRegex(RuntimeError,'primary-review-error'):self.drive(review_attack='raise')
        self.assertEqual(self.closed,1)


if __name__=='__main__':unittest.main()
