"""Actual SSH-manager-shaped local pipes/admission/signatures; providers doubled."""
import json
import copy
import os
from pathlib import Path
import secrets
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts','tests/support')]
import deployment_compose_owned_recovery_session_v3_host as session_module
import deployment_compose_owned_recovery_controller_v3_host as controller
import deployment_compose_owned_recovery_worker_v3_host as worker
from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
    'POSIX/OpenSSL/OpenSSH required')
class SessionTests(unittest.TestCase):
    def open(self,attack='',*,verify_daemon=False,verify_resources=False,verify_host=False):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.root.chmod(0o700)
        self.engine='/var/tmp/dw-engine-'+secrets.token_hex(8)
        self.addCleanup(lambda:shutil.rmtree(self.engine,ignore_errors=True))
        def spawn(argv):
            self.argv=argv
            return subprocess.Popen([sys.executable,'-u',str(ROOT/'tests/support/owned_recovery_managed_fixture.py'),attack,self.engine],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        with patch.object(session_module.loader,'published_manager_archive',return_value=b'fixture-code'),\
                patch.object(session_module,'_spawn',side_effect=spawn):
            self.session=session_module.OwnedRecoverySSHSessionV3(self.root,'host-one','b'*40,
                timeout=60 if verify_host else 30,verify_daemon_stop=verify_daemon,
                verify_resource_inventory=verify_resources,verify_host_snapshot=verify_host)
        created=self.session
        def close_created():
            try:created.close()
            except Exception:pass
        self.addCleanup(close_created)
        return self.session
    def close_session(self):
        try:self.session.close()
        except Exception:pass
    def drive(self,attack='',review_failure=False,verify_daemon=False,verify_resources=False,verify_host=False):
        session=self.open(attack,verify_daemon=verify_daemon,verify_resources=verify_resources,verify_host=verify_host)
        self.owner=SimpleNamespace(reviewed=[]);base=LocalAcceptanceCase.review_adapter(self.owner)
        self.closed=0;owner=self
        class Review:
            def consume_prepared(self,bundle,request,notify):
                if review_failure:raise RuntimeError('primary-review-failed')
                return base.consume_prepared(bundle,request,notify)
            def close(self):owner.closed+=1
        return controller._drive_managed_recovery_protocol(self.root,session=session,
            review=Review(),on_review=lambda _:None,timeout=80)

    def test_full_managed_flow_checks_independent_history_and_manager_completion(self):
        original=controller.live.verify_private_capsule
        seen=[]
        def verify(*args,**kwargs):
            seen.append(kwargs['trusted_boot_id'])
            return original(*args,**kwargs)
        with patch.object(controller.live,'verify_private_capsule',side_effect=verify):result=self.drive()
        self.assertEqual(seen,['4'*32])
        self.assertNotEqual(seen[0],'1'*32)
        for key in ('protocolCompleted','historyCompleted','localTransportExited','remoteWrapperStoppedVerified'):
            self.assertIs(result[key],True)
        self.assertIs(result['daemonCleanupVerified'],False);self.assertIs(result['productionReady'],False)
        self.assertEqual([r.operation for r in self.owner.reviewed],['deploy','recovery'])
        self.assertEqual(self.closed,1)
        self.assertIn('StrictHostKeyChecking=yes',self.argv)
        self.assertTrue(self.session._finished);self.assertTrue(self.session._closed)

    def test_source_project_pin_cannot_be_copied_from_valid_capsule(self):
        with self.assertRaises(ValueError):self.drive('bad-managed-project')
        self.assertEqual(self.owner.reviewed,[]);self.assertEqual(self.closed,1)

    def test_verified_daemon_mode_composes_with_signed_business_history(self):
        result=self.drive(verify_daemon=True)
        self.assertTrue(result['daemonStoppedVerified']);self.assertTrue(result['remoteWrapperStoppedVerified'])
        self.assertFalse(result['daemonCleanupVerified']);self.assertFalse(result['productionReady'])

    def test_independent_resource_checkpoint_composes_with_signed_history(self):
        result=self.drive(verify_daemon=True,verify_resources=True)
        self.assertTrue(result['resourceInventoryRestored']);self.assertTrue(result['daemonStoppedVerified'])
        self.assertFalse(result['daemonCleanupVerified']);self.assertFalse(result['productionReady'])

    def test_host_profile_composes_with_independent_business_and_lifecycle(self):
        result=self.drive(verify_daemon=True,verify_resources=True,verify_host=True)
        self.assertTrue(result['hostSnapshotUnchangedVerified']);self.assertTrue(result['resourceInventoryRestored'])
        self.assertFalse(result['daemonCleanupVerified']);self.assertFalse(result['productionReady'])

    def test_host_downgrade_or_changed_projection_and_terminal_reject(self):
        with self.assertRaises(ValueError):self.open('simple-resource-host-downgrade',
            verify_daemon=True,verify_resources=True,verify_host=True)
        for attack in ('simple-resource-host-drift','simple-resource-host-late-drift','simple-resource-host-after',
                'simple-resource-host-flag','simple-resource-host-binding'):
            with self.subTest(attack=attack):
                session=self.open(attack,verify_daemon=True,verify_resources=True,verify_host=True);session.begin(20)
                session.receive_worker();session.send_worker(dict(kind='configure',channelNonce=session.nonce))
                with self.assertRaises(ValueError):session.receive_worker();session.complete()
                self.assertFalse(session.host_snapshot_unchanged_verified);self.close_session()

    def test_host_baseline_is_observed_even_when_business_never_starts(self):
        session=self.open('simple',verify_daemon=True,verify_resources=True,verify_host=True);session.close()
        self.assertTrue(session.host_snapshot_unchanged_verified)
        self.assertFalse(session.daemon_stopped_verified);self.assertFalse(session.resource_inventory_restored)

    def test_resource_missing_leak_rpc_after_check_and_bad_receipts_reject(self):
        for attack in ('simple-resource-missing','simple-resource-leak','simple-resource-rpc',
                'simple-resource-duplicate','simple-resource-false','simple-resource-after','simple-resource-wrong-baseline'):
            with self.subTest(attack=attack):
                session=self.open(attack,verify_daemon=True,verify_resources=True);session.begin(15)
                self.assertEqual(session.receive_worker()['kind'],'hello')
                session.send_worker(dict(kind='configure',channelNonce=session.nonce))
                with self.assertRaises(ValueError):
                    frame=session.receive_worker()
                    self.assertEqual(frame['kind'],'final');session.complete()
                self.assertFalse(session.resource_inventory_restored);self.close_session()

    def test_resource_mode_cannot_downgrade_or_accept_client_ack(self):
        with self.assertRaises(ValueError):self.open('simple-resource-downgrade',verify_daemon=True,verify_resources=True)
        session=self.open('simple-resource-good',verify_daemon=True,verify_resources=True);session.begin(15)
        session.receive_worker();session.send_worker(dict(kind='cleanup-checked',channelNonce=session.nonce))
        with self.assertRaises(ValueError):session.receive_worker()
        self.close_session()

    def test_resource_mode_stop_before_start_is_unverified(self):
        session=self.open('simple',verify_daemon=True,verify_resources=True);session.close()
        self.assertTrue(session._finished);self.assertFalse(session.resource_inventory_restored)

    def test_checkpoint_cannot_seal_with_undelivered_business_bytes(self):
        session=self.open('simple-resource-backlog',verify_daemon=True,verify_resources=True);session.begin(15)
        session.receive_worker();session.send_worker(dict(kind='configure',channelNonce=session.nonce))
        self.assertEqual(session.receive_worker()['kind'],'ready-for-backlog')
        session.send_worker(dict(kind='unexpected-business',channelNonce=session.nonce,data='x'*(2*1024*1024)))
        (Path(self.engine)/'checkpoint-go').touch()
        with self.assertRaises(ValueError):session.receive_worker()
        self.assertFalse(session.resource_inventory_restored);self.close_session()

    def test_daemon_mode_cannot_downgrade_or_miss_binding(self):
        for attack in ('simple-daemon-downgrade','simple-daemon-missing','simple-daemon-mismatch'):
            with self.subTest(attack=attack):
                if attack.endswith('downgrade'):
                    with self.assertRaises(ValueError):self.open(attack,verify_daemon=True)
                else:
                    session=self.open(attack,verify_daemon=True);session.begin(15)
                    with self.assertRaises(ValueError):session.receive_worker()
                    self.close_session()

    def test_daemon_false_or_changed_terminal_is_not_verified(self):
        for attack in ('simple-daemon-active','simple-daemon-false','simple-daemon-terminal'):
            with self.subTest(attack=attack):
                session=self.open(attack,verify_daemon=True);session.begin(15)
                self.assertEqual(session.receive_worker()['kind'],'hello')
                with self.assertRaises(ValueError):session.complete()
                self.assertFalse(session.daemon_stopped_verified);self.close_session()

    def test_stop_before_start_never_vacuously_verifies_daemon(self):
        session=self.open('simple',verify_daemon=True);session.close()
        self.assertTrue(session._finished);self.assertFalse(session.daemon_stopped_verified)

    def test_close_can_validate_daemon_binding_queued_before_first_receive(self):
        session=self.open('simple-daemon-wait',verify_daemon=True);session.begin(15)
        with selectors.DefaultSelector() as selector:
            selector.register(session._process.stdout,selectors.EVENT_READ)
            self.assertTrue(selector.select(5))
        session.close()
        self.assertTrue(session._finished);self.assertTrue(session.daemon_stopped_verified)

    def test_close_drains_valid_receipt_even_after_manager_exit(self):
        session=self.open('simple',verify_daemon=True);session.begin(15)
        self.assertEqual(session._process.wait(timeout=5),0)
        session.close()
        self.assertTrue(session._finished);self.assertTrue(session.daemon_stopped_verified)

    def test_gateway_boot_must_match_owned_observation_before_review(self):
        with self.assertRaises(ValueError):self.drive('bad-observer')
        self.assertEqual(self.owner.reviewed,[]);self.assertEqual(self.closed,1)

    def test_missing_or_reordered_source_facts_never_reach_review(self):
        for attack in ('missing-managed-source','reordered-managed-source'):
            with self.subTest(attack=attack):
                with self.assertRaises(ValueError):self.drive(attack)
                self.assertEqual(self.owner.reviewed,[]);self.assertEqual(self.closed,1)

    def test_review_failure_preserved_and_session_closed(self):
        with self.assertRaisesRegex(RuntimeError,'primary-review-failed'):self.drive(review_failure=True)
        self.assertEqual(self.closed,1);self.assertTrue(self.session._closed)

    def test_terminal_failures_do_not_complete_issued_session(self):
        for attack in ('simple-terminal-binding','simple-terminal-bool','simple-terminal-missing',
                'simple-terminal-extra','simple-ssh-nonzero'):
            with self.subTest(attack=attack):
                session=self.open(attack);session.begin(15)
                self.assertEqual(session.receive_worker()['kind'],'hello')
                with self.assertRaises(ValueError):session.complete()
                self.assertFalse(session._finished)
                self.close_session()

    def test_unissued_copied_or_reused_session_is_not_authority(self):
        fake=object.__new__(session_module.OwnedRecoverySSHSessionV3)
        with self.assertRaises(ValueError):session_module.issued(fake)
        session=self.open('simple')
        with self.assertRaises(ValueError):session_module.issued(copy.copy(session))
        with patch.object(session_module.os,'getpid',return_value=session._pid+1):
            with self.assertRaises(ValueError):session_module.issued(session)
        session.close()
        with self.assertRaises(ValueError):session_module.issued(session)

    def test_late_stderr_reader_keeps_transferred_descriptor(self):
        base=session_module.threading.Thread
        class LateReader(base):
            def run(self):time.sleep(.15);super().run()
        with patch.object(session_module.threading,'Thread',LateReader):session=self.open('simple')
        time.sleep(.3)
        self.assertEqual(session._errors,[])
        session.close();self.assertTrue(session._finished)


class SourceFactsTests(unittest.TestCase):
    def test_host_mode_requires_dependencies_and_explicit_startup_budget(self):
        with patch.object(session_module.loader,'published_manager_archive') as fetch:
            for daemon,resources,timeout in ((False,False,60),(True,False,60),(True,True,30)):
                with self.assertRaises(ValueError):session_module.OwnedRecoverySSHSessionV3(None,'host-one','b'*40,
                    verify_daemon_stop=daemon,verify_resource_inventory=resources,verify_host_snapshot=True,timeout=timeout)
            fetch.assert_not_called()
    def test_unsupported_local_platform_rejects_before_source_or_ssh_access(self):
        with patch.object(session_module.os,'name','nt'),\
                patch.object(session_module.loader,'published_manager_archive') as fetch:
            with self.assertRaises(ValueError):session_module.OwnedRecoverySSHSessionV3(None,'host-one','b'*40)
            fetch.assert_not_called()

    def test_owned_producer_facts_do_not_come_from_request_and_drift_rejects(self):
        root=Path(tempfile.gettempdir()).resolve()/('dw-engine-'+'a'*16)
        project='dw-restore-'+'2'*24
        producer=TrustedPhaseStateProducerV3(socket_path=str(root/'docker.sock'),project=project,
            daemon_id='daemon-one',container_ids=('1'*64,))
        version=dict(Version='29.8.2',GitCommit='8af9fe3')
        session=SimpleNamespace(project=project,producer=producer,target=SimpleNamespace(socket=producer._socket_path),
            guard=SimpleNamespace(_root=str(root/'data'),_version=version),
            prepared=SimpleNamespace(request=SimpleNamespace(target=SimpleNamespace(namespace='candidate-project'))))
        for attack in ('valid','daemon','root','version','project'):
            with self.subTest(attack=attack):
                info=dict(ID='other' if attack=='daemon' else 'daemon-one',
                    DockerRootDir='/wrong' if attack=='root' else str(root/'data'))
                profile=dict(version,GitCommit='wrong') if attack=='version' else version
                session.project='other' if attack=='project' else project
                frames=[]
                channel=SimpleNamespace(config=dict(sourceSha='b'*40,archiveDigest='c'*64,hostId='host-one'),
                    emit=lambda kind,**data:frames.append((kind,data)))
                def get(path):return info if path=='/v1.45/info' else profile
                with patch.object(producer,'_get',side_effect=get) as read:
                    if attack=='valid':
                        worker.emit_managed_source_facts(channel,session,root)
                        self.assertEqual(frames[0][1]['project'],project)
                        self.assertEqual(frames[0][1]['normalizationVersion'],version)
                        self.assertEqual([c.args[0] for c in read.call_args_list],['/v1.45/info','/v1.45/version'])
                    else:
                        with self.assertRaises(ValueError):worker.emit_managed_source_facts(channel,session,root)
                        self.assertEqual(frames,[])


if __name__=='__main__':unittest.main()
