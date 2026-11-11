"""Native TLS/Gate/witness/status first create; provider/Engine/kernel doubles."""
import os,shutil,unittest
from tests.support.compose_scene_create_integration_fixture import run_case


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'POSIX/OpenSSL/OpenSSH required')
class WorkerIntegrationTests(unittest.TestCase):
    def test_first_create_closes_native_signed_history_once(self):
        result=run_case(self)
        self.assertEqual(result['postCount'],1)
        self.assertFalse(result['terminal']['runtimePermit'])
        self.assertTrue(result['nativeGateTLSSSHSIG'])
    def test_forged_consumption_status_key_and_nonce_never_post(self):
        for attack in ('fake-consumption','wrong-status-key','wrong-status-nonce','revoked-ledger','unconsumed-status'):
            with self.subTest(attack=attack):self.assertEqual(run_case(self,attack)['postCount'],0)


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'POSIX/OpenSSL/OpenSSH required')
class SceneControllerIntegrationTests(unittest.TestCase):
    def test_controller_broker_first_create_cert_and_original_cleanup(self):
        self.assertEqual(run_case(self,scene_controller=True)['postCount'],1)
    def test_json_consumed_and_wrong_status_root_never_create(self):
        for attack in ('fake-consumption','wrong-status-key'):
            with self.subTest(attack=attack):self.assertEqual(run_case(self,attack,scene_controller=True)['postCount'],0)

    def test_lost_controller_freezes_original_attempt_before_post(self):
        self.assertEqual(run_case(self,'controller-lost',scene_controller=True)['postCount'],0)
    def test_bad_closure_phase_drift_and_unclean_worker_keep_pending(self):
        for attack in ('bad-closure','native-phase-drift','unclean-worker-exit'):
            with self.subTest(attack=attack):self.assertEqual(run_case(self,attack,scene_controller=True)['postCount'],1)
