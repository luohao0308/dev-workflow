"""Real relay pipes + original Unix/HMAC; SSH/source and Linux peer are doubled."""
import os,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
from tests import test_deployment_compose_scene_service_v3_host as service_fixture
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_scene_control_ssh_v3_host as relay


@unittest.skipUnless(os.name=='posix','POSIX Unix sockets and pipes required')
class RelayTests(unittest.TestCase):
 setUp=service_fixture.SceneTests.setUp
 cleanup_service=service_fixture.SceneTests.cleanup_service
 def connect(self,attack=''):
  handle=relay.SceneSSHHandleV3(self.scene_id,'/var/tmp/'+self.scene_id+'/control.sock',self.key,'host-one','a'*40,b'fixed-source-double')
  def spawn(handle,code):
   self.assertIn(relay.ENTRYPOINT,code)
   inherited=None
   if attack=='held-stderr':
    reader,inherited=os.pipe();self.addCleanup(os.close,inherited)
   process=subprocess.Popen([sys.executable,str(ROOT/'tests/support/compose_scene_control_ssh_fixture.py'),str(self.base),attack],
       stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE if inherited is None else inherited,bufsize=0)
   if inherited is not None:process.stderr=os.fdopen(reader,'rb',buffering=0)
   return process
  with patch.object(relay,'_verify_source'),patch.object(relay,'_spawn',side_effect=spawn):return relay.SceneSSHClientV3(handle)
 def test_original_client_authentication_reconnect_and_clean_terminal(self):
  first=self.connect();one=first.status();first.detach();self.assertTrue(first._closed)
  second=self.connect();two=second.status();self.assertGreater(two['generation'],one['generation'])
  closed=second.close_scene();self.assertTrue(closed['daemonStoppedVerified']);self.assertTrue(second._closed)
  self.assertEqual(self.process.wait(timeout=5),0);self.assertTrue(self.marker.exists())
 def test_wrong_ready_nonce_and_oversize_command_close_only_owned_relay(self):
  with self.assertRaises(ValueError):self.connect('nonce')
  client=self.connect()
  with self.assertRaises(ValueError):client._call('worker_reply_chunk',{'dataBase64':'x'*9000})
  self.assertTrue(client._closed);self.assertIsNotNone(client._process.poll());self.assertIsNone(self.process.poll())
  self.connect().close_scene();self.assertEqual(self.process.wait(timeout=5),0)
 def test_late_stderr_or_nonzero_exit_cannot_claim_clean_detach(self):
  for attack in ('stderr','exit'):
   client=self.connect(attack);client.status()
   with self.subTest(attack=attack),self.assertRaises(ValueError):client.detach()
   self.assertTrue(client._closed);self.assertIsNotNone(client._process.poll())
  self.connect().close_scene();self.assertEqual(self.process.wait(timeout=5),0)

 def test_exit_zero_with_inherited_stderr_fd_is_bounded_failure(self):
  import time
  client=self.connect('held-stderr');client.status();start=time.monotonic()
  with patch.object(relay,'END_TIMEOUT',.2),self.assertRaises(ValueError):client.detach()
  self.assertLess(time.monotonic()-start,2);self.assertTrue(client._closed)
  self.assertEqual(client._process.returncode,0)
  self.connect().close_scene();self.assertEqual(self.process.wait(timeout=5),0)

 def test_boolean_response_or_terminal_sequence_is_not_integer_one(self):
  for attack in ('seq-bool','terminal-bool'):
   client=self.connect(attack)
   with self.subTest(attack=attack),self.assertRaises(ValueError):
    if attack=='seq-bool':client.status()
    else:client.detach()
   self.assertTrue(client._closed)
  self.connect().close_scene();self.assertEqual(self.process.wait(timeout=5),0)
