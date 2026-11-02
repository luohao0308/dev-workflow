"""Actual service/client processes and Unix/HMAC; daemon/peer are explicit doubles."""
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_scene_service_v3_host as scene


@unittest.skipUnless(os.name=='posix','POSIX Unix sockets/processes required')
class SceneTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix="scene-",dir="/tmp");self.addCleanup(self.temporary.cleanup)
        self.base=Path(self.temporary.name).resolve();self.base.chmod(0o700)
        self.scene_id='dw-scene-'+secrets.token_hex(8);self.path=self.base/self.scene_id;self.path.mkdir(mode=0o700)
        self.key=secrets.token_bytes(32);keyfile=self.path/'control.key';keyfile.write_bytes(self.key);keyfile.chmod(0o600)
        if getattr(self,'writer_source_enabled',False):
            source=scene._signed(self.key,dict(kind='scene-loader-source-v3',sceneId=self.scene_id,sourceSha='a'*40,archiveDigest='b'*64))
            file=self.path/'loader-source.private.json';file.write_bytes(scene.canonical(source));file.chmod(0o600)
        self.marker=self.base/'owner-stopped'
        for item in (patch.object(scene,'BASE',self.base),patch.object(scene,'ROOT_UID',os.getuid()),
                patch.object(scene,'_peer',return_value=(os.getpid(),os.getuid(),os.getgid()))):
            item.start();self.addCleanup(item.stop)
        self.script=ROOT/'tests/support/compose_scene_service_fixture.py'
        self.process=subprocess.Popen([sys.executable,str(self.script),'serve',str(self.base),self.scene_id,str(self.marker),'6' if 'slow_stop' in self._testMethodName else '0',
             '.2' if 'idle_lease' in self._testMethodName else '30','0',
             'fail-drain' if 'failed_drain' in self._testMethodName else ''],
            stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup_service)
        end=time.monotonic()+5
        while not (self.path/'ready-marker').exists():
            if self.process.poll() is not None:self.fail(self.process.stderr.read().decode())
            self.assertLess(time.monotonic(),end);time.sleep(.01)
        self.handle=scene.SceneHandleV3(self.scene_id,str(self.path/'control.sock'),self.key)

    def cleanup_service(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
        self.process.stderr.close()

    def connect(self):return scene.SceneClientV3(self.handle)

    def test_disconnect_retains_owner_and_new_client_gets_new_generation(self):
        first=self.connect();one=first.status()
        self.assertTrue(one['controllerExclusive']);self.assertFalse(one['writerQuiescenceVerified'])
        with self.assertRaises(ValueError):self.connect()
        first.detach();self.assertFalse(self.marker.exists());self.assertIsNone(self.process.poll())
        second=self.connect();two=second.status()
        self.assertGreater(two['generation'],one['generation'])
        self.assertEqual(two['daemonBinding'],one['daemonBinding'])
        self.assertNotIn(self.key.hex(),repr(self.handle))
        result=second.close_scene();self.assertTrue(result['daemonStoppedVerified'])
        self.assertEqual(self.process.wait(timeout=5),0);self.assertTrue(self.marker.exists())

    def test_killed_controller_does_not_stop_service_and_next_process_reconnects(self):
        controller=subprocess.Popen([sys.executable,str(self.script),'client',str(self.base),self.scene_id],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            one=json.loads(controller.stdout.readline());controller.kill()
            self.assertEqual(controller.wait(timeout=5),-signal.SIGKILL)
        finally:
            if controller.poll() is None:controller.kill();controller.wait(timeout=3)
            controller.stdout.close();controller.stderr.close()
        time.sleep(.05)
        self.assertIsNone(self.process.poll());self.assertFalse(self.marker.exists())
        client=self.connect();two=client.status()
        self.assertGreater(two['generation'],one['generation']);client.close_scene()
        self.assertEqual(self.process.wait(timeout=5),0)

    def test_wrong_control_key_and_bad_frame_do_not_stop_owner(self):
        wrong=scene.SceneHandleV3(self.scene_id,self.handle.socketPath,b'z'*32)
        with self.assertRaises(ValueError):scene.SceneClientV3(wrong)
        with socket.socket(socket.AF_UNIX) as peer:
            peer.connect(self.handle.socketPath);peer.sendall(struct.pack('!I',8193))
        time.sleep(.05)
        self.assertFalse(self.marker.exists());client=self.connect();self.assertFalse(client.status()['runtimePermit'])
        client.close_scene();self.assertEqual(self.process.wait(timeout=5),0)

    def test_used_scene_identity_cannot_restart_or_adopt(self):
        self.connect().close_scene();self.assertEqual(self.process.wait(timeout=5),0)
        again=subprocess.run([sys.executable,str(self.script),'serve',str(self.base),self.scene_id,str(self.marker),'6' if 'slow_stop' in self._testMethodName else '0',
             '.2' if 'idle_lease' in self._testMethodName else '30','0',
             'fail-drain' if 'failed_drain' in self._testMethodName else ''],
            capture_output=True,timeout=5)
        self.assertNotEqual(again.returncode,0)

    def test_idle_lease_expires_without_stopping_daemon(self):
        first=self.connect();one=first.status();time.sleep(.4)
        with self.assertRaises(ValueError):first.status()
        self.assertFalse(self.marker.exists())
        second=self.connect();self.assertGreater(second.status()['generation'],one['generation'])
        second.close_scene();self.assertEqual(self.process.wait(timeout=5),0)

    def test_slow_stop_has_separate_bounded_reply_budget(self):
        client=self.connect();result=client.close_scene()
        self.assertTrue(result['daemonStoppedVerified']);self.assertEqual(self.process.wait(timeout=5),0)

    def test_stale_generation_and_replayed_sequence_reject(self):
        for corrupt in ('generation','seq'):
            client=self.connect();client.status()
            if corrupt=='generation':client._lease['generation']-=1
            else:client._seq=0
            with self.assertRaises(ValueError):client.status()
            client.close();time.sleep(.02)
            self.assertFalse(self.marker.exists())
        self.connect().close_scene();self.assertEqual(self.process.wait(timeout=5),0)

    def test_launcher_waits_for_published_ready_before_authenticating(self):
        from types import SimpleNamespace
        children=[]
        def launch(argv,**kwargs):
            self.assertIn('--property=Restart=no',argv)
            self.assertIn('--property=MemoryMax=256M',argv)
            identity=argv[-1]
            child=subprocess.Popen([sys.executable,str(self.script),'serve',str(self.base),identity,
                str(self.base/'launched-owner-stop'),'0','30','.2'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            children.append(child);return SimpleNamespace(returncode=0)
        started=time.monotonic()
        try:
            with patch.object(scene.units,'_environment'),patch.object(scene,'subprocess',SimpleNamespace(run=launch)):
                handle=scene.start_scene()
            self.assertGreaterEqual(time.monotonic()-started,.2)
            self.assertTrue((self.base/handle.sceneId/'ready-marker').exists())
            scene.client_scene(handle).close_scene()
            self.assertEqual(children[0].wait(timeout=5),0)
        finally:
            for child in children:
                if child.poll() is None:child.terminate();child.wait(timeout=5)
                child.stderr.close()


@unittest.skipUnless(os.name=='posix','POSIX Unix sockets required')
class WriterSceneTests(unittest.TestCase):
    writer_source_enabled=True
    setUp=SceneTests.setUp
    cleanup_service=SceneTests.cleanup_service
    connect=SceneTests.connect

    def test_reconnect_retains_original_writer_and_requires_drain_before_replacement(self):
        first=self.connect();one=first.reserve_writer(0)
        origin=one['writerSlot']['writerOrigin']
        first.detach();second=self.connect()
        self.assertEqual(second.status()['writerSlot']['writerOrigin'],origin)
        with self.assertRaises(ValueError):second.reserve_writer(1)
        time.sleep(.02);third=self.connect()
        drained=third.drain_writer(1);self.assertTrue(drained['writerSlot']['slotStoppedObserved'])
        two=third.reserve_writer(1)
        self.assertEqual(two['slotGeneration'],2)
        self.assertNotEqual(two['writerSlot']['writerOrigin']['unit'],origin['unit'])
        self.assertFalse(two['runtimePermit']);self.assertFalse(two['writerQuiescenceVerified'])
        closed=third.close_scene();self.assertEqual(closed['slotState'],'drained')
        self.assertTrue(closed['daemonStoppedVerified']);self.assertEqual(self.process.wait(timeout=5),0)

    def test_old_slot_generation_cannot_drain_new_slot(self):
        client=self.connect();client.reserve_writer(0)
        with self.assertRaises(ValueError):client.drain_writer(0)
        time.sleep(.02);replacement=self.connect()
        self.assertEqual(replacement.status()['slotState'],'waiting')
        replacement.drain_writer(1);replacement.close_scene()
        self.assertEqual(self.process.wait(timeout=5),0)

    def test_close_scene_failed_drain_rejects_client_stops_daemon_and_exits_nonzero(self):
        client=self.connect();client.reserve_writer(0)
        with self.assertRaises(ValueError):client.close_scene()
        self.assertNotEqual(self.process.wait(timeout=5),0)
        self.assertTrue(self.marker.exists())
