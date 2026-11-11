"""Real fixture history crypto/Unix I/O; unit Engine and kernel remain doubles."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts','tests/support')]
from tests.support import compose_restart_material_fixture as restart_fixture
from tests import test_deployment_compose_live_phase_v3_host as live_fixture
from compose_retained_history_fixture import SyntheticClosedCreateHistory
import compose_retained_engine_fixture as retained
from compose_live_phase_fixture import start_witness_server,record
from deployment_compose_restart_material_v3_host import capture_material,reopen_material
from deployment_compose_witness_store import canonical


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class SyntheticHistoryTests(unittest.TestCase):
    def setUp(self):
        self.case=restart_fixture.RestartFixture();self.case.setUp();self.addCleanup(self.case.doCleanups)
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.subject=SyntheticClosedCreateHistory(self.root);self.addCleanup(self.subject.close)
        self.request=replace(self.case.req,policy_hash=self.subject.policy.identity_hash())

    def test_native_synthetic_history_reopens_without_product_authority(self):
        history=self.subject.close_create(self.case.bundle,self.request,'a'*64)
        snapshot=history.capture();self.assertEqual(snapshot.snapshot['chainStatus']['activeSeq'],6)
        raw=capture_material(history,baseline_bytes=self.case.baseline_bytes,
            authenticated_image_defaults=self.case.defaults,archive_digest=restart_fixture.ARCHIVE_DIGEST)
        context=dict(sourceSha=self.request.source.source_sha,hostId=self.request.host_id,daemonId=self.request.daemon_id,
            archiveDigest=restart_fixture.ARCHIVE_DIGEST,historyDigest=snapshot.digest,
            baselineStateDigest=self.case.bundle.to_dict()['baselineStateDigest'])
        before=(self.subject.store.root/'state.json').read_bytes()
        reopened=reopen_material(raw,expected_digest=hashlib.sha256(raw).hexdigest(),expected_context=context,
            gate_key=self.subject.gate_key,witness_public_key=self.subject.public,witness_transport=self.subject.transport)
        self.assertEqual(reopened.snapshot.digest,snapshot.digest)
        self.assertEqual(before,(self.subject.store.root/'state.json').read_bytes())
        self.assertTrue(self.subject.syntheticFixtureHistory)
        self.assertFalse(self.subject.authorityGranted)
        with self.assertRaises(ValueError):self.subject.transport('transition_successor',{})
        with self.assertRaises(ValueError):self.subject.close_create(self.case.bundle,self.request,'b'*64)

    def test_foreign_policy_or_baseline_candidate_is_rejected_permanently(self):
        with self.assertRaises(ValueError):self.subject.close_create(self.case.bundle,self.case.req,'a'*64)
        with self.assertRaises(ValueError):self.subject.close_create(self.case.bundle,self.request,'a'*64)

    def test_remote_config_rejects_before_starting_daemon(self):
        good=dict(entrypoint=retained.ENTRYPOINT,sourceSha='a'*40,archiveDigest='b'*64,hostId='test-host',channelNonce='c'*64)
        for change in ({'extra':True},{'hostId':'x;false'},{'sourceSha':True},{'entrypoint':'other'}):
            with self.subTest(change=change),patch('deployment_compose_isolated_daemon_probe.probe') as start:
                with self.assertRaises(ValueError):retained.remote_main(dict(good,**change))
                start.assert_not_called()


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class NativeConsumerSeamTests(unittest.TestCase):
    identity=live_fixture.LivePhaseTests.identity
    ticks=live_fixture.LivePhaseTests.ticks
    command=live_fixture.LivePhaseTests.command
    stopped=live_fixture.LivePhaseTests.stopped
    make_capture=live_fixture.LivePhaseTests.make_capture

    def setUp(self):
        live_fixture.LivePhaseTests.setUp(self)
        self.directory=self.root/'handoff';self.directory.mkdir(mode=0o700)
        raw=self.case.material();pins=dict(expectedDigest=hashlib.sha256(raw).hexdigest(),expectedContext=self.case.expected_context())
        socket=self.root/'witness.sock'
        server,thread,self.rpc=start_witness_server(self.case,socket)
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=3)))
        config=dict(daemonRoot=str(self.root),witnessSocket=str(socket),gateKeyHex=restart_fixture.GATE_KEY.hex(),expectedVersion=self.case.version)
        for name,data in (('validated-material.private.json',raw),('pins.private.json',canonical(pins)),
                ('validated-pins.private.json',canonical(pins)),('witness.pub',self.case.public),('config.private.json',canonical(config))):
            record(self.directory/name,data)

    def test_sigkill_after_validated_ready_is_reaped_before_fresh_unix_consumer(self):
        raw=(self.directory/'validated-material.private.json').read_bytes()
        record(self.directory/'material.private.json',raw)
        (self.directory/'validated-material.private.json').unlink()
        (self.directory/'validated-pins.private.json').unlink()
        config=json.loads((self.directory/'config.private.json').read_text())
        config.update(cgroupRoot=str(self.cg),unit=self.unit,pid=self.pid,main=self.main,invocation=self.invocation)
        (self.directory/'config.private.json').write_bytes(canonical(config))
        order=[]
        def consumer(mode,directory,*,deadline=None):
            self.assertEqual(mode,'consume');order.append('consumer')
            self.assertTrue((directory/'producer-ready.private.json').exists())
            ready=json.loads((directory/'producer-ready.private.json').read_text())
            with self.assertRaises(ChildProcessError):os.waitpid(ready['producerPid'],os.WNOHANG)
            result=subprocess.run([sys.executable,str(ROOT/'tests/support/compose_live_phase_fixture.py'),
                'prepare',str(directory)],capture_output=True,text=True,timeout=retained._remaining(deadline))
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads(result.stdout)
        before=(self.case.store.root/'state.json').read_bytes()
        with patch.object(retained,'_child',side_effect=consumer):
            producer,result=retained._producer_consumer(self.directory,crash=True,
                after_producer=lambda:order.append('reaped'))
        self.assertEqual(order,['reaped','consumer'])
        self.assertEqual(producer['producerExitCode'],-signal.SIGKILL)
        self.assertEqual(producer['producerSignal'],signal.SIGKILL)
        self.assertIs(type(producer['producerSignal']),int)
        self.assertEqual(producer['producerExitMode'],'sigkill')
        self.assertTrue(producer['producerReadyVerified'])
        self.assertNotEqual(producer['producerPid'],result['consumerPid'])
        self.assertTrue(result['summary']['verified']);self.assertFalse(result['summary']['approvalReady'])
        self.assertEqual(before,(self.case.store.root/'state.json').read_bytes())

    def test_unknown_ready_fails_without_consumer_and_reaps_original_child(self):
        observed=[];original=subprocess.Popen
        def spawn(*args,**kwargs):
            process=original(*args,**kwargs);observed.append(process);return process
        with patch.object(retained.subprocess,'Popen',side_effect=spawn),\
                patch.object(retained,'_wait_ready_ack'),patch.object(retained,'_ready',side_effect=ValueError('unknown-ready')),\
                patch.object(retained,'_child') as consumer:
            with self.assertRaisesRegex(ValueError,'unknown-ready'):
                retained._producer_consumer(self.directory,crash=True)
            consumer.assert_not_called()
        self.assertEqual(len(observed),1)
        self.assertEqual(observed[0].returncode,-signal.SIGKILL)
        with self.assertRaises(ChildProcessError):os.waitpid(observed[0].pid,os.WNOHANG)

    def test_ready_link_exposes_only_complete_fsynced_bytes(self):
        pins=json.loads((self.directory/'pins.private.json').read_text())
        original_link=os.link;original_sync=os.fsync;synced=set();linked=[];acks=[]
        def sync(fd):
            info=os.fstat(fd);original_sync(fd);synced.add((info.st_dev,info.st_ino))
        def link(source,target,**kwargs):
            self.assertEqual(target,'producer-ready.private.json')
            self.assertFalse((self.directory/target).exists());self.assertEqual(acks,[])
            fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=kwargs['src_dir_fd'])
            try:
                info=os.fstat(fd);self.assertIn((info.st_dev,info.st_ino),synced)
                complete=os.read(fd,4097)
                self.assertEqual(canonical(json.loads(complete)),complete)
            finally:os.close(fd)
            original_link(source,target,**kwargs);linked.append(True)
        with patch.object(retained,'produce',return_value={'historyDigest':pins['expectedContext']['historyDigest']}),\
                patch.object(retained.os,'fsync',side_effect=sync),patch.object(retained.os,'link',side_effect=link),\
                patch.object(retained.os,'write',side_effect=lambda fd,data:acks.append(data) or len(data)),\
                patch.object(retained.time,'sleep',side_effect=RuntimeError('ready-published')):
            with self.assertRaisesRegex(RuntimeError,'ready-published'):retained.crash_produce(self.directory)
        self.assertEqual(linked,[True]);self.assertEqual(acks,[b'R'])
        for name in ('validated-material.private.json','validated-pins.private.json'):
            info=(self.directory/name).stat();self.assertIn((info.st_dev,info.st_ino),synced)
        self.assertEqual((self.directory/'producer-ready.private.json').stat().st_mode&0o777,0o600)

    def test_bad_ack_rejects_before_ready_read_or_consumer(self):
        with patch.object(retained,'_wait_ready_ack',side_effect=ValueError('bad-ack')),\
                patch.object(retained,'_ready') as ready,patch.object(retained,'_child') as consumer:
            with self.assertRaisesRegex(ValueError,'bad-ack'):
                retained._producer_consumer(self.directory,crash=True)
            ready.assert_not_called();consumer.assert_not_called()

    def test_unknown_byte_and_eof_are_not_ready_ack(self):
        import time
        for code in ("import os,time;os.write(1,b'X');time.sleep(2)","pass"):
            process=subprocess.Popen([sys.executable,'-c',code],stdout=subprocess.PIPE)
            try:
                with self.assertRaises(ValueError):retained._wait_ready_ack(process,time.monotonic()+2)
            finally:
                if process.poll() is None:process.kill()
                process.wait(timeout=3);process.stdout.close()

    def test_fsync_failure_prevents_crash_ready_publication(self):
        pins=json.loads((self.directory/'pins.private.json').read_text())
        with patch.object(retained,'produce',return_value={'historyDigest':pins['expectedContext']['historyDigest']}),\
                patch.object(retained.os,'fsync',side_effect=OSError('sync-failed')):
            with self.assertRaises(OSError):retained.crash_produce(self.directory)
        self.assertFalse((self.directory/'producer-ready.private.json').exists())

    def test_default_handoff_retains_normal_producer_order(self):
        with patch.object(retained,'_child',side_effect=[{'producerPid':1},{'consumerPid':2}]) as child,\
                patch.object(retained,'_crash_producer') as crash:
            producer,result=retained._producer_consumer(self.directory)
            crash.assert_not_called()
            self.assertEqual([call.args[0] for call in child.call_args_list],['produce','consume'])
            self.assertEqual(producer['producerExitMode'],'normal')
            self.assertEqual(producer['producerExitCode'],0)
            self.assertIsNone(producer['producerSignal'])
            self.assertEqual(result['consumerPid'],2)

    def test_native_consumer_prepares_then_cleaned_scene_rejects(self):
        # Only boot-id read is doubled here; systemd/proc/peer/Engine doubles are
        # inherited from the explicit live fixture. Real acceptance uses no patch.
        original=Path.read_text
        def text(path,*args,**kwargs):
            if str(path)=='/proc/sys/kernel/random/boot_id':return live_fixture.BOOT
            return original(path,*args,**kwargs)
        with patch.object(Path,'read_text',text):
            result=retained.consume(self.directory)
            self.assertTrue(result['draftVerified']);self.assertFalse(result['runtimePermit'])
            del self.case.rows['a'*64]
            self.assertTrue(retained.consume(self.directory,cleaned=True)['blockedAfterCleanup'])
        self.assertTrue(set(self.rpc)<={'read','check','events_after','chain_status'})
        self.assertGreaterEqual(self.http.count('/v1.45/version'),6)
