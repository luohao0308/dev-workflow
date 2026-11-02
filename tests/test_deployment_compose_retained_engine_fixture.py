"""Real fixture history crypto/Unix I/O; unit Engine and kernel remain doubles."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
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
