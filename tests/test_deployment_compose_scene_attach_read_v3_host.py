"""Fixed attachment validation and actual Unix GETs; kernel identities doubled."""
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile
from tests import test_deployment_compose_recovery_daemon_v3_host as native_fixture
from tests import test_deployment_compose_scene_writer_slot_v3_host as slots_fixture
import deployment_compose_scene_attach_read_v3_host as attached
import deployment_compose_scene_writer_slot_v3_host as slots
import deployment_compose_recovery_daemon_v3_host as daemon
from deployment_compose_witness_store import canonical
from deployment_compose_v3_channel_worker import read_frame


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve()
        for name in ('scripts/deployment_compose_scene_attach_read_v3_host.py','scripts/deployment_compose_recovery_daemon_v3_host.py'):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'# trusted distribution\n')
        patcher=patch.object(attached,'ROOT',self.root);patcher.start();self.addCleanup(patcher.stop)
    def archive(self,changed=False,extra=False):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as archive:
            for file in self.root.rglob('*.py'):
                archive.writestr(file.relative_to(self.root).as_posix(),b'injected' if changed else file.read_bytes())
            if extra:archive.writestr('scripts/deployment_compose_extra.py',b'extra')
        return out.getvalue()
    def test_archive_must_equal_service_distribution_not_only_control_signed_hash(self):
        raw=self.archive();self.assertEqual(attached.validate_distribution_archive(raw,hashlib.sha256(raw).hexdigest()),raw)
        for raw in (self.archive(changed=True),self.archive(extra=True)):
            with self.assertRaises(ValueError):attached.validate_distribution_archive(raw,hashlib.sha256(raw).hexdigest())
    def test_distribution_symlink_and_wrong_external_digest_reject(self):
        raw=self.archive()
        with self.assertRaises(ValueError):attached.validate_distribution_archive(raw,'0'*64)
        file=next(self.root.rglob('*.py'));copy=self.root/'other';copy.write_bytes(file.read_bytes());file.unlink();file.symlink_to(copy)
        with self.assertRaises(ValueError):attached.validate_distribution_archive(raw,hashlib.sha256(raw).hexdigest())


@unittest.skipUnless(os.name=='posix','Unix sockets and pipes required')
class WorkerTests(unittest.TestCase):
    identity=native_fixture.DaemonTests.identity
    ticks=native_fixture.DaemonTests.ticks
    command=native_fixture.DaemonTests.command
    def setUp(self):
        native_fixture.DaemonTests.setUp(self);self.patches[-1].stop()
        patcher=patch.object(daemon,'subprocess',SimpleNamespace(run=self.command));patcher.start();self.addCleanup(patcher.stop)
        self.observer=native_fixture.DaemonTests.observe(self)
        self.config=dict(entrypoint=attached.ENTRYPOINT,sourceSha='a'*40,archiveDigest='b'*64,
            channelNonce='c'*64,daemonBinding=self.observer.binding())
    def invoke(self,config=None,extra=b''):
        incoming,writer=os.pipe();output,reader=os.pipe()
        try:
            if extra:os.write(writer,extra)
            os.close(writer);writer=None
            with os.fdopen(incoming,'rb',buffering=0) as stdin,os.fdopen(reader,'wb',buffering=0) as stdout:
                reader=None;incoming=None
                attached.run(self.config if config is None else config,stdin,stdout)
            with os.fdopen(output,'rb',buffering=0) as result:
                output=None
                return read_frame(result,timeout=3)
        finally:
            for fd in (incoming,writer,output,reader):
                if fd is not None:
                    try:os.close(fd)
                    except OSError:pass
    def test_new_worker_reopens_same_native_daemon_and_only_reads_fixed_inventory(self):
        self.http.clear();result=self.invoke()
        self.assertTrue(result['readOnly']);self.assertFalse(result['runtimePermit'])
        self.assertEqual(result['bindingDigest'],hashlib.sha256(canonical(self.config['daemonBinding'])).hexdigest())
        self.assertEqual(self.http.count('/v1.45/containers/json?all=true'),2)
        self.assertTrue(all('stop' not in command for command in self.calls))
    def test_wrong_attachment_and_extra_input_never_get_inventory(self):
        self.http.clear()
        with self.assertRaises(ValueError):self.invoke(extra=b'x')
        self.assertEqual(self.http,[])
        changed=dict(self.config,daemonBinding=dict(self.config['daemonBinding'],mainStartTicks=999))
        with self.assertRaises(ValueError):self.invoke(changed)
        self.assertFalse(any('/containers/' in path for path in self.http))


class InspectSlotTests(unittest.TestCase):
    def test_success_requires_reply_and_original_drain_before_replacement(self):
        raw=b'fixed-read-distribution';sha=hashlib.sha256(raw).hexdigest()
        class Unit(slots_fixture.FakeUnit):pass
        Unit.instances=[]
        receipt=dict(readOnly=True,inventoryDigest='c'*64,authorityGranted=False,runtimePermit=False,productionReady=False)
        with patch.object(slots,'AttachReadUnitV3',Unit),patch.object(slots,'run_attached_read',return_value=receipt),\
                patch.object(slots,'observe_stopped_writer',return_value=SimpleNamespace(writerStoppedObserved=True,observation_digest='d'*64)):
            subject=slots.SlotOwnerV3('a'*40,sha);result=subject.inspect_attached(raw,{'root':'service-owned'},0)
            self.assertEqual(result['slotState'],'drained');self.assertEqual(result['closedReadReceipt'],receipt)
            self.assertEqual(Unit.instances[0].calls,['start','origin','stop','close'])
    def test_bad_read_reply_keeps_slot_failed_until_explicit_drain(self):
        raw=b'fixed-read-distribution';sha=hashlib.sha256(raw).hexdigest()
        class Unit(slots_fixture.FakeUnit):pass
        Unit.instances=[]
        with patch.object(slots,'AttachReadUnitV3',Unit),patch.object(slots,'run_attached_read',side_effect=ValueError('bad-read')):
            subject=slots.SlotOwnerV3('a'*40,sha)
            with self.assertRaises(ValueError):subject.inspect_attached(raw,{},0)
            self.assertEqual(subject.status()['slotState'],'failed')
            with self.assertRaises(ValueError):subject.reserve(1)


class WireUnit(slots_fixture.FakeUnit):
    attack=''
    def __init__(self,archive_digest,source_sha):
        super().__init__(archive_digest,source_sha)
        self._source_sha=source_sha;self._archive_digest=archive_digest;self._process=None
    def _check(self):pass
    def start(self,**kwargs):
        import subprocess
        self.calls.append('start')
        self._process=subprocess.Popen([sys.executable,str(Path(__file__).resolve().parent/'support/compose_scene_attach_wire_fixture.py'),self.attack],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    def stop(self,**kwargs):
        self.calls.append('stop')
        if self._process.poll() is None:self._process.terminate()
        self._process.wait(timeout=3)
    def close(self):
        self.calls.append('close')
        for stream in (self._process.stdin,self._process.stdout,self._process.stderr):stream.close()


@unittest.skipUnless(os.name=='posix','POSIX pipe protocol required')
class WireTests(unittest.TestCase):
    def test_real_frame_delivery_receipt_and_clean_exit_precede_native_drain(self):
        raw=b'fixed-archive';sha=hashlib.sha256(raw).hexdigest();WireUnit.attack=''
        with patch.object(slots,'AttachReadUnitV3',WireUnit),patch.object(attached,'AttachReadUnitV3',WireUnit),\
                patch.object(slots,'observe_stopped_writer',return_value=SimpleNamespace(writerStoppedObserved=True,observation_digest='d'*64)):
            subject=slots.SlotOwnerV3('a'*40,sha);result=subject.inspect_attached(raw,{'root':'trusted-scene'},0)
            self.assertEqual(result['slotState'],'drained');self.assertTrue(result['closedReadReceipt']['readOnly'])
            self.assertFalse(result['closedReadReceipt']['runtimePermit'])
    def test_wrong_nonce_write_claim_extra_output_stderr_and_exit_reject(self):
        raw=b'fixed-archive';sha=hashlib.sha256(raw).hexdigest()
        for attack in ('nonce','write','extra','stderr','exit'):
            WireUnit.attack=attack
            with self.subTest(attack=attack),patch.object(slots,'AttachReadUnitV3',WireUnit),\
                    patch.object(attached,'AttachReadUnitV3',WireUnit),\
                    patch.object(slots,'observe_stopped_writer',return_value=SimpleNamespace(writerStoppedObserved=True,observation_digest='d'*64)):
                subject=slots.SlotOwnerV3('a'*40,sha)
                try:
                    with self.assertRaises(ValueError):subject.inspect_attached(raw,{},0)
                    self.assertEqual(subject.status()['slotState'],'failed')
                    with self.assertRaises(ValueError):subject.reserve(1)
                finally:subject.drain(1)
