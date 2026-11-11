"""Fixed SSH protocol and pinned checkpoint seam; kernel/SSH peers are doubles."""
from copy import deepcopy
from dataclasses import replace
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),*(str(ROOT/p) for p in
    ('scripts','packs/deployment/scripts','packs/release/scripts'))]
import deployment_compose_cold_writer_ssh_v3_host as bridge
from deployment_compose_restart_checkpoint_v3_host import RestartCheckpointReaderV3
from deployment_compose_witness_store import canonical

ARCHIVE=b'fixture-verifier-source'
VERIFIER='e'*40
ORIGIN=dict(schemaVersion=1,kind='compose-owned-writer-origin-v3',sourceSha='a'*40,
    archiveDigest='b'*64,unit='dw-writer-host-'+'c'*16+'.service',
    kernelBoot='11111111-1111-1111-1111-111111111111',invocationId='d'*32,
    mainPid=123,mainStartTicks=456,cgroupDevice=1,cgroupInode=2,parentDevice=1,parentInode=3,
    pidNamespaceDevice=1,pidNamespaceInode=4)
BINDING=dict(materialDigest='f'*64,originMaterialDigest='1'*64,historyDigest='2'*64)
PEER=ROOT/'tests/support/compose_cold_writer_ssh_fixture.py'


def peer(mode):
    return subprocess.Popen([sys.executable,'-u',str(PEER),mode],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)


@unittest.skipUnless(os.name=='posix','POSIX binary pipe selectors required')
class ColdSSHTests(unittest.TestCase):
    def invoke(self,mode='good',**changes):
        raw=canonical(ORIGIN)
        options=dict(expected_origin_digest=hashlib.sha256(raw).hexdigest(),host_id='target-host',
            producer_source_sha=ORIGIN['sourceSha'],producer_archive_digest=ORIGIN['archiveDigest'],
            verifier_source_sha=VERIFIER,checkpoint_binding=BINDING,timeout=5)
        options.update(changes);created=[];self.argv=[]
        def spawn(argv):
            self.argv.append(argv);process=peer(mode);created.append(process);return process
        try:
            with patch.object(bridge,'published_cold_archive',return_value=ARCHIVE), \
                 patch.object(bridge,'_private_spawn',side_effect=spawn):
                return bridge.observe_origin_over_ssh(raw,**options)
        finally:
            for process in created:
                self.assertIsNotNone(process.poll())
                self.assertTrue(all(stream.closed for stream in (process.stdin,process.stdout,process.stderr)))

    def test_new_verifier_checks_old_producer_and_binds_checkpoint_without_authority(self):
        result=self.invoke()
        self.assertTrue(result.sshDeliveryVerified)
        self.assertTrue(result.writerStoppedObserved)
        self.assertTrue(result.checkpointBound)
        self.assertEqual(result.producer_source_sha,ORIGIN['sourceSha'])
        self.assertEqual(result.producer_archive_digest,ORIGIN['archiveDigest'])
        self.assertEqual(result.verifier_source_sha,VERIFIER)
        self.assertEqual(result.verifier_archive_digest,hashlib.sha256(ARCHIVE).hexdigest())
        self.assertNotEqual(result.producer_archive_digest,result.verifier_archive_digest)
        self.assertEqual(result.checkpoint_binding,canonical(BINDING))
        for name in ('authorityGranted','runtimePermit','recoveryAuthorized','productionReady','daemonStoppedVerified'):
            self.assertIs(getattr(result,name),False)
        self.assertIn('StrictHostKeyChecking=yes',self.argv[0])
        self.assertIn('ForwardAgent=no',self.argv[0])
        self.assertEqual(self.argv[0][-2],'target-host')

    def test_origin_only_smoke_explicitly_has_no_checkpoint_subject(self):
        self.assertFalse(self.invoke(checkpoint_binding=None).checkpointBound)

    def test_wrong_echo_pins_nonce_flags_and_checkpoint_are_rejected(self):
        for mode in ('nonce','host','verifier-source','verifier-archive','producer-source',
                'producer-archive','request','origin','observation-hash','bool','authority','bound',
                'checkpoint','extra-field'):
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.invoke(mode)

    def test_consistent_hashes_do_not_accept_contradictory_kernel_observations(self):
        for mode in ('boot','namespace','active','populated','tree-inode','unequal'):
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.invoke(mode)

    def test_clean_eof_ssh_zero_and_stderr_eof_are_required(self):
        for mode in ('partial','oversized','extra-output','warning','nonzero'):
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.invoke(mode)
        with self.assertRaises(ValueError):self.invoke('held-stderr',timeout=.4)
        with self.assertRaises(ValueError):self.invoke('hang',timeout=.2)

    def test_extra_input_is_not_accepted_as_a_second_request(self):
        original=bridge.write_frame
        def extra(stream,value,**kwargs):
            original(stream,value,**kwargs);os.write(stream.fileno(),b'x')
        with patch.object(bridge,'write_frame',side_effect=extra),self.assertRaises(ValueError):self.invoke()

    def test_bad_configuration_and_unpublished_code_never_spawn(self):
        raw=canonical(ORIGIN)
        options=dict(expected_origin_digest=hashlib.sha256(raw).hexdigest(),host_id='target-host',
            producer_source_sha=ORIGIN['sourceSha'],producer_archive_digest=ORIGIN['archiveDigest'],
            verifier_source_sha=VERIFIER)
        with patch.object(bridge,'_private_spawn') as spawn:
            for changes in (dict(host_id='-oProxyCommand=x'),dict(expected_origin_digest='0'*64),
                    dict(producer_source_sha='0'*40),dict(checkpoint_binding={}),dict(timeout=True)):
                with self.assertRaises(ValueError):bridge.observe_origin_over_ssh(raw,**dict(options,**changes))
            with patch.object(bridge,'published_cold_archive',side_effect=ValueError('not published')):
                with self.assertRaises(ValueError):bridge.observe_origin_over_ssh(raw,**options)
            spawn.assert_not_called()

    def test_bootstrap_rejects_duplicate_and_noncanonical_input_before_fixed_worker(self):
        package=io.BytesIO()
        with zipfile.ZipFile(package,'w') as archive:
            archive.writestr('scripts/deployment_compose_cold_writer_ssh_v3_host.py',
                "def run(config,stdin,stdout):\n stdout.write(b'FIXED-WORKER-RAN');stdout.flush()\n")
            archive.writestr('scripts/deployment_compose_v3_channel_worker.py','def write_frame(*args,**kwargs):pass\n')
        raw=package.getvalue();digest=hashlib.sha256(raw).hexdigest()
        config=dict(entrypoint=bridge.ENTRYPOINT,sourceSha=VERIFIER,archiveDigest=digest,hostId='target-host',
            channelNonce='f'*64,origin=ORIGIN,originDigest=hashlib.sha256(canonical(ORIGIN)).hexdigest(),
            producerSourceSha=ORIGIN['sourceSha'],producerArchiveDigest=ORIGIN['archiveDigest'],
            checkpointBinding=None,archiveBase64=base64.b64encode(raw).decode())
        code=bridge.cold_bootstrap(digest,VERIFIER)
        valid=canonical(config)
        for index,body in enumerate((valid,b'{"hostId":"first",'+valid[1:],json.dumps(config,indent=1).encode())):
            result=subprocess.run([sys.executable,'-I','-c',code],
                input=struct.pack('!I',len(body))+body,capture_output=True,timeout=10)
            if index==0:
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,b'FIXED-WORKER-RAN')
            else:
                self.assertNotEqual(result.returncode,0)
                self.assertIn(b'cold-bootstrap-rejected',result.stderr)
                self.assertNotIn(b'FIXED-WORKER-RAN',result.stdout)


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
    'original managed checkpoint uses POSIX/OpenSSL/OpenSSH')
class ReaderSSHTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.support.compose_restart_checkpoint_fixture import produce
        cls.temp=tempfile.TemporaryDirectory(prefix='dw-reader-cold-ssh-')
        cls.root=Path(cls.temp.name).resolve();cls.root.chmod(0o700)
        cls.descriptor=produce(cls.root)['descriptor'];cls.case=Path(cls.descriptor['casePath'])
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def reader(self,with_origin=True):
        d=self.descriptor;options=dict(expected_material_digest=d['materialDigest'],expected_custody_digest=d['custodyDigest'],
            expected_context=d['context'],expected_witness_key_hash=d['witnessKeyHash'])
        if with_origin:options.update(expected_origin_material_digest=d['writerOriginMaterialDigest'],expected_origin_digest=d['writerOriginDigest'])
        return RestartCheckpointReaderV3(self.case,**options)

    def test_authenticated_reader_derives_host_and_request_subject_from_pinned_files(self):
        commands=[]
        def spawn(argv):commands.append(argv);return peer('good')
        with self.reader() as reader,patch.object(bridge,'published_cold_archive',return_value=ARCHIVE), \
             patch.object(bridge,'_private_spawn',side_effect=spawn):
            result=reader.observe_writer_stopped(verifier_source_sha=VERIFIER)
        self.assertTrue(result.checkpointBound)
        self.assertEqual(commands[0][-2],self.descriptor['context']['hostId'])
        binding=json.loads(result.checkpoint_binding)
        self.assertEqual(binding,dict(materialDigest=self.descriptor['materialDigest'],
            originMaterialDigest=self.descriptor['writerOriginMaterialDigest'],historyDigest=self.descriptor['context']['historyDigest']))
        self.assertFalse(result.runtimePermit)

    def test_original_producer_exits_before_new_reader_process_invokes_fixed_protocol(self):
        script=ROOT/'tests/support/compose_restart_checkpoint_fixture.py'
        with tempfile.TemporaryDirectory(prefix='dw-cold-reader-process-') as directory:
            root=Path(directory).resolve();root.chmod(0o700)
            producer=subprocess.run([sys.executable,str(script),'produce',str(root)],
                capture_output=True,text=True,timeout=120)
            self.assertEqual(producer.returncode,0,producer.stderr)
            produced=json.loads(producer.stdout)
            consumer=subprocess.run([sys.executable,str(PEER),'reader-consume'],
                input=json.dumps(produced['descriptor']),capture_output=True,text=True,timeout=60)
            self.assertEqual(consumer.returncode,0,consumer.stderr)
            result=json.loads(consumer.stdout)
            self.assertNotEqual(produced['producerPid'],result['consumerPid'])
            self.assertTrue(result['summary']['checkpointBound'])
            self.assertTrue(result['summary']['sshDeliveryVerified'])
            self.assertTrue(result['witnessUnchanged'])
            self.assertEqual(result['newApprovalConsumptions'],0)
            self.assertFalse(result['executionRecovered'])

    def test_missing_origin_closed_or_replaced_reader_never_spawns(self):
        with patch.object(bridge,'_private_spawn') as spawn:
            with self.reader(False) as legacy:
                with self.assertRaises(ValueError):legacy.observe_writer_stopped(verifier_source_sha=VERIFIER)
            for field in ('_guard','_store','_context'):
                with self.reader() as reader:
                    original=getattr(reader,field);setattr(reader,field,object())
                    try:
                        with self.assertRaises(ValueError):reader.observe_writer_stopped(verifier_source_sha=VERIFIER)
                    finally:setattr(reader,field,original)
            reader=self.reader();reader.close()
            with self.assertRaises(ValueError):reader.observe_writer_stopped(verifier_source_sha=VERIFIER)
            spawn.assert_not_called()

    def test_mutable_cached_host_cannot_retarget_network(self):
        with self.reader() as reader,patch.object(bridge,'_private_spawn') as spawn:
            history=reader.context.history
            original=history._request
            history._request=replace(original,host_id='attacker-host')
            try:
                with self.assertRaises(ValueError):reader.observe_writer_stopped(verifier_source_sha=VERIFIER)
            finally:history._request=original
            spawn.assert_not_called()

    def test_file_change_or_caller_close_during_network_rejects_even_a_valid_reply(self):
        path=self.case/'writer-origin/origin.private.json';original=path.read_bytes()
        with self.reader() as reader,patch.object(bridge,'published_cold_archive',return_value=ARCHIVE):
            def change(argv):path.write_bytes(b'{}');return peer('good')
            try:
                with patch.object(bridge,'_private_spawn',side_effect=change),self.assertRaises(ValueError):
                    reader.observe_writer_stopped(verifier_source_sha=VERIFIER)
            finally:path.write_bytes(original);path.chmod(0o600)
        reader=self.reader()
        with patch.object(bridge,'published_cold_archive',return_value=ARCHIVE):
            def close(argv):reader.close();return peer('good')
            with patch.object(bridge,'_private_spawn',side_effect=close),self.assertRaises(ValueError):
                reader.observe_writer_stopped(verifier_source_sha=VERIFIER)


if __name__=='__main__':unittest.main()
