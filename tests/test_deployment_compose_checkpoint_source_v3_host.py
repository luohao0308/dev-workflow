"""Native Git/Merkle/ZIP checks plus original session checkpoint archive custody."""
from copy import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_checkpoint_source_v3_host as source
import deployment_compose_checkpoint_archive_v3_host as custody
from deployment_compose_witness_store import canonical


@unittest.skipUnless(os.name=='posix' and Path('/usr/bin/git').exists(),'POSIX/native Git required')
class GitArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.repo=Path(temporary.name).resolve()
        self.git('init','-q');self.git('config','user.email','fixture@example.test');self.git('config','user.name','Fixture')
        self.git('remote','add','origin',source.ORIGIN)
        for name in source.REQUIRED|{'scripts/deployment_compose_unit_fixture.py'}:
            file=self.repo/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(('# '+name+'\n').encode())
        self.git('add','.');self.git('commit','-qm','source fixture')
        self.sha=self.git('rev-parse','HEAD').decode().strip()
        self.raw=self.archive()

    def git(self,*args):
        return subprocess.run(['/usr/bin/git','-C',str(self.repo),*args],capture_output=True,check=True,timeout=10).stdout

    def archive(self,changes=None,extra=None,duplicate=False,mode=None):
        changes={} if changes is None else changes
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as zipped:
            for name in sorted(source.REQUIRED|{'scripts/deployment_compose_unit_fixture.py'}):
                if changes.get(name) is None and name in changes:continue
                data=changes.get(name,(self.repo/name).read_bytes())
                info=zipfile.ZipInfo(name);info.compress_type=zipfile.ZIP_DEFLATED
                if mode is not None:info.external_attr=mode<<16
                zipped.writestr(info,data)
            if extra is not None:zipped.writestr(*extra)
            if duplicate:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore');zipped.writestr(sorted(source.REQUIRED)[0],b'duplicate')
        return output.getvalue()

    def verify(self,raw=None,**changes):
        raw=self.raw if raw is None else raw
        args=dict(repository=self.repo,source_sha=self.sha,archive_digest=hashlib.sha256(raw).hexdigest())
        args.update(changes)
        return source._verify_archive(raw,**args)

    def test_native_commit_tree_blob_bytes_match_original_archive_without_current_head_requirement(self):
        manifest=json.loads(self.verify());self.assertEqual(len(manifest),5)
        self.git('commit','--allow-empty','-qm','new verifier revision')
        (self.repo/'scripts/deployment_compose_unit_fixture.py').write_text('dirty current worktree\n')
        self.assertEqual(json.loads(self.verify()),manifest)
        self.assertEqual({row['path'] for row in manifest},source.REQUIRED|{'scripts/deployment_compose_unit_fixture.py'})

    def test_wrong_origin_oid_pin_or_timeout_rejects(self):
        for args in (dict(source_sha='0'*40),dict(archive_digest='0'*64),dict(timeout=0),dict(timeout=True),dict(timeout=float('nan'))):
            with self.subTest(args=args),self.assertRaises(Exception):self.verify(**args)
        self.git('remote','set-url','origin','https://example.invalid/other.git')
        with self.assertRaises(ValueError):self.verify()

    def test_changed_missing_extra_duplicate_and_special_members_reject(self):
        name=sorted(source.REQUIRED)[0]
        variants=[self.archive(changes={name:b'changed'}),self.archive(changes={name:None}),
            self.archive(extra=('scripts/deployment_compose_extra.py',b'extra')),
            self.archive(extra=('../outside.py',b'extra')),self.archive(duplicate=True),
            self.archive(mode=stat.S_IFLNK|0o777),self.archive(mode=stat.S_IFIFO|0o600)]
        for raw in variants:
            with self.subTest(digest=hashlib.sha256(raw).hexdigest()),self.assertRaises(Exception):self.verify(raw)

    def test_git_symlink_and_tampered_native_object_are_rejected(self):
        path=self.repo/'scripts/deployment_compose_unit_fixture.py';original=path.read_bytes()
        path.unlink();path.symlink_to('another.py');self.git('add','.');self.git('commit','-qm','symlink')
        self.sha=self.git('rev-parse','HEAD').decode().strip()
        with self.assertRaises(ValueError):self.verify()
        # A loose object whose filename claims a different object ID must fail
        # even if cat-file itself returns its readable bytes without fsck.
        path.unlink();path.write_bytes(original);self.git('add','.');self.git('commit','-qm','regular again')
        self.sha=self.git('rev-parse','HEAD').decode().strip()
        blob=self.git('rev-parse',self.sha+':scripts/deployment_compose_unit_fixture.py').decode().strip()
        import zlib
        object_path=self.repo/'.git/objects'/blob[:2]/blob[2:]
        object_path.chmod(0o600)
        wrong=b'altered blob';object_path.write_bytes(zlib.compress(b'blob '+str(len(wrong)).encode()+b'\0'+wrong))
        with self.assertRaises(Exception):self.verify()

    def test_git_replace_ref_does_not_replace_pinned_object(self):
        original=self.sha
        (self.repo/'scripts/deployment_compose_unit_fixture.py').write_text('replacement\n')
        self.git('add','.');self.git('commit','-qm','replacement')
        replacement=self.git('rev-parse','HEAD').decode().strip()
        self.git('replace',original,replacement)
        self.assertEqual(len(json.loads(self.verify())),5)

    def test_bound_public_result_rechecks_reader_and_exposes_only_consistency(self):
        from deployment_contract_v2 import SourceIdentity
        identity=SourceIdentity('github.com',source.ORIGIN,1327491026,'luohao0308/dev-workflow',self.sha)
        bound=(self.raw,identity,dict(sourceSha=self.sha,archiveDigest=hashlib.sha256(self.raw).hexdigest()),'c'*64)
        marker=object()
        with patch.object(custody,'read_bound_source_archive',return_value=bound) as reads:
            result=source.verify_checkpoint_published_source(marker,repository=self.repo)
        self.assertEqual(reads.call_count,2)
        self.assertTrue(result.publishedSourceArchiveVerified)
        self.assertTrue(result.gitObjectContentsVerified)
        for name in ('sourceRevalidated','currentPublicationVerified','approvalReady','authorityGranted','runtimePermit','recoveryAuthorized','productionReady'):
            self.assertFalse(getattr(result,name))
        self.assertNotIn('manifest_bytes',result.public_summary())
        with patch.object(custody,'read_bound_source_archive',side_effect=[bound,(*bound[:3],'d'*64)]):
            with self.assertRaises(ValueError):source.verify_checkpoint_published_source(marker,repository=self.repo)


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class ArchiveCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.support.compose_restart_checkpoint_fixture import produce
        cls.temporary=tempfile.TemporaryDirectory();cls.root=Path(cls.temporary.name).resolve();cls.root.chmod(0o700)
        cls.produced=produce(cls.root);cls.descriptor=cls.produced['descriptor']
        cls.case=Path(cls.descriptor['casePath'])

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def reader(self):
        from deployment_compose_restart_checkpoint_v3_host import RestartCheckpointReaderV3
        d=self.descriptor
        return RestartCheckpointReaderV3(self.case,expected_material_digest=d['materialDigest'],
            expected_custody_digest=d['custodyDigest'],expected_context=d['context'],expected_witness_key_hash=d['witnessKeyHash'],
            expected_origin_material_digest=d['writerOriginMaterialDigest'],expected_origin_digest=d['writerOriginDigest'])

    def test_native_controller_retains_original_sent_bytes_and_cold_reader_reads(self):
        d=self.descriptor;self.assertEqual(d['sourceArchiveDigest'],hashlib.sha256(b'fixture-code').hexdigest())
        path=self.case/'source-archive/archive.private.zip'
        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        with self.reader() as reader:
            raw,identity,pins,material=custody.read_bound_source_archive(reader)
            self.assertEqual(raw,b'fixture-code');self.assertEqual(identity.source_sha,pins['sourceSha'])
            self.assertEqual(material,d['materialDigest'])
            # The synthetic local session fixture never claimed to contain a ZIP.
            with self.assertRaises(ValueError):source.verify_checkpoint_published_source(reader,repository=ROOT)
        self.assertEqual(self.produced['secondConsumptionCount'],0)

    def test_bad_archive_permissions_replacement_and_closed_reader_reject(self):
        path=self.case/'source-archive/archive.private.zip';original=path.read_bytes()
        with self.reader() as reader:
            path.chmod(0o644)
            try:
                with self.assertRaises(ValueError):custody.read_source_archive(reader)
            finally:path.chmod(0o600)
            path.write_bytes(b'bad bytes')
            try:
                with self.assertRaises(ValueError):custody.read_source_archive(reader)
            finally:path.write_bytes(original)
        with self.assertRaises(ValueError):custody.read_source_archive(reader)
        for unissued in (None,object(),{}):
            with self.assertRaises(ValueError):custody.read_source_archive(unissued)


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class SourceProcessTests(unittest.TestCase):
    git=GitArchiveTests.git
    archive=GitArchiveTests.archive
    setUp=GitArchiveTests.setUp

    def test_native_checkpoint_producer_exits_before_fresh_source_consumer(self):
        directory=self.repo/'private';directory.mkdir(mode=0o700)
        archive=self.repo/'input.private.zip';archive.write_bytes(self.raw);archive.chmod(0o600)
        script=ROOT/'tests/support/compose_checkpoint_source_fixture.py'
        producer=subprocess.run([sys.executable,str(script),'produce',str(directory),str(self.repo),self.sha,str(archive)],
            capture_output=True,text=True,timeout=120)
        self.assertEqual(producer.returncode,0,producer.stderr)
        value=json.loads(producer.stdout)
        self.assertTrue(value['controllerClosed']);self.assertEqual(value['newRecoveryConsumptions'],0)
        consumer=subprocess.run([sys.executable,str(script),'consume'],input=producer.stdout,
            capture_output=True,text=True,timeout=60)
        self.assertEqual(consumer.returncode,0,consumer.stderr)
        result=json.loads(consumer.stdout)
        self.assertNotEqual(result['producerPid'],result['consumerPid'])
        self.assertTrue(result['summary']['publishedSourceArchiveVerified'])
        self.assertEqual(result['summary']['source_sha'],self.sha)
        self.assertEqual(result['summary']['archive_digest'],hashlib.sha256(self.raw).hexdigest())
        self.assertFalse(result['summary']['sourceRevalidated'])
        self.assertFalse(result['summary']['runtimePermit'])


@unittest.skipUnless(os.name=='posix' and Path('/usr/bin/git').exists(),'POSIX/native Git required')
class PartialCloneBoundaryTests(unittest.TestCase):
    git=GitArchiveTests.git
    archive=GitArchiveTests.archive
    verify=GitArchiveTests.verify
    setUp=GitArchiveTests.setUp

    def test_direct_and_included_promisor_configuration_reject_before_object_reads(self):
        for included in (False,True):
            if included:
                settings=self.repo/'included.private.cfg'
                settings.write_text('[remote "private"]\n  promisor = true\n  url = ext::unused-helper\n')
                self.git('config','include.path',str(settings))
            else:self.git('config','remote.private.promisor','true')
            original=source._Git.object
            with self.subTest(included=included),patch.object(source._Git,'object',autospec=True,side_effect=original) as read:
                with self.assertRaises(ValueError):self.verify()
                read.assert_not_called()
            if not included:self.git('config','--unset','remote.private.promisor')

    def test_null_delimited_promisor_key_with_newline_is_rejected(self):
        original=source._Git.run
        def configuration(instance,args,limit):
            if args==['config','--includes','--null','--name-only','--list']:
                return b'remote.hidden\nremote.promisor\0'
            return original(instance,args,limit)
        with patch.object(source._Git,'run',configuration),\
                patch.object(source._Git,'object',side_effect=AssertionError('unexpected object read')):
            with self.assertRaises(ValueError):self.verify()


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class SourceSessionBoundaryTests(unittest.TestCase):
    def test_original_cache_rejects_copy_thread_process_change_diagnostic_and_close(self):
        from tests.test_deployment_compose_owned_recovery_session_v3_host import SessionTests
        import deployment_compose_owned_recovery_session_v3_host as sessions
        harness=SessionTests('test_full_managed_flow_checks_independent_history_and_manager_completion')
        self.addCleanup(harness.doCleanups)
        session=harness.open('simple')
        self.assertEqual(sessions.session_source_archive(session),b'fixture-code')
        with self.assertRaises(ValueError):sessions.session_source_archive(copy(session))
        errors=[]
        def read():
            try:sessions.session_source_archive(session)
            except ValueError:errors.append(True)
        thread=threading.Thread(target=read);thread.start();thread.join(timeout=5)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[True])
        original=session._process;session._process=object()
        try:
            with self.assertRaises(ValueError):sessions.session_source_archive(session)
        finally:session._process=original
        session.close()
        with self.assertRaises(ValueError):sessions.session_source_archive(session)
        diagnostic=harness.open('simple',diagnostic=True)
        with self.assertRaises(ValueError):sessions.session_source_archive(diagnostic)

    def test_archive_publication_failure_stops_before_second_review_and_callback(self):
        from tests.test_deployment_compose_owned_recovery_session_v3_host import SessionTests
        from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase
        from types import SimpleNamespace
        import deployment_compose_owned_recovery_controller_v3_host as controller
        harness=SessionTests('test_full_managed_flow_checks_independent_history_and_manager_completion')
        self.addCleanup(harness.doCleanups)
        session=harness.open(verify_daemon=True,verify_resources=True,verify_host=True)
        owner=SimpleNamespace(reviewed=[]);base=LocalAcceptanceCase.review_adapter(owner);second=[];notices=[]
        class Review:
            def consume_prepared(self,bundle,request,notice):
                if request.operation=='recovery':second.append(True)
                return base.consume_prepared(bundle,request,notice)
            def close(self):pass
        with patch.object(custody,'publish',side_effect=OSError('archive-fsync-failed')):
            with self.assertRaises(ValueError):
                controller._drive_managed_recovery_protocol(harness.root,session=session,review=Review(),
                    on_review=lambda value:None,on_restart_checkpoint=notices.append,timeout=100)
        self.assertEqual(notices,[]);self.assertEqual(second,[])
        self.assertEqual([request.operation for request in owner.reviewed],['deploy'])
        self.assertTrue(session.cleanup_report()['localProcessReaped'])
