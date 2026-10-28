"""Published-package validation and owned local pipes; never SSH or Docker."""
import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import struct
import time
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'packs/deployment/scripts'),str(ROOT/'packs/release/scripts'),str(ROOT/'tests/support')]
import deployment_compose_profile3_prepare_ssh_probe as host

SHA='b'*40
NAMES=['scripts/deployment_compose_profile3_prepare_ssh_probe.py',
       'scripts/deployment_compose_isolated_daemon_probe.py','tests/support/compose_profile3_prepare_fixture.py',
       'core/scripts/published.py','packs/deployment/scripts/kept.py','packs/release/scripts/kept.py',
       'scripts/arbitrary.py','tests/test_not_support.py','untracked.py','README.md']


@unittest.skipUnless(os.name == 'posix', 'owned POSIX SSH pipe controller')
class PrepareSSHTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.spawns=[];self.processes=[];self.configs=[]

    def git(self,*args):
        if args==('rev-parse','HEAD'):return SHA.encode()+b'\n'
        if args==('remote','get-url','origin'):return host.ORIGIN.encode()+b'\n'
        if args==('ls-remote','--exit-code','origin',host.PUBLISHED_REF):return (SHA+'\t'+host.PUBLISHED_REF+'\n').encode()
        if args==('diff','--name-only','HEAD','--'):return b''
        if args==('ls-tree','-r','--name-only','-z',SHA):return '\0'.join(NAMES).encode()+b'\0'
        if args[0]=='show':return ('# published '+args[1]+'\n').encode()
        raise AssertionError(args)

    def local_spawn(self,argv):
        self.spawns.append(argv)
        self.assertEqual(argv[:-1],['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',
            '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','ForwardX11=no','-o','PermitLocalCommand=no','-T','unit-host'])
        command=shlex.split(argv[-1]);self.assertEqual(command[:5],['exec','python3','-I','-u','-c'])
        self.assertLess(len(command[-1]),6000)
        self.assertIn(SHA,command[-1]);self.assertIn(host.ENTRYPOINT,command[-1])
        # Own an actual pipe child; do not execute SSH or any remote Engine code.
        code="""import sys,base64,hashlib
sys.path[:0]=PATHS
from deployment_compose_v3_channel_worker import read_frame,write_frame
config=read_frame(sys.stdin.buffer)
assert hashlib.sha256(base64.b64decode(config['archiveBase64'])).hexdigest()==config['archiveDigest']
assert set(config['keys'])=={'config','image','declaration','archive','target'}
assert all(len(base64.b64decode(v))==32 for v in config['keys'].values())
result=dict(success=True,remoteRoot='/var/tmp/dw-engine-'+'1'*16,sourceSha=config['sourceSha'],preparationOnly=True,approvalAvailable=False,productWriterOpened=False,requestReusable=False,productionReady=False,daemonStopped=True,productionSnapshotUnchanged=True,sessionCleaned=True)
write_frame(sys.stdout.buffer,dict(channelNonce=config['channelNonce'],result=result))
""".replace('PATHS',repr([str(ROOT/'scripts'),str(ROOT/'packs/deployment/scripts')]))
        process=subprocess.Popen([sys.executable,'-I','-u','-c',code],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        self.processes.append(process)
        return process

    def run_probe(self,spawn=None):
        real_write=host.write_frame
        def write(stream,value,**kwargs):
            self.configs.append(deepcopy(value));return real_write(stream,value,**kwargs)
        with patch.object(host,'_git',self.git),patch.object(host,'_spawn',spawn or self.local_spawn),patch.object(host,'write_frame',write):
            return host.run_prepare_probe(self.root,'unit-host',SHA)

    def test_fixed_published_manifest_and_small_bound_bootstrap(self):
        with patch.object(host,'_git',self.git):archive=host._published_archive(SHA)
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            self.assertEqual(set(zipped.namelist()),{n for n in NAMES if host._allowed(n)})
            self.assertNotIn('untracked.py',zipped.namelist())
            self.assertNotIn('scripts/arbitrary.py',zipped.namelist())
        code=host._bootstrap(hashlib.sha256(archive).hexdigest(),SHA)
        self.assertIn(hashlib.sha256(archive).hexdigest(),code)
        self.assertNotIn(base64.b64encode(archive).decode(),code)
        with patch.object(host,'_git',self.git),patch.object(host,'MAX_ARCHIVE',1),self.assertRaises(ValueError):host._published_archive(SHA)

    def test_wrong_source_dirty_code_origin_alias_and_root_before_spawn(self):
        with patch.object(host,'_spawn') as spawn,patch.object(host,'_git',self.git):
            for alias in ('-host','host;bad','host/name','host name',''):
                with self.subTest(alias=alias),self.assertRaises(ValueError):host.run_prepare_probe(self.root,alias,SHA)
            with self.assertRaises(ValueError):host.run_prepare_probe(ROOT,'unit-host',SHA)
            with self.assertRaises(ValueError):host.run_prepare_probe(self.root,'unit-host','c'*40)
            with self.assertRaises(ValueError):host.run_prepare_probe(self.root,'unit-host','HEAD')
            for dirty,origin in ((b'scripts/deployment_compose_dirty.py\n',host.ORIGIN.encode()),(b'',b'https://example.com/foreign.git')):
                def git(*args):
                    if args[0]=='diff':return dirty
                    if args[:2]==('remote','get-url'):return origin
                    return self.git(*args)
                with patch.object(host,'_git',git),self.assertRaises(ValueError):host.run_prepare_probe(self.root,'unit-host',SHA)
            spawn.assert_not_called()

    def test_private_keys_pipe_only_safe_summary_and_stopped_owned_process(self):
        summary=self.run_probe()
        self.assertTrue(summary['success']);self.assertFalse(summary['requestReusable'])
        self.assertFalse(summary['approvalAvailable']);self.assertFalse(summary['productWriterOpened'])
        self.assertEqual(len(self.spawns),1);self.assertIsNotNone(self.processes[0].poll())
        config=self.configs[0]
        for name in host.KEY_NAMES:
            key=next(self.root.rglob(name+'.key')).read_bytes()
            self.assertEqual(base64.b64decode(config['keys'][name]),key)
            self.assertNotIn(base64.b64encode(key).decode(),self.spawns[0][-1])
            self.assertNotIn(base64.b64encode(key).decode(),json.dumps(summary))
        for path in self.root.rglob('*'):
            self.assertEqual(path.stat().st_mode&0o777,0o700 if path.is_dir() else 0o600)
        self.assertLess(len(next(self.root.rglob('stdout.private.json')).read_bytes()),4096)

    def test_unknown_remote_result_never_restarts(self):
        def spawn(argv):
            self.spawns.append(argv)
            code="import sys;sys.path[:0]=PATHS;from deployment_compose_v3_channel_worker import read_frame;read_frame(sys.stdin.buffer);sys.exit(9)".replace('PATHS',repr([str(ROOT/'scripts'),str(ROOT/'packs/deployment/scripts')]))
            process=subprocess.Popen([sys.executable,'-I','-u','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            self.processes.append(process);return process
        with self.assertRaises(ValueError):self.run_probe(spawn)
        self.assertEqual(len(self.spawns),1);self.assertIsNotNone(self.processes[0].poll())

    def config(self):
        return dict(entrypoint=host.ENTRYPOINT,sourceSha=SHA,archiveDigest='c'*64,channelNonce='d'*64,
                    keys={name:base64.b64encode(b'x'*32).decode() for name in host.KEY_NAMES},policyHash='e'*64,hostId='unit-host')

    def session(self,events):
        from tests.test_deployment_compose_bundle_v3 import fixture
        from deployment_compose_bundle_v3 import ExecutionBundleV3
        from tests.test_deployment_compose_approval_v3_host import request
        value,defaults=fixture();bundle=ExecutionBundleV3(value,authenticated_image_defaults=defaults)
        session=Mock()
        session.prepared={'bundle':bundle,'request':request(plan_hash=bundle.digest)}
        session.guard=lambda context:events.append('first-create-guard') or True
        session.raw_source={'private':'source'};session.raw_rows={'private':'rows'};session.source_model={'private':'model'}
        session.source_inputs={'private_key':b'x'*32,'identity':{'sourceSha':SHA}}
        session.cleanup=lambda:events.append('session-cleanup')
        return session

    def test_remote_preparation_first_guard_private_save_cleanup_and_nonreuse(self):
        events=[];session=self.session(events)
        def probe(workload):
            workload_result=workload(self.root,{'ID':'isolated-daemon'})
            events.extend(['daemon-stop','production-snapshot-compare'])
            return dict(root=str(self.root),completed=True,stopped=True,productionSnapshotUnchanged=True,workload=workload_result)
        with patch.object(host,'_prepare_session',return_value=session) as prepare,patch.object(host,'_probe',probe):
            summary=host._remote_main(self.config())
        self.assertEqual(prepare.call_args.kwargs['environment'],'staging')
        self.assertEqual(prepare.call_args.kwargs['host_id'],'unit-host')
        self.assertEqual(events,['first-create-guard','session-cleanup','daemon-stop','production-snapshot-compare'])
        self.assertTrue(summary['sessionCleaned']);self.assertFalse(summary['requestReusable'])
        saved=json.loads((self.root/'profile3-prepared.private.json').read_bytes())
        self.assertEqual(saved['rawSource'],{'private':'source'})
        self.assertTrue(saved['cleanupCompleted']);self.assertFalse(saved['requestReusable'])
        public=json.loads((self.root/'profile3-public.private.json').read_bytes())
        self.assertEqual(set(public),{'request','review'})
        self.assertNotIn('Env',json.dumps(public))
        for path in self.root.iterdir():self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_exception_preparation_session_is_cleaned_before_daemon_stop(self):
        events=[];session=self.session(events)
        failure=ValueError('synthetic preparation failure');failure.preparation_session=session
        def probe(workload):
            try:workload(self.root,{'ID':'isolated-daemon'})
            except ValueError:pass
            finally:events.extend(['daemon-stop','production-snapshot-compare'])
            return dict(root=str(self.root),completed=False,stopped=True,productionSnapshotUnchanged=True)
        with patch.object(host,'_prepare_session',side_effect=failure),patch.object(host,'_probe',probe):
            summary=host._remote_main(self.config())
        self.assertEqual(events,['session-cleanup','daemon-stop','production-snapshot-compare'])
        self.assertFalse(summary['success']);self.assertFalse(summary['requestReusable'])

    def test_fixed_isolated_workload_lifetime_optin(self):
        import deployment_compose_isolated_daemon_probe as isolated
        with patch.object(isolated,'probe',return_value={}) as probe:
            callback=lambda *_:None
            host._probe(callback)
            probe.assert_called_once_with(callback,storage_driver='overlayfs',workload_lifetime_seconds=3600)

    def test_terminal_stdout_bound_and_deadline(self):
        evidence=self.root/'raw.private.bin';host._private_write(evidence,b'')
        read,write=os.pipe()
        try:
            os.write(write,struct.pack('!I',65537))
            with os.fdopen(read,'rb',buffering=0) as stream,self.assertRaises(ValueError):
                host._read_terminal(stream,evidence,time.monotonic()+1)
            self.assertEqual(evidence.stat().st_size,4)
        finally:os.close(write)
        read,write=os.pipe()
        try:
            with os.fdopen(read,'rb',buffering=0) as stream,self.assertRaises(TimeoutError):
                host._read_terminal(stream,evidence,time.monotonic()+0.02)
        finally:os.close(write)

    def test_actual_fixed_loader_archive_digest_and_entrypoint(self):
        from deployment_compose_v3_channel_host import MANIFEST
        names=set(MANIFEST)|{name for name in NAMES if host._allowed(name)}
        def git(*args):
            if args[0]=='ls-tree':return '\0'.join(sorted(names)).encode()+b'\0'
            if args[0]=='show':
                name=args[1].split(':',1)[1]
                if name=='scripts/deployment_compose_profile3_prepare_ssh_probe.py':
                    return b"def _remote_main(c):\n return dict(success=True,remoteRoot='/var/tmp/dw-engine-'+'1'*16,sourceSha=c['sourceSha'],preparationOnly=True,approvalAvailable=False,productWriterOpened=False,requestReusable=False,productionReady=False,daemonStopped=True,productionSnapshotUnchanged=True,sessionCleaned=True)\n"
                if name in MANIFEST:return (ROOT/name).read_bytes()
                return b'# published fixture\n'
            return self.git(*args)
        def spawn(argv):
            self.spawns.append(argv)
            process=subprocess.Popen([sys.executable,'-I','-u','-c',shlex.split(argv[-1])[-1]],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            self.processes.append(process);return process
        with patch.object(host,'_git',git),patch.object(host,'_spawn',spawn):
            self.assertTrue(host.run_prepare_probe(self.root,'unit-host',SHA)['success'])
        real_write=host.write_frame
        def tamper(stream,value,**kwargs):
            value=dict(value,archiveBase64=base64.b64encode(b'not-the-published-package').decode())
            return real_write(stream,value,**kwargs)
        with patch.object(host,'_git',git),patch.object(host,'_spawn',spawn),patch.object(host,'write_frame',tamper),self.assertRaises(ValueError):
            host.run_prepare_probe(self.root,'unit-host',SHA)
        def tamper_digest(stream,value,**kwargs):
            return real_write(stream,dict(value,archiveDigest='f'*64),**kwargs)
        with patch.object(host,'_git',git),patch.object(host,'_spawn',spawn),patch.object(host,'write_frame',tamper_digest),self.assertRaises(ValueError):
            host.run_prepare_probe(self.root,'unit-host',SHA)
        self.assertEqual(len(self.spawns),3)
        for process in self.processes:self.assertIsNotNone(process.poll())

    def test_local_evidence_failure_occurs_before_owned_ssh_spawn(self):
        real_write=host._private_write
        def fail(path,raw,**kwargs):
            if path.name=='stderr.private.txt':raise OSError('synthetic evidence disk failure')
            return real_write(path,raw,**kwargs)
        with patch.object(host,'_git',self.git),patch.object(host,'_private_write',fail),patch.object(host,'_spawn') as spawn:
            with self.assertRaises(OSError):host.run_prepare_probe(self.root,'unit-host',SHA)
            spawn.assert_not_called()

    def test_unpublished_or_moved_fixed_branch_rejected_before_spawn(self):
        for publication in (b'',('c'*40+'\t'+host.PUBLISHED_REF+'\n').encode(),
                            (SHA+'\trefs/heads/other\n').encode(),
                            ((SHA+'\t'+host.PUBLISHED_REF+'\n')*2).encode()):
            def git(*args):
                if args[0]=='ls-remote':
                    self.assertEqual(args,('ls-remote','--exit-code','origin',host.PUBLISHED_REF))
                    return publication
                return self.git(*args)
            with self.subTest(publication=publication),patch.object(host,'_git',git),patch.object(host,'_spawn') as spawn:
                with self.assertRaises(ValueError):host.run_prepare_probe(self.root,'unit-host',SHA)
                spawn.assert_not_called()

    def test_source_head_and_tracked_code_rechecked_after_packaging(self):
        for changed in ('head','dirty'):
            counts={'head':0,'dirty':0}
            def git(*args):
                if args==('rev-parse','HEAD'):
                    counts['head']+=1
                    if changed=='head' and counts['head']>1:return b'c'*40+b'\n'
                if args[0]=='diff':
                    counts['dirty']+=1
                    if changed=='dirty' and counts['dirty']>1:return b'tests/support/changed.py\n'
                return self.git(*args)
            with self.subTest(changed=changed),patch.object(host,'_git',git),patch.object(host,'_spawn') as spawn:
                with self.assertRaises(ValueError):host.run_prepare_probe(self.root,'unit-host',SHA)
                spawn.assert_not_called()
                self.assertGreater(counts[changed],1)
