import importlib.util
from pathlib import Path
import unittest
import os
from unittest.mock import patch
from unittest.mock import Mock
import shutil
import subprocess
import uuid
import tempfile
import ast
import pathlib
import signal
import sys

path=Path(__file__).resolve().parents[1]/'scripts/deployment_compose_isolated_daemon_probe.py'
spec=importlib.util.spec_from_file_location('isolated_probe',path)
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)


class IsolatedDaemonConfigTests(unittest.TestCase):
    def test_unsupported_hold_lifetime_rejected_before_host_access(self):
        for seconds in (True, 0, 599, 601, 3601, '3600', None):
            with self.subTest(seconds=seconds), patch.object(probe.uuid,'uuid4') as allocate:
                with self.assertRaises(ValueError):
                    probe.probe(lambda *_: {'success': True},workload_lifetime_seconds=seconds)
                allocate.assert_not_called()
        with self.assertRaises(ValueError):
            probe.probe(workload_lifetime_seconds=3600)

    @unittest.skipUnless(os.name=='posix','POSIX bounded hold controller simulation')
    def test_explicit_approval_hold_keeps_limits_and_autonomous_cleanup(self):
        token=uuid.uuid4();root=Path('/var/tmp')/('dw-engine-'+token.hex[:16])
        self.addCleanup(lambda:shutil.rmtree(root,ignore_errors=True))
        original_read=Path.read_text
        def read(path,*args,**kwargs):
            if str(path)=='/proc/meminfo':
                return 'MemAvailable: 2097152 kB\n'
            return original_read(path,*args,**kwargs)
        with patch.object(Path,'read_text',autospec=True,side_effect=read), \
             patch.object(probe.os,'getuid',return_value=0),patch.object(probe.uuid,'uuid4',return_value=token), \
             patch.object(probe,'production_snapshot',return_value={'netns':'host','mountns':'host'}), \
             patch.object(probe,'run',side_effect=[b'not-found\n',b'valid',b'created']) as commands, \
             patch.object(probe.time,'monotonic',side_effect=[0,61]), \
             patch.object(probe.subprocess,'run',side_effect=subprocess.TimeoutExpired('stop',45)):
            result=probe.probe(lambda *_: {'success': True},workload_lifetime_seconds=3600)
        command=commands.call_args_list[2].args
        for option in ('--property=RuntimeMaxSec=3600','--property=MemoryMax=768M',
                       '--property=MemorySwapMax=0','--property=KillMode=control-group',
                       '--property=TimeoutStopSec=30'):
            self.assertIn(option,command)
        self.assertFalse(result['completed'])
        self.assertEqual(result['cleanupFailureType'],'TimeoutExpired')

    @unittest.skipUnless(os.name=='posix','POSIX controller simulation')
    def test_embedded_supervisor_controller_guards_and_owned_write(self):
        token=uuid.uuid4();root=Path('/var/tmp')/('dw-engine-'+token.hex[:16])
        self.addCleanup(lambda:shutil.rmtree(root,ignore_errors=True))
        with patch.object(probe.os,'getuid',return_value=0),patch.object(probe.uuid,'uuid4',return_value=token), \
             patch.object(probe,'production_snapshot',return_value={'netns':'host','mountns':'host'}), \
             patch.object(probe,'run',side_effect=[b'not-found\n',b'valid',b'created']), \
             patch.object(probe.time,'monotonic',side_effect=[0,61]), \
             patch.object(probe.subprocess,'run',side_effect=subprocess.TimeoutExpired('stop',45)):
            probe.probe()
        source=(root/'supervisor.py').read_text();(root/'containerd.sock').touch()
        concrete_path=type(root)
        for case in ('wrong-member','populated','missing-controller','swap-not-capped','missing-swap','success'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as directory:
                base=Path(directory);groups=base/'system.slice';group=groups/(root.name+'.service')
                (group/'supervisor').mkdir(parents=True)
                (base/'membership').write_text('0::/system.slice/'+root.name+'.service/supervisor' if case!='wrong-member' else '0::/elsewhere')
                (group/'cgroup.procs').write_text('123' if case=='populated' else '')
                (group/'memory.swap.max').write_text('max' if case=='swap-not-capped' else '0')
                (group/'cgroup.controllers').write_text('cpu pids' if case=='missing-controller' else 'cpu memory pids')
                (group/'cgroup.subtree_control').write_text('')
                if case!='missing-swap':(group/'supervisor/memory.swap.max').write_text('max')
                def mapped(value):
                    if value=='/proc/self/cgroup':return base/'membership'
                    if value=='/sys/fs/cgroup/system.slice':return groups
                    return concrete_path(value)
                child=Mock();child.poll.return_value=0;child.wait.return_value=0
                with patch.object(pathlib,'Path',side_effect=mapped),patch.object(sys,'argv',['supervisor',str(root)]), \
                     patch.object(signal,'signal'),patch.object(subprocess,'Popen',return_value=child) as launch:
                    if case=='success':
                        with self.assertRaises(SystemExit) as done:exec(compile(source,'supervisor','exec'),{})
                        self.assertEqual(done.exception.code,0);self.assertEqual(launch.call_count,2)
                    else:
                        with self.assertRaises(RuntimeError):exec(compile(source,'supervisor','exec'),{})
                        launch.assert_not_called()
                written=(group/'cgroup.subtree_control').read_text()
                self.assertEqual(written,'+cpu +memory +pids' if case in ('missing-swap','success') else '')
    def test_all_daemon_paths_are_dedicated_and_network_defaults_disabled(self):
        root=Path('/var/tmp/dw-engine-'+'a'*16)
        c=probe.configuration(root,root.name+'.service')
        for field in ('data-root','exec-root','pidfile'):
            self.assertEqual(Path(c[field]).parent, root)
        self.assertEqual(c['hosts'],['unix://'+str(root/'docker.sock')])
        self.assertEqual(c['containerd'],str(root/'containerd.sock'))
        self.assertEqual(c['containerd-namespace'],root.name)
        self.assertEqual(c['storage-driver'],'vfs')
        self.assertIs(c['features']['containerd-snapshotter'],False)
        for field in ('iptables','ip6tables','ip-forward','ip-masq','userland-proxy'):
            self.assertIs(c[field],False)
        self.assertEqual(c['bridge'],'none')
        self.assertEqual(c['cgroup-parent'],'/system.slice/'+root.name+'.service')


    @unittest.skipUnless(os.name=='posix','private POSIX evidence files')
    def test_firewall_raw_evidence_is_private_exclusive_and_same_read_as_hash(self):
        root=Path('/var/tmp')/('dw-engine-'+uuid.uuid4().hex[:16]);root.mkdir(mode=0o700)
        self.addCleanup(lambda:shutil.rmtree(root,ignore_errors=True))
        raw=b'# Generated now\n:INPUT ACCEPT [1:2]\n-A INPUT -j ACCEPT\n'
        destination=root/'firewall-before.private.json'
        with patch.object(probe.shutil,'which',return_value='/fixture'),patch.object(probe,'run',return_value=raw):
            hashes=probe.firewall_digest(evidence_path=destination)
            import json,hashlib
            captured=json.loads(destination.read_text())
            self.assertEqual(captured['iptables-save'],raw.decode())
            expected=hashlib.sha256(b':INPUT ACCEPT [COUNTERS]\n-A INPUT -j ACCEPT').hexdigest()
            self.assertEqual(hashes['iptables-save'],expected)
            self.assertEqual(destination.stat().st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError):probe.firewall_digest(evidence_path=destination)
            with self.assertRaises(ValueError):probe.firewall_digest(evidence_path=root/'not-private-evidence.json')

    def test_matching_containerd_backend_is_explicit_and_keeps_private_socket(self):
        root=Path('/var/tmp/dw-engine-'+'a'*16)
        c=probe.configuration(root,root.name+'.service',storage_driver='overlayfs')
        self.assertIs(c['features']['containerd-snapshotter'],True)
        self.assertEqual(c['containerd'],str(root/'containerd.sock'))
        with self.assertRaises(ValueError):probe.configuration(root,root.name+'.service',storage_driver='unknown')

    def test_arbitrary_roots_and_units_rejected(self):
        for root in (Path('/var/lib/docker'),Path('/tmp/dw-engine-'+'a'*16),Path('/var/tmp/dw-engine-../bad')):
            with self.assertRaises(ValueError):probe.configuration(root,root.name+'.service')
        root=Path('/var/tmp/dw-engine-'+'a'*16)
        with self.assertRaises(ValueError):probe.configuration(root,'docker.service')

    def test_firewall_normalization_ignores_only_chain_counters(self):
        with patch.object(probe.shutil,'which',return_value='/stub'),patch.object(probe,'run') as read:
            read.return_value=b'# Generated now\n:INPUT ACCEPT [1:2]\n-A INPUT --comment "[1:2]"\n'
            first=probe.firewall_digest()
            read.return_value=b'# Generated later\n:INPUT ACCEPT [3:4]\n-A INPUT --comment "[1:2]"\n'
            self.assertEqual(first,probe.firewall_digest())
            read.return_value=b':INPUT ACCEPT [3:4]\n-A INPUT --comment "[3:4]"\n'
            self.assertNotEqual(first,probe.firewall_digest())

    def test_empty_parent_does_not_hide_populated_descendant_cgroup(self):
        with tempfile.TemporaryDirectory() as directory:
            group=Path(directory)
            (group/'cgroup.procs').write_text('')
            (group/'cgroup.events').write_text('populated 1\nfrozen 0\n')
            self.assertFalse(probe.cgroup_empty(group))
            (group/'cgroup.events').write_text('populated 0\nfrozen 0\n')
            self.assertTrue(probe.cgroup_empty(group))
            (group/'cgroup.events').unlink()
            self.assertFalse(probe.cgroup_empty(group))

    @unittest.skipUnless(os.name=='posix','POSIX namespace diagnostic')
    def test_cleanup_timeout_persists_failure_and_unit_has_autonomous_deadline(self):
        token=uuid.uuid4()
        root=Path('/var/tmp')/('dw-engine-'+token.hex[:16])
        self.addCleanup(lambda:shutil.rmtree(root,ignore_errors=True))
        with patch.object(probe.os,'getuid',return_value=0),patch.object(probe.uuid,'uuid4',return_value=token), \
             patch.object(probe,'production_snapshot',return_value={'netns':'host','mountns':'host'}), \
             patch.object(probe,'run',side_effect=[b'not-found\n',b'valid',b'created']) as commands, \
             patch.object(probe.time,'monotonic',side_effect=[0,61]), \
             patch.object(probe.subprocess,'run',side_effect=subprocess.TimeoutExpired('stop',45)):
            result=probe.probe()
        self.assertFalse(result['completed'])
        self.assertFalse(result['stopped'])
        self.assertEqual(result['cleanupFailureType'],'TimeoutExpired')
        self.assertTrue((root/'report.private.json').is_file())
        ast.parse((root/'supervisor.py').read_text())
        self.assertIn('--property=MemorySwapMax=0',commands.call_args_list[2].args)
        command=commands.call_args_list[2].args
        self.assertIn('--property=RuntimeMaxSec=120',command)
        self.assertIn('--property=TimeoutStopSec=30',command)
        self.assertIn('--property=KillMode=control-group',command)
        self.assertIn('--mount',command)
        self.assertIn('--net',command)


if __name__=='__main__':unittest.main()
