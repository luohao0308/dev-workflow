"""Kernel proof cases run only in an explicitly provisioned delegated Linux unit."""
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import deployment_compose_writer_cgroup_v3_host as cg


class BoundaryTests(unittest.TestCase):
    def test_events_and_deadlines(self):
        self.assertEqual(cg.events('populated 0\nfrozen 0\n')['populated'],0)
        for raw in ('populated 2','frozen 0','populated 0\npopulated 1'):
            with self.assertRaises(ValueError):cg.events(raw)
        for value in (True,float('inf'),float('nan'),time.monotonic()-1):
            with self.assertRaises(ValueError):cg.remaining(value)

    def test_rejects_platform_root_and_invalid_bindings(self):
        with patch.object(cg.sys,'platform','darwin'),self.assertRaises(ValueError):
            cg.WriterCgroupV3('a'*64,'b'*64,65534,65534)
        if sys.platform=='linux':
            with patch.object(cg.os,'geteuid',return_value=1000),self.assertRaises(ValueError):
                cg.WriterCgroupV3('a'*64,'b'*64,65534,65534)
        for uid in (0,True,-1):
            with self.assertRaises(ValueError):cg.WriterCgroupV3('a'*64,'b'*64,uid,65534)

    def test_fork_identity_checked_before_resource_access(self):
        group=object.__new__(cg.WriterCgroupV3);group._owner=os.getpid()+1;group._closed=False
        with self.assertRaisesRegex(ValueError,'^writer-cgroup-v3-rejected$'):group.close()


PRIVILEGED=(sys.platform=='linux' and os.geteuid()==0
            and os.environ.get('DEV_WORKFLOW_PRIVILEGED_LINUX_TESTS')=='1')


@unittest.skipUnless(PRIVILEGED,'requires root in owned delegated Linux test unit')
class KernelTests(unittest.TestCase):
    def start(self,attach=True,dispose_only=False):
        group=cg.WriterCgroupV3('a'*64,'b'*64,65534,65534)
        self.addCleanup(group._dispose if dispose_only else group.close)
        code="""import ctypes,os,sys
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(38,1,0,0,0)!=0:raise RuntimeError('nnp')
os.write(1,b'R');os.read(0,1)
"""
        p=subprocess.Popen([sys.executable,'-I','-S','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,user=65534,group=65534,extra_groups=[],env={},close_fds=True)
        def cleanup():
            if p.poll() is None:p.kill()
            p.wait(timeout=5);p.stdin.close();p.stdout.close()
        self.addCleanup(cleanup)
        self.assertTrue(select.select([p.stdout],[],[],5)[0]);self.assertEqual(p.stdout.read(1),b'R')
        if attach:
            group.attach(p,time.monotonic()+5);group.verify_worker(p,time.monotonic()+5)
        return group,p

    def test_real_permissions_kill_wait_empty_and_opaque_proof(self):
        group,p=self.start()
        with self.assertRaises(ValueError):group.verify_drain(p,cg.ProcessDrainV3())
        proof=group.kill_and_drain(p,time.monotonic()+5)
        self.assertLess(p.returncode,0)
        self.assertTrue(group.verify_drain(p,proof))
        with self.assertRaises(ValueError):group.kill_and_drain(p,time.monotonic()-1)
        group.close();group.close()
        with self.assertRaises(ValueError):group.verify_drain(p,proof)

    def test_higher_ancestor_write_result_rejects(self):
        group,p=self.start()
        real=cg.subprocess.run
        def changed(*args,**kwargs):
            if '-c' in args[0]:
                import json
                paths=json.loads(kwargs['input'])
                return subprocess.CompletedProcess(args[0],0,b'['+b','.join([b'false']*(len(paths)-1)+[b'true'])+b']')
            return real(*args,**kwargs)
        with patch.object(cg.subprocess,'run',side_effect=changed),self.assertRaises(ValueError):
            group.verify_worker(p,time.monotonic()+5)
        group.kill_and_drain(p,time.monotonic()+5)

    def test_missing_or_replaced_leaf_never_counts_as_empty(self):
        # cgroupfs forbids renaming populated groups. Destroy only our drained
        # test leaf while retaining its FD, then create a distinct replacement.
        group,p=self.start(dispose_only=True)
        proof=group.kill_and_drain(p,time.monotonic()+5)
        self.assertTrue(group.verify_drain(p,proof))
        os.rmdir(group._name,dir_fd=group._parent_fd)
        with self.assertRaises(ValueError):group.verify_drain(p,proof)
        os.mkdir(group._name,dir_fd=group._parent_fd)
        try:
            identity=group._id(os.stat(group._name,dir_fd=group._parent_fd,follow_symlinks=False))
            self.assertNotEqual(identity,group._identity)
            with self.assertRaises(ValueError):group.verify_drain(p,proof)
            with self.assertRaises(ValueError):group.kill_and_drain(p,time.monotonic()+5)
        finally:os.rmdir(group._name,dir_fd=group._parent_fd)

    def test_failed_migration_revokes_bootstrap_without_proof(self):
        group,p=self.start(attach=False)
        original=group._write
        def failed(name,value):
            if name=='cgroup.procs':raise OSError('migration')
            return original(name,value)
        with patch.object(group,'_write',side_effect=failed),self.assertRaises(ValueError):
            group.attach(p,time.monotonic()+5)
        self.assertIsNotNone(p.poll())
        self.assertIsNone(group._proof)
        with self.assertRaises(ValueError):group.kill_and_drain(p,time.monotonic()+5)
        group.close()
