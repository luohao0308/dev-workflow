"""Real local pipes/processes; explicit systemd and cgroup filesystem doubles."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_owned_recovery_unit_v3_host as unit


@unittest.skipUnless(os.name=='posix','POSIX directory descriptors required')
class UnitTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);(self.root/'system.slice').mkdir()
        self.process=None;self.argv=None;self.phase='absent';self.calls=[]
        self.invocation='a'*32;self.populated='0';self.remove_group=False
        self.bad_state=False;self.reuse_pid=False;self.duplicate=False
        self.preexisting=False;self.unknown=False;self.stop_timeout=False
        self.patches=[patch.object(unit,'CGROUP',self.root),patch.object(unit,'_environment'),
            patch.object(unit,'_boot',return_value='kernel-boot'),
            patch.object(unit,'_spawn',side_effect=self.spawn),
            patch.object(unit,'_pid_identity',side_effect=self.pid_identity),
            patch.object(unit.subprocess,'run',side_effect=self.command)]
        for p in self.patches:p.start();self.addCleanup(p.stop)
        self.addCleanup(self.reap)
        self.owner=unit.OwnedRecoveryUnitV3('b'*64,'c'*40)
        self.group=self.root/'system.slice'/self.owner.unit

    def test_diagnostic_unit_changes_only_fixed_loader_before_start(self):
        diagnostic=unit.ResponseLossUnitV3('b'*64,'c'*40)
        self.addCleanup(diagnostic._release_fds)
        self.assertIsNone(diagnostic._process)
        self.assertIn('deployment_compose_response_loss_worker_v3_host.run',diagnostic._code)
        self.assertNotIn('deployment_compose_owned_recovery_worker_v3_host.run',diagnostic._code)
        self.assertIn('deployment_compose_owned_recovery_worker_v3_host.run',self.owner._code)
        self.assertFalse(diagnostic._attempted)

    def test_site_is_disabled_only_when_explicitly_configured(self):
        for value in (None,1,'true'):
            with self.subTest(value=value),self.assertRaises(ValueError):
                unit.OwnedRecoveryUnitV3('b'*64,'c'*40,disable_site=value)
        owner=unit.OwnedRecoveryUnitV3('b'*64,'c'*40,disable_site=True)
        self.addCleanup(owner._release_fds)
        self.owner=owner
        self.group=self.root/'system.slice'/owner.unit
        owner.start()
        self.assertEqual(self.argv[-6:-1],['/usr/bin/python3','-I','-S','-u','-c'])
        owner.stop();owner.close()

    def reap(self):
        if self.process is not None:
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr):stream.close()
        for name in ('_fd','_parent'):
            fd=getattr(self.owner,name)
            if fd is not None:os.close(fd);setattr(self.owner,name,None)

    def pid_identity(self,pid,group):
        self.assertEqual(group,'/system.slice/'+self.owner.unit)
        return int(pid),999 if self.reuse_pid else 123

    def spawn(self,argv):
        self.argv=argv
        self.process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        self.group.mkdir()
        (self.group/'cgroup.type').write_text('domain\n')
        (self.group/'cgroup.procs').write_text(str(self.process.pid)+'\n')
        (self.group/'cgroup.events').write_text('populated 1\nfrozen 0\n')
        self.phase='starting' if self.unknown else 'active'
        return self.process

    def state(self):
        if self.phase=='absent' and not self.preexisting:
            return dict(LoadState='not-found',ActiveState='inactive',SubState='dead',MainPID='0',
                ControlGroup='',InvocationID='',Delegate='no')
        active=self.phase!='inactive'
        return dict(LoadState='loaded',ActiveState='active' if active else 'inactive',
            SubState='running' if active else 'dead',MainPID=str(self.process.pid) if self.process and active else '0',
            ControlGroup='/system.slice/'+self.owner.unit,InvocationID=self.invocation,Delegate='yes')

    def command(self,argv,**kwargs):
        self.calls.append(argv)
        if 'show' in argv:
            self.assertIn('--all',argv);self.assertIn('--system',argv)
            if self.unknown and self.process is not None:raise TimeoutError('manager-unavailable')
            value=self.state()
            if self.bad_state:value['ControlGroup']='/system.slice/unrelated.service'
            raw=''.join(k+'='+v+'\n' for k,v in value.items())
            if self.duplicate:raw+='InvocationID='+self.invocation+'\n'
            return SimpleNamespace(stdout=raw.encode(),returncode=1 if value['LoadState']=='not-found' else 0)
        self.assertEqual(argv,['/usr/bin/systemctl','--system','stop',self.owner.unit])
        if self.stop_timeout:raise subprocess.TimeoutExpired(argv,kwargs['timeout'])
        self.process.terminate();self.process.wait(timeout=5)
        self.phase='inactive'
        if self.remove_group:shutil.rmtree(self.group);self.phase='absent'
        else:(self.group/'cgroup.events').write_text('populated '+self.populated+'\nfrozen 0\n')
        return SimpleNamespace(stdout=b'',returncode=0)

    def stops(self):return [c for c in self.calls if 'stop' in c]

    def test_start_handoff_fixed_command_and_stop_are_distinct_from_workload_success(self):
        process=self.owner.start()
        self.assertIs(process,self.process);self.assertIsNone(process.poll())
        self.assertFalse(self.owner.creation_outcome_unknown)
        for option in ('--system','--pipe','--wait','--collect','--slice=system.slice',
                '--service-type=exec','--property=Delegate=yes','--property=Restart=no',
                '--property=KillMode=control-group','--property=RuntimeMaxSec=3700',
                '--property=TimeoutStopSec=15','--property=SendSIGKILL=yes'):
            self.assertIn(option,self.argv)
        self.assertIn('deployment_compose_owned_recovery_worker_v3_host.run',self.argv[-1])
        self.assertIsNone(self.owner.stop())
        self.assertTrue(self.owner._stopped)
        self.assertNotEqual(self.owner.transport_returncode,0)
        self.owner.close()
        self.assertTrue(all(p.closed for p in (process.stdin,process.stdout,process.stderr)))

    def test_preexisting_unit_and_repeat_start_rejected_without_spawn(self):
        self.preexisting=True
        with self.assertRaises(ValueError):self.owner.start()
        self.assertIsNone(self.argv)
        self.preexisting=False
        with self.assertRaises(ValueError):self.owner.start()

    def test_unknown_start_kills_only_local_runner_and_does_not_claim_stop(self):
        self.unknown=True
        with self.assertRaises(TimeoutError):self.owner.start()
        self.assertTrue(self.owner.creation_outcome_unknown)
        self.assertFalse(self.owner._stopped);self.assertEqual(self.stops(),[])
        self.assertIsNotNone(self.process.poll())
        self.assertTrue(self.group.exists())
        with self.assertRaises(ValueError):self.owner.close()

    def test_changed_invocation_or_pid_never_stops_service(self):
        self.owner.start();self.invocation='d'*32
        with self.assertRaises(ValueError):self.owner.stop()
        self.assertEqual(self.stops(),[])
        self.invocation='a'*32;self.reuse_pid=True
        with self.assertRaises(ValueError):self.owner.stop()
        self.assertEqual(self.stops(),[])

    def test_replaced_cgroup_rejected_before_stop(self):
        self.owner.start();self.group.rename(self.group.with_suffix('.retained'));self.group.mkdir()
        with self.assertRaises(ValueError):self.owner.stop()
        self.assertEqual(self.stops(),[])

    def test_inactive_and_zero_mainpid_still_reject_populated_descendants(self):
        self.owner.start();self.populated='1'
        with self.assertRaises(ValueError):self.owner.stop()
        self.assertFalse(self.owner._stopped)
        (self.group/'cgroup.events').write_text('populated 0\nfrozen 0\n')
        self.owner.stop();self.owner.close()

    def test_collected_unit_requires_previously_bound_group_absence_or_empty(self):
        self.owner.start();self.remove_group=True
        self.owner.stop();self.owner.close()
        self.assertFalse(self.group.exists())

    def test_repeated_stop_checks_state_without_second_stop_command(self):
        self.owner.start();self.owner.stop();self.owner.stop();self.owner.close()
        self.assertEqual(len(self.stops()),1)

    def test_bad_post_spawn_group_is_unknown_not_a_stop_target(self):
        original=self.spawn
        def spawn(argv):
            process=original(argv);self.bad_state=True;return process
        with patch.object(unit,'_spawn',side_effect=spawn):
            with self.assertRaises(ValueError):self.owner.start()
        self.assertTrue(self.owner.creation_outcome_unknown)
        self.assertEqual(self.stops(),[])
        self.assertIsNotNone(self.process.poll())

    def test_startup_cleanup_cannot_replace_primary_failure(self):
        self.unknown=True
        with patch.object(self.owner,'_discard_local',side_effect=RuntimeError('secondary')):
            with self.assertRaisesRegex(TimeoutError,'manager-unavailable'):self.owner.start()

    def test_stop_timeout_is_not_completion_and_retry_revalidates(self):
        self.owner.start();self.stop_timeout=True
        with self.assertRaises(subprocess.TimeoutExpired):self.owner.stop(timeout=.1)
        self.assertFalse(self.owner._stopped)
        self.stop_timeout=False;self.owner.stop();self.owner.close()

    def test_state_is_rechecked_after_local_runner_is_reaped(self):
        self.owner.start()
        original=self.process.wait
        def wait(*args,**kwargs):
            result=original(*args,**kwargs)
            self.invocation='e'*32
            return result
        # Only mutate during the owner's final wait, after stop command returns.
        original_command=self.command
        def command(argv,**kwargs):
            result=original_command(argv,**kwargs)
            if 'stop' in argv:self.process.wait=wait
            return result
        with patch.object(unit.subprocess,'run',side_effect=command):
            with self.assertRaises(ValueError):self.owner.stop()
        self.assertFalse(self.owner._stopped)

    def test_boot_change_and_fork_reject_before_lock(self):
        self.owner.start()
        with patch.object(unit,'_boot',return_value='different-kernel-boot'):
            with self.assertRaises(ValueError):self.owner.stop()
        with patch.object(unit.os,'getpid',return_value=self.owner._owner+1):
            with self.assertRaises(ValueError):self.owner.stop()
        self.assertEqual(self.stops(),[])

    def test_duplicate_or_wrong_group_state_is_not_accepted(self):
        self.duplicate=True
        with self.assertRaises(ValueError):self.owner.start()
        self.assertIsNone(self.argv)

    def test_invalid_timeouts_reject_without_effects(self):
        for value in (True,0,-1,float('inf'),float('nan'),31):
            with self.assertRaises(ValueError):self.owner.start(timeout=value)
        self.assertEqual(self.calls,[])


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0
    and os.environ.get('DEV_WORKFLOW_TEST_OWNED_RECOVERY_UNIT')=='1',
    'explicit dedicated Linux root systemd/cgroup test host required')
class KernelTests(unittest.TestCase):
    def test_fixed_loader_waits_for_archive_and_owned_wrapper_stops(self):
        owner=unit.OwnedRecoveryUnitV3('0'*64,'0'*40)
        try:
            process=owner.start()
            self.assertIsNone(process.poll())
            self.assertFalse(owner.creation_outcome_unknown)
            # Send no archive/config: no worker import, daemon or Docker access.
            owner.stop()
            self.assertTrue(owner._stopped)
            self.assertIsNotNone(process.poll())
        finally:
            if owner._invocation is not None and not owner._stopped:owner.stop()
            if owner._stopped:owner.close()


if __name__=='__main__':unittest.main()
