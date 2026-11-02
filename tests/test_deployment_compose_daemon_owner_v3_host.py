"""Real owner-shaped local pipes and Unix HTTP; systemd/proc/peer are doubles."""
from copy import copy,deepcopy
import os
from pathlib import Path
import pickle
import shutil
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from tests import test_deployment_compose_recovery_daemon_v3_host as fixture
import deployment_compose_recovery_daemon_v3_host as daemon
import deployment_compose_daemon_owner_v3_host as owner_module

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name=='posix','POSIX pipes and sockets required')
class OwnerTests(unittest.TestCase):
    identity=fixture.DaemonTests.identity
    ticks=fixture.DaemonTests.ticks
    command=fixture.DaemonTests.command
    stopped=fixture.DaemonTests.stopped

    def setUp(self):
        fixture.DaemonTests.setUp(self)
        self.patches[-1].stop()
        patcher=patch.object(daemon,'subprocess',SimpleNamespace(run=self.command));patcher.start();self.addCleanup(patcher.stop)
        self.spawned=[]

    def open(self,attack=''):
        value=owner_module.OwnedRecoveryDaemonHostV3()
        def spawn(argv):
            self.assertIn('-I',argv);self.assertEqual(argv[-2],'--owner')
            process=subprocess.Popen([sys.executable,str(ROOT/'tests/support/compose_daemon_owner_fixture.py'),
                str(self.root),argv[-1],attack],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            self.spawned.append(process);return process
        receive=owner_module._receive
        def read(record,deadline):
            result=receive(record,deadline)
            if result.get('kind')=='daemon-owner-terminal-v3':self.stopped()
            return result
        self.patcher=patch.object(owner_module,'_receive',side_effect=read);self.patcher.start();self.addCleanup(self.patcher.stop)
        with patch.object(owner_module,'_spawn',side_effect=spawn):
            observed=value.start(timeout=.2 if attack=='no-hello' else 5)
        self.assertIs(type(observed),daemon.ObservedRecoveryDaemonV3)
        def close():
            self.stopped()
            try:value.close()
            except Exception:pass
        self.addCleanup(close)
        return value

    def test_owned_start_stop_reaps_transport_and_native_daemon_observation(self):
        value=self.open();result=value.stop(timeout=5)
        self.assertTrue(result['daemonStoppedVerified'])
        self.assertIsNotNone(self.spawned[0].poll())
        self.assertEqual(value.stop(timeout=5),result)
        self.assertTrue(all('stop' not in argv for argv in self.calls))

    def test_constructor_does_not_spawn_and_owner_cannot_be_copied(self):
        with patch.object(owner_module,'_spawn') as spawn:
            value=owner_module.OwnedRecoveryDaemonHostV3();spawn.assert_not_called()
        for clone in (copy,deepcopy,pickle.dumps):
            with self.assertRaises(ValueError):clone(value)

    def test_duplicate_start_and_foreign_thread_cannot_control_original_owner(self):
        value=self.open()
        with self.assertRaises(ValueError):value.start()
        errors=[]
        def foreign():
            try:value.stop()
            except ValueError:errors.append(True)
        thread=threading.Thread(target=foreign);thread.start();thread.join(timeout=3)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[True])
        self.assertIsNone(self.spawned[0].poll());value.stop(timeout=5)

    def test_terminal_host_failure_extra_output_and_nonzero_exit_never_succeed(self):
        for attack in ('host-drift','extra','exit'):
            with self.subTest(attack=attack):
                self.active=True;self.dead=False;(self.group/'cgroup.events').write_text('populated 1\n')
                value=self.open(attack)
                with self.assertRaises(ValueError):value.stop(timeout=5)
                self.assertIsNotNone(self.spawned[-1].poll())
                self.patcher.stop()

    def test_invalid_deadline_rejects_without_starting(self):
        for limit in (True,0,float('nan'),float('inf'),91):
            with patch.object(owner_module,'_spawn') as spawn,self.assertRaises(ValueError):
                owner_module.OwnedRecoveryDaemonHostV3().start(timeout=limit)
            spawn.assert_not_called()

    def test_bad_hello_stderr_and_deadline_reap_only_owned_transport(self):
        for attack in ('bad-nonce','stderr','no-hello'):
            try:
                with self.subTest(attack=attack),self.assertRaises(ValueError):self.open(attack)
                self.assertIsNotNone(self.spawned[-1].poll())
            finally:self.patcher.stop()


@unittest.skipUnless(os.name=='posix','POSIX guarded files required')
class StopGuardTests(unittest.TestCase):
    identity=fixture.DaemonTests.identity
    ticks=fixture.DaemonTests.ticks
    command=fixture.DaemonTests.command
    stopped=fixture.DaemonTests.stopped

    def setUp(self):
        fixture.DaemonTests.setUp(self)
        self.patches[-1].stop()
        import deployment_compose_daemon_stop_guard_v3_host as guard
        self.module=guard
        def state(argv,**kwargs):
            result=self.command(argv,**kwargs);result.stderr=b'';return result
        for patcher in (patch.object(guard,'_ROOT_UID',os.getuid()),
                patch.object(guard,'subprocess',SimpleNamespace(run=state)),patch.object(guard,'PROC',self.root/'proc-double')):
            patcher.start();self.addCleanup(patcher.stop)
        self.guard=guard.DaemonStopGuardV3(self.root);self.addCleanup(self.guard.close)

    def test_only_original_live_identity_allows_stop_and_guard_never_issues_it(self):
        self.assertTrue(self.guard.should_stop())
        self.assertTrue(all('stop' not in cmd for cmd in self.calls))
        for action in (copy,deepcopy,pickle.dumps):
            with self.assertRaises(ValueError):action(self.guard)

    def test_changed_invocation_or_cgroup_rejects(self):
        original=self.invocation;self.invocation='b'*32
        with self.assertRaises(ValueError):self.guard.should_stop()
        self.invocation=original
        self.group.rename(self.group.with_suffix('.old'));self.group.mkdir()
        with self.assertRaises(ValueError):self.guard.should_stop()

    def test_strict_original_stopped_or_absent_skips_stop(self):
        self.stopped();self.assertFalse(self.guard.should_stop())
        self.collected=True;shutil.rmtree(self.group)
        self.assertFalse(self.guard.should_stop())

    def test_pid_reuse_or_residual_cgroup_blocks_skip(self):
        self.stopped();proc=self.module.PROC/str(self.main);proc.mkdir(parents=True)
        with self.assertRaises(ValueError):self.guard.should_stop()
        proc.rmdir();(self.group/'cgroup.events').write_text('populated 1\n')
        with self.assertRaises(ValueError):self.guard.should_stop()

    def test_guard_bound_probe_rejects_unsupported_context_before_allocating(self):
        import deployment_compose_isolated_daemon_probe as probe
        for kwargs in (dict(require_bound_stop=True),dict(require_bound_stop=1),
                dict(require_bound_stop=True,bind_to_owned_writer=True,workload=lambda *_:{})):
            with patch.object(probe.uuid,'uuid4') as create,self.assertRaises(ValueError):probe.probe(**kwargs)
            create.assert_not_called()

    def test_guard_drift_blocks_probe_finally_stop_command(self):
        import deployment_compose_isolated_daemon_probe as probe
        from unittest.mock import Mock
        import uuid
        token=uuid.uuid4();path=Path('/var/tmp')/('dw-engine-'+token.hex[:16])
        self.addCleanup(lambda:shutil.rmtree(path,ignore_errors=True))
        original=Path.read_text
        def read(file,*args,**kwargs):
            if str(file)=='/proc/meminfo':return 'MemAvailable: 2097152 kB\n'
            return original(file,*args,**kwargs)
        guard=Mock();guard.should_stop.side_effect=ValueError('replacement')
        with patch.object(Path,'read_text',read),patch.object(probe.os,'getuid',return_value=0),\
                patch.object(probe.uuid,'uuid4',return_value=token),\
                patch.object(probe,'production_snapshot',return_value={'netns':'host','mountns':'host'}),\
                patch.object(probe,'run',side_effect=[b'not-found\n',b'valid',b'created']),\
                patch.object(probe.time,'monotonic',side_effect=[0,61]),\
                patch.object(self.module,'DaemonStopGuardV3',return_value=guard),\
                patch.object(probe.subprocess,'run') as stop:
            result=probe.probe(lambda *_:{'success':True},require_bound_stop=True,workload_lifetime_seconds=3600)
        stop.assert_not_called();self.assertFalse(result['stopped']);self.assertFalse(result['completed'])
        guard.close.assert_called_once()
