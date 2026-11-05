"""Opt-in Linux kernel test: actual units/pidfd; daemon binaries are markers."""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import deployment_compose_isolated_daemon_probe as probe


def command(*args):
    return subprocess.run(args,check=True,capture_output=True,timeout=15).stdout


def supervisor_source():
    tree=ast.parse(Path(probe.__file__).read_text())
    return next(node.args[0].value for node in ast.walk(tree)
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
        and isinstance(node.func.value,ast.Name) and node.func.value.id=='supervisor'
        and node.func.attr=='write_text')


def parent(root,mode):
    binding=probe._owned_writer_binding()
    (root/'owner.private.json').write_text(json.dumps(binding[1]))
    if mode=='dead':
        # The guard must reject a dead original PID before starting children.
        child=subprocess.Popen(['/usr/bin/true']);child.wait(timeout=3)
        value=dict(binding[1],MainPID=str(child.pid))
        (root/'owner.private.json').write_text(json.dumps(value))
    if mode=='stale':
        value=dict(binding[1],StartTime=str(int(binding[1]['StartTime'])+1))
        (root/'owner.private.json').write_text(json.dumps(value))
    if mode=='wrong-group':
        value=dict(binding[1],ControlGroup='/system.slice/docker.service')
        (root/'owner.private.json').write_text(json.dumps(value))
    (root/'supervisor.py').write_text(supervisor_source())
    command('/usr/bin/systemd-run','--system','--quiet','--collect','--service-type=exec',
        '--unit='+root.name+'.service','--property=Delegate=yes',
        '--property=DelegateSubgroup=supervisor','--property=MemoryMax=128M',
        '--property=MemorySwapMax=0','--property=TasksMax=32',
        '--property=KillMode=control-group','--property=TimeoutStopSec=5',
        '--property=RuntimeMaxSec=90','--property=Restart=no',
        '--setenv=PATH='+str(root/'bin')+':/usr/bin:/bin',
        '/usr/bin/python3',str(root/'supervisor.py'),str(root),'--owned-writer')
    (root/'started').touch()
    while True:time.sleep(.1)


@unittest.skipUnless(sys.platform=='linux' and os.getuid()==0 and
    os.environ.get('DEV_WORKFLOW_TEST_OWNED_DAEMON_BINDING')=='1',
    'explicit root Linux transient-marker-unit opt-in')
class KernelTests(unittest.TestCase):
    def test_parent_stop_sigkill_and_dead_owner_startup(self):
        for mode in ('stop','kill','dead','stale','wrong-group','wait-loss','ignore-term'):
            with self.subTest(mode=mode):self.case(mode)

    def case(self,mode):
        root=Path('/var/tmp')/('dw-engine-'+uuid.uuid4().hex[:16]);root.mkdir(mode=0o700)
        unit='dw-writer-host-'+uuid.uuid4().hex[:16]+'.service';child=root.name+'.service'
        binary=root/'bin';binary.mkdir(mode=0o700)
        for name in ('containerd','dockerd'):
            path=binary/name
            path.write_text('#!/usr/bin/python3\nimport os,pathlib,time,signal\nr=pathlib.Path('+repr(str(root))+')\n'
                +('signal.signal(signal.SIGTERM,signal.SIG_IGN)\n' if mode=='ignore-term' and name=='containerd' else '')
                +
                '(r/'+repr(name+'.marker')+').write_text(str(os.getpid()))\n'
                +("(r/'containerd.sock').touch()\n" if name=='containerd' and mode!='wait-loss' else '')
                +'while True:time.sleep(.1)\n')
            path.chmod(0o700)
        (root/'containerd.toml').touch();(root/'daemon.json').write_text('{}')
        try:
            command('/usr/bin/systemd-run','--system','--quiet','--collect','--service-type=exec',
                '--unit='+unit,'--property=Delegate=yes','--property=Restart=no',
                '--property=RuntimeMaxSec=90','--property=TimeoutStopSec=5',
                '/usr/bin/python3',str(Path(__file__).resolve()),'--parent',str(root),mode)
            deadline=time.monotonic()+20
            target=('started' if mode in ('dead','stale','wrong-group') else
                    'containerd.marker' if mode=='wait-loss' else 'dockerd.marker')
            while not (root/target).exists():
                self.assertLess(time.monotonic(),deadline,'marker startup deadline');time.sleep(.05)
            if mode in ('dead','stale','wrong-group'):
                time.sleep(.3)
                self.assertFalse((root/'containerd.marker').exists())
                self.assertFalse((root/'dockerd.marker').exists())
            else:
                names=('containerd',) if mode=='wait-loss' else ('containerd','dockerd')
                pids=[int((root/(name+'.marker')).read_text()) for name in names]
                if mode in ('kill','wait-loss','ignore-term'):command('/usr/bin/systemctl','kill','--kill-who=main','--signal=KILL',unit)
                else:command('/usr/bin/systemctl','stop',unit)
                deadline=time.monotonic()+25
                while any(Path('/proc',str(pid)).exists() for pid in pids):
                    self.assertLess(time.monotonic(),deadline,'marker children survived parent');time.sleep(.05)
                if mode=='wait-loss':self.assertFalse((root/'dockerd.marker').exists())
            deadline=time.monotonic()+10
            group=Path('/sys/fs/cgroup/system.slice')/child
            while not probe.cgroup_empty(group):
                self.assertLess(time.monotonic(),deadline,'daemon cgroup populated');time.sleep(.05)
            state=command('/usr/bin/systemctl','show',child,'-p','MainPID','-p','ActiveState').decode()
            self.assertIn('MainPID=0',state)
            self.assertTrue('ActiveState=inactive' in state or 'ActiveState=failed' in state)
        finally:
            for name in (child,unit):
                subprocess.run(['/usr/bin/systemctl','stop',name],capture_output=True,timeout=15)
                subprocess.run(['/usr/bin/systemctl','reset-failed',name],capture_output=True,timeout=5)
            shutil.rmtree(root)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--parent':parent(Path(sys.argv[2]),sys.argv[3])
    else:unittest.main()
