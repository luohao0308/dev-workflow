"""Real Unix HTTP and directory identities; systemd/proc/peer credentials doubled."""
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_recovery_daemon_v3_host as daemon
import deployment_compose_resource_inventory_v3_host as inventory
BOOT='11111111-1111-1111-1111-111111111111'


@unittest.skipUnless(os.name=='posix','POSIX Unix sockets and directory FDs required')
class DaemonTests(unittest.TestCase):
    def setUp(self):
        self.root=Path('/var/tmp')/('dw-engine-'+secrets.token_hex(8));self.root.mkdir(mode=0o700)
        self.addCleanup(lambda:shutil.rmtree(self.root,ignore_errors=True))
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.cg=Path(temp.name);self.unit=self.root.name+'.service'
        self.group=self.cg/'system.slice'/self.unit;self.group.mkdir(parents=True)
        (self.group/'cgroup.type').write_text('domain\n')
        (self.group/'cgroup.events').write_text('populated 1\nfrozen 0\n')
        self.pid=os.getpid();self.main=self.pid+100000
        (self.root/'daemon.pid').write_text(str(self.pid));(self.root/'daemon.pid').chmod(0o600)
        self.active=True;self.collected=False;self.dead=False;self.invocation='a'*32
        self.peer=(self.pid,os.getuid(),42);self.info={'ID':'daemon-one','DockerRootDir':str(self.root/'data')}
        self.on_info=None;self.on_request=None;self.calls=[];self.http=[]
        self.inventory={inventory.CONTAINERS:[],inventory.IMAGES:[],inventory.NETWORKS:[{'Id':'c'*64}],
            inventory.VOLUMES:{'Volumes':[],'Warnings':None}}
        test=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                test.http.append(self.path)
                raw=json.dumps(test.info if self.path=='/v1.45/info' else test.inventory[self.path]).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers()
                if self.path=='/v1.45/info' and test.on_info:test.on_info()
                if test.on_request:test.on_request(self.path)
                self.wfile.write(raw);self.wfile.flush()
        server=socketserver.UnixStreamServer(str(self.root/'docker.sock'),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=3)))
        original=daemon._UnixDocker
        def connection(path,timeout):
            self.assertRegex(path,r'^/proc/self/fd/[0-9]+/docker.sock$')
            return original(str(self.root/'docker.sock'),timeout)
        self.patches=[patch.object(daemon,'_ROOT_UID',os.getuid()),patch.object(daemon.units,'_environment'),
            patch.object(daemon.units,'_boot',return_value=BOOT),patch.object(daemon.units,'CGROUP',self.cg),
            patch.object(daemon.units,'_pid_identity',side_effect=self.identity),
            patch.object(daemon,'_ticks',side_effect=self.ticks),patch.object(daemon,'_peer',side_effect=lambda _:self.peer),
            patch.object(daemon,'_UnixDocker',side_effect=connection),patch.object(daemon.subprocess,'run',side_effect=self.command)]
        for item in self.patches:item.start();self.addCleanup(item.stop)
    def identity(self,pid,group):
        self.assertEqual(group,'/system.slice/'+self.unit+'/supervisor')
        return int(pid),123 if int(pid)==self.main else 456
    def ticks(self,pid):return None if self.dead else (123 if pid==self.main else 456)
    def command(self,argv,**kwargs):
        self.calls.append(argv)
        self.assertEqual(argv[:4],['/usr/bin/systemctl','--system','show',self.unit])
        self.assertIn('--all',argv)
        if self.collected:
            value=dict(LoadState='not-found',ActiveState='inactive',SubState='dead',MainPID='0',
                ControlGroup='',InvocationID='',Delegate='no')
        else:
            value=dict(LoadState='loaded',ActiveState='active' if self.active else 'inactive',
                SubState='running' if self.active else 'dead',MainPID=str(self.main) if self.active else '0',
                ControlGroup='/system.slice/'+self.unit,InvocationID=self.invocation,Delegate='yes')
        return SimpleNamespace(stdout=''.join(k+'='+v+'\n' for k,v in value.items()).encode(),returncode=1 if self.collected else 0)
    def observe(self):
        value=daemon.ObservedRecoveryDaemonV3(str(self.root),'daemon-one',kernel_boot=BOOT)
        self.addCleanup(value.close);return value
    def stopped(self):
        self.active=False;self.dead=True;(self.group/'cgroup.events').write_text('populated 0\nfrozen 0\n')

    def test_live_binding_then_recursive_stop_is_read_only(self):
        value=self.observe();binding=value.binding()
        self.assertEqual(binding['daemonId'],'daemon-one');self.assertEqual(binding['mainPid'],self.main)
        self.assertEqual(binding['daemonPid'],self.pid);self.assertEqual(self.http,['/v1.45/info'])
        self.stopped();value.verify_stopped()
        self.assertTrue(all('stop' not in cmd for cmd in self.calls))
    def test_resource_baseline_and_restored_inventory_use_pinned_live_peer(self):
        value=self.observe();before=value.begin_resource_observation()
        self.assertEqual(value.verify_resources_restored(),before)
        self.assertEqual(len(before),64)
        with self.assertRaises(ValueError):value.begin_resource_observation()
        self.assertTrue(all(path=='/v1.45/info' or path in inventory.PATHS for path in self.http))
    def test_each_resource_leak_blocks_inventory_restoration(self):
        value=self.observe();value.begin_resource_observation()
        for path,leak in ((inventory.CONTAINERS,[{'Id':'a'*64}]),(inventory.IMAGES,[{'Id':'sha256:'+'b'*64}]),
                (inventory.NETWORKS,[{'Id':'d'*64}]),(inventory.VOLUMES,{'Volumes':[{'Name':'leaked'}],'Warnings':[]})):
            with self.subTest(path=path):
                old=self.inventory[path];self.inventory[path]=leak
                with self.assertRaises(ValueError):value.verify_resources_restored()
                self.inventory[path]=old
    def test_resource_capture_cannot_repin_a_new_pid_or_socket(self):
        value=self.observe();value.begin_resource_observation()
        (self.root/'daemon.pid').write_text(str(self.main))
        with self.assertRaises(ValueError):value.verify_resources_restored()
        (self.root/'daemon.pid').write_text(str(self.pid))
        retained=self.root/'original.sock';(self.root/'docker.sock').rename(retained)
        sock=socket.socket(socket.AF_UNIX);self.addCleanup(sock.close);sock.bind(str(self.root/'docker.sock'))
        with self.assertRaises(ValueError):value.verify_resources_restored()
    def test_nonempty_initial_sandbox_or_incomplete_volume_listing_rejects(self):
        self.inventory[inventory.IMAGES]=[{'Id':'sha256:'+'b'*64}]
        value=self.observe()
        with self.assertRaises(ValueError):value.begin_resource_observation()
        self.inventory[inventory.IMAGES]=[]
        with self.assertRaises(ValueError):value.begin_resource_observation()
        other=self.observe();self.inventory[inventory.VOLUMES]['Warnings']=['unavailable-plugin']
        with self.assertRaises(ValueError):other.begin_resource_observation()
    def test_unstable_scans_do_not_create_a_new_baseline(self):
        value=self.observe()
        def change(path):
            if path==inventory.CONTAINERS:self.inventory[path]=[{'Id':'b'*64}]
        self.on_request=change
        with self.assertRaises(ValueError):value.begin_resource_observation()
        self.assertIsNone(value._resource_baseline)
    def test_original_peer_starttime_cannot_be_replaced_during_resource_read(self):
        value=self.observe();value.begin_resource_observation()
        def changed(pid,group):return (int(pid),999) if int(pid)==self.pid else self.identity(pid,group)
        with patch.object(daemon.units,'_pid_identity',side_effect=changed):
            with self.assertRaises(ValueError):value.verify_resources_restored()
        self.assertEqual(value.binding()['daemonStartTicks'],456)
    def test_collected_unit_with_bound_group_absent_is_accepted(self):
        value=self.observe();self.stopped();self.collected=True;shutil.rmtree(self.group)
        value.verify_stopped()

    def test_stop_observation_waits_for_original_service_with_one_deadline(self):
        value=self.observe();read=value._state;calls=[]
        def transition(deadline):
            calls.append(deadline)
            if len(calls)==2:self.stopped()
            result=read(deadline)
            if len(calls)==1:result['ActiveState']='deactivating';result['SubState']='stop-sigterm'
            return result
        with patch.object(value,'_state',side_effect=transition),patch.object(daemon.time,'sleep'):
            value.verify_stopped(timeout=.5)
        self.assertGreaterEqual(len(calls),3);self.assertEqual(len(set(calls)),1)
        self.assertTrue(all('stop' not in cmd for cmd in self.calls))

    def test_live_original_service_times_out_without_claiming_stop(self):
        value=self.observe();start=time.monotonic()
        with self.assertRaises(ValueError):value.verify_stopped(timeout=.05)
        self.assertLess(time.monotonic()-start,.5);self.assertTrue(self.active)

    def test_invocation_change_while_waiting_is_rejected(self):
        value=self.observe();read=value._state;count=[]
        def transition(deadline):
            count.append(1)
            if len(count)==2:self.invocation='b'*32
            return read(deadline)
        with patch.object(value,'_state',side_effect=transition),patch.object(daemon.time,'sleep'):
            with self.assertRaises(ValueError):value.verify_stopped(timeout=.5)
        self.assertEqual(len(count),2)

    def test_disappearance_between_service_and_process_reads_is_stop_progress(self):
        value=self.observe();read=value._state;count=[]
        def transition(deadline):
            count.append(1);result=read(deadline)
            if len(count)==1:
                self.stopped();self.collected=True;shutil.rmtree(self.group)
            return result
        with patch.object(value,'_state',side_effect=transition),patch.object(daemon.time,'sleep'):
            value.verify_stopped(timeout=.5)
        self.assertGreaterEqual(len(count),3)

    def test_replacement_pid_or_cgroup_during_stop_wait_is_rejected_immediately(self):
        for attack in ('pid','ticks','group'):
            with self.subTest(attack=attack):
                value=self.observe();read=value._state
                def changed(deadline):
                    row=read(deadline)
                    if attack=='pid':row['MainPID']=str(self.main+1)
                    if attack=='group':
                        self.group.rename(self.group.with_suffix('.retained'));self.group.mkdir()
                    return row
                with patch.object(value,'_state',side_effect=changed),\
                        patch.object(daemon,'_ticks',return_value=999 if attack=='ticks' else 123),\
                        patch.object(daemon.time,'sleep') as sleep:
                    with self.assertRaises(ValueError):value.verify_stopped(timeout=.5)
                sleep.assert_not_called()
    def test_inactive_zero_mainpid_does_not_hide_descendants_or_escaped_pid(self):
        value=self.observe();self.active=False
        with self.assertRaises(ValueError):value.verify_stopped()
        (self.group/'cgroup.events').write_text('populated 0\n')
        with self.assertRaises(ValueError):value.verify_stopped()
        self.dead=True;value.verify_stopped()
    def test_changed_invocation_or_group_is_not_prior_daemon(self):
        value=self.observe();self.stopped();self.invocation='b'*32
        with self.assertRaises(ValueError):value.verify_stopped()
        self.invocation='a'*32;self.group.rename(self.group.with_suffix('.retained'));self.group.mkdir()
        with self.assertRaises(ValueError):value.verify_stopped()
    def test_wrong_peer_uid_or_pid_is_rejected(self):
        for peer in ((self.pid+1,os.getuid(),0),(self.pid,os.getuid()+1,0)):
            with self.subTest(peer=peer):
                self.peer=peer
                with self.assertRaises(ValueError):self.observe()
    def test_wrong_info_id_or_root_is_rejected(self):
        for info in ({'ID':'other','DockerRootDir':str(self.root/'data')},{'ID':'daemon-one','DockerRootDir':'/wrong'}):
            self.info=info
            with self.assertRaises(ValueError):self.observe()
    def test_pid_file_symlink_or_fifo_reject_without_waiting(self):
        file=self.root/'daemon.pid';file.unlink();file.symlink_to('/dev/null')
        with self.assertRaises(OSError):self.observe()
        file.unlink();os.mkfifo(file)
        with self.assertRaises(ValueError):self.observe()
    def test_socket_replacement_during_info_rejects(self):
        replacement=socket.socket(socket.AF_UNIX);self.addCleanup(replacement.close)
        def replace():
            (self.root/'docker.sock').rename(self.root/'original.sock')
            replacement.bind(str(self.root/'docker.sock'))
        self.on_info=replace
        with self.assertRaises(ValueError):self.observe()
    def test_private_root_replacement_during_info_rejects(self):
        retained=self.root.with_name(self.root.name+'-retained')
        self.addCleanup(lambda:shutil.rmtree(retained,ignore_errors=True))
        def replace():self.root.rename(retained);self.root.mkdir(mode=0o700)
        self.on_info=replace
        with self.assertRaises(ValueError):self.observe()
    def test_pid_file_change_during_info_rejects(self):
        self.on_info=lambda:(self.root/'daemon.pid').write_text(str(self.main))
        with self.assertRaises(ValueError):self.observe()
    def test_surviving_daemon_pid_is_not_hidden_by_dead_supervisor(self):
        value=self.observe();self.stopped()
        with patch.object(daemon,'_ticks',side_effect=lambda pid:456 if pid==self.pid else None):
            with self.assertRaises(ValueError):value.verify_stopped()
    def test_boot_and_fork_rejected(self):
        value=self.observe()
        with patch.object(daemon.units,'_boot',return_value='other'):
            with self.assertRaises(ValueError):value.verify_stopped()
        with patch.object(daemon.os,'getpid',return_value=os.getpid()+1):
            with self.assertRaises(ValueError):value.verify_stopped()


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0
    and os.environ.get('DEV_WORKFLOW_TEST_DAEMON_OBSERVER')=='1',
    'explicit dedicated Linux root systemd/cgroup marker test required')
class KernelTests(unittest.TestCase):
    def test_real_service_peer_credentials_and_recursive_drain_without_docker(self):
        root=Path('/var/tmp')/('dw-engine-'+secrets.token_hex(8));root.mkdir(mode=0o700)
        unit=root.name+'.service';observer=None;started=False;verified=False
        server='''import json,os,pathlib,socketserver,sys
from http.server import BaseHTTPRequestHandler
root=pathlib.Path(sys.argv[1])
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  values={'/v1.45/info':dict(ID='marker-daemon',DockerRootDir=str(root/'data')),
   '/v1.45/containers/json?all=true':[], '/v1.45/images/json?all=true':[],
   '/v1.45/networks':[{'Id':'c'*64}], '/v1.45/volumes':{'Volumes':[],'Warnings':None}}
  body=json.dumps(values[self.path]).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
service=socketserver.UnixStreamServer(str(root/'docker.sock'),Handler)
(root/'daemon.pid').write_text(str(os.getpid()));(root/'daemon.pid').chmod(0o600)
service.serve_forever()
'''
        supervisor='''import signal,subprocess,sys
def stop(*args):raise SystemExit(143)
signal.signal(signal.SIGTERM,stop)
child=subprocess.Popen([sys.executable,'-u','-c',sys.argv[1],sys.argv[2]])
try:child.wait()
finally:
 if child.poll() is None:child.terminate()
 try:child.wait(timeout=3)
 except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
'''
        try:
            initial=subprocess.run(['/usr/bin/systemctl','--system','show',unit,'--property=LoadState','--value'],
                capture_output=True,text=True,timeout=5)
            self.assertEqual(initial.stdout.strip(),'not-found')
            subprocess.run(['/usr/bin/systemd-run','--system','--quiet','--collect','--service-type=exec',
                '--unit='+unit,'--slice=system.slice','--property=User=root','--property=Delegate=yes',
                '--property=DelegateSubgroup=supervisor','--property=KillMode=control-group',
                '--property=RuntimeMaxSec=45','--property=TimeoutStopSec=5','--property=SendSIGKILL=yes',
                '--property=Restart=no','--property=StandardOutput=null','--property=StandardError=null','--',
                '/usr/bin/python3','-u','-c',supervisor,server,str(root)],capture_output=True,check=True,timeout=10)
            started=True;deadline=time.monotonic()+10
            while not (root/'daemon.pid').exists() or not (root/'docker.sock').exists():
                if time.monotonic()>=deadline:raise TimeoutError('marker-not-ready')
                time.sleep(.02)
            observer=daemon.ObservedRecoveryDaemonV3(str(root),'marker-daemon',kernel_boot=daemon.units._boot())
            self.assertNotEqual(observer.binding()['mainPid'],observer.binding()['daemonPid'])
            baseline=observer.begin_resource_observation()
            self.assertEqual(observer.verify_resources_restored(),baseline)
            subprocess.run(['/usr/bin/systemctl','--system','stop',unit],capture_output=True,check=True,timeout=10)
            observer.verify_stopped();verified=True
            print(json.dumps(dict(markerBinding=observer.binding(),daemonStopped=True,
                resourceBaselineDigest=baseline,resourceInventoryRestored=True,
                cgroupExists=(daemon.units.CGROUP/'system.slice'/unit).exists(),newDockerWrites=0)))
        finally:
            if started and not verified:
                subprocess.run(['/usr/bin/systemctl','--system','stop',unit],capture_output=True,timeout=10)
            if observer is not None:observer.close()
            if verified:shutil.rmtree(root)


if __name__=='__main__':unittest.main()
