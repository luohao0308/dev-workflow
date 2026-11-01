"""Actual manager relay and local processes; SSH/systemd/Engine/provider doubles."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
from deployment_compose_v3_channel_worker import read_frame,write_frame
import deployment_compose_owned_recovery_manager_v3_host as manager


def child(attack,engine):
    initial=read_frame(sys.stdin.buffer)
    archive=base64.b64decode(initial.pop('archiveBase64'))
    assert hashlib.sha256(archive).hexdigest()==initial['archiveDigest']
    assert set(initial)=={'entrypoint','sourceSha','archiveDigest','hostId','channelNonce'}
    if attack.startswith('simple'):
        write_frame(sys.stdout.buffer,dict(kind='hello',channelNonce=initial['channelNonce'],root=engine,daemonId='daemon-one'))
        if attack.startswith('simple-resource'):
            read_frame(sys.stdin.buffer)  # Wait for the test parent to consume hello.
            if attack=='simple-resource-backlog':
                Path(engine).mkdir(mode=0o700,exist_ok=True)
                write_frame(sys.stdout.buffer,dict(kind='ready-for-backlog',channelNonce=initial['channelNonce']))
                while not (Path(engine)/'checkpoint-go').exists():time.sleep(.01)
            if attack!='simple-resource-missing':
                ready=dict(kind='cleanup-ready',channelNonce=initial['channelNonce'],root=engine,daemonId='daemon-one')
                write_frame(sys.stdout.buffer,ready)
                ack=read_frame(sys.stdin.buffer);assert ack['kind']=='cleanup-checked'
                if attack=='simple-resource-rpc':
                    write_frame(sys.stdout.buffer,dict(kind='rpc',channelNonce=initial['channelNonce']));return
                if attack=='simple-resource-duplicate':write_frame(sys.stdout.buffer,ready);return
            write_frame(sys.stdout.buffer,dict(kind='final',channelNonce=initial['channelNonce']))
        if attack=='simple-daemon-wait':time.sleep(30)
        return
    root=Path(engine);root.mkdir(mode=0o700,exist_ok=True)
    config=root/'managed-config.json';config.write_text(json.dumps(initial));config.chmod(0o600)
    import os
    os.execv(sys.executable,[sys.executable,str(ROOT/'tests/support/owned_recovery_controller_fixture.py'),attack,engine,str(config)])


def main(attack,engine):
    initial=read_frame(sys.stdin.buffer)
    archive=base64.b64decode(initial.pop('archiveBase64'))
    phase={'host':False}
    class Host:
        def __init__(self,**kwargs):phase['host']=True;self.checks=0
        def descriptor(self):return dict(profile='linux-docker-host-projection-v1',beforeDigest='e'*64,endpointDigest='d'*64)
        def verify_unchanged(self,**kwargs):
            self.checks+=1
            if attack=='simple-resource-host-drift' or attack=='simple-resource-host-late-drift' and self.checks>1:
                raise ValueError('fixture-host-changed')
            return 'e'*64
        def close(self):pass
    class Daemon:
        def __init__(self,root,daemon_id,*,kernel_boot,timeout):
            assert root==engine and daemon_id=='daemon-one'
            self.value=dict(root=root,daemonId=daemon_id,unit=Path(root).name+'.service',kernelBoot=kernel_boot,
                invocationId='8'*32,cgroupDevice=1,cgroupInode=2,mainPid=3,mainStartTicks=4,daemonPid=5,daemonStartTicks=6)
        def binding(self):return dict(self.value)
        def verify_stopped(self,**kwargs):
            if attack=='simple-daemon-active':raise ValueError('fixture-daemon-still-active')
        def begin_resource_observation(self,**kwargs):return 'f'*64
        def verify_resources_restored(self,**kwargs):
            if attack=='simple-resource-leak':raise ValueError('fixture-resource-leak')
            return 'f'*64
        def close(self):pass
    class Owner:
        def __init__(self,*args):
            self.unit='dw-writer-host-'+'2'*16+'.service'
            self._boot_id='11111111-1111-1111-1111-111111111111'
            self._invocation='3'*32;self._stopped=False;self.transport_returncode=None
        def start(self,**kwargs):
            if initial.get('verifyHostSnapshot'):assert phase['host']
            self.process=subprocess.Popen([sys.executable,'-u',__file__,'--child',attack,engine],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            return self.process
        def stop(self,**kwargs):
            try:self.process.wait(timeout=.5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
            self.transport_returncode=self.process.returncode;self._stopped=True
        def _discard_local(self):
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=3)
            for stream in (self.process.stdin,self.process.stdout,self.process.stderr):stream.close()
        def close(self):self._discard_local()
    original=manager.write_frame
    original_encode=manager.encode
    def control(value):
        if type(value) is dict and value.get('kind')=='manager-bound' and attack=='simple-daemon-downgrade':
            value.pop('verifyDaemonStop',None)
        if type(value) is dict and value.get('kind')=='manager-bound' and attack=='simple-resource-downgrade':
            value.pop('verifyResourceInventory',None)
        if type(value) is dict and value.get('kind')=='manager-bound' and attack=='simple-resource-host-downgrade':
            value.pop('verifyHostSnapshot',None)
        if type(value) is dict and value.get('kind')=='daemon-bound':
            if attack=='simple-daemon-missing':
                nonce=value['channelNonce'];data=value['daemonBinding']
                value=dict(kind='worker-frame',channelNonce=nonce,
                    frame=dict(kind='hello',channelNonce=nonce,root=data['root'],daemonId=data['daemonId']))
            if attack=='simple-daemon-mismatch':value['daemonBinding']=dict(value['daemonBinding'],daemonId='other')
            if attack=='simple-resource-wrong-baseline':value['resourceBaselineDigest']='9'*64
        return original_encode(value)
    def output(stream,value,**kwargs):
        if value.get('kind')=='manager-stopped':
            if attack=='simple-terminal-missing':return
            if attack=='simple-terminal-bool':value['transportReturncode']=False
            if attack=='simple-terminal-binding':value['binding']=dict(value['binding'],invocationId='9'*32)
            if attack=='simple-daemon-false':value['daemonStoppedVerified']=False
            if attack=='simple-daemon-terminal':value['daemonBinding']=dict(value['daemonBinding'],invocationId='9'*32)
            if attack=='simple-resource-false':value['resourceInventoryRestored']=False
            if attack=='simple-resource-after':value['resourceAfterDigest']='9'*64
            if attack=='simple-resource-host-after':value['hostSnapshotAfterDigest']='9'*64
            if attack=='simple-resource-host-flag':value['hostSnapshotUnchangedVerified']=False
            if attack=='simple-resource-host-binding':value['hostSnapshotBaseline']=dict(value['hostSnapshotBaseline'],endpointDigest='9'*64)
        return original(stream,value,**kwargs)
    with patch.object(manager,'OwnedRecoveryUnitV3',Owner),patch.object(manager,'ObservedRecoveryDaemonV3',Daemon),\
            patch.object(manager,'HostSnapshotV3',Host),patch.object(manager,'write_frame',side_effect=output),\
            patch.object(manager,'encode',side_effect=control):
        manager.run(initial,sys.stdin.buffer,sys.stdout.buffer,archive,timeout=90)
    if attack=='simple-terminal-extra':write_frame(sys.stdout.buffer,dict(kind='extra',channelNonce=initial['channelNonce']))
    if attack=='simple-ssh-nonzero':raise SystemExit(7)


if __name__=='__main__':
    if sys.argv[1]=='--child':child(sys.argv[2],sys.argv[3])
    else:main(sys.argv[1],sys.argv[2])
