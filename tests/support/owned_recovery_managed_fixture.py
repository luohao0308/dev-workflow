"""Actual manager relay and local processes; SSH/systemd/Engine/provider doubles."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
from deployment_compose_v3_channel_worker import read_frame,write_frame
import deployment_compose_owned_recovery_manager_v3_host as manager


def child(attack,engine):
    initial=read_frame(sys.stdin.buffer)
    archive=base64.b64decode(initial.pop('archiveBase64'))
    assert hashlib.sha256(archive).hexdigest()==initial['archiveDigest']
    if attack.startswith('simple'):
        write_frame(sys.stdout.buffer,dict(kind='hello',channelNonce=initial['channelNonce']))
        return
    root=Path(engine);root.mkdir(mode=0o700,exist_ok=True)
    config=root/'managed-config.json';config.write_text(json.dumps(initial));config.chmod(0o600)
    import os
    os.execv(sys.executable,[sys.executable,str(ROOT/'tests/support/owned_recovery_controller_fixture.py'),attack,engine,str(config)])


def main(attack,engine):
    initial=read_frame(sys.stdin.buffer)
    archive=base64.b64decode(initial.pop('archiveBase64'))
    class Owner:
        def __init__(self,*args):
            self.unit='dw-writer-host-'+'2'*16+'.service'
            self._boot_id='11111111-1111-1111-1111-111111111111'
            self._invocation='3'*32;self._stopped=False;self.transport_returncode=None
        def start(self,**kwargs):
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
    def output(stream,value,**kwargs):
        if value.get('kind')=='manager-stopped':
            if attack=='simple-terminal-missing':return
            if attack=='simple-terminal-bool':value['transportReturncode']=False
            if attack=='simple-terminal-binding':value['binding']=dict(value['binding'],invocationId='9'*32)
        return original(stream,value,**kwargs)
    with patch.object(manager,'OwnedRecoveryUnitV3',Owner),patch.object(manager,'write_frame',side_effect=output):
        manager.run(initial,sys.stdin.buffer,sys.stdout.buffer,archive,timeout=90)
    if attack=='simple-terminal-extra':write_frame(sys.stdout.buffer,dict(kind='extra',channelNonce=initial['channelNonce']))
    if attack=='simple-ssh-nonzero':raise SystemExit(7)


if __name__=='__main__':
    if sys.argv[1]=='--child':child(sys.argv[2],sys.argv[3])
    else:main(sys.argv[1],sys.argv[2])
