"""Fixed local wire double; no Engine or host service is launched."""
import json,os,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
from deployment_compose_v3_channel_worker import read_frame,write_frame
root,nonce,attack=sys.argv[1:]
if attack=='no-hello':time.sleep(5);raise SystemExit(0)
hello=dict(kind='daemon-owner-hello-v3',nonce=nonce,root=root,daemonId='daemon-one')
if attack=='bad-nonce':hello['nonce']='0'*64
write_frame(sys.stdout.buffer,hello)
if attack=='stderr':sys.stderr.write('unexpected warning\n');sys.stderr.flush()
command=read_frame(sys.stdin.buffer,timeout=5)
if command!={'kind':'daemon-owner-stop-v3','nonce':nonce}:raise ValueError('fixture-stop')
terminal=dict(kind='daemon-owner-terminal-v3',nonce=nonce,root=root,daemonId='daemon-one',
    completed=True,stopped=True,productionSnapshotUnchanged=attack!='host-drift')
write_frame(sys.stdout.buffer,terminal)
if attack=='extra':write_frame(sys.stdout.buffer,terminal)
if attack=='exit':raise SystemExit(7)
if attack=='hold':time.sleep(5)
