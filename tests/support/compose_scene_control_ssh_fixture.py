"""Local SSH/source and Linux peer double; original relay and Unix/HMAC client."""
import os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_scene_service_v3_host as scene
import deployment_compose_scene_control_ssh_v3_host as relay
from deployment_compose_v3_channel_worker import read_frame,write_frame
scene.BASE=Path(sys.argv[1]);scene.ROOT_UID=os.getuid();scene._peer=lambda sock:(os.getpid(),os.getuid(),os.getgid())
config=read_frame(sys.stdin.buffer);config.pop('archiveBase64')
config['handle']['socketPath']=str(scene.BASE/config['handle']['sceneId']/'control.sock')
original=relay._small_write
if sys.argv[2] in ('nonce','seq-bool'):
 def small(stream,value,timeout):
  if sys.argv[2]=='nonce' and value.get('kind')=='scene-control-ready-v3':value=dict(value,channelNonce='0'*64)
  if sys.argv[2]=='seq-bool' and value.get('kind')=='scene-control-result-v3':value=dict(value,seq=True)
  return original(stream,value,timeout)
 relay._small_write=small
result=relay._remote_main(config)
if sys.argv[2]=='terminal-bool':result=dict(result,seq=True)
write_frame(sys.stdout.buffer,dict(channelNonce=config['channelNonce'],result=result))
if sys.argv[2]=='stderr':sys.stderr.write('test late cleanup stderr\n')
if sys.argv[2]=='exit':raise SystemExit(2)
