"""Pipe framing double, not approval or an Engine writer."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
from deployment_compose_v3_channel_worker import read_frame,write_frame
from deployment_compose_witness_store import canonical
nonce,attack,marker=sys.argv[1:]
rpc=dict(kind='rpc',channelNonce=nonce,rpcId=1,service='intent',method='check',request={'large':'x'*17000})
if attack=='method':rpc['service']='witness';rpc['method']='transition_successor'
if attack=='nonce':rpc['channelNonce']='0'*64
write_frame(sys.stdout.buffer,rpc)
reply=read_frame(sys.stdin.buffer,timeout=5)
Path(marker).write_text(json.dumps(reply))
history={'closed':'fixture declaration only'}
terminal=dict(kind='scene-create-closed',channelNonce=nonce,requestHash='1'*64,bundleDigest='2'*64,
 historyDigest=hashlib.sha256(canonical(history)).hexdigest(),receiptMap={'backend':'3'*64},history=history,
 authorityGranted=False,runtimePermit=False,recoveryAuthorized=False,productionReady=False)
write_frame(sys.stdout.buffer,terminal)
