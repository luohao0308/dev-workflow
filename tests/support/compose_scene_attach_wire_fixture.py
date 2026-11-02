"""Canonical frame/pipe worker double; never executes an archive."""
import base64,hashlib,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
from deployment_compose_v3_channel_worker import read_frame,write_frame
from deployment_compose_witness_store import canonical
from deployment_compose_scene_attach_read_v3_host import _FALSE
attack=sys.argv[1] if len(sys.argv)>1 else ''
config=read_frame(sys.stdin.buffer,timeout=5)
archive=base64.b64decode(config.pop('archiveBase64'),validate=True)
if hashlib.sha256(archive).hexdigest()!=config['archiveDigest']:raise ValueError('fixture-archive')
if sys.stdin.buffer.read(1):raise ValueError('extra-input')
reply=dict(kind='scene-attach-read-v3',channelNonce=config['channelNonce'],sourceSha=config['sourceSha'],
    archiveDigest=config['archiveDigest'],bindingDigest=hashlib.sha256(canonical(config['daemonBinding'])).hexdigest(),
    inventoryDigest='c'*64,readOnly=True,**{key:False for key in _FALSE})
if attack=='nonce':reply['channelNonce']='0'*64
if attack=='write':reply['readOnly']=False
if attack=='stderr':sys.stderr.write('warning\n');sys.stderr.flush()
write_frame(sys.stdout.buffer,reply)
if attack=='extra':write_frame(sys.stdout.buffer,reply)
if attack=='exit':raise SystemExit(7)
