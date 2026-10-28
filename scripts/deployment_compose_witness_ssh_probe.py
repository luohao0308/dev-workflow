"""Controller-side signed witness fixture over SSH; no production authority."""
import base64
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parents[1]
import sys
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'packs/deployment/scripts')]
from deployment_compose_witness_store import ComposeWitnessStore,hex_value,hex_value
from deployment_gate_witness import NAMESPACE,encode
from deployment_compose_witness_worker_fixture import MODES,material,read_frame

FILES=('packs/deployment/scripts/deployment_gateway.py','packs/deployment/scripts/deployment_maintenance_state.py',
       'packs/deployment/scripts/deployment_gate_witness.py','scripts/deployment_compose_journal_host.py',
       'scripts/deployment_compose_recovery_store.py','scripts/deployment_compose_witness_worker_fixture.py')

def reply(store,signer,method,request):
    if type(request) is not dict or method not in ('check','reserve'):raise ValueError('witness-rpc-rejected')
    common={'binding','expectedSeq','expectedHead','bootNonce','rpcNonce'}
    if set(request)!=(common if method=='check' else common|{'nextHead','eventDigest'}):raise ValueError('witness-rpc-rejected')
    if not all(hex_value(request[k]) for k in ('bootNonce','rpcNonce')):raise ValueError('witness-rpc-rejected')
    if not all(hex_value(request[k]) for k in ('bootNonce','rpcNonce')):raise ValueError('witness-rpc-rejected')
    args=dict(expected_seq=request['expectedSeq'],expected_head=request['expectedHead'])
    if method=='check':payload=store.check(request['binding'],**args)
    else:payload=store.reserve(request['binding'],**args,next_head=request['nextHead'],event_digest=request['eventDigest'],
                               boot_nonce=request['bootNonce'],rpc_nonce=request['rpcNonce'])
    payload.update(bootNonce=request['bootNonce'],rpcNonce=request['rpcNonce'])
    signature=subprocess.run(['ssh-keygen','-Y','sign','-f',str(signer),'-n',NAMESPACE],input=encode(payload),capture_output=True,check=True,timeout=10).stdout
    return {'payload':payload,'signature':base64.b64encode(signature).decode()}

def bootstrap():
    archive=io.BytesIO()
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for name in FILES:z.writestr(name,(ROOT/name).read_bytes())
    packed=base64.b64encode(archive.getvalue()).decode()
    return "import base64,io,pathlib,sys,tempfile,zipfile; r=pathlib.Path(tempfile.mkdtemp(prefix='dw-witness-code-',dir='/var/tmp')); zipfile.ZipFile(io.BytesIO(base64.b64decode("+repr(packed)+"))).extractall(r); sys.path[:0]=[str(r/'scripts'),str(r/'packs/deployment/scripts')]; from deployment_compose_witness_worker_fixture import main; main()"

def run_probe(root,ssh_alias):
    if not isinstance(root,Path) or not root.is_absolute() or root.is_symlink():raise ValueError('invalid-witness-controller-root')
    root=root.resolve(strict=True)
    if (not isinstance(root,Path) or not root.is_absolute() or root.is_symlink()
            or root.is_relative_to(ROOT) or root.stat().st_uid!=os.getuid() or root.stat().st_mode&0o777!=0o700
            or type(ssh_alias) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',ssh_alias)):
        raise ValueError('invalid-witness-controller-root')
    results=[]
    for mode in MODES:
        case=root/mode;case.mkdir(mode=0o700)
        signer=case/'signer'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','witness-test','-f',str(signer)],check=True,capture_output=True,timeout=10)
        public=signer.with_suffix('.pub').read_bytes();generation=secrets.token_hex(32)
        policy,_,_,_,_,_=material(generation,public)
        binding={'scopeHash':policy.witness_scope_hash,'epoch':secrets.token_hex(32),'generation':generation,'policyHash':policy.identity_hash()}
        state=case/'state';state.mkdir(mode=0o700)
        witness_key=secrets.token_bytes(32)
        fd=os.open(case/'witness.key',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(witness_key)
        store=ComposeWitnessStore(state,key=witness_key)
        store.register_once(binding)
        gate_key=secrets.token_bytes(32)
        fd=os.open(case/'gate-fixture.key',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(gate_key)
        config={'mode':mode,'publicKey':base64.b64encode(public).decode(),'gateKey':base64.b64encode(gate_key).decode(),'binding':binding}
        command='python3 -u -c '+shlex.quote(bootstrap())
        process=subprocess.Popen(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',ssh_alias,command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        frames=[]
        try:
            process.stdin.write(encode(config)+b'\n');process.stdin.flush()
            while True:
                frame=read_frame(process.stdout,30);frames.append(frame)
                if frame.get('kind')=='fixture-result':
                    result=frame['result']
                    if type(result) is not dict or type(result.get('success')) is not bool:raise ValueError('invalid-worker-result')
                    if result.get('mode')!=mode:result['success']=False
                    break
                if frame.get('kind')!='witness-rpc':raise ValueError('unknown-worker-frame')
                try:response=reply(store,signer,frame['method'],frame['request'])
                except (ValueError,OSError,subprocess.SubprocessError):response={'error':'witness-rejected'}
                frames.append({'kind':'witness-reply','response':response})
                process.stdin.write(encode(response)+b'\n');process.stdin.flush()
            process.stdin.close();process.wait(timeout=15)
            if process.returncode:raise ValueError('witness-worker-failed')
            result['witnessFinal']=store.read(binding)
            result['witnessPrivateKeysTransferred']=False
            result['gateFixtureKeyTransferred']=True
            results.append(result)
            (case/'frames.private.json').write_text(json.dumps(frames,indent=2));(case/'frames.private.json').chmod(0o600)
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=10)
            (case/'frames.private.json').write_text(json.dumps(frames,indent=2));(case/'frames.private.json').chmod(0o600)
            (case/'stderr.private.txt').write_bytes(process.stderr.read(65536));(case/'stderr.private.txt').chmod(0o600)
            store.close()
    output={'kind':'cross-host-witness-fixture','cases':results,'success':all(x.get('success') for x in results),
            'dockerWrites':0,'productionReady':False,'productionApprovalAvailable':False,
            'controllerPlatform':sys.platform,'crashRecoveryValidated':False,
            'scope':'Linux Gate/journal/CAS directory rollback only; excludes code/startup policy/Mac witness rollback and active root bypass'}
    (root/'report.private.json').write_text(json.dumps(output,indent=2));(root/'report.private.json').chmod(0o600)
    return output
