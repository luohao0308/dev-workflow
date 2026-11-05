"""Owned SSH stdio provenance for fixed V3 workers; no listening service.

Only frames read from the process spawned here reach the private dispatch path.
The channel nonce correlates frames; SSH host verification and owned process
stdio establish provenance. This diagnostic scope grants no execution authority.
"""
import base64
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'scripts'), str(ROOT/'packs/deployment/scripts')]
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_operation_witness_client_v3 import dispatch_request, encode, NAMESPACE, hex_value
from deployment_compose_v3_channel_worker import ENTRYPOINT, material, read_frame, write_frame, reject

# No supplied paths, archive bytes, source text or import entrypoints are accepted.
MANIFEST = (
    'scripts/deployment_compose_v3_channel_worker.py',
    'packs/deployment/scripts/deployment_compose_operation_witness_client_v3.py',
    'packs/deployment/scripts/deployment_compose_gate_witness_v3.py',
    'packs/deployment/scripts/deployment_gateway.py',
    'packs/deployment/scripts/deployment_gate_witness.py',
    'packs/deployment/scripts/deployment_maintenance_state.py',
)


def bootstrap(entrypoint=ENTRYPOINT):
    if entrypoint != ENTRYPOINT: reject()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as zipped:
        for name in MANIFEST:
            zipped.writestr(name, (ROOT/name).read_bytes())
    packed = base64.b64encode(archive.getvalue()).decode('ascii')
    return '''import base64,io,pathlib,shutil,signal,sys,tempfile,zipfile
r=pathlib.Path(tempfile.mkdtemp(prefix='dw-v3-channel-code-'))
def stop(signum,frame): raise SystemExit(1)
signal.signal(signal.SIGTERM,stop)
signal.signal(signal.SIGHUP,stop)
try:
 zipfile.ZipFile(io.BytesIO(base64.b64decode(PACKED))).extractall(r)
 sys.path[:0]=[str(r/'scripts'),str(r/'packs/deployment/scripts')]
 from deployment_compose_v3_channel_worker import diagnostic,read_frame,write_frame
 config=read_frame(sys.stdin.buffer)
 result=diagnostic(config,sys.stdin.buffer,sys.stdout.buffer)
finally:
 shutil.rmtree(r)
write_frame(sys.stdout.buffer,dict(kind='result',channelNonce=config['channelNonce'],result=result,scratchCleaned=True))
'''.replace('PACKED', repr(packed))


def _private_root(root):
    if (type(root) is not Path and not isinstance(root, Path)) or not root.is_absolute() or root.is_symlink(): reject()
    root = root.resolve(strict=True)
    if (root.is_relative_to(ROOT) or root.stat().st_uid != os.getuid()
            or root.stat().st_mode & 0o777 != 0o700): reject()
    return root


def _write_private(path, raw):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(raw)


def _key(root, name):
    path = root/name
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','synthetic-v3-channel','-f',str(path)],
                   check=True,capture_output=True,timeout=10)
    path.chmod(0o600); path.with_suffix('.pub').chmod(0o600)
    return path


def _sign(key, namespace, payload):
    signature = subprocess.run(['ssh-keygen','-Y','sign','-f',str(key),'-n',namespace],
        input=encode(payload),capture_output=True,check=True,timeout=10).stdout
    return dict(payload=payload,signature=base64.b64encode(signature).decode('ascii'))


def _spawn_ssh(argv, stderr):
    return subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,bufsize=0)


class _OwnedSSHChannel:
    """One owned process and immutable registered scope; never an RPC server."""
    def __init__(self, *, root, ssh_alias, store, binding, signer, config,
                 approval=None, registered_request=None, intent_signer=None):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',ssh_alias or ''): reject()
        if type(store) is not OperationWitnessStoreV3 or config['binding'] != binding: reject()
        if any(x is not None for x in (approval,registered_request,intent_signer)):
            from deployment_compose_approval_v3_host import GitHubFullBodyApprovalV3
            from deployment_contract_v2 import RequestV2
            if (type(approval) is not GitHubFullBodyApprovalV3 or type(registered_request) is not RequestV2
                    or registered_request not in approval.requests or intent_signer is None
                    or Path(intent_signer).resolve() == Path(signer).resolve()): reject()
        self._store,self._binding,self._signer = store,deepcopy(binding),signer
        self._approval,self._request,self._intent_signer = approval,registered_request,intent_signer
        self._config = deepcopy(config); self._seen = set(); self._closed = False
        self._stderr = open(root/'stderr.private.txt','xb',buffering=0)
        try:
            os.chmod(root/'stderr.private.txt',0o600)
            command = 'exec python3 -I -u -c ' + shlex.quote(bootstrap(config['entrypoint']))
            self._process = _spawn_ssh(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ConnectTimeout=10','-o','ClearAllForwardings=yes',
                '-o','ForwardAgent=no','-o','ForwardX11=no','-o','PermitLocalCommand=no',
                '-T',ssh_alias,command],self._stderr)
        except Exception:
            self._stderr.close()
            raise

    def _reply_owned_frame(self, frame):
        if (self._closed or type(frame) is not dict
                or set(frame) != {'kind','channelNonce','service','method','request'}
                or frame['kind'] != 'rpc' or frame['channelNonce'] != self._config['channelNonce']): reject()
        request = frame['request']
        if type(request) is not dict or not hex_value(request.get('rpcNonce')) or request['rpcNonce'] in self._seen: reject()
        self._seen.add(request['rpcNonce'])
        if frame['service'] == 'witness':
            if (frame['method'] not in ('read','chain_status','check','append_event','events_after')
                    or request.get('binding') != self._binding): reject()
            payload = dispatch_request(self._store,frame['method'],request)
            response = _sign(self._signer,NAMESPACE,payload)
        elif frame['service'] == 'intent' and frame['method'] == 'check' and self._approval is not None:
            from deployment_compose_intent_status_v3 import issue_intent_status, NAMESPACE as INTENT_NAMESPACE
            payload = issue_intent_status(self._approval,self._request,request)
            response = _sign(self._intent_signer,INTENT_NAMESPACE,payload)
        else: reject()
        return dict(kind='reply',channelNonce=self._config['channelNonce'],response=response)

    def run(self):
        if self._closed: reject()
        process = self._process
        try:
            deadline = time.monotonic() + 120
            write_frame(process.stdin,self._config,timeout=min(30,deadline-time.monotonic()))
            # Bounded lifetime and RPC count; each mutation is dispatched once only.
            for _ in range(128):
                remaining = deadline-time.monotonic()
                if remaining <= 0: reject()
                frame = read_frame(process.stdout,min(30,remaining))
                if type(frame) is dict and frame.get('kind') == 'result':
                    if (set(frame) != {'kind','channelNonce','result','scratchCleaned'}
                            or frame['channelNonce'] != self._config['channelNonce']
                            or frame['scratchCleaned'] is not True): reject()
                    process.stdin.close(); process.wait(timeout=10)
                    if process.returncode != 0: reject()
                    return frame['result']
                response = self._reply_owned_frame(frame)
                write_frame(process.stdin,response,timeout=min(30,deadline-time.monotonic()))
            reject()
        finally:
            self.close()

    def close(self):
        if self._closed: return
        self._closed = True
        process = self._process
        if process.stdin and not process.stdin.closed: process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
        if process.stdout: process.stdout.close()
        self._stderr.close()


def run_channel_probe(privateRoot, sshAlias):
    """Launch only the fixed synthetic worker; never connect without explicit use."""
    root = _private_root(privateRoot)
    if type(sshAlias) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',sshAlias): reject()
    case = root/('channel-'+secrets.token_hex(12)); case.mkdir(mode=0o700)
    signer = _key(case,'witness-signing')
    public = signer.with_suffix('.pub').read_bytes()
    generation = secrets.token_hex(32)
    policy,*_ = material(generation,public)
    binding = dict(scopeHash=policy.witness_scope_hash,generation=generation,
                   epoch=secrets.token_hex(32),policyHash=policy.identity_hash())
    state = case/'witness'; state.mkdir(mode=0o700)
    witness_key = secrets.token_bytes(32); gate_key = secrets.token_bytes(32)
    _write_private(case/'witness.key',witness_key)
    _write_private(case/'synthetic-gate.key',gate_key)
    store = OperationWitnessStoreV3(state,key=witness_key)
    try:
        store.register_once(binding)
        config = dict(entrypoint=ENTRYPOINT,channelNonce=secrets.token_hex(32),binding=binding,
            publicKey=base64.b64encode(public).decode('ascii'),gateKey=base64.b64encode(gate_key).decode('ascii'))
        channel = _OwnedSSHChannel(root=case,ssh_alias=sshAlias,store=store,binding=binding,signer=signer,config=config)
        result = channel.run()
        view = store.read(binding)
        expected = dict(kind='synthetic-gate-v3-diagnostic',success=True,sealedEventCount=6,
            dockerWrites=0,approvalAvailable=False,authorityGranted=False,runtimePermit=False,
            productionReady=False,liveExecutionReusable=False,subjectPlatform=result.get('subjectPlatform') if type(result) is dict else None)
        if (type(result) is not dict or encode(result) != encode(expected)
                or result['subjectPlatform'] not in ('linux','darwin')
                or view['seq'] != 6 or view['phase'] != 'closed'): reject()
        report = dict(result,witnessFinal=view,scope='synthetic-only-non-authorizing',
            witnessPrivateKeysTransferred=False,githubCredentialsTransferred=False,scratchCleaned=True,
            ownedProcessStopped=True)
        _write_private(case/'report.private.json',encode(report))
        return report
    finally:
        store.close()
