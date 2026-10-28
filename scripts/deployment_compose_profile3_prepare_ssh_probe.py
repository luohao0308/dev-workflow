"""Published-code-only SSH preparation diagnostic; no approval or product writer.

The private callback creates isolated baseline fixtures, prepares an intent and
cleans its session. Every resulting request is diagnostic-only and nonreusable
once the isolated daemon stops. No public artifact is published by this module.
"""
import base64
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import struct
import shlex
import subprocess
import sys
import threading
import time
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'packs/deployment/scripts'),str(ROOT/'packs/release/scripts'),str(ROOT/'tests/support')]
from deployment_compose_v3_channel_worker import write_frame
from deployment_compose_operation_witness_client_v3 import encode

ORIGIN='https://github.com/luohao0308/dev-workflow.git'
PUBLISHED_REF='refs/heads/feat/compose-validation-20261028'
MAX_ARCHIVE=2*1024*1024
MAX_SOURCE=16*1024*1024
MAX_STDERR=1024*1024
KEY_NAMES=('config','image','declaration','archive','target')
ENTRYPOINT='deployment_compose_profile3_prepare_ssh_probe._remote_main'


def reject(): raise ValueError('profile3-prepare-ssh-rejected')


def _git(*args):
    return subprocess.run(['git','-C',str(ROOT),*args],capture_output=True,check=True,timeout=15).stdout


def _allowed(name):
    path=Path(name)
    if path.is_absolute() or '..' in path.parts or path.suffix!='.py':return False
    return (name.startswith('core/scripts/') or name.startswith('packs/deployment/scripts/')
        or name.startswith('packs/release/scripts/') or name.startswith('tests/support/')
        or name.startswith('scripts/deployment_compose_') and len(path.parts)==2)


def _check_local_source(source_sha):
    if type(source_sha) is not str or not re.fullmatch('[0-9a-f]{40}',source_sha):reject()
    if _git('rev-parse','HEAD').decode().strip()!=source_sha or _git('remote','get-url','origin').decode().strip()!=ORIGIN:reject()
    dirty=_git('diff','--name-only','HEAD','--').decode().splitlines()
    if any(_allowed(name) for name in dirty):reject()


def _published_archive(source_sha):
    _check_local_source(source_sha)
    published=_git('ls-remote','--exit-code','origin',PUBLISHED_REF).decode().splitlines()
    if published!=[source_sha+'\t'+PUBLISHED_REF]:reject()
    names=_git('ls-tree','-r','--name-only','-z',source_sha).decode().split('\0')
    names=sorted(name for name in names if name and _allowed(name))
    required={'scripts/deployment_compose_profile3_prepare_ssh_probe.py',
              'scripts/deployment_compose_isolated_daemon_probe.py','tests/support/compose_profile3_prepare_fixture.py'}
    if not required.issubset(names) or len(names)>1024:reject()
    archive=io.BytesIO();total=0
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as zipped:
        for name in names:
            raw=_git('show',source_sha+':'+name)
            total+=len(raw)
            if total>MAX_SOURCE:reject()
            zipped.writestr(name,raw)
    raw=archive.getvalue()
    if len(raw)>MAX_ARCHIVE:reject()
    _check_local_source(source_sha)
    return raw


def _private_root(root):
    if not isinstance(root,Path) or not root.is_absolute() or root.is_symlink():reject()
    root=root.resolve(strict=True)
    if root.is_relative_to(ROOT) or root.stat().st_uid!=os.getuid() or root.stat().st_mode&0o777!=0o700:reject()
    return root


def _private_write(path,raw,*,replace=False):
    temp=path.with_name(path.name+'.new-'+secrets.token_hex(8)) if replace else path
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw)
    if replace:os.replace(temp,path)


# Small fixed loader: archive and secrets arrive on owned stdio, never argv.
_BOOTSTRAP='''import base64,hashlib,io,json,os,pathlib,selectors,shutil,signal,struct,sys,tempfile,time,zipfile
limit=4*1024*1024
def interrupted(*args):raise TimeoutError('owned-controller-disconnected')
signal.signal(signal.SIGHUP,interrupted)
signal.signal(signal.SIGTERM,interrupted)
deadline=time.monotonic()+30
def exact(size):
 data=bytearray()
 with selectors.DefaultSelector() as selector:
  selector.register(sys.stdin.buffer,selectors.EVENT_READ)
  while len(data)<size:
   remaining=deadline-time.monotonic()
   if remaining<=0 or not selector.select(remaining):raise TimeoutError('bootstrap-frame-deadline')
   chunk=os.read(sys.stdin.fileno(),size-len(data))
   if not chunk:raise ValueError('bootstrap-eof')
   data.extend(chunk)
 return bytes(data)
size=struct.unpack('!I',exact(4))[0]
if not 0<size<=limit:raise ValueError('bootstrap-frame-size')
config=json.loads(exact(size))
archive=base64.b64decode(config.pop('archiveBase64'),validate=True)
if len(archive)>2097152 or hashlib.sha256(archive).hexdigest()!=ARCHIVE_DIGEST or config['archiveDigest']!=ARCHIVE_DIGEST or config['sourceSha']!=SOURCE_SHA or config['entrypoint']!='deployment_compose_profile3_prepare_ssh_probe._remote_main':raise ValueError('published-package-rejected')
r=pathlib.Path(tempfile.mkdtemp(prefix='dw-profile3-published-')).resolve()
try:
 with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
  if sum(i.file_size for i in zipped.infolist())>16777216:raise ValueError('package-too-large')
  for name in zipped.namelist():
   p=pathlib.PurePosixPath(name)
   if p.is_absolute() or '..' in p.parts or not name.endswith('.py'):raise ValueError('package-path-rejected')
  zipped.extractall(r)
 for p in r.rglob('*'):p.chmod(448 if p.is_dir() else 384)
 sys.path[:0]=[str(r/'scripts'),str(r/'core/scripts'),str(r/'packs/deployment/scripts'),str(r/'packs/release/scripts'),str(r/'tests/support')]
 from deployment_compose_profile3_prepare_ssh_probe import _remote_main
 from deployment_compose_v3_channel_worker import write_frame
 result=_remote_main(config)
finally:
 shutil.rmtree(r)
write_frame(sys.stdout.buffer,dict(channelNonce=config['channelNonce'],result=result),timeout=30)
'''


def _bootstrap(archive_digest,source_sha):
    if not re.fullmatch('[0-9a-f]{64}',archive_digest) or not re.fullmatch('[0-9a-f]{40}',source_sha):reject()
    return _BOOTSTRAP.replace('ARCHIVE_DIGEST',repr(archive_digest)).replace('SOURCE_SHA',repr(source_sha))


def _prepare_session(*args,**kwargs):
    from compose_profile3_prepare_fixture import prepare_profile3
    return prepare_profile3(*args,**kwargs)


def _probe(workload):
    from deployment_compose_isolated_daemon_probe import probe
    return probe(workload,storage_driver='overlayfs',workload_lifetime_seconds=3600)


def _private_json(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    if len(raw)>MAX_SOURCE:reject()
    return raw


def _workload(root,info,config):
    session=None;payload=None;cleanup=False
    try:
        keys={name:base64.b64decode(config['keys'][name],validate=True) for name in KEY_NAMES}
        if any(len(key)!=32 for key in keys.values()):reject()
        session=_prepare_session(root,info,source_sha=config['sourceSha'],host_id=config['hostId'],environment='staging',
            expected_daemon_id=info['ID'],keys=keys,policy_hash=config['policyHash'],expiry_seconds=600)
        prepared=session.prepared
        operation=prepared['bundle'].creation_operations()[0]
        if session.guard(dict(phase_index=0,operation=operation,receipts={},completed_operations=[])) is not True:reject()
        from compose_profile3_prepare_fixture import public_payload
        payload=dict(bundle=prepared['bundle'].to_dict(),request=asdict(prepared['request']),
            rawSource=session.raw_source,rawRows=session.raw_rows,sourceModel=session.source_model,
            sourceFacts=dict(sourceSha=config['sourceSha'],archiveDigest=config['archiveDigest'],
                sourceInputs={k:v for k,v in session.source_inputs.items() if type(v) is not bytes}),
            requestReusable=False,approvalAvailable=False,productionReady=False,cleanupCompleted=False)
        _private_write(root/'profile3-prepared.private.json',_private_json(payload))
        _private_write(root/'profile3-public.private.json',_private_json(public_payload(prepared)))
    except BaseException as error:
        if session is None:session=getattr(error,'preparation_session',None)
        raise
    finally:
        if session is not None:
            session.cleanup();cleanup=True
        if payload is not None:
            payload['cleanupCompleted']=cleanup
            _private_write(root/'profile3-prepared.private.json',_private_json(payload),replace=True)
    return dict(success=True,preparationOnly=True,sessionCleaned=cleanup,requestReusable=False,
        approvalAvailable=False,productWriterOpened=False,productionReady=False)


def _remote_main(config):
    if (type(config) is not dict or set(config)!={'entrypoint','sourceSha','archiveDigest','channelNonce','keys','policyHash','hostId'}
            or config['entrypoint']!=ENTRYPOINT or set(config['keys'])!=set(KEY_NAMES)
            or type(config['hostId']) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',config['hostId'])
            or not re.fullmatch('[0-9a-f]{40}',config['sourceSha'])
            or not re.fullmatch('[0-9a-f]{64}',config['archiveDigest'])
            or not re.fullmatch('[0-9a-f]{64}',config['channelNonce'])
            or not re.fullmatch('[0-9a-f]{64}',config['policyHash'])):reject()
    result=_probe(lambda root,info:_workload(root,info,config))
    root=Path(result['root'])
    summary=dict(success=result.get('completed') is True,remoteRoot=str(root),sourceSha=config['sourceSha'],
        preparationOnly=True,approvalAvailable=False,productWriterOpened=False,requestReusable=False,
        productionReady=False,daemonStopped=result.get('stopped') is True,
        productionSnapshotUnchanged=result.get('productionSnapshotUnchanged') is True,
        sessionCleaned=result.get('workload',{}).get('sessionCleaned') is True)
    _private_write(root/'profile3-summary.private.json',encode(summary))
    return summary


def _spawn(argv):
    return subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)


def _read_terminal(stream,path,deadline):
    def exact(size):
        data=bytearray()
        with selectors.DefaultSelector() as selector,open(path,'ab',buffering=0) as evidence:
            selector.register(stream,selectors.EVENT_READ)
            while len(data)<size:
                remaining=deadline-time.monotonic()
                if remaining<=0 or not selector.select(remaining):raise TimeoutError('prepare-probe-deadline')
                chunk=os.read(stream.fileno(),size-len(data))
                if not chunk:reject()
                evidence.write(chunk);data.extend(chunk)
        return bytes(data)
    size=struct.unpack('!I',exact(4))[0]
    if not 0<size<=65536:reject()
    raw=exact(size);frame=json.loads(raw)
    if encode(frame)!=raw:reject()
    return frame


def run_prepare_probe(privateRoot,sshAlias,source_sha):
    root=_private_root(privateRoot)
    if type(sshAlias) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',sshAlias):reject()
    archive=_published_archive(source_sha)  # All source checks precede keys, spawn and SSH.
    archive_digest=hashlib.sha256(archive).hexdigest()
    case=root/('profile3-prepare-'+secrets.token_hex(12));case.mkdir(mode=0o700)
    keys={name:secrets.token_bytes(32) for name in KEY_NAMES}
    for name,key in keys.items():_private_write(case/(name+'.key'),key)
    config=dict(entrypoint=ENTRYPOINT,sourceSha=source_sha,archiveDigest=archive_digest,hostId=sshAlias,
        archiveBase64=base64.b64encode(archive).decode(),channelNonce=secrets.token_hex(32),
        keys={name:base64.b64encode(key).decode() for name,key in keys.items()},
        policyHash=hashlib.sha256(b'dev-workflow:profile3-private-preparation-only:v1').hexdigest())
    command='exec python3 -I -u -c '+shlex.quote(_bootstrap(archive_digest,source_sha))
    argv=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',
        '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','ForwardX11=no',
        '-o','PermitLocalCommand=no','-T',sshAlias,command]
    errors=[]
    stderr_path=case/'stderr.private.txt'
    stdout_path=case/'stdout.private.bin'
    _private_write(stderr_path,b'');_private_write(stdout_path,b'')
    def drain():
        count=0
        with open(stderr_path,'ab',buffering=0) as output:
            while True:
                chunk=process.stderr.read(65536)
                if not chunk:break
                if count<MAX_STDERR:output.write(chunk[:MAX_STDERR-count])
                count+=len(chunk)
                if count>MAX_STDERR and not errors:errors.append('stderr-bound')
    thread=threading.Thread(target=drain,daemon=True)
    process=_spawn(argv);thread_started=False
    deadline=time.monotonic()+900
    try:
        thread.start();thread_started=True
        write_frame(process.stdin,config,timeout=30)
        frame=_read_terminal(process.stdout,stdout_path,deadline)
        if (type(frame) is not dict or set(frame)!={'channelNonce','result'}
                or frame['channelNonce']!=config['channelNonce']):reject()
        result=frame['result']
        expected={'success','remoteRoot','sourceSha','preparationOnly','approvalAvailable','productWriterOpened',
                  'requestReusable','productionReady','daemonStopped','productionSnapshotUnchanged','sessionCleaned'}
        if (type(result) is not dict or set(result)!=expected or result['sourceSha']!=source_sha
                or not re.fullmatch('/var/tmp/dw-engine-[0-9a-f]{16}',result['remoteRoot'])
                or any(result[k] is not False for k in ('approvalAvailable','productWriterOpened','requestReusable','productionReady'))
                or any(type(result[k]) is not bool for k in expected-{'remoteRoot','sourceSha'})):reject()
        _private_write(case/'stdout.private.json',encode(frame))
        process.stdin.close();process.wait(timeout=60)
        thread.join(timeout=5)
        if process.returncode or thread.is_alive() or errors:reject()
        return result
    finally:
        if not process.stdin.closed:process.stdin.close()
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=60)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
        if thread_started:thread.join(timeout=5)
        process.stdout.close();process.stderr.close()
