"""Fixed published-source SSH relay for the original Linux scene client.

Only scene control credentials travel to Linux. Mac business signing and approval
stay in the original admission object. EOF closes the original local connection;
active writers are drained/frozen by the scene service, never recreated here.
"""
import base64
from dataclasses import dataclass,field
import hashlib
import os
import re
import selectors
import shlex
import subprocess
import struct
import sys
import threading
import time
import weakref

import deployment_compose_profile3_prepare_ssh_probe as source
from deployment_compose_scene_service_v3_host import SceneClientV3,SceneHandleV3,MAX_FRAME,_frame,decode,canonical,_FALSE
from deployment_compose_v3_channel_worker import read_frame,write_frame

ENTRYPOINT='deployment_compose_scene_control_ssh_v3_host._remote_main'
END_TIMEOUT=5
_ISSUED_CLIENTS=weakref.WeakKeyDictionary()
_COMMANDS={'status','detach','closeScene','reserve_writer','drain_writer','inspect_attached_worker',
    'prepare_identity','prepare_staging','preparation_chunk','start_first_create','poll_worker',
    'read_worker_chunk','begin_worker_reply','worker_reply_chunk','commit_worker_reply','finish_worker','reconcile_closure'}
_BUDGETS={'closeScene':420,'reserve_writer':25,'drain_writer':40,'inspect_attached_worker':60,
    'prepare_identity':90,'prepare_staging':1200,'start_first_create':40,'finish_worker':40,'reconcile_closure':40}


def reject():raise ValueError('compose-scene-control-ssh-v3-rejected') from None


def _client_identity(client):
    handle=client._handle;process=client._process
    return (client._owner,id(handle),id(process),id(process.stdin),id(process.stdout),id(process.stderr),
        client._nonce,handle.sceneId,handle.socketPath,hashlib.sha256(handle.controlKey).digest(),
        handle.hostAlias,handle.sourceSha,hashlib.sha256(handle.archiveBytes).digest())


def _issued_scene_ssh_client(client):
    """Constructor provenance for checkpoint capture; copies cannot mint it."""
    if type(client) is not SceneSSHClientV3 or _ISSUED_CLIENTS.get(client) is None:reject()
    try:actual=_client_identity(client)
    except Exception:reject()
    if (client._owner!=(os.getpid(),threading.get_ident())
            or _ISSUED_CLIENTS[client]!=actual
            or any(name in client.__dict__ for name in
                   ('status','_call','_owned','_read','_finish','close','detach'))):reject()
    return _ISSUED_CLIENTS[client]


@dataclass(frozen=True)
class SceneSSHHandleV3:
    sceneId:str
    socketPath:str
    controlKey:bytes=field(repr=False)
    hostAlias:str
    sourceSha:str
    archiveBytes:bytes=field(repr=False)


def _bootstrap(digest,sha):
    code=source._bootstrap(digest,sha)
    original='from deployment_compose_profile3_prepare_ssh_probe import _remote_main'
    if code.count(original)!=1 or code.count(source.ENTRYPOINT)!=1:reject()
    return code.replace(original,'from deployment_compose_scene_control_ssh_v3_host import _remote_main').replace(source.ENTRYPOINT,ENTRYPOINT)


def _verify_source(handle):
    from deployment_compose_checkpoint_source_v3_host import _verify_archive
    # Rebuilding ZIP bytes changes timestamps. Reuse the retained exact ZIP and
    # compare every member with pinned Git objects, rejecting promisor/lazy
    # object retrieval before the ordinary checkout/ref checks.
    _verify_archive(handle.archiveBytes,repository=source.ROOT,source_sha=handle.sourceSha,
        archive_digest=hashlib.sha256(handle.archiveBytes).hexdigest(),timeout=30)
    source._check_local_source(handle.sourceSha)
    published=source._git('ls-remote','--exit-code','origin',source.PUBLISHED_REF).decode().splitlines()
    if published!=[handle.sourceSha+'\t'+source.PUBLISHED_REF]:reject()
    source._check_local_source(handle.sourceSha)


def _spawn(handle,code):
    return subprocess.Popen(['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',
        '-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','ForwardX11=no','-o','PermitLocalCommand=no','-T',
        handle.hostAlias,'exec python3 -I -u -c '+shlex.quote(code)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,bufsize=0,close_fds=True)


def _small_write(stream,value,timeout):
    pending=memoryview(_frame(value));fd=stream.fileno();blocking=os.get_blocking(fd);end=time.monotonic()+timeout
    os.set_blocking(fd,False)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(fd,selectors.EVENT_WRITE)
            while pending:
                left=end-time.monotonic()
                if left<=0 or not selector.select(left):reject()
                try:count=os.write(fd,pending)
                except BlockingIOError:continue
                if count<=0:reject()
                pending=pending[count:]
    finally:os.set_blocking(fd,blocking)


def _small_read(stream,timeout,*,stderr=None,error_state=None):
    end=time.monotonic()+timeout
    def exact(size):
        raw=bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(stream,selectors.EVENT_READ,'out')
            if stderr is not None and not error_state[0]:selector.register(stderr,selectors.EVENT_READ,'err')
            while len(raw)<size:
                left=end-time.monotonic()
                if left<=0:reject()
                events=selector.select(left)
                if not events:reject()
                for key,_ in events:
                    if key.data=='err':
                        if os.read(key.fd,65536):reject()
                        error_state[0]=True;selector.unregister(stderr)
                    else:
                        chunk=os.read(key.fd,size-len(raw))
                        if not chunk:reject()
                        raw.extend(chunk)
        return bytes(raw)
    size=struct.unpack('!I',exact(4))[0]
    if not 0<size<=MAX_FRAME:reject()
    return decode(exact(size))


class SceneSSHClientV3(SceneClientV3):
    def __init__(self,handle):
        self._process=None;self._stderr_eof=[False];self._closed=False;self._owner=(os.getpid(),threading.get_ident())
        try:
            if (type(handle) is not SceneSSHHandleV3 or type(handle.sceneId) is not str
                    or re.fullmatch('dw-scene-[0-9a-f]{16}',handle.sceneId) is None
                    or handle.socketPath!='/var/tmp/'+handle.sceneId+'/control.sock'
                    or type(handle.controlKey) is not bytes or len(handle.controlKey)!=32
                    or type(handle.hostAlias) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',handle.hostAlias) is None
                    or type(handle.sourceSha) is not str or re.fullmatch('[0-9a-f]{40}',handle.sourceSha) is None
                    or type(handle.archiveBytes) is not bytes or not 0<len(handle.archiveBytes)<=2*1024*1024):reject()
            # Same original published checkout/source gate as the SSH managers;
            # a caller-selected ZIP and its own digest do not authorize code.
            _verify_source(handle)
            self._handle=handle;self._nonce=__import__('secrets').token_hex(32);self._seq=0
            digest=hashlib.sha256(handle.archiveBytes).hexdigest()
            config=dict(entrypoint=ENTRYPOINT,sourceSha=handle.sourceSha,archiveDigest=digest,channelNonce=self._nonce,
                hostId=handle.hostAlias,archiveBase64=base64.b64encode(handle.archiveBytes).decode(),
                handle=dict(sceneId=handle.sceneId,socketPath=handle.socketPath,controlKey=base64.b64encode(handle.controlKey).decode()))
            self._process=_spawn(handle,_bootstrap(digest,handle.sourceSha))
            write_frame(self._process.stdin,config,timeout=15)
            ready=self._read(20)
            if ready!=dict(kind='scene-control-ready-v3',channelNonce=self._nonce,sceneId=handle.sceneId,
                    sourceSha=handle.sourceSha,archiveDigest=digest):reject()
            _ISSUED_CLIENTS[self]=_client_identity(self)
        except BaseException:
            self.close();raise

    def _read(self,timeout):
        return _small_read(self._process.stdout,timeout,stderr=self._process.stderr,error_state=self._stderr_eof)

    def _owned(self):
        if self._owner!=(os.getpid(),threading.get_ident()):reject()

    def _call(self,command,args=None):
        self._owned()
        if self._closed or command not in _COMMANDS:reject()
        try:
            self._seq+=1;budget=_BUDGETS.get(command,5)
            request=dict(kind='scene-control-command-v3',channelNonce=self._nonce,seq=self._seq,command=command)
            if args is not None:request['args']=args
            _small_write(self._process.stdin,request,5)
            reply=self._read(budget+5)
            expected=dict(kind='scene-control-result-v3',channelNonce=self._nonce,seq=self._seq,command=command)
            if type(reply) is not dict or set(reply)!=set(expected)|{'result'} or any(canonical(reply[k])!=canonical(v) for k,v in expected.items()):reject()
            result=reply['result']
            if type(result) is not dict or any(result.get(key) is not False for key in _FALSE):reject()
            if command in ('detach','closeScene'):self._finish(command)
            return result
        except BaseException:
            self.close();raise

    def _finish(self,command):
        terminal=self._read(END_TIMEOUT)
        expected=dict(channelNonce=self._nonce,result=dict(kind='scene-control-closed-v3',sceneId=self._handle.sceneId,
            command=command,seq=self._seq))
        if canonical(terminal)!=canonical(expected):reject()
        self._process.stdin.close();end=time.monotonic()+END_TIMEOUT;stdout_eof=False
        while not stdout_eof or not self._stderr_eof[0]:
            left=end-time.monotonic()
            if left<=0:reject()
            with selectors.DefaultSelector() as selector:
                if not stdout_eof:selector.register(self._process.stdout,selectors.EVENT_READ,'out')
                if not self._stderr_eof[0]:selector.register(self._process.stderr,selectors.EVENT_READ,'err')
                events=selector.select(left)
                if not events:reject()
                for key,_ in events:
                    if os.read(key.fd,65536):reject()
                    if key.data=='out':stdout_eof=True
                    else:self._stderr_eof[0]=True
        left=end-time.monotonic()
        if left<=0:reject()
        self._process.wait(timeout=left)
        if self._process.returncode!=0:reject()
        self._closed=True
        for stream in (self._process.stdout,self._process.stderr):stream.close()

    def detach(self):return self._call('detach')
    def close_scene(self):return self._call('closeScene')
    def close(self):
        self._owned()
        if self._closed:return
        self._closed=True;p=self._process
        if p is None:return
        if not p.stdin.closed:p.stdin.close()
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
        for stream in (p.stdout,p.stderr):
            if not stream.closed:stream.close()


def _remote_main(config):
    expected={'entrypoint','sourceSha','archiveDigest','channelNonce','hostId','handle'}
    if (type(config) is not dict or set(config)!=expected or config['entrypoint']!=ENTRYPOINT
            or type(config['channelNonce']) is not str or re.fullmatch('[0-9a-f]{64}',config['channelNonce']) is None
            or type(config['handle']) is not dict or set(config['handle'])!={'sceneId','socketPath','controlKey'}):reject()
    value=config['handle'];key=base64.b64decode(value['controlKey'],validate=True)
    if len(key)!=32 or base64.b64encode(key).decode()!=value['controlKey']:reject()
    handle=SceneHandleV3(value['sceneId'],value['socketPath'],key);client=SceneClientV3(handle);seq=0
    try:
        _small_write(sys.stdout.buffer,dict(kind='scene-control-ready-v3',channelNonce=config['channelNonce'],sceneId=handle.sceneId,
            sourceSha=config['sourceSha'],archiveDigest=config['archiveDigest']),5)
        while True:
            message=_small_read(sys.stdin.buffer,130)
            if (type(message) is not dict or set(message) not in ({'kind','channelNonce','seq','command'},
                    {'kind','channelNonce','seq','command','args'}) or message['kind']!='scene-control-command-v3'
                    or message['channelNonce']!=config['channelNonce'] or type(message['seq']) is not int
                    or message['seq']!=seq+1 or message['command'] not in _COMMANDS):reject()
            seq=message['seq'];command=message['command']
            result=client._call(command,message.get('args'))
            _small_write(sys.stdout.buffer,dict(kind='scene-control-result-v3',channelNonce=config['channelNonce'],
                seq=seq,command=command,result=result),5)
            if command in ('detach','closeScene'):
                return dict(kind='scene-control-closed-v3',sceneId=handle.sceneId,command=command,seq=seq)
    finally:client.close()
