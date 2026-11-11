"""Host-only first-create TLS client; process drain is not recovery authority.

Raw Engine access and all authorization remain in the parent V3 gateway.
No command/entry callback or ordinary CLI is exposed.
"""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from functools import wraps
import time

MAX_FRAME = 196608
LEAF = r'''
import base64,ctypes,hashlib,http.client,json,os,re,select,socket,ssl,sys,time
LIMIT=196608
def reject():raise ValueError('owned-create-leaf-rejected')
def pairs(items):
 d={}
 for k,v in items:
  if k in d:reject()
  d[k]=v
 return d
def read(deadline):
 data=bytearray()
 while True:
  left=deadline-time.monotonic()
  if left<=0 or not select.select([0],[],[],left)[0]:reject()
  c=os.read(0,1)
  if not c or len(data)>=LIMIT:reject()
  if c==b'\n':return json.loads(data,object_pairs_hook=pairs,parse_constant=lambda v:reject())
  data.extend(c)
def send(v,deadline=None):
 if deadline is None:deadline=time.monotonic()+15
 raw=json.dumps(v,separators=(',',':'),allow_nan=False).encode()+b'\n'
 if len(raw)>LIMIT:reject()
 os.set_blocking(1,False)
 while raw:
  left=deadline-time.monotonic()
  if left<=0 or not select.select([],[1],[],left)[1]:reject()
  try:n=os.write(1,raw)
  except BlockingIOError:continue
  if n<=0:reject()
  raw=raw[n:]
lib=ctypes.CDLL(None,use_errno=True)
if os.geteuid()==0 or lib.prctl(38,1,0,0,0)!=0 or lib.prctl(39,0,0,0,0)!=1:reject()
s=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
if any(int(s[k].strip(),16) for k in ('CapEff','CapPrm','CapAmb')):reject()
send({'kind':'booted'})
c=read(time.monotonic()+15)
fields={'kind','port','pin','path','body','headers','ca','cert','key','nonce','deadline','bodyDigest'}
if type(c)!=dict or set(c)!=fields or c['kind']!='create-config' or type(c['port'])!=int or not 0<c['port']<65536:reject()
if type(c['path'])!=str or re.fullmatch(r'/v1\.45/containers/create\?name=dwc-[a-f0-9]{24}-[A-Za-z0-9_.-]+',c['path']) is None:reject()
if any(type(c[k])!=str or re.fullmatch('[a-f0-9]{64}',c[k]) is None for k in ('pin','nonce','bodyDigest')):reject()
body=base64.b64decode(c['body'],validate=True)
if len(body)>65536 or hashlib.sha256(body).hexdigest()!=c['bodyDigest']:reject()
if type(c['headers'])!=dict or len(c['headers'])>64 or any(type(k)!=str or type(v)!=str or len(k)+len(v)>8192 or any(ch in k+v for ch in '\r\n') for k,v in c['headers'].items()):reject()
if c['headers'].get('Content-Length')!=str(len(body)):reject()
if type(c['deadline']) not in (int,float) or not time.monotonic()<c['deadline']<=time.monotonic()+180:reject()
go=read(c['deadline'])
if go!={'kind':'go','nonce':c['nonce']}:reject()
ctx=ssl.create_default_context(cafile=c['ca']);ctx.load_cert_chain(c['cert'],c['key'])
conn=http.client.HTTPSConnection('127.0.0.1',c['port'],context=ctx,timeout=min(30,c['deadline']-time.monotonic()))
try:
 peer=socket.create_connection(('127.0.0.1',c['port']),timeout=min(30,c['deadline']-time.monotonic()))
 conn.sock=ctx.wrap_socket(peer,server_hostname='localhost')
 if hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()!=c['pin']:reject()
 conn.request('POST',c['path'],body=body,headers=c['headers'])
 r=conn.getresponse();length=r.getheader('Content-Length')
 if length is None or not length.isdecimal() or int(length)>65536 or r.getheader('Transfer-Encoding') is not None:reject()
 body=r.read(int(length)+1)
 if len(body)!=int(length) or time.monotonic()>=c['deadline']:reject()
 send({'kind':'response','nonce':c['nonce'],'status':r.status,'body':base64.b64encode(body).decode()})
finally:conn.close()
# A parked leaf cannot perform another request, regardless of subsequent input.
while True:time.sleep(60)
'''


def reject():
    raise ValueError('owned-create-transport-v3-rejected') from None


def _pairs(items):
    result = {}
    for k, v in items:
        if k in result: reject()
        result[k] = v
    return result


def _read(stream, deadline):
    data = bytearray()
    while True:
        left = deadline-time.monotonic()
        if left <= 0 or not select.select([stream], [], [], left)[0]: reject()
        c = os.read(stream.fileno(), 1)
        if not c or len(data) >= MAX_FRAME: reject()
        if c == b'\n':
            return json.loads(data, object_pairs_hook=_pairs,
                parse_constant=lambda value: reject())
        data.extend(c)


def _send(stream, value, deadline):
    raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')+b'\n'
    if len(raw)>MAX_FRAME: reject()
    os.set_blocking(stream.fileno(), False)
    while raw:
        left=deadline-time.monotonic()
        if left<=0 or not select.select([], [stream], [], left)[1]: reject()
        try: count=os.write(stream.fileno(), raw)
        except BlockingIOError: continue
        if count<=0: reject()
        raw=raw[count:]


def _clear_acl(path, *, directory=False):
    names=['system.posix_acl_access']
    if directory:names.append('system.posix_acl_default')
    for name in names:
        try:os.removexattr(path,name,follow_symlinks=False)
        except OSError as error:
            if error.errno not in (errno.ENODATA,errno.ENOTSUP):reject()


def serialized(method):
    @wraps(method)
    def locked(self,*args,**kwargs):
        if os.getpid()!=self._owner:reject()
        with self._mutex:return method(self,*args,**kwargs)
    return locked


class OwnedCreateTransportV3:
    def __init__(self, *, worker_uid, worker_gid, ca_pem, client_cert_pem, client_key_pem):
        if (sys.platform!='linux' or os.geteuid()!=0
                or type(worker_uid) is not int or worker_uid<=0
                or type(worker_gid) is not int or worker_gid<=0
                or any(type(x) is not bytes or not 0<len(x)<=16384
                       for x in (ca_pem,client_cert_pem,client_key_pem))): reject()
        self._owner=os.getpid();self._mutex=threading.RLock();self._uid=worker_uid;self._gid=worker_gid
        self._pem=(ca_pem,client_cert_pem,client_key_pem)
        self._process=self._group=self._directory=None
        self._used=False;self._closed=False;self._process_proof=None;self._go_sent=False
        self._pending_terminal=None;self._terminal=None;self._response_fact=None

    def _check(self):
        if os.getpid()!=self._owner or self._closed: reject()

    @serialized
    def request(self, *, request_hash, scope_hash, port, pin, operation, body, headers,
                docker_socket, deadline):
        self._check()
        if (self._used or type(port) is not int or not 0<port<65536
                or type(body) is not bytes or len(body)>65536
                or operation.get('phase')!='create' or operation.get('method')!='POST'
                or hashlib.sha256(body).hexdigest()!=operation.get('bodyDigest')
                or type(pin) is not str or len(pin)!=64
                or type(deadline) not in (int,float) or not time.monotonic()<deadline<=time.monotonic()+180): reject()
        # A root-private ancestor prevents this non-root leaf reaching raw Engine.
        raw=Path(docker_socket)
        parent=raw.parent.stat()
        if (not raw.is_absolute() or raw.parent.resolve()!=raw.parent
                or parent.st_uid!=0 or stat.S_IMODE(parent.st_mode)!=0o700): reject()
        self._used=True
        try:
            from deployment_compose_writer_cgroup_v3_host import WriterCgroupV3
            self._group=WriterCgroupV3(request_hash=request_hash,scope_hash=scope_hash,
                worker_uid=self._uid,worker_gid=self._gid)
            self._process=subprocess.Popen([sys.executable,'-I','-S','-c',LEAF],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                user=self._uid,group=self._gid,extra_groups=[],env={},close_fds=True,start_new_session=True)
            if _read(self._process.stdout,deadline)!={'kind':'booted'}:reject()
            self._group.attach(self._process,deadline)
            self._group.verify_worker(self._process,deadline)
            self._directory=Path(tempfile.mkdtemp(prefix='dw-create-client-'))
            info=self._directory.stat();self._directory_identity=(info.st_dev,info.st_ino)
            _clear_acl(self._directory,directory=True)
            os.chown(self._directory,0,self._gid)
            paths=[]
            for name,pem in zip(('ca.pem','client.pem','client.key'),self._pem):
                path=self._directory/name
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as f:
                    _clear_acl(path)
                    f.write(pem)
                os.chown(path,0,self._gid);os.chmod(path,0o640);paths.append(str(path))
            os.chmod(self._directory,0o710)
            import secrets
            nonce=secrets.token_hex(32)
            _send(self._process.stdin,dict(kind='create-config',port=port,pin=pin,
                path=operation['path'],body=base64.b64encode(body).decode(),bodyDigest=operation['bodyDigest'],headers=headers,
                ca=paths[0],cert=paths[1],key=paths[2],nonce=nonce,deadline=deadline),deadline)
            self._go_sent=True
            _send(self._process.stdin,dict(kind='go',nonce=nonce),deadline)
            result=_read(self._process.stdout,deadline)
            if (type(result) is not dict or set(result)!={'kind','nonce','status','body'}
                    or result['kind']!='response' or result['nonce']!=nonce
                    or type(result['status']) is not int or not 100<=result['status']<=599):reject()
            data=base64.b64decode(result['body'],validate=True)
            if len(data)>65536:reject()
            self._response_fact=(result['status'],hashlib.sha256(data).hexdigest())
            return result['status'],data
        except Exception:
            reject()

    @serialized
    def close(self, deadline=None):
        if os.getpid()!=self._owner:reject()
        if self._closed:return
        if deadline is None:deadline=time.monotonic()+10
        import math
        if type(deadline) not in (int,float) or not math.isfinite(deadline) or deadline>time.monotonic()+180:reject()
        failure=None
        try:
            if self._process is not None:
                if not self._go_sent:
                    # Before GO this fixed bootstrap cannot fork or write.
                    if self._process.poll() is None:self._process.kill()
                    self._process.wait(timeout=max(0,deadline-time.monotonic()))
                elif self._group is not None:
                    if self._pending_terminal is None:
                        self._process_proof=self._group.kill_and_drain(self._process,deadline)
                        facts=self._group.capture_drain_facts(self._process,self._process_proof)
                        self._pending_terminal=(facts,self._response_fact)
                else:reject()
        except Exception as error:
            failure=error;self._process_proof=None
        finally:
            # Expired drain still reaches the retained group's revocation path.
            # It may kill without waiting, but cannot mint a completion proof.
            if self._group is not None:
                try:self._group.close(deadline)
                except Exception as error:
                    if failure is None:failure=error
        try:
            if self._process is None or self._process.poll() is not None:
                if self._process is not None:
                    self._process.stdin.close();self._process.stdout.close()
                if self._directory is not None:
                    info=self._directory.lstat()
                    if not stat.S_ISDIR(info.st_mode) or (info.st_dev,info.st_ino)!=self._directory_identity:reject()
                    shutil.rmtree(self._directory);self._directory=None
            else:
                if failure is None:failure=ValueError('owned-process-not-drained')
        except Exception as error:
            if failure is None:failure=error
        if failure is not None:reject()
        self._closed=True
        if self._pending_terminal is not None and self._response_fact is not None:
            self._terminal=self._pending_terminal

    @serialized
    def terminal_facts(self):
        if not self._closed or self._terminal is None:reject()
        return self._terminal
