"""Fixed local single-create actor. Private pipes are the only command channel.

This is not a general Docker proxy. No signing helper, fork, retry, arbitrary
command, production socket or successor action exists in the leaf process.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import stat
import subprocess
import sys
import threading
import time
from functools import wraps


def serialized(method):
    @wraps(method)
    def locked(self,*args,**kwargs):
        if os.getpid()!=self._owner_pid:reject()
        with self._mutex:
            if os.getpid()!=self._owner_pid:reject()
            return method(self,*args,**kwargs)
    return locked

MAX_FRAME=196608
PATH=re.compile(r'/v1\.45/containers/create\?name=dwc-[0-9a-f]{24}-[A-Za-z0-9_.-]+\Z')
HASH=re.compile(r'[0-9a-f]{64}\Z')


def encode(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
def reject():raise ValueError('action-actor-v4-rejected')
def send(stream,v,deadline=None):
    raw=encode(v)+b'\n'
    if len(raw)>MAX_FRAME:reject()
    if deadline is None:deadline=time.monotonic()+10
    fd=stream.fileno();os.set_blocking(fd,False)
    while raw:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([],[fd],[],remaining)[1]:reject()
        try:written=os.write(fd,raw)
        except BlockingIOError:continue
        if written<=0:reject()
        raw=raw[written:]

def receive(stream,deadline):
    pending=bytearray()
    while True:
        left=deadline-time.monotonic()
        if left<=0 or not select.select([stream],[],[],left)[0]:reject()
        chunk=os.read(stream.fileno(),1)
        if not chunk or len(pending)>=MAX_FRAME:reject()
        if chunk==b'\n':return json.loads(pending)
        pending.extend(chunk)


def socket_facts(path):
    p=Path(path);root=p.parent
    if not p.is_absolute() or root.resolve()!=root or p==Path('/var/run/docker.sock'):reject()
    d=root.stat();s=p.lstat()
    if (stat.S_IMODE(d.st_mode)!=0o700 or d.st_uid!=os.getuid()
            or not stat.S_ISSOCK(s.st_mode) or s.st_uid!=os.getuid()):reject()
    return [d.st_dev,d.st_ino,s.st_dev,s.st_ino]


def leaf():
    config=receive(sys.stdin.buffer,time.monotonic()+10)
    fields={'schemaVersion','kind','socket','socketIdentity','path','bodyBase64','bodyDigest',
            'requestHash','contextDigest','actionDigest','sessionHash','actorEpoch'}
    if (type(config) is not dict or set(config)!=fields or config['schemaVersion']!=4
            or type(config['schemaVersion']) is not int or config['kind']!='single-create-leaf-v4'
            or type(config['path']) is not str or PATH.fullmatch(config['path']) is None
            or any(type(config[k]) is not str or HASH.fullmatch(config[k]) is None for k in
                   ('bodyDigest','requestHash','contextDigest','actionDigest','sessionHash','actorEpoch'))):reject()
    raw=base64.b64decode(config['bodyBase64'],validate=True)
    if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=config['bodyDigest']:reject()
    if socket_facts(config['socket'])!=config['socketIdentity']:reject()
    send(sys.stdout.buffer,{'kind':'ready','actorEpoch':config['actorEpoch']})
    go=receive(sys.stdin.buffer,time.monotonic()+180)
    binding={k:config[k] for k in ('requestHash','contextDigest','actionDigest','sessionHash','actorEpoch')}
    if (type(go) is not dict or set(go)!=set(binding)|{'kind','nonce','deadline','cursor','scopeOrdinal','planWriteIndex'}
            or go['kind']!='go-v4' or any(go[k]!=v for k,v in binding.items())
            or type(go['nonce']) is not str or HASH.fullmatch(go['nonce']) is None
            or type(go['deadline']) not in (int,float) or not time.monotonic()<go['deadline']<=time.monotonic()+180
            or type(go['scopeOrdinal']) is not int or go['scopeOrdinal']!=0
            or type(go['planWriteIndex']) is not int or go['planWriteIndex']!=0
            or type(go['cursor']) is not dict or set(go['cursor'])!={'seq','head'}
            or type(go['cursor']['seq']) is not int or go['cursor']['seq']!=2
            or type(go['cursor']['head']) is not str or HASH.fullmatch(go['cursor']['head']) is None):reject()
    # The only go is consumed before any socket access. This process exits after
    # one response or any failure, even if further frames are queued in its pipe.
    if socket_facts(config['socket'])!=config['socketIdentity'] or time.monotonic()>=go['deadline']:reject()
    connection=http.client.HTTPConnection('localhost',timeout=min(30,go['deadline']-time.monotonic()))
    peer=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    peer.settimeout(min(30,go['deadline']-time.monotonic()))
    engine_deadline=min(go['deadline'],time.monotonic()+30)
    def abort():
        try:peer.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        peer.close()
    timer=threading.Timer(max(0,engine_deadline-time.monotonic()),abort);timer.daemon=True;timer.start()
    try:
        peer.connect(config['socket']);connection.sock=peer
        if socket_facts(config['socket'])!=config['socketIdentity'] or time.monotonic()>=engine_deadline:reject()
        connection.request('POST',config['path'],body=raw,headers={'Content-Length':str(len(raw)),'Content-Type':'application/json','Connection':'close'})
        response=connection.getresponse()
        length=response.getheader('Content-Length')
        if length is None or not length.isdecimal() or int(length)>65536 or response.getheader('Transfer-Encoding') is not None:reject()
        body=response.read(int(length)+1)
        if len(body)!=int(length) or time.monotonic()>=min(go['deadline'],engine_deadline):reject()
        send(sys.stdout.buffer,dict(kind='response-v4',nonce=go['nonce'],status=response.status,
                                   bodyBase64=base64.b64encode(body).decode('ascii')),go['deadline'])
    finally:timer.cancel();connection.close();peer.close()


class WriterActorHandleV4:pass
class WriterActorTerminationV4:pass


class ActionActorSupervisorV4:
    def __init__(self):
        self._owner_pid=os.getpid();self._mutex=threading.RLock();self.boot=secrets.token_hex(32);self._actors={};self._proofs={};self._closed=False;self._go_sent=set()

    @serialized
    def _start(self,config):
        if self._closed:reject()
        process=subprocess.Popen([sys.executable,'-I','-S',str(Path(__file__).resolve()),'--fixed-leaf-v4'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={},close_fds=True,start_new_session=True)
        handle=WriterActorHandleV4()
        self._actors[handle]=(process,json.loads(encode(config)))
        try:
            deadline=time.monotonic()+10
            send(process.stdin,config,deadline)
            response=receive(process.stdout,deadline)
            if response!={'kind':'ready','actorEpoch':config['actorEpoch']}:reject()
        except BaseException:
            self.stop_and_join(handle);raise
        return handle

    @serialized
    def actor_identity(self,handle,session_hash):
        if (self._closed or type(handle) is not WriterActorHandleV4 or handle not in self._actors
                or self._actors[handle][1]['sessionHash']!=session_hash):reject()
        return self._actors[handle][1]['actorEpoch']

    @serialized
    def send_go(self,handle,*,host,go_evidence):
        from deployment_compose_action_host_v4 import SingleActionHostV4
        if self._closed or type(host) is not SingleActionHostV4 or handle not in self._actors or handle in self._go_sent:reject()
        process,config=self._actors[handle]
        if process.poll() is not None:reject()
        go=host._go_for_supervisor(go_evidence,self,handle)
        if any(go[k]!=config[k] for k in ('requestHash','contextDigest','actionDigest','sessionHash','actorEpoch')):reject()
        self._go_sent.add(handle)
        send(process.stdin,go,go['deadline'])

    def receive_response(self,handle,deadline):
        if os.getpid()!=self._owner_pid:reject()
        with self._mutex:
            if os.getpid()!=self._owner_pid:reject()
            if self._closed or handle not in self._go_sent or handle not in self._actors:reject()
            stream=self._actors[handle][0].stdout
        return receive(stream,deadline)

    @serialized
    def stop_and_join(self,handle):
        if type(handle) is not WriterActorHandleV4 or handle not in self._actors:reject()
        if handle in self._proofs:return self._proofs[handle][0]
        process,config=self._actors[handle]
        if process.poll() is None:process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        process.stdin.close();process.stdout.close()
        proof=WriterActorTerminationV4()
        self._proofs[handle]=(proof,hashlib.sha256(b'dev-workflow:local-action-termination:v4\0'+encode(
            dict(boot=self.boot,epoch=config['actorEpoch'],session=config['sessionHash'],
                 requestHash=config['requestHash'],contextDigest=config['contextDigest'],
                 actionDigest=config['actionDigest'],bodyDigest=config['bodyDigest'],
                 socketIdentity=config['socketIdentity'],returnCode=process.returncode))).hexdigest())
        return proof

    @serialized
    def termination_digest(self,handle,proof,session_hash):
        self.actor_identity(handle,session_hash)
        record=self._proofs.get(handle)
        if type(proof) is not WriterActorTerminationV4 or record is None or record[0] is not proof:reject()
        return record[1]

    @serialized
    def close(self):
        for actor in list(self._actors):self.stop_and_join(actor)
        self._closed=True


if __name__=='__main__':
    if sys.argv[1:]!=['--fixed-leaf-v4']:reject()
    leaf()
