"""Mac-owned fixed SSH manager session. Caller JSON/Popen cannot issue a session.

One calling thread owns the session; stderr has its own bounded reader. The
kernel boot in manager bindings is never used as gateway observer identity.
"""
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import subprocess
import threading
import time
import weakref

import deployment_compose_owned_recovery_ssh_v3_host as loader
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_profile3_prepare_ssh_probe import _private_root
from deployment_compose_v3_channel_worker import write_frame

_ISSUED = weakref.WeakKeyDictionary()


def reject():
    raise ValueError('compose-owned-recovery-session-v3-rejected') from None


def _spawn(argv):
    return subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,bufsize=0,close_fds=True)


def issued(session,process=None):
    if type(session) is not OwnedRecoverySSHSessionV3:reject()
    record=_ISSUED.get(session)
    if (record is None or record[:2]!=(os.getpid(),threading.get_ident())
            or record[2] is not session._process or (process is not None and process is not record[2])
            or record[3:]!=(session.nonce,session.source_sha,session.archive_digest,session.host_id)):reject()
    return session


class OwnedRecoverySSHSessionV3:
    def __init__(self,private_root,ssh_alias,source_sha,*,timeout=30):
        if (os.name!='posix' or type(ssh_alias) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',ssh_alias)
                or type(source_sha) is not str or not re.fullmatch('[0-9a-f]{40}',source_sha)
                or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60):reject()
        root=_private_root(private_root)
        archive=loader.published_manager_archive(source_sha)
        self.source_sha,self.host_id=source_sha,ssh_alias
        self.archive_digest=hashlib.sha256(archive).hexdigest()
        self.nonce=secrets.token_hex(32)
        self._pid,self._thread=os.getpid(),threading.get_ident()
        self._process=None;self._reader=None
        self._errors=[];self._stop_reader=threading.Event()
        self._started=self._finished=self._closed=False
        self._cleanup_mode=False
        self._binding=None;self._count=self._bytes=0
        self._deadline=time.monotonic()+timeout
        self._maximum=time.monotonic()+3600
        case=root/('managed-ssh-'+secrets.token_hex(12));case.mkdir(mode=0o700)
        fd=os.open(case/'stderr.private.txt',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            self._process=_spawn(loader.manager_ssh_argv(ssh_alias,self.archive_digest,source_sha))
            if type(self._process) is not subprocess.Popen:reject()
            _ISSUED[self]=(self._pid,self._thread,self._process,self.nonce,source_sha,self.archive_digest,ssh_alias)
            def drain(stderr_fd=fd):
                size=0
                try:
                    with os.fdopen(stderr_fd,'wb',buffering=0) as output,selectors.DefaultSelector() as selector:
                        selector.register(self._process.stderr,selectors.EVENT_READ)
                        while not self._stop_reader.is_set():
                            if not selector.select(.1):continue
                            raw=os.read(self._process.stderr.fileno(),65536)
                            if not raw:return
                            if size<1024*1024:output.write(raw[:1024*1024-size])
                            size+=len(raw)
                            if size>1024*1024:self._errors.append('stderr-bound');return
                except Exception:self._errors.append('stderr-io')
            self._reader=threading.Thread(target=drain,daemon=True);self._reader.start();fd=None
            self._send('initial',dict(entrypoint=loader.MANAGER_ENTRYPOINT,sourceSha=source_sha,
                archiveDigest=self.archive_digest,hostId=ssh_alias,channelNonce=self.nonce,
                archiveBase64=base64.b64encode(archive).decode('ascii')))
            bound=self._receive()
            if set(bound)!={'kind','channelNonce','binding'} or bound['kind']!='manager-bound':reject()
            binding=bound['binding']
            if (type(binding) is not dict or set(binding)!={'unit','kernelBoot','invocationId','sourceSha','archiveDigest','hostId'}
                    or binding['sourceSha']!=source_sha or binding['archiveDigest']!=self.archive_digest or binding['hostId']!=ssh_alias
                    or type(binding['unit']) is not str or not re.fullmatch('dw-writer-host-[0-9a-f]{16}\\.service',binding['unit'])
                    or type(binding['invocationId']) is not str or not re.fullmatch('[0-9a-f]{32}',binding['invocationId'])
                    or type(binding['kernelBoot']) is not str or not re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',binding['kernelBoot'])):reject()
            self._binding=encode(binding)
        except BaseException:
            if fd is not None:os.close(fd)
            try:self._dispose_local()
            except Exception:pass
            _ISSUED.pop(self,None)
            raise

    def _left(self,limit=30):
        issued(self)
        left=self._deadline-time.monotonic()
        if self._closed or left<=0 or (self._errors and not self._cleanup_mode):reject()
        return min(limit,left)

    def _send(self,kind,initial=None,**data):
        frame=initial if initial is not None else dict(kind=kind,channelNonce=self.nonce,**data)
        write_frame(self._process.stdin,frame,timeout=self._left())

    def _receive(self,limit=30):
        from deployment_compose_owned_recovery_controller_v3_host import _receive
        value=_receive(self._process.stdout,time.monotonic()+self._left(limit),[] if self._cleanup_mode else self._errors)
        self._count+=1;self._bytes+=len(encode(value))
        if (self._count>4096 or self._bytes>64*1024*1024 or type(value) is not dict
                or value.get('channelNonce')!=self.nonce):reject()
        return value

    def begin(self,timeout):
        issued(self)
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=3600 or self._started:reject()
        self._left();self._deadline=min(self._maximum,time.monotonic()+timeout)
        self._started=True
        self._send('manager-start')

    def send_worker(self,frame):
        if not self._started or type(frame) is not dict or frame.get('channelNonce')!=self.nonce:reject()
        self._send('worker-frame',frame=frame)

    def receive_worker(self,limit=900):
        if not self._started:reject()
        value=self._receive(limit)
        if set(value)!={'kind','channelNonce','frame'} or value['kind']!='worker-frame':reject()
        frame=value['frame']
        if type(frame) is not dict or frame.get('channelNonce')!=self.nonce or type(frame.get('kind')) is not str:reject()
        return frame

    def _terminal(self,value,*,business):
        if (set(value)!={'kind','channelNonce','binding','workerStartRequested','reason','wrapperStopped',
                'transportReturncode','daemonCleanupVerified','productionReady'}
                or value['kind']!='manager-stopped' or encode(value['binding'])!=self._binding
                or value['workerStartRequested'] is not self._started or value['wrapperStopped'] is not True
                or value['daemonCleanupVerified'] is not False or value['productionReady'] is not False
                or type(value['transportReturncode']) is not int
                or value['reason'] not in ('worker-eof','requested-stop')):reject()
        if business and (value['reason']!='worker-eof' or value['transportReturncode']!=0):reject()

    def _exit(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self._process.stdout,selectors.EVENT_READ)
            if not selector.select(self._left()):reject()
            if os.read(self._process.stdout.fileno(),1):reject()
        if self._process.wait(timeout=self._left())!=0:reject()
        self._reader.join(timeout=self._left(5))
        if self._reader.is_alive() or self._errors:reject()
        self._finished=True

    def complete(self):
        issued(self)
        if not self._started or self._finished:reject()
        self._terminal(self._receive(),business=True)
        self._exit()

    def _dispose_local(self):
        failure=None
        def cleanup(action):
            nonlocal failure
            try:action()
            except Exception as error:
                if failure is None:failure=error
        if self._process is not None:
            if self._process.poll() is None:
                cleanup(self._process.kill);cleanup(lambda:self._process.wait(timeout=5))
        self._stop_reader.set()
        if self._reader is not None and self._reader.ident is not None:cleanup(lambda:self._reader.join(timeout=1))
        if self._process is not None:
            for stream in (self._process.stdin,self._process.stdout,self._process.stderr):
                if stream is not None:cleanup(stream.close)
        if failure is not None:raise failure

    def close(self):
        if (os.getpid(),threading.get_ident())!=(self._pid,self._thread):reject()
        if self._closed:return
        failure=None
        try:
            if not self._finished and self._binding is not None and self._process.poll() is None:
                # Cleanup has its own finite budget; it cannot resume business.
                self._deadline=time.monotonic()+30
                self._cleanup_mode=True
                self._send('manager-stop')
                for _ in range(4096):
                    value=self._receive()
                    if value['kind']=='worker-frame':continue
                    self._terminal(value,business=False);self._exit();break
                else:reject()
        except Exception as error:failure=error
        finally:
            try:self._dispose_local()
            except Exception as error:
                if failure is None:failure=error
            finally:self._closed=True;_ISSUED.pop(self,None)
        if failure is not None:raise failure
