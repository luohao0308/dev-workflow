"""Native independent daemon creator; no restart adoption or execution authority.

Only this live issuer's original process receives stop requests. The borrowed
observer is read-only. Daemon startup is diagnostic; product resources/approval
and aggregate cleanup are separate. Failure cleanup has its own finite grace.
"""
import math
import os
from pathlib import Path
import re
import selectors
import secrets
import signal
import struct
import subprocess
import sys
import time
import threading
import weakref

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
import deployment_compose_owned_recovery_unit_v3_host as units
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_v3_channel_worker import write_frame

_RECORDS=weakref.WeakKeyDictionary()


def reject():raise ValueError('compose-daemon-owner-v3-rejected') from None


def _left(deadline):
    value=deadline-time.monotonic()
    if value<=0:reject()
    return value


def _deadline(timeout,maximum):
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=maximum:reject()
    return time.monotonic()+timeout


def _spawn(argv):
    return subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        bufsize=0,close_fds=True,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})


def _record(owner):
    record=_RECORDS.get(owner)
    if type(owner) is not OwnedRecoveryDaemonHostV3 or record is None or record['owner']!=(os.getpid(),threading.get_ident()):reject()
    return record


def _receive(record,deadline):
    process=record['process']
    def exact(size):
        result=bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ,'stdout')
            selector.register(process.stderr,selectors.EVENT_READ,'stderr')
            while len(result)<size:
                for key,_ in selector.select(min(.1,_left(deadline))):
                    raw=os.read(key.fd,min(65536,size-len(result)) if key.data=='stdout' else 65536)
                    if key.data=='stderr':
                        if raw:
                            record['stderr_bytes']+=len(raw);reject()
                        selector.unregister(process.stderr);record['stderr_eof']=True
                    else:
                        if not raw:reject()
                        result.extend(raw)
        return bytes(result)
    size=struct.unpack('!I',exact(4))[0]
    if not 0<size<=8192:reject()
    return decode(exact(size))


def _finish(record,deadline):
    process=record['process']
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout,selectors.EVENT_READ,'stdout')
        if not record['stderr_eof']:selector.register(process.stderr,selectors.EVENT_READ,'stderr')
        while selector.get_map():
            for key,_ in selector.select(min(.1,_left(deadline))):
                raw=os.read(key.fd,65536)
                if raw:reject()
                selector.unregister(key.fileobj)
                if key.data=='stderr':record['stderr_eof']=True
    if process.wait(timeout=_left(deadline))!=0 or not record['stderr_eof'] or record['stderr_bytes']:reject()


def _cleanup(record,primary):
    process=record['process'];failed=False
    if process is not None:
        if process.poll() is None:
            try:process.terminate();process.wait(timeout=15)
            except Exception:
                try:process.kill();process.wait(timeout=5)
                except Exception:failed=True
        for stream in (process.stdin,process.stdout,process.stderr):
            if stream is not None and not stream.closed:
                try:stream.close()
                except Exception:failed=True
    if failed:
        try:
            if hasattr(primary,'add_note'):primary.add_note('daemon owner process cleanup incomplete')
        except Exception:pass


def _dispose_failed_observer(record):
    observer=record['observer']
    if observer is None:return
    try:
        try:observer.verify_stopped(timeout=5)
        except Exception:pass
    finally:
        try:observer.close()
        except Exception:pass
        finally:record['observer']=None


class OwnedRecoveryDaemonHostV3:
    def __init__(self):
        _RECORDS[self]=dict(owner=(os.getpid(),threading.get_ident()),phase='new',process=None,nonce=None,
            observer=None,binding=None,stop_sent=False,stderr_eof=False,stderr_bytes=0,result=None,hello=None)

    def __copy__(self):reject()
    def __deepcopy__(self,memo):reject()
    def __reduce_ex__(self,protocol):reject()

    def start(self,*,timeout=90):
        record=_record(self)
        if record['phase']!='new':reject()
        deadline=_deadline(timeout,90);record['phase']='starting'
        try:
            units._environment();nonce=secrets.token_hex(32);record['nonce']=nonce
            process=_spawn([sys.executable,'-I','-u',str(Path(__file__).resolve()),'--owner',nonce])
            if (type(process) is not subprocess.Popen or process.text_mode
                    or any(stream is None for stream in (process.stdin,process.stdout,process.stderr))):reject()
            record['process']=process
            value=_receive(record,deadline)
            if (type(value) is not dict or set(value)!={'kind','nonce','root','daemonId'}
                    or value['kind']!='daemon-owner-hello-v3' or value['nonce']!=nonce
                    or type(value['root']) is not str or re.fullmatch('/var/tmp/dw-engine-[0-9a-f]{16}',value['root']) is None
                    or type(value['daemonId']) is not str or not 0<len(value['daemonId'])<=256
                    or process.poll() is not None):reject()
            record['hello']=encode(value)
            observer=ObservedRecoveryDaemonV3(value['root'],value['daemonId'],kernel_boot=units._boot(),timeout=min(15,_left(deadline)))
            record['observer']=observer;record['binding']=encode(observer.binding())
            _left(deadline)
            if process.poll() is not None:reject()
            record['phase']='live'
            return observer
        except BaseException as primary:
            record['phase']='failed';_cleanup(record,primary)
            _dispose_failed_observer(record)
            reject()

    @property
    def observer(self):
        record=_record(self)
        if record['phase']!='live' or record['process'].poll() is not None:reject()
        if encode(record['observer'].binding())!=record['binding']:reject()
        return record['observer']

    def stop(self,*,timeout=60):
        record=_record(self)
        deadline=_deadline(timeout,60)
        if record['phase']=='stopped':return decode(record['result'])
        if record['phase'] not in ('live','failed') or record['process'] is None:reject()
        try:
            if record['phase']=='failed':
                _cleanup(record,ValueError('cleanup-retry'))
                _dispose_failed_observer(record)
                reject()  # Cleanup evidence never upgrades a failed protocol.
            if encode(record['observer'].binding())!=record['binding']:reject()
            if record['stop_sent']:reject()
            record['stop_sent']=True
            write_frame(record['process'].stdin,dict(kind='daemon-owner-stop-v3',nonce=record['nonce']),timeout=_left(deadline))
            record['process'].stdin.close()
            value=_receive(record,deadline);hello=decode(record['hello'])
            flags=('completed','stopped','productionSnapshotUnchanged')
            if (type(value) is not dict or set(value)!={'kind','nonce','root','daemonId',*flags}
                    or value['kind']!='daemon-owner-terminal-v3' or value['nonce']!=record['nonce']
                    or value['root']!=hello['root'] or value['daemonId']!=hello['daemonId']
                    or any(value[key] is not True for key in flags)):reject()
            _finish(record,deadline)
            record['observer'].verify_stopped(timeout=min(30,_left(deadline)))
            if encode(record['observer'].binding())!=record['binding']:reject()
            record['observer'].close()
            for stream in (record['process'].stdin,record['process'].stdout,record['process'].stderr):
                if not stream.closed:stream.close()
            result=dict(daemonStoppedVerified=True,creatorProcessReaped=True,transportVerified=True,
                productionSnapshotUnchanged=True,resourceInventoryRestored=False,daemonCleanupVerified=False,
                authorityGranted=False,runtimePermit=False,recoveryAuthorized=False,productionReady=False)
            _left(deadline);record['result']=encode(result);record['phase']='stopped'
            return decode(record['result'])
        except BaseException as primary:
            record['phase']='failed';_cleanup(record,primary)
            _dispose_failed_observer(record)
            reject()

    def close(self):return self.stop()
    def __enter__(self):self.start();return self
    def __exit__(self,exc_type,primary,tb):
        try:self.stop()
        except Exception:
            if primary is None:raise
            if hasattr(primary,'add_note'):primary.add_note('daemon owner stop incomplete')


def _owner(nonce):
    if type(nonce) is not str or re.fullmatch('[0-9a-f]{64}',nonce) is None:reject()
    units._environment()
    def interrupted(*args):raise SystemExit('daemon-owner-interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    from deployment_compose_isolated_daemon_probe import probe
    identity={}
    def waiting(root,info):
        identity.update(root=str(root),daemonId=info['ID'])
        write_frame(sys.stdout.buffer,dict(kind='daemon-owner-hello-v3',nonce=nonce,**identity),timeout=5)
        with selectors.DefaultSelector() as selector:
            selector.register(sys.stdin.buffer,selectors.EVENT_READ)
            if not selector.select(3590):reject()
        # EOF is the fixed parent's disappearance, not a request to adopt ownership.
        first=os.read(sys.stdin.fileno(),4)
        if not first:return dict(success=True)
        end=time.monotonic()+5
        if len(first)!=4:
            header=bytearray(first)
            with selectors.DefaultSelector() as selector:
                selector.register(sys.stdin.buffer,selectors.EVENT_READ)
                while len(header)<4:
                    if not selector.select(_left(end)):reject()
                    chunk=os.read(sys.stdin.fileno(),4-len(header))
                    if not chunk:reject()
                    header.extend(chunk)
            first=bytes(header)
        size=struct.unpack('!I',first)[0]
        if not 0<size<=8192:reject()
        remaining=bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(sys.stdin.buffer,selectors.EVENT_READ)
            while len(remaining)<size:
                if not selector.select(_left(end)):reject()
                chunk=os.read(sys.stdin.fileno(),size-len(remaining))
                if not chunk:reject()
                remaining.extend(chunk)
            value=decode(bytes(remaining))
            if value!=dict(kind='daemon-owner-stop-v3',nonce=nonce):reject()
            if not selector.select(_left(end)) or os.read(sys.stdin.fileno(),1):reject()
        return dict(success=True)
    result=probe(waiting,storage_driver='overlayfs',workload_lifetime_seconds=3600,bind_to_owned_writer=False,require_bound_stop=True)
    flags={key:result.get(key) is True for key in ('completed','stopped','productionSnapshotUnchanged')}
    if not identity:reject()
    write_frame(sys.stdout.buffer,dict(kind='daemon-owner-terminal-v3',nonce=nonce,**identity,**flags),timeout=5)
    if not all(flags.values()):reject()


if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1]!='--owner':reject()
    _owner(sys.argv[2])
