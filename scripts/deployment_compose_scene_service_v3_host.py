"""Native root-only scene control; connection exclusion is not a writer fence.

The service retains one original daemon issuer. Disconnect revokes a controller
lease, not the daemon. The key authenticates diagnostic control, never approval.
No restart/adoption, product dispatch, or reconstructed stop authority exists.
"""
from dataclasses import dataclass,field
import hashlib
import base64
import hmac
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
from deployment_compose_daemon_owner_v3_host import OwnedRecoveryDaemonHostV3
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical
import deployment_compose_owned_recovery_unit_v3_host as units

BASE=Path('/var/tmp')
ROOT_UID=0
DOMAIN=b'dev-workflow:scene-control:v3\0'
MAX_FRAME=8192
LEASE_SECONDS=30
BUSINESS_LEASE_SECONDS=120
CLOSE_RESPONSE_SECONDS=420
STOP_RESPONSE_SECONDS=CLOSE_RESPONSE_SECONDS
RESERVE_RESPONSE_SECONDS=25
DRAIN_RESPONSE_SECONDS=40
INSPECT_RESPONSE_SECONDS=60
IDENTITY_RESPONSE_SECONDS=90
PREPARATION_RESPONSE_SECONDS=1200
_FALSE=('authorityGranted','runtimePermit','recoveryAuthorized','productionReady','writerQuiescenceVerified')


def reject():raise ValueError('compose-scene-service-v3-rejected') from None


def _left(end):
    left=end-time.monotonic()
    if left<=0:reject()
    return left


def _peer(sock):return struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))


def _path(scene_id):
    if type(scene_id) is not str or re.fullmatch('dw-scene-[0-9a-f]{16}',scene_id) is None:reject()
    return BASE/scene_id


def _directory(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        info=os.fstat(fd)
        if info.st_uid!=ROOT_UID or stat.S_IMODE(info.st_mode)!=0o700:reject()
        return fd,(info.st_dev,info.st_ino)
    except BaseException:os.close(fd);raise


def _key(fd):
    file=os.open('control.key',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=fd)
    try:
        info=os.fstat(file);raw=os.read(file,33)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=ROOT_UID or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_nlink!=1 or info.st_size!=32 or len(raw)!=32):reject()
        return raw,(info.st_dev,info.st_ino,digest(raw))
    finally:os.close(file)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def _mac(key,value):return hmac.new(key,DOMAIN+canonical(value),hashlib.sha256).hexdigest()


def _signed(key,value):return dict(value,mac=_mac(key,value))


def _verify(key,value):
    if type(value) is not dict or 'mac' not in value or type(value['mac']) is not str:reject()
    unsigned={k:v for k,v in value.items() if k!='mac'}
    if not hmac.compare_digest(value['mac'],_mac(key,unsigned)):reject()
    return unsigned


def _frame(value):
    raw=canonical(value)
    if not 0<len(raw)<=MAX_FRAME:reject()
    return struct.pack('!I',len(raw))+raw


def _read(sock,end):
    def exact(size):
        result=bytearray()
        while len(result)<size:
            sock.settimeout(_left(end));raw=sock.recv(size-len(result))
            if not raw:reject()
            result.extend(raw)
        return bytes(result)
    size=struct.unpack('!I',exact(4))[0]
    if not 0<size<=MAX_FRAME:reject()
    return decode(exact(size))


def _write(sock,value,end):
    sock.settimeout(_left(end));sock.sendall(_frame(value))


@dataclass(frozen=True)
class SceneHandleV3:
    sceneId:str
    socketPath:str
    controlKey:bytes=field(repr=False)


class SceneClientV3:
    def __init__(self,handle):
        self._socket=None;self._closed=False
        self._owner=(os.getpid(),__import__('threading').get_ident())
        try:
            if (type(handle) is not SceneHandleV3 or type(handle.controlKey) is not bytes or len(handle.controlKey)!=32
                    or handle.socketPath!=str(_path(handle.sceneId)/'control.sock')):reject()
            self._handle=handle;fd,identity=_directory(_path(handle.sceneId))
            try:
                info=os.stat('control.sock',dir_fd=fd,follow_symlinks=False)
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=ROOT_UID or stat.S_IMODE(info.st_mode)!=0o600:reject()
                self._socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);end=time.monotonic()+5
                self._socket.settimeout(5);self._socket.connect(handle.socketPath)
                if _peer(self._socket)[1]!=ROOT_UID:reject()
                after=os.stat('control.sock',dir_fd=fd,follow_symlinks=False)
                if (info.st_dev,info.st_ino)!=(after.st_dev,after.st_ino):reject()
                fresh,again=_directory(_path(handle.sceneId))
                try:
                    if again!=identity:reject()
                finally:os.close(fresh)
            finally:os.close(fd)
            challenge=_read(self._socket,end)
            if (type(challenge) is not dict or set(challenge)!={'kind','sceneId','serverNonce'}
                    or challenge['kind']!='scene-challenge-v3' or challenge['sceneId']!=handle.sceneId
                    or type(challenge['serverNonce']) is not str or re.fullmatch('[0-9a-f]{64}',challenge['serverNonce']) is None):reject()
            client_nonce=secrets.token_hex(32)
            auth=dict(kind='scene-auth-v3',sceneId=handle.sceneId,serverNonce=challenge['serverNonce'],clientNonce=client_nonce)
            _write(self._socket,_signed(handle.controlKey,auth),end)
            lease=_verify(handle.controlKey,_read(self._socket,end))
            if (set(lease)!={'kind','sceneId','serverNonce','clientNonce','generation','leaseNonce','seq'}
                    or lease['kind']!='scene-lease-v3' or lease['sceneId']!=handle.sceneId
                    or lease['serverNonce']!=challenge['serverNonce'] or lease['clientNonce']!=client_nonce
                    or type(lease['generation']) is not int or lease['generation']<=0 or type(lease['seq']) is not int or lease['seq']!=0
                    or type(lease['leaseNonce']) is not str or re.fullmatch('[0-9a-f]{64}',lease['leaseNonce']) is None):reject()
            self._lease={k:lease[k] for k in ('sceneId','serverNonce','clientNonce','generation','leaseNonce')};self._seq=0
        except Exception:
            if self._socket is not None:self._socket.close()
            reject()

    def __copy__(self):reject()
    def __deepcopy__(self,memo):reject()
    def __reduce_ex__(self,protocol):reject()

    def _call(self,command,args=None):
        if self._closed or self._owner!=(os.getpid(),__import__('threading').get_ident()):reject()
        try:
            self._seq+=1;end=time.monotonic()+5
            request=dict(kind='scene-command-v3',**self._lease,seq=self._seq,command=command)
            if args is not None:request['args']=args
            _write(self._socket,_signed(self._handle.controlKey,request),end)
            if command=='closeScene':end=time.monotonic()+STOP_RESPONSE_SECONDS
            elif command in ('start_first_create','finish_worker','reconcile_closure'):end=time.monotonic()+40
            elif command in ('observe_closed_phase','capture_closed_phase_snapshot'):end=time.monotonic()+25
            elif command=='observe_stopped_writer_phase':end=time.monotonic()+30
            elif command=='confirm_recovery_worker':end=time.monotonic()+55
            elif command=='reserve_writer':end=time.monotonic()+RESERVE_RESPONSE_SECONDS
            elif command=='drain_writer':end=time.monotonic()+DRAIN_RESPONSE_SECONDS
            elif command=='inspect_attached_worker':end=time.monotonic()+INSPECT_RESPONSE_SECONDS
            elif command=='prepare_identity':end=time.monotonic()+IDENTITY_RESPONSE_SECONDS
            elif command=='prepare_staging':end=time.monotonic()+PREPARATION_RESPONSE_SECONDS
            reply=_verify(self._handle.controlKey,_read(self._socket,end))
            expected=dict(kind='scene-result-v3',**self._lease,seq=self._seq,command=command)
            if set(reply)!=set(expected)|{'result'} or any(canonical(reply[k])!=canonical(v) for k,v in expected.items()):reject()
            result=reply['result']
            if type(result) is not dict or any(result.get(k) is not False for k in _FALSE):reject()
            return result
        except Exception:
            self._socket.close();self._closed=True;reject()

    def start_first_create(self,**args):return self._call('start_first_create',args)
    def observe_closed_phase(self,request_nonce):return self._call('observe_closed_phase',dict(requestNonce=request_nonce))
    def observe_stopped_writer_phase(self,request_nonce,first_write,*,recovery_handoff=None):
        args=dict(requestNonce=request_nonce,firstWrite=first_write)
        if recovery_handoff is not None:args['recoveryHandoff']=recovery_handoff
        return self._call('observe_stopped_writer_phase',args)
    def confirm_recovery_worker(self,proof,*,launch=False,relay=False,execute=False,through_delete=False,full_recovery=False):
        args=dict(proof=proof)
        if launch:args['launchWorker']=True
        if relay:args['relayWorker']=True
        if execute:args['executeStop']=True
        if through_delete:args['throughDelete']=True
        if full_recovery:args['fullRecovery']=True
        return self._call('confirm_recovery_worker',args)
    def capture_closed_phase_snapshot(self,request_nonce):return self._call('capture_closed_phase_snapshot',dict(requestNonce=request_nonce))
    def read_closed_phase_chunk(self,snapshot_id,phase_digest,offset,length):
        return self._call('read_closed_phase_chunk',dict(snapshotId=snapshot_id,phaseDigest=phase_digest,offset=offset,length=length))
    def poll_worker(self):return self._call('poll_worker',{})
    def read_worker_chunk(self,attempt_id,message_digest,offset,length):
        return self._call('read_worker_chunk',dict(attemptId=attempt_id,messageDigest=message_digest,offset=offset,length=length))
    def begin_worker_reply(self,attempt_id,total_bytes,message_digest,rpc_id):
        return self._call('begin_worker_reply',dict(attemptId=attempt_id,totalBytes=total_bytes,messageDigest=message_digest,rpcId=rpc_id))
    def worker_reply_chunk(self,attempt_id,offset,data_base64):
        return self._call('worker_reply_chunk',dict(attemptId=attempt_id,offset=offset,dataBase64=data_base64))
    def commit_worker_reply(self,attempt_id):return self._call('commit_worker_reply',dict(attemptId=attempt_id))
    def finish_worker(self,attempt_id):return self._call('finish_worker',dict(attemptId=attempt_id))
    def reconcile_closure(self,certificate):return self._call('reconcile_closure',dict(certificate=certificate))

    def prepare_identity(self,host_id):return self._call('prepare_identity',{'hostId':host_id})
    def prepare_staging(self,policy_hash,keys):
        if type(keys) is not dict or set(keys)!={'config','image','declaration','archive','target'} or any(type(v) is not bytes or len(v)!=32 for v in keys.values()):reject()
        return self._call('prepare_staging',{'policyHash':policy_hash,'keys':{k:base64.b64encode(v).decode('ascii') for k,v in keys.items()}})
    def preparation_chunk(self,preparation_id,capsule_digest,offset,length):
        return self._call('preparation_chunk',dict(preparationId=preparation_id,capsuleDigest=capsule_digest,offset=offset,length=length))
    def inspect_attached_worker(self,expected_slot_generation):
        if type(expected_slot_generation) is not int or not 0<=expected_slot_generation<2**53:reject()
        return self._call('inspect_attached_worker',{'slotGeneration':expected_slot_generation})
    def reserve_writer(self,expected_slot_generation):
        if type(expected_slot_generation) is not int or not 0<=expected_slot_generation<2**53:reject()
        return self._call('reserve_writer',{'slotGeneration':expected_slot_generation})
    def drain_writer(self,expected_slot_generation):
        if type(expected_slot_generation) is not int or not 0<=expected_slot_generation<2**53:reject()
        return self._call('drain_writer',{'slotGeneration':expected_slot_generation})
    def status(self):return self._call('status')
    def detach(self):
        result=self._call('detach');self._socket.close();self._closed=True;return result
    def close_scene(self):
        result=self._call('closeScene');self._socket.close();self._closed=True;return result
    def close(self):
        if self._owner!=(os.getpid(),__import__('threading').get_ident()):reject()
        if not self._closed:self._socket.close();self._closed=True
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


def client_scene(handle):return SceneClientV3(handle)


def _install_distribution(scene_fd,raw):
    import io,zipfile
    from deployment_compose_scene_attach_read_v3_host import validate_distribution_archive
    validate_distribution_archive(raw,digest(raw))
    os.mkdir('distribution',0o700,dir_fd=scene_fd);os.fsync(scene_fd)
    root=os.open('distribution',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=scene_fd)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                parts=info.filename.split('/');parent=os.dup(root)
                try:
                    for part in parts[:-1]:
                        try:os.mkdir(part,0o700,dir_fd=parent);os.fsync(parent)
                        except FileExistsError:pass
                        child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                        st=os.fstat(child)
                        if st.st_uid!=ROOT_UID or stat.S_IMODE(st.st_mode)!=0o700:os.close(child);reject()
                        os.close(parent);parent=child
                    file=os.open(parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                    with os.fdopen(file,'wb') as output:output.write(archive.read(info));output.flush();os.fsync(output.fileno())
                    os.fsync(parent)
                finally:os.close(parent)
        os.fsync(root)
    finally:os.close(root)
    os.fsync(scene_fd)


def start_scene(*,writer_source_sha=None,writer_archive_digest=None,writer_archive_bytes=None,
                business_witness_public_key=None,business_intent_public_key=None):
    if (business_witness_public_key is None)!=(business_intent_public_key is None):reject()
    if business_witness_public_key is not None:
        from deployment_gate_witness import key_material
        business_witness_public_key=key_material(business_witness_public_key)
        business_intent_public_key=key_material(business_intent_public_key)
        if business_witness_public_key==business_intent_public_key or writer_archive_bytes is None:reject()
    if (writer_source_sha is None)!=(writer_archive_digest is None):reject()
    if writer_source_sha is not None:
        if (type(writer_source_sha) is not str or re.fullmatch('[0-9a-f]{40}',writer_source_sha) is None
                or type(writer_archive_digest) is not str or re.fullmatch('[0-9a-f]{64}',writer_archive_digest) is None):reject()
    if writer_archive_bytes is not None:
        if writer_source_sha is None:reject()
        from deployment_compose_scene_attach_read_v3_host import validate_distribution_archive
        validate_distribution_archive(writer_archive_bytes,writer_archive_digest)
    units._environment()
    scene_id='dw-scene-'+secrets.token_hex(8);path=_path(scene_id);path.mkdir(mode=0o700)
    fd,identity=_directory(path)
    script=Path(__file__).resolve()
    try:
        key=secrets.token_bytes(32)
        file=os.open('control.key',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(file,'wb') as output:output.write(key);output.flush();os.fsync(output.fileno())
        if business_witness_public_key is not None:
            pins=_signed(key,dict(kind='scene-business-pins-v3',sceneId=scene_id,
                witnessPublicKey=base64.b64encode(business_witness_public_key).decode(),
                intentPublicKey=base64.b64encode(business_intent_public_key).decode()))
            pins_fd=os.open('business-pins.private.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(pins_fd,'wb') as output:output.write(canonical(pins));output.flush();os.fsync(output.fileno())
        if writer_source_sha is not None:
            source=_signed(key,dict(kind='scene-loader-source-v3',sceneId=scene_id,
                sourceSha=writer_source_sha,archiveDigest=writer_archive_digest))
            source_fd=os.open('loader-source.private.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(source_fd,'wb') as output:output.write(canonical(source));output.flush();os.fsync(output.fileno())
        if writer_archive_bytes is not None:
            archive_fd=os.open('loader-archive.private.zip',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            with os.fdopen(archive_fd,'wb') as output:output.write(writer_archive_bytes);output.flush();os.fsync(output.fileno())
            _install_distribution(fd,writer_archive_bytes)
            script=path/'distribution/scripts/deployment_compose_scene_service_v3_host.py'
        os.fsync(fd)
    finally:os.close(fd)
    unit='dw-scene-owner-'+scene_id[-16:]+'.service'
    subprocess.run(['/usr/bin/systemd-run','--system','--quiet','--collect','--service-type=exec','--unit='+unit,
        '--property=User=root','--property=Restart=no','--property=RuntimeMaxSec=3300','--property=TimeoutStopSec=420',
        '--property=KillMode=control-group','--property=MemoryMax=256M','--property=MemorySwapMax=0',
        '--property=CPUQuota=50%','--property=TasksMax=128','--',sys.executable,'-I','-u',str(script),'--serve',scene_id],
        capture_output=True,check=True,timeout=10,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})
    handle=SceneHandleV3(scene_id,str(path/'control.sock'),key);end=time.monotonic()+100
    while True:
        _left(end)
        if (path/'ready-marker').exists():
            ready_fd,ready_identity=_directory(path)
            try:
                if ready_identity!=identity:reject()
                marker=os.open('ready-marker',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=ready_fd)
                try:
                    info=os.fstat(marker);raw=os.read(marker,4097)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=ROOT_UID or stat.S_IMODE(info.st_mode)!=0o600
                            or info.st_nlink!=1 or not 0<info.st_size<=4096 or len(raw)!=info.st_size):reject()
                    ready=decode(raw)
                    if (type(ready) is not dict or set(ready)!={'kind','sceneId','socketDevice','socketInode'}
                            or ready['kind']!='scene-ready-v3' or ready['sceneId']!=scene_id
                            or type(ready['socketDevice']) is not int or type(ready['socketInode']) is not int):reject()
                    current=os.stat('control.sock',dir_fd=ready_fd,follow_symlinks=False)
                    if (current.st_dev,current.st_ino)!=(ready['socketDevice'],ready['socketInode']):reject()
                finally:os.close(marker)
            finally:os.close(ready_fd)
            with client_scene(handle) as client:client.status();client.detach()
            return handle
        time.sleep(min(.05,_left(end)))


def _loader_source(fd,key,scene_id):
    try:file=os.open('loader-source.private.json',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=fd)
    except FileNotFoundError:return None,None
    try:
        info=os.fstat(file);raw=os.read(file,4097)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=ROOT_UID or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_nlink!=1 or not 0<info.st_size<=4096 or len(raw)!=info.st_size):reject()
        value=_verify(key,decode(raw))
        if (set(value)!={'kind','sceneId','sourceSha','archiveDigest'} or value['kind']!='scene-loader-source-v3'
                or value['sceneId']!=scene_id or type(value['sourceSha']) is not str
                or re.fullmatch('[0-9a-f]{40}',value['sourceSha']) is None or type(value['archiveDigest']) is not str
                or re.fullmatch('[0-9a-f]{64}',value['archiveDigest']) is None):reject()
        return value,(info.st_dev,info.st_ino,digest(raw))
    finally:os.close(file)


def _loader_archive(fd,expected_digest,*,validate=False):
    try:file=os.open('loader-archive.private.zip',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=fd)
    except FileNotFoundError:return None,None
    try:
        info=os.fstat(file)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=ROOT_UID or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_nlink!=1 or not 0<info.st_size<=2*1024*1024):reject()
        chunks=[];size=0
        while True:
            raw=os.read(file,min(65536,2*1024*1024+1-size))
            if not raw:break
            chunks.append(raw);size+=len(raw)
            if size>2*1024*1024:reject()
        raw=b''.join(chunks);after=os.fstat(file)
        identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        if identity(info)!=identity(after) or len(raw)!=info.st_size or digest(raw)!=expected_digest:reject()
        if validate:
            from deployment_compose_scene_attach_read_v3_host import validate_distribution_archive
            validate_distribution_archive(raw,expected_digest)
        return raw,identity(info)+(digest(raw),)
    finally:os.close(file)


def _business_pins(fd,key,scene_id):
    try:file=os.open('business-pins.private.json',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=fd)
    except FileNotFoundError:return None,None
    try:
        info=os.fstat(file);raw=os.read(file,16385)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=ROOT_UID or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_nlink!=1 or not 0<info.st_size<=16384 or len(raw)!=info.st_size):reject()
        value=_verify(key,decode(raw))
        if set(value)!={'kind','sceneId','witnessPublicKey','intentPublicKey'} or value['kind']!='scene-business-pins-v3' or value['sceneId']!=scene_id:reject()
        from deployment_gate_witness import key_material
        keys=[]
        for name in ('witnessPublicKey','intentPublicKey'):
            encoded=value[name]
            if type(encoded) is not str:reject()
            material=base64.b64decode(encoded,validate=True)
            if key_material(material)!=material or base64.b64encode(material).decode()!=encoded:reject()
            keys.append(material)
        if keys[0]==keys[1]:reject()
        return tuple(keys),(info.st_dev,info.st_ino,digest(raw))
    finally:os.close(file)


def serve(scene_id):
    units._environment();path=_path(scene_id);fd,identity=_directory(path)
    key,key_identity=_key(fd);listener=connection=None;owner=OwnedRecoveryDaemonHostV3();generation=0
    service_end=time.monotonic()+2850;state=None;closing=False;socket_identity=None;slot_cleanup_attempted=False;preparation=None;preparation_cleanup_attempted=False;broker=None;broker_cleanup_attempted=False
    business_pins,business_identity=_business_pins(fd,key,scene_id)
    source,source_identity=_loader_source(fd,key,scene_id)
    attached_archive,archive_identity=_loader_archive(fd,source['archiveDigest'] if source is not None else None,validate=True)
    from deployment_compose_scene_writer_slot_v3_host import SlotOwnerV3
    from deployment_compose_scene_preparation_v3_host import PreparationOwnerV3
    slot=SlotOwnerV3(source['sourceSha'],source['archiveDigest']) if source is not None else None
    def interrupted(*args):raise SystemExit('scene-service-interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    def check():
        fresh,again=_directory(path)
        try:
            if again!=identity or _key(fd)!=(key,key_identity):reject()
            if _loader_source(fd,key,scene_id)!=(source,source_identity):reject()
            if _business_pins(fd,key,scene_id)!=(business_pins,business_identity):reject()
            if _loader_archive(fd,source['archiveDigest'] if source is not None else None)!=(attached_archive,archive_identity):reject()
            if socket_identity is not None:
                info=os.stat('control.sock',dir_fd=fd,follow_symlinks=False)
                if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=ROOT_UID
                        or stat.S_IMODE(info.st_mode)!=0o600 or (info.st_dev,info.st_ino)!=socket_identity):reject()
        finally:os.close(fresh)
    def release(selector):
        nonlocal connection,state
        if connection is not None:
            if broker is not None:broker.controller_lost()
            selector.unregister(connection);connection.close();connection=None;state=None
    try:
        # Burn this identity before any daemon can be created. Neither stale
        # socket nor marker is ever repaired or adopted.
        for stale in ('control.sock','ready-marker'):
            try:os.stat(stale,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:reject()
        marker=os.open('started-marker',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        try:os.write(marker,b'scene-started-v3\n');os.fsync(marker)
        finally:os.close(marker)
        os.fsync(fd)
        owner.start();check()
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(path/'control.sock'))
        os.chmod(path/'control.sock',0o600);listener.listen(8);listener.setblocking(False)
        info=os.stat('control.sock',dir_fd=fd,follow_symlinks=False);socket_identity=(info.st_dev,info.st_ino)
        check()
        # Publish readiness only after socket permissions, listen and identity
        # checks complete. The burned scene has one legitimate writer, so
        # atomic rename exposes the complete single-link inode without a link
        # count transition. Readiness itself grants no control authority.
        temporary='.scene-ready-'+secrets.token_hex(16)
        marker=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        try:
            with os.fdopen(marker,'wb') as output:
                output.write(canonical(dict(kind='scene-ready-v3',sceneId=scene_id,
                    socketDevice=socket_identity[0],socketInode=socket_identity[1])))
                output.flush();os.fsync(output.fileno())
            os.rename(temporary,'ready-marker',src_dir_fd=fd,dst_dir_fd=fd)
        finally:
            try:os.unlink(temporary,dir_fd=fd)
            except FileNotFoundError:pass
        os.fsync(fd)
        with selectors.DefaultSelector() as selector:
            selector.register(listener,selectors.EVENT_READ,'listener')
            while not closing:
                _left(service_end);check()
                if state is not None:
                    now=time.monotonic()
                    expired=(state['expires'] is not None and now>=state['expires'] or
                        state.get('lease_deadline') is not None and now>=state['lease_deadline'])
                    if state.get('flush_expires') is not None and now>=state['flush_expires']:
                        release(selector)
                    elif expired:
                        if state['output'] and state.get('flush_expires') is not None:state['release']=True
                        else:release(selector)
                    if connection is not None and state['release']:
                        selector.modify(connection,selectors.EVENT_WRITE,'client')
                ready=selector.select(min(.1,_left(service_end)))
                ready.sort(key=lambda event:event[0].data=='listener')
                for selected,events in ready:
                    if selected.data=='listener':
                        peer=None
                        try:
                            peer,_=listener.accept();peer.setblocking(False)
                            if connection is not None or _peer(peer)[1]!=ROOT_UID:peer.close();continue
                        except Exception:
                            if peer is not None:peer.close()
                            continue
                        connection=peer;state=dict(buffer=bytearray(),output=bytearray(),expires=time.monotonic()+5,
                            server=secrets.token_hex(32),lease=None,seq=0,release=False,flush_expires=None)
                        state['output'].extend(_frame(dict(kind='scene-challenge-v3',sceneId=scene_id,serverNonce=state['server'])))
                        selector.register(peer,selectors.EVENT_READ|selectors.EVENT_WRITE,'client');continue
                    if connection is None:continue
                    try:
                        if events&selectors.EVENT_WRITE and state['output']:
                            sent=connection.send(state['output'])
                            if sent<=0:reject()
                            del state['output'][:sent]
                            if not state['output']:
                                state['flush_expires']=None
                                if closing or state['release']:release(selector);continue
                                if state['lease'] is not None and not state['buffer']:state['expires']=None
                        if events&selectors.EVENT_READ and not state['release']:
                            raw=connection.recv(16384)
                            if not raw:release(selector);continue
                            if state['expires'] is None:state['expires']=time.monotonic()+5
                            state['buffer'].extend(raw)
                            if len(state['buffer'])>16384:reject()
                            while len(state['buffer'])>=4:
                                size=struct.unpack('!I',state['buffer'][:4])[0]
                                if not 0<size<=MAX_FRAME:reject()
                                if len(state['buffer'])<size+4:break
                                value=_verify(key,decode(bytes(state['buffer'][4:4+size])));del state['buffer'][:size+4]
                                if state['lease'] is None:
                                    if (set(value)!={'kind','sceneId','serverNonce','clientNonce'} or value['kind']!='scene-auth-v3'
                                            or value['sceneId']!=scene_id or value['serverNonce']!=state['server']
                                            or type(value['clientNonce']) is not str or re.fullmatch('[0-9a-f]{64}',value['clientNonce']) is None):reject()
                                    generation+=1;state['lease']=dict(sceneId=scene_id,serverNonce=state['server'],clientNonce=value['clientNonce'],
                                        generation=generation,leaseNonce=secrets.token_hex(32))
                                    state['lease_deadline']=min(time.monotonic()+LEASE_SECONDS,service_end)
                                    reply=dict(kind='scene-lease-v3',**state['lease'],seq=0)
                                else:
                                    lease=state['lease']
                                    extended=value.get('command') in ('reserve_writer','drain_writer','inspect_attached_worker','prepare_identity','prepare_staging','preparation_chunk','start_first_create','poll_worker','read_worker_chunk','begin_worker_reply','worker_reply_chunk','commit_worker_reply','finish_worker','reconcile_closure','observe_closed_phase','observe_stopped_writer_phase','confirm_recovery_worker','capture_closed_phase_snapshot','read_closed_phase_chunk')
                                    if (set(value)!=({'kind',*lease,'seq','command'}|({'args'} if extended else set())) or value['kind']!='scene-command-v3'
                                            or any(canonical(value[k])!=canonical(v) for k,v in lease.items()) or type(value['seq']) is not int
                                            or value['seq']!=state['seq']+1 or value['command'] not in ('status','detach','closeScene','reserve_writer','drain_writer','inspect_attached_worker','prepare_identity','prepare_staging','preparation_chunk','start_first_create','poll_worker','read_worker_chunk','begin_worker_reply','worker_reply_chunk','commit_worker_reply','finish_worker','reconcile_closure','observe_closed_phase','observe_stopped_writer_phase','confirm_recovery_worker','capture_closed_phase_snapshot','read_closed_phase_chunk')):reject()
                                    if time.monotonic()>=state['lease_deadline']:reject()
                                    if extended:
                                        args=value['args'];command=value['command']
                                        expected_args={'prepare_identity':{'hostId'},'prepare_staging':{'policyHash','keys'},
                                            'preparation_chunk':{'preparationId','capsuleDigest','offset','length'},
                                            'start_first_create':{'preparationId','capsuleDigest','slotGeneration','policy','gateKeyBase64','requestHash','receiptHash','firstBinding'},
                                            'poll_worker':set(),'read_worker_chunk':{'attemptId','messageDigest','offset','length'},
                                            'begin_worker_reply':{'attemptId','totalBytes','messageDigest','rpcId'},
                                            'worker_reply_chunk':{'attemptId','offset','dataBase64'},'commit_worker_reply':{'attemptId'},
                                            'finish_worker':{'attemptId'},'reconcile_closure':{'certificate'},'observe_closed_phase':{'requestNonce'},'observe_stopped_writer_phase':{'requestNonce','firstWrite'},'confirm_recovery_worker':{'proof'},'capture_closed_phase_snapshot':{'requestNonce'},
                                            'read_closed_phase_chunk':{'snapshotId','phaseDigest','offset','length'}}.get(command,{'slotGeneration'})
                                        if type(args) is not dict:reject()
                                        if command=='observe_stopped_writer_phase' and 'recoveryHandoff' in args:
                                            if type(args['recoveryHandoff']) is not dict:reject()
                                            expected_args=expected_args|{'recoveryHandoff'}
                                        if command=='confirm_recovery_worker' and 'launchWorker' in args:
                                            if args['launchWorker'] is not True:reject()
                                            expected_args=expected_args|{'launchWorker'}
                                        if command=='confirm_recovery_worker' and 'relayWorker' in args:
                                            if args['relayWorker'] is not True or 'launchWorker' in args:reject()
                                            expected_args=expected_args|{'relayWorker'}
                                        if command=='confirm_recovery_worker' and 'executeStop' in args:
                                            if args['executeStop'] is not True or {'launchWorker','relayWorker'} & args.keys():reject()
                                            expected_args=expected_args|{'executeStop'}
                                        if command=='confirm_recovery_worker' and 'throughDelete' in args:
                                            if args['throughDelete'] is not True or 'executeStop' not in args:reject()
                                            expected_args=expected_args|{'throughDelete'}
                                        if command=='confirm_recovery_worker' and 'fullRecovery' in args:
                                            if args['fullRecovery'] is not True or 'throughDelete' not in args:reject()
                                            expected_args=expected_args|{'fullRecovery'}
                                        if set(args)!=expected_args:reject()
                                        if 'slotGeneration' in expected_args and (type(args['slotGeneration']) is not int
                                                or not 0<=args['slotGeneration']<2**53 or slot is None):reject()
                                        if command in ('prepare_identity','prepare_staging') and (source is None or attached_archive is None or slot is not None
                                                and slot.status()['slotState'] not in ('empty','drained')):reject()
                                    state['seq']=value['seq'];command=value['command']
                                    lease_seconds=(BUSINESS_LEASE_SECONDS if broker is not None and broker.status()['businessState']
                                        in ('starting','active','terminal','transport-exited','closed') else LEASE_SECONDS)
                                    if command=='status':state['lease_deadline']=min(time.monotonic()+lease_seconds,service_end)
                                    result=dict(sceneId=scene_id,controllerExclusive=True,leaseSeconds=lease_seconds,daemonId=owner.observer.daemon_id,
                                        daemonBinding=owner.observer.binding(),
                                        generation=generation,**{k:False for k in _FALSE})
                                    metadata=slot.status() if slot is not None else dict(slotGeneration=0,slotState='disabled')
                                    if broker is not None and command in ('reserve_writer','drain_writer','inspect_attached_worker','prepare_identity','prepare_staging'):reject()
                                    if command=='reserve_writer':metadata=slot.reserve(value['args']['slotGeneration'])
                                    if command=='drain_writer':metadata=slot.drain(value['args']['slotGeneration'])
                                    if command=='inspect_attached_worker':
                                        if attached_archive is None:reject()
                                        metadata=slot.inspect_attached(attached_archive,owner.observer.binding(),value['args']['slotGeneration'])
                                    result.update(writerSlot=metadata,slotGeneration=metadata['slotGeneration'],slotState=metadata['slotState'])
                                    if command=='prepare_identity':
                                        if preparation is None:preparation=PreparationOwnerV3(owner.observer,source['sourceSha'],source['archiveDigest'])
                                        result['hello']=preparation.identity(args['hostId'])
                                    if command=='prepare_staging':
                                        if service_end-time.monotonic()<PREPARATION_RESPONSE_SECONDS:reject()
                                        if preparation is None or type(args['keys']) is not dict or set(args['keys'])!={'config','image','declaration','archive','target'}:reject()
                                        keys={}
                                        for name,encoded in args['keys'].items():
                                            if type(encoded) is not str or len(encoded)!=44:reject()
                                            decoded_key=base64.b64decode(encoded,validate=True)
                                            if len(decoded_key)!=32 or base64.b64encode(decoded_key).decode('ascii')!=encoded:reject()
                                            keys[name]=decoded_key
                                        result['preparation']=preparation.prepare(args['policyHash'],keys)
                                    if preparation is not None:
                                        prep_status=preparation.status()
                                        result['preparationState']=prep_status['preparationState']
                                        result['preparationIdentity']=prep_status['preparationIdentity']
                                        result['preparation']=prep_status['capsule']
                                    else:result.update(preparationState='disabled' if source is None or attached_archive is None else 'new',preparation=None,preparationIdentity=None)
                                    if command=='preparation_chunk':
                                        if preparation is None:reject()
                                        result=dict(preparationChunk=preparation.chunk(args['preparationId'],args['capsuleDigest'],args['offset'],args['length']),
                                            **{k:False for k in _FALSE})
                                    business_commands=('start_first_create','poll_worker','read_worker_chunk','begin_worker_reply',
                                        'worker_reply_chunk','commit_worker_reply','finish_worker','reconcile_closure','observe_closed_phase','observe_stopped_writer_phase','confirm_recovery_worker','capture_closed_phase_snapshot','read_closed_phase_chunk')
                                    if command in business_commands:
                                        if business_pins is None or preparation is None or attached_archive is None:reject()
                                        if command=='start_first_create':
                                            if broker is not None:reject()
                                            from deployment_compose_scene_create_broker_v3_host import SceneCreateBrokerV3
                                            broker=SceneCreateBrokerV3(preparation,attached_archive,*business_pins,slot,scene_id)
                                            state['lease_deadline']=min(time.monotonic()+BUSINESS_LEASE_SECONDS,service_end)
                                            business_result=broker.start_first_create(args,generation)
                                        else:
                                            if broker is None:reject()
                                            if command=='poll_worker':business_result=broker.poll_worker()
                                            elif command=='read_worker_chunk':business_result=broker.read_worker_chunk(args['attemptId'],args['messageDigest'],args['offset'],args['length'])
                                            elif command=='begin_worker_reply':business_result=broker.begin_worker_reply(args['attemptId'],args['totalBytes'],args['messageDigest'],args['rpcId'])
                                            elif command=='worker_reply_chunk':business_result=broker.worker_reply_chunk(args['attemptId'],args['offset'],args['dataBase64'])
                                            elif command=='commit_worker_reply':business_result=broker.commit_worker_reply(args['attemptId'])
                                            elif command=='finish_worker':business_result=broker.finish_worker(args['attemptId'])
                                            elif command=='observe_closed_phase':business_result=broker.observe_closed_phase(args['requestNonce'])
                                            elif command=='observe_stopped_writer_phase':
                                                if 'recoveryHandoff' in args:
                                                    business_result=broker.observe_stopped_writer_phase(
                                                        args['requestNonce'],args['firstWrite'],recovery_handoff=args['recoveryHandoff'],lease_generation=generation)
                                                else:
                                                    business_result=broker.observe_stopped_writer_phase(args['requestNonce'],args['firstWrite'])
                                                if time.monotonic()>=state['lease_deadline']:reject()
                                            elif command=='confirm_recovery_worker':
                                                if 'launchWorker' in args:
                                                    state['lease_deadline']=min(time.monotonic()+60,service_end)
                                                    business_result=broker.confirm_recovery_worker(args['proof'],generation,launch=True)
                                                elif 'relayWorker' in args:
                                                    state['lease_deadline']=min(time.monotonic()+60,service_end)
                                                    business_result=broker.confirm_recovery_worker(args['proof'],generation,relay=True)
                                                elif 'executeStop' in args:
                                                    through_delete = args.get('throughDelete', False)
                                                    full_recovery = args.get('fullRecovery', False)
                                                    execution_seconds = 210 if full_recovery else 180 if through_delete else 120
                                                    state['lease_deadline']=min(time.monotonic()+execution_seconds,service_end)
                                                    business_result=broker.confirm_recovery_worker(args['proof'],generation,execute=True,
                                                        through_delete=through_delete,full_recovery=full_recovery)
                                                else:
                                                    business_result=broker.confirm_recovery_worker(args['proof'],generation)
                                                if time.monotonic()>=state['lease_deadline']:reject()
                                            elif command=='capture_closed_phase_snapshot':business_result=broker.capture_closed_phase_snapshot(args['requestNonce'])
                                            elif command=='read_closed_phase_chunk':business_result=broker.read_closed_phase_chunk(args['snapshotId'],args['phaseDigest'],args['offset'],args['length'])
                                            else:business_result=broker.reconcile_closure(args['certificate'])
                                        result=dict(**{{'observe_closed_phase':'phaseObservation','capture_closed_phase_snapshot':'phaseSnapshot',
                                            'observe_stopped_writer_phase':'writerPhaseObservation','confirm_recovery_worker':'workerConfirmation',
                                            'read_closed_phase_chunk':'phaseChunk'}.get(command,'business'):business_result},**{k:False for k in _FALSE})
                                    elif broker is not None:result['business']=broker.status()
                                    else:result['business']=dict(businessState='disabled' if business_pins is None else 'new',
                                        witnessKeyHash=digest(business_pins[0]) if business_pins else None,
                                        intentKeyHash=digest(business_pins[1]) if business_pins else None)
                                    if command=='detach':state['release']=True
                                    if command=='closeScene':
                                        closing=True;slot_error=None;broker_error=None
                                        if broker is not None:
                                            broker_cleanup_attempted=True
                                            try:broker.drain()
                                            except BaseException as error:broker_error=error
                                        if slot is not None and slot.status()['slotState'] not in ('empty','drained'):
                                            slot_cleanup_attempted=True
                                            try:slot.drain(slot.status()['slotGeneration'])
                                            except BaseException as error:slot_error=error
                                        if slot is not None:
                                            metadata=slot.status()
                                            result.update(writerSlot=metadata,slotGeneration=metadata['slotGeneration'],slotState=metadata['slotState'])
                                        prep_error=None
                                        if preparation is not None:
                                            preparation_cleanup_attempted=True
                                            try:
                                                result.update(preparation.cleanup())
                                                cleaned_status=preparation.status()
                                                result.update(preparationState=cleaned_status['preparationState'],
                                                    preparationIdentity=cleaned_status['preparationIdentity'],
                                                    preparation=cleaned_status['capsule'])
                                            except BaseException as error:prep_error=error
                                        result.update(owner.stop())
                                        if broker_error is not None:raise broker_error
                                        if prep_error is not None:raise prep_error
                                        if slot_error is not None:raise slot_error
                                    reply=dict(kind='scene-result-v3',**lease,seq=state['seq'],command=command,result=result)
                                state['output'].extend(_frame(_signed(key,reply)))
                                # A completed authenticated operation gets a fresh
                                # bounded reply flush, never a renewed lease.
                                state['flush_expires']=time.monotonic()+5
                                if not state['buffer']:state['expires']=None
                                if state.get('lease_deadline') is not None and time.monotonic()>=state['lease_deadline']:
                                    state['release']=True
                                if len(state['output'])>16384:reject()
                                if state['release'] or closing:break
                        if connection is not None:
                            selector.modify(connection,(0 if state['release'] else selectors.EVENT_READ)|(selectors.EVENT_WRITE if state['output'] else 0),'client')
                    except Exception:
                        if connection is not None:release(selector)
                        if closing:raise
                if closing and connection is not None:
                    # Finish the authenticated terminal reply before leaving.
                    end=time.monotonic()+5
                    while state['output']:
                        with selectors.DefaultSelector() as flush:
                            flush.register(connection,selectors.EVENT_WRITE)
                            if not flush.select(_left(end)):reject()
                        sent=connection.send(state['output'])
                        if sent<=0:reject()
                        del state['output'][:sent]
                    release(selector)
    finally:
        primary=sys.exc_info()[1];failed=False;cleanup_error=None
        actions=[]
        if connection is not None:actions.append(connection.close)
        if broker is not None and not broker_cleanup_attempted:actions.append(broker.drain)
        if listener is not None:actions.append(listener.close)
        if slot is not None and not slot_cleanup_attempted and slot.status()['slotState'] not in ('empty','drained'):
            actions.append(lambda:slot.drain(slot.status()['slotGeneration']))
        if preparation is not None and not preparation_cleanup_attempted:actions.append(preparation.cleanup)
        actions.extend((lambda:os.close(fd),owner.stop))
        for action in actions:
            try:action()
            except BaseException as error:
                failed=True
                if cleanup_error is None:cleanup_error=error
        if failed:
            if primary is None:
                if not isinstance(cleanup_error,Exception):raise cleanup_error
                reject()
            try:
                if hasattr(primary,'add_note'):primary.add_note('scene service cleanup incomplete')
            except Exception:pass


if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1]!='--serve':reject()
    serve(sys.argv[2])
