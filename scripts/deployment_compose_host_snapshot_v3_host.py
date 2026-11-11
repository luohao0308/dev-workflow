"""Fixed independent host projection, not total-host immutability or authority.

Supports root docker.service with direct or docker.socket/PID1 listener. Host
administration and service lifecycle are trusted/exclusive during observation;
state checks are not an atomic fence against a hostile root actor.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading
import time
import weakref

import deployment_runtime as runtime
import deployment_compose_owned_recovery_unit_v3_host as units
from deployment_compose_reader_host import _UnixDocker,_complete_json_response
from deployment_compose_resource_inventory_v3_host import inventory,PATHS
from deployment_compose_host_commands_v3_host import capture_network,read_systemd

PROFILE='linux-docker-host-projection-v1'
FRONTEND_PROTECTION_PROFILE='linux-docker-production-frontend-protection-v1'
_FRONTEND_PROTECTIONS=weakref.WeakKeyDictionary()
_RUN=Path('/run')
_UID=0
_SERVICE=('Id','LoadState','ActiveState','SubState','MainPID','ControlGroup','InvocationID')
_SOCKET=('Id','LoadState','ActiveState','SubState','InvocationID','Listen')


def reject():raise ValueError('compose-host-snapshot-v3-rejected') from None


def encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')


def _peer(sock):return struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))


def _root_process(pid):
    values=dict(line.split(':',1) for line in (Path('/proc')/str(pid)/'status').read_text().splitlines() if ':' in line)
    if values.get('Uid','').split()!=['0']*4:reject()


def _context():
    from deployment_compose_recovery_daemon_v3_host import _ticks
    result={'kernelBoot':units._boot(),'initStartTicks':_ticks(1)}
    if type(result['initStartTicks']) is not int or result['initStartTicks']<=0:reject()
    _root_process(1)
    for name in ('net','mnt','pid'):
        value=os.readlink('/proc/self/ns/'+name)
        if value!=os.readlink('/proc/1/ns/'+name):reject()
        result[name]=value
    return result


class HostSnapshotV3:
    def __init__(self,*,timeout=20):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=20:reject()
        units._environment()
        self._owner=os.getpid();self._fd=None;self._closed=False
        self._peer_pid=None;self._peer_ticks=None;self._socket_state=None;self._baseline=None
        self._info_id=self._data_root=None
        deadline=time.monotonic()+timeout
        try:
            self._context=_context()
            self._fd=os.open(_RUN,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            info=os.fstat(self._fd)
            if info.st_uid!=_UID or info.st_mode&0o022:reject()
            self._run_id=self._id(info)
            self._run_meta=(info.st_uid,info.st_gid,info.st_mode&0o777)
            sock=os.stat('docker.sock',dir_fd=self._fd,follow_symlinks=False)
            if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid!=_UID:reject()
            self._socket_id=self._id(sock)
            self._socket_meta=(sock.st_uid,sock.st_gid,sock.st_mode&0o777)
            self._service=self._show('docker.service',_SERVICE,deadline)
            value=self._service
            if (value['Id']!='docker.service' or value['LoadState']!='loaded'
                    or value['ActiveState']!='active' or value['SubState']!='running'
                    or not value['MainPID'].isascii() or not value['MainPID'].isdecimal() or int(value['MainPID'])<=0
                    or value['ControlGroup']!='/system.slice/docker.service'
                    or not re.fullmatch('[0-9a-f]{32}',value['InvocationID'])):reject()
            self._main=units._pid_identity(value['MainPID'],value['ControlGroup'])
            _root_process(self._main[0])
            budget=[32*1024*1024]
            info=self._get('/v1.45/info',deadline,budget)
            if (type(info) is not dict or type(info.get('ID')) is not str or not 0<len(info['ID'])<=256
                    or type(info.get('DockerRootDir')) is not str or not Path(info['DockerRootDir']).is_absolute()):reject()
            self._info_id,self._data_root=info['ID'],info['DockerRootDir']
            self._endpoint=encode(dict(profile=PROFILE,context=self._context,service=self._service,
                socketService=self._socket_state,socketIdentity=self._socket_id,runIdentity=self._run_id,
                socketOwnership=self._socket_meta,runOwnership=self._run_meta,
                main=self._main,peerPid=self._peer_pid,peerStartTicks=self._peer_ticks,
                daemonId=self._info_id,dockerRootDir=self._data_root))
            self._baseline=self._capture(deadline,budget)
        except BaseException:
            try:self.close()
            except Exception:pass
            raise

    @staticmethod
    def _id(value):return value.st_dev,value.st_ino

    def _show(self,name,properties,deadline):
        raw=read_systemd(name,deadline)
        if len(raw)>16384:reject()
        value={}
        for line in raw.decode('ascii').splitlines():
            key,item=line.split('=',1)
            if key in value:reject()
            value[key]=item
        if set(value)!=set(properties):reject()
        return value

    def _check(self):
        if os.getpid()!=self._owner or self._closed or _context()!=self._context:reject()

    def _local(self):
        self._check()
        parent=os.stat(_RUN,follow_symlinks=False)
        sock=os.stat('docker.sock',dir_fd=self._fd,follow_symlinks=False)
        if (self._id(parent)!=self._run_id
                or self._id(os.fstat(self._fd))!=self._run_id
                or (parent.st_uid,parent.st_gid,parent.st_mode&0o777)!=self._run_meta
                or self._id(sock)!=self._socket_id
                or (sock.st_uid,sock.st_gid,sock.st_mode&0o777)!=self._socket_meta
                or units._pid_identity(str(self._main[0]),self._service['ControlGroup'])!=self._main):reject()
        _root_process(self._main[0])

    def _fresh(self,deadline):
        self._local()
        if self._show('docker.service',_SERVICE,deadline)!=self._service:reject()
        if self._socket_state is not None and self._show('docker.socket',_SOCKET,deadline)!=self._socket_state:reject()

    def _get(self,path,deadline,budget):
        if path not in PATHS and path!='/v1.45/info' and not re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/json',path):reject()
        self._local()
        connection=_UnixDocker('/proc/self/fd/'+str(self._fd)+'/docker.sock',min(3,units._left(deadline)))
        watchdog=None
        try:
            connection.connect()
            watchdog=runtime.deadline_watchdog(connection.sock,min(deadline,time.monotonic()+3))
            pid,uid,_=_peer(connection.sock)
            if uid!=_UID:reject()
            if self._peer_pid is None:
                if pid==self._main[0]:self._peer_ticks=self._main[1]
                elif pid==1:
                    value=self._show('docker.socket',_SOCKET,deadline)
                    if (value['Id']!='docker.socket' or value['LoadState']!='loaded' or value['ActiveState']!='active'
                            or value['SubState'] not in ('running','listening')
                            or value['InvocationID'] and not re.fullmatch('[0-9a-f]{32}',value['InvocationID'])
                            or value['Listen'] not in ('/run/docker.sock (Stream)','/var/run/docker.sock (Stream)')):reject()
                    self._socket_state=value;self._peer_ticks=self._context['initStartTicks']
                else:reject()
                self._peer_pid=pid
            elif pid!=self._peer_pid:reject()
            connection.request('GET',path,headers={'Accept':'application/json'})
            raw,value=_complete_json_response(connection.getresponse())
            budget[0]-=len(raw)
            if budget[0]<0:reject()
        finally:
            if watchdog is not None:watchdog.cancel()
            connection.close()
        self._local()
        return value

    def _scan(self,deadline,budget,*,include_definitions=False):
        self._fresh(deadline)
        info=self._get('/v1.45/info',deadline,budget)
        if (type(info) is not dict or info.get('ID')!=self._info_id or info.get('DockerRootDir')!=self._data_root):reject()
        resources=inventory(lambda path:self._get(path,deadline,budget),include_definitions=include_definitions)
        if len(resources['containers'])>64:reject()
        containers=[]
        for cid in resources['containers']:
            row=self._get('/v1.45/containers/'+cid+'/json',deadline,budget)
            if (type(row) is not dict or row.get('Id')!=cid or type(row.get('State')) is not dict
                    or type(row.get('RestartCount')) is not int or row['RestartCount']<0
                    or type(row.get('Name')) is not str or type(row.get('Image')) is not str
                    or type(row.get('Config')) is not dict or type(row.get('HostConfig')) is not dict
                    or type(row.get('Mounts')) is not list or type(row.get('NetworkSettings')) is not dict):reject()
            state=row['State']
            if (type(state.get('StartedAt')) is not str or len(state['StartedAt'])>128
                    or state.get('Status') not in ('created','running','paused','restarting','removing','exited','dead')):reject()
            settings=row['NetworkSettings']
            if type(settings.get('Networks')) is not dict or type(settings.get('Ports')) not in (dict,type(None)):reject()
            mounts=row['Mounts']
            if (len(mounts)>128 or any(type(m) is not dict or type(m.get('Destination')) is not str
                    or not m['Destination'].startswith('/') for m in mounts)
                    or len({m['Destination'] for m in mounts})!=len(mounts)):reject()
            static=dict(name=row['Name'],image=row['Image'],config=row['Config'],hostConfig=row['HostConfig'],
                mounts=sorted(mounts,key=lambda m:m['Destination']),networks=settings['Networks'],ports=settings['Ports'])
            containers.append(dict(id=cid,startedAt=state['StartedAt'],status=state['Status'],
                restartCount=row['RestartCount'],staticDigest=hashlib.sha256(encode(static)).hexdigest()))
        network=capture_network(deadline)
        if network['netns']!=self._context['net'] or network['mountns']!=self._context['mnt']:reject()
        self._fresh(deadline)
        return encode(dict(profile=PROFILE,endpointDigest=hashlib.sha256(self._endpoint).hexdigest(),
            resources=resources,containers=containers,network=network))

    def _capture(self,deadline,budget,*,include_definitions=False):
        first=self._scan(deadline,budget,include_definitions=include_definitions)
        second=self._scan(deadline,budget,include_definitions=include_definitions)
        if first!=second:reject()
        units._left(deadline)
        return first

    def descriptor(self):
        self._check()
        return dict(profile=PROFILE,beforeDigest=hashlib.sha256(self._baseline).hexdigest(),
            endpointDigest=hashlib.sha256(self._endpoint).hexdigest())

    def verify_unchanged(self,*,timeout=20):
        self._check()
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=20:reject()
        value=self._capture(time.monotonic()+timeout,[32*1024*1024])
        if value!=self._baseline:reject()
        return hashlib.sha256(value).hexdigest()

    def close(self):
        if os.getpid()!=self._owner:reject()
        self._closed=True
        if self._fd is not None:os.close(self._fd);self._fd=None


def _frontend_projection(snapshot, original_id, protected_ids, candidate_id):
    expected = set(protected_ids) | {original_id}
    if candidate_id is not None:
        if (type(candidate_id) is not str or not re.fullmatch('[0-9a-f]{64}', candidate_id)
                or candidate_id in expected):
            reject()
        expected.add(candidate_id)
    resources = snapshot['resources']
    rows = snapshot['containers']
    if set(resources['containers']) != expected or {row['id'] for row in rows} != expected:
        reject()
    resources = {key: value for key, value in resources.items() if key != 'containers'}
    definitions = {}
    for network_id, definition in resources['networkDefinitions'].items():
        network = dict(definition)
        if 'Containers' in network:
            members = network['Containers']
            if members is not None and type(members) is not dict:
                reject()
            network['Containers'] = {
                key: value for key, value in (members or {}).items()
                if key != original_id and key != candidate_id
            }
        definitions[network_id] = network
    resources['networkDefinitions'] = definitions
    return encode(dict(
        profile=FRONTEND_PROTECTION_PROFILE,
        endpointDigest=snapshot['endpointDigest'],
        resources=resources,
        containers=[row for row in rows if row['id'] in protected_ids],
        network=snapshot['network'],
    ))


class ProductionFrontendProtectionV1:
    """Observe the whole host while allowing only a retained original and one candidate.

    The trusted worker supplies the exact candidate ID from its create receipt.
    This projection records Docker resource definitions, not volume contents.
    """
    __slots__ = ('__weakref__',)

    def __init__(self, observer, *, daemon_id, original_id, protected_ids, timeout=20):
        if (type(self) is not ProductionFrontendProtectionV1 or type(observer) is not HostSnapshotV3
                or self in _FRONTEND_PROTECTIONS
                or type(daemon_id) is not str or daemon_id!=observer._info_id
                or type(original_id) is not str or not re.fullmatch('[0-9a-f]{64}',original_id)
                or type(protected_ids) is not tuple or not 1<=len(protected_ids)<=63
                or any(type(item) is not str or not re.fullmatch('[0-9a-f]{64}',item) for item in protected_ids)
                or tuple(sorted(set(protected_ids)))!=protected_ids or original_id in protected_ids):
            reject()
        baseline = _frontend_projection(self._observe(observer,timeout),original_id,protected_ids,None)
        _FRONTEND_PROTECTIONS[self] = ((os.getpid(),threading.get_ident()),observer,original_id,protected_ids,baseline)

    @staticmethod
    def _observe(observer,timeout):
        observer._check()
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=20:
            reject()
        return json.loads(observer._capture(time.monotonic()+timeout,[32*1024*1024],include_definitions=True))

    def verify(self, *, candidate_id=None, timeout=20):
        state = _FRONTEND_PROTECTIONS.get(self)
        if state is None or state[0]!=(os.getpid(),threading.get_ident()):
            reject()
        _,observer,original,protected,baseline=state
        current=_frontend_projection(self._observe(observer,timeout),original,protected,candidate_id)
        if current!=baseline:
            reject()
        return hashlib.sha256(current).hexdigest()
