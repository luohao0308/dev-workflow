"""Read-only observation of the fixed worker's separate daemon service.

No start/stop method or caller-supplied unit/PID exists. This proves the bound
daemon lifetime, not resource deletion, host invariance or hostile-root isolation.
"""
import os
import math
import hashlib
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import time

import deployment_runtime as runtime
import deployment_compose_owned_recovery_unit_v3_host as units
from deployment_compose_reader_host import _UnixDocker,_complete_json_response
from deployment_compose_writer_cgroup_v3_host import events
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_resource_inventory_v3_host import inventory,PATHS

_ROOT_UID=0


def reject():
    raise ValueError('compose-recovery-daemon-v3-rejected') from None


def _ticks(pid):
    try:raw=Path('/proc')/str(pid)/'stat';value=raw.read_text()
    except FileNotFoundError:return None
    tail=value[value.rindex(')')+2:].split()
    if len(tail)<20 or not tail[19].isascii() or not tail[19].isdecimal():reject()
    return int(tail[19])


def _peer(sock):
    return struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))


class ObservedRecoveryDaemonV3:
    def __init__(self,root,daemon_id,*,kernel_boot,timeout=15):
        if (type(root) is not str or not re.fullmatch('/var/tmp/dw-engine-[0-9a-f]{16}',root)
                or type(daemon_id) is not str or not 0<len(daemon_id)<=256
                or type(kernel_boot) is not str or not re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',kernel_boot)
                or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=15):reject()
        units._environment()
        self._owner=os.getpid();self._boot=kernel_boot
        self.root=root;self.daemon_id=daemon_id;self.unit=Path(root).name+'.service'
        self._group='/system.slice/'+self.unit
        self._root_parent=self._root_fd=self._parent=self._fd=None
        self._identity=self._root_identity=None
        self._main=self._daemon=None
        self._binding=None;self._closed=False
        self._socket_identity=self._pid_file_identity=None
        self._resource_baseline=None
        self._resource_attempted=False
        deadline=time.monotonic()+timeout
        try:
            self._check()
            self._root_parent=os.open('/var/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            self._root_fd=os.open(Path(root).name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self._root_parent)
            info=os.fstat(self._root_fd)
            if info.st_uid!=_ROOT_UID or info.st_mode&0o777!=0o700:reject()
            self._root_identity=self._id(info)
            before=self._state(deadline)
            if (before['LoadState']!='loaded' or before['ActiveState']!='active'
                    or before['SubState']!='running' or before['Delegate']!='yes'
                    or before['ControlGroup']!=self._group or int(before['MainPID'])<=0
                    or not re.fullmatch('[0-9a-f]{32}',before['InvocationID'])):reject()
            self._invocation=before['InvocationID']
            group_root=os.open(units.CGROUP,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:self._parent=os.open('system.slice',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=group_root)
            finally:os.close(group_root)
            self._fd=os.open(self.unit,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self._parent)
            self._identity=self._id(os.fstat(self._fd))
            self._main=units._pid_identity(before['MainPID'],self._group+'/supervisor')
            if self._read('cgroup.type').strip()!='domain' or events(self._read('cgroup.events'))['populated']!=1:reject()
            self._info(deadline)
            if (self._state(deadline)!=before
                    or units._pid_identity(before['MainPID'],self._group+'/supervisor')!=self._main
                    or not self._same_group()):reject()
            self._live_state=dict(before)
            self._binding=dict(root=root,daemonId=daemon_id,unit=self.unit,kernelBoot=kernel_boot,
                invocationId=self._invocation,cgroupDevice=self._identity[0],cgroupInode=self._identity[1],
                mainPid=self._main[0],mainStartTicks=self._main[1],daemonPid=self._daemon[0],daemonStartTicks=self._daemon[1])
            units._left(deadline)
        except BaseException:
            try:self.close()
            except Exception:pass
            raise

    @staticmethod
    def _id(info):return info.st_dev,info.st_ino

    def _check(self):
        if os.getpid()!=self._owner or self._closed or units._boot()!=self._boot:reject()

    def _state(self,deadline):
        self._check()
        result=subprocess.run(['/usr/bin/systemctl','--system','show',self.unit,'--all',
            '--property='+','.join(units.PROPERTIES)],capture_output=True,env={},
            timeout=min(5,units._left(deadline)),check=False)
        if len(result.stdout)>16384:reject()
        value={}
        for line in result.stdout.decode('ascii').splitlines():
            key,item=line.split('=',1)
            if key in value:reject()
            value[key]=item
        if (set(value)!=set(units.PROPERTIES) or not value['MainPID'].isascii()
                or not value['MainPID'].isdecimal()
                or result.returncode and value['LoadState']!='not-found'):reject()
        return value

    def _root_same(self):
        info=os.stat(Path(self.root).name,dir_fd=self._root_parent,follow_symlinks=False)
        if self._id(info)!=self._root_identity or self._id(os.fstat(self._root_fd))!=self._root_identity:reject()

    def _same_group(self):
        self._check()
        if self._id(os.stat(units.CGROUP/'system.slice',follow_symlinks=False))!=self._id(os.fstat(self._parent)):reject()
        try:info=os.stat(self.unit,dir_fd=self._parent,follow_symlinks=False)
        except FileNotFoundError:return False
        if self._id(info)!=self._identity or self._id(os.fstat(self._fd))!=self._identity:reject()
        return True

    def _read(self,name):
        if not self._same_group():reject()
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self._fd)
        try:
            raw=os.read(fd,65537)
            if len(raw)>65536:reject()
            return raw.decode('ascii')
        finally:os.close(fd)

    def _pid_file(self):
        fd=os.open('daemon.pid',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._root_fd)
        try:
            info=os.fstat(fd);raw=os.read(fd,65)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=_ROOT_UID or info.st_mode&0o022
                    or len(raw)>64):reject()
            value=raw.decode('ascii').strip()
            if not value.isascii() or not value.isdecimal() or not 0<int(value)<2**31:reject()
            return int(value),self._id(info)
        finally:os.close(fd)

    def _request(self,path,deadline,budget=None,*,phase_paths=None):
        allowed=PATHS|{'/v1.45/info'} if phase_paths is None else phase_paths
        if phase_paths is not None and type(phase_paths) is not frozenset:reject()
        if path not in allowed:reject()
        self._root_same()
        inode=os.stat('docker.sock',dir_fd=self._root_fd,follow_symlinks=False)
        if not stat.S_ISSOCK(inode.st_mode) or inode.st_uid!=_ROOT_UID:reject()
        pid,file_id=self._pid_file()
        identity=units._pid_identity(str(pid),self._group+'/supervisor')
        if self._daemon is None:
            self._daemon=identity;self._socket_identity=self._id(inode);self._pid_file_identity=(pid,file_id)
        elif (identity!=self._daemon or self._id(inode)!=self._socket_identity
                or (pid,file_id)!=self._pid_file_identity):reject()
        connection=_UnixDocker('/proc/self/fd/'+str(self._root_fd)+'/docker.sock',min(5,units._left(deadline)))
        watchdog=None
        phase_response=None
        try:
            connection.connect()
            watchdog=runtime.deadline_watchdog(connection.sock,min(deadline,time.monotonic()+5))
            peer,uid,_=_peer(connection.sock)
            if peer!=pid or uid!=_ROOT_UID:reject()
            connection.request('GET',path,headers={'Accept':'application/json'})
            response=connection.getresponse()
            if phase_paths is not None:
                phase_response=response
                if type(budget) is not list or len(budget)!=1 or type(budget[0]) is not int or budget[0]<0:reject()
                original_response=response
                class BudgetResponse:
                    def __getattr__(self,name):return getattr(original_response,name)
                    def read1(self,size):
                        raw=original_response.read1(min(size,budget[0]+1))
                        budget[0]-=len(raw)
                        if budget[0]<0:reject()
                        return raw
                response=BudgetResponse()
            raw,value=_complete_json_response(response)
            if budget is not None and phase_paths is None:
                budget[0]-=len(raw)
                if budget[0]<0:reject()
        finally:
            if phase_paths is None:
                if watchdog is not None:watchdog.cancel()
                connection.close()
            else:
                import sys
                primary=sys.exc_info()[1]
                failed=False
                actions=[]
                if phase_response is not None:actions.append(lambda:phase_response.close())
                if watchdog is not None:actions.append(lambda:watchdog.cancel())
                actions.append(lambda:connection.close())
                for action in actions:
                    try:action()
                    except Exception:failed=True
                if failed:
                    if primary is None:reject()
                    try:
                        if hasattr(primary,'add_note'):primary.add_note('live phase response cleanup incomplete')
                    except Exception:pass
        self._root_same()
        if (self._pid_file()!=(pid,file_id)
                or self._id(os.stat('docker.sock',dir_fd=self._root_fd,follow_symlinks=False))!=self._id(inode)
                or units._pid_identity(str(pid),self._group+'/supervisor')!=self._daemon):reject()
        return value

    def _info(self,deadline,budget=None):
        value=self._request('/v1.45/info',deadline,budget)
        if type(value) is not dict or value.get('ID')!=self.daemon_id or value.get('DockerRootDir')!=self.root+'/data':reject()

    def _resources(self,deadline):
        self._check()
        state=self._state(deadline)
        if (state!=self._live_state or state['ActiveState']!='active' or state['InvocationID']!=self._invocation
                or state['ControlGroup']!=self._group or int(state['MainPID'])!=self._main[0]
                or units._pid_identity(state['MainPID'],self._group+'/supervisor')!=self._main
                or not self._same_group()):reject()
        budget=[16*1024*1024]
        self._info(deadline,budget)
        read=lambda path:self._request(path,deadline,budget)
        first=inventory(read);second=inventory(read)
        self._info(deadline,budget)
        if encode(first)!=encode(second) or self._state(deadline)!=state:reject()
        units._left(deadline)
        return encode(dict(schemaVersion=1,daemonBindingDigest=hashlib.sha256(encode(self._binding)).hexdigest(),**first))

    def begin_resource_observation(self,*,timeout=15):
        self._check()
        if (self._resource_attempted or type(timeout) not in (int,float)
                or not math.isfinite(timeout) or not 0<timeout<=15):reject()
        self._resource_attempted=True
        raw=self._resources(time.monotonic()+timeout)
        import json
        value=json.loads(raw)
        if any(value[k] for k in ('containers','images','volumes')):reject()
        self._resource_baseline=raw
        return hashlib.sha256(raw).hexdigest()

    def verify_resources_restored(self,*,timeout=15):
        self._check()
        if (self._resource_baseline is None or type(timeout) not in (int,float)
                or not math.isfinite(timeout) or not 0<timeout<=15):reject()
        raw=self._resources(time.monotonic()+timeout)
        if raw!=self._resource_baseline:reject()
        return hashlib.sha256(raw).hexdigest()

    def _phase_endpoint(self,deadline,budget,paths,version):
        from deployment_compose_cold_writer_v3_host import pid_namespace,process_pid_namespace,PROC
        self._check()
        self._root_same()
        root_info=os.fstat(self._root_fd)
        if root_info.st_uid!=_ROOT_UID or root_info.st_mode&0o777!=0o700:reject()
        state=self._state(deadline)
        if (state!=self._live_state or state['ActiveState']!='active' or state['InvocationID']!=self._invocation
                or state['ControlGroup']!=self._group or int(state['MainPID'])!=self._main[0]
                or units._pid_identity(state['MainPID'],self._group+'/supervisor')!=self._main
                or not self._same_group() or self._read('cgroup.type').strip()!='domain'
                or events(self._read('cgroup.events'))['populated']!=1):reject()
        info=self._request('/v1.45/info',deadline,budget,phase_paths=paths)
        if type(info) is not dict or info.get('ID')!=self.daemon_id or info.get('DockerRootDir')!=self.root+'/data':reject()
        namespace=pid_namespace();daemon_namespace=process_pid_namespace(self._daemon[0])
        if namespace!=daemon_namespace:reject()
        def ns(name):
            info=os.stat(PROC/str(self._daemon[0])/'ns'/name)
            return [info.st_dev,info.st_ino]
        value=dict(daemonBinding=self.binding(),pidNamespace=list(namespace),daemonPidNamespace=list(daemon_namespace),
            networkNamespace=ns('net'),mountNamespace=ns('mnt'),normalizationVersion=version,
            rootIdentity=list(self._root_identity),socketIdentity=list(self._socket_identity),
            pidFileIdentity=[self._pid_file_identity[0],list(self._pid_file_identity[1])])
        if self._state(deadline)!=state or not self._same_group():reject()
        units._left(deadline)
        return encode(value)

    def capture_recovery_phase(self,bundle,baseline_rows,phase_context,*,expected_version,timeout=15,terminal=False):
        from copy import deepcopy
        import json
        from urllib.parse import quote
        from deployment_compose_bundle_v3 import ExecutionBundleV3
        from deployment_compose_phase_guard_v3_host import PhaseGuardV3,_plain
        try:
            self._check()
            if (type(bundle) is not ExecutionBundleV3 or bundle.to_dict()['identity']['daemonId']!=self.daemon_id
                    or type(expected_version) is not dict or set(expected_version)!={'Version','GitCommit'}
                    or any(type(v) is not str or not v for v in expected_version.values())
                    or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=30
                    or type(terminal) is not bool):reject()
            deadline=time.monotonic()+timeout;budget=[16*1024*1024]
            version=deepcopy(expected_version);baseline=deepcopy(baseline_rows);context=_plain(phase_context)
            value=bundle.to_dict()
            filters=json.dumps({'label':['com.docker.compose.project='+value['identity']['project']]},sort_keys=True,separators=(',',':'))
            ids=set(baseline)|set(context['receipts'].values())
            paths=frozenset({'/v1.45/info','/v1.45/version',
                '/v1.45/containers/json?all=1&filters='+quote(filters,safe='')}|
                {'/v1.45/containers/'+cid+'/json' for cid in ids}|
                {'/v1.45/networks/'+pin['id'] for pin in value['networks'].values()}|
                {'/v1.45/volumes/'+quote(m['Name'],safe='') for row in baseline.values() for m in row['Mounts'] if m['Type']=='volume'})
            def read(path):return self._request(path,deadline,budget,phase_paths=paths)
            guard=PhaseGuardV3(bundle,baseline,read_json=read,daemon_version=version,expected_docker_root=self.root+'/data')
            guard._context(context, terminal=terminal)
            before=self._phase_endpoint(deadline,budget,paths,version)
            phase=encode(_plain(guard.capture_phase(context, terminal=terminal)))
            if self._phase_endpoint(deadline,budget,paths,version)!=before:reject()
            units._left(deadline)
            return phase,before
        except Exception:reject()

    def binding(self):
        self._check()
        return dict(self._binding)

    def verify_stopped(self,*,timeout=10):
        self._check()
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=30:reject()
        deadline=time.monotonic()+timeout
        confirmed=0
        while confirmed<2:
            units._left(deadline)
            value=self._state(deadline)
            if value['ActiveState'] in ('active','deactivating'):
                # Parent death initiates asynchronous supervisor teardown. Wait
                # for this same service, never start/stop/rebind or reset time.
                if (value['LoadState']!='loaded' or value['InvocationID']!=self._invocation
                        or value['ControlGroup']!=self._group or value['Delegate']!='yes'
                        or value['MainPID'] not in ('0',str(self._main[0]))):reject()
                self._same_group()  # An absent group can be normal stop progress.
                if value['MainPID']!='0' and _ticks(self._main[0]) not in (None,self._main[1]):reject()
                confirmed=0
                time.sleep(min(.1,units._left(deadline)))
                continue
            if not units.OwnedRecoveryUnitV3._absent(value):
                if (value['LoadState']!='loaded' or value['ActiveState'] not in ('inactive','failed')
                        or value['MainPID']!='0' or value['InvocationID'] not in ('',self._invocation)
                        or value['ControlGroup'] not in ('',self._group)):reject()
            if self._same_group() and events(self._read('cgroup.events'))['populated']!=0:reject()
            for pid,ticks in (self._main,self._daemon):
                if _ticks(pid)==ticks:reject()
            confirmed+=1
        units._left(deadline)
        return None

    def close(self):
        if os.getpid()!=self._owner:reject()
        self._closed=True
        failure=None
        for name in ('_fd','_parent','_root_fd','_root_parent'):
            fd=getattr(self,name)
            if fd is not None:
                try:os.close(fd)
                except Exception as error:
                    if failure is None:failure=error
                finally:setattr(self,name,None)
        if failure is not None:raise failure
