"""Read-only observation of the fixed worker's separate daemon service.

No start/stop method or caller-supplied unit/PID exists. This proves the bound
daemon lifetime, not resource deletion, host invariance or hostile-root isolation.
"""
import os
import math
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

    def _info(self,deadline):
        self._root_same()
        inode=os.stat('docker.sock',dir_fd=self._root_fd,follow_symlinks=False)
        if not stat.S_ISSOCK(inode.st_mode) or inode.st_uid!=_ROOT_UID:reject()
        pid,file_id=self._pid_file()
        self._daemon=units._pid_identity(str(pid),self._group+'/supervisor')
        connection=_UnixDocker('/proc/self/fd/'+str(self._root_fd)+'/docker.sock',min(5,units._left(deadline)))
        watchdog=None
        try:
            connection.connect()
            watchdog=runtime.deadline_watchdog(connection.sock,min(deadline,time.monotonic()+5))
            peer,uid,_=_peer(connection.sock)
            if peer!=pid or uid!=_ROOT_UID:reject()
            connection.request('GET','/v1.45/info',headers={'Accept':'application/json'})
            _,value=_complete_json_response(connection.getresponse())
            if type(value) is not dict or value.get('ID')!=self.daemon_id or value.get('DockerRootDir')!=self.root+'/data':reject()
        finally:
            if watchdog is not None:watchdog.cancel()
            connection.close()
        self._root_same()
        if (self._pid_file()!=(pid,file_id)
                or self._id(os.stat('docker.sock',dir_fd=self._root_fd,follow_symlinks=False))!=self._id(inode)
                or units._pid_identity(str(pid),self._group+'/supervisor')!=self._daemon):reject()

    def binding(self):
        self._check()
        return dict(self._binding)

    def verify_stopped(self,*,timeout=10):
        self._check()
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=10:reject()
        deadline=time.monotonic()+timeout
        for _ in range(2):
            value=self._state(deadline)
            if not units.OwnedRecoveryUnitV3._absent(value):
                if (value['LoadState']!='loaded' or value['ActiveState'] not in ('inactive','failed')
                        or value['MainPID']!='0' or value['InvocationID'] not in ('',self._invocation)
                        or value['ControlGroup'] not in ('',self._group)):reject()
            if self._same_group() and events(self._read('cgroup.events'))['populated']!=0:reject()
            for pid,ticks in (self._main,self._daemon):
                if _ticks(pid)==ticks:reject()
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
