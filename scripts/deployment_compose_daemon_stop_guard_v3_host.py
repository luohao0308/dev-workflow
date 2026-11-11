"""Read-only stop precondition for a newly created fixed daemon unit.

Never imports stop authority from a serialized record. The trusted creator must
reserve its random unit name exclusively: systemd offers no atomic
compare-InvocationID-and-stop operation.
"""
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import deployment_compose_owned_recovery_unit_v3_host as units
from deployment_compose_writer_cgroup_v3_host import events

PROC=Path('/proc')
_ROOT_UID=0


def reject():raise ValueError('compose-daemon-stop-guard-v3-rejected') from None


class DaemonStopGuardV3:
    def __copy__(self):reject()
    def __deepcopy__(self,memo):reject()
    def __reduce_ex__(self,protocol):reject()

    def __init__(self,root):
        self._owner=os.getpid();self._closed=False
        self._root_parent=self._root_fd=self._parent=self._fd=None
        try:
            if not isinstance(root,Path) or re.fullmatch('/var/tmp/dw-engine-[0-9a-f]{16}',str(root)) is None:reject()
            units._environment();self.root=root;self.unit=root.name+'.service'
            self._group='/system.slice/'+self.unit;self._boot=units._boot()
            self._root_parent=os.open('/var/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            self._root_fd=os.open(root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self._root_parent)
            info=os.fstat(self._root_fd)
            if info.st_uid!=_ROOT_UID or stat.S_IMODE(info.st_mode)!=0o700:reject()
            self._root_id=self._id(info)
            group_root=os.open(units.CGROUP,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:self._parent=os.open('system.slice',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=group_root)
            finally:os.close(group_root)
            self._parent_id=self._id(os.fstat(self._parent))
            self._fd=os.open(self.unit,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self._parent)
            self._group_id=self._id(os.fstat(self._fd))
            deadline=time.monotonic()+5
            before=self._state(deadline)
            if (before['LoadState']!='loaded' or before['ActiveState']!='active' or before['SubState']!='running'
                    or before['Delegate']!='yes' or before['ControlGroup']!=self._group
                    or int(before['MainPID'])<=0 or re.fullmatch('[0-9a-f]{32}',before['InvocationID']) is None
                    or before['InvocationID']=='0'*32):reject()
            self._state_origin=before
            self._pid=units._pid_identity(before['MainPID'],self._group+'/supervisor')
            if not self._same_group() or self._populated()!=1 or self._state(deadline)!=before:reject()
            if units._pid_identity(before['MainPID'],self._group+'/supervisor')!=self._pid:reject()
            units._left(deadline)
        except BaseException:
            try:self.close()
            except Exception:pass
            raise

    @staticmethod
    def _id(info):return info.st_dev,info.st_ino

    def _check(self):
        if self._closed or self._owner!=os.getpid() or units._boot()!=self._boot:reject()
        for name,fd,expected,parent in ((self.root.name,self._root_fd,self._root_id,self._root_parent),
                ('system.slice',self._parent,self._parent_id,None)):
            info=os.stat(name,dir_fd=parent,follow_symlinks=False) if parent is not None else os.stat(units.CGROUP/name,follow_symlinks=False)
            if self._id(info)!=expected or self._id(os.fstat(fd))!=expected:reject()
        info=os.fstat(self._root_fd)
        if info.st_uid!=_ROOT_UID or stat.S_IMODE(info.st_mode)!=0o700:reject()

    def _same_group(self):
        self._check()
        try:info=os.stat(self.unit,dir_fd=self._parent,follow_symlinks=False)
        except FileNotFoundError:return False
        if self._id(info)!=self._group_id or self._id(os.fstat(self._fd))!=self._group_id:reject()
        return True

    def _populated(self):
        def read(name):
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self._fd)
            try:
                raw=os.read(fd,65537)
                if len(raw)>65536:reject()
                return raw.decode('ascii')
            finally:os.close(fd)
        if read('cgroup.type').strip()!='domain':reject()
        return events(read('cgroup.events'))['populated']

    def _state(self,deadline):
        self._check()
        result=subprocess.run(['/usr/bin/systemctl','--system','show',self.unit,'--all',
            '--property='+','.join(units.PROPERTIES)],capture_output=True,timeout=min(5,units._left(deadline)),env={},check=False)
        if len(result.stdout)>16384 or len(result.stderr)>16384 or result.stderr:reject()
        value={}
        for line in result.stdout.decode('ascii').splitlines():
            key,item=line.split('=',1)
            if key in value:reject()
            value[key]=item
        if (set(value)!=set(units.PROPERTIES) or not value['MainPID'].isascii() or not value['MainPID'].isdecimal()
                or result.returncode and value['LoadState']!='not-found'):reject()
        return value

    def should_stop(self,*,timeout=5):
        self._check()
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=5:reject()
        end=time.monotonic()+timeout;before=self._state(end);exists=self._same_group()
        if before==self._state_origin:
            if (not exists or self._populated()!=1
                    or units._pid_identity(before['MainPID'],self._group+'/supervisor')!=self._pid):reject()
            result=True
        else:
            inactive=(before['LoadState']=='loaded' and before['ActiveState'] in ('inactive','failed')
                and before['MainPID']=='0' and before['InvocationID'] in ('',self._state_origin['InvocationID'])
                and before['ControlGroup'] in ('',self._group))
            if not units.OwnedRecoveryUnitV3._absent(before) and not inactive:reject()
            # Reused PIDs, zombies and ambiguous process states all reject.
            try:os.stat(PROC/str(self._pid[0]),follow_symlinks=False)
            except FileNotFoundError:pass
            else:reject()
            if exists and self._populated()!=0:reject()
            result=False
        if self._state(end)!=before or self._same_group()!=exists:reject()
        if result and units._pid_identity(before['MainPID'],self._group+'/supervisor')!=self._pid:reject()
        units._left(end)
        return result

    def close(self):
        if os.getpid()!=self._owner:reject()
        self._closed=True;failure=None
        for name in ('_fd','_parent','_root_fd','_root_parent'):
            fd=getattr(self,name)
            if fd is not None:
                try:os.close(fd)
                except Exception as error:failure=error
                finally:setattr(self,name,None)
        if failure is not None:raise failure
