"""Trusted Linux-local owner of one fixed recovery wrapper service.

This object controls only its wrapper cgroup. The worker's separate daemon unit,
observer boot identity, approval and remote authentication remain independent.
No CLI or serialized termination capability is provided.
The trusted host manager must reserve this random unit name exclusively: systemd
does not offer an atomic compare-InvocationID-and-stop operation.
"""
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time

from deployment_compose_owned_recovery_ssh_v3_host import recovery_bootstrap, response_loss_bootstrap
from deployment_compose_writer_cgroup_v3_host import events

CGROUP = Path('/sys/fs/cgroup')
PROPERTIES = ('LoadState','ActiveState','SubState','MainPID','ControlGroup','InvocationID','Delegate')


def reject():
    raise ValueError('compose-owned-recovery-unit-v3-rejected') from None


def _left(deadline):
    left = deadline-time.monotonic()
    if not 0 < left <= 60:reject()
    return left


def _boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',value):reject()
    return value


def _environment():
    if sys.platform != 'linux' or os.geteuid() != 0:reject()
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    unified = [line.split() for line in mounts if ' - cgroup2 ' in line]
    if len(unified) != 1 or unified[0][3:5] != ['/',str(CGROUP)]:reject()


def _spawn(argv):
    return subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,bufsize=0,env={},close_fds=True)


def _pid_identity(pid,group):
    path = Path('/proc')/pid
    raw = (path/'stat').read_text()
    tail = raw[raw.rindex(')')+2:].split()
    if (len(tail)<20 or not tail[19].isascii() or not tail[19].isdecimal()
            or (path/'cgroup').read_text().strip()!='0::'+group):reject()
    return int(pid),int(tail[19])


class OwnedRecoveryUnitV3:
    """One start, bounded stop, revalidated wrapper-empty state, same process only.

    Caller must not send initial archive/config until start() returns. Its pipe
    process is the local systemd-run transport, never an SSH-host identity proof.
    """
    def __init__(self, archive_digest, source_sha):
        self._code = recovery_bootstrap(archive_digest,source_sha)
        self._source_sha, self._archive_digest = source_sha, archive_digest
        _environment()
        self._owner = os.getpid()
        self._boot_id = _boot()
        self.unit = 'dw-writer-host-'+secrets.token_hex(8)+'.service'
        self._group = '/system.slice/'+self.unit
        self._lock = threading.RLock()
        self._attempted = False
        self._invocation = None
        self._process = None
        self._parent = self._fd = None
        self._identity = None
        self._stopped = False
        self.creation_outcome_unknown = False
        self.transport_returncode = None
        self._pid = None

    def _check(self):
        if os.getpid() != self._owner or _boot() != self._boot_id:reject()

    def _state(self,deadline):
        self._check()
        result = subprocess.run(['/usr/bin/systemctl','--system','show',self.unit,'--all',
            '--property='+','.join(PROPERTIES)],capture_output=True,
            timeout=min(5,_left(deadline)),env={},check=False)
        if len(result.stdout)>16384:reject()
        value = {}
        for line in result.stdout.decode('ascii').splitlines():
            key,content = line.split('=',1)
            if key in value:reject()
            value[key] = content
        if (set(value) != set(PROPERTIES) or not value['MainPID'].isascii()
                or not value['MainPID'].isdecimal()):reject()
        # systemctl may return nonzero for a collected not-found unit only.
        if result.returncode and value['LoadState'] != 'not-found':reject()
        return value

    @staticmethod
    def _absent(state):
        return (state['LoadState']=='not-found' and state['ActiveState']=='inactive'
            and state['MainPID']=='0' and state['ControlGroup']=='' and state['InvocationID']=='')

    def _open_group(self):
        root = os.open(CGROUP,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            self._parent = os.open('system.slice',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
        finally:os.close(root)
        self._fd = os.open(self.unit,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self._parent)
        self._identity = self._id(os.fstat(self._fd))
        self._same_group()

    @staticmethod
    def _id(info):return info.st_dev,info.st_ino

    def _same_group(self):
        if self._parent is None or self._identity is None:reject()
        if self._id(os.stat(CGROUP/'system.slice',follow_symlinks=False)) != self._id(os.fstat(self._parent)):reject()
        try:info = os.stat(self.unit,dir_fd=self._parent,follow_symlinks=False)
        except FileNotFoundError:return False
        if self._id(info) != self._identity or self._id(os.fstat(self._fd)) != self._identity:reject()
        return True

    def _read(self,name):
        if not self._same_group():reject()
        fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self._fd)
        try:
            raw = os.read(fd,65537)
            if len(raw)>65536:reject()
            return raw.decode('ascii')
        finally:os.close(fd)

    def start(self, *, timeout=15):
        self._check()
        with self._lock:
            self._check()
            if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=30:reject()
            if self._attempted:reject()
            self._attempted = True
            deadline = time.monotonic()+timeout
            if not self._absent(self._state(deadline)):reject()
            argv = ['/usr/bin/systemd-run','--system','--quiet','--wait','--pipe','--collect',
                '--slice=system.slice',
                '--service-type=exec','--unit='+self.unit,'--property=User=root',
                '--property=Delegate=yes','--property=KillMode=control-group',
                '--property=RuntimeMaxSec=3700','--property=TimeoutStopSec=15',
                '--property=SendSIGKILL=yes','--property=Restart=no','--',
                '/usr/bin/python3','-I','-u','-c',self._code]
            self.creation_outcome_unknown = True
            try:
                self._process = _spawn(argv)
                while True:
                    state = self._state(deadline)
                    if state['ActiveState']=='active':break
                    if self._process.poll() is not None:reject()
                    time.sleep(min(.02,_left(deadline)))
                if (state['LoadState']!='loaded' or state['Delegate']!='yes'
                        or state['ControlGroup']!=self._group or int(state['MainPID'])<=0
                        or not re.fullmatch('[0-9a-f]{32}',state['InvocationID'])):reject()
                self._invocation = state['InvocationID']
                self._open_group()
                if (self._read('cgroup.type').strip()!='domain'
                        or self._read('cgroup.procs').split()!=[state['MainPID']]
                        or events(self._read('cgroup.events'))['populated']!=1):reject()
                self._pid = _pid_identity(state['MainPID'],self._group)
                # A second direct manager read prevents a changed invocation
                # being accepted after opening the cgroup; no input sent yet.
                if (self._state(deadline)!=state or self._process.poll() is not None
                        or _pid_identity(state['MainPID'],self._group)!=self._pid):reject()
                self.creation_outcome_unknown = False
                return self._process
            except BaseException as original:
                # Never guess ownership when start/binding was uncertain.
                # The fixed loader input deadline and service runtime still apply.
                if self._invocation is not None and self._identity is not None:
                    try:self.stop(timeout=20)
                    except Exception:pass
                try:self._discard_local()
                except Exception:
                    if hasattr(original,'add_note'):original.add_note('local wrapper cleanup unverified')
                raise

    def capture_origin(self, *, timeout=5):
        self._check()
        with self._lock:
            self._check()
            if (type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 30
                    or not self._attempted or self.creation_outcome_unknown or self._stopped
                    or self._process is None or self._process.poll() is not None):reject()
            from deployment_compose_cold_writer_v3_host import pid_namespace, process_pid_namespace, validate_origin
            from deployment_compose_witness_store import canonical
            deadline = time.monotonic()+timeout
            namespace = pid_namespace()
            state = self._state(deadline)
            if (state['LoadState']!='loaded' or state['ActiveState']!='active' or state['Delegate']!='yes'
                    or state['ControlGroup']!=self._group or state['InvocationID']!=self._invocation
                    or self._pid is None or state['MainPID']!=str(self._pid[0])
                    or process_pid_namespace(self._pid[0])!=namespace
                    or _pid_identity(state['MainPID'],self._group)!=self._pid
                    or not self._same_group() or self._read('cgroup.type').strip()!='domain'
                    or events(self._read('cgroup.events'))['populated']!=1):reject()
            parent = self._id(os.fstat(self._parent))
            raw = canonical(dict(schemaVersion=1,kind='compose-owned-writer-origin-v3',
                sourceSha=self._source_sha,archiveDigest=self._archive_digest,unit=self.unit,
                kernelBoot=self._boot_id,invocationId=self._invocation,mainPid=self._pid[0],
                mainStartTicks=self._pid[1],cgroupDevice=self._identity[0],cgroupInode=self._identity[1],
                parentDevice=parent[0],parentInode=parent[1],
                pidNamespaceDevice=namespace[0],pidNamespaceInode=namespace[1]))
            validate_origin(raw)
            if (self._state(deadline)!=state or pid_namespace()!=namespace
                    or process_pid_namespace(self._pid[0])!=namespace or not self._same_group()
                    or _pid_identity(state['MainPID'],self._group)!=self._pid
                    or self._process.poll() is not None):reject()
            _left(deadline)
            return raw

    def stop(self, *, timeout=30):
        self._check()
        with self._lock:
            self._check()
            if (type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=60
                    or self._invocation is None or self._identity is None):reject()
            deadline = time.monotonic()+timeout
            before = self._state(deadline)
            if not self._absent(before):
                if (before['InvocationID'] not in (self._invocation,'')
                        or before['ControlGroup'] not in (self._group,'')
                        or before['LoadState']!='loaded'):reject()
                if before['ActiveState'] not in ('inactive','failed'):
                    if before['InvocationID']!=self._invocation or before['ControlGroup']!=self._group:reject()
                    if not self._same_group():reject()
                    if before['MainPID']!='0' and _pid_identity(before['MainPID'],self._group)!=self._pid:reject()
                    subprocess.run(['/usr/bin/systemctl','--system','stop',self.unit],capture_output=True,
                        timeout=_left(deadline),env={},check=True)
            self._verify_stopped(deadline)
            # Reaping is separate from workload success. The controller must
            # still reject a nonzero transport exit after its protocol completes.
            self.transport_returncode = self._process.wait(timeout=_left(deadline))
            self._verify_stopped(deadline)
            self._stopped = True
            self.creation_outcome_unknown = False
            return None

    def _verify_stopped(self,deadline):
        after = self._state(deadline)
        if not self._absent(after):
            if (after['LoadState']!='loaded' or after['ActiveState'] not in ('inactive','failed')
                    or after['MainPID']!='0' or after['InvocationID'] not in ('',self._invocation)
                    or after['ControlGroup'] not in ('',self._group)):reject()
        if self._same_group() and events(self._read('cgroup.events'))['populated']!=0:reject()

    def _discard_local(self):
        """Close local resources after startup failure; never claim unit stop."""
        if self._process is not None:
            if self._process.poll() is None:
                self._process.kill()
                self._process.wait(timeout=5)
            for stream in (self._process.stdin,self._process.stdout,self._process.stderr):
                if stream is not None:stream.close()
        self._release_fds()

    def _release_fds(self):
        for name in ('_fd','_parent'):
            fd = getattr(self,name)
            if fd is not None:os.close(fd);setattr(self,name,None)

    def close(self):
        """Release descriptors only after verified stop; retry failures explicitly."""
        self._check()
        with self._lock:
            self._check()
            if not self._stopped:reject()
            self._discard_local()


class ResponseLossUnitV3(OwnedRecoveryUnitV3):
    """Same owner invariants, with only the fixed diagnostic loader selected."""
    def __init__(self,archive_digest,source_sha):
        super().__init__(archive_digest,source_sha)
        self._code=response_loss_bootstrap(archive_digest,source_sha)
