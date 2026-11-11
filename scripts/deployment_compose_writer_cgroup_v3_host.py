"""Owned Linux process-tree drain, never a writer or recovery authorization.

Only a root manager in its dedicated systemd delegated unit can create a leaf.
The embedding owns the fixed no-fork bootstrap until attach and verification.
"""
import json
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import threading
from functools import wraps

UNIT = re.compile(r'dw-writer-host-[0-9a-f]{16}\.service\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
ROOT = Path('/sys/fs/cgroup')


def reject():
    raise ValueError('writer-cgroup-v3-rejected') from None


def remaining(deadline):
    if type(deadline) not in (float, int) or not math.isfinite(deadline): reject()
    left = deadline-time.monotonic()
    if not 0 < left <= 180: reject()
    return left


def events(raw):
    result = {}
    for line in raw.splitlines():
        key, value = line.split()
        if key in result or not value.isdecimal(): reject()
        result[key] = int(value)
    if result.get('populated') not in (0, 1): reject()
    return result


def serialized(method):
    @wraps(method)
    def call(self,*args,**kwargs):
        if os.getpid() != self._owner: reject()
        with self._mutex:
            return method(self,*args,**kwargs)
    return call


class ProcessDrainV3:
    """Opaque live-issuer record; contains no capability or serialized proof."""
    pass


class WriterCgroupV3:
    def __init__(self, request_hash, scope_hash, worker_uid, worker_gid):
        self._owner = os.getpid()
        self._mutex = threading.RLock()
        self._parent_fd = self._fd = None
        self._process = self._proof = None
        self._attached = False
        self._closed = False
        try:
            if (sys.platform != 'linux' or os.geteuid() != 0
                    or type(request_hash) is not str or not HASH.fullmatch(request_hash)
                    or type(scope_hash) is not str or not HASH.fullmatch(scope_hash)
                    or type(worker_uid) is not int or not 0 < worker_uid < 2**31
                    or type(worker_gid) is not int or not 0 < worker_gid < 2**31): reject()
            self.request_hash, self.scope_hash = request_hash, scope_hash
            self.worker_uid, self.worker_gid = worker_uid, worker_gid
            self.actor_epoch = secrets.token_hex(32)
            membership = Path('/proc/self/cgroup').read_text().splitlines()
            if len(membership) != 1 or not membership[0].startswith('0::/system.slice/'): reject()
            relative = membership[0][3:]
            unit = relative.split('/')[-1]
            if relative != '/system.slice/'+unit or not UNIT.fullmatch(unit): reject()
            result = subprocess.run(['/usr/bin/systemctl', 'show', unit,
                '--property=Delegate', '--property=ControlGroup'], capture_output=True,
                timeout=5, check=True, env={})
            properties = dict(line.split('=', 1) for line in result.stdout.decode().splitlines())
            if properties != {'Delegate': 'yes', 'ControlGroup': relative}: reject()
            # Require the actual complete unified mount, not a namespace-truncated view.
            mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
            unified = [p for p in mounts if ' - cgroup2 ' in ' '.join(p)]
            if len(unified) != 1 or unified[0][3:5] != ['/', str(ROOT)]: reject()
            self._parent_path = ROOT/relative.lstrip('/')
            fd = os.open(ROOT, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                for part in relative.strip('/').split('/'):
                    child = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child
                self._parent_fd = fd; fd = None
            finally:
                if fd is not None: os.close(fd)
            if self._read_at(self._parent_fd, 'cgroup.type').strip() != 'domain': reject()
            self._name = 'writer-'+secrets.token_hex(16)
            os.mkdir(self._name, dir_fd=self._parent_fd)
            self._identity = self._id(os.stat(self._name,dir_fd=self._parent_fd,follow_symlinks=False))
            self._fd = os.open(self._name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=self._parent_fd)
            self._validate()
            if self._read('cgroup.type').strip() != 'domain' or events(self._read('cgroup.events'))['populated']: reject()
            probe = os.open('cgroup.kill', os.O_WRONLY|os.O_NOFOLLOW, dir_fd=self._fd); os.close(probe)
        except Exception:
            self._dispose()
            reject()

    @staticmethod
    def _id(info): return info.st_dev, info.st_ino

    @staticmethod
    def _read_at(directory, name):
        fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW, dir_fd=directory)
        try:
            raw = os.read(fd, 65537)
            if len(raw) > 65536: reject()
            return raw.decode('ascii')
        finally: os.close(fd)

    def _owner_check(self):
        if os.getpid() != self._owner or self._closed: reject()

    def _validate(self):
        self._owner_check()
        if self._fd is None or self._id(os.fstat(self._fd)) != self._identity: reject()
        if self._id(os.stat(self._name, dir_fd=self._parent_fd, follow_symlinks=False)) != self._identity: reject()
        path = self._parent_path/self._name
        if self._id(path.stat(follow_symlinks=False)) != self._identity: reject()

    def _read(self, name):
        self._validate()
        return self._read_at(self._fd, name)

    def _write(self, name, value):
        self._validate()
        fd = os.open(name, os.O_WRONLY|os.O_NOFOLLOW, dir_fd=self._fd)
        try:
            if os.write(fd, value) != len(value): reject()
        finally: os.close(fd)

    def _owned(self, process):
        self._validate()
        if type(process) is not subprocess.Popen or process is not self._process: reject()

    @serialized
    def attach(self, process, deadline):
        try:
            remaining(deadline); self._validate()
            if self._process is not None or type(process) is not subprocess.Popen or process.poll() is not None: reject()
            status = self._status(process)
            if status['PPid'].strip() != str(self._owner) or status['Uid'].split() != [str(self.worker_uid)]*4: reject()
            # Bind before migration: a failed migration still retains cleanup responsibility.
            self._process = process
            self._write('cgroup.procs', str(process.pid).encode())
            if self._read('cgroup.procs').split() != [str(process.pid)]: reject()
            remaining(deadline)
            self._attached = True
        except Exception:
            if self._process is process and not self._attached:
                self._cleanup_before_go(deadline)
            reject()

    def _cleanup_before_go(self,deadline):
        # Only the registered, fixed bootstrap has been bound; no private GO
        # has been issued. Revocation here is cleanup, never containment proof.
        try: self._write('cgroup.kill',b'1')
        except Exception: pass
        try:
            if self._process.poll() is None: self._process.kill()
            self._process.wait(timeout=remaining(deadline))
        except Exception: pass

    @staticmethod
    def _status(process):
        return dict(line.split(':', 1) for line in Path('/proc/'+str(process.pid)+'/status').read_text().splitlines() if ':' in line)

    @serialized
    def verify_worker(self, process, deadline):
        try:
            self._owned(process); remaining(deadline)
            if not self._attached: reject()
            status = {k:v.strip() for k,v in self._status(process).items()}
            if (process.poll() is not None or status['PPid'] != str(self._owner)
                    or status['Uid'].split() != [str(self.worker_uid)]*4
                    or status['Gid'].split() != [str(self.worker_gid)]*4
                    or status['Groups'].split() or status['NoNewPrivs'] != '1'
                    or any(int(status[k],16) for k in ('CapEff','CapPrm','CapAmb'))): reject()
            expected = '0::/'+str((self._parent_path/self._name).relative_to(ROOT))
            if Path('/proc/'+str(process.pid)+'/cgroup').read_text().strip() != expected: reject()
            paths = []
            parent = self._parent_path
            while True:
                paths.append(str(parent/'cgroup.procs'))
                if parent == ROOT: break
                parent = parent.parent
            # This fixed helper has no writer material. Real dropped credentials make
            # os.access evaluate the kernel's DAC/ACL rules, including higher ancestors.
            code = "import os,json,sys; p=json.load(sys.stdin); print(json.dumps([os.access(x,os.W_OK) for x in p]))"
            result = subprocess.run([sys.executable,'-I','-S','-c',code],input=json.dumps(paths).encode(),
                capture_output=True, check=True, timeout=min(5,remaining(deadline)),
                user=self.worker_uid, group=self.worker_gid, extra_groups=[], env={}, close_fds=True)
            if json.loads(result.stdout) != [False]*len(paths): reject()
            self._owned(process); remaining(deadline)
            if process.poll() is not None or self._read('cgroup.procs').split() != [str(process.pid)]: reject()
        except Exception: reject()

    @serialized
    def kill_and_drain(self, process, deadline):
        try:
            self._owned(process); remaining(deadline)
            if not self._attached: reject()
            if self._proof is not None:
                self.verify_drain(process,self._proof)
                return self._proof
            self._write('cgroup.kill', b'1')
            process.wait(timeout=remaining(deadline))
            while events(self._read('cgroup.events'))['populated']:
                time.sleep(min(.01, remaining(deadline)))
            remaining(deadline)
            self._proof = ProcessDrainV3()
            return self._proof
        except Exception: reject()

    @serialized
    def verify_drain(self, process, proof):
        try:
            self._owned(process)
            if (type(proof) is not ProcessDrainV3 or proof is not self._proof
                    or process.returncode is None or events(self._read('cgroup.events'))['populated']): reject()
            return True
        except Exception: reject()

    @serialized
    def capture_drain_facts(self, process, proof):
        self.verify_drain(process, proof)
        return (self.request_hash, self.scope_hash, self.actor_epoch,
                tuple(self._identity), process.pid, process.returncode)

    def _dispose(self):
        if self._fd is not None:
            os.close(self._fd); self._fd = None
        if self._parent_fd is not None:
            if hasattr(self,'_name'):
                try:
                    if (hasattr(self,'_identity') and self._id(os.stat(self._name,dir_fd=self._parent_fd,follow_symlinks=False)) == self._identity):
                        os.rmdir(self._name, dir_fd=self._parent_fd)
                except OSError: pass  # Never delete a nonempty or foreign tree.
            os.close(self._parent_fd); self._parent_fd = None

    @serialized
    def close(self, deadline=None):
        if os.getpid() != self._owner: reject()
        if self._closed: return
        if deadline is None: deadline=time.monotonic()+5
        try:
            try:
                remaining(deadline)
            except ValueError:
                # Expiry never mints proof, but revoke this retained tree before
                # returning failure; ownership remains for a later cleanup pass.
                if self._process is not None: self._write('cgroup.kill',b'1')
                reject()
            if self._process is not None:
                if self._attached: self.kill_and_drain(self._process,deadline)
                else:
                    self._cleanup_before_go(deadline)
                    remaining(deadline)
                    if self._process.returncode is None: reject()
            self._validate()
            if events(self._read('cgroup.events'))['populated']: reject()
            os.rmdir(self._name,dir_fd=self._parent_fd)
            self._dispose(); self._closed=True
        except Exception: reject()
