"""Linux-local stopped-writer observations, not a stop or recovery capability."""
from dataclasses import dataclass, field
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import deployment_compose_owned_recovery_unit_v3_host as units
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical

PROC = Path('/proc')
MAX_ORIGIN = 8192
_FIELDS = {'schemaVersion','kind','sourceSha','archiveDigest','unit','kernelBoot','invocationId',
           'mainPid','mainStartTicks','cgroupDevice','cgroupInode','parentDevice','parentInode',
           'pidNamespaceDevice','pidNamespaceInode'}


def reject():
    raise ValueError('compose-cold-writer-v3-rejected') from None


def _left(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        reject()
    return left


def _file(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, limit + 1)
        if len(raw) > limit:
            reject()
        return raw.decode('ascii')
    finally:
        os.close(fd)


def pid_namespace():
    raw = _file(PROC / 'self' / 'stat')
    if raw.split(' ', 1)[0] != str(os.getpid()):
        reject()
    value = os.stat(PROC / 'self' / 'ns' / 'pid')
    namespace = value.st_dev, value.st_ino
    if process_pid_namespace(1) != namespace:
        reject()
    return namespace


def process_pid_namespace(pid):
    if type(pid) is not int or not 0 < pid < 2**31:
        reject()
    value = os.stat(PROC / str(pid) / 'ns' / 'pid')
    return value.st_dev, value.st_ino


def validate_origin(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ORIGIN:
        reject()
    value = decode(raw)
    if (type(value) is not dict or set(value) != _FIELDS or type(value['schemaVersion']) is not int
            or value['schemaVersion'] != 1 or value['kind'] != 'compose-owned-writer-origin-v3'):
        reject()
    for name, pattern in (('sourceSha','[0-9a-f]{40}'),('archiveDigest','[0-9a-f]{64}'),
                          ('unit','dw-writer-host-[0-9a-f]{16}\\.service'),
                          ('kernelBoot','[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}'),
                          ('invocationId','[0-9a-f]{32}')):
        if type(value[name]) is not str or re.fullmatch(pattern, value[name]) is None:
            reject()
    for name in _FIELDS - {'schemaVersion','kind','sourceSha','archiveDigest','unit','kernelBoot','invocationId'}:
        if type(value[name]) is not int or not 0 <= value[name] < 2**64:
            reject()
        if not name.endswith('Device') and value[name] == 0:
            reject()
    if value['mainPid'] >= 2**31:
        reject()
    return value


def _state(unit, deadline):
    result = subprocess.run(['/usr/bin/systemctl','--system','show',unit,'--all',
        '--property='+','.join(units.PROPERTIES)], capture_output=True,
        timeout=min(5, _left(deadline)), env={}, check=False)
    if len(result.stdout) > 16384 or len(result.stderr) > 16384:
        reject()
    value = {}
    for line in result.stdout.decode('ascii').splitlines():
        key, content = line.split('=', 1)
        if key in value:
            reject()
        value[key] = content
    if set(value) != set(units.PROPERTIES) or result.returncode and value['LoadState'] != 'not-found':
        reject()
    return value


def _tree(fd, deadline, budget, depth=0):
    _left(deadline)
    budget[0] += 1
    if depth > 16 or budget[0] > 128:
        reject()
    before = os.fstat(fd)
    names = sorted(os.listdir(fd))
    if len(names) > 256:
        reject()
    data, children = {}, []
    for name in names:
        _left(deadline)
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            reject()
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if (os.fstat(child).st_dev, os.fstat(child).st_ino) != (info.st_dev, info.st_ino):
                    reject()
                children.append((name, _tree(child, deadline, budget, depth + 1)))
            finally:
                os.close(child)
            again = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (again.st_dev, again.st_ino) != (info.st_dev, info.st_ino):
                reject()
        elif name in ('cgroup.type','cgroup.events','cgroup.procs'):
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                opened = os.fstat(file)
                if (opened.st_dev,opened.st_ino) != (info.st_dev,info.st_ino):
                    reject()
                raw = os.read(file, 65537)
                budget[1] += len(raw)
                if len(raw) > 65536 or budget[1] > 1024 * 1024:
                    reject()
                data[name] = raw.decode('ascii')
                again = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if (again.st_dev,again.st_ino) != (info.st_dev,info.st_ino):
                    reject()
            finally:
                os.close(file)
    if (set(data) != {'cgroup.type','cgroup.events','cgroup.procs'} or data['cgroup.type'].strip() != 'domain'
            or data['cgroup.procs'].strip() or units.events(data['cgroup.events'])['populated'] != 0
            or sorted(os.listdir(fd)) != names):
        reject()
    after = os.fstat(fd)
    if (before.st_dev,before.st_ino) != (after.st_dev,after.st_ino):
        reject()
    return dict(device=before.st_dev, inode=before.st_ino, files=data, children=children)


def _observe(value, deadline):
    _left(deadline)
    namespace = pid_namespace()
    if namespace != (value['pidNamespaceDevice'],value['pidNamespaceInode']) or units._boot() != value['kernelBoot']:
        reject()
    try:
        os.stat(PROC / str(value['mainPid']), follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        reject()
    state = _state(value['unit'], deadline)
    group = '/system.slice/' + value['unit']
    if state['LoadState'] == 'not-found' and state['SubState'] != 'dead':
        reject()
    if not units.OwnedRecoveryUnitV3._absent(state):
        if (state['LoadState'] != 'loaded' or state['ActiveState'] not in ('inactive','failed')
                or state['SubState'] not in ('dead','failed')
                or state['MainPID'] != '0' or state['InvocationID'] not in ('',value['invocationId'])
                or state['ControlGroup'] not in ('',group)):
            reject()
    root = os.open(units.CGROUP, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent = os.open('system.slice', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    finally:
        os.close(root)
    try:
        info = os.fstat(parent)
        if (info.st_dev,info.st_ino) != (value['parentDevice'],value['parentInode']):
            reject()
        try:
            fd = os.open(value['unit'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            tree = None
        else:
            try:
                current = os.fstat(fd)
                if (current.st_dev,current.st_ino) != (value['cgroupDevice'],value['cgroupInode']):
                    reject()
                tree = _tree(fd, deadline, [0,0])
                current = os.stat(value['unit'], dir_fd=parent, follow_symlinks=False)
                if (current.st_dev,current.st_ino) != (value['cgroupDevice'],value['cgroupInode']):
                    reject()
            finally:
                os.close(fd)
        fresh = os.stat(units.CGROUP / 'system.slice', follow_symlinks=False)
        if (fresh.st_dev,fresh.st_ino) != (info.st_dev,info.st_ino):
            reject()
    finally:
        os.close(parent)
    if pid_namespace() != namespace or units._boot() != value['kernelBoot']:
        reject()
    try:
        os.stat(PROC / str(value['mainPid']), follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        reject()
    _left(deadline)
    return dict(namespace=list(namespace), boot=value['kernelBoot'], unit=state, tree=tree)


@dataclass(frozen=True)
class StoppedWriterObservationV3:
    origin_digest: str
    observation_digest: str
    observations: bytes = field(repr=False)
    writerStoppedObserved: bool = field(default=True,init=False)
    daemonStoppedVerified: bool = field(default=False,init=False)
    historyFreshnessVerified: bool = field(default=False,init=False)
    linuxQuiescenceVerified: bool = field(default=False,init=False)
    authorityGranted: bool = field(default=False,init=False)
    runtimePermit: bool = field(default=False,init=False)
    recoveryAuthorized: bool = field(default=False,init=False)
    productionReady: bool = field(default=False,init=False)

    def public_summary(self):
        return {key:getattr(self,key) for key in ('origin_digest','observation_digest','writerStoppedObserved',
            'daemonStoppedVerified','historyFreshnessVerified','linuxQuiescenceVerified','authorityGranted',
            'runtimePermit','recoveryAuthorized','productionReady')}


def observe_stopped_writer(origin, *, expected_digest, expected_source_sha, expected_archive_digest, timeout=5):
    try:
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            reject()
        deadline = time.monotonic() + timeout
        units._environment()
        value = validate_origin(origin)
        if (type(expected_digest) is not str or type(expected_source_sha) is not str
                or type(expected_archive_digest) is not str or hashlib.sha256(origin).hexdigest() != expected_digest
                or value['sourceSha'] != expected_source_sha or value['archiveDigest'] != expected_archive_digest):
            reject()
        first = _observe(value, deadline)
        second = _observe(value, deadline)
        if first != second:
            reject()
        raw = canonical([first,second])
        result = StoppedWriterObservationV3(expected_digest,hashlib.sha256(raw).hexdigest(),raw)
        _left(deadline)
        return result
    except Exception:
        reject()
