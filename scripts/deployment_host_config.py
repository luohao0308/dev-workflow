"""Explicit distribution-owned host configuration. Loading never initializes authority."""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
from pathlib import Path
DISTRIBUTION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DISTRIBUTION / 'packs/deployment/scripts'))
import json
import os
import stat
import re
from dataclasses import dataclass
from types import MappingProxyType
from deployment_runtime import RuntimePolicy, digest
from deployment_execute import ExecutionPolicy
from deployment_verify import ProbePolicy
from deployment_store import StorePolicy
from deployment_gateway import GatePolicy
from deployment_host import DeploymentHostPolicy
from deployment_recovery_host import RecoveryHostPolicy

class ConfigurationError(ValueError):
    pass

def _deny():
    raise ConfigurationError('invalid-host-configuration')

def _path(value):
    if type(value) is not str or not Path(value).is_absolute() or '..' in Path(value).parts:
        _deny()
    path = Path(value)
    for part in (path, *path.parents):
        try:
            st = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
            _deny()
    return path

def read_private_bytes(path, *, maximum, minimum=0):
    path = _path(str(path))
    descriptors = []
    try:
        # Walk from the filesystem root through open directory handles. A rename
        # cannot redirect later opens through a newly substituted symlink.
        if os.name == 'nt':
            raise ConfigurationError('private-acl-unverified')
        parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(parent)
        for component in path.parts[1:-1]:
            parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            actual = os.fstat(stream.fileno())
            if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
                    or actual.st_uid != os.getuid() or actual.st_mode & 0o077):
                _deny()
            raw = stream.read(maximum + 1)
            after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns):
                _deny()
        # Reject path replacement as well as symlink substitution during the read.
        _path(str(path))
        final = path.lstat()
        if (final.st_dev, final.st_ino) != (actual.st_dev, actual.st_ino):
            _deny()
        if not minimum <= len(raw) <= maximum:
            _deny()
        return raw
    except OSError:
        _deny()
    finally:
        for fd in reversed(descriptors):
            os.close(fd)

def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _deny()
        result[key] = value
    return result

@dataclass(frozen=True, repr=False)
class HostConfiguration:
    runtime_policy: RuntimePolicy
    execution_policy: ExecutionPolicy
    probe_policy: ProbePolicy | None
    store_policy: StorePolicy
    gate_policy: GatePolicy
    candidate_root: Path
    store_root: Path
    gate_root: Path
    store_key_file: Path
    gate_key_file: Path
    ca_file: Path
    reader_cert_file: Path
    reader_key_file: Path
    writer_cert_file: Path
    writer_key_file: Path
    github: object
    distribution_commit: str

PATHS = ('candidate_root', 'store_root', 'gate_root', 'store_key_file', 'gate_key_file', 'ca_file', 'reader_cert_file', 'reader_key_file', 'writer_cert_file', 'writer_key_file')

def load_host_config(path):
    try:
        data = json.loads(read_private_bytes(path, maximum=1024*1024), object_pairs_hook=_pairs, parse_constant=lambda _: _deny())
        if type(data) is not dict or set(data) != set(PATHS) | {'schemaVersion', 'runtime', 'execution', 'probe', 'store', 'gate', 'github', 'distribution_commit'} or type(data['schemaVersion']) is not int or data['schemaVersion'] != 1:
            _deny()
        paths = {key: _path(data[key]) for key in PATHS}
        roots = [paths[x] for x in ('candidate_root', 'store_root', 'gate_root')] + [DISTRIBUTION]
        for index, left in enumerate(roots):
            for right in roots[index+1:]:
                if left == right or left in right.parents or right in left.parents:
                    _deny()
        if not re.fullmatch('[0-9a-f]{40}', data['distribution_commit']):
            _deny()
        r = dict(data['runtime']); r['components'] = tuple(r['components'])
        runtime = RuntimePolicy(**r)
        store = StorePolicy(runtime_policy=runtime, **data['store'])
        gate = GatePolicy(**data['gate'])
        probe = None if data['probe'] is None else ProbePolicy(**data['probe'])
        execution = ExecutionPolicy(runtime_policy=runtime, **data['execution'])
        if (gate.store_id != store.store_id or gate.key_id != store.key_id or gate.scope_hash != digest(store._scope()) or execution.history_policy_hash != store.identity_hash() or execution.gateway_policy_hash != gate.identity_hash() or execution.writer_certificate_sha256 != gate.writer_certificate_sha256 or execution.verification_policy_hash != (probe.identity_hash() if probe else None) or (probe and probe.runtime_policy_hash != runtime.identity_hash())):
            _deny()
        github = dict(data['github'])
        credential = _path(github.pop('credential_file'))
        environments = {name: github.pop(name) for name in ('deploy_approval_environment', 'rollback_approval_environment', 'recovery_approval_environment')}
        github['reviewer_ids'] = tuple(github['reviewer_ids'])
        common = dict(github, target_repository=runtime.repository, target_repository_id=store.repository_id,
                      deployment_environment=runtime.environment, deployment_target=runtime.target,
                      production=runtime.production, runtime_policy_hash=runtime.identity_hash(),
                      allowed_components=runtime.components, execution_policy_hash=execution.identity_hash())
        deployment = DeploymentHostPolicy(**common, approval_environment=environments['deploy_approval_environment'])
        rollback = DeploymentHostPolicy(**common, approval_environment=environments['rollback_approval_environment'])
        recovery = RecoveryHostPolicy(**common, approval_environment=environments['recovery_approval_environment'],
                                      store_policy_hash=store.identity_hash(), gate_policy_hash=gate.identity_hash())
        github = dict(github, **environments, credential_file=credential,
                      deployment_policy=deployment, rollback_policy=rollback, recovery_policy=recovery)
        return HostConfiguration(runtime, execution, probe, store, gate, **paths, github=MappingProxyType(github), distribution_commit=data['distribution_commit'])
    except ConfigurationError:
        raise
    except Exception:
        raise ConfigurationError('invalid-host-configuration') from None
