#!/usr/bin/env python3
"""Read-only local Linux startup evidence; never proves effective create defaults.

stdout is PRIVATE JSON (startup arguments and selected daemon configuration).
Run through a host-controlled channel and retain it outside the repository.
No configuration reload, Docker mutation, or authorization is performed.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

LIMIT = 1024 * 1024
CONFIG_KEYS = ('log-driver', 'log-opts', 'default-runtime', 'default-shm-size',
               'default-ulimits', 'default-address-pools', 'features',
               'icc', 'ip-forward', 'iptables', 'ip6tables', 'userns-remap')


def fail():
    raise ValueError('compose-daemon-sample-rejected')


def bounded(path):
    with path.open('rb') as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        fail()
    return raw


def config_path(argv):
    """Resolve the Linux rootful default or one explicit config flag only."""
    paths = []
    for index, arg in enumerate(argv[1:], 1):
        if arg == '--config-file':
            if index + 1 >= len(argv) or argv[index + 1].startswith('-'):
                fail()
            paths.append(argv[index + 1])
        elif arg.startswith('--config-file='):
            paths.append(arg.partition('=')[2])
    if len(paths) > 1:
        fail()
    path = paths[0] if paths else '/etc/docker/daemon.json'
    if not path.startswith('/') or '\0' in path:
        fail()
    return path, bool(paths)


def read_info():
    env = dict(os.environ, DOCKER_API_VERSION='1.45')
    # Never pair local /proc evidence with a remote/context-selected daemon.
    for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        env.pop(name, None)
    result = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock',
        'info', '--format', '{{json .}}'], env=env, capture_output=True,
        timeout=15, check=True)
    if len(result.stdout) > LIMIT:
        fail()
    info = json.loads(result.stdout)
    if (type(info) is not dict or info.get('OSType') != 'linux'
            or not isinstance(info.get('ID'), str) or not info['ID']):
        fail()
    return {key: info.get(key) for key in ('ID', 'OSType', 'ServerVersion',
        'LoggingDriver', 'DefaultRuntime', 'CgroupDriver', 'CgroupVersion', 'SecurityOptions')}


def read_config(path, explicit):
    try:
        stream = path.open('rb')
    except FileNotFoundError:
        if explicit:
            fail()
        return None, None, None
    def identity(stat):
        return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]
    with stream:
        before = identity(os.fstat(stream.fileno()))
        raw = stream.read(LIMIT + 1)
        if (len(raw) > LIMIT or before != identity(os.fstat(stream.fileno()))
                or before != identity(path.stat())):
            fail()
    value = json.loads(raw)
    if type(value) is not dict:
        fail()
    return {key: value[key] for key in CONFIG_KEYS if key in value}, before, raw


def snapshot(proc=Path('/proc')):
    processes = []
    for path in proc.iterdir():
        if not path.name.isdigit():
            continue
        try:
            if bounded(path / 'comm').strip() == b'dockerd':
                processes.append(path)
        except FileNotFoundError:
            continue
    if len(processes) != 1:
        fail()
    path = processes[0]
    argv = bounded(path / 'cmdline').decode('utf-8').split('\0')
    if not argv or argv[-1] != '':
        fail()
    argv.pop()
    if not argv or not argv[0]:
        fail()
    # Rootless startup/config discovery is a different unsupported profile.
    status = bounded(path / 'status').decode('utf-8').splitlines()
    uid = [line.split()[1:] for line in status if line.startswith('Uid:')]
    if uid != [['0', '0', '0', '0']]:
        fail()
    config, explicit = config_path(argv)
    selected, config_identity, raw = read_config(Path(config), explicit)
    return {'pid': path.name, 'processStat': bounded(path / 'stat').decode('utf-8'),
        'bootId': bounded(proc / 'sys/kernel/random/boot_id').decode('ascii').strip(),
        'argv': argv, 'configPath': config, 'configExplicit': explicit,
        'configFileIdentity': config_identity, 'selectedConfig': selected,
        'configFileDigest': hashlib.sha256(raw).hexdigest() if raw is not None else None,
        'info': read_info()}


def stable_identity(value):
    result = dict(value)
    # /proc stat contains changing CPU counters. Start time follows 19 fields
    # after comm, whose embedded spaces/parentheses must not shift parsing.
    stat = result.pop('processStat')
    end = stat.rfind(')')
    fields = stat[end + 2:].split()
    if end < 0 or len(fields) < 20:
        fail()
    result['processStartTicks'] = fields[19]
    return result


def capture(read=snapshot):
    first, second = read(), read()
    if stable_identity(first) != stable_identity(second):
        fail()
    report = {'schemaVersion': 1, 'kind': 'compose-daemon-startup-diagnostic',
        'stableTwoRoundRead': True, 'localSocketPinned': True,
        'rootfulSingleProcessObserved': True,
        'configFileObserved': second['selectedConfig'] is not None,
        'explicitConfigPathObserved': second['configExplicit'],
        'configuredKeysPresent': sorted(second['selectedConfig'] or {}),
        'engineVersion': second['info']['ServerVersion'],
        'processSocketAssociationVerified': False,
        'effectiveDefaultsVerified': False, 'authorityGranted': False,
        'executionAvailable': False, 'productionReady': False}
    return {'samples': [first, second], 'report': report}


if __name__ == '__main__':
    try:
        if sys.platform != 'linux':
            fail()
        print(json.dumps(capture(), sort_keys=True, allow_nan=False))
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, KeyError, TypeError):
        print('compose-daemon-sample-rejected', file=sys.stderr)
        sys.exit(1)
