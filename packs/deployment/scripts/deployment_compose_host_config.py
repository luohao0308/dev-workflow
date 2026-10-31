"""Exact private HostConfig observations; no create semantics or write authority.

Only the observed field tree is accepted. Non-observed complex structures fail
closed rather than inferring support. Values returned here can contain secrets.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json

from deployment_compose_recipe import HEX, IMAGE, MAX_BYTES, NAME

DOMAIN = b'dev-workflow:compose-observed-host-config:v1\0'
CONTEXT = {'project', 'service', 'containerId', 'containerName', 'imageId'}
BOOLS = set('AutoRemove Privileged PublishAllPorts ReadonlyRootfs'.split())
STRINGS = set('Cgroup CgroupParent CgroupnsMode ContainerIDFile CpusetCpus CpusetMems IpcMode Isolation NetworkMode PidMode Runtime UTSMode UsernsMode VolumeDriver'.split())
INTS = set('BlkioWeight CpuCount CpuPercent CpuPeriod CpuQuota CpuRealtimePeriod CpuRealtimeRuntime CpuShares IOMaximumBandwidth IOMaximumIOps Memory MemoryReservation MemorySwap NanoCpus OomScoreAdj ShmSize'.split())
VECTORS = set('Binds CapAdd CapDrop DeviceCgroupRules Dns DnsOptions DnsSearch ExtraHosts GroupAdd Links MaskedPaths ReadonlyPaths SecurityOpt VolumesFrom'.split())
NULLS = set('BlkioDeviceReadBps BlkioDeviceReadIOps BlkioDeviceWriteBps BlkioDeviceWriteIOps BlkioWeightDevice DeviceRequests Devices Ulimits'.split())
REQUIRED = BOOLS | STRINGS | INTS | VECTORS | NULLS | {'ConsoleSize', 'LogConfig', 'MemorySwappiness', 'OomKillDisable', 'PidsLimit', 'PortBindings', 'RestartPolicy', 'Tmpfs'}


def _fail():
    raise ValueError('invalid-compose-observed-host-config')


def _string(v):
    return type(v) is str and len(v) <= 8192 and '\0' not in v


def _integer(v):
    return type(v) is int and -(2**63) <= v < 2**63


def _vector(v):
    return v is None or (type(v) is list and len(v) <= 128 and all(_string(x) for x in v))


def _strings(v):
    return type(v) is dict and len(v) <= 128 and all(_string(k) and k and _string(x) for k, x in v.items())


def _encode(v):
    try:
        raw = json.dumps(v, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail()
    if len(raw) > MAX_BYTES:
        _fail()
    return raw


def _mount(v):
    if (type(v) is not dict or not {'Type', 'Source', 'Target'} <= set(v)
            or set(v) - {'Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions', 'BindOptions'}
            or any(not _string(v[k]) for k in ('Type', 'Source', 'Target'))
            or v['Type'] not in ('volume', 'bind')):
        _fail()
    if 'ReadOnly' in v and type(v['ReadOnly']) is not bool:
        _fail()
    if 'VolumeOptions' in v:
        o = v['VolumeOptions']
        if v['Type'] != 'volume' or type(o) is not dict or set(o) != {'NoCopy'} or type(o['NoCopy']) is not bool:
            _fail()
    if 'BindOptions' in v and (v['Type'] != 'bind' or type(v['BindOptions']) is not dict or v['BindOptions'] != {}):
        _fail()


def map_host_config(raw_host_config: object, context: object) -> dict:
    """Snapshot bounded exact observations, retaining absent/null/list distinctions."""
    if type(context) is not dict or set(context) != CONTEXT:
        _fail()
    for k in ('project', 'service', 'containerName'):
        if type(context[k]) is not str or not NAME.fullmatch(context[k]):
            _fail()
    if (type(context['containerId']) is not str or not HEX.fullmatch(context['containerId'])
            or type(context['imageId']) is not str or not IMAGE.fullmatch(context['imageId'])):
        _fail()
    h = raw_host_config
    if type(h) is not dict or not REQUIRED <= set(h) or set(h) - REQUIRED - {'Mounts'}:
        _fail()
    if (any(type(h[k]) is not bool for k in BOOLS)
            or any(not _string(h[k]) for k in STRINGS)
            or any(not _integer(h[k]) for k in INTS)
            or any(not _vector(h[k]) for k in VECTORS)
            or any(h[k] is not None for k in NULLS)):
        _fail()
    if type(h['ConsoleSize']) is not list or len(h['ConsoleSize']) != 2 or any(not _integer(x) for x in h['ConsoleSize']):
        _fail()
    for k in ('MemorySwappiness', 'PidsLimit'):
        if h[k] is not None and not _integer(h[k]):
            _fail()
    if h['OomKillDisable'] is not None and type(h['OomKillDisable']) is not bool:
        _fail()
    log = h['LogConfig']
    if type(log) is not dict or set(log) != {'Config', 'Type'} or not _string(log['Type']) or not _strings(log['Config']):
        _fail()
    restart = h['RestartPolicy']
    if (type(restart) is not dict or set(restart) != {'Name', 'MaximumRetryCount'}
            or not _string(restart['Name']) or not _integer(restart['MaximumRetryCount'])):
        _fail()
    # The sample has no published ports. Preserve that observation only.
    if type(h['PortBindings']) is not dict or h['PortBindings'] != {} or not _strings(h['Tmpfs']):
        _fail()
    if 'Mounts' in h and h['Mounts'] is not None:
        if type(h['Mounts']) is not list or len(h['Mounts']) > 128:
            _fail()
        for mount in h['Mounts']:
            _mount(mount)
    value = {'schemaVersion': 1, 'authorityGranted': False, 'executionAvailable': False,
             'reconstructionValidated': False, 'context': context, 'rawHostConfig': h}
    _encode(value)
    return copy.deepcopy(value)


def canonical_host_config(mapping: object) -> bytes:
    if (type(mapping) is not dict or set(mapping) != {'schemaVersion', 'authorityGranted', 'executionAvailable', 'reconstructionValidated', 'context', 'rawHostConfig'}
            or type(mapping['schemaVersion']) is not int or mapping['schemaVersion'] != 1
            or any(mapping[k] is not False for k in ('authorityGranted', 'executionAvailable', 'reconstructionValidated'))):
        _fail()
    return _encode(map_host_config(mapping['rawHostConfig'], mapping['context']))


def commit_host_config(mapping: object, key_id: str, key: bytes) -> dict[str, str]:
    if type(key_id) is not str or not NAME.fullmatch(key_id) or type(key) is not bytes or len(key) < 32:
        _fail()
    identity = key_id.encode('ascii')
    digest = hmac.new(key, DOMAIN + len(identity).to_bytes(2, 'big') + identity + canonical_host_config(mapping), hashlib.sha256).hexdigest()
    return {'keyId': key_id, 'hmac': digest}


def verify_host_config(mapping: object, commitment: object, key: bytes) -> bool:
    if (type(commitment) is not dict or set(commitment) != {'keyId', 'hmac'}
            or type(commitment['hmac']) is not str or not HEX.fullmatch(commitment['hmac'])):
        _fail()
    return hmac.compare_digest(commit_host_config(mapping, commitment['keyId'], key)['hmac'], commitment['hmac'])
