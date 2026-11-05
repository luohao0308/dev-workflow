"""Assemble host-bound private observations; no freshness or execution authority.

Identity, artifact, topology and keys must come independently from the host, not
from imported snapshot JSON. This checks authenticated value coherence only.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import hmac
import json
import re

from deployment_compose_artifacts import ServiceArtifact
from deployment_compose_config import CONTEXT, map_config
from deployment_compose_host_config import map_host_config
from deployment_compose_network import map_network_settings
from deployment_compose_private import MOUNT, commit as private_commit
from deployment_compose_recipe import HEX, NAME

DOMAIN = b'dev-workflow:compose-observed-snapshot:v1\0'
MAX_BYTES = 256 * 1024
IDENTITY = CONTEXT | {'hostId', 'daemonId', 'requestedApiVersion', 'engineVersion'}


def _fail():
    raise ValueError('invalid-compose-observed-snapshot')


def _encode(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                         allow_nan=False).encode('ascii')
    except (TypeError, ValueError, RecursionError, UnicodeError):
        _fail()
    if len(raw) > MAX_BYTES:
        _fail()
    return raw


def _path(value):
    return (type(value) is str and value.startswith('/') and len(value) <= 4096
            and '\0' not in value and all(x not in ('.', '..') for x in value.split('/')))


def prepare_snapshot(inspected, identity, artifact, private_key, network_ids, expected_mounts):
    """Match all surfaces to independently pinned identity, artifact and topology."""
    try:
        return _prepare(inspected, identity, artifact, private_key, network_ids, expected_mounts)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        _fail()


def _prepare(raw, identity, artifact, private_key, network_ids, expected_mounts):
    if (type(identity) is not dict or set(identity) != IDENTITY
            or type(artifact) is not ServiceArtifact or artifact.os != 'linux'
            or artifact.migration_mode != 'none'
            or type(identity['hostId']) is not str or not NAME.fullmatch(identity['hostId'])
            or type(identity['daemonId']) is not str
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}', identity['daemonId'])
            or type(identity['requestedApiVersion']) is not str or identity['requestedApiVersion'] != '1.45'
            or type(identity['engineVersion']) is not str or len(identity['engineVersion']) > 128
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?', identity['engineVersion'])):
        _fail()
    if type(raw) is not dict or set(raw) != {'Id', 'Name', 'Image', 'Config', 'HostConfig', 'NetworkSettings', 'Mounts'}:
        _fail()
    context = {k: identity[k] for k in CONTEXT}
    config = map_config(raw['Config'], context)
    host = map_host_config(raw['HostConfig'], context)
    network = map_network_settings(raw['NetworkSettings'], context)
    if (raw['Id'] != context['containerId'] or raw['Name'] != '/' + context['containerName']
            or raw['Image'] != context['imageId'] or artifact.service != context['service']
            or artifact.image_id != context['imageId']):
        _fail()
    endpoints = raw['NetworkSettings']['Networks']
    if (type(network_ids) is not dict or set(network_ids) != set(endpoints)
            or any(type(v) is not str or not HEX.fullmatch(v) for v in network_ids.values())
            or len(set(network_ids.values())) != len(network_ids)
            or any(endpoints[k]['NetworkID'] != v for k, v in network_ids.items())
            or raw['HostConfig']['NetworkMode'] not in (*network_ids, *network_ids.values())):
        _fail()
    if type(expected_mounts) is not dict or len(expected_mounts) > 32:
        _fail()
    for destination, mount in expected_mounts.items():
        if (not _path(destination) or type(mount) is not dict
                or set(mount) != {'type', 'source', 'readOnly'}
                or mount['type'] not in ('bind', 'volume') or type(mount['readOnly']) is not bool
                or type(mount['source']) is not str):
            _fail()
        if mount['type'] == 'bind' and (not _path(mount['source']) or mount['readOnly'] is not True):
            _fail()
        if mount['type'] == 'volume' and not NAME.fullmatch(mount['source']):
            _fail()
    mounts = raw['Mounts']
    if type(mounts) is not list or len(mounts) != len(expected_mounts):
        _fail()
    actual = {}
    for mount in mounts:
        if type(mount) is not dict or type(mount.get('RW')) is not bool:
            _fail()
        if (not {'Type', 'Source', 'Destination', 'RW', 'Mode', 'Propagation'} <= set(mount)
                or set(mount) - MOUNT or not _path(mount['Source']) or not _path(mount['Destination'])
                or mount['Destination'] in actual):
            _fail()
        if mount['Type'] == 'volume':
            if mount.get('Driver') != 'local' or type(mount.get('Name')) is not str or not NAME.fullmatch(mount['Name']):
                _fail()
            source = mount['Name']
        elif mount['Type'] == 'bind':
            if mount.get('Name') not in ('', None) or mount.get('Driver') not in ('', None):
                _fail()
            source = mount['Source']
        else:
            _fail()
        if (type(mount['Mode']) is not str or type(mount['Propagation']) is not str
                or len(mount['Mode']) > 128 or len(mount['Propagation']) > 128):
            _fail()
        actual[mount['Destination']] = {'type': mount['Type'], 'source': source, 'readOnly': not mount['RW']}
    if _encode(actual) != _encode(expected_mounts) or raw['HostConfig']['Binds'] not in (None, []):
        _fail()
    declared = raw['HostConfig'].get('Mounts')
    declared = [] if declared is None else declared
    if len(declared) != len(actual):
        _fail()
    seen = set()
    for mount in declared:
        target = mount['Target']
        if target not in actual or target in seen:
            _fail()
        seen.add(target)
        resolved = actual[target]
        if mount['Type'] != resolved['type'] or mount['Source'] != resolved['source']:
            _fail()
        if 'ReadOnly' not in mount and resolved['readOnly']:
            _fail()
        if 'ReadOnly' in mount and mount['ReadOnly'] is not resolved['readOnly']:
            _fail()
        if mount['Type'] == 'bind' and mount.get('ReadOnly') is not True:
            _fail()
        if mount['Type'] == 'volume' and mount.get('VolumeOptions', {}).get('NoCopy') is not True:
            _fail()
    # HostConfig mapper supports no explicit port publication; do not accept
    # contradictory runtime bindings or an automatic publish request.
    ports = raw['NetworkSettings']['Ports']
    exposed = raw['Config'].get('ExposedPorts')
    if raw['HostConfig']['PublishAllPorts'] is not False:
        _fail()
    if ports is not None and (any(bindings for bindings in ports.values())
            or not set(ports).issubset(exposed if exposed is not None else {})):
        _fail()
    if set(raw['HostConfig']['Tmpfs']) & set(actual):
        _fail()
    projection = {'Config': raw['Config'], 'HostConfig': raw['HostConfig'],
                  'NetworkSettings': raw['NetworkSettings'],
                  'Mounts': [{**m, **{k: m.get(k) for k in MOUNT}} for m in mounts]}
    proof = private_commit(context['project'], context['service'], projection,
                           artifact.config_key_id, private_key)
    if not hmac.compare_digest(proof['configHmac'], artifact.config_hmac):
        _fail()
    if (_encode(config['rawConfig']) != _encode(raw['Config'])
            or _encode(host['rawHostConfig']) != _encode(raw['HostConfig'])
            or _encode(network['rawNetworkSettings']) != _encode(raw['NetworkSettings'])):
        _fail()
    result = {'schemaVersion': 1, 'identity': identity, 'artifact': asdict(artifact),
              'config': config, 'hostConfig': host, 'networkSettings': network,
              'mounts': mounts, 'networkIds': network_ids, 'expectedMounts': expected_mounts,
              'authorityGranted': False, 'executionAvailable': False, 'reconstructionValidated': False}
    _encode(result)
    return deepcopy(result)


def commit_snapshot(inspected, identity, artifact, private_key, network_ids, expected_mounts, *, key_id, key):
    """Revalidate original private HMAC before sealing the combined observation."""
    if type(key_id) is not str or not NAME.fullmatch(key_id) or type(key) is not bytes or len(key) < 32:
        _fail()
    snapshot = prepare_snapshot(inspected, identity, artifact, private_key, network_ids, expected_mounts)
    encoded = key_id.encode('ascii')
    return {'keyId': key_id, 'hmac': hmac.new(key, DOMAIN + len(encoded).to_bytes(2, 'big')
                      + encoded + _encode(snapshot), hashlib.sha256).hexdigest()}
