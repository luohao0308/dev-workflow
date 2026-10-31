"""Host-private Compose target recipe commitment; this module grants no authority.

The schema is a deliberately narrow value contract, not a Docker Engine create
payload. In particular, a matching commitment does not prove that the host can
run the recipe or that its image and filesystem contents are trustworthy.
Recipe schema v2 explicitly represents the none logging driver; schema v1
commitments are not accepted as v2 recipes. This profile accepts exec-form health checks only (CMD); CMD-SHELL is
unsupported pending separate trust and Engine compatibility tests.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re


DOMAIN = b'dev-workflow:compose-target-recipe:v2\0'
MAX_BYTES = 65536
NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z')


def _fail() -> None:
    # Never include caller-controlled material: recipes may contain secrets.
    raise ValueError('invalid-compose-target-recipe')


def _fields(value: object, names: set[str]) -> dict:
    if type(value) is not dict or set(value) != names:
        _fail()
    return value


def _string(value: object, limit: int = 4096) -> bool:
    return type(value) is str and 0 < len(value) <= limit and '\0' not in value


def _path(value: object) -> bool:
    return (_string(value, 1024) and value.startswith('/') and value != '/'
            and all(part not in ('', '.', '..') for part in value[1:].split('/')))


def _strings(value: object, limit: int, max_items: int) -> bool:
    return type(value) is list and len(value) <= max_items and all(_string(x, limit) for x in value)


def canonical_recipe(recipe: object) -> bytes:
    """Validate and canonicalize a private value; never log the returned bytes."""
    value = _fields(recipe, {'schemaVersion', 'project', 'service', 'containerName',
                             'imageId', 'process', 'hostConfig', 'mounts',
                             'networks', 'ports', 'health'})
    if type(value['schemaVersion']) is not int or value['schemaVersion'] != 2:
        _fail()
    if any(type(value[k]) is not str or not NAME.fullmatch(value[k])
           for k in ('project', 'service', 'containerName')):
        _fail()
    if type(value['imageId']) is not str or not IMAGE.fullmatch(value['imageId']):
        _fail()
    process = _fields(value['process'], {'user', 'workingDir', 'entrypoint', 'cmd', 'env'})
    if ((process['user'] != '' and not _string(process['user'], 128))
            or (process['workingDir'] != '' and not _path(process['workingDir']))
            or not _strings(process['entrypoint'], 1024, 32)
            or not _strings(process['cmd'], 1024, 64)
            or not _strings(process['env'], 8192, 128)):
        _fail()
    env_names = []
    for item in process['env']:
        key, separator, _ = item.partition('=')
        if separator != '=' or not ENV_NAME.fullmatch(key):
            _fail()
        env_names.append(key)
    if len(env_names) != len(set(env_names)) or env_names != sorted(env_names):
        _fail()
    host = _fields(value['hostConfig'], {'privileged', 'readOnlyRootfs', 'capAdd',
                                          'devices', 'pidMode', 'ipcMode', 'logConfig'})
    if (host['privileged'] is not False or type(host['readOnlyRootfs']) is not bool
            or host['capAdd'] != [] or host['devices'] != []
            or host['pidMode'] != 'private' or host['ipcMode'] != 'private'):
        _fail()
    # Explicit logging avoids treating omitted daemon defaults as equivalent.
    # First comparator supports the none driver only; json-file needs its own
    # complete option/default contract before it may be recreated.
    log = _fields(host['logConfig'], {'type', 'config'})
    if log['type'] != 'none' or type(log['config']) is not dict or log['config'] != {}:
        _fail()
    mounts = value['mounts']
    if type(mounts) is not list or len(mounts) > 32:
        _fail()
    targets = []
    for mount in mounts:
        m = _fields(mount, {'type', 'source', 'target', 'readOnly', 'noCopy', 'createHostPath'})
        if not _path(m['target']) or not _string(m['source'], 1024):
            _fail()
        if m['type'] == 'volume':
            if (not NAME.fullmatch(m['source']) or type(m['readOnly']) is not bool
                    or m['noCopy'] is not True or m['createHostPath'] is not False):
                _fail()
        elif m['type'] == 'bind':
            if (not _path(m['source']) or m['readOnly'] is not True
                    or m['noCopy'] is not False or m['createHostPath'] is not False):
                _fail()
        else:
            _fail()
        targets.append(m['target'])
    if targets != sorted(set(targets)):
        _fail()
    networks = value['networks']
    if type(networks) is not list or not 1 <= len(networks) <= 8:
        _fail()
    network_ids = []
    for network in networks:
        n = _fields(network, {'id', 'aliases'})
        if type(n['id']) is not str or not HEX.fullmatch(n['id']):
            _fail()
        aliases = n['aliases']
        if (type(aliases) is not list or not 1 <= len(aliases) <= 16
                or any(type(a) is not str or not NAME.fullmatch(a) for a in aliases)
                or aliases != sorted(set(aliases))):
            _fail()
        network_ids.append(n['id'])
    if network_ids != sorted(set(network_ids)):
        _fail()
    ports = value['ports']
    if type(ports) is not list or len(ports) > 32:
        _fail()
    port_keys = []
    host_bindings = []
    for port in ports:
        p = _fields(port, {'hostIp', 'hostPort', 'containerPort', 'protocol'})
        if (p['hostIp'] not in ('127.0.0.1', '0.0.0.0')
                or type(p['hostPort']) is not int or not 1024 <= p['hostPort'] <= 65535
                or type(p['containerPort']) is not int or not 1 <= p['containerPort'] <= 65535
                or p['protocol'] not in ('tcp', 'udp')):
            _fail()
        port_keys.append((p['hostIp'], p['hostPort'], p['containerPort'], p['protocol']))
        # The wildcard address overlaps loopback; v1 permits one binding per
        # host port/protocol rather than attempting platform-specific overlap.
        host_bindings.append((p['hostPort'], p['protocol']))
    if port_keys != sorted(set(port_keys)) or len(host_bindings) != len(set(host_bindings)):
        _fail()
    health = _fields(value['health'], {'test', 'intervalNs', 'timeoutNs', 'retries'})
    if (not _strings(health['test'], 1024, 32) or not health['test']
            or health['test'][0] != 'CMD' or len(health['test']) < 2
            or any(type(health[key]) is not int or not 1 <= health[key] <= 60_000_000_000
                   for key in ('intervalNs', 'timeoutNs'))
            or type(health['retries']) is not int or not 1 <= health['retries'] <= 20):
        _fail()
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'),
                         allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail()
    if len(raw) > MAX_BYTES:
        _fail()
    return raw


def commit_recipe(recipe: object, key_id: str, key: bytes) -> dict[str, str]:
    """Return only key identity and a domain-separated private HMAC."""
    if (type(key_id) is not str or not NAME.fullmatch(key_id)
            or type(key) is not bytes or len(key) < 32):
        _fail()
    encoded_key_id = key_id.encode('ascii')
    digest = hmac.new(key, DOMAIN + len(encoded_key_id).to_bytes(2, 'big')
                      + encoded_key_id + canonical_recipe(recipe), hashlib.sha256).hexdigest()
    return {'keyId': key_id, 'hmac': digest}


def verify_recipe(recipe: object, commitment: object, key: bytes) -> bool:
    value = _fields(commitment, {'keyId', 'hmac'})
    if type(value['hmac']) is not str or not HEX.fullmatch(value['hmac']):
        _fail()
    expected = commit_recipe(recipe, value['keyId'], key)
    return hmac.compare_digest(expected['hmac'], value['hmac'])
