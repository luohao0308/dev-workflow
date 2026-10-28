"""Exact-preserving private Config evidence contract, never executable authority.

This validates bounded observed values only. It neither constructs Engine create
payloads nor proves reconstruction equivalence. Returned values contain secrets.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re

from deployment_compose_recipe import ENV_NAME, HEX, IMAGE, MAX_BYTES, NAME

DOMAIN = b'dev-workflow:compose-observed-config:v1\0'
REQUIRED = {'AttachStderr', 'AttachStdin', 'AttachStdout', 'Cmd', 'Domainname',
            'Entrypoint', 'Env', 'Healthcheck', 'Hostname', 'Image', 'Labels',
            'OpenStdin', 'StdinOnce', 'Tty', 'User', 'Volumes', 'WorkingDir'}
FLAGS = {'AttachStderr', 'AttachStdin', 'AttachStdout', 'OpenStdin', 'StdinOnce', 'Tty'}
CONTEXT = {'project', 'service', 'containerId', 'containerName', 'imageId'}


def _fail():
    raise ValueError('invalid-compose-observed-config')


def _string(value, limit=8192):
    return type(value) is str and len(value) <= limit and '\0' not in value


def _vector(value):
    return value is None or (type(value) is list and len(value) <= 128
                             and all(_string(item) for item in value))


def _encode(value):
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=True,
                         separators=(',', ':'), allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail()
    if len(raw) > MAX_BYTES:
        _fail()
    return raw


def map_config(raw_config: object, context: object) -> dict:
    """Validate and snapshot literal Config plus independently supplied identity."""
    if type(context) is not dict or set(context) != CONTEXT:
        _fail()
    for field in ('project', 'service', 'containerName'):
        if type(context[field]) is not str or not NAME.fullmatch(context[field]):
            _fail()
    if (type(context['containerId']) is not str or not HEX.fullmatch(context['containerId'])
            or type(context['imageId']) is not str or not IMAGE.fullmatch(context['imageId'])):
        _fail()
    if (type(raw_config) is not dict or not REQUIRED <= set(raw_config)
            or set(raw_config) - REQUIRED - {'ExposedPorts'}):
        _fail()
    c = raw_config
    if any(type(c[k]) is not bool for k in FLAGS):
        _fail()
    if any(not _string(c[k]) for k in ('Domainname', 'Hostname', 'User', 'WorkingDir', 'Image')) or not c['Image']:
        _fail()
    if not _vector(c['Cmd']) or not _vector(c['Entrypoint']):
        _fail()
    env = c['Env']
    if type(env) is not list or len(env) > 128 or any(not _string(e) for e in env):
        _fail()
    keys = []
    for item in env:
        key, separator, _ = item.partition('=')
        if not separator or not ENV_NAME.fullmatch(key):
            _fail()
        keys.append(key)
    if len(keys) != len(set(keys)):
        _fail()
    labels = c['Labels']
    if (type(labels) is not dict or len(labels) > 128
            or any(not _string(k, 1024) or not k or not _string(v) for k, v in labels.items())
            or labels.get('com.docker.compose.project') != context['project']
            or labels.get('com.docker.compose.service') != context['service']):
        _fail()
    if c['Volumes'] is not None and (type(c['Volumes']) is not dict or c['Volumes'] != {}):
        _fail()
    ports = c.get('ExposedPorts')
    if ports is not None:
        if type(ports) is not dict or len(ports) > 32:
            _fail()
        for port, options in ports.items():
            if (type(port) is not str or re.fullmatch(r'[1-9][0-9]{0,4}/(?:tcp|udp)', port) is None
                    or int(port.split('/')[0]) > 65535 or type(options) is not dict or options != {}):
                _fail()
    health = c['Healthcheck']
    required = {'Test', 'Interval', 'Timeout', 'Retries', 'StartPeriod'}
    if type(health) is not dict or not required <= set(health) or set(health) - required - {'StartInterval'}:
        _fail()
    test = health['Test']
    if (type(test) is not list or not 2 <= len(test) <= 32 or test[0] != 'CMD'
            or any(not _string(item, 1024) for item in test)):
        _fail()
    for field in ('Interval', 'Timeout', 'StartPeriod', 'StartInterval'):
        if field in health and (type(health[field]) is not int or not 0 <= health[field] <= 60_000_000_000):
            _fail()
    if type(health['Retries']) is not int or not 0 <= health['Retries'] <= 20:
        _fail()
    value = {'schemaVersion': 1, 'authorityGranted': False, 'executionAvailable': False,
             'reconstructionValidated': False, 'context': context, 'rawConfig': c}
    _encode(value)
    return copy.deepcopy(value)


def canonical_config(mapping: object) -> bytes:
    """Canonical bytes for private storage only, retaining missing/null distinctions."""
    if (type(mapping) is not dict or set(mapping) != {'schemaVersion', 'authorityGranted',
            'executionAvailable', 'reconstructionValidated', 'context', 'rawConfig'}
            or type(mapping['schemaVersion']) is not int or mapping['schemaVersion'] != 1
            or any(mapping[k] is not False for k in ('authorityGranted', 'executionAvailable', 'reconstructionValidated'))):
        _fail()
    return _encode(map_config(mapping['rawConfig'], mapping['context']))


def commit_config(mapping: object, key_id: str, key: bytes) -> dict[str, str]:
    if (type(key_id) is not str or not NAME.fullmatch(key_id)
            or type(key) is not bytes or len(key) < 32):
        _fail()
    identity = key_id.encode('ascii')
    digest = hmac.new(key, DOMAIN + len(identity).to_bytes(2, 'big') + identity
                      + canonical_config(mapping), hashlib.sha256).hexdigest()
    return {'keyId': key_id, 'hmac': digest}


def verify_config(mapping: object, commitment: object, key: bytes) -> bool:
    if (type(commitment) is not dict or set(commitment) != {'keyId', 'hmac'}
            or type(commitment['hmac']) is not str or not HEX.fullmatch(commitment['hmac'])):
        _fail()
    return hmac.compare_digest(commit_config(mapping, commitment['keyId'], key)['hmac'], commitment['hmac'])
