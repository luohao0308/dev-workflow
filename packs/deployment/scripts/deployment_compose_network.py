"""Bounded literal network evidence, never Engine create settings or authority.

Configurable and assigned endpoint values are both retained. In particular an
observed MAC/IP is not evidence of whether a user explicitly requested it.
Returned values include private daemon paths; do not log them.
"""
from copy import deepcopy
import hashlib
import hmac
import json
import re

from deployment_compose_config import CONTEXT
from deployment_compose_recipe import HEX, IMAGE, MAX_BYTES, NAME

DOMAIN = b'dev-workflow:compose-observed-network:v1\0'
ROOT_FIELDS = {'Networks', 'Ports', 'SandboxID', 'SandboxKey'}
ENDPOINT_FIELDS = {'NetworkID', 'EndpointID', 'IPAMConfig', 'Links', 'Aliases',
    'DriverOpts', 'Gateway', 'IPAddress', 'IPPrefixLen', 'IPv6Gateway',
    'GlobalIPv6Address', 'GlobalIPv6PrefixLen', 'MacAddress', 'DNSNames'}


def _fail():
    raise ValueError('invalid-compose-observed-network')


def _string(value, limit=4096):
    return type(value) is str and len(value) <= limit and '\0' not in value


def _strings(value):
    return value is None or (type(value) is list and len(value) <= 128
                            and all(_string(v, 1024) for v in value))


def _object(value, fields):
    if type(value) is not dict or set(value) != fields:
        _fail()


def _encode(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (ValueError, TypeError, RecursionError, UnicodeError):
        _fail()
    if len(raw) > MAX_BYTES:
        _fail()
    return raw


def map_network_settings(raw, context):
    """Validate and retain supplied endpoint fields, never fill API omissions."""
    _object(context, CONTEXT)
    if (any(type(context[k]) is not str or not NAME.fullmatch(context[k])
            for k in ('project', 'service', 'containerName'))
            or type(context['containerId']) is not str or not HEX.fullmatch(context['containerId'])
            or type(context['imageId']) is not str or not IMAGE.fullmatch(context['imageId'])):
        _fail()
    _object(raw, ROOT_FIELDS)
    if not _string(raw['SandboxID']) or not _string(raw['SandboxKey']):
        _fail()
    networks = raw['Networks']
    if type(networks) is not dict or not 1 <= len(networks) <= 8:
        _fail()
    for name, endpoint in networks.items():
        if type(name) is not str or not NAME.fullmatch(name) or type(endpoint) is not dict:
            _fail()
        if not ENDPOINT_FIELDS <= set(endpoint) or set(endpoint) - ENDPOINT_FIELDS - {'GwPriority'}:
            _fail()
        if type(endpoint['NetworkID']) is not str or not HEX.fullmatch(endpoint['NetworkID']):
            _fail()
        for field in ('EndpointID', 'Gateway', 'IPAddress', 'IPv6Gateway', 'GlobalIPv6Address', 'MacAddress'):
            if not _string(endpoint[field], 256):
                _fail()
        for field, upper in (('IPPrefixLen', 32), ('GlobalIPv6PrefixLen', 128)):
            if type(endpoint[field]) is not int or not 0 <= endpoint[field] <= upper:
                _fail()
        if 'GwPriority' in endpoint and (type(endpoint['GwPriority']) is not int
                                       or not -(2**63) <= endpoint['GwPriority'] < 2**63):
            _fail()
        if any(not _strings(endpoint[k]) for k in ('Aliases', 'DNSNames', 'Links')):
            _fail()
        options = endpoint['DriverOpts']
        if options is not None and (type(options) is not dict or len(options) > 64
                or any(not _string(k, 256) or not k or not _string(v) for k, v in options.items())):
            _fail()
        ipam = endpoint['IPAMConfig']
        if ipam is not None:
            if type(ipam) is not dict or set(ipam) - {'IPv4Address', 'IPv6Address', 'LinkLocalIPs'}:
                _fail()
            if any(not _string(ipam[k], 256) for k in ('IPv4Address', 'IPv6Address') if k in ipam):
                _fail()
            if 'LinkLocalIPs' in ipam and not _strings(ipam['LinkLocalIPs']):
                _fail()
    ports = raw['Ports']
    if ports is not None:
        if type(ports) is not dict or len(ports) > 128:
            _fail()
        for port, bindings in ports.items():
            if (type(port) is not str or not re.fullmatch(r'[1-9][0-9]{0,4}/(?:tcp|udp)', port)
                    or int(port.split('/')[0]) > 65535):
                _fail()
            if bindings is None:
                continue
            if type(bindings) is not list or len(bindings) > 32:
                _fail()
            for binding in bindings:
                _object(binding, {'HostIp', 'HostPort'})
                if not _string(binding['HostIp'], 256) or not _string(binding['HostPort'], 8):
                    _fail()
                if binding['HostPort'] and (not binding['HostPort'].isascii()
                        or not binding['HostPort'].isdigit() or not 1 <= int(binding['HostPort']) <= 65535):
                    _fail()
    result = {'schemaVersion': 1, 'context': context, 'rawNetworkSettings': raw,
              'authorityGranted': False, 'executionAvailable': False, 'reconstructionValidated': False}
    _encode(result)
    return deepcopy(result)


def canonical_network(mapping):
    _object(mapping, {'schemaVersion', 'context', 'rawNetworkSettings',
                     'authorityGranted', 'executionAvailable', 'reconstructionValidated'})
    if (type(mapping['schemaVersion']) is not int or mapping['schemaVersion'] != 1
            or any(mapping[k] is not False for k in ('authorityGranted', 'executionAvailable', 'reconstructionValidated'))):
        _fail()
    return _encode(map_network_settings(mapping['rawNetworkSettings'], mapping['context']))


def commit_network(mapping, key_id, key):
    if type(key_id) is not str or not NAME.fullmatch(key_id) or type(key) is not bytes or len(key) < 32:
        _fail()
    identity = key_id.encode('ascii')
    return {'keyId': key_id, 'hmac': hmac.new(key, DOMAIN + len(identity).to_bytes(2, 'big')
                + identity + canonical_network(mapping), hashlib.sha256).hexdigest()}


def verify_network(mapping, commitment, key):
    _object(commitment, {'keyId', 'hmac'})
    if type(commitment['hmac']) is not str or not HEX.fullmatch(commitment['hmac']):
        _fail()
    return hmac.compare_digest(commit_network(mapping, commitment['keyId'], key)['hmac'], commitment['hmac'])
