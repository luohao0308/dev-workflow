"""Host-private Compose configuration commitment; never an authorization token.

The caller must supply configuration from a trusted Engine inspect. Minimal legacy
projections remain diagnostic commitments, not proof of complete reconstruction.
This module neither obtains inspect data nor proves its origin, source, migrations, or
continuity of named-volume contents. Never serialize the projection into diagnostics.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re

DOMAIN = b'dev-workflow:compose-private-inspect:v1\0'
MAX_BYTES = 256 * 1024
IDENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
REQUIRED_CONFIG = {'Env', 'Labels', 'User', 'WorkingDir', 'Entrypoint', 'Cmd',
                   'Healthcheck'}
# Engine omits ExposedPorts when the image declares no exposed ports. Preserve
# absence in the commitment rather than inserting null or an empty object.
KNOWN_OPTIONAL_CONFIG = {'ExposedPorts'}
REQUIRED_HOST = {'Binds', 'RestartPolicy', 'Privileged', 'ReadonlyRootfs', 'NetworkMode',
                 'SecurityOpt', 'CapAdd', 'CapDrop', 'Devices', 'PortBindings'}
# Mounts is omitted for containers without structured mount declarations.
KNOWN_OPTIONAL_HOST = {'Mounts'}
MOUNT = {'Type', 'Name', 'Source', 'Destination', 'RW', 'Mode', 'Propagation', 'Driver'}
NETWORK = {'NetworkID', 'Aliases'}


def _json_tree(value: object, depth: int = 0) -> None:
    if depth > 16:
        raise ValueError('invalid-private-projection')
    if value is None or type(value) in (str, bool, int):
        if type(value) is str and len(value) > MAX_BYTES:
            raise ValueError('invalid-private-projection')
        return
    if type(value) is list:
        if len(value) > 4096:
            raise ValueError('invalid-private-projection')
        for item in value:
            _json_tree(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > 4096 or any(type(key) is not str for key in value):
            raise ValueError('invalid-private-projection')
        for key, item in value.items():
            _json_tree(key, depth + 1)
            _json_tree(item, depth + 1)
        return
    raise ValueError('invalid-private-projection')


def _exact(value: object, keys: set[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        raise ValueError('invalid-private-projection')
    return value


def _required(value: object, keys: set[str]) -> dict:
    # Hash every supplied Engine field, including fields added in future Engine versions.
    # Completeness of that supply is a trusted-host responsibility.
    if type(value) is not dict or not keys <= set(value):
        raise ValueError('invalid-private-projection')
    return value


def _projection(value: object) -> dict:
    root = _exact(value, {'Config', 'HostConfig', 'Mounts', 'NetworkSettings'})
    config = _required(root['Config'], REQUIRED_CONFIG)
    host = _required(root['HostConfig'], REQUIRED_HOST)
    if type(config['Env']) is not list or any(type(x) is not str or '=' not in x for x in config['Env']):
        raise ValueError('invalid-private-projection')
    if type(config['Labels']) is not dict or any(type(k) is not str or type(v) is not str
                                                  for k, v in config['Labels'].items()):
        raise ValueError('invalid-private-projection')
    if type(host['Privileged']) is not bool or type(host['ReadonlyRootfs']) is not bool:
        raise ValueError('invalid-private-projection')
    mounts = root['Mounts']
    if type(mounts) is not list or any(type(m) is not dict or not MOUNT <= set(m)
                                       or type(m['RW']) is not bool for m in mounts):
        raise ValueError('invalid-private-projection')
    networks = _required(root['NetworkSettings'], {'Networks'})['Networks']
    if type(networks) is not dict or not networks or any(
            type(name) is not str or type(endpoint) is not dict or not NETWORK <= set(endpoint)
            or type(endpoint['NetworkID']) is not str or type(endpoint['Aliases']) is not list
            or any(type(alias) is not str for alias in endpoint['Aliases'])
            for name, endpoint in networks.items()):
        raise ValueError('invalid-private-projection')
    _json_tree(value)
    return root


def commit(project: str, service: str, projection: object, key_id: str, key: bytes) -> dict:
    """Return only a domain-separated HMAC and public key ID; no raw config escapes."""
    if any(type(v) is not str or not IDENT.fullmatch(v)
           for v in (project, service, key_id)) or type(key) is not bytes or len(key) < 32:
        raise ValueError('invalid-private-commitment-input')
    private = _projection(projection)
    try:
        raw = json.dumps({'project': project, 'service': service, 'keyId': key_id,
                          'projection': private}, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as error:
        raise ValueError('invalid-private-projection') from None
    if len(raw) > MAX_BYTES:
        raise ValueError('invalid-private-projection')
    return {'schemaVersion': 1, 'keyId': key_id,
            'configHmac': hmac.new(key, DOMAIN + raw, hashlib.sha256).hexdigest(),
            'authorityGranted': False}
