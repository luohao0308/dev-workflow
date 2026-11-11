"""Isolated private recipe v3 values; no create payload, rebuild proof or authority.

This experimental profile is deliberately not connected to authorization or any
writer. Validation proves only a bounded, explicit value contract.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re

from deployment_compose_recipe import MAX_BYTES, NAME, HEX, _fail, _fields
from deployment_compose_recipe import canonical_recipe as canonical_recipe_v2

DOMAIN = b'dev-workflow:compose-target-recipe:v3\0'


def canonical_recipe_v3(recipe: object) -> bytes:
    """Validate every v3 field, then canonicalize the original private value."""
    if type(recipe) is not dict or type(recipe.get('schemaVersion')) is not int or recipe['schemaVersion'] != 3:
        _fail()
    host = _fields(recipe.get('hostConfig'), {
        'privileged', 'readOnlyRootfs', 'capAdd', 'devices', 'pidMode', 'ipcMode',
        'logConfig', 'restartPolicy', 'resources',
    })
    restart = _fields(host['restartPolicy'], {'name', 'maximumRetryCount'})
    if (type(restart['name']) is not str or restart['name'] not in ('no', 'unless-stopped')
            or type(restart['maximumRetryCount']) is not int or restart['maximumRetryCount'] != 0):
        _fail()
    resources = _fields(host['resources'], {'memoryBytes', 'memorySwapBytes', 'nanoCpus', 'pidsLimit'})
    for field, upper in (('memoryBytes', 1 << 30), ('memorySwapBytes', 1 << 30),
                         ('nanoCpus', 1_000_000_000), ('pidsLimit', 256)):
        if type(resources[field]) is not int or not 1 <= resources[field] <= upper:
            _fail()
    if resources['memorySwapBytes'] != resources['memoryBytes']:
        _fail()
    log = _fields(host['logConfig'], {'type', 'config'})
    if type(log['type']) is not str:
        _fail()
    if log['type'] == 'none':
        _fields(log['config'], set())
    elif log['type'] == 'json-file':
        config = _fields(log['config'], {'max-size', 'max-file'})
        if (type(config['max-size']) is not str
                or re.fullmatch(r'(?:[1-9]|[1-9][0-9]|100)m', config['max-size']) is None
                or type(config['max-file']) is not str
                or re.fullmatch(r'(?:[1-9]|10)', config['max-file']) is None):
            _fail()
    else:
        _fail()
    # Reuse the unchanged v2 field contract only after validating the v3
    # additions. Normalization is for validation, never for the commitment.
    normalized = dict(recipe, schemaVersion=2)
    normalized['hostConfig'] = {k: v for k, v in host.items() if k not in ('restartPolicy', 'resources')}
    normalized['hostConfig']['logConfig'] = {'type': 'none', 'config': {}}
    canonical_recipe_v2(normalized)
    try:
        raw = json.dumps(recipe, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail()
    if len(raw) > MAX_BYTES:
        _fail()
    return raw


def commit_recipe_v3(recipe: object, key_id: str, key: bytes) -> dict[str, str]:
    """Commit original v3 fields in a separate HMAC domain; grants no authority."""
    if type(key_id) is not str or not NAME.fullmatch(key_id) or type(key) is not bytes or len(key) < 32:
        _fail()
    identity = key_id.encode('ascii')
    digest = hmac.new(key, DOMAIN + len(identity).to_bytes(2, 'big') + identity
                      + canonical_recipe_v3(recipe), hashlib.sha256).hexdigest()
    return {'keyId': key_id, 'hmac': digest}


def verify_recipe_v3(recipe: object, commitment: object, key: bytes) -> bool:
    value = _fields(commitment, {'keyId', 'hmac'})
    if type(value['hmac']) is not str or not HEX.fullmatch(value['hmac']):
        _fail()
    return hmac.compare_digest(commit_recipe_v3(recipe, value['keyId'], key)['hmac'], value['hmac'])
