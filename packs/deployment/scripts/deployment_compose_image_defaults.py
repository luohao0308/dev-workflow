"""Authenticate complete image Config before deriving versioned merge inputs.

HMAC authenticates a host assertion, not observation freshness or build origin.
No result grants execution authority. Unknown Config fields remain committed but
cannot be projected until their merge semantics have been reviewed.
"""
from copy import deepcopy
import hashlib
import hmac
import json
import re

from deployment_compose_create import DEFAULT_FIELDS
from deployment_compose_recipe import IMAGE, NAME, MAX_BYTES

DOMAIN = b'dev-workflow:compose-image-config:v1\0'
PROJECTION_VERSION = 2
DIGEST_REF = re.compile(r'(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)*'
                        r'[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}\Z')


def _registry_reference(value):
    return type(value) is str and len(value) <= 512 and DIGEST_REF.fullmatch(value) is not None

# Omitted Engine nullable collections become null; omitted scalar
# merge defaults become empty strings. Explicit null/empty values stay distinct.
# Version 2 also accepts the exact empty legacy API image Config.Image field;
# it is not the immutable root Id and remains included in the original HMAC.
ZERO_DEFAULTS = {k: None for k in ('Env', 'Labels', 'Volumes', 'ExposedPorts',
                                  'Healthcheck', 'Entrypoint', 'Cmd')}
ZERO_DEFAULTS.update({k: '' for k in ('User', 'WorkingDir', 'StopSignal')})
INERT = {'Hostname': '', 'Domainname': '', 'AttachStdin': False,
         'AttachStdout': False, 'AttachStderr': False, 'Tty': False,
         'OpenStdin': False, 'StdinOnce': False, 'ArgsEscaped': False,
         'NetworkDisabled': False, 'OnBuild': None, 'Shell': None,
         'StopTimeout': None, 'MacAddress': '', 'Image': ''}


def _fail():
    raise ValueError('invalid-compose-image-defaults')


def _plain(value, depth=0, budget=None):
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 32 or budget[0] > 10000:
        _fail()
    if value is None or type(value) in (bool, int):
        if type(value) is int and value.bit_length() > 64:
            _fail()
        return
    if type(value) is str:
        if len(value) > MAX_BYTES or '\0' in value:
            _fail()
        return
    if type(value) is list:
        if len(value) > 10000:
            _fail()
        for item in value:
            _plain(item, depth + 1, budget)
        return
    if type(value) is dict:
        if len(value) > 10000:
            _fail()
        for k, v in value.items():
            if type(k) is not str:
                _fail()
            _plain(k, depth + 1, budget)
            _plain(v, depth + 1, budget)
        return
    _fail()


def _material(image):
    if type(image) is not dict or not {'Id', 'Os', 'Architecture', 'RepoDigests', 'Config'} <= set(image):
        _fail()
    value = {k: image[k] for k in ('Id', 'Os', 'Architecture', 'RepoDigests', 'Config')}
    _plain(value)
    if (type(value['Id']) is not str or not IMAGE.fullmatch(value['Id'])
            or value['Os'] != 'linux' or value['Architecture'] not in ('amd64', 'arm64')
            or type(value['Config']) is not dict or type(value['RepoDigests']) is not list
            or not 1 <= len(value['RepoDigests']) <= 128
            or any(type(r) is not str or not _registry_reference(r) for r in value['RepoDigests'])
            or len(set(value['RepoDigests'])) != len(value['RepoDigests'])):
        _fail()
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False).encode('ascii')
    if len(raw) > MAX_BYTES:
        _fail()
    return raw


def commit_image_config(image, key_id, key):
    """Secret-free commitment to complete Config and exact image metadata."""
    if (type(key_id) is not str or not NAME.fullmatch(key_id)
            or type(key) is not bytes or len(key) < 32):
        _fail()
    raw = _material(image)
    identity = key_id.encode('ascii')
    return {'schemaVersion': 1, 'keyId': key_id,
            'imageConfigHmac': hmac.new(key, DOMAIN + len(identity).to_bytes(2, 'big') + identity + raw, hashlib.sha256).hexdigest(),
            'authorityGranted': False}


def derive_defaults(image, commitment, key, *, expected_image_id,
                    expected_registry_digest, expected_architecture):
    """Verify the original commitment and project reviewed merge inputs only."""
    if (type(commitment) is not dict
            or set(commitment) != {'schemaVersion', 'keyId', 'imageConfigHmac', 'authorityGranted'}
            or type(commitment['schemaVersion']) is not int or commitment['schemaVersion'] != 1
            or commitment['authorityGranted'] is not False
            or type(commitment['imageConfigHmac']) is not str
            or not re.fullmatch('[0-9a-f]{64}', commitment['imageConfigHmac'])):
        _fail()
    actual = commit_image_config(image, commitment['keyId'], key)
    if not hmac.compare_digest(actual['imageConfigHmac'], commitment['imageConfigHmac']):
        _fail()
    if (type(expected_image_id) is not str or expected_image_id != image['Id']
            or type(expected_registry_digest) is not str or not _registry_reference(expected_registry_digest)
            or expected_registry_digest not in image['RepoDigests']
            or type(expected_architecture) is not str or expected_architecture != image['Architecture']):
        _fail()
    config = image['Config']
    if set(config) - set(ZERO_DEFAULTS) - set(INERT):
        _fail()
    for k in config.keys() & INERT.keys():
        if type(config[k]) is not type(INERT[k]) or config[k] != INERT[k]:
            _fail()
    for k in config.keys() & ZERO_DEFAULTS.keys():
        v = config[k]
        expected_type = (list if k in ('Env', 'Entrypoint', 'Cmd') else
                         dict if k in ('Labels', 'Volumes', 'ExposedPorts', 'Healthcheck') else str)
        if v is not None and type(v) is not expected_type:
            _fail()
        if expected_type is list and v is not None and any(type(x) is not str for x in v):
            _fail()
    result = {'ImageId': image['Id'], 'Os': image['Os'], 'Architecture': image['Architecture']}
    result.update({k: deepcopy(config[k] if k in config else zero) for k, zero in ZERO_DEFAULTS.items()})
    if set(result) != DEFAULT_FIELDS:
        _fail()
    return result
