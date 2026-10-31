"""Offline, same-image-only Engine create candidate compiler; no transport/Permit.

The host must authenticate the recipe, identity, topology and complete image
merge inputs independently. Supplied image defaults are assertions here, not a
verified image catalog. The result is private and still requires Engine testing.
"""
from copy import deepcopy
import hashlib
import json
import re

from deployment_compose_recipe import NAME, IMAGE, MAX_BYTES
from deployment_compose_recipe_v3 import canonical_recipe_v3

DOMAIN = b'dev-workflow:compose-create-candidate:v1\0'
DEFAULT_FIELDS = {'ImageId', 'Os', 'Architecture', 'Env', 'Labels', 'Volumes', 'ExposedPorts', 'Healthcheck',
                  'User', 'WorkingDir', 'Entrypoint', 'Cmd', 'StopSignal'}


def _fail():
    raise ValueError('invalid-compose-create-candidate')


def _encode(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                         allow_nan=False).encode('ascii')
    except (TypeError, ValueError, RecursionError, UnicodeError):
        _fail()
    if len(raw) > MAX_BYTES:
        _fail()
    return raw


def _digest(value):
    return hashlib.sha256(_encode(value)).hexdigest()


def compile_create(recipe, *, baseline_image_id, image_defaults, identity, network_ids,
                   allowed_mounts, hostname):
    """Compile only the deliberately closed no-publication, explicit-command subset."""
    try:
        return _compile(recipe, baseline_image_id, image_defaults, identity, network_ids,
                        allowed_mounts, hostname)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        _fail()


def _compile(recipe, baseline_image_id, defaults, identity, network_ids, allowed_mounts, hostname):
    canonical_recipe_v3(recipe)
    if (type(baseline_image_id) is not str or not IMAGE.fullmatch(baseline_image_id)
            or baseline_image_id != recipe['imageId']
            or type(identity) is not dict
            or set(identity) != {'hostId', 'daemonId', 'project', 'service', 'containerName'}
            or any(type(identity[k]) is not str or not NAME.fullmatch(identity[k])
                   for k in ('hostId', 'project', 'service', 'containerName'))
            or type(identity['daemonId']) is not str
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}', identity['daemonId'])
            or any(identity[k] != recipe[k] for k in ('project', 'service', 'containerName'))
            or type(hostname) is not str or not NAME.fullmatch(hostname)):
        _fail()
    if type(defaults) is not dict or set(defaults) != DEFAULT_FIELDS or type(defaults['ImageId']) is not str or defaults['ImageId'] != baseline_image_id:
        _fail()
    if defaults['Os'] != 'linux' or type(defaults['Architecture']) is not str or defaults['Architecture'] not in ('amd64', 'arm64'):
        _fail()
    process = recipe['process']
    # Nonempty vectors avoid null/empty image-command inheritance and [""] reset.
    if not process['entrypoint'] or not process['cmd'] or any(
            not v for v in process['entrypoint'] + process['cmd']):
        _fail()
    if recipe['ports'] or len(recipe['networks']) != 1:
        _fail()
    if (type(network_ids) is not dict or len(network_ids) != 1
            or any(type(name) is not str or not NAME.fullmatch(name) for name in network_ids)
            or list(network_ids.values()) != [recipe['networks'][0]['id']]):
        _fail()
    network_name = next(iter(network_ids))
    if type(allowed_mounts) is not list or _encode(allowed_mounts) != _encode(recipe['mounts']):
        _fail()
    # This initial compiler has no complete daemon log-option contract.
    if recipe['hostConfig']['logConfig'] != {'type': 'none', 'config': {}}:
        _fail()
    labels = {'com.docker.compose.project': recipe['project'],
              'com.docker.compose.service': recipe['service']}
    if defaults['Labels'] is not None and (type(defaults['Labels']) is not dict
                                         or defaults['Labels'] != {}):
        _fail()
    if defaults['Volumes'] is not None and (type(defaults['Volumes']) is not dict or defaults['Volumes'] != {}):
        _fail()
    if defaults['ExposedPorts'] is not None and (type(defaults['ExposedPorts']) is not dict or defaults['ExposedPorts'] != {}):
        _fail()
    # Health merging can inherit zero parameters: reject nonempty image health.
    if defaults['Healthcheck'] is not None and (type(defaults['Healthcheck']) is not dict or defaults['Healthcheck'] != {}):
        _fail()
    if defaults['StopSignal'] != '' or type(defaults['StopSignal']) is not str:
        _fail()
    for key in ('User', 'WorkingDir'):
        desired = process['user' if key == 'User' else 'workingDir']
        if (type(defaults[key]) is not str or len(defaults[key]) > 8192
                or '\0' in defaults[key] or (not desired and defaults[key])):
            _fail()
    for key in ('Entrypoint', 'Cmd'):
        v = defaults[key]
        if v is not None and (type(v) is not list or len(v) > 128
                              or any(type(x) is not str or '\0' in x or len(x) > 8192 for x in v)):
            _fail()
    image_env = defaults['Env']
    if image_env is not None:
        if type(image_env) is not list or len(image_env) > 128:
            _fail()
        requested = {v.partition('=')[0] for v in process['env']}
        names = set()
        for item in image_env:
            if type(item) is not str or '\0' in item or len(item) > 8192 or '=' not in item:
                _fail()
            name = item.partition('=')[0]
            if name not in requested or name in names:
                _fail()
            names.add(name)
    host = recipe['hostConfig']
    resources = host['resources']
    # Conservative compiler policy, not a general Engine-validity guarantee.
    if resources['memoryBytes'] < 6 * 1024 * 1024 or resources['nanoCpus'] < 10_000_000:
        _fail()
    mounts = []
    for source in recipe['mounts']:
        mount = {'Type': source['type'], 'Source': source['source'],
                 'Target': source['target'], 'ReadOnly': source['readOnly']}
        if source['type'] == 'volume':
            mount['VolumeOptions'] = {'NoCopy': True}
        else:
            mount['BindOptions'] = {'Propagation': 'rprivate', 'CreateMountpoint': False}
        mounts.append(mount)
    health = recipe['health']
    body = {'Image': baseline_image_id, 'Hostname': hostname, 'Domainname': '',
        'User': process['user'], 'WorkingDir': process['workingDir'],
        'Entrypoint': process['entrypoint'], 'Cmd': process['cmd'], 'Env': process['env'],
        'Labels': labels, 'Volumes': {}, 'ExposedPorts': {}, 'StopSignal': '',
        'AttachStdin': False, 'AttachStdout': False, 'AttachStderr': False,
        'OpenStdin': False, 'StdinOnce': False, 'Tty': False,
        'Healthcheck': {'Test': health['test'], 'Interval': health['intervalNs'],
            'Timeout': health['timeoutNs'], 'Retries': health['retries'], 'StartPeriod': 0, 'StartInterval': 0},
        'HostConfig': {'Privileged': False, 'ReadonlyRootfs': host['readOnlyRootfs'],
            'PidMode': '', 'IpcMode': 'private', 'PublishAllPorts': False,
            'NetworkMode': recipe['networks'][0]['id'], 'PortBindings': {}, 'Mounts': mounts,
            'RestartPolicy': {'Name': host['restartPolicy']['name'],
                              'MaximumRetryCount': host['restartPolicy']['maximumRetryCount']},
            'LogConfig': {'Type': 'none', 'Config': {}},
            'Memory': resources['memoryBytes'], 'MemorySwap': resources['memorySwapBytes'],
            'NanoCpus': resources['nanoCpus'], 'PidsLimit': resources['pidsLimit']},
        'NetworkingConfig': {'EndpointsConfig': {network_name: {
            'NetworkID': recipe['networks'][0]['id'], 'Aliases': recipe['networks'][0]['aliases']}}}}
    value = {'schemaVersion': 1, 'kind': 'compose-create-candidate',
        'method': 'POST', 'path': '/v1.45/containers/create?name=' + recipe['containerName'],
        'body': body, 'identity': identity, 'recipeDigest': _digest(recipe),
        'imageDefaultsDigest': _digest(defaults), 'imageDefaultsVerification': 'host-asserted-unverified', 'networkPolicyDigest': _digest(network_ids),
        'mountPolicyDigest': _digest(allowed_mounts), 'sameImageOnly': True, 'targetPlatform': 'linux/' + defaults['Architecture'],
        'authorityGranted': False, 'executionAvailable': False, 'reconstructionValidated': False,
        'productionReady': False, 'validationBlockers': ['trusted-image-defaults-required',
            'daemon-defaults-verification-required', 'engine-reconstruction-required',
            'fresh-network-volume-bind-evidence-required',
            'independent-write-authorization-required']}
    digest = hashlib.sha256(DOMAIN + _encode(value)).hexdigest()
    result = deepcopy(dict(value, candidateDigest=digest))
    _encode(result)
    return result


def compile_create_with_image_proof(recipe, *, baseline_image_id, image, image_commitment,
                                    image_key, expected_image_key_id, expected_registry_digest,
                                    expected_architecture, identity, network_ids, allowed_mounts, hostname):
    """Authenticate immutable image input only; all execution/daemon gates remain."""
    from deployment_compose_image_defaults import derive_defaults, PROJECTION_VERSION
    try:
        if (type(expected_image_key_id) is not str or not NAME.fullmatch(expected_image_key_id)
                or type(image_commitment) is not dict
                or image_commitment.get('keyId') != expected_image_key_id):
            _fail()
        defaults = derive_defaults(image, image_commitment, image_key,
            expected_image_id=baseline_image_id, expected_registry_digest=expected_registry_digest,
            expected_architecture=expected_architecture)
        candidate = compile_create(recipe, baseline_image_id=baseline_image_id,
            image_defaults=defaults, identity=identity, network_ids=network_ids,
            allowed_mounts=allowed_mounts, hostname=hostname)
        candidate.pop('candidateDigest')
        candidate['imageDefaultsVerification'] = 'hmac-verified-no-freshness'
        candidate['imageProjectionVersion'] = PROJECTION_VERSION
        candidate['imageCommitmentDigest'] = _digest(image_commitment)
        candidate['expectedRegistryDigest'] = expected_registry_digest
        candidate['validationBlockers'] = [v for v in candidate['validationBlockers']
                                            if v != 'trusted-image-defaults-required']
        candidate['validationBlockers'].extend(['fresh-image-presence-required',
                                                'image-build-provenance-required'])
        digest = hashlib.sha256(DOMAIN + _encode(candidate)).hexdigest()
        result = deepcopy(dict(candidate, candidateDigest=digest))
        _encode(result)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        _fail()
