"""Conservative baseline/recipe comparison, not an Engine reconstruction proof.

Only the closed field set below is represented. Unknown Config/HostConfig or
endpoint options are rejected rather than dropped. Inputs must first be matched
to host-observed private HMACs by the recovery host. No Docker calls occur here.
"""
from deployment_compose_recipe import canonical_recipe
from deployment_compose_private import _projection
import json


def _fail():
    raise ValueError('baseline-recipe-not-representable')


def _same(left, right):
    # Unlike Python equality, JSON distinguishes booleans and numbers.
    encode = lambda x: json.dumps(x, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return encode(left) == encode(right)


ENDPOINT_RUNTIME = {'EndpointID': str, 'Gateway': str, 'IPAddress': str,
    'IPPrefixLen': int, 'IPv6Gateway': str, 'GlobalIPv6Address': str,
    'GlobalIPv6PrefixLen': int, 'MacAddress': str, 'DNSNames': list}
ENDPOINT_CONFIG = {'NetworkID', 'Aliases', 'IPAMConfig', 'Links', 'DriverOpts'}


def verify_baseline_recipe(projection, recipe, *, project, service, container_name, image_id):
    """Verify value equivalence for an explicitly restricted baseline subset."""
    try:
        canonical_recipe(recipe)
        _projection(projection)
        _verify(projection, recipe, project, service, container_name, image_id)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError):
        _fail()


def _verify(projection, recipe, project, service, container_name, image_id):
    if any(recipe[k] != v for k, v in (
            ('project', project), ('service', service),
            ('containerName', container_name), ('imageId', image_id))):
        _fail()
    process, health = recipe['process'], recipe['health']
    ports = {}
    for port in recipe['ports']:
        key = str(port['containerPort']) + '/' + port['protocol']
        ports.setdefault(key, []).append({'HostIp': port['hostIp'], 'HostPort': str(port['hostPort'])})
    expected_config = {
        'Env': process['env'], 'Labels': {'com.docker.compose.project': project,
                                        'com.docker.compose.service': service},
        'User': process['user'], 'WorkingDir': process['workingDir'],
        'Entrypoint': process['entrypoint'], 'Cmd': process['cmd'],
        'ExposedPorts': {key: {} for key in ports},
        'Healthcheck': {'Test': health['test'], 'Interval': health['intervalNs'],
                       'Timeout': health['timeoutNs'], 'Retries': health['retries'],
                       'StartPeriod': 0, 'StartInterval': 0},
    }
    # No assumptions about hostname, custom labels, stop signal, tty or image
    # defaults: this first comparator rejects them until recipes represent them.
    if not _same(projection['Config'], expected_config):
        _fail()
    networks = projection['NetworkSettings']
    if set(networks) != {'Networks'}:
        _fail()
    endpoints = networks['Networks']
    # Primary/default-route semantics for multiple attachments are unrepresented.
    if len(recipe['networks']) != 1 or len(endpoints) != len(recipe['networks']):
        _fail()
    actual_networks = []
    for name, endpoint in endpoints.items():
        if (set(endpoint) != ENDPOINT_CONFIG | set(ENDPOINT_RUNTIME)
                or endpoint['IPAMConfig'] is not None or endpoint['Links'] not in (None, [])
                or endpoint['DriverOpts'] not in (None, {}) or endpoint['MacAddress'] != ''):
            _fail()
        for key, kind in ENDPOINT_RUNTIME.items():
            if type(endpoint[key]) is not kind:
                _fail()
        if any(type(x) is not str for x in endpoint['DNSNames']):
            _fail()
        actual_networks.append({'id': endpoint['NetworkID'], 'aliases': endpoint['Aliases']})
    if not _same(sorted(actual_networks, key=lambda x: x['id']), recipe['networks']):
        _fail()
    declared_mounts, resolved_mounts = [], []
    for mount in recipe['mounts']:
        volume = mount['type'] == 'volume'
        declared = {'Type': mount['type'], 'Source': mount['source'],
                    'Target': mount['target'], 'ReadOnly': mount['readOnly']}
        if volume:
            declared['VolumeOptions'] = {'NoCopy': True}
        else:
            declared['BindOptions'] = {'Propagation': 'rprivate', 'CreateMountpoint': False}
        declared_mounts.append(declared)
    expected_host = {
        'LogConfig': {'Type': recipe['hostConfig']['logConfig']['type'],
                      'Config': recipe['hostConfig']['logConfig']['config']},
        'Binds': None, 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
        'Privileged': False, 'ReadonlyRootfs': recipe['hostConfig']['readOnlyRootfs'],
        'SecurityOpt': None, 'CapAdd': None, 'CapDrop': None, 'Devices': [],
        'PidMode': '', 'IpcMode': 'private', 'PortBindings': ports,
        'Mounts': declared_mounts,
    }
    host = projection['HostConfig']
    if host.get('NetworkMode') not in endpoints:
        _fail()
    expected_host['NetworkMode'] = host['NetworkMode']
    if not _same(host, expected_host):
        _fail()
    # Resolved paths for named volumes are daemon details. Identity/topology is
    # separately checked by observation; do not turn the data directory into bind.
    for actual in projection['Mounts']:
        if set(actual) != {'Type', 'Name', 'Source', 'Destination', 'RW', 'Mode', 'Propagation', 'Driver'}:
            _fail()
        if actual['Mode'] not in ('', 'ro' if actual['RW'] is False else 'rw'):
            _fail()
        if actual['Type'] == 'volume':
            if (actual['Driver'] != 'local' or actual['Propagation'] != ''
                    or type(actual['Source']) is not str or not actual['Source'].startswith('/')):
                _fail()
            source = actual['Name']
        elif actual['Type'] == 'bind':
            if actual['Name'] not in ('', None) or actual['Driver'] not in ('', None) or actual['Propagation'] != 'rprivate':
                _fail()
            source = actual['Source']
        else:
            _fail()
        resolved_mounts.append({'type': actual['Type'], 'source': source,
            'target': actual['Destination'], 'readOnly': not actual['RW'],
            'noCopy': actual['Type'] == 'volume', 'createHostPath': False})
    if not _same(sorted(resolved_mounts, key=lambda x: x['target']), recipe['mounts']):
        _fail()
