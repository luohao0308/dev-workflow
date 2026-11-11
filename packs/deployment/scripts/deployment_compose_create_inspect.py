"""Value-free diagnostic of explicit create inputs against one exact receipt.

This checks requested fields only. Extra Engine fields and daemon defaults do
not establish whole-container equivalence, freshness, or permission to write.
"""
import hashlib
import hmac
import re

from deployment_compose_create import DOMAIN, _encode

_CONFIG = {'Image', 'Hostname', 'Domainname', 'User', 'WorkingDir', 'Entrypoint',
           'Cmd', 'Env', 'Labels', 'Volumes', 'ExposedPorts', 'StopSignal',
           'AttachStdin', 'AttachStdout', 'AttachStderr', 'OpenStdin', 'StdinOnce',
           'Tty', 'Healthcheck'}
_HOST = {'Privileged', 'ReadonlyRootfs', 'PidMode', 'IpcMode', 'PublishAllPorts',
         'NetworkMode', 'PortBindings', 'Mounts', 'RestartPolicy', 'LogConfig',
         'Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit'}
# Only fixed Engine field names may escape: even an unknown object's key can
# contain a credential. Unknown extra names are counted, never reflected.
_EXTRA = {
    'inspect': {'Created', 'Path', 'Args', 'State', 'ResolvConfPath', 'HostnamePath',
                'HostsPath', 'LogPath', 'RestartCount', 'Driver', 'Platform',
                'MountLabel', 'ProcessLabel', 'AppArmorProfile', 'ExecIDs',
                'GraphDriver', 'Mounts', 'SizeRw', 'SizeRootFs'},
    'Config': {'OnBuild', 'ArgsEscaped', 'NetworkDisabled', 'MacAddress', 'Shell'},
    'HostConfig': {'Binds', 'ContainerIDFile', 'AutoRemove', 'VolumeDriver',
        'VolumesFrom', 'ConsoleSize', 'CapAdd', 'CapDrop', 'CgroupnsMode', 'Dns',
        'DnsOptions', 'DnsSearch', 'ExtraHosts', 'GroupAdd', 'Links', 'OomScoreAdj',
        'SecurityOpt', 'StorageOpt', 'Tmpfs', 'UTSMode', 'UsernsMode', 'ShmSize',
        'Runtime', 'Isolation', 'CpuShares', 'CpuPeriod', 'CpuQuota',
        'CpuRealtimePeriod', 'CpuRealtimeRuntime', 'CpusetCpus', 'CpusetMems',
        'Devices', 'DeviceCgroupRules', 'DeviceRequests', 'MemoryReservation',
        'KernelMemory', 'KernelMemoryTCP', 'MemorySwappiness', 'OomKillDisable',
        'Ulimits', 'CpuCount', 'CpuPercent', 'IOMaximumIOps', 'IOMaximumBandwidth',
        'MaskedPaths', 'ReadonlyPaths', 'Init', 'Cgroup', 'CgroupParent',
        'BlkioWeight', 'BlkioWeightDevice', 'BlkioDeviceReadBps',
        'BlkioDeviceWriteBps', 'BlkioDeviceReadIOps', 'BlkioDeviceWriteIOps'},
    'NetworkSettings': {'Ports', 'SandboxID', 'SandboxKey', 'Bridge',
        'HairpinMode', 'LinkLocalIPv6Address', 'LinkLocalIPv6PrefixLen',
        'SecondaryIPAddresses', 'SecondaryIPv6Addresses', 'EndpointID',
        'Gateway', 'GlobalIPv6Address', 'GlobalIPv6PrefixLen', 'IPAddress',
        'IPPrefixLen', 'IPv6Gateway', 'MacAddress'},
    'endpoint': {'IPAMConfig', 'Links', 'MacAddress', 'DriverOpts', 'GwPriority',
        'EndpointID', 'Gateway', 'IPAddress', 'IPPrefixLen', 'IPv6Gateway',
        'GlobalIPv6Address', 'GlobalIPv6PrefixLen', 'DNSNames'}
}


def _fail():
    raise ValueError('invalid-compose-create-inspect')


def _same(left, right):
    # Canonical JSON preserves bool/int, null/empty, order, and every map field.
    return _encode(left) == _encode(right)


def compare_create_inspect(candidate, inspect, *, expected_receipt_id):
    """Return fixed mismatch paths; reject malformed or unbound observations.

    NetworkID and aliases are compared literally even for stopped containers.
    No API normalization or treatment of runtime extras as equivalent occurs.
    The receipt must be independently obtained; the candidate digest is an
    integrity check, not authentication of either the receipt or candidate.
    """
    try:
        return _compare(candidate, inspect, expected_receipt_id)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, UnicodeError):
        _fail()


def _compare(candidate, observed, receipt):
    if (type(candidate) is not dict or type(observed) is not dict
            or type(receipt) is not str or not re.fullmatch(r'[0-9a-f]{64}', receipt)
            or type(observed.get('Id')) is not str or observed['Id'] != receipt):
        _fail()
    digest = candidate.get('candidateDigest')
    material = {k: v for k, v in candidate.items() if k != 'candidateDigest'}
    if (type(digest) is not str or not re.fullmatch(r'[0-9a-f]{64}', digest)
            or not hmac.compare_digest(digest, hashlib.sha256(DOMAIN + _encode(material)).hexdigest())
            or type(candidate.get('schemaVersion')) is not int
            or candidate.get('schemaVersion') != 1
            or candidate.get('kind') != 'compose-create-candidate'
            or candidate.get('method') != 'POST'
            or any(candidate.get(k) is not False for k in ('authorityGranted',
                'executionAvailable', 'reconstructionValidated', 'productionReady'))):
        _fail()
    body = candidate['body']
    if type(body) is not dict or set(body) != _CONFIG | {'HostConfig', 'NetworkingConfig'}:
        _fail()
    host = body['HostConfig']
    net = body['NetworkingConfig']
    if (type(host) is not dict or set(host) != _HOST or type(net) is not dict
            or set(net) != {'EndpointsConfig'} or type(net['EndpointsConfig']) is not dict
            or len(net['EndpointsConfig']) != 1):
        _fail()
    name, endpoint = next(iter(net['EndpointsConfig'].items()))
    if (type(name) is not str or type(endpoint) is not dict
            or set(endpoint) != {'NetworkID', 'Aliases'}
            or type(endpoint['NetworkID']) is not str
            or type(endpoint['Aliases']) is not list
            or any(type(a) is not str for a in endpoint['Aliases'])):
        _fail()
    config, actual_host, actual_net = (observed['Config'], observed['HostConfig'],
                                      observed['NetworkSettings'])
    if any(type(v) is not dict for v in (config, actual_host, actual_net)):
        _fail()
    networks = actual_net['Networks']
    if type(networks) is not dict or any(type(v) is not dict for v in networks.values()):
        _fail()
    if type(observed.get('Name')) is not str or type(observed.get('Image')) is not str:
        _fail()
    for expected, actual in ((body, config), (host, actual_host)):
        for field, value in expected.items():
            if field in ('HostConfig', 'NetworkingConfig') or field not in actual:
                continue
            seen = actual[field]
            # Engine can expose null instead of an empty collection; preserve
            # that as a mismatch rather than silently replacing either value.
            if type(seen) is not type(value) and not (seen is None and type(value) in (list, dict)):
                _fail()
    resolved = observed['Mounts']
    if (type(resolved) is not list or any(type(m) is not dict for m in resolved)
            or type(host['Mounts']) is not list
            or any(type(m) is not dict for m in host['Mounts'])):
        _fail()
    for mount in resolved:
        if (any(type(mount.get(k)) is not str for k in ('Type', 'Destination'))
                or type(mount.get('RW')) is not bool
                or mount['Type'] == 'bind' and type(mount.get('Source')) is not str
                or 'Source' in mount and type(mount['Source']) is not str
                or mount['Type'] == 'volume' and type(mount.get('Name')) is not str):
            _fail()
    for mount in host['Mounts']:
        if (any(type(mount.get(k)) is not str for k in ('Type', 'Target', 'Source'))
                or type(mount.get('ReadOnly')) is not bool):
            _fail()
    if (len({m['Destination'] for m in resolved}) != len(resolved)
            or len({m['Target'] for m in host['Mounts']}) != len(host['Mounts'])):
        _fail()
    # Bound JSON and reject non-JSON input before producing any diagnostic.
    _encode(observed)
    mismatches = []
    by_destination = {m['Destination']: m for m in resolved}
    requested_mounts = host['Mounts']
    if set(by_destination) != {m['Target'] for m in requested_mounts}:
        mismatches.append('Mounts.destinations')
    for mount in requested_mounts:
        seen = by_destination.get(mount['Target'])
        if seen is None:
            continue
        if seen['Type'] != mount['Type']:
            mismatches.append('Mounts.type')
        elif mount['Type'] == 'volume' and seen['Name'] != mount['Source']:
            mismatches.append('Mounts.volumeName')
        elif mount['Type'] == 'bind' and seen['Source'] != mount['Source']:
            mismatches.append('Mounts.bindSource')
        if seen['RW'] is not (not mount['ReadOnly']):
            mismatches.append('Mounts.readWrite')
    path = candidate['path']
    expected_name = candidate['identity']['containerName']
    if type(path) is not str or path != '/v1.45/containers/create?name=' + expected_name:
        _fail()
    if observed['Name'] != '/' + expected_name:
        mismatches.append('Name')
    if observed['Image'] != body['Image']:
        mismatches.append('Image')
    for field in sorted(_CONFIG):
        if field not in config or not _same(config[field], body[field]):
            mismatches.append('Config.' + field)
    for field in sorted(_HOST):
        if field not in actual_host or not _same(actual_host[field], host[field]):
            mismatches.append('HostConfig.' + field)
    if set(networks) != {name}:
        mismatches.append('NetworkSettings.Networks')
    actual_endpoint = networks.get(name, {})
    if ('NetworkID' in actual_endpoint and type(actual_endpoint['NetworkID']) is not str
            or 'Aliases' in actual_endpoint and actual_endpoint['Aliases'] is not None
            and (type(actual_endpoint['Aliases']) is not list
                 or any(type(v) is not str for v in actual_endpoint['Aliases']))):
        _fail()
    for field in ('Aliases', 'NetworkID'):
        if field not in actual_endpoint or not _same(actual_endpoint[field], endpoint[field]):
            mismatches.append('NetworkSettings.Networks.endpoint.' + field)
    extras = {}
    unknown = {}
    for scope, obj, expected in (
        ('inspect', observed, {'Id','Name','Image','Config','HostConfig','NetworkSettings','Mounts'}),
        ('Config', config, _CONFIG), ('HostConfig', actual_host, _HOST),
        ('NetworkSettings', actual_net, {'Networks'}),
        ('endpoint', actual_endpoint, {'Aliases','NetworkID'})):
        extra = set(obj) - expected
        extras[scope] = sorted(extra & _EXTRA[scope])
        unknown[scope] = len(extra - _EXTRA[scope])
    return {'schemaVersion': 1, 'kind': 'compose-create-inspect-diagnostic',
        'explicitRequestedFieldsMatch': not mismatches,
        'mismatchPaths': sorted(set(mismatches)), 'observedExtraFields': extras,
        'unlistedExtraFieldCounts': unknown, 'wholeInspectEquivalenceEstablished': False,
        'authorityGranted': False, 'executionAvailable': False,
        'reconstructionValidated': False, 'productionReady': False}


def compare_create_inspect_wire(candidate, inspect, *, expected_receipt_id, image_defaults):
    """Explain only the bounded API 1.45 omissions; retain literal diagnostics.

    This profile is not an Engine reconstruction or image-defaults attestation.
    Image merging of an empty Volumes map requires the exact bound image input.
    """
    from copy import deepcopy
    from deployment_compose_create import DEFAULT_FIELDS, _digest
    try:
        literal = compare_create_inspect(candidate, inspect,
                                         expected_receipt_id=expected_receipt_id)
        if (type(image_defaults) is not dict or set(image_defaults) != DEFAULT_FIELDS
                or _digest(image_defaults) != candidate['imageDefaultsDigest']
                or image_defaults['ImageId'] != candidate['body']['Image']
                or type(image_defaults['StopSignal']) is not str
                or image_defaults['StopSignal'] != ''):
            _fail()
        for key in ('Volumes', 'ExposedPorts', 'Healthcheck'):
            value = image_defaults[key]
            if value is not None and (type(value) is not dict or value != {}):
                _fail()
        adjusted = deepcopy(inspect)
        requested = candidate['body']
        config = adjusted['Config']
        if (requested['Volumes'] == {} and image_defaults['Volumes'] is None
                and 'Volumes' in config and config['Volumes'] is None):
            config['Volumes'] = {}
        if requested['ExposedPorts'] == {} and 'ExposedPorts' not in config:
            config['ExposedPorts'] = {}
        if requested['StopSignal'] == '' and 'StopSignal' not in config:
            config['StopSignal'] = ''
        health = config.get('Healthcheck')
        if type(health) is dict:
            for key in ('StartPeriod', 'StartInterval'):
                wanted = requested['Healthcheck'].get(key)
                if key not in health and type(wanted) is int and wanted == 0:
                    health[key] = 0
        mounts = adjusted['HostConfig'].get('Mounts')
        wanted_mounts = requested['HostConfig']['Mounts']
        if type(mounts) is list and len(mounts) == len(wanted_mounts):
            for wanted, actual in zip(wanted_mounts, mounts):
                if type(actual) is not dict:
                    continue
                if wanted.get('ReadOnly') is False and 'ReadOnly' not in actual:
                    actual['ReadOnly'] = False
                options = actual.get('BindOptions')
                if (wanted.get('Type') == 'bind' and type(options) is dict
                        and wanted.get('BindOptions', {}).get('CreateMountpoint') is False
                        and 'CreateMountpoint' not in options):
                    options['CreateMountpoint'] = False
        explained_view = compare_create_inspect(candidate, adjusted,
                                                expected_receipt_id=expected_receipt_id)
        unresolved = explained_view['mismatchPaths']
        literal.update(wireProfile='api145-explicit-empty-image-and-zero-omissions-v1',
            wireExplainedMismatchPaths=sorted(set(literal['mismatchPaths']) - set(unresolved)),
            unexplainedMismatchPaths=unresolved,
            requestedFieldsMatchUnderWireProfile=not unresolved)
        return literal
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, UnicodeError):
        _fail()
