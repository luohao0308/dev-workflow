"""Private, reconstructable recipes for the bounded Docker replacement profile.

Recipes may contain secrets. Only their versioned digest belongs in public evidence.
Docker instance/network/file identities belong to the collector's separate drift hash.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re

MAX_JSON = 1024 * 1024
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
RESERVED = frozenset(('com.docker.compose.project', 'com.docker.compose.service',
                      'dev-workflow.execution-id', 'dev-workflow.spec'))
CONFIG = frozenset(('Cmd', 'Entrypoint', 'Env', 'User', 'WorkingDir', 'Labels', 'ExposedPorts'))


class SpecificationError(ValueError):
    """Sanitized invalid or unsupported recipe."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SpecificationError('Duplicate specification field')
        result[key] = value
    return result


def _parse(text):
    try:
        if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_JSON:
            raise SpecificationError('Invalid specification size')
        return json.loads(text, object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise SpecificationError('Invalid specification JSON') from None


def _text(value, *, empty=True, limit=65536):
    if (not isinstance(value, str) or len(value) > limit or (not empty and not value)
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise SpecificationError('Invalid specification string')
    return value


def _name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise SpecificationError('Invalid specification scope')
    return value


def _config(value):
    if not isinstance(value, dict) or set(value) - CONFIG:
        raise SpecificationError('Unsupported configuration field')
    result = {}
    for field in ('Cmd', 'Entrypoint', 'Env'):
        items = value.get(field)
        items = [] if items is None else items
        if not isinstance(items, list) or len(items) > 4096:
            raise SpecificationError('Invalid configuration list')
        result[field] = [_text(item) for item in items]
    environment_names = set()
    for item in result['Env']:
        key, separator, _ = item.partition('=')
        if not separator or not key or key in environment_names:
            raise SpecificationError('Explicit unique environment assignments are required')
        environment_names.add(key)
    if not result['Cmd'] and not result['Entrypoint']:
        raise SpecificationError('An explicit image command is required')
    if any(items and not items[0] for items in (result['Cmd'], result['Entrypoint'])):
        raise SpecificationError('Empty command/entrypoint reset is unsupported')
    user = _text(value.get('User', ''), empty=False)
    if not re.fullmatch(r'[0-9]+(?::[0-9]+)?', user) or int(user.split(':')[0]) <= 0:
        raise SpecificationError('A numeric nonroot image user is required')
    result['User'] = user
    result['WorkingDir'] = _text(value.get('WorkingDir', ''))
    if result['WorkingDir'] and not result['WorkingDir'].startswith('/'):
        raise SpecificationError('Working directory must be absolute')
    labels = value.get('Labels')
    labels = {} if labels is None else labels
    if not isinstance(labels, dict) or len(labels) > 256:
        raise SpecificationError('Invalid image labels')
    result['Labels'] = {}
    for key, item in labels.items():
        _text(key, empty=False, limit=256)
        if key in RESERVED:
            raise SpecificationError('Reserved image label')
        result['Labels'][key] = _text(item)
    ports = value.get('ExposedPorts')
    ports = {} if ports is None else ports
    if not isinstance(ports, dict) or len(ports) > 256:
        raise SpecificationError('Invalid exposed ports')
    result['ExposedPorts'] = {}
    for port, item in ports.items():
        _port(port)
        if item != {}:
            raise SpecificationError('Invalid exposed port')
        result['ExposedPorts'][port] = {}
    return result


def _port(value):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,4}/(?:tcp|udp|sctp)', value):
        raise SpecificationError('Invalid container port')
    if int(value.split('/')[0]) > 65535:
        raise SpecificationError('Invalid container port')


def _bindings(value):
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 256:
        raise SpecificationError('Invalid port bindings')
    result = {}
    occupied = set()
    for port, bindings in value.items():
        _port(port)
        if not isinstance(bindings, list) or not bindings or len(bindings) > 64:
            raise SpecificationError('Invalid port bindings')
        result[port] = []
        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != {'HostIp', 'HostPort'}:
                raise SpecificationError('Invalid port binding')
            try:
                if not isinstance(binding['HostIp'], str):
                    raise ValueError
                address = str(ipaddress.IPv4Address(binding['HostIp']))
            except (ValueError, TypeError, KeyError):
                raise SpecificationError('A literal IPv4 binding is required') from None
            number = binding['HostPort']
            if (not isinstance(number, str) or not re.fullmatch(r'[1-9][0-9]{0,4}', number)
                    or int(number) > 65535):
                raise SpecificationError('A fixed host port is required')
            identity = (address, number, port.split('/')[1])
            if identity in occupied:
                raise SpecificationError('Duplicate host port binding')
            occupied.add(identity)
            result[port].append({'HostIp': address, 'HostPort': number})
        result[port].sort(key=lambda b: (b['HostIp'], int(b['HostPort'])))
    return result


def _host(network, bindings):
    _name(network)
    if network in ('host', 'default'):
        raise SpecificationError('Unsupported network mode')
    return {'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges:true'],
            'NetworkMode': network, 'PortBindings': _bindings(bindings),
            'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
            'ShmSize': 67108864, 'AutoRemove': False}


# Known Docker inspect defaults only. Unknown fields fail closed, including future
# resource/security features. These are not accepted in a stored host recipe.
# Non-default daemon logging/resources and unfamiliar mask lists require a new
# reviewed profile; they are intentionally not inferred from the observed state.
HOST_DEFAULTS = {
    'Binds': (None, []), 'ContainerIDFile': ('',), 'LogConfig': ({'Type': 'json-file', 'Config': {}},
                                                           {'Type': '', 'Config': {}}),
    'Privileged': (False,), 'PublishAllPorts': (False,), 'CapAdd': (None, []),
    'Dns': (None, []), 'DnsOptions': (None, []), 'DnsSearch': (None, []),
    'ExtraHosts': (None, []), 'GroupAdd': (None, []), 'Links': (None, []),
    'VolumesFrom': (None, []), 'Mounts': (None, []), 'Tmpfs': (None, {}),
    'Devices': (None, []), 'DeviceRequests': (None, []), 'DeviceCgroupRules': (None, []),
    'PidMode': ('',), 'IpcMode': ('private', ''), 'UTSMode': ('',), 'UsernsMode': ('',),
    'CgroupnsMode': ('private', ''), 'Cgroup': ('',), 'CgroupParent': ('',),
    'Runtime': ('runc', ''), 'Isolation': ('', 'default'), 'Init': (None, False),
    'ConsoleSize': ([0, 0],), 'Annotations': (None, {}),
    'CpuCount': (0,), 'CpuPercent': (0,), 'IOMaximumIOps': (0,), 'IOMaximumBandwidth': (0,),
    'CpuShares': (0,), 'Memory': (0,), 'NanoCpus': (0,), 'CpuPeriod': (0,), 'CpuQuota': (0,),
    'CpuRealtimePeriod': (0,), 'CpuRealtimeRuntime': (0,), 'CpusetCpus': ('',), 'CpusetMems': ('',),
    'MemoryReservation': (0,), 'MemorySwap': (0,), 'MemorySwappiness': (None,),
    'OomKillDisable': (None, False), 'OomScoreAdj': (0,), 'PidsLimit': (None, 0),
    'BlkioWeight': (0,), 'BlkioWeightDevice': (None, []), 'BlkioDeviceReadBps': (None, []),
    'BlkioDeviceWriteBps': (None, []), 'BlkioDeviceReadIOps': (None, []),
    'BlkioDeviceWriteIOps': (None, []), 'Ulimits': (None, []), 'Sysctls': (None, {}),
    'StorageOpt': (None, {}), 'VolumeDriver': ('',), 'MaskedPaths': (
        ['/proc/asound', '/proc/acpi', '/proc/interrupts', '/proc/kcore', '/proc/keys',
         '/proc/latency_stats', '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug',
         '/proc/scsi', '/sys/firmware', '/sys/devices/virtual/powercap'],),
    'ReadonlyPaths': (['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'],),
}
CONFIG_DEFAULTS = {'Domainname': ('',), 'AttachStdin': (False,), 'AttachStdout': (False, True),
                   'AttachStderr': (False, True), 'Tty': (False,), 'OpenStdin': (False,),
                   'StdinOnce': (False,), 'Volumes': (None, {}), 'NetworkDisabled': (False,),
                   'MacAddress': ('',), 'StopSignal': ('', 'SIGTERM'), 'StopTimeout': (None, 10),
                   'Healthcheck': (None, {}), 'OnBuild': (None, []), 'ArgsEscaped': (False, True)}


def _default_equal(value, alternatives):
    # bool is an int subclass; do not silently accept malformed numeric flags.
    return any(type(value) is type(default) and value == default for default in alternatives)


@dataclass(frozen=True)
class ContainerSpec:
    component: str
    image_id: str
    config_json: str
    host_config_json: str

    def __post_init__(self):
        _name(self.component)
        if not isinstance(self.image_id, str) or not IMAGE.fullmatch(self.image_id):
            raise SpecificationError('An immutable image ID is required')
        config = _config(_parse(self.config_json))
        host = _parse(self.host_config_json)
        if not isinstance(host, dict) or set(host) != set(_host('bridge', None)):
            raise SpecificationError('Unsupported host recipe')
        expected = _host(host.get('NetworkMode'), host.get('PortBindings'))
        if canonical(host) != canonical(expected):
            raise SpecificationError('Unsupported host recipe')
        if set(host['PortBindings']) - set(config['ExposedPorts']):
            raise SpecificationError('Bound ports must be exposed')
        if host['NetworkMode'] == 'none' and host['PortBindings']:
            raise SpecificationError('Port publishing requires a network')
        object.__setattr__(self, 'config_json', canonical(config))
        object.__setattr__(self, 'host_config_json', canonical(expected))

    @classmethod
    def from_image(cls, component, image, *, network_mode='bridge', port_bindings=None):
        if not isinstance(image, dict) or image.get('Os') != 'linux' or not isinstance(image.get('Config'), dict):
            raise SpecificationError('A Linux image inspect is required')
        source = image['Config']
        # Image features that create mounts or alter process policy cannot be ignored.
        if (source.get('Volumes') not in (None, {}) or source.get('OnBuild') not in (None, [])
                or source.get('Healthcheck') not in (None, {})
                or source.get('StopSignal') not in (None, '', 'SIGTERM')
                or (source.get('ArgsEscaped') is not None and type(source['ArgsEscaped']) is not bool)):
            raise SpecificationError('Unsupported image configuration')
        config = _config({key: source[key] for key in CONFIG if key in source})
        host = _host(network_mode, port_bindings)
        # Docker creates exposed port entries for explicitly bound ports.
        config['ExposedPorts'].update({port: {} for port in host['PortBindings']})
        return cls(component, image.get('Id'), canonical(config), canonical(host))

    def to_dict(self):
        return {'component': self.component, 'imageId': self.image_id,
                'config': _parse(self.config_json), 'hostConfig': _parse(self.host_config_json)}

    def configuration_digest(self):
        value = {'schemaVersion': 1, 'kind': 'docker-container-specification', **self.to_dict()}
        return 'sha256:' + hashlib.sha256(canonical(value).encode()).hexdigest()

    def to_create(self, project, execution_id):
        _name(project)
        _name(execution_id)
        body = _parse(self.config_json)
        body['Labels'].update({'com.docker.compose.project': project,
                               'com.docker.compose.service': self.component,
                               'dev-workflow.execution-id': execution_id,
                               'dev-workflow.spec': self.configuration_digest()})
        body['Image'] = self.image_id
        body['HostConfig'] = _parse(self.host_config_json)
        return body

    def matches(self, container):
        try:
            if (not isinstance(container, dict) or container.get('Image') != self.image_id
                    or container.get('Mounts') != []):
                return False
            config, host = container['Config'], container['HostConfig']
            if not isinstance(config, dict) or not isinstance(host, dict):
                return False
            # Missing effective fields are not evidence of defaults.
            if not (CONFIG - {'ExposedPorts'}) <= config.keys() or not set(_parse(self.host_config_json)) <= host.keys():
                return False
            if host.get('Privileged') is not False or any(host.get(k) != '' for k in ('PidMode', 'UTSMode')):
                return False
            if host.get('IpcMode') != 'private':
                return False
            projected = {key: config.get(key) for key in CONFIG}
            if 'Image' in config and config['Image'] != self.image_id:
                return False
            if not isinstance(projected['Labels'], dict):
                return False
            projected['Labels'] = {k: v for k, v in projected['Labels'].items() if k not in RESERVED}
            if _config(projected) != _parse(self.config_json):
                return False
            for key, value in config.items():
                if key in CONFIG or key == 'Image':
                    continue
                if key == 'Hostname':
                    if value != container.get('Id', '')[:12]:
                        return False
                elif key not in CONFIG_DEFAULTS or not _default_equal(value, CONFIG_DEFAULTS[key]):
                    return False
            expected = _parse(self.host_config_json)
            actual = {key: host[key] for key in expected}
            actual['PortBindings'] = _bindings(actual['PortBindings'])
            if actual['SecurityOpt'] == ['no-new-privileges']:
                actual['SecurityOpt'] = ['no-new-privileges:true']
            if actual['CapDrop'] == ['CAP_ALL']:
                actual['CapDrop'] = ['ALL']
            if canonical(actual) != canonical(expected):
                return False
            if container.get('State', {}).get('Running') is True:
                settings = container.get('NetworkSettings', {})
                if set(settings.get('Networks', {})) != {expected['NetworkMode']}:
                    return False
                ports = settings.get('Ports')
                if ports is None:
                    if expected['PortBindings']:
                        return False
                elif not isinstance(ports, dict) or _bindings({key: value for key, value in ports.items() if value}) != expected['PortBindings']:
                    return False
            for key, value in host.items():
                if key not in expected and (key not in HOST_DEFAULTS or not _default_equal(value, HOST_DEFAULTS[key])):
                    return False
            return True
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
            return False


def specifications_json(specs: tuple[ContainerSpec, ...]) -> str:
    if type(specs) is not tuple or any(type(spec) is not ContainerSpec for spec in specs):
        raise SpecificationError('An immutable specification tuple is required')
    value = canonical({'schemaVersion': 1, 'kind': 'docker-spec-catalog',
                       'specifications': [spec.to_dict() for spec in sorted(specs, key=lambda s: (s.component, s.image_id))]})
    parse_specifications(value)
    return value


def parse_specifications(text) -> dict[tuple[str, str], ContainerSpec]:
    try:
        value = _parse(text)
        if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'kind', 'specifications'}
                or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                or value['kind'] != 'docker-spec-catalog' or not isinstance(value['specifications'], list)):
            raise SpecificationError('Invalid specification catalog')
        result = {}
        for entry in value['specifications']:
            if not isinstance(entry, dict) or set(entry) != {'component', 'imageId', 'config', 'hostConfig'}:
                raise SpecificationError('Invalid specification entry')
            spec = ContainerSpec(entry['component'], entry['imageId'], canonical(entry['config']), canonical(entry['hostConfig']))
            key = (spec.component, spec.image_id)
            if key in result:
                raise SpecificationError('Duplicate specification entry')
            result[key] = spec
        return result
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise SpecificationError('Invalid specification catalog') from None
