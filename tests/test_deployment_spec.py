"""Synthetic Docker image/create/inspect contracts; no daemon proof is implied."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
import deployment_spec as specification

IMAGE_ID = 'sha256:' + 'a' * 64
CONTAINER_ID = 'b' * 64
SECRET = 'PRIVATE-TOKEN-NOT-EVIDENCE'


def image_fixture(image_id=IMAGE_ID):
    """A Linux image inspect containing the usual nullable image defaults."""
    return {'Id': image_id, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [],
            'Config': {'Hostname': '', 'Domainname': '', 'User': '1000:1000',
                       'AttachStdin': False, 'AttachStdout': False, 'AttachStderr': False,
                       'ExposedPorts': {'8080/tcp': {}}, 'Tty': False, 'OpenStdin': False,
                       'StdinOnce': False, 'Env': ['PATH=/usr/local/bin:/usr/bin:/bin', 'TOKEN=' + SECRET],
                       'Cmd': ['serve', '--port', '8080'], 'Entrypoint': ['/app/server'],
                       'Image': '', 'Volumes': None, 'WorkingDir': '/app',
                       'OnBuild': None, 'Labels': {'org.opencontainers.image.title': 'fixture'}}}


def inspect_fixture(spec=None, container_id=CONTAINER_ID):
    """Typical inspect defaults plus generated instance/network/file values."""
    spec = spec or specification.ContainerSpec.from_image('web', image_fixture())
    body = spec.to_create('fixture', 'execution-1')
    host = body.pop('HostConfig')
    host.update({'Binds': None, 'ContainerIDFile': '', 'LogConfig': {'Type': 'json-file', 'Config': {}},
                 'ConsoleSize': [0, 0], 'CapAdd': None, 'CgroupnsMode': 'private',
                 'Dns': [], 'DnsOptions': [], 'DnsSearch': [], 'ExtraHosts': None,
                 'GroupAdd': None, 'IpcMode': 'private', 'Cgroup': '', 'Links': None,
                 'OomScoreAdj': 0, 'PidMode': '', 'Privileged': False, 'PublishAllPorts': False,
                 'UTSMode': '', 'UsernsMode': '', 'VolumesFrom': None, 'Runtime': 'runc',
                 'Isolation': '', 'CpuShares': 0, 'Memory': 0, 'NanoCpus': 0,
                 'CgroupParent': '', 'BlkioWeight': 0, 'BlkioWeightDevice': [],
                 'BlkioDeviceReadBps': [], 'BlkioDeviceWriteBps': [],
                 'BlkioDeviceReadIOps': [], 'BlkioDeviceWriteIOps': [],
                 'CpuPeriod': 0, 'CpuQuota': 0, 'CpuRealtimePeriod': 0, 'CpuRealtimeRuntime': 0,
                 'CpusetCpus': '', 'CpusetMems': '', 'Devices': [], 'DeviceCgroupRules': None,
                 'DeviceRequests': None, 'MemoryReservation': 0, 'MemorySwap': 0,
                 'MemorySwappiness': None, 'OomKillDisable': False, 'PidsLimit': None,
                 'Ulimits': [], 'CpuCount': 0, 'CpuPercent': 0, 'IOMaximumIOps': 0,
                 'IOMaximumBandwidth': 0, 'MaskedPaths': ['/proc/asound', '/proc/acpi',
                     '/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats',
                     '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug', '/proc/scsi',
                     '/sys/firmware', '/sys/devices/virtual/powercap'],
                 'ReadonlyPaths': ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger']})
    body.update({'Hostname': container_id[:12], 'Domainname': '', 'AttachStdin': False,
                 'AttachStdout': False, 'AttachStderr': False, 'Tty': False, 'OpenStdin': False,
                 'StdinOnce': False, 'Volumes': None})
    return {'Id': container_id, 'Image': spec.image_id, 'Config': body, 'HostConfig': host,
            'Mounts': [], 'Path': '/app/server', 'Args': ['serve', '--port', '8080'],
            'HostsPath': '/var/lib/docker/containers/' + container_id + '/hosts',
            'HostnamePath': '/var/lib/docker/containers/' + container_id + '/hostname',
            'ResolvConfPath': '/var/lib/docker/containers/' + container_id + '/resolv.conf',
            'NetworkSettings': {'Ports': deepcopy(host['PortBindings']),
                                'Networks': {host['NetworkMode']: {'IPAddress': '172.17.0.2',
                                                                 'EndpointID': 'e' * 64}}},
            'State': {'Running': True, 'Paused': False, 'Restarting': False, 'Dead': False,
                      'Status': 'running', 'Pid': 123, 'StartedAt': '2026-01-01T00:00:00.000000000Z'}}


class ContainerSpecTests(unittest.TestCase):
    def setUp(self):
        self.spec = specification.ContainerSpec.from_image('web', image_fixture())

    def test_image_create_inspect_roundtrip_and_private_immutable_json(self):
        self.assertTrue(self.spec.matches(inspect_fixture(self.spec)))
        body = self.spec.to_create('fixture', 'execution-2')
        self.assertEqual(body['Image'], IMAGE_ID)
        self.assertEqual(body['Labels']['dev-workflow.spec'], self.spec.configuration_digest())
        self.assertEqual(body['HostConfig']['CapDrop'], ['ALL'])
        body['Env'].append('MUTATION=1')
        self.assertNotIn('MUTATION', self.spec.config_json)
        with self.assertRaises(FrozenInstanceError):
            self.spec.component = 'other'
        self.assertEqual(set(self.spec.to_dict()), {'component', 'imageId', 'config', 'hostConfig'})
        self.assertRegex(self.spec.configuration_digest(), r'^sha256:[a-f0-9]{64}$')

    def test_custom_hostname_and_entrypoint_reset_are_not_generated_defaults(self):
        inspected = inspect_fixture(self.spec)
        inspected['Config']['Hostname'] = 'external-service'
        self.assertFalse(self.spec.matches(inspected))
        for field in ('Cmd', 'Entrypoint'):
            image = image_fixture()
            image['Config'][field] = ['']
            with self.subTest(field=field), self.assertRaises(ValueError):
                specification.ContainerSpec.from_image('web', image)

    def test_linux_legacy_args_escaped_flag_has_no_windows_semantics(self):
        image = image_fixture()
        image['Config']['ArgsEscaped'] = True
        spec = specification.ContainerSpec.from_image('web', image)
        inspected = inspect_fixture(spec)
        inspected['Config']['ArgsEscaped'] = True
        self.assertTrue(spec.matches(inspected))
        image['Os'] = 'windows'
        with self.assertRaises(ValueError):
            specification.ContainerSpec.from_image('web', image)

    def test_running_port_publication_must_match_actual_mappings(self):
        bindings = {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18080'}]}
        spec = specification.ContainerSpec.from_image('web', image_fixture(), port_bindings=bindings)
        inspected = inspect_fixture(spec)
        inspected['NetworkSettings'].pop('Ports')
        self.assertFalse(spec.matches(inspected))
        inspected['NetworkSettings']['Ports'] = bindings
        self.assertTrue(spec.matches(inspected))
        inspected['NetworkSettings']['Ports'] = {'8080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '18080'}]}
        self.assertFalse(spec.matches(inspected))

    def test_catalog_roundtrip_is_canonical_sorted_and_duplicate_refusing(self):
        other = specification.ContainerSpec.from_image('api', image_fixture())
        text = specification.specifications_json((self.spec, other))
        self.assertEqual(text, specification.specifications_json((other, self.spec)))
        parsed = specification.parse_specifications(text)
        self.assertEqual(parsed[('web', IMAGE_ID)], self.spec)
        pretty = json.dumps(json.loads(text), indent=2)
        self.assertEqual(specification.parse_specifications(pretty), parsed)
        invalid = [text.replace('"schemaVersion":1', '"schemaVersion":true'),
                   text.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'),
                   '{}', 'null', '{invalid', 'NaN', 'x' * (specification.MAX_JSON + 1), '\ud800']
        data = json.loads(text)
        data['specifications'].append(data['specifications'][0])
        invalid.append(json.dumps(data))
        for value in invalid:
            with self.subTest(value=value[:30]), self.assertRaises(ValueError):
                specification.parse_specifications(value)
        with self.assertRaises(ValueError):
            specification.specifications_json((self.spec, self.spec))

    def test_digest_binds_whole_recipe_without_instance_values(self):
        changed = inspect_fixture(self.spec, 'c' * 64)
        changed['NetworkSettings']['Networks']['bridge']['IPAddress'] = '172.17.0.3'
        changed['Config']['Labels']['dev-workflow.execution-id'] = 'another'
        changed['Config']['Labels']['dev-workflow.spec'] = 'untrusted-label'
        self.assertTrue(self.spec.matches(changed))
        for field, value in [('Env', ['TOKEN=changed']), ('Cmd', ['other']),
                             ('Entrypoint', ['/other']), ('WorkingDir', '/other'),
                             ('User', '1001'), ('Labels', {'custom': 'value'})]:
            image = image_fixture()
            image['Config'][field] = value
            spec = specification.ContainerSpec.from_image('web', image)
            self.assertNotEqual(spec.configuration_digest(), self.spec.configuration_digest())
            self.assertFalse(spec.matches(inspect_fixture(self.spec)))
        self.assertNotEqual(self.spec.configuration_digest(),
                            specification.ContainerSpec.from_image('api', image_fixture()).configuration_digest())

    def test_nullable_defaults_cmd_or_entrypoint_and_exposed_port_omission(self):
        for command, entrypoint in [(['/app/server'], None), (None, ['/app/server'])]:
            image = image_fixture()
            image['Config'].update(Cmd=command, Entrypoint=entrypoint, Env=None, ExposedPorts=None, Labels=None)
            spec = specification.ContainerSpec.from_image('web', image)
            container = inspect_fixture(spec)
            container['Config'].update(Cmd=command, Entrypoint=entrypoint, Env=None)
            container['Config'].pop('ExposedPorts')  # Docker omits nil ExposedPorts.
            container['HostConfig']['PortBindings'] = None
            container['HostConfig']['SecurityOpt'] = ['no-new-privileges']
            container['HostConfig']['CapDrop'] = ['CAP_ALL']
            self.assertTrue(spec.matches(container))

    def test_literal_fixed_port_bindings_and_network(self):
        bindings = {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18080'}]}
        spec = specification.ContainerSpec.from_image('web', image_fixture(),
                    network_mode='existing_network', port_bindings=bindings)
        self.assertTrue(spec.matches(inspect_fixture(spec)))
        for network in ('host', 'container:other', 'default', '', 'bad\n'):
            with self.subTest(network=network), self.assertRaises(ValueError):
                specification.ContainerSpec.from_image('web', image_fixture(), network_mode=network)
        for binding in ({'HostIp': '', 'HostPort': '8080'}, {'HostIp': '::1', 'HostPort': '8080'},
                        {'HostIp': 'localhost', 'HostPort': '8080'}, {'HostIp': 2130706433, 'HostPort': '8080'}, {'HostIp': '127.0.0.1', 'HostPort': ''},
                        {'HostIp': '127.0.0.1', 'HostPort': '0'}, {'HostIp': '127.0.0.1', 'HostPort': '65536'}):
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                specification.ContainerSpec.from_image('web', image_fixture(), port_bindings={'8080/tcp': [binding]})

    def test_unsafe_or_unmodeled_inspect_is_rejected(self):
        for changes in ({'Privileged': True}, {'Memory': 128}, {'CpuQuota': 100},
                        {'Binds': ['/private:/data']}, {'Devices': [{'PathOnHost': '/dev/x'}]},
                        {'NetworkMode': 'host'}, {'IpcMode': 'host'}, {'PidMode': 'host'},
                        {'UTSMode': 'host'}, {'UsernsMode': 'host'}, {'CgroupnsMode': 'host'},
                        {'CapAdd': ['NET_ADMIN']}, {'SecurityOpt': []}, {'AutoRemove': True},
                        {'MaskedPaths': []}, {'ReadonlyPaths': []},
                        {'RestartPolicy': {'Name': 'always', 'MaximumRetryCount': 0}},
                        {'FutureDockerOverride': 0}, {'ReadonlyRootfs': 1}, {'CpuShares': False}):
            container = inspect_fixture(self.spec)
            container['HostConfig'].update(changes)
            with self.subTest(changes=changes):
                self.assertFalse(self.spec.matches(container))
        for field in ('Env', 'User', 'Cmd', 'Labels', 'Entrypoint', 'WorkingDir'):
            container = inspect_fixture(self.spec)
            del container['Config'][field]
            self.assertFalse(self.spec.matches(container))
        for field in ('ReadonlyRootfs', 'Privileged', 'IpcMode', 'CapDrop'):
            container = inspect_fixture(self.spec)
            del container['HostConfig'][field]
            self.assertFalse(self.spec.matches(container))
        for changes in ({'Tty': True}, {'Healthcheck': {'Test': ['CMD', 'anything']}},
                        {'Volumes': {'/data': {}}}, {'FutureField': 'x'}, {'Env': False}):
            container = inspect_fixture(self.spec)
            container['Config'].update(changes)
            self.assertFalse(self.spec.matches(container))
        container = inspect_fixture(self.spec)
        container['Image'] = 'sha256:' + 'f' * 64
        self.assertFalse(self.spec.matches(container))
        container = inspect_fixture(self.spec)
        container['Mounts'] = [{}]
        self.assertFalse(self.spec.matches(container))

    def test_recipe_rejects_unsafe_images_fields_and_payloads(self):
        for change in ({'User': 'root'}, {'User': '0'}, {'User': ''}, {'User': 'user:group'},
                       {'Volumes': {'/data': {}}}, {'OnBuild': ['RUN bad']},
                       {'Healthcheck': {'Test': ['CMD', '/check']}}, {'StopSignal': 'SIGKILL'},
                       {'Cmd': [], 'Entrypoint': None}, {'Cmd': 'shell command'},
                       {'Env': ['TOKEN=bad\nvalue']}, {'Env': ['HOST_DISCOVERY']},
                       {'Env': ['TOKEN=a', 'TOKEN=b']}, {'WorkingDir': 'relative'},
                       {'Labels': {'dev-workflow.spec': 'fake'}}, {'Env': ['x' * 65537]}):
            image = image_fixture()
            image['Config'].update(change)
            with self.subTest(change=str(change)[:70]), self.assertRaises(ValueError):
                specification.ContainerSpec.from_image('web', image)
        for change in ({'Os': 'windows'}, {'Id': 'web:latest'}, {'Id': None}):
            image = image_fixture()
            image.update(change)
            with self.assertRaises(ValueError):
                specification.ContainerSpec.from_image('web', image)
        for key, value in [('Privileged', False), ('Memory', 0), ('ExtraHostField', None)]:
            host = json.loads(self.spec.host_config_json)
            host[key] = value
            with self.assertRaises(ValueError):
                specification.ContainerSpec('web', IMAGE_ID, self.spec.config_json, json.dumps(host))


if __name__ == '__main__':
    unittest.main()
