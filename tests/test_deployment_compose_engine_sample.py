"""Read-only collector tests; mock samples are not Linux Engine evidence."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('engine_sample_tests_module',
    ROOT / 'scripts/deployment_compose_engine_sample.py')
sample = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sample)
PROJECT = 'dw-compose-sample-' + 'a' * 24
IMAGE = 'python:3.13-alpine@sha256:' + 'a' * 64
IMAGE_ID = 'sha256:' + 'b' * 64


def containers():
    result = []
    for index, service in enumerate(sample.SERVICES, 1):
        result.append({'Id': str(index) * 64, 'Name': '/' + PROJECT + '-' + service + '-1',
            'Image': IMAGE_ID, 'Config': {'Image': IMAGE, 'Env': ['TOKEN=private-value'],
              'Labels': {'com.docker.compose.project': PROJECT, 'com.docker.compose.service': service,
                         'com.docker.compose.oneoff': 'False'}, 'Hostname': 'instance-host'},
            'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0},
                           'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '10m'}}},
            'NetworkSettings': {'SandboxKey': '/host/private-path', 'Networks': {'default': {
                'NetworkID': 'c' * 64, 'Aliases': [service], 'MacAddress': '02:42:00:00:00:01'}}},
            'Mounts': [], 'RestartCount': 0, 'State': {'Running': True, 'Pid': index,
                'StartedAt': '2026-10-26T00:00:00Z', 'Health': {'Status': 'healthy', 'Log': []}}})
    return result


class Reader:
    def __init__(self):
        self.calls = []
        self.items = containers()
        self.api, self.minimum, self.os_type = '1.45', '1.24', 'linux'
        self.inspect_count = 0
        self.change = None

    def object(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == 'version':
            return {'ApiVersion': self.api, 'MinAPIVersion': self.minimum, 'Version': '26.0.0'}
        if args[0] == 'info':
            return {'ID': 'test-daemon', 'OSType': self.os_type, 'Architecture': 'x86_64', 'LoggingDriver': 'json-file'}
        if args[:2] == ('container', 'inspect'):
            self.inspect_count += 1
            values = deepcopy(self.items)
            if self.change and self.inspect_count == 2:
                self.change(values)
            return values
        if args[:2] == ('image', 'inspect'):
            return [{'Id': IMAGE_ID, 'Os': 'linux', 'RepoDigests': ['python@sha256:' + 'a' * 64]}]
        raise AssertionError('Unexpected Docker command')

    def read(self, *args, **kwargs):
        self.calls.append(args)
        return '\n'.join(str(i) * 64 for i in (1, 2, 3))


class EngineSampleTests(unittest.TestCase):
    def capture(self, reader):
        with mock.patch.object(sample.sys, 'platform', 'linux'):
            return sample.capture(reader, PROJECT, IMAGE)

    def test_exact_three_service_double_read_diagnostic_only(self):
        reader = Reader()
        raw, report = self.capture(reader)
        self.assertEqual(set(raw['containers']), set(sample.SERVICES))
        self.assertEqual(reader.inspect_count, 2)
        self.assertEqual(report['requestedApiVersion'], '1.45')
        self.assertFalse(report['productionReady'] or report['authorityGranted'] or report['executionAvailable'])
        self.assertNotIn('private-value', json.dumps(report))
        self.assertNotIn('/host/private-path', json.dumps(report))
        self.assertIn('private-value', json.dumps(raw))
        self.assertIn('unsupported-effective-log-config', report['services']['backend']['knownBlockers'])
        self.assertTrue(all(call[0] in ('version', 'info', 'container', 'image') for call in reader.calls))

    def test_mutable_image_arbitrary_project_or_platform_denied_before_read(self):
        for project, image in ((PROJECT, 'python:latest'), ('production', IMAGE),
                               (PROJECT, 'other@sha256:' + 'a' * 64)):
            reader = Reader()
            with mock.patch.object(sample.sys, 'platform', 'linux'), self.assertRaises(ValueError):
                sample.capture(reader, project, image)
            self.assertEqual(reader.calls, [])
        reader = Reader()
        with mock.patch.object(sample.sys, 'platform', 'darwin'), self.assertRaises(ValueError):
            sample.capture(reader, PROJECT, IMAGE)
        self.assertEqual(reader.calls, [])

    def test_unsupported_engine_version_never_reads_containers(self):
        for field, value in (('api', '1.43'), ('minimum', '1.46'), ('os_type', 'windows')):
            reader = Reader()
            setattr(reader, field, value)
            with self.assertRaises(ValueError):
                self.capture(reader)
            self.assertFalse(any(x[0] == 'container' for x in reader.calls))

    def test_drift_and_foreign_service_are_rejected(self):
        for change in (lambda xs: xs[0]['Config']['Env'].append('OTHER=x'),
                       lambda xs: xs[0]['NetworkSettings']['Networks']['default'].update(DriverOpts={'x': 'y'}),
                       lambda xs: xs[0].update(RestartCount=1)):
            reader = Reader()
            reader.change = change
            with self.assertRaises(ValueError):
                self.capture(reader)
        reader = Reader()
        reader.items[0]['Config']['Labels']['com.docker.compose.project'] = 'production'
        with self.assertRaises(ValueError):
            self.capture(reader)

    def test_health_log_changes_do_not_look_like_config_drift(self):
        reader = Reader()
        reader.change = lambda xs: xs[0]['State']['Health']['Log'].append({'Output': 'new log'})
        self.capture(reader)

    @unittest.skipUnless(os.name == 'posix', 'POSIX private output mechanics')
    def test_private_output_permissions_no_overwrite_and_symlink_rejection(self):
        raw, report = self.capture(Reader())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with mock.patch.object(sample.sys, 'platform', 'linux'):
                sample.save_private(root, raw, report)
                self.assertEqual((root / 'sample.private.json').stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError):
                    sample.save_private(root, raw, report)
                link = root / 'link'
                link.symlink_to(root, target_is_directory=True)
                with self.assertRaises(OSError):
                    sample.save_private(link, raw, report)

    def test_transport_issues_only_fixed_api_read_commands_without_shell(self):
        def execute(*args, **kwargs):
            kwargs['stdout'].write(b'{}')
            return mock.Mock(returncode=0)
        with mock.patch.object(sample.subprocess, 'run', side_effect=execute) as run:
            reader = sample.DockerReader()
            reader.object('info', '--format', '{{json .}}')
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['docker', 'info', '--format', '{{json .}}'])
        self.assertNotIn('shell', kwargs)
        self.assertEqual(kwargs['env']['DOCKER_API_VERSION'], '1.45')


if __name__ == '__main__':
    unittest.main()
