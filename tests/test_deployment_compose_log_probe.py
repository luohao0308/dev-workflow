"""Stopped probes clean exact new receipts only and never retry unknown creates."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

SPEC = importlib.util.spec_from_file_location('log_probe',
    Path(__file__).resolve().parents[1] / 'scripts/deployment_compose_log_probe.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class Docker:
    def __init__(self):
        self.calls, self.created = [], {}
        self.count = 0
        self.unknown = self.old_receipt = self.rm_fail = self.mounted = False

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == 'info':
            return json.dumps({'OSType': 'linux', 'ID': 'test-daemon'})
        if args[:2] == ('image', 'inspect'):
            return json.dumps([{'Id': 'sha256:' + 'a' * 64, 'Os': 'linux',
                'RepoDigests': [probe.IMAGE], 'Config': {}}])
        if args[:2] == ('container', 'ls'):
            return '\n'.join(['f' * 64, *self.created])
        if args[:2] == ('container', 'inspect'):
            values = []
            for id_ in args[2:]:
                values.append(self.created[id_] if id_ in self.created else {
                    'Id': id_, 'State': {'StartedAt': 'before', 'Status': 'running'}, 'RestartCount': 0})
            return json.dumps(values)
        if args[:2] == ('container', 'create'):
            self.count += 1
            if self.unknown:
                raise subprocess.TimeoutExpired('create', 20)
            if self.old_receipt:
                return 'f' * 64
            id_ = str(self.count) * 64
            name = next(arg.partition('=')[2] for arg in args if arg.startswith('--name='))
            project = next(arg.partition('=')[2] for arg in args if arg.startswith('--label=com.docker.compose.project='))
            self.created[id_] = {'Id': id_, 'Image': 'sha256:' + 'a' * 64, 'Name': '/' + name,
                'Config': {'Labels': {'com.docker.compose.project': project.split('=', 1)[1]}},
                'State': {'Running': False, 'Status': 'created'}, 'Mounts': [{}] if self.mounted else [],
                'HostConfig': {'NetworkMode': 'none', 'LogConfig': {'Type': 'none', 'Config': {}}}}
            return id_
        if args[:2] == ('container', 'rm'):
            if self.rm_fail:
                raise subprocess.CalledProcessError(1, 'rm')
            self.created.pop(args[2])
            return args[2]
        raise AssertionError(args)


class LogProbeTests(unittest.TestCase):
    def test_three_stopped_containers_cleaned_by_new_exact_receipt(self):
        docker = Docker()
        result = probe.probe(docker)
        self.assertTrue(result['success'])
        self.assertEqual(len(result['observations']), 3)
        self.assertFalse(result['effectiveDefaultsVerified'] or result['authorityGranted'])
        self.assertFalse(result['executionAvailable'] or result['productionReady'])
        creates = [args for args in docker.calls if args[:2] == ('container', 'create')]
        self.assertEqual(len(creates), 3)
        for args in creates:
            for flag in ('--network=none', '--pull=never', '--read-only', '--memory=64m', '--restart=no'):
                self.assertIn(flag, args)
        self.assertEqual([args[2] for args in docker.calls if args[:2] == ('container', 'rm')],
                         [str(index) * 64 for index in (3, 2, 1)])
        self.assertFalse(any('start' in args or '--force' in args for args in docker.calls))

    def test_unknown_create_is_not_retried_or_removed_by_name(self):
        docker = Docker(); docker.unknown = True
        result = probe.probe(docker)
        self.assertTrue(result['unknownCreateResult'])
        self.assertFalse(result['success'])
        self.assertEqual(docker.count, 1)
        self.assertEqual(result['cleanup'], [])
        self.assertEqual(result['privateFailure']['phase'], 'default-create')
        self.assertEqual(result['privateFailure']['type'], 'TimeoutExpired')

    def test_existing_id_receipt_never_deleted(self):
        docker = Docker(); docker.old_receipt = True
        result = probe.probe(docker)
        self.assertTrue(result['unknownCreateResult'])
        self.assertEqual(result['cleanup'], [])

    def test_cleanup_failure_blocks_success(self):
        docker = Docker(); docker.rm_fail = True
        result = probe.probe(docker)
        self.assertFalse(result['success'])
        self.assertFalse(result['existingContainersUnchanged'])
        self.assertEqual(result['cleanup'][0]['privateFailure']['exitCode'], 1)

    def test_failure_diagnostics_are_bounded_private_evidence(self):
        error = subprocess.CalledProcessError(125, 'docker', stderr=b'x' * 5000)
        value = probe.diagnostic(error, 'json-create')
        self.assertEqual(value['exitCode'], 125)
        self.assertEqual(len(value['stderr']), 4096)

    def test_unexpected_mount_stops_further_creates_but_cleans_receipt(self):
        docker = Docker(); docker.mounted = True
        result = probe.probe(docker)
        self.assertFalse(result['success'])
        self.assertEqual(docker.count, 1)
        self.assertEqual(len(result['cleanup']), 1)
        self.assertTrue(result['cleanup'][0]['removed'])


if __name__ == '__main__':
    unittest.main()
