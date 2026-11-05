"""Diagnostic harness ownership and unknown-write boundaries, without Docker."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('candidate_probe', ROOT / 'scripts/deployment_compose_candidate_probe.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class Docker:
    def __init__(self):
        self.calls, self.nets, self.vols, self.containers = [], {}, {}, {}
        self.network_unknown = self.rm_fail = False
        self.image = {'Id': 'sha256:' + 'a' * 64, 'Os': 'linux', 'Architecture': 'amd64',
            'RepoDigests': [probe.IMAGE], 'Config': {'Env': ['PATH=/usr/local/bin:/usr/bin'], 'Cmd': ['python3']}}

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == 'info':
            return json.dumps({'OSType': 'linux', 'ID': 'test-daemon'})
        if args[:2] == ('image', 'inspect'):
            return json.dumps([self.image])
        if args[:2] == ('container', 'ls'):
            return '\n'.join(['f' * 64, *self.containers])
        if args[:2] == ('container', 'inspect'):
            return json.dumps([self.containers[id_] if id_ in self.containers else {
                'Id': id_, 'State': {'StartedAt': 'before', 'Status': 'running'}, 'RestartCount': 0}
                for id_ in args[2:]])
        if args[:2] == ('network', 'ls'):
            return '\n'.join(json.dumps({'ID': id_, 'Name': item['Name']}) for id_, item in
                [('e' * 64, {'Name': 'original'}), *self.nets.items()])
        if args[:2] == ('volume', 'ls'):
            return '\n'.join(['original-volume', *self.vols])
        if args[1] == 'create':
            name = args[-1]
            project = next(v.partition('=')[2].partition('=')[2] for v in args if v.startswith('--label='))
            if args[0] == 'network':
                id_ = 'b' * 64
                self.nets[id_] = {'Id': id_, 'Name': name, 'Driver': 'bridge', 'Internal': True,
                    'Labels': {'com.docker.compose.project': project}}
                if self.network_unknown:
                    raise subprocess.TimeoutExpired('network create', 20)
                return id_
            self.vols[name] = {'Name': name, 'Driver': 'local', 'Labels': {'com.docker.compose.project': project}}
            return name
        if args[:2] == ('network', 'inspect'):
            return json.dumps([self.nets[args[2]]])
        if args[:2] == ('volume', 'inspect'):
            return json.dumps([self.vols[args[2]]])
        if args[1] == 'rm':
            if self.rm_fail:
                raise subprocess.CalledProcessError(1, args)
            {'network': self.nets, 'volume': self.vols, 'container': self.containers}[args[0]].pop(args[2])
            return args[2]
        raise AssertionError(args)

    def post(self, candidate):
        self.calls.append(('POST', candidate['path']))
        body = deepcopy(candidate['body'])
        host, network = body.pop('HostConfig'), body.pop('NetworkingConfig')
        id_ = 'c' * 64
        self.containers[id_] = {'Id': id_, 'Name': '/' + candidate['identity']['containerName'],
            'Image': body['Image'], 'Config': body, 'HostConfig': host,
            'State': {'Status': 'created', 'Running': False, 'StartedAt': '', 'Pid': 0}, 'RestartCount': 0,
            'NetworkSettings': {'Networks': network['EndpointsConfig']},
            'Mounts': [{'Type': item['Type'], 'Source': item['Source'], 'Destination': item['Target'],
                'RW': not item['ReadOnly'], **({'Name': item['Source']} if item['Type'] == 'volume' else {})}
                for item in host['Mounts']]}
        return {'Id': id_, 'Warnings': []}


@unittest.skipIf(sys.platform == 'win32', 'Linux diagnostic requires POSIX bind fixture paths')
class CandidateProbeTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        original = tempfile.mkdtemp
        self.patch = mock.patch.object(probe.tempfile, 'mkdtemp',
            side_effect=lambda prefix: original(prefix=prefix, dir=self.root.name))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.root.cleanup()

    def test_exact_compiler_body_and_receipt_order_cleanup(self):
        docker = Docker()
        result = probe.probe(docker, docker.post)
        self.assertTrue(result['success'], result.get('privateFailure'))
        self.assertEqual([v['kind'] for v in result['cleanup']], ['container', 'volume', 'network'])
        self.assertEqual(result['candidate']['body']['Image'], docker.image['Id'])
        self.assertEqual(result['candidate']['body']['HostConfig']['Mounts'][1]['VolumeOptions'], {'NoCopy': True})
        self.assertIs(result['candidate']['body']['HostConfig']['Mounts'][0]['ReadOnly'], True)
        self.assertTrue(result['bindSentinelUnchanged'])
        self.assertFalse(any('start' in call or '--force' in call or 'pull' in call for call in docker.calls))
        for flag in ('authorityGranted', 'executionAvailable', 'reconstructionValidated', 'productionReady'):
            self.assertIs(result[flag], False)

    def test_unknown_post_never_retried_or_dependencies_deleted(self):
        docker = Docker()
        post = mock.Mock(side_effect=TimeoutError())
        result = probe.probe(docker, post)
        self.assertFalse(result['success'])
        self.assertTrue(result['unknownWriteResult'])
        self.assertEqual(post.call_count, 1)
        self.assertEqual(result['cleanup'], [])
        self.assertTrue(Path(result['retainedBindDirectory']).exists())

    def test_known_mismatch_is_completed_experiment_but_failed_validation(self):
        docker = Docker()
        def post(candidate):
            receipt = docker.post(candidate)
            docker.containers[receipt['Id']]['Config']['Env'] = ['CHANGED=value']
            return receipt
        result = probe.probe(docker, post)
        self.assertTrue(result['experimentCompleted'])
        self.assertFalse(result['success'] or result['validationPassed'])
        self.assertIn('Config.Env', result['comparison']['mismatchPaths'])

    def test_bind_cleanup_error_keeps_json_evidence_and_after_inventory(self):
        docker = Docker()
        with mock.patch.object(probe.shutil, 'rmtree', side_effect=OSError('test-cleanup-failed')):
            result = probe.probe(docker, docker.post)
        self.assertFalse(result['success'])
        self.assertIn('afterResources', result)
        self.assertEqual(result['privateBindCleanupFailure']['phase'], 'bind-cleanup')
        self.assertTrue(Path(result['retainedBindDirectory']).exists())

    def test_existing_container_id_receipt_is_not_deleted(self):
        docker = Docker()
        result = probe.probe(docker, lambda c: {'Id': 'f' * 64})
        self.assertTrue(result['unknownWriteResult'])
        self.assertEqual(result['cleanup'], [])
        self.assertFalse(any(call[:2] == ('container', 'rm') for call in docker.calls))

    def test_unknown_network_stops_before_volume_or_container_creation(self):
        docker = Docker(); docker.network_unknown = True
        post = mock.Mock()
        result = probe.probe(docker, post)
        self.assertTrue(result['unknownWriteResult'])
        self.assertEqual(result['cleanup'], [])
        self.assertFalse(docker.vols)
        post.assert_not_called()

    def test_cleanup_failure_preserves_dependencies_and_bind(self):
        docker = Docker(); docker.rm_fail = True
        result = probe.probe(docker, docker.post)
        self.assertFalse(result['success'])
        self.assertEqual(len(result['cleanup']), 1)
        self.assertEqual(result['cleanup'][0]['kind'], 'container')
        self.assertTrue(docker.vols and docker.nets)
        self.assertTrue(Path(result['retainedBindDirectory']).exists())

    def test_unsupported_image_refused_before_any_resource_write(self):
        docker = Docker(); docker.image['Config']['Volumes'] = {'/implicit': {}}
        result = probe.probe(docker, docker.post)
        self.assertFalse(result['success'])
        self.assertFalse(any(call[1:2] == ('create',) or call[0] == 'POST' for call in docker.calls))


if __name__ == '__main__':
    unittest.main()
