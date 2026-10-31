"""Runtime experiment orchestration uses only known IDs; no real Docker calls."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests.test_deployment_compose_candidate_probe import Docker as BaseDocker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('runtime_probe', ROOT / 'scripts/deployment_compose_runtime_probe.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class Docker(BaseDocker):
    def __init__(self):
        super().__init__()
        self.candidates = {}
        self.start_unknown = self.exec_unknown = self.stop_unknown = self.wrong_peer = False
        self.count = 0

    def post(self, candidate):
        self.count += 1
        super().post(candidate)
        item = self.containers.pop('c' * 64)
        receipt = str(self.count) * 64
        item['Id'] = receipt
        self.containers[receipt] = item
        self.candidates[receipt] = deepcopy(candidate)
        return {'Id': receipt, 'Warnings': []}

    def __call__(self, *args):
        if args[:2] == ('container', 'start'):
            self.calls.append(args)
            receipt = args[2]
            self.containers[receipt]['State'].update(Running=True, Status='running')
            if self.start_unknown:
                raise subprocess.TimeoutExpired('start', 20)
            return receipt
        if args[:2] == ('container', 'stop'):
            self.calls.append(args)
            if self.stop_unknown:
                raise subprocess.TimeoutExpired('stop', 20)
            self.containers[args[-1]]['State'].update(Running=False, Status='exited')
            return args[-1]
        if args[:2] == ('container', 'exec'):
            self.calls.append(args)
            if self.exec_unknown:
                raise subprocess.TimeoutExpired('exec', 20)
            candidate = self.candidates[args[2]]
            role = candidate['identity']['service']
            peer = 'frontend' if role == 'backend' else 'backend'
            return json.dumps({'role': role if self.wrong_peer else peer,
                'token': candidate['identity']['project'], 'checks': dict.fromkeys(probe.CHECKS[peer], True)})
        return super().__call__(*args)

    def healthy(self, run, receipt):
        item = self.containers[receipt]
        item['State']['Health'] = {'Status': 'healthy'}
        return deepcopy(item)

    def stop(self, receipt):
        return self('container', 'stop', '--time=10', receipt)


@unittest.skipIf(sys.platform == 'win32', 'Linux runtime diagnostic needs POSIX bind fixture paths')
class RuntimeProbeTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        original = tempfile.mkdtemp
        self.patch = mock.patch.object(probe.tempfile, 'mkdtemp',
            side_effect=lambda prefix: original(prefix=prefix, dir=self.root.name))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.root.cleanup()

    def test_two_compiled_candidates_runtime_checks_and_exact_cleanup(self):
        docker = Docker()
        result = probe.probe(docker, docker.post, docker.healthy, docker.stop)
        self.assertTrue(result['success'], result.get('privateFailure'))
        self.assertEqual([x['kind'] for x in result['cleanup']], ['container', 'container', 'volume', 'network'])
        for role in ('backend', 'frontend'):
            body = result['containers'][role]['candidate']['body']
            self.assertEqual(body['Cmd'], ['-u', '/probe/runtime.py'])
            self.assertEqual(body['HostConfig']['Memory'], 67108864)
            volume = next(m for m in body['HostConfig']['Mounts'] if m['Type'] == 'volume')
            self.assertIs(volume['VolumeOptions']['NoCopy'], True)
            self.assertIs(volume['ReadOnly'], role == 'frontend')
            for mount in body['HostConfig']['Mounts']:
                if mount['Type'] == 'bind':
                    self.assertIs(mount['ReadOnly'], True)
                    self.assertIs(mount['BindOptions']['CreateMountpoint'], False)
        self.assertEqual(len([c for c in docker.calls if c[:2] == ('container', 'start')]), 2)
        self.assertFalse(any('--force' in call or 'pull' in call for call in docker.calls))
        for key in ('authorityGranted', 'executionAvailable', 'reconstructionValidated', 'productionReady'):
            self.assertIs(result[key], False)

    def test_unknown_start_preserves_all_dependencies_without_stop_or_retry(self):
        docker = Docker(); docker.start_unknown = True
        result = probe.probe(docker, docker.post, docker.healthy, docker.stop)
        self.assertTrue(result['unknownWriteResult'])
        self.assertFalse(result['success'])
        self.assertEqual(result['cleanup'], [])
        self.assertEqual(len([c for c in docker.calls if c[:2] == ('container', 'start')]), 1)
        self.assertFalse(any(c[1:2] in (('stop',), ('rm',)) for c in docker.calls))
        self.assertTrue(Path(result['retainedBindDirectory']).exists())

    def test_unknown_exec_preserves_running_fixture(self):
        docker = Docker(); docker.exec_unknown = True
        result = probe.probe(docker, docker.post, docker.healthy, docker.stop)
        self.assertTrue(result['unknownWriteResult'])
        self.assertEqual(result['cleanup'], [])
        self.assertFalse(result['success'])

    def test_wrong_peer_does_not_count_as_validation(self):
        docker = Docker(); docker.wrong_peer = True
        result = probe.probe(docker, docker.post, docker.healthy, docker.stop)
        self.assertTrue(result['unknownWriteResult'])
        self.assertEqual(result['privateFailure']['phase'], 'backend-peer-exec')
        self.assertFalse(result['success'])

    def test_unknown_stop_blocks_dependent_removals(self):
        docker = Docker(); docker.stop_unknown = True
        result = probe.probe(docker, docker.post, docker.healthy, docker.stop)
        self.assertTrue(result['unknownWriteResult'])
        self.assertFalse(result['success'])
        self.assertEqual(len(result['cleanup']), 1)
        self.assertFalse(any(c[1:2] == ('rm',) for c in docker.calls))

    def test_malformed_stop_response_preserves_unknown_evidence_and_dependencies(self):
        docker = Docker()
        def broken_stop(receipt):
            raise probe.http.client.BadStatusLine('bad-response')
        result = probe.probe(docker, docker.post, docker.healthy, broken_stop)
        self.assertTrue(result['unknownWriteResult'])
        self.assertFalse(result['success'])
        self.assertEqual(result['cleanup'][0]['privateFailure']['type'], 'BadStatusLine')
        self.assertIn('afterContainers', result)
        self.assertTrue(Path(result['retainedBindDirectory']).exists())
        self.assertFalse(any(c[1:2] == ('rm',) for c in docker.calls))

    def test_health_failure_with_known_start_can_cleanup_known_ids(self):
        docker = Docker()
        def unhealthy(run, receipt):
            raise ValueError('runtime-container-unhealthy')
        result = probe.probe(docker, docker.post, unhealthy, docker.stop)
        self.assertFalse(result['unknownWriteResult'])
        self.assertFalse(result['success'])
        self.assertEqual(len(result['cleanup']), 4)
        self.assertEqual(len([c for c in docker.calls if c[:2] == ('container', 'stop')]), 1)

    def test_bind_cleanup_failure_retains_after_evidence(self):
        docker = Docker()
        with mock.patch.object(probe.shutil, 'rmtree', side_effect=OSError('fixture-cleanup-failed')):
            result = probe.probe(docker, docker.post, docker.healthy, docker.stop)
        self.assertFalse(result['success'])
        self.assertIn('afterContainers', result)
        self.assertEqual(result['privateBindCleanupFailure']['phase'], 'bind-cleanup')


class HealthWaitTests(unittest.TestCase):
    def test_stop_uses_exact_local_api_status_and_never_cli_output(self):
        for status in (204, 304):
            connection = mock.Mock()
            connection.getresponse.return_value = mock.Mock(status=status, read=mock.Mock(return_value=b''))
            with mock.patch.object(probe, 'UnixConnection', return_value=connection):
                self.assertEqual(probe.stop_container('a' * 64), 'a' * 64)
            connection.request.assert_called_once_with('POST', '/v1.45/containers/' + 'a' * 64 + '/stop?t=10')
            connection.close.assert_called_once()
        for status, body in ((500, b''), (204, b'unknown')):
            connection = mock.Mock()
            connection.getresponse.return_value = mock.Mock(status=status, read=mock.Mock(return_value=body))
            with mock.patch.object(probe, 'UnixConnection', return_value=connection), self.assertRaises(ValueError):
                probe.stop_container('a' * 64)
            connection.close.assert_called_once()
        with mock.patch.object(probe, 'UnixConnection') as factory, self.assertRaises(ValueError):
            probe.stop_container('short-id')
        factory.assert_not_called()

    def test_known_exit_or_wrong_id_blocks_health(self):
        for item in ({'Id': 'a' * 64, 'State': {'Running': False}},
                     {'Id': 'b' * 64, 'State': {'Running': True}}):
            with self.subTest(item=item), self.assertRaises(ValueError):
                probe.wait_healthy(lambda *args: json.dumps([item]), 'a' * 64)

    def test_wait_has_a_deadline_and_requires_running_healthy(self):
        item = {'Id': 'a' * 64, 'State': {'Running': True, 'Health': {'Status': 'starting'}}}
        with self.assertRaisesRegex(ValueError, 'runtime-health-deadline'):
            probe.wait_healthy(lambda *args: json.dumps([item]), 'a' * 64,
                clock=mock.Mock(side_effect=[0, 1, 121]), sleep=lambda _: None)
        item['State']['Health']['Status'] = 'healthy'
        self.assertEqual(probe.wait_healthy(lambda *args: json.dumps([item]), 'a' * 64), item)


if __name__ == '__main__':
    unittest.main()
