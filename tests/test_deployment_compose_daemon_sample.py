"""Startup evidence is diagnostic only; never equates file values with runtime."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('daemon_sample',
    Path(__file__).resolve().parents[1] / 'scripts/deployment_compose_daemon_sample.py')
sample = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sample)


def fixture():
    # Stat field 22 is starttime; comm deliberately contains spaces and ')'.
    return {'pid': '9', 'processStat': '9 (docker ) daemon) ' + ' '.join(['S'] + ['0'] * 18 + ['42'] + ['0'] * 10),
        'bootId': 'boot', 'argv': ['dockerd', '--label=private-value'],
        'configPath': '/private/daemon.json', 'configExplicit': True,
        'configFileIdentity': [1, 2, 3, 4], 'configFileDigest': 'digest',
        'selectedConfig': {'log-opts': {'tag': 'private-value'}},
        'info': {'ServerVersion': '29.8.2', 'ID': 'private-daemon'}}


class DaemonSampleTests(unittest.TestCase):
    def test_config_unlink_after_open_is_not_reported_as_absent(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'daemon.json'
            self.assertEqual(sample.read_config(path, False), (None, None, None))
            with self.assertRaises(ValueError):
                sample.read_config(path, True)
            path.write_text('{"log-driver":"none","private":"not-projected"}')
            selected, identity, raw = sample.read_config(path, False)
            self.assertEqual(selected, {'log-driver': 'none'})
            self.assertEqual(len(identity), 5)
            self.assertIn(b'not-projected', raw)
            with mock.patch.object(Path, 'stat', side_effect=FileNotFoundError), \
                 self.assertRaises(FileNotFoundError):
                sample.read_config(path, False)

    def test_config_flag_forms_and_reject_ambiguous_or_relative(self):
        self.assertEqual(sample.config_path(['dockerd']), ('/etc/docker/daemon.json', False))
        for args in (['--config-file', '/a'], ['--config-file=/a']):
            self.assertEqual(sample.config_path(['dockerd'] + args), ('/a', True))
        for args in (['--config-file'], ['--config-file='], ['--config-file=a'],
                     ['--config-file', '--log-driver=x'],
                     ['--config-file=/a', '--config-file=/b']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                sample.config_path(['dockerd'] + args)

    def test_private_values_do_not_enter_public_diagnostic(self):
        result = sample.capture(lambda: deepcopy(fixture()))
        self.assertIn('private-value', json.dumps(result['samples']))
        self.assertNotIn('private', json.dumps(result['report']))
        self.assertEqual(result['report']['configuredKeysPresent'], ['log-opts'])
        for key in ('effectiveDefaultsVerified', 'processSocketAssociationVerified',
                    'authorityGranted', 'executionAvailable', 'productionReady'):
            self.assertIs(result['report'][key], False)

    def test_process_start_config_daemon_or_boot_change_rejected(self):
        for key, value in (('pid', '10'), ('bootId', 'other'), ('argv', ['dockerd']),
                           ('configFileDigest', 'changed'), ('selectedConfig', {}),
                           ('info', {'ServerVersion': '29.8.2', 'ID': 'other'}),
                           ('processStat', fixture()['processStat'].replace('42', '43'))):
            first, second = fixture(), fixture()
            second[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                sample.capture(mock.Mock(side_effect=[first, second]))

    def test_cpu_counters_can_change_without_starttime_change(self):
        first, second = fixture(), fixture()
        second['processStat'] += ' 1'
        self.assertEqual(sample.stable_identity(first)['processStartTicks'], '42')
        sample.capture(mock.Mock(side_effect=[first, second]))
        with self.assertRaises(ValueError):
            sample.stable_identity(dict(first, processStat='bad'))

    def test_api_is_fixed_to_local_socket_and_ignores_environment(self):
        with mock.patch.dict(sample.os.environ, {'DOCKER_HOST': 'tcp://remote:2375',
            'DOCKER_CONTEXT': 'remote', 'DOCKER_TLS_VERIFY': '1', 'DOCKER_CERT_PATH': '/private'}), \
             mock.patch.object(sample.subprocess, 'run', return_value=mock.Mock(stdout=
                 b'{"ID":"local","OSType":"linux","ServerVersion":"29.8.2"}')) as run:
            sample.read_info()
        args, kwargs = run.call_args
        self.assertEqual(args[0][:3], ['docker', '--host', 'unix:///var/run/docker.sock'])
        self.assertEqual(args[0][3], 'info')
        self.assertEqual(kwargs['env']['DOCKER_API_VERSION'], '1.45')
        for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
            self.assertNotIn(key, kwargs['env'])


if __name__ == '__main__':
    unittest.main()
