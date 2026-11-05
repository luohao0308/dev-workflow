import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
import deployment_compose_private as private


def fixture():
    return {
        'Config': {'Env': ['DB_PASSWORD=private-value'], 'Labels': {'com.docker.compose.service': 'backend'},
                   'User': '1000:1000', 'WorkingDir': '/app', 'Entrypoint': ['/app/server'],
                   'Cmd': [], 'ExposedPorts': {'8080/tcp': {}}, 'Healthcheck': None,
                   'Tty': False, 'StopSignal': 'SIGTERM'},
        'HostConfig': {'Binds': None, 'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0},
                       'Privileged': False, 'ReadonlyRootfs': False, 'NetworkMode': 'blog_default',
                       'SecurityOpt': None, 'CapAdd': None, 'CapDrop': None, 'Devices': [],
                       'PortBindings': {}, 'Mounts': [], 'LogConfig': {'Type': 'json-file', 'Config': {}},
                       'Dns': [], 'ExtraHosts': [], 'Memory': 0},
        'Mounts': [{'Type': 'volume', 'Name': 'blog_uploads', 'Source': '/var/lib/docker/volumes/blog_uploads/_data',
                    'Destination': '/uploads', 'RW': True, 'Mode': 'z', 'Propagation': '', 'Driver': 'local'}],
        'NetworkSettings': {'Networks': {'blog_default': {'NetworkID': 'a' * 64,
                                                          'Aliases': ['backend', 'blog-backend-1']}}},
    }


class PrivateCommitmentTests(unittest.TestCase):
    def setUp(self):
        self.key = b'k' * 32
        self.source = fixture()
        self.baseline = private.commit('blog', 'backend', self.source, 'host-key-1', self.key)

    def test_stable_secret_free_commitment(self):
        again = copy.deepcopy(self.source)
        again['Config'] = dict(reversed(list(again['Config'].items())))
        self.assertEqual(self.baseline, private.commit('blog', 'backend', again, 'host-key-1', self.key))
        self.assertEqual(len(self.baseline['configHmac']), 64)
        self.assertFalse(self.baseline['authorityGranted'])
        self.assertNotIn('private-value', json.dumps(self.baseline))

    def test_omitted_exposed_ports_is_valid_and_distinct_from_null_or_empty(self):
        values = []
        for sentinel in ('missing', 'null', 'empty'):
            data = copy.deepcopy(self.source)
            if sentinel == 'missing':
                data['Config'].pop('ExposedPorts')
            else:
                data['Config']['ExposedPorts'] = None if sentinel == 'null' else {}
            values.append(private.commit('blog', 'backend', data, 'host-key-1', self.key)['configHmac'])
        self.assertEqual(len(set(values)), 3)

    def test_omitted_host_mounts_is_not_normalized_to_null_or_empty(self):
        values = []
        for sentinel in ('missing', 'null', 'empty'):
            data = copy.deepcopy(self.source)
            if sentinel == 'missing':
                data['HostConfig'].pop('Mounts')
            else:
                data['HostConfig']['Mounts'] = None if sentinel == 'null' else []
            values.append(private.commit('blog', 'backend', data, 'host-key-1', self.key)['configHmac'])
        self.assertEqual(len(set(values)), 3)

    def test_sensitive_drift_changes_hmac(self):
        changes = [
            lambda x: x['Config']['Env'].append('NEW=private-value-2'),
            lambda x: x['Config']['Labels'].update({'other': 'private-value-2'}),
            lambda x: x['HostConfig'].update(Binds=['/host:/app:rw']),
            lambda x: x['Mounts'][0].update(RW=False),
            lambda x: x['Mounts'][0].update(Source='/other'),
            lambda x: x['NetworkSettings']['Networks']['blog_default']['Aliases'].append('other'),
            lambda x: x['HostConfig'].update(RestartPolicy={'Name': 'always', 'MaximumRetryCount': 0}),
            lambda x: x['HostConfig'].update(Privileged=True),
            lambda x: x['Config'].update(Tty=True),
            lambda x: x['Config'].update(StopSignal='SIGKILL'),
            lambda x: x['HostConfig'].update(LogConfig={'Type': 'json-file', 'Config': {'max-size': '1m'}}),
            lambda x: x['HostConfig'].update(Memory=1024),
            lambda x: x['NetworkSettings']['Networks']['blog_default'].update(IPAMConfig={'IPv4Address': '172.20.0.5'}),
            lambda x: x['NetworkSettings']['Networks']['blog_default'].update(Links=['db:database']),
            lambda x: x['NetworkSettings']['Networks']['blog_default'].update(DriverOpts={'private': 'value'}),
            lambda x: x['NetworkSettings']['Networks']['blog_default'].update(FutureEndpoint={'enabled': True}),
            lambda x: x['NetworkSettings'].update(SandboxKey='/private/sandbox'),
            lambda x: x['Mounts'][0].update(FutureMount={'option': 'private-value'}),
        ]
        for change in changes:
            with self.subTest(change=change):
                data = copy.deepcopy(self.source)
                change(data)
                self.assertNotEqual(self.baseline['configHmac'],
                                    private.commit('blog', 'backend', data, 'host-key-1', self.key)['configHmac'])

    def test_key_and_scope_are_bound(self):
        for project, service, key_id, key in (
            ('other', 'backend', 'host-key-1', self.key),
            ('blog', 'frontend', 'host-key-1', self.key),
            ('blog', 'backend', 'host-key-2', self.key),
            ('blog', 'backend', 'host-key-1', b'z' * 32),
        ):
            self.assertNotEqual(self.baseline['configHmac'],
                                private.commit(project, service, self.source, key_id, key)['configHmac'])

    def test_malformed_rejected_without_secret_diagnostic(self):
        variants = [
            lambda x: x.pop('HostConfig'),
            lambda x: x['Config'].pop('Env'),
            lambda x: x['Config'].update(Env=['private-value']),
            lambda x: x['HostConfig'].update(Privileged='private-value'),
            lambda x: x['Mounts'][0].update(RW='private-value'),
            lambda x: x['NetworkSettings']['Networks']['blog_default'].update(Aliases='private-value'),
            lambda x: x['Config'].update(Healthcheck=object()),
        ]
        for change in variants:
            data = copy.deepcopy(self.source)
            change(data)
            with self.assertRaises(ValueError) as caught:
                private.commit('blog', 'backend', data, 'host-key-1', self.key)
            self.assertNotIn('private-value', str(caught.exception))
        for key in (b'short', 'private-value', None):
            with self.assertRaises(ValueError):
                private.commit('blog', 'backend', self.source, 'host-key-1', key)


if __name__ == '__main__':
    unittest.main()
