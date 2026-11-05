"""Closed-subset equivalence tests; fixtures are not Engine acceptance evidence."""
import unittest
from tests.test_deployment_compose_recipe import recipe as recipe_fixture
from deployment_compose_baseline_recipe import verify_baseline_recipe


def fixture():
    recipe = recipe_fixture()
    projection = {
        'Config': {'Env': ['API_KEY=private-value', 'MODE=staging'],
            'Labels': {'com.docker.compose.project': 'blog', 'com.docker.compose.service': 'web'},
            'User': '1000:1000', 'WorkingDir': '/app', 'Entrypoint': ['/app/server'],
            'Cmd': ['--port=8080'], 'ExposedPorts': {'8080/tcp': {}},
            'Healthcheck': {'Test': ['CMD', '/app/health'], 'Interval': 1000000000,
                'Timeout': 1000000000, 'Retries': 3, 'StartPeriod': 0, 'StartInterval': 0}},
        'HostConfig': {'LogConfig': {'Type': 'none', 'Config': {}}, 'Binds': None, 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
            'Privileged': False, 'ReadonlyRootfs': True, 'NetworkMode': 'blog_default',
            'SecurityOpt': None, 'CapAdd': None, 'CapDrop': None, 'Devices': [],
            'PidMode': '', 'IpcMode': 'private',
            'PortBindings': {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18080'}]},
            'Mounts': [
                {'Type': 'volume', 'Source': 'blog-data', 'Target': '/data', 'ReadOnly': False,
                 'VolumeOptions': {'NoCopy': True}},
                {'Type': 'bind', 'Source': '/srv/blog/config.json', 'Target': '/etc/config.json',
                 'ReadOnly': True, 'BindOptions': {'Propagation': 'rprivate', 'CreateMountpoint': False}}]},
        'Mounts': [
            {'Type': 'volume', 'Name': 'blog-data', 'Source': '/var/lib/docker/volumes/blog-data/_data',
             'Destination': '/data', 'RW': True, 'Mode': '', 'Propagation': '', 'Driver': 'local'},
            {'Type': 'bind', 'Name': None, 'Source': '/srv/blog/config.json',
             'Destination': '/etc/config.json', 'RW': False, 'Mode': 'ro', 'Propagation': 'rprivate', 'Driver': None}],
        'NetworkSettings': {'Networks': {'blog_default': {'NetworkID': 'b' * 64, 'Aliases': ['web'],
            'IPAMConfig': None, 'Links': None, 'DriverOpts': None, 'EndpointID': 'd' * 64,
            'Gateway': '172.20.0.1', 'IPAddress': '172.20.0.3', 'IPPrefixLen': 16,
            'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0,
            'MacAddress': '', 'DNSNames': ['web']}}}}
    return projection, recipe


def verify(projection, recipe):
    return verify_baseline_recipe(projection, recipe, project='blog', service='web',
             container_name='blog-web-1', image_id='sha256:' + 'a' * 64)


class BaselineRecipeTests(unittest.TestCase):
    def test_supported_values_match_without_authorizing_engine_reconstruction(self):
        projection, recipe = fixture()
        self.assertIsNone(verify(projection, recipe))

    def test_unsupported_or_missing_private_fields_are_rejected(self):
        mutations = [
            lambda p: p['Config'].update(StopSignal='SIGKILL'),
            lambda p: p['Config']['Labels'].update(custom='value'),
            lambda p: p['Config'].update(Healthcheck=None),
            lambda p: p['Config'].update(Entrypoint=None),
            lambda p: p['Config']['Healthcheck'].update(StartPeriod=10),
            lambda p: p['HostConfig'].update(LogConfig={'Type': 'json-file', 'Config': {}}),
            lambda p: p['HostConfig'].update(RestartPolicy={'Name': 'unless-stopped', 'MaximumRetryCount': 0}),
            lambda p: p['HostConfig'].update(Memory=1024),
            lambda p: p['HostConfig'].pop('PidMode'),
            lambda p: p['HostConfig'].pop('LogConfig'),
            lambda p: p['NetworkSettings']['Networks']['blog_default'].update(MacAddress='02:42:ac:14:00:03'),
            lambda p: p['HostConfig'].update(IpcMode='host'),
            lambda p: p['HostConfig']['Mounts'][0]['VolumeOptions'].update(NoCopy=False),
            lambda p: p['HostConfig']['Mounts'][1]['BindOptions'].update(CreateMountpoint=True),
            lambda p: p['Mounts'][1].update(RW=True),
            lambda p: p['Mounts'][0].update(Mode='z'),
            lambda p: p['NetworkSettings']['Networks']['blog_default'].pop('IPAMConfig'),
            lambda p: p['NetworkSettings']['Networks']['blog_default'].update(IPAMConfig={'IPv4Address': '172.20.0.3'}),
            lambda p: p['NetworkSettings']['Networks']['blog_default'].update(Links=['db:db']),
            lambda p: p['NetworkSettings']['Networks']['blog_default'].update(DriverOpts={'x': 'y'}),
            lambda p: p['NetworkSettings']['Networks']['blog_default'].update(UnknownOption=False),
            lambda p: p['NetworkSettings'].update(SandboxKey='/unrepresented'),
        ]
        for mutate in mutations:
            projection, recipe = fixture()
            mutate(projection)
            with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, '^baseline-recipe-not-representable$'):
                verify(projection, recipe)

    def test_recipe_drift_across_every_surface_is_rejected(self):
        mutations = [
            lambda r: r.update(imageId='sha256:' + 'b' * 64),
            lambda r: r.update(containerName='other'),
            lambda r: r['process']['env'].__setitem__(0, 'API_KEY=changed'),
            lambda r: r['hostConfig'].update(readOnlyRootfs=False),
            lambda r: r['mounts'][0].update(source='other-data'),
            lambda r: r['networks'][0].update(aliases=['other']),
            lambda r: r['ports'][0].update(hostPort=18081),
            lambda r: r['health'].update(retries=4),
        ]
        for mutate in mutations:
            projection, recipe = fixture()
            mutate(recipe)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                verify(projection, recipe)

    def test_type_confusion_does_not_match_numeric_fields(self):
        projection, recipe = fixture()
        projection['Config']['Healthcheck']['Retries'] = True
        with self.assertRaises(ValueError):
            verify(projection, recipe)


if __name__ == '__main__':
    unittest.main()
