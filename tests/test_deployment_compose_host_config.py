import copy
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
import deployment_compose_host_config as hc


def fixture():
    h = {k: False for k in hc.BOOLS}
    h.update({k: '' for k in hc.STRINGS})
    h.update({k: 0 for k in hc.INTS})
    h.update({k: None for k in hc.VECTORS | hc.NULLS})
    h.update(ConsoleSize=[0, 0], LogConfig={'Type': 'json-file', 'Config': {'max-file': '3', 'max-size': '10m'}},
             MemorySwappiness=None, OomKillDisable=None, PidsLimit=32, PortBindings={},
             RestartPolicy={'Name': 'unless-stopped', 'MaximumRetryCount': 0}, Tmpfs={'/tmp': 'size=4m'},
             Mounts=[{'Type': 'volume', 'Source': 'sample-data', 'Target': '/data', 'VolumeOptions': {'NoCopy': True}},
                     {'Type': 'bind', 'Source': '/sample/config', 'Target': '/config', 'ReadOnly': True, 'BindOptions': {}}])
    h.update(CgroupnsMode='private', IpcMode='private', Runtime='runc', NetworkMode='sample_default',
             ExtraHosts=[], MaskedPaths=['/proc/keys'], ReadonlyPaths=['/proc/sys'], Memory=67108864,
             MemorySwap=67108864, NanoCpus=100000000, ShmSize=67108864, ReadonlyRootfs=True)
    return h


class HostConfigTests(unittest.TestCase):
    def setUp(self):
        self.h = fixture()
        self.context = dict(project='sample', service='api', containerName='sample-api-1', containerId='a' * 64, imageId='sha256:' + 'b' * 64)
        self.key = b'k' * 32

    def mapping(self, h=None):
        return hc.map_host_config(self.h if h is None else h, self.context)

    def reject(self, h):
        with self.assertRaisesRegex(ValueError, '^invalid-compose-observed-host-config$'):
            self.mapping(h)

    def test_exact_snapshot_and_commitment(self):
        m = self.mapping()
        self.assertEqual(json.loads(hc.canonical_host_config(m))['rawHostConfig'], self.h)
        c = hc.commit_host_config(m, 'host', self.key)
        self.assertTrue(hc.verify_host_config(m, c, self.key))
        self.assertFalse(hc.verify_host_config(m, c, b'x' * 32))
        self.h['LogConfig']['Config']['max-size'] = '20m'
        self.assertEqual(m['rawHostConfig']['LogConfig']['Config']['max-size'], '10m')
        for flag in ('authorityGranted', 'executionAvailable', 'reconstructionValidated'):
            self.assertIs(m[flag], False)
            bad = copy.deepcopy(m); bad[flag] = True
            with self.assertRaises(ValueError): hc.canonical_host_config(bad)

    def test_optional_mount_identity(self):
        values = []
        for value in ('missing', None, []):
            h = fixture()
            if value == 'missing': del h['Mounts']
            else: h['Mounts'] = value
            values.append(hc.canonical_host_config(self.mapping(h)))
        self.assertEqual(len(set(values)), 3)

    def test_mutations_across_entire_surface_change_mac(self):
        base = hc.commit_host_config(self.mapping(), 'host', self.key)
        for k, v in fixture().items():
            with self.subTest(field=k):
                h = fixture()
                if k in hc.NULLS: continue  # Only null has observed support.
                if type(v) is bool: h[k] = not v
                elif type(v) is int: h[k] += 1
                elif type(v) is str: h[k] += 'x'
                elif k in hc.VECTORS: h[k] = ['changed']
                elif k in ('MemorySwappiness', 'PidsLimit'): h[k] = 1
                elif k == 'OomKillDisable': h[k] = True
                elif k == 'ConsoleSize': h[k] = [1, 2]
                elif k == 'LogConfig': h[k]['Config']['max-file'] = '4'
                elif k == 'RestartPolicy': h[k]['MaximumRetryCount'] = 1
                elif k == 'Tmpfs': h[k]['/tmp'] = 'size=8m'
                elif k == 'Mounts': h[k][0]['VolumeOptions']['NoCopy'] = False
                elif k == 'PortBindings': continue
                else: self.fail(k)
                self.assertFalse(hc.verify_host_config(self.mapping(h), base, self.key))
        for k in self.context:
            context = dict(self.context); context[k] = 'c' * 64 if k == 'containerId' else ('sha256:' + 'c' * 64 if k == 'imageId' else 'different')
            self.assertFalse(hc.verify_host_config(hc.map_host_config(self.h, context), base, self.key))

    def test_unknown_missing_and_bad_types(self):
        for k in hc.REQUIRED:
            h = fixture(); del h[k]; self.reject(h)
        for k in hc.BOOLS | hc.STRINGS | hc.INTS | hc.VECTORS | hc.NULLS:
            h = fixture(); h[k] = {}; self.reject(h)
        for k in hc.INTS | {'PidsLimit', 'MemorySwappiness'}:
            h = fixture(); h[k] = True; self.reject(h)
        h = fixture(); h['secret-extra'] = 'sensitive'; self.reject(h)
        for k in ('LogConfig', 'RestartPolicy'):
            h = fixture(); h[k]['secret-extra'] = 'sensitive'; self.reject(h)
        for k in ('VolumeOptions', 'BindOptions'):
            h = fixture(); h['Mounts'][0 if k == 'VolumeOptions' else 1][k]['secret-extra'] = 'sensitive'; self.reject(h)

    def test_bounds_cycles_and_nested_types(self):
        for k, v in [('Runtime', 'sensitive' * 8193), ('Memory', 2**63), ('MaskedPaths', ['a'] * 129),
                     ('Tmpfs', {'/tmp': False}), ('ConsoleSize', [True, 0]), ('Mounts', [None]),
                     ('PortBindings', {'80/tcp': []}), ('Devices', [])]:
            h = fixture(); h[k] = v; self.reject(h)
        h = fixture(); h['MaskedPaths'] = [h]; self.reject(h)
        h = fixture(); h['Mounts'][0]['VolumeOptions'] = h; self.reject(h)
        h = fixture(); h['LogConfig']['Config'] = {str(i): 'x' * 8192 for i in range(128)}; self.reject(h)


if __name__ == '__main__':
    unittest.main()
