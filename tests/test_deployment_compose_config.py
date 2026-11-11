"""Synthetic observed-shape tests; no Engine reconstruction claims."""
import copy
import hashlib
import hmac
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packs/deployment/scripts"))

from deployment_compose_config import (DOMAIN, canonical_config, commit_config,
                                      map_config, verify_config)


def context():
    return dict(project='sample', service='app', containerId='a' * 64,
                containerName='sample-app-1', imageId='sha256:' + 'b' * 64)


def config():
    return dict(AttachStderr=True, AttachStdin=False, AttachStdout=True,
                Cmd=[''], Domainname='', Entrypoint=None, Env=['Z=last', 'A=a=b'],
                Healthcheck=dict(Test=['CMD', 'true'], Interval=1000000000,
                                 Timeout=1000000000, Retries=3, StartPeriod=5000000000),
                Hostname='012345678abc', Image='example@sha256:' + 'c' * 64,
                Labels={'com.docker.compose.project': 'sample',
                        'com.docker.compose.service': 'app',
                        'com.docker.compose.config-hash': 'literal', 'custom': 'private'},
                OpenStdin=False, StdinOnce=False, Tty=False, User='', Volumes=None, WorkingDir='/app')


class ConfigTests(unittest.TestCase):
    def test_exact_snapshot_and_private_domain(self):
        raw = config()
        self.assertEqual(len(raw), 17)
        mapped = map_config(raw, context())
        self.assertEqual(mapped['rawConfig'], raw)
        self.assertFalse(mapped['authorityGranted'])
        self.assertFalse(mapped['executionAvailable'])
        self.assertFalse(mapped['reconstructionValidated'])
        raw['Labels']['custom'] = 'changed'
        self.assertEqual(mapped['rawConfig']['Labels']['custom'], 'private')
        key = b'k' * 32
        expected = hmac.new(key, DOMAIN + b'\0\x01k' + canonical_config(mapped), hashlib.sha256).hexdigest()
        commitment = commit_config(mapped, 'k', key)
        self.assertEqual(commitment['hmac'], expected)
        self.assertTrue(verify_config(mapped, commitment, key))

    def test_missing_empty_and_null_ports_distinct(self):
        values = []
        for port in ('missing', None, {}, {'80/tcp': {}}):
            raw = config()
            if port != 'missing':
                raw['ExposedPorts'] = port
            values.append(canonical_config(map_config(raw, context())))
        self.assertEqual(len(set(values)), 4)

    def test_vectors_and_optional_health_preserved(self):
        for vector in (None, [], ['']):
            raw = config()
            raw['Cmd'] = raw['Entrypoint'] = vector
            self.assertEqual(map_config(raw, context())['rawConfig'], raw)
        raw['Healthcheck']['StartInterval'] = 0
        self.assertEqual(map_config(raw, context())['rawConfig'], raw)

    def test_every_literal_and_identity_drift_changes_commitment(self):
        original = map_config(config(), context())
        digest = commit_config(original, 'k', b'k' * 32)
        mutations = [lambda m: m['rawConfig'].__setitem__('Hostname', 'different'),
                     lambda m: m['rawConfig']['Env'].reverse(),
                     lambda m: m['rawConfig']['Labels'].__setitem__('com.docker.compose.config-hash', 'other'),
                     lambda m: m['context'].__setitem__('containerId', 'd' * 64),
                     lambda m: m['rawConfig'].__setitem__('Volumes', {})]
        for mutate in mutations:
            mapped = copy.deepcopy(original)
            mutate(mapped)
            self.assertNotEqual(commit_config(mapped, 'k', b'k' * 32), digest)

    def test_reject_invalid_values_without_disclosing_input(self):
        changes = [('Extra', 'secret'), ('AttachStdin', 0), ('Cmd', 'secret'),
                   ('Volumes', {'/data': {}}), ('Env', ['A=secret', 'A=other']),
                   ('Labels', {'com.docker.compose.project': 'wrong'}),
                   ('Hostname', 's' * 8193), ('ExposedPorts', {'65536/tcp': {}})]
        for field, value in changes:
            with self.subTest(field=field):
                raw = config()
                raw[field] = value
                with self.assertRaisesRegex(ValueError, '^invalid-compose-observed-config$'):
                    map_config(raw, context())
        for field in config():
            raw = config()
            del raw[field]
            with self.assertRaises(ValueError):
                map_config(raw, context())
        for field in ('Interval', 'Timeout', 'Retries', 'StartPeriod', 'StartInterval'):
            for invalid in (True, -1, 60_000_000_001):
                raw = config()
                raw['Healthcheck'][field] = invalid
                with self.assertRaises(ValueError):
                    map_config(raw, context())
        raw = config()
        raw['Env'] = [f'KEY{i}=' + 's' * 8000 for i in range(12)]
        with self.assertRaises(ValueError):
            map_config(raw, context())
        raw = config()
        raw['Healthcheck']['Test'] = ['CMD-SHELL', 'secret']
        with self.assertRaises(ValueError):
            map_config(raw, context())

    def test_invalid_context_and_mapping(self):
        for field in context():
            identity = context()
            identity[field] = None
            with self.assertRaises(ValueError):
                map_config(config(), identity)
        for flag in ('authorityGranted', 'executionAvailable', 'reconstructionValidated'):
            mapped = map_config(config(), context())
            mapped[flag] = True
            with self.assertRaises(ValueError):
                canonical_config(mapped)


if __name__ == '__main__':
    unittest.main()
