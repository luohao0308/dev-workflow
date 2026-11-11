"""Private literal network evidence; fixtures grant no Docker authority."""
import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_network import (DOMAIN, canonical_network, map_network_settings,
                                       commit_network, verify_network)
from tests.test_deployment_compose_config import context


def fixture():
    return {'SandboxID': 'sandbox', 'SandboxKey': '/private/sandbox', 'Ports': {'8080/tcp': None},
            'Networks': {'sample_default': {'NetworkID': 'c' * 64, 'EndpointID': 'd' * 64,
                'Aliases': ['app', 'custom'], 'DNSNames': ['app', 'container-name'],
                'IPAMConfig': None, 'Links': None, 'DriverOpts': None,
                'Gateway': '172.20.0.1', 'IPAddress': '172.20.0.3', 'IPPrefixLen': 16,
                'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0,
                'MacAddress': '02:42:ac:14:00:03', 'GwPriority': 0}}}


class NetworkTests(unittest.TestCase):
    def test_roundtrip_separate_domain_and_no_authority(self):
        raw = fixture()
        mapped = map_network_settings(raw, context())
        self.assertEqual(json.loads(canonical_network(mapped))['rawNetworkSettings'], raw)
        key = b'k' * 32
        result = commit_network(mapped, 'key', key)
        expected = hmac.new(key, DOMAIN + b'\x00\x03key' + canonical_network(mapped), hashlib.sha256).hexdigest()
        self.assertEqual(result, {'keyId': 'key', 'hmac': expected})
        self.assertTrue(verify_network(mapped, result, key))
        self.assertFalse(verify_network(mapped, result, b'x' * 32))
        for field in ('authorityGranted', 'executionAvailable', 'reconstructionValidated'):
            self.assertIs(mapped[field], False)
        raw['Networks']['sample_default']['Aliases'].append('changed')
        self.assertNotEqual(mapped['rawNetworkSettings'], raw)

    def test_configurable_runtime_and_context_drift_change_commitment(self):
        base = map_network_settings(fixture(), context())
        digest = commit_network(base, 'key', b'k' * 32)['hmac']
        for field, value in [('Aliases', ['other']), ('DNSNames', ['other']), ('GwPriority', -1),
            ('IPAMConfig', {'IPv4Address': '172.20.0.4'}), ('DriverOpts', {'option': 'private-value'}),
            ('Links', ['db:db']), ('MacAddress', '02:42:ac:14:00:04'), ('IPAddress', '172.20.0.4')]:
            raw = fixture()
            raw['Networks']['sample_default'][field] = value
            with self.subTest(field=field):
                self.assertNotEqual(commit_network(map_network_settings(raw, context()), 'key', b'k' * 32)['hmac'], digest)
        changed = context()
        changed['containerId'] = 'b' * 64
        self.assertNotEqual(commit_network(map_network_settings(fixture(), changed), 'key', b'k' * 32)['hmac'], digest)

    def test_missing_priority_and_null_empty_values_are_not_normalized(self):
        variants = []
        for mode in ('absent', 'zero'):
            raw = fixture()
            if mode == 'absent':
                raw['Networks']['sample_default'].pop('GwPriority')
            variants.append(commit_network(map_network_settings(raw, context()), 'key', b'k' * 32)['hmac'])
        self.assertEqual(len(set(variants)), 2)
        variants = []
        for value in (None, {}, {'IPv4Address': ''}):
            raw = fixture()
            raw['Networks']['sample_default']['IPAMConfig'] = value
            variants.append(commit_network(map_network_settings(raw, context()), 'key', b'k' * 32)['hmac'])
        self.assertEqual(len(set(variants)), 3)

    def test_unknown_invalid_and_oversize_inputs_fail_without_values(self):
        mutations = [lambda x: x.update(UnknownOption='private-value'),
            lambda x: x['Networks']['sample_default'].update(UnknownOption='private-value'),
            lambda x: x['Networks']['sample_default'].update(GwPriority=True),
            lambda x: x['Networks']['sample_default'].update(IPPrefixLen=True),
            lambda x: x['Networks']['sample_default'].update(DriverOpts={'bad': []}),
            lambda x: x['Networks']['sample_default'].update(IPAMConfig={'Unknown': 'private-value'}),
            lambda x: x.update(Ports={'8080/tcp': [{'HostIp': '', 'HostPort': '65536'}]}),
            lambda x: x.update(SandboxKey='private-value' * 4096),
            lambda x: x['Networks']['sample_default'].pop('DNSNames')]
        for change in mutations:
            raw = fixture()
            change(raw)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, '^invalid-compose-observed-network$'):
                map_network_settings(raw, context())
        raw = fixture()
        raw['Networks'] = raw
        with self.assertRaises(ValueError):
            map_network_settings(raw, context())

    def test_flags_and_commitment_shapes_cannot_be_promoted(self):
        mapped = map_network_settings(fixture(), context())
        mapped['authorityGranted'] = True
        with self.assertRaises(ValueError):
            canonical_network(mapped)
        with self.assertRaises(ValueError):
            verify_network(map_network_settings(fixture(), context()), {'keyId': 'key', 'hmac': 'bad'}, b'k' * 32)


if __name__ == '__main__':
    unittest.main()
