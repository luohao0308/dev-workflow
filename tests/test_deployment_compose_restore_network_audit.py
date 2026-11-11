from copy import deepcopy
from unittest.mock import patch
import unittest

from tests.test_deployment_compose_snapshot import fixture, rebind, KEY
import deployment_compose_restore_network_audit as audit


def build(args):
    raw, identity, artifact, networks, mounts = args
    return audit.audit_restore_network(raw, identity, artifact, KEY, networks, mounts)


class RestoreNetworkAuditTests(unittest.TestCase):
    def test_all_original_fields_partitioned_without_create_payload(self):
        args = fixture(); before = deepcopy(args)
        result = build(args)
        self.assertEqual(args, before)
        for name, endpoint in args[0]['NetworkSettings']['Networks'].items():
            parts = result['endpoints'][name]
            merged = {k: v for part in parts.values() for k, v in part.items()}
            self.assertEqual(merged, endpoint)
            self.assertEqual(sum(len(p) for p in parts.values()), len(endpoint))
        for flag in ('declarationOriginVerified', 'dynamicAddressOriginVerified',
                     'writeApiSemanticsVerified', 'completeCreatePayloadAvailable',
                     'authorityGranted', 'executionAvailable', 'reconstructionValidated', 'productionReady'):
            self.assertIs(result[flag], False)
        self.assertFalse({'method', 'path', 'NetworkingConfig', 'EndpointsConfig'} & result.keys())

    def test_mac_and_ipam_never_become_origin_proof(self):
        for ipam in (None, {}, {'IPv4Address': '172.20.0.3'}):
            raw, identity, artifact, networks, mounts = fixture()
            endpoint = raw['NetworkSettings']['Networks']['sample_default']
            endpoint.update(MacAddress='02:42:ac:14:00:03', IPAMConfig=ipam)
            result = build((raw, identity, rebind(raw, identity, artifact), networks, mounts))
            self.assertFalse(result['dynamicAddressOriginVerified'])
            self.assertEqual(result['endpoints']['sample_default']['ambiguousOriginEvidence'],
                             {'MacAddress': '02:42:ac:14:00:03'})

    def test_optional_priority_preserved_without_api_support_inference(self):
        digests = []
        for priority in (None, 0, 1):
            raw, identity, artifact, networks, mounts = fixture()
            endpoint = raw['NetworkSettings']['Networks']['sample_default']
            endpoint.pop('GwPriority', None)
            if priority is not None:
                endpoint['GwPriority'] = priority
            result = build((raw, identity, rebind(raw, identity, artifact), networks, mounts))
            self.assertEqual(result['endpoints']['sample_default']['writeVersionUnverifiedEvidence'],
                             {} if priority is None else {'GwPriority': priority})
            digests.append(result['auditDigest'])
        self.assertEqual(len(set(digests)), 3)

    def test_source_hmac_topology_and_unknown_fields_fail_closed(self):
        args = fixture()
        args[0]['NetworkSettings']['Networks']['sample_default']['Aliases'].append('tampered')
        with self.assertRaisesRegex(ValueError, '^invalid-compose-restore-network-audit$'):
            build(args)
        raw, identity, artifact, networks, mounts = fixture()
        networks['sample_default'] = 'f'*64
        with self.assertRaises(ValueError):
            build((raw, identity, artifact, networks, mounts))
        with patch.object(audit, 'ENDPOINT_FIELDS', audit.ENDPOINT_FIELDS | {'FutureField'}):
            with self.assertRaises(ValueError):
                build(fixture())

    def test_private_values_detached_and_identity_bound(self):
        args = fixture(); first = build(args)
        changed = (args[0], dict(args[1], daemonId='another-daemon'), *args[2:])
        self.assertNotEqual(first['auditDigest'], build(changed)['auditDigest'])
        original = deepcopy(first['endpoints'])
        args[0]['NetworkSettings']['Networks']['sample_default']['Aliases'].append('later')
        self.assertEqual(first['endpoints'], original)


if __name__ == '__main__':
    unittest.main()
