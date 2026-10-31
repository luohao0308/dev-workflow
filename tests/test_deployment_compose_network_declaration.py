from copy import deepcopy
import hashlib
import unittest

from tests.test_deployment_compose_snapshot import fixture as source_fixture, KEY, rebind
from deployment_compose_snapshot import prepare_snapshot, _encode
from deployment_compose_network_declaration import commit_network_declaration, bind_network_declaration

DKEY = b'declaration-test-key-' + b'x'*32


def fixture():
    args = source_fixture()
    raw, identity, artifact, networks, mounts = args
    snapshot = prepare_snapshot(raw, identity, artifact, KEY, networks, mounts)
    declaration = {'schemaVersion': 1, 'identity': deepcopy(identity), 'sourceSha': artifact.source_sha,
        'sourceModelDigest': 'e'*64, 'sourceSnapshotDigest': hashlib.sha256(_encode(snapshot)).hexdigest(),
        'networks': {name: {'id': nid, 'aliases': deepcopy(raw['NetworkSettings']['Networks'][name]['Aliases']),
            'addressPolicy': 'dynamic-no-requested-addresses', 'requestedMac': None,
            'ipamConfig': None, 'links': None, 'driverOpts': None} for name, nid in networks.items()}}
    return args, declaration


def build(args, declaration, proof=None, **pins):
    raw, identity, artifact, networks, mounts = args
    if proof is None:
        proof = commit_network_declaration(declaration, 'declaration-key', DKEY)
    options = dict(expected_key_id='declaration-key', expected_declaration_hmac=proof['declarationHmac'],
                   expected_source_model_digest='e'*64)
    options.update(pins)
    return bind_network_declaration(raw, identity, artifact, KEY, networks, mounts,
                                     declaration, proof, DKEY, **options)


class NetworkDeclarationTests(unittest.TestCase):
    def test_bound_assertion_only_no_runtime_addresses_or_authority(self):
        args, dec = fixture(); before = deepcopy((args, dec))
        result = build(args, dec)
        self.assertEqual((args, dec), before)
        self.assertTrue(result['hostAssertionAuthenticated'])
        self.assertEqual(result['networkFragment']['sample_default'],
            {'NetworkID': args[3]['sample_default'], 'Aliases': ['app', 'custom']})
        for flag in ('sourceModelProvenanceVerified', 'addressOriginIndependentlyVerified', 'freshnessVerified',
                     'completeCreatePayloadAvailable', 'authorityGranted', 'executionAvailable',
                     'reconstructionValidated', 'productionReady'):
            self.assertIs(result[flag], False)
        dec['networks']['sample_default']['aliases'].append('later')
        self.assertEqual(result['networkFragment']['sample_default']['Aliases'], ['app', 'custom'])

    def test_tampered_commitment_or_independent_pins_reject(self):
        args, dec = fixture(); proof = commit_network_declaration(dec, 'declaration-key', DKEY)
        for pins in ({'expected_key_id': 'other'}, {'expected_declaration_hmac': '0'*64},
                     {'expected_source_model_digest': 'f'*64}):
            with self.assertRaises(ValueError):
                build(args, dec, proof, **pins)
        dec['networks']['sample_default']['aliases'].reverse()
        with self.assertRaises(ValueError):
            build(args, dec, proof)

    def test_even_resigned_wrong_source_identity_and_scope_reject(self):
        for field, value in [('sourceSha', 'b'*40), ('sourceSnapshotDigest', 'f'*64),
                             ('sourceModelDigest', 'f'*64), ('identity', {})]:
            args, dec = fixture(); dec[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                build(args, dec)
        for field, value in [('id', 'f'*64), ('aliases', ['foreign']), ('aliases', ['custom', 'app'])]:
            args, dec = fixture(); dec['networks']['sample_default'][field] = value
            with self.assertRaises(ValueError):
                build(args, dec)

    def test_unreviewed_declaration_forms_reject(self):
        for field, value in [('addressPolicy', 'infer-from-inspect'), ('requestedMac', '02:42:ac:14:00:03'),
                             ('ipamConfig', {}), ('links', []), ('driverOpts', {}),
                             ('aliases', []), ('aliases', ['app', 'app']), ('aliases', [True]), ('extra', None)]:
            args, dec = fixture(); dec['networks']['sample_default'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                build(args, dec)

    def test_authenticated_observation_contradictions_reject(self):
        for field, value in [('IPAMConfig', {}), ('Links', []), ('DriverOpts', {}), ('GwPriority', 1)]:
            args, dec = fixture(); raw, identity, artifact, networks, mounts = args
            raw['NetworkSettings']['Networks']['sample_default'][field] = value
            args = (raw, identity, rebind(raw, identity, artifact), networks, mounts)
            snapshot = prepare_snapshot(raw, identity, args[2], KEY, networks, mounts)
            dec['sourceSnapshotDigest'] = hashlib.sha256(_encode(snapshot)).hexdigest()
            with self.subTest(field=field), self.assertRaises(ValueError):
                build(args, dec)

    def test_source_hmac_drift_rejects_before_declaration_can_excuse_it(self):
        args, dec = fixture()
        args[0]['Config']['Env'].append('TAMPERED=secret')
        with self.assertRaisesRegex(ValueError, '^invalid-compose-network-declaration$'):
            build(args, dec)

    def test_wrong_key_and_key_identity_change_mac(self):
        _, dec = fixture()
        one = commit_network_declaration(dec, 'declaration-key', DKEY)
        self.assertNotEqual(one['declarationHmac'], commit_network_declaration(dec, 'other', DKEY)['declarationHmac'])
        args, dec = fixture()
        other = commit_network_declaration(dec, 'declaration-key', b'z'*32)
        with self.assertRaises(ValueError):
            build(args, dec, other)


if __name__ == '__main__':
    unittest.main()
