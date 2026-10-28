"""Explicit candidate fields are diagnostic, never reconstruction authority."""
from copy import deepcopy
import hashlib
import json
import unittest

from tests.test_deployment_compose_create import fixture
from deployment_compose_create import compile_create, DOMAIN, _encode
from deployment_compose_create_inspect import compare_create_inspect, compare_create_inspect_wire

RECEIPT = 'a' * 64


def sample():
    recipe, args = fixture()
    candidate = compile_create(recipe, **args)
    body = candidate['body']
    observed = {'Id': RECEIPT, 'Name': '/' + candidate['identity']['containerName'],
        'Image': body['Image'], 'Config': {k: deepcopy(v) for k, v in body.items()
            if k not in ('HostConfig', 'NetworkingConfig')},
        'HostConfig': deepcopy(body['HostConfig']),
        'Mounts': [dict(Type=m['Type'], Destination=m['Target'],
            Source=m['Source'] if m['Type'] == 'bind' else '/private/engine/path',
            Name=m['Source'] if m['Type'] == 'volume' else '', RW=not m['ReadOnly'])
            for m in body['HostConfig']['Mounts']],
        'NetworkSettings': {'Networks': deepcopy(body['NetworkingConfig']['EndpointsConfig'])}}
    return candidate, observed


class CompareTests(unittest.TestCase):
    def compare(self, candidate, observed):
        return compare_create_inspect(candidate, observed, expected_receipt_id=RECEIPT)

    def test_matching_explicit_subset_never_grants_equivalence_or_authority(self):
        candidate, observed = sample()
        result = self.compare(candidate, observed)
        self.assertTrue(result['explicitRequestedFieldsMatch'])
        self.assertEqual(result['mismatchPaths'], [])
        for key in ('wholeInspectEquivalenceEstablished', 'authorityGranted',
                    'executionAvailable', 'reconstructionValidated', 'productionReady'):
            self.assertIs(result[key], False)

    def test_explicit_config_drift_values_do_not_escape(self):
        for field, value in [('Env', ['SECRET=very-private']), ('Hostname', 'secret-host'),
                             ('Labels', {'secret-label': 'private'}), ('Cmd', ['private-command']),
                             ('Volumes', None)]:
            candidate, observed = sample()
            observed['Config'][field] = value
            result = self.compare(candidate, observed)
            self.assertEqual(result['mismatchPaths'], ['Config.' + field])
            self.assertNotIn('very-private', json.dumps(result))
            self.assertNotIn('secret-label', json.dumps(result))
            self.assertNotIn('private-command', json.dumps(result))

    def test_host_resource_security_mount_log_drift(self):
        for field, value in [('Memory', 123), ('NanoCpus', 123), ('PidsLimit', 1),
            ('Privileged', True), ('ReadonlyRootfs', False), ('NetworkMode', 'other'),
            ('Mounts', []), ('LogConfig', {'Type': 'json-file', 'Config': {}})]:
            candidate, observed = sample()
            if observed['HostConfig'][field] == value:
                value = not value
            observed['HostConfig'][field] = value
            self.assertEqual(self.compare(candidate, observed)['mismatchPaths'], ['HostConfig.' + field])
        candidate, observed = sample()
        observed['HostConfig']['Mounts'][0]['VolumeOptions']['NoCopy'] = False
        self.assertEqual(self.compare(candidate, observed)['mismatchPaths'], ['HostConfig.Mounts'])

    def test_network_id_empty_alias_order_and_network_extras_not_normalized(self):
        for field, value in [('NetworkID', ''), ('Aliases', ['secret-alias']), ('Aliases', None)]:
            candidate, observed = sample()
            endpoint = next(iter(observed['NetworkSettings']['Networks'].values()))
            endpoint[field] = value
            result = self.compare(candidate, observed)
            self.assertEqual(result['mismatchPaths'], ['NetworkSettings.Networks.endpoint.' + field])
            self.assertNotIn('secret-alias', json.dumps(result))
        candidate, observed = sample()
        observed['NetworkSettings']['Networks']['private-other-name'] = {}
        result = self.compare(candidate, observed)
        self.assertEqual(result['mismatchPaths'], ['NetworkSettings.Networks'])
        self.assertNotIn('private-other-name', json.dumps(result))

    def test_missing_explicit_fields_are_drift(self):
        candidate, observed = sample()
        del observed['Config']['StopSignal']
        self.assertEqual(self.compare(candidate, observed)['mismatchPaths'], ['Config.StopSignal'])

    def test_observed_extras_are_names_only_and_unknown_names_redacted(self):
        candidate, observed = sample()
        observed['State'] = {'Error': 'secret-error'}
        observed['Config']['secret-name'] = 'secret-value'
        observed['HostConfig']['SecurityOpt'] = ['secret-security']
        next(iter(observed['NetworkSettings']['Networks'].values()))['IPAddress'] = 'secret-ip'
        result = self.compare(candidate, observed)
        self.assertTrue(result['explicitRequestedFieldsMatch'])
        self.assertEqual(result['observedExtraFields']['inspect'], ['State'])
        self.assertEqual(result['observedExtraFields']['HostConfig'], ['SecurityOpt'])
        self.assertEqual(result['unlistedExtraFieldCounts']['Config'], 1)
        self.assertNotIn('secret-', json.dumps(result))

    def test_name_and_resolved_image_drift(self):
        candidate, observed = sample()
        observed.update(Name='/other', Image='sha256:' + 'f' * 64)
        self.assertEqual(self.compare(candidate, observed)['mismatchPaths'], ['Image', 'Name'])

    def test_malformed_receipt_types_and_digest_are_generic_errors(self):
        mutations = [lambda c,o: c['body'].update(Env=['SECRET=tampered']),
            lambda c,o: c.update(candidateDigest='f' * 64),
            lambda c,o: o.update(Id='b' * 64), lambda c,o: o.update(Config=[]),
            lambda c,o: o.update(HostConfig=None),
            lambda c,o: o['Config'].update(Env=1),
            lambda c,o: o['HostConfig'].update(Memory=True),
            lambda c,o: o['NetworkSettings'].update(Networks=[]),
            lambda c,o: o['NetworkSettings'].update(Networks={'other': []}),
            lambda c,o: o.update(State={'bad': float('nan')})]
        for mutate in mutations:
            candidate, observed = sample()
            mutate(candidate, observed)
            with self.assertRaisesRegex(ValueError, '^invalid-compose-create-inspect$'):
                self.compare(candidate, observed)
        candidate, observed = sample()
        with self.assertRaisesRegex(ValueError, '^invalid-compose-create-inspect$'):
            compare_create_inspect(candidate, observed, expected_receipt_id=True)

    def test_rehashed_unknown_candidate_shape_cannot_inject_output_path(self):
        candidate, observed = sample()
        candidate['body']['secret-field-name'] = 'private'
        candidate.pop('candidateDigest')
        candidate['candidateDigest'] = hashlib.sha256(DOMAIN + _encode(candidate)).hexdigest()
        with self.assertRaisesRegex(ValueError, '^invalid-compose-create-inspect$'):
            self.compare(candidate, observed)

    def test_resolved_mounts_match_by_destination_not_order_or_volume_host_path(self):
        candidate, observed = sample()
        observed['Mounts'].reverse()
        for mount in observed['Mounts']:
            if mount['Type'] == 'volume':
                mount['Source'] = '/another/private/engine/path'
        self.assertTrue(self.compare(candidate, observed)['explicitRequestedFieldsMatch'])

    def test_resolved_mount_semantic_drift_paths_never_reveal_values(self):
        for kind, field, value, path in (
            ('bind', 'Source', '/secret/source', 'Mounts.bindSource'),
            ('volume', 'Name', 'secret-volume', 'Mounts.volumeName'),
            ('bind', 'RW', True, 'Mounts.readWrite'),
            ('bind', 'Destination', '/secret/target', 'Mounts.destinations'),
            ('bind', 'Type', 'tmpfs', 'Mounts.type')):
            candidate, observed = sample()
            mount = next(m for m in observed['Mounts'] if m['Type'] == kind)
            if field == 'RW':
                value = not mount[field]
            mount[field] = value
            result = self.compare(candidate, observed)
            self.assertEqual(result['mismatchPaths'], [path])
            self.assertNotIn('secret', json.dumps(result))
        candidate, observed = sample()
        observed['Mounts'] = []
        self.assertEqual(self.compare(candidate, observed)['mismatchPaths'], ['Mounts.destinations'])

    def test_malformed_or_duplicate_resolved_mounts_rejected(self):
        for mutate in (lambda o: o.update(Mounts=None),
                       lambda o: o.update(Mounts=[None]),
                       lambda o: o['Mounts'][0].update(RW=1),
                       lambda o: o['Mounts'][0].update(Destination=None),
                       lambda o: o['Mounts'][0].update(Name=None),
                       lambda o: o['Mounts'].append(deepcopy(o['Mounts'][0]))):
            candidate, observed = sample()
            mutate(observed)
            with self.assertRaisesRegex(ValueError, '^invalid-compose-create-inspect$'):
                self.compare(candidate, observed)

    def test_inputs_are_not_mutated(self):
        candidate, observed = sample()
        before = deepcopy((candidate, observed))
        self.compare(candidate, observed)
        self.assertEqual((candidate, observed), before)


class WireTests(unittest.TestCase):
    def sample_wire(self):
        candidate, observed = sample()
        _, args = fixture()
        observed['Config']['Volumes'] = None
        del observed['Config']['ExposedPorts']
        del observed['Config']['StopSignal']
        del observed['Config']['Healthcheck']['StartPeriod']
        del observed['Config']['Healthcheck']['StartInterval']
        for mount in observed['HostConfig']['Mounts']:
            if mount['ReadOnly'] is False:
                del mount['ReadOnly']
            if mount['Type'] == 'bind':
                del mount['BindOptions']['CreateMountpoint']
        return candidate, observed, args['image_defaults']

    def compare(self, candidate, observed, defaults):
        return compare_create_inspect_wire(candidate, observed,
            expected_receipt_id=RECEIPT, image_defaults=defaults)

    def test_exact_five_omissions_explained_without_changing_literal_results(self):
        candidate, observed, defaults = self.sample_wire()
        before = deepcopy((candidate, observed, defaults))
        result = self.compare(candidate, observed, defaults)
        self.assertFalse(result['explicitRequestedFieldsMatch'])
        self.assertEqual(result['mismatchPaths'], ['Config.ExposedPorts', 'Config.Healthcheck',
            'Config.StopSignal', 'Config.Volumes', 'HostConfig.Mounts'])
        self.assertEqual(result['wireExplainedMismatchPaths'], result['mismatchPaths'])
        self.assertEqual(result['unexplainedMismatchPaths'], [])
        self.assertTrue(result['requestedFieldsMatchUnderWireProfile'])
        for key in ('authorityGranted', 'executionAvailable', 'productionReady',
                    'reconstructionValidated', 'wholeInspectEquivalenceEstablished'):
            self.assertIs(result[key], False)
        self.assertEqual(before, (candidate, observed, defaults))

    def test_other_drifts_still_unexplained(self):
        mutations = [
            (lambda o: o['Config'].update(Env=['SECRET=private']), 'Config.Env'),
            (lambda o: o['HostConfig'].update(Memory=123), 'HostConfig.Memory'),
            (lambda o: next(iter(o['NetworkSettings']['Networks'].values())).update(Aliases=['secret']),
             'NetworkSettings.Networks.endpoint.Aliases'),
            (lambda o: o['HostConfig']['Mounts'][0]['VolumeOptions'].update(NoCopy=False), 'HostConfig.Mounts'),
            (lambda o: o['HostConfig']['Mounts'].reverse(), 'HostConfig.Mounts'),
            (lambda o: o['HostConfig']['Mounts'][1]['BindOptions'].update(Propagation='shared'), 'HostConfig.Mounts'),
            (lambda o: o['Config'].pop('Volumes'), 'Config.Volumes'),
            (lambda o: o['Config'].update(ExposedPorts=None), 'Config.ExposedPorts'),
            (lambda o: o['Config'].update(StopSignal='SIGTERM'), 'Config.StopSignal'),
            (lambda o: o['Config']['Healthcheck'].update(Timeout=1), 'Config.Healthcheck')]
        for mutate, path in mutations:
            candidate, observed, defaults = self.sample_wire()
            mutate(observed)
            result = self.compare(candidate, observed, defaults)
            self.assertFalse(result['requestedFieldsMatchUnderWireProfile'])
            self.assertIn(path, result['unexplainedMismatchPaths'])
            self.assertNotIn('private', json.dumps(result))

    def test_bound_empty_image_inputs_required_even_for_rehashed_defaults(self):
        from deployment_compose_create import _digest
        for key, value in [('Volumes', {'/private': {}}), ('Healthcheck', {'Test': ['NONE']}),
                           ('ExposedPorts', {'80/tcp': {}}), ('StopSignal', None)]:
            candidate, observed, defaults = self.sample_wire()
            defaults[key] = value
            candidate['imageDefaultsDigest'] = _digest(defaults)
            candidate.pop('candidateDigest')
            candidate['candidateDigest'] = hashlib.sha256(DOMAIN + _encode(candidate)).hexdigest()
            with self.assertRaisesRegex(ValueError, '^invalid-compose-create-inspect$'):
                self.compare(candidate, observed, defaults)
        candidate, observed, defaults = self.sample_wire()
        defaults['Cmd'] = ['tampered']
        with self.assertRaisesRegex(ValueError, '^invalid-compose-create-inspect$'):
            self.compare(candidate, observed, defaults)

    def test_empty_image_volumes_map_does_not_explain_null_observation(self):
        from deployment_compose_create import _digest
        candidate, observed, defaults = self.sample_wire()
        defaults['Volumes'] = {}
        candidate['imageDefaultsDigest'] = _digest(defaults)
        candidate.pop('candidateDigest')
        candidate['candidateDigest'] = hashlib.sha256(DOMAIN + _encode(candidate)).hexdigest()
        result = self.compare(candidate, observed, defaults)
        self.assertEqual(result['unexplainedMismatchPaths'], ['Config.Volumes'])
        self.assertNotIn('Config.Volumes', result['wireExplainedMismatchPaths'])

    def test_missing_only_zero_health_keys_explainable(self):
        candidate, observed, defaults = self.sample_wire()
        candidate['body']['Healthcheck']['StartPeriod'] = 1
        candidate.pop('candidateDigest')
        candidate['candidateDigest'] = hashlib.sha256(DOMAIN + _encode(candidate)).hexdigest()
        result = self.compare(candidate, observed, defaults)
        self.assertIn('Config.Healthcheck', result['unexplainedMismatchPaths'])


if __name__ == '__main__':
    unittest.main()
