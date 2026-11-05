import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
import deployment_compose_observation as observation

SERVICES = ('frontend', 'backend', 'caddy', 'db', 'redis', 'es')
HEX = 'a' * 64


def fixture():
    project = 'blog'
    network = {'name': 'blog_default', 'id': 'b' * 64, 'project': project}
    volumes = [{'name': 'blog_uploads', 'project': project, 'driver': 'local', 'options': {}}]
    containers = []
    for index, service in enumerate(SERVICES):
        containers.append({
            'id': f'{index + 1:064x}', 'name': f'blog-{service}-1', 'service': service,
            'project': project, 'labels': {'com.docker.compose.project': project,
                                          'com.docker.compose.service': service},
            'imageId': 'sha256:' + HEX,
            'networks': [{'name': network['name'], 'id': network['id'], 'aliases': [service, f'blog-{service}-1']}],
            'mounts': ([{'type': 'volume', 'source': 'blog_uploads', 'target': '/uploads', 'readOnly': False}]
                       if service == 'backend' else []),
            'running': True, 'health': 'healthy', 'healthLog': 'secret log', 'startedAt': '2026-01-01',
            'Env': ['SECRET=private-value'],
        })
    records = {'daemonId': 'fixture-daemon:desktop-linux', 'project': project, 'networks': [network],
               'volumes': volumes, 'containers': containers}
    policy = {'daemonId': records['daemonId'], 'project': project,
              'selectedServices': ['frontend', 'backend'],
              'protectedServices': ['caddy', 'db', 'redis', 'es'],
              'networks': {network['name']: network['id']},
              'volumes': {'blog_uploads': {'driver': 'local', 'options': {}}},
              'mounts': {name: copy.deepcopy(next(c for c in containers if c['service'] == name)['mounts'])
                         for name in SERVICES},
              'containerNames': {name: f'blog-{name}-1' for name in SERVICES},
              'networkAttachments': {name: {'blog_default': [name, f'blog-{name}-1']}
                                     for name in SERVICES}}
    return records, policy


class ComposeObservationTests(unittest.TestCase):
    def test_full_scope_and_dynamic_state_does_not_change_structure(self):
        records, policy = fixture()
        first = observation.assess(records, policy)
        self.assertEqual(first['structuralStatus'], 'candidate-unverified')
        self.assertTrue(first['structureDigest'].startswith('sha256:'))
        self.assertEqual(set(first['serviceState']), set(SERVICES))
        self.assertEqual(first['runtimeVerification'], 'unknown')
        self.assertFalse(first['authorityGranted'])
        self.assertFalse(first['executionAvailable'])
        self.assertFalse(first['productionReady'])
        changed = copy.deepcopy(records)
        changed['containers'][0].update(health='unhealthy', running=False,
                                        healthLog='private-value 999', startedAt='tomorrow')
        self.assertEqual(first['structureDigest'], observation.assess(changed, policy)['structureDigest'])
        self.assertNotEqual(first['serviceState'], observation.assess(changed, policy)['serviceState'])
        changed['containers'][0]['imageId'] = 'sha256:' + 'd' * 64
        self.assertNotEqual(first['structureDigest'], observation.assess(changed, policy)['structureDigest'])
        self.assertNotIn('private-value', json.dumps(first))
        self.assertNotIn('Env', json.dumps(first))

    def test_rejects_extra_duplicate_and_wrong_identity(self):
        for mutate in (
            lambda r, p: r['containers'].append(copy.deepcopy(r['containers'][0])),
            lambda r, p: r['containers'].__setitem__(1, copy.deepcopy(r['containers'][0])),
            lambda r, p: r['containers'][1].update(id=r['containers'][0]['id']),
            lambda r, p: r['containers'][0]['labels'].update({'com.docker.compose.project': 'other'}),
            lambda r, p: r['containers'][0]['networks'][0].update(aliases=['wrong']),
            lambda r, p: r['containers'][0]['networks'][0].update(id='e' * 64),
            lambda r, p: r['containers'][0].update(id='bad'),
            lambda r, p: r['containers'][0].update(name='replacement'),
            lambda r, p: p['protectedServices'].remove('db'),
        ):
            with self.subTest(mutate=mutate):
                records, policy = fixture()
                mutate(records, policy)
                result = observation.assess(records, policy)
                self.assertEqual(result['structuralStatus'], 'blocked')
                self.assertIsNone(result['structureDigest'])

    def test_rejects_mount_and_volume_changes(self):
        for mutate in (
            lambda r, p: r['volumes'][0].update(driver='other'),
            lambda r, p: r['volumes'][0].update(options={'device': '/tmp'}),
            lambda r, p: (r['volumes'][0].update(driver='other'), p['volumes']['blog_uploads'].update(driver='other')),
            lambda r, p: (r['volumes'][0].update(options={'device': '/tmp'}), p['volumes']['blog_uploads'].update(options={'device': '/tmp'})),
            lambda r, p: r['containers'][1]['mounts'][0].update(source='other'),
            lambda r, p: r['containers'][1]['mounts'].append({'type': 'volume', 'source': 'blog_uploads',
                                                              'target': '/uploads', 'readOnly': False}),
            lambda r, p: r['containers'][1]['mounts'].append({'type': 'bind', 'source': '/tmp',
                                                              'target': '/config', 'readOnly': False}),
        ):
            with self.subTest(mutate=mutate):
                records, policy = fixture()
                mutate(records, policy)
                self.assertEqual(observation.assess(records, policy)['structuralStatus'], 'blocked')

    def test_mount_order_is_structurally_stable(self):
        records, policy = fixture()
        second = {'type': 'bind', 'source': '/etc/blog', 'target': '/config', 'readOnly': True}
        records['containers'][1]['mounts'].append(second)
        policy['mounts']['backend'].append(copy.deepcopy(second))
        first = observation.assess(records, policy)
        records['containers'][1]['mounts'].reverse()
        self.assertEqual(first['structureDigest'], observation.assess(records, policy)['structureDigest'])

    def test_malformed_network_policy_is_blocked(self):
        for invalid in (3, [], None):
            with self.subTest(invalid=invalid):
                records, policy = fixture()
                if invalid is None:
                    policy.pop('networks')
                else:
                    policy['networks'] = invalid
                self.assertEqual(observation.assess(records, policy)['structuralStatus'], 'blocked')

    def test_network_attachment_must_be_exact(self):
        for mutate in (
            lambda r, p: r['containers'][0]['networks'].clear(),
            lambda r, p: r['containers'][0]['networks'][0]['aliases'].append('unexpected'),
            lambda r, p: p['networkAttachments']['frontend']['blog_default'].append('missing'),
        ):
            with self.subTest(mutate=mutate):
                records, policy = fixture()
                mutate(records, policy)
                self.assertEqual(observation.assess(records, policy)['structuralStatus'], 'blocked')

    def test_alias_ownership_is_per_network(self):
        records, policy = fixture()
        backend = records['containers'][1]
        backend['networks'][0]['aliases'].append('frontend')
        policy['networkAttachments']['backend']['blog_default'].append('frontend')
        self.assertIn('network-alias-collision', observation.assess(records, policy)['reasons'])

        records, policy = fixture()
        alternative = {'name': 'blog_internal', 'id': 'd' * 64, 'project': 'blog'}
        records['networks'].append(alternative)
        policy['networks'][alternative['name']] = alternative['id']
        backend = records['containers'][1]
        backend['networks'] = [{'name': alternative['name'], 'id': alternative['id'],
                                'aliases': ['backend', 'blog-backend-1', 'frontend']}]
        policy['networkAttachments']['backend'] = {alternative['name']: ['backend', 'blog-backend-1', 'frontend']}
        self.assertEqual(observation.assess(records, policy)['structuralStatus'], 'candidate-unverified')

    def test_invalid_volume_shape_is_blocked_without_serialization(self):
        for mutate in (
            lambda r, p: r['volumes'][0].update(options={'password': object()}),
            lambda r, p: p['volumes']['blog_uploads'].update(options={'password': object()}),
            lambda r, p: r['volumes'][0].update(driver=object()),
            lambda r, p: p['volumes']['blog_uploads'].update(driver=''),
        ):
            with self.subTest(mutate=mutate):
                records, policy = fixture()
                mutate(records, policy)
                self.assertEqual(observation.assess(records, policy)['structuralStatus'], 'blocked')

    def test_secret_never_in_rejection(self):
        records, policy = fixture()
        records['containers'][0]['labels']['com.docker.compose.project'] = 'private-value'
        self.assertNotIn('private-value', json.dumps(observation.assess(records, policy)))


if __name__ == '__main__':
    unittest.main()
