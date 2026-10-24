import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs' / 'deployment' / 'scripts'))
from deployment_acceptance import AcceptanceError, AcceptanceProfile, assess_supplied, _assess_trusted


def example():
    return dict(schemaVersion=1, kind='deployment-acceptance-profile', profileName='p2-test',
                repositoryId=42, environment='staging', target='isolated', component='web',
                runtimePolicyHash='a' * 64, executionPolicyHash='b' * 64,
                verificationPolicyHash='c' * 64, storePolicyHash='d' * 64,
                gatePolicyHash='e' * 64, allowInterruption=True, requireHealth=True,
                requireSmoke=True, rollbackRef='history-v1', platform='linux',
                adapter='docker', state='stateless', readOnly=True, mounts=[])


class AcceptanceTest(unittest.TestCase):
    def test_profile_strict_immutable_identity(self):
        source = example()
        profile = AcceptanceProfile.from_mapping(source)
        identity = profile.identity_hash()
        source['mounts'].append('/host')
        self.assertEqual(profile.identity_hash(), identity)
        self.assertEqual(profile.to_mapping()['mounts'], [])
        self.assertEqual(AcceptanceProfile.from_mapping(profile.to_mapping()), profile)
        with self.assertRaises(AttributeError):
            profile.component = 'api'
        for key, value in [('repositoryId', True), ('schemaVersion', 2),
                           ('schemaVersion', True),
                           ('runtimePolicyHash', 'abc'), ('allowInterruption', 'true')]:
            bad = example()
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(AcceptanceError):
                AcceptanceProfile.from_mapping(bad)
        bad = example()
        bad['extra'] = 'yes'
        with self.assertRaises(AcceptanceError):
            AcceptanceProfile.from_mapping(bad)
        with self.assertRaises(AcceptanceError):
            AcceptanceProfile(**{**vars(profile), 'repository_id': True})
        with self.assertRaises(AcceptanceError):
            AcceptanceProfile(**{**vars(profile), 'mounts': ['/host']})

    def test_supplied_success_claims_never_accept(self):
        profile = AcceptanceProfile.from_mapping(example())
        forged = {'status': 'accepted', 'productionReady': True,
                  'stages': {name: 'passed' for name in ('approval', 'deployment', 'health', 'smoke', 'rollback', 'recovery')}}
        report = assess_supplied(profile, forged)
        self.assertEqual(report['status'], 'unknown')
        self.assertFalse(report['productionReady'])
        self.assertFalse(report['authorityGranted'])
        self.assertFalse(report['executionAvailable'])
        self.assertEqual(set(report['stages'].values()), {'unknown'})

    def test_scope_and_contract_rejected_before_evidence(self):
        for key, value, expected in [('platform', 'windows', 'unsupported'),
                                      ('mounts', ['/data'], 'unsupported'),
                                      ('state', 'persistent', 'unsupported'),
                                      ('readOnly', False, 'unsupported'),
                                      ('allowInterruption', False, 'blocked'),
                                      ('requireSmoke', False, 'blocked')]:
            source = example()
            source[key] = value
            with self.subTest(key=key):
                self.assertEqual(assess_supplied(AcceptanceProfile.from_mapping(source), {})['status'], expected)

    def test_private_host_aggregation_is_still_not_production_ready(self):
        profile = AcceptanceProfile.from_mapping(example())
        observations = dict.fromkeys(('approval', 'deployment', 'health', 'smoke', 'rollback', 'recovery'), 'passed')
        report = _assess_trusted(profile, observations)
        self.assertEqual(report['status'], 'accepted')
        self.assertFalse(report['productionReady'])
        self.assertEqual(assess_supplied(profile, report)['status'], 'unknown')
        observations['recovery'] = 'unknown'
        self.assertEqual(_assess_trusted(profile, observations)['status'], 'unknown')
        observations['recovery'] = 'blocked'
        self.assertEqual(_assess_trusted(profile, observations)['status'], 'blocked')


if __name__ == '__main__':
    unittest.main()
