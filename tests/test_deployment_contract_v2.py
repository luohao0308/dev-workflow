import hashlib
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity, MAX_JSON


def request():
    source = SourceIdentity('github.com', 'https://github.com/owner/project.git', 17,
                            'owner/project', 'a' * 40)
    return RequestV2(2, 'deploy', 'docker-local', '1', source,
                     TargetIdentity('docker', 'project', 'web'),
                     'staging', False, 'daemon-1', ('web',), ('db',),
                     'a' * 64, 'b' * 64, 'c' * 64, 'f' * 64, None, 'host-one',
                     'd' * 64, 'e' * 64, '2026-12-31T00:00:00Z', 1)


class DeploymentContractV2Tests(unittest.TestCase):
    def test_canonical_roundtrip_and_immutability(self):
        value = request()
        self.assertEqual(RequestV2.from_json(value.canonical_json()), value)
        self.assertEqual(RequestV2.from_json(value.canonical_json()).digest(), value.digest())
        with self.assertRaises(FrozenInstanceError):
            value.target.runtime = 'compose'

    def test_every_authority_binding_changes_digest(self):
        value = request()
        variants = [replace(value, operation='rollback', history_hash='1' * 64),
                    replace(value, operation='recovery', history_hash='1' * 64),
                    replace(value, source=replace(value.source, project_id=18)),
                    replace(value, source=replace(value.source, source_sha='b' * 40)),
                    replace(value, production=True), replace(value, daemon_id='daemon-2'),
                    replace(value, protected_components=('cache', 'db')),
                    replace(value, profile_id='compose-local'), replace(value, profile_version='2'),
                    replace(value, target=TargetIdentity('compose', 'project', 'web')),
                    replace(value, environment='production'), replace(value, components=('api', 'web')),
                    replace(value, before_hash='f' * 64), replace(value, after_hash='f' * 64),
                    replace(value, artifact_digest='0' * 64),
                    replace(value, observation_hash='0' * 64), replace(value, host_id='host-two'),
                    replace(value, plan_hash='f' * 64), replace(value, policy_hash='f' * 64),
                    replace(value, expires_at='2026-12-30T00:00:00Z')]
        self.assertEqual(len({value.digest(), *(v.digest() for v in variants)}), len(variants) + 1)
        self.assertNotEqual(value.digest(), hashlib.sha256(value.canonical_json().encode('ascii')).hexdigest())
        self.assertNotEqual(value.digest(), hashlib.sha256(b'dev-workflow:release-request:v2\0' +
                                                          value.canonical_json().encode('ascii')).hexdigest())
        rollback = replace(value, operation='rollback', history_hash='1' * 64)
        self.assertNotEqual(rollback.digest(), replace(rollback, history_hash='2' * 64).digest())

    def test_unknown_duplicate_and_noncanonical_json_fail_closed(self):
        raw = request().canonical_json()
        for changed in (raw[:-1] + ',"extra":1}', raw.replace('"max_uses":1', '"max_uses":1,"max_uses":1'),
                        raw.replace('"max_uses":1', '"max_uses": 1'),
                        raw.replace('"project_id":17', '"project_id":17,"extra":1'),
                        raw.replace('"project_id":17', '"project_id":17,"project_id":17'),
                        raw.replace('"runtime":"docker"', '"runtime":"docker","extra":1'),
                        raw.replace('"runtime":"docker"', '"runtime":"docker","runtime":"docker"')):
            with self.subTest(changed=changed[-70:]), self.assertRaises(ValueError):
                RequestV2.from_json(changed)

    def test_invalid_values_and_types_fail_closed(self):
        value = request()
        for change in ({'schema_version': True}, {'schema_version': 1}, {'operation': 'execute'},
                       {'components': ('web', 'web')}, {'components': ('web', 'api')},
                       {'components': ('web', True)}, {'max_uses': True}, {'max_uses': 2},
                       {'production': 1}, {'daemon_id': ''}, {'daemon_id': 'a' * 257},
                       {'protected_components': ('web',)}, {'protected_components': ('db', 'db')},
                       {'protected_components': ('db', 'cache')},
                       {'before_hash': '0' * 63}, {'observation_hash': '0' * 63},
                       {'history_hash': '1' * 64}, {'operation': 'rollback'},
                       {'operation': 'recovery'}, {'expires_at': '2026-02-30T00:00:00Z'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(value, **change)
        for operation in ('rollback', 'recovery'):
            self.assertEqual(RequestV2.from_json(replace(value, operation=operation,
                                                         history_hash='1' * 64).canonical_json()).operation,
                             operation)
        with self.assertRaises(ValueError):
            RequestV2.from_json(value.canonical_json().replace('"components":["web"]', '"components":"web"'))
        with self.assertRaises(ValueError):
            TargetIdentity('kubernetes', 'project', 'web')
        for change in ({'origin': 'http://github.com/owner/project.git'},
                       {'project_path': 'owner/../project'}, {'project_id': True},
                       {'source_sha': 'a' * 39}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(value.source, **change)

    def test_size_limit_and_trusted_time(self):
        value = request()
        with self.assertRaises(ValueError):
            RequestV2.from_json(' ' * (MAX_JSON + 1))
        value.ensure_fresh(datetime(2026, 12, 30, 23, 30, tzinfo=timezone.utc))
        for now in (datetime(2026, 12, 31, tzinfo=timezone.utc),
                    datetime(2026, 12, 30, 22, tzinfo=timezone.utc),
                    datetime(2026, 12, 30, 23, 30)):
            with self.subTest(now=now), self.assertRaises(ValueError):
                value.ensure_fresh(now)


if __name__ == '__main__':
    unittest.main()
