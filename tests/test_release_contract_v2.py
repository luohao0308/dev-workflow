import sys
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/release/scripts'))
from release_contract_v2 import ProviderIdentity, RequestV2


def request(provider='github.com', project_id=17):
    path = 'owner/project' if provider == 'github.com' else 'group/sub/project'
    identity = ProviderIdentity(provider, f'https://{provider}/{path}.git', project_id, path, 'a' * 40)
    return RequestV2(2, 'remote-tag-push', identity, 'trusted-host', 'release-v2', 'a' * 40,
                     'v1.0.0', identity.origin, '{}', 'b' * 64, 'c' * 64,
                     '2026-12-31T00:00:00Z', 1)


class ReleaseContractV2Tests(unittest.TestCase):
    def test_roundtrip_and_stable_digest(self):
        value = request()
        self.assertEqual(RequestV2.from_json(value.canonical_json()), value)
        self.assertEqual(RequestV2.from_json(value.canonical_json()).digest(), value.digest())
        self.assertEqual(len(value.digest()), 64)
        with self.assertRaises(FrozenInstanceError):
            value.identity.project_id = 18
        with self.assertRaises(FrozenInstanceError):
            value.tag = 'v2'

    def test_identity_and_operation_are_bound(self):
        value = request()
        variants = [request(project_id=18), request('gitlab.com'),
                    replace(value, host_id='another-host'), replace(value, profile_id='another-profile'),
                    replace(value, target_sha='d' * 40), replace(value, tag='v2'),
                    replace(value, operation='remote-release-create'),
                    replace(value, provider_payload_json='{"name":"v1"}'),
                    replace(value, plan_hash='d' * 64), replace(value, policy_hash='d' * 64),
                    replace(value, expires_at='2026-12-30T00:00:00Z')]
        self.assertEqual(len({value.digest(), *(item.digest() for item in variants)}), len(variants) + 1)

    def test_v1_digest_domain_is_incompatible(self):
        import hashlib
        value = request()
        self.assertNotEqual(value.digest(), hashlib.sha256(value.canonical_json().encode('ascii')).hexdigest())

    def test_rejects_bad_identity_or_remote(self):
        for provider, origin, path in (
            ('example.com', 'https://example.com/owner/project', 'owner/project'),
            ('github.com', 'http://github.com/owner/project', 'owner/project'),
            ('github.com', 'https://user@github.com/owner/project', 'owner/project'),
            ('github.com', 'https://github.com:443/owner/project', 'owner/project'),
            ('github.com', 'https://github.com/owner/project?x=1', 'owner/project'),
            ('github.com', 'https://github.com/owner/other', 'owner/project'),
            ('github.com', 'https://github.com/owner/project.git', 'owner/project.git'),
            ('gitlab.com', 'https://gitlab.com/group/../project', 'group/../project'),
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                ProviderIdentity(provider, origin, 17, path, 'a' * 40)
        with self.assertRaises(ValueError):
            ProviderIdentity('github.com', 'https://github.com/owner/project', True, 'owner/project', 'a' * 40)
        with self.assertRaises(ValueError):
            replace(request(), remote='https://github.com/owner/other.git')

    def test_rejects_unknown_fields_duplicate_keys_and_noncanonical_json(self):
        raw = request().canonical_json()
        for changed in (raw[:-1] + ',"extra":1}', raw.replace('"max_uses":1', '"max_uses":1,"max_uses":1'),
                        raw.replace('"max_uses":1', '"max_uses": 1'),
                        raw.replace('"project_id":17', '"project_id":17,"extra":1')):
            with self.subTest(changed=changed[-80:]), self.assertRaises(ValueError):
                RequestV2.from_json(changed)
        with self.assertRaises(ValueError):
            replace(request(), provider_payload_json='{ "name": "v1" }')
        with self.assertRaises(ValueError):
            replace(request(), provider_payload_json='{"name":1,"name":2}')

    def test_one_use_and_version_are_strict(self):
        for change in ({'max_uses': 2}, {'max_uses': True}, {'schema_version': 1},
                       {'schema_version': True}, {'expires_at': '2026-02-30T00:00:00Z'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(request(), **change)

    def test_trusted_host_must_enforce_bounded_expiry(self):
        value = request()
        value.ensure_fresh(datetime(2026, 12, 30, 23, 30, tzinfo=timezone.utc))
        for now in (datetime(2026, 12, 31, 0, 0, tzinfo=timezone.utc),
                    datetime(2026, 12, 30, 22, 0, tzinfo=timezone.utc),
                    datetime(2026, 12, 30, 23, 30)):
            with self.subTest(now=now), self.assertRaises(ValueError):
                value.ensure_fresh(now)
        with self.assertRaises(ValueError):
            value.ensure_fresh(datetime(2026, 12, 30, 23, 30, tzinfo=timezone.utc), maximum_seconds=61.5)

    def test_valid_request_always_roundtrips_within_json_bound(self):
        value = request()
        payload = json.dumps({'body': '\\' * 300000}, separators=(',', ':'))
        with self.assertRaisesRegex(ValueError, 'bounded JSON size'):
            replace(value, provider_payload_json=payload)
        smaller = replace(value, provider_payload_json=json.dumps({'body': '\\' * 1000}, separators=(',', ':')))
        self.assertEqual(RequestV2.from_json(smaller.canonical_json()), smaller)


if __name__ == '__main__':
    unittest.main()
