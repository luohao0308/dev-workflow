"""Pure schema-v2 target manifest and request separation regressions."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_target_v2 import (
    ComposeTargetArtifactsV2, ServiceTargetArtifactV2, PROFILE, PROFILE_VERSION,
    DOMAIN, MAX_JSON, verify_target_request_v2)
from deployment_compose_target_artifacts import ComposeTargetArtifacts, ServiceTargetArtifact
from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity


def artifact(service='web'):
    return ServiceTargetArtifactV2(service, 'a' * 40,
        'registry.example.test/team/web@sha256:' + 'b' * 64, 'sha256:' + 'b' * 64,
        'linux', 'amd64', 'recipe-key', 'c' * 64, 'd' * 64, 'none', 3)


def manifest():
    return ComposeTargetArtifactsV2(2, PROFILE, PROFILE_VERSION, (artifact(),))


def request(target):
    return RequestV2(2, 'deploy', PROFILE, PROFILE_VERSION,
        SourceIdentity('github.com', 'https://github.com/team/blog.git', 1, 'team/blog', 'a' * 40),
        TargetIdentity('compose', 'staging', 'blog'), 'staging', False, 'daemon-1',
        ('web',), (), '1' * 64, target.digest(), target.digest(), '3' * 64, None,
        'host-1', '4' * 64, '5' * 64, '2026-10-25T12:00:00Z', 1)


class TargetV2Tests(unittest.TestCase):
    def assert_invalid(self, callback):
        with self.assertRaisesRegex(ValueError, '^invalid-compose-target-v2$'):
            callback()

    def test_roundtrip_explicit_profile_and_domain(self):
        target = manifest()
        self.assertEqual(ComposeTargetArtifactsV2.from_json(target.canonical_json()), target)
        self.assertEqual(target.digest(), hashlib.sha256(DOMAIN + target.canonical_json().encode()).hexdigest())
        self.assertNotEqual(target.digest(), hashlib.sha256(b'dev-workflow:compose-target-artifacts:v1\0' + target.canonical_json().encode()).hexdigest())
        self.assertEqual(json.loads(target.canonical_json())['services'][0]['recipe_schema_version'], 3)
        verify_target_request_v2(request(target), target)

    def test_strict_versions_and_string_fields(self):
        for value in (2, True, 3.0, '3'):
            self.assert_invalid(lambda: replace(artifact(), recipe_schema_version=value))
        for field in asdict(artifact()):
            if field != 'recipe_schema_version':
                self.assert_invalid(lambda: replace(artifact(), **{field: True}))
        for value in (True, 2.0, '2', 1):
            self.assert_invalid(lambda: replace(manifest(), schema_version=value))
        self.assert_invalid(lambda: replace(artifact(), architecture='s390x'))
        self.assert_invalid(lambda: replace(manifest(), profile_version=2))

    def test_manifest_services_bounds_and_uniform_source(self):
        for services in ((), [], (artifact('web'), artifact('api')), (artifact(), artifact()),
                         (artifact('api'), replace(artifact(), source_sha='e' * 40)),
                         tuple(artifact('s%02d' % i) for i in range(33))):
            self.assert_invalid(lambda: replace(manifest(), services=services))
        self.assert_invalid(lambda: replace(manifest(), profile_id='compose-application-batch-v1'))

    def test_canonical_duplicate_unknown_nonfinite_and_oversize(self):
        good = manifest().canonical_json()
        data = json.loads(good)
        for raw in (good + '\n', good.replace('"schema_version":2', '"schema_version":2,"schema_version":2'),
                    good.replace('"recipe_schema_version":3', '"recipe_schema_version":3,"recipe_schema_version":3'),
                    good.replace('"recipe_schema_version":3', '"recipe_schema_version":NaN'),
                    good.replace('"recipe_schema_version":3', '"recipe_schema_version":2'),
                    good.replace('"recipe_schema_version":3', '"recipe_schema_version":true'),
                    good.replace('"recipe_schema_version":3', '"recipe_schema_version":3.0'),
                    json.dumps(dict(data, extra=True), sort_keys=True, separators=(',', ':')),
                    good.replace('"service":"web"', '"service":"web","extra":0'),
                    ' ' * (MAX_JSON + 1), '{}', None):
            self.assert_invalid(lambda: ComposeTargetArtifactsV2.from_json(raw))

    def test_cross_schema_denied_both_directions(self):
        common = asdict(artifact())
        del common['recipe_schema_version']
        old = ComposeTargetArtifacts(1, (ServiceTargetArtifact(**common),))
        self.assert_invalid(lambda: ComposeTargetArtifactsV2.from_json(old.canonical_json()))
        with self.assertRaises(ValueError):
            ComposeTargetArtifacts.from_json(manifest().canonical_json())
        self.assert_invalid(lambda: verify_target_request_v2(request(manifest()), old))

    def test_request_binding_rejects_all_other_scopes(self):
        target = manifest()
        req = request(target)
        for changed in (replace(req, profile_id='compose-application-batch-v1'),
                        replace(req, profile_version='1'),
                        replace(req, source=replace(req.source, source_sha='e' * 40)),
                        replace(req, artifact_digest='f' * 64), replace(req, after_hash='f' * 64),
                        replace(req, components=('api',)),
                        replace(req, operation='rollback', history_hash='f' * 64),
                        replace(req, operation='recovery', history_hash='f' * 64),
                        replace(req, target=replace(req.target, runtime='docker'))):
            self.assert_invalid(lambda: verify_target_request_v2(changed, target))
        self.assert_invalid(lambda: verify_target_request_v2(None, target))


if __name__ == '__main__':
    unittest.main()
