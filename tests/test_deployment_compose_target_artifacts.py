"""Target artifact contracts remain distinct from observed artifact contracts."""
import hashlib
import json
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs' / 'deployment' / 'scripts'))
from deployment_compose_artifacts import ComposeArtifacts, ServiceArtifact
from deployment_compose_target_artifacts import (
    ComposeTargetArtifacts, ServiceTargetArtifact, MAX_JSON, verify_target_request)
from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity


def artifact(service='web', char='a'):
    return ServiceTargetArtifact(service, 'a' * 40,
                                 'registry.example.test/team/' + service + '@sha256:' + char * 64,
                                 'sha256:' + char * 64, 'linux', 'amd64',
                                 'recipe-key-1', char * 64, '0' * 64, 'none')


def request(manifest, operation='deploy'):
    return RequestV2(2, operation, 'compose-application-batch-v1', '1',
                     SourceIdentity('github.com', 'https://github.com/team/blog.git', 1,
                                    'team/blog', 'a' * 40),
                     TargetIdentity('compose', 'staging', 'blog'), 'staging', False,
                     'daemon-1', tuple(item.service for item in manifest.services), (),
                     '1' * 64, '2' * 64, manifest.digest(), '3' * 64,
                     None if operation == 'deploy' else '6' * 64,
                     'host-1', '4' * 64, '5' * 64, '2026-10-25T12:00:00Z', 1)


class TargetArtifactTests(unittest.TestCase):
    def test_two_service_deploy_and_rollback_binding(self):
        manifest = ComposeTargetArtifacts(1, (artifact('api'), artifact('web', 'b')))
        self.assertEqual(ComposeTargetArtifacts.from_json(manifest.canonical_json()), manifest)
        self.assertEqual(len(manifest.digest()), 64)
        for operation in ('deploy', 'rollback'):
            verify_target_request(request(manifest, operation), manifest)

    def test_distinct_domain_and_cross_type_denial(self):
        target = ComposeTargetArtifacts(1, (artifact(),))
        observed = ComposeArtifacts(1, (ServiceArtifact(
            'web', 'a' * 40, target.services[0].registry_digest,
            target.services[0].image_id, 'linux', 'amd64', 'recipe-key-1',
            'a' * 64, '0' * 64, 'none'),))
        self.assertNotEqual(target.digest(), observed.digest())
        self.assertNotEqual(target.digest(), hashlib.sha256(target.canonical_json().encode()).hexdigest())
        with self.assertRaises(ValueError):
            verify_target_request(request(target), observed)
        with self.assertRaises(ValueError):
            ComposeTargetArtifacts(1, observed.services)
        with self.assertRaises(ValueError):
            ComposeTargetArtifacts.from_json(observed.canonical_json())
        with self.assertRaises(ValueError):
            ComposeArtifacts.from_json(target.canonical_json())

    def test_all_target_fields_bound_to_digest(self):
        base = ComposeTargetArtifacts(1, (artifact('api'), artifact('web', 'b')))
        changes = [('source_sha', 'b' * 40),
                   ('registry_digest', 'registry.example.test/team/api@sha256:' + 'c' * 64),
                   ('image_id', 'sha256:' + 'c' * 64), ('architecture', 'arm64'),
                   ('recipe_key_id', 'new-key'), ('recipe_hmac', 'c' * 64),
                   ('migration_digest', 'c' * 64)]
        for field, value in changes:
            with self.subTest(field=field):
                changed = ComposeTargetArtifacts(1, (replace(base.services[0], **{field: value}), base.services[1]))
                self.assertNotEqual(base.digest(), changed.digest())
                with self.assertRaises(ValueError):
                    verify_target_request(request(base), changed)

    def test_request_scope_source_and_profile(self):
        manifest = ComposeTargetArtifacts(1, (artifact('api'), artifact('web', 'b')))
        req = request(manifest)
        variants = [replace(req, components=('api',)),
                    replace(req, source=replace(req.source, source_sha='b' * 40)),
                    replace(req, target=TargetIdentity('docker', 'staging', 'blog')),
                    replace(req, profile_id='other'), replace(req, profile_version='2'),
                    replace(req, operation='recovery', history_hash='6' * 64),
                    replace(req, artifact_digest='f' * 64)]
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                verify_target_request(changed, manifest)

    def test_mixed_source_history_cannot_be_a_v2_rollback_target(self):
        mixed = ComposeTargetArtifacts(1, (artifact('api'),
            replace(artifact('web', 'b'), source_sha='b' * 40)))
        with self.assertRaisesRegex(ValueError, 'Target source SHA differs'):
            verify_target_request(request(mixed, 'rollback'), mixed)

    def test_sorted_unique_nonempty_exact_type(self):
        for services in ((), (artifact('web'), artifact('api')),
                         (artifact('api'), artifact('api', 'b')),
                         tuple(artifact('s' + str(i).zfill(2)) for i in range(33))):
            with self.assertRaises(ValueError):
                ComposeTargetArtifacts(1, services)
        with self.assertRaises(ValueError):
            ComposeTargetArtifacts(True, (artifact(),))
        with self.assertRaises(ValueError):
            ComposeTargetArtifacts(1, [artifact()])

    def test_canonical_duplicate_unknown_and_oversize_denial(self):
        good = ComposeTargetArtifacts(1, (artifact(),)).canonical_json()
        data = json.loads(good)
        cases = [good + ' ', good.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
                 good.replace('"recipe_key_id":', '"recipe_key_id":"x","recipe_key_id":', 1),
                 json.dumps(dict(data, extra=True), sort_keys=True, separators=(',', ':')),
                 good.replace('"services":[', '"services":"bad"'),
                 good.replace('"schema_version":1', '"schema_version":true'),
                 good.replace('"migration_mode":"none"', '"migration_mode":"none","env":"SECRET"'),
                 ' ' * (MAX_JSON + 1)]
        for raw in cases:
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                ComposeTargetArtifacts.from_json(raw)

    def test_unsafe_images_platform_recipe_and_migration_denial(self):
        base = artifact()
        for field, value in [('registry_digest', 'registry.example.test/team/web:latest'),
                             ('registry_digest', 'web@sha256:' + 'a' * 64),
                             ('source_sha', 'short'), ('image_id', 'latest'),
                             ('os', 'windows'), ('architecture', 'bad/name'),
                             ('recipe_key_id', ''), ('recipe_hmac', True),
                             ('migration_digest', 'short'), ('migration_mode', 'forward'),
                             ('service', 'bad/name')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(base, **{field: value})


if __name__ == '__main__':
    unittest.main()
