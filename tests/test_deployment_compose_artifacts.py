"""Pure-value Compose artifact binding tests; no Docker or host authorization."""
import json
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs' / 'deployment' / 'scripts'))
from deployment_compose_artifacts import ComposeArtifacts, ServiceArtifact, verify_request_artifacts, MAX_JSON
from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity


def artifact(service, char):
    return ServiceArtifact(service, 'a' * 40,
                           'registry.example.test/team/' + service + '@sha256:' + char * 64,
                           'sha256:' + char * 64, 'linux', 'amd64', 'staging-key-1',
                           char * 64, '0' * 64, 'none')


def request(manifest):
    return RequestV2(2, 'deploy', 'compose-application-batch-v1', '1',
                     SourceIdentity('github.com', 'https://github.com/team/blog.git', 1,
                                    'team/blog', 'a' * 40),
                     TargetIdentity('compose', 'staging', 'blog'), 'staging', False,
                     'daemon-1', tuple(item.service for item in manifest.services), (),
                     '1' * 64, '2' * 64, manifest.digest(), '3' * 64, None,
                     'host-1', '4' * 64, '5' * 64, '2026-10-25T12:00:00Z', 1)


class ComposeArtifactTests(unittest.TestCase):
    def test_two_service_roundtrip_and_request_binding(self):
        manifest = ComposeArtifacts(1, (artifact('api', 'a'), artifact('web', 'b')))
        self.assertEqual(ComposeArtifacts.from_json(manifest.canonical_json()), manifest)
        self.assertEqual(len(manifest.digest()), 64)
        verify_request_artifacts(request(manifest), manifest)
        self.assertNotEqual(manifest.digest(), __import__('hashlib').sha256(manifest.canonical_json().encode()).hexdigest())

    def test_every_artifact_identity_change_changes_digest(self):
        base = ComposeArtifacts(1, (artifact('api', 'a'), artifact('web', 'b')))
        for field, value in [('source_sha', 'b' * 40),
                             ('registry_digest', 'registry.example.test/team/api@sha256:' + 'c' * 64),
                             ('image_id', 'sha256:' + 'c' * 64), ('os', 'windows'),
                             ('architecture', 'arm64'), ('config_key_id', 'different-key'),
                             ('config_hmac', 'c' * 64), ('migration_digest', 'c' * 64),
                             ('migration_mode', 'forward')]:
            with self.subTest(field=field):
                changed = ComposeArtifacts(1, (replace(base.services[0], **{field: value}), base.services[1]))
                self.assertNotEqual(base.digest(), changed.digest())
                with self.assertRaises(ValueError):
                    verify_request_artifacts(request(base), changed)

    def test_selected_services_exact_and_unique(self):
        pair = ComposeArtifacts(1, (artifact('api', 'a'), artifact('web', 'b')))
        for services in [(artifact('api', 'a'),),
                         (artifact('api', 'a'), artifact('db', 'c'), artifact('web', 'b'))]:
            with self.assertRaisesRegex(ValueError, 'services'):
                verify_request_artifacts(request(pair), ComposeArtifacts(1, services))
        for services in [(artifact('web', 'b'), artifact('api', 'a')),
                         (artifact('api', 'a'), artifact('api', 'b')), ()]:
            with self.assertRaises(ValueError):
                ComposeArtifacts(1, services)

    def test_strict_json_and_fields(self):
        good = ComposeArtifacts(1, (artifact('web', 'b'),)).canonical_json()
        data = json.loads(good)
        extra = dict(data, unknown=True)
        cases = [good + ' ', good.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
                 json.dumps(extra, sort_keys=True, separators=(',', ':')),
                 ' ' * (MAX_JSON + 1), good.replace('"schema_version":1', '"schema_version":true'),
                 good.replace('"services":[', '"services":"oops"'),
                 good.replace('"migration_mode":"none"', '"migration_mode":"none","env":"SECRET"')]
        for raw in cases:
            with self.subTest(raw=raw[:70]), self.assertRaises(ValueError):
                ComposeArtifacts.from_json(raw)

    def test_mutable_tag_and_invalid_values_refused(self):
        base = artifact('web', 'b')
        for field, value in [('registry_digest', 'registry.example.test/team/web:latest'),
                             ('registry_digest', 'web@sha256:' + 'a' * 64),
                             ('source_sha', 'bad'), ('image_id', 'latest'),
                             ('config_hmac', True), ('migration_mode', 'run-shell'),
                             ('service', 'bad/name')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(base, **{field: value})

    def test_first_batch_profile_rejects_windows_and_migrations(self):
        base = ComposeArtifacts(1, (artifact('api', 'a'), artifact('web', 'b')))
        for field, value in [('os', 'windows'), ('migration_mode', 'forward'),
                             ('migration_mode', 'reverse')]:
            with self.subTest(field=field, value=value):
                changed = ComposeArtifacts(1, (replace(base.services[0], **{field: value}), base.services[1]))
                self.assertNotEqual(base.digest(), changed.digest())
                with self.assertRaisesRegex(ValueError, 'Linux images and no migrations'):
                    verify_request_artifacts(request(changed), changed)

    def test_request_scope_and_source_commit_required(self):
        base = ComposeArtifacts(1, (artifact('api', 'a'), artifact('web', 'b')))
        changed = ComposeArtifacts(1, (replace(base.services[0], source_sha='b' * 40), base.services[1]))
        with self.assertRaisesRegex(ValueError, 'source SHA'):
            verify_request_artifacts(request(changed), changed)
        req = request(base)
        variants = [replace(req, target=TargetIdentity('docker', 'staging', 'blog')),
                    replace(req, profile_id='docker-local'),
                    replace(req, profile_version='2'),
                    replace(req, operation='rollback', history_hash='6' * 64)]
        for variant in variants:
            with self.subTest(profile=variant.profile_id, runtime=variant.target.runtime,
                              operation=variant.operation), self.assertRaisesRegex(ValueError, 'profile or operation'):
                verify_request_artifacts(variant, base)

    def test_registry_reference_port_and_path_boundaries(self):
        base = artifact('web', 'b')
        accepted = ['localhost:5000/team/web@sha256:' + 'b' * 64,
                    'registry.example.test:65535/team/sub/web@sha256:' + 'b' * 64]
        for reference in accepted:
            self.assertEqual(replace(base, registry_digest=reference).registry_digest, reference)
        rejected = ['registry.example.test/team//web@sha256:' + 'b' * 64,
                    'registry.example.test/team/../web@sha256:' + 'b' * 64,
                    'registry.example.test:0/team/web@sha256:' + 'b' * 64,
                    'registry.example.test:65536/team/web@sha256:' + 'b' * 64,
                    'registry.example.test/team/web:latest',
                    'registry.example.test/team/Web@sha256:' + 'b' * 64]
        for reference in rejected:
            with self.subTest(reference=reference), self.assertRaisesRegex(ValueError, 'registry digest'):
                replace(base, registry_digest=reference)


if __name__ == '__main__':
    unittest.main()
