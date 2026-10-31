"""Host catalog to Engine image projection comparison, without authorization."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs' / 'deployment' / 'scripts'))
from deployment_compose_artifacts import ComposeArtifacts, ServiceArtifact
from deployment_compose_image_catalog import verify_images


def artifact(service, char):
    return ServiceArtifact(service, 'a' * 40,
                           f'registry.example.test/team/{service}@sha256:' + char * 64,
                           'sha256:' + char * 64, 'linux', 'amd64', 'host-key',
                           char * 64, '0' * 64, 'none')


class ImageCatalogTests(unittest.TestCase):
    def setUp(self):
        self.manifest = ComposeArtifacts(1, (artifact('api', 'a'), artifact('web', 'b')))
        self.images = {item.service: {'Id': item.image_id, 'Os': 'linux',
                                      'Architecture': 'amd64',
                                      'RepoDigests': [item.registry_digest]}
                       for item in self.manifest.services}

    def test_two_service_match(self):
        self.assertIsNone(verify_images(self.manifest, self.images))

    def test_scope_exact(self):
        for changed in [{}, {'api': self.images['api']},
                        dict(self.images, db=self.images['api'])]:
            with self.subTest(changed=changed.keys()), self.assertRaisesRegex(ValueError, 'image-service-scope-mismatch'):
                verify_images(self.manifest, changed)

    def test_identity_platform_and_digest_drift(self):
        for field, value, reason in [('Id', 'sha256:' + 'c' * 64, 'image-id-mismatch'),
                                     ('Os', 'windows', 'image-platform-mismatch'),
                                     ('Architecture', 'arm64', 'image-platform-mismatch'),
                                     ('RepoDigests', [], 'image-registry-digest-mismatch'),
                                     ('RepoDigests', ['registry.example.test/other@sha256:' + 'b' * 64],
                                      'image-registry-digest-mismatch')]:
            changed = {name: dict(image) for name, image in self.images.items()}
            changed['web'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, reason):
                verify_images(self.manifest, changed)

    def test_duplicate_or_malformed_projection(self):
        cases = [({'RepoDigests': self.images['api']['RepoDigests'] * 2}, 'duplicate-image-digest'),
                 ({'RepoDigests': 'secret'}, 'invalid-image-projection'),
                 ({'RepoDigests': [False]}, 'invalid-image-projection'),
                 ({'RepoDigests': [{}]}, 'invalid-image-projection'),
                 ({'extra': 'secret'}, 'invalid-image-projection')]
        for fields, reason in cases:
            changed = {name: dict(image) for name, image in self.images.items()}
            changed['api'].update(fields)
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, reason):
                verify_images(self.manifest, changed)

    def test_two_services_can_share_one_image(self):
        shared = replace(self.manifest.services[1], image_id=self.manifest.services[0].image_id)
        manifest = ComposeArtifacts(1, (self.manifest.services[0], shared))
        changed = {name: dict(image) for name, image in self.images.items()}
        changed['web']['Id'] = shared.image_id
        self.assertIsNone(verify_images(manifest, changed))
        changed['web']['Id'] = 'sha256:' + 'c' * 64
        with self.assertRaisesRegex(ValueError, 'image-id-mismatch'):
            verify_images(manifest, changed)

    def test_catalog_assertions_are_not_inferred_from_labels(self):
        changed = {name: dict(image) for name, image in self.images.items()}
        changed['api']['Labels'] = {'source_sha': 'f' * 40}
        with self.assertRaisesRegex(ValueError, 'invalid-image-projection'):
            verify_images(self.manifest, changed)
        asserted = replace(self.manifest.services[0], source_sha='f' * 40,
                           migration_digest='f' * 64)
        manifest = ComposeArtifacts(1, (asserted, self.manifest.services[1]))
        self.assertIsNone(verify_images(manifest, self.images))


if __name__ == '__main__':
    unittest.main()
