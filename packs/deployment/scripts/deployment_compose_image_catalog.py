"""Read-only comparison of a host-owned Compose manifest with image inspections.

The caller must authenticate the manifest and the Engine observations. This
comparison does not establish source provenance, authorize, or execute writes.
"""
from __future__ import annotations

from deployment_compose_artifacts import ComposeArtifacts


_FIELDS = {'Id', 'Os', 'Architecture', 'RepoDigests'}


def verify_images(manifest: ComposeArtifacts, observed: dict[str, dict]) -> None:
    """Reject image drift using fixed, secret-free ValueError reasons.

    ``observed`` is keyed by selected Compose service and contains the four
    projected Docker image inspect fields. Source SHA, migration set, and the
    host-private configuration commitment remain host catalog assertions;
    Docker image labels cannot establish those claims.
    """
    if type(manifest) is not ComposeArtifacts or type(observed) is not dict:
        raise ValueError('invalid-image-catalog-input')
    selected = {item.service for item in manifest.services}
    if set(observed) != selected or any(type(key) is not str for key in observed):
        raise ValueError('image-service-scope-mismatch')
    for artifact in manifest.services:
        image = observed[artifact.service]
        if type(image) is not dict or set(image) != _FIELDS:
            raise ValueError('invalid-image-projection')
        if (type(image['Id']) is not str or type(image['Os']) is not str
                or type(image['Architecture']) is not str
                or type(image['RepoDigests']) is not list
                or len(image['RepoDigests']) > 128
                or any(type(ref) is not str or len(ref) > 512 for ref in image['RepoDigests'])):
            raise ValueError('invalid-image-projection')
        if image['Id'] != artifact.image_id:
            raise ValueError('image-id-mismatch')
        if image['Os'] != artifact.os or image['Architecture'] != artifact.architecture:
            raise ValueError('image-platform-mismatch')
        if len(set(image['RepoDigests'])) != len(image['RepoDigests']):
            raise ValueError('duplicate-image-digest')
        if artifact.registry_digest not in image['RepoDigests']:
            raise ValueError('image-registry-digest-mismatch')
