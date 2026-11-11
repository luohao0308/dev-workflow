"""Explicit test-seam observation over live private-daemon source reads.

This is not the production mTLS observation transport and never grants authority.
Image names use the existing explicit local binding; no registry provenance claim.
"""
from copy import deepcopy
import hashlib
import json
import uuid

from deployment_compose_observation_host import ComposeObservationHost, _TEST_SEAM
from deployment_compose_artifacts import ComposeArtifacts
from deployment_compose_collect import image_catalog_digest
from deployment_compose_image_reference import derive_bound_defaults, POLICY
from deployment_compose_private import MOUNT, commit
from deployment_compose_snapshot import _encode


def archive_snapshot(row):
    """The existing archive's complete-MOUNT projection, not original raw presence."""
    result = {k: deepcopy(row[k]) for k in ('Id', 'Name', 'Image', 'Config', 'HostConfig', 'NetworkSettings', 'Mounts')}
    result['Mounts'] = [{**{k: None for k in MOUNT}, **mount} for mount in row['Mounts']]
    return result


def archive_observer(target, identity, artifact, private_key, image, image_commitment, image_key,
                     *, expected_image_key_id, expected_observed_reference):
    _, binding = derive_bound_defaults(image, image_commitment, image_key,
        expected_key_id=expected_image_key_id, expected_image_id=artifact.image_id,
        expected_artifact_reference=artifact.registry_digest,
        expected_observed_reference=expected_observed_reference,
        expected_architecture=artifact.architecture, policy=POLICY)
    if identity['service'] != artifact.service or identity['imageId'] != artifact.image_id:
        raise ValueError('archive-fixture-scope-rejected')
    service = artifact.service
    scope = {'project': identity['project'], 'daemonId': identity['daemonId'],
        'selectedServices': [service], 'protectedServices': [], 'protectedContainerIds': {},
        'protectedConfigHmacs': {}, 'selectedContainerIds': {service: identity['containerId']},
        'containerNames': {service: identity['containerName']}, 'imageIds': {service: artifact.image_id}}
    boot = uuid.uuid4().hex
    def digest(value):
        return hashlib.sha256(_encode(value)).hexdigest()
    class Reader:
        gateway_boot_id = boot
        def gateway_info(self, *, deadline):
            return {'bootId': boot}
        def get(self, path, *, deadline):
            if path != '/v1.45/images/' + artifact.image_id + '/json':
                raise ValueError('archive-fixture-image-path-rejected')
            rows = json.loads(target.run('image', 'inspect', artifact.image_id))
            if (len(rows) != 1 or any(_encode(rows[0].get(k)) != _encode(image.get(k))
                                      for k in ('Id', 'Os', 'Architecture', 'Config', 'RootFS'))):
                raise ValueError('archive-fixture-image-drift')
            return {'Id': artifact.image_id, 'Os': image['Os'], 'Architecture': image['Architecture'],
                    'RepoDigests': [binding['artifactReference']]}
    def collect(reader, policy, *, max_seconds):
        rows = json.loads(target.run('container', 'inspect', identity['containerId']))
        if len(rows) != 1:
            raise ValueError('archive-fixture-source-count-rejected')
        row = rows[0]
        if (row['Id'] != identity['containerId'] or row['Name'] != '/' + identity['containerName']
                or row['Config']['Labels'].get('com.docker.compose.project') != identity['project']
                or row['Config']['Labels'].get('com.docker.compose.service') != service):
            raise ValueError('archive-fixture-source-identity-drift')
        raw = archive_snapshot(row)
        projection = {k: raw[k] for k in ('Config', 'HostConfig', 'NetworkSettings', 'Mounts')}
        hmac = commit(identity['project'], service, projection, artifact.config_key_id, private_key)['configHmac']
        catalog = {artifact.image_id: {'os': image['Os'], 'architecture': image['Architecture'],
                                     'repoDigests': [binding['artifactReference']]}}
        structure = {'project': identity['project'], 'service': service, 'containerId': row['Id'],
                     'image': row['Image'], 'networks': raw['NetworkSettings']['Networks']}
        instance = {'id': row['Id'], 'startedAt': row['State']['StartedAt'],
                    'restartCount': row['RestartCount'], 'running': row['State']['Running'],
                    'health': row['State']['Health']['Status']}
        return {'structuralStatus': 'candidate-unverified', 'structureDigest': 'sha256:' + digest(structure),
            'privateDigest': digest(projection), 'instanceDigest': digest(instance),
            'imageCatalogDigest': image_catalog_digest(catalog),
            'serviceContainerIds': {service: row['Id']}, 'serviceImages': {service: row['Image']},
            'serviceConfigHmacs': {service: hmac},
            'serviceState': {service: {'running': row['State']['Running'], 'health': row['State']['Health']['Status']}}}
    observer = ComposeObservationHost._test_host(Reader(), scope, collect,
        ComposeArtifacts(1, (artifact,)), _token=_TEST_SEAM)
    observation = observer.issue()
    if observation is None:
        raise ValueError('archive-fixture-observation-rejected')
    return observer, observation
