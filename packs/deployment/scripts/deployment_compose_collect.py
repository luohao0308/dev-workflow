"""Two-pass, read-only Compose inventory projection. Never grants execution authority."""
from __future__ import annotations

import hashlib
import json
import re
import time

from deployment_compose_observation import assess
from deployment_compose_reader import ComposeDockerReader, ComposeReadError
from deployment_prepare import registry_reference

ID = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')


def image_catalog_digest(images):
    """Digest a normalized image-ID map; no registry refs escape diagnostics."""
    if type(images) is not dict or any(
            type(image_id) is not str or not IMAGE.fullmatch(image_id)
            or type(value) is not dict or set(value) != {'os', 'architecture', 'repoDigests'}
            or value['os'] != 'linux' or type(value['architecture']) is not str
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value['architecture'])
            or type(value['repoDigests']) is not list
            or any(type(ref) is not str or not registry_reference(ref)
                   for ref in value['repoDigests'])
            or value['repoDigests'] != sorted(set(value['repoDigests']))
            for image_id, value in images.items()):
        raise ValueError('invalid-image-catalog')
    canonical = json.dumps(images, sort_keys=True, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(b'dev-workflow:compose-image-catalog:v1\0' + canonical).hexdigest()


def _blocked(reason):
    return {'schemaVersion': 1, 'kind': 'compose-untrusted-inspect-projection',
            'structuralStatus': 'blocked', 'reasons': [reason], 'structureDigest': None,
            'privateDigest': None, 'instanceDigest': None, 'imageCatalogDigest': None,
            'bindDigest': None, 'serviceConfigHmacs': {},
            'serviceImages': {},
            'serviceState': {}, 'runtimeVerification': 'unknown',
            'authorityGranted': False, 'executionAvailable': False, 'productionReady': False}


def _object(value):
    if type(value) is not dict:
        raise ValueError('shape')
    return value


def _labels(value):
    labels = _object(value)
    return {key: labels.get(key) for key in ('com.docker.compose.project', 'com.docker.compose.service')}


def _snapshot(reader, policy, deadline):
    info = _object(reader.get('/v1.45/info', deadline=deadline))
    if info.get('ID') != policy['daemonId']:
        raise ValueError('identity')
    inventory = reader.get(reader.list_path, deadline=deadline)
    if type(inventory) is not list or len(inventory) > 128:
        raise ValueError('inventory')
    containers, seen, private_commitments, service_commitments, instances = [], set(), {}, {}, {}
    for summary in inventory:
        summary = _object(summary)
        cid = summary.get('Id')
        if type(cid) is not str or not ID.fullmatch(cid) or cid in seen:
            raise ValueError('inventory')
        seen.add(cid)
        if _labels(summary.get('Labels'))['com.docker.compose.project'] != policy['project']:
            raise ValueError('inventory')
        raw = _object(reader.get(f'/v1.45/containers/{cid}/json', deadline=deadline))
        if reader.policy.private_key_id is not None:
            commitment = _object(reader.get(f'/v1.45/workflow/private/{cid}', deadline=deadline))
            private_commitments[cid] = commitment['configHmac']
        config = _object(raw.get('Config'))
        labels = _labels(config.get('Labels'))
        if raw.get('Id') != cid or labels['com.docker.compose.project'] != policy['project']:
            raise ValueError('identity')
        service = labels['com.docker.compose.service']
        if reader.policy.private_key_id is not None:
            service_commitments[service] = private_commitments[cid]
        if service != _labels(summary.get('Labels'))['com.docker.compose.service']:
            raise ValueError('identity')
        name = raw.get('Name')
        if type(name) is not str or not name.startswith('/'):
            raise ValueError('shape')
        network_map = _object(_object(raw.get('NetworkSettings')).get('Networks'))
        networks = []
        for network_name, endpoint in network_map.items():
            endpoint = _object(endpoint)
            aliases = endpoint.get('Aliases')
            if type(aliases) is not list:
                raise ValueError('shape')
            networks.append({'name': network_name, 'id': endpoint.get('NetworkID'),
                             'aliases': aliases})
        mounts = []
        raw_mounts = raw.get('Mounts')
        if type(raw_mounts) is not list:
            raise ValueError('shape')
        for mount in raw_mounts:
            mount = _object(mount)
            kind = mount.get('Type')
            mounts.append({'type': kind,
                           'source': mount.get('Name') if kind == 'volume' else mount.get('Source'),
                           'target': mount.get('Destination'), 'readOnly': not mount.get('RW') if type(mount.get('RW')) is bool else None})
        state = _object(raw.get('State'))
        pid, started_at, restarts = state.get('Pid'), state.get('StartedAt'), raw.get('RestartCount')
        if (type(pid) is not int or not 0 <= pid <= 1_000_000_000
                or type(started_at) is not str or not 1 <= len(started_at) <= 64
                or type(restarts) is not int or not 0 <= restarts <= 1_000_000_000):
            raise ValueError('instance')
        instances[cid] = (pid, started_at, restarts)
        health = state.get('Health')
        health_status = 'none' if health is None else _object(health).get('Status')
        containers.append({'id': cid, 'name': name[1:], 'service': service,
                           'project': labels['com.docker.compose.project'], 'labels': labels,
                           'imageId': raw.get('Image'), 'networks': networks,
                           'mounts': mounts, 'running': state.get('Running'), 'health': health_status})
    networks = []
    expected_networks = _object(policy.get('networks'))
    for name, network_id in expected_networks.items():
        if type(network_id) is not str or not ID.fullmatch(network_id):
            raise ValueError('policy')
        raw = _object(reader.get(f'/v1.45/networks/{network_id}', deadline=deadline))
        labels = _labels(raw.get('Labels'))
        networks.append({'name': raw.get('Name'), 'id': raw.get('Id'),
                         'project': labels['com.docker.compose.project']})
        if raw.get('Name') != name:
            raise ValueError('identity')
    volumes = []
    expected_volumes = _object(policy.get('volumes'))
    for name in expected_volumes:
        raw = _object(reader.get(f'/v1.45/volumes/{name}', deadline=deadline))
        labels = _labels(raw.get('Labels'))
        # Never pass daemon-supplied option values to diagnostics or output.
        options = raw.get('Options')
        if options != {}:
            raise ValueError('volume')
        volumes.append({'name': raw.get('Name'), 'project': labels['com.docker.compose.project'],
                        'driver': raw.get('Driver'), 'options': {}})
    images = {container['imageId'] for container in containers}
    image_evidence = {}
    for image_id in images:
        if type(image_id) is not str or not IMAGE.fullmatch(image_id):
            raise ValueError('image')
        image = _object(reader.get(f'/v1.45/images/{image_id}/json', deadline=deadline))
        if image.get('Id') != image_id:
            raise ValueError('image')
        digests = image.get('RepoDigests')
        architecture = image.get('Architecture')
        if (image.get('Os') != 'linux' or type(architecture) is not str
                or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', architecture)
                or type(digests) is not list or len(digests) > 128
                or len(digests) != len(set(digests))
                or any(type(item) is not str or not registry_reference(item) for item in digests)):
            raise ValueError('image')
        image_evidence[image_id] = {'os': 'linux', 'architecture': architecture,
                                    'repoDigests': sorted(digests)}
    bind_evidence = {}
    for index in range(reader.policy.bind_count):
        result = _object(reader.get(f'/v1.45/workflow/binds/{index}', deadline=deadline))
        bind_evidence[str(index)] = result['bindDigest']
    end = _object(reader.get('/v1.45/info', deadline=deadline))
    if end.get('ID') != policy['daemonId']:
        raise ValueError('identity')
    assessment = assess({'daemonId': info['ID'], 'project': policy['project'],
                         'networks': networks, 'volumes': volumes, 'containers': containers}, policy)
    assessment['privateDigest'] = None
    assessment['instanceDigest'] = None
    assessment['imageCatalogDigest'] = None
    assessment['bindDigest'] = None
    assessment['serviceConfigHmacs'] = (service_commitments
                                         if assessment['structuralStatus'] != 'blocked' else {})
    assessment['serviceContainerIds'] = {item['service']: item['id'] for item in containers}
    assessment['serviceImages'] = ({item['service']: item['imageId'] for item in containers}
                                   if assessment['structuralStatus'] != 'blocked' else {})
    return assessment, private_commitments, instances, image_evidence, bind_evidence


def collect(reader, policy, *, max_seconds=60):
    """Return only sanitized, untrusted assessment; failures are fail-closed."""
    if (type(reader) is not ComposeDockerReader or type(policy) is not dict
            or type(max_seconds) not in (int, float) or not 0 < max_seconds <= 300):
        return _blocked('invalid-input')
    try:
        deadline = time.monotonic() + max_seconds
        if (reader.policy.daemon_id != policy.get('daemonId') or
                reader.policy.project != policy.get('project') or
                set(reader.policy.volume_names) != set(_object(policy.get('volumes')))):
            return _blocked('reader-policy-mismatch')
        gateway_boot_id = (reader.gateway_info(deadline=deadline)['bootId']
                           if reader.policy.gateway_policy_hash is not None else None)
        first, first_private, first_instances, first_images, first_binds = _snapshot(reader, policy, deadline)
        if first['structuralStatus'] == 'blocked':
            return first
        second, second_private, second_instances, second_images, second_binds = _snapshot(reader, policy, deadline)
        if gateway_boot_id is not None and reader.gateway_info(deadline=deadline)['bootId'] != gateway_boot_id:
            return _blocked('gateway-boot-drift')
        if second['structuralStatus'] == 'blocked':
            return second
        if first['structureDigest'] != second['structureDigest']:
            return _blocked('structure-drift')
        if first_private != second_private:
            return _blocked('private-config-drift')
        if first_instances != second_instances:
            return _blocked('instance-drift')
        if first_images != second_images:
            return _blocked('image-catalog-drift')
        if first_binds != second_binds:
            return _blocked('bind-content-drift')
        canonical_instances = json.dumps(second_instances, sort_keys=True, separators=(',', ':')).encode('ascii')
        second['instanceDigest'] = hashlib.sha256(
            b'dev-workflow:compose-instance-batch:v1\0' + canonical_instances).hexdigest()
        second['imageCatalogDigest'] = image_catalog_digest(second_images)
        if reader.policy.bind_count:
            canonical_binds = json.dumps(second_binds, sort_keys=True, separators=(',', ':')).encode('ascii')
            second['bindDigest'] = hashlib.sha256(
                b'dev-workflow:compose-bind-batch:v1\0' + canonical_binds).hexdigest()
        if reader.policy.private_key_id is not None:
            canonical = json.dumps(second_private, sort_keys=True, separators=(',', ':')).encode('ascii')
            second['privateDigest'] = hashlib.sha256(b'dev-workflow:compose-private-batch:v1\0' + canonical).hexdigest()
        else:
            second['privateDigest'] = None
        return second
    except ComposeReadError as error:
        return _blocked('docker-read-' + error.code)
    except Exception:
        # Docker errors, policy values and inspect payloads may contain secrets.
        return _blocked('read-unverified')
