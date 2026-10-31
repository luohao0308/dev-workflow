#!/usr/bin/env python3
"""Validate an untrusted, pre-projected Compose inspect snapshot without granting authority.

The caller, not this module, obtains Docker data. Neither input nor this projection is
trusted evidence for deployment authorization. It cannot prove that same-named volumes
are the same physical volumes, or that Env/configuration did not drift. A future trusted
host must verify those separately. Raw inspect objects must never be logged.
"""
from __future__ import annotations

import hashlib
import json
import re

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
ID = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
DAEMON = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z')


def _names(value):
    return (isinstance(value, list) and all(isinstance(x, str) and NAME.fullmatch(x) for x in value)
            and len(value) == len(set(value)))


def _mapping(value):
    return isinstance(value, dict) and all(isinstance(k, str) and NAME.fullmatch(k) for k in value)


def _volume_shape(value):
    return (isinstance(value, dict) and isinstance(value.get('driver'), str)
            and bool(NAME.fullmatch(value['driver'])) and isinstance(value.get('options'), dict)
            and all(isinstance(k, str) and isinstance(v, (str, type(None)))
                    for k, v in value['options'].items()))


def _normalized_mounts(value, volumes, reasons):
    if not isinstance(value, list):
        reasons.add('invalid-mount')
        return []
    result, targets = [], set()
    for mount in value:
        if not isinstance(mount, dict) or set(mount) != {'type', 'source', 'target', 'readOnly'}:
            reasons.add('invalid-mount')
            continue
        kind, source, target = (mount[k] for k in ('type', 'source', 'target'))
        if (not isinstance(target, str) or not target.startswith('/') or target == '/'
                or target in targets or not isinstance(source, str) or not source):
            reasons.add('mount-target-conflict')
            continue
        targets.add(target)
        if kind == 'volume' and source not in volumes:
            reasons.add('unknown-volume')
        elif kind == 'bind' and (mount['readOnly'] is not True or not source.startswith('/')):
            reasons.add('writable-bind')
        elif kind not in ('volume', 'bind') or type(mount['readOnly']) is not bool:
            reasons.add('invalid-mount')
        result.append(mount)
    return sorted(result, key=lambda x: (x['target'], x['type'], x['source']))


def _result(reasons, structure=None, health=None):
    return {'schemaVersion': 1, 'kind': 'compose-untrusted-inspect-projection',
            'structuralStatus': 'blocked' if reasons else 'candidate-unverified',
            'reasons': sorted(reasons), 'structureDigest': structure if not reasons else None,
            'serviceState': health if not reasons else {}, 'runtimeVerification': 'unknown',
            'authorityGranted': False, 'executionAvailable': False, 'productionReady': False}


def assess(records: dict, policy: dict) -> dict:
    """Assess a bounded snapshot. Policies describe the expected full Compose scope.

    records: {daemonId, project, networks:[{name,id,project}],
      volumes:[{name,project,driver,options}], containers:[{id,name,service,project,
      labels:{com.docker.compose.project,com.docker.compose.service},imageId,
      networks:[{name,id,aliases}],mounts:[{type,source,target,readOnly}],
      running,health}]}.
    policy: {daemonId,project,selectedServices,protectedServices,
      networks:{name:id},volumes:{name:{driver,options}},
      mounts:{service:[{type,source,target,readOnly}]},
      containerNames:{service:name},
      networkAttachments:{service:{network:[alias,...]}}}.
    """
    reasons = set()
    if not isinstance(records, dict) or not isinstance(policy, dict):
        return _result({'invalid-input'})
    selected, protected = policy.get('selectedServices'), policy.get('protectedServices')
    if not _names(selected) or not selected or not _names(protected) or set(selected) & set(protected):
        reasons.add('invalid-service-scope')
        selected, protected = [], []
    scope = set(selected) | set(protected)
    project, daemon = policy.get('project'), policy.get('daemonId')
    if not isinstance(project, str) or not NAME.fullmatch(project) or not isinstance(daemon, str) or not DAEMON.fullmatch(daemon):
        reasons.add('invalid-policy-identity')
    if records.get('project') != project or records.get('daemonId') != daemon:
        reasons.add('identity-mismatch')
    expected_networks, expected_volumes, expected_mounts = (policy.get(k) for k in ('networks', 'volumes', 'mounts'))
    expected_names = policy.get('containerNames')
    if (not _mapping(expected_names) or set(expected_names) != scope
            or any(not isinstance(v, str) or not NAME.fullmatch(v) for v in expected_names.values())
            or len(set(expected_names.values())) != len(scope)):
        reasons.add('invalid-container-name-policy')
        expected_names = {}
    if not _mapping(expected_networks) or not expected_networks or any(not isinstance(v, str) or not ID.fullmatch(v) for v in expected_networks.values()):
        reasons.add('invalid-network-policy')
        expected_networks = {}
    expected_attachments = policy.get('networkAttachments')
    if (not _mapping(expected_attachments) or set(expected_attachments) != scope
            or any(not _mapping(value) or not value
                   or any(network not in (expected_networks or {}) or not _names(aliases)
                          or service not in aliases
                          for network, aliases in value.items())
                   for service, value in expected_attachments.items())):
        reasons.add('invalid-network-attachment-policy')
        expected_attachments = {}
    if not _mapping(expected_volumes) or not _mapping(expected_mounts) or set(expected_mounts) != scope:
        reasons.add('invalid-mount-policy')
        expected_volumes, expected_mounts = {}, {}
    networks = records.get('networks')
    if not isinstance(networks, list) or len(networks) != len(expected_networks):
        reasons.add('network-set-mismatch')
        networks = []
    seen_networks = set()
    for network in networks:
        if not isinstance(network, dict):
            reasons.add('invalid-network')
            continue
        name, network_id = network.get('name'), network.get('id')
        if not isinstance(name, str) or name in seen_networks or expected_networks.get(name) != network_id or network.get('project') != project:
            reasons.add('network-identity-mismatch')
        if isinstance(name, str):
            seen_networks.add(name)
    volumes = records.get('volumes')
    if not isinstance(volumes, list) or len(volumes) != len(expected_volumes):
        reasons.add('volume-set-mismatch')
        volumes = []
    seen_volumes = set()
    for volume in volumes:
        if not isinstance(volume, dict):
            reasons.add('invalid-volume')
            continue
        name = volume.get('name')
        expected = expected_volumes.get(name) if isinstance(name, str) else None
        if (not isinstance(name, str) or name in seen_volumes or not _volume_shape(expected)
                or not _volume_shape(volume) or volume.get('project') != project
                or volume.get('driver') != expected.get('driver')
                or volume.get('options') != expected.get('options')
                or expected.get('driver') != 'local' or expected.get('options') != {}):
            reasons.add('volume-identity-mismatch')
        if isinstance(name, str):
            seen_volumes.add(name)
    containers = records.get('containers')
    if not isinstance(containers, list) or len(containers) != len(scope):
        reasons.add('service-set-mismatch')
        containers = []
    seen_services, seen_ids, seen_names = set(), set(), set()
    alias_owners = {}
    for service, attachments in expected_attachments.items():
        for network_name in attachments:
            for alias in (service, expected_names.get(service)):
                if alias is None:
                    continue
                key = (network_name, alias)
                owner = alias_owners.setdefault(key, service)
                if owner != service:
                    reasons.add('network-alias-collision')
    projection, state = [], {}
    for container in containers:
        if not isinstance(container, dict):
            reasons.add('invalid-container')
            continue
        service, container_id, name = (container.get(k) for k in ('service', 'id', 'name'))
        if (not isinstance(service, str) or service not in scope or service in seen_services or not isinstance(container_id, str)
                or not ID.fullmatch(container_id) or container_id in seen_ids
                or not isinstance(name, str) or not NAME.fullmatch(name) or name in seen_names):
            reasons.add('container-identity-mismatch')
            continue
        if expected_names.get(service) != name:
            reasons.add('container-name-mismatch')
        seen_services.add(service)
        seen_ids.add(container_id)
        seen_names.add(name)
        labels = container.get('labels')
        if (container.get('project') != project or not isinstance(labels, dict)
                or labels.get('com.docker.compose.project') != project
                or labels.get('com.docker.compose.service') != service):
            reasons.add('container-project-mismatch')
        image_id = container.get('imageId')
        if not isinstance(image_id, str) or not IMAGE.fullmatch(image_id):
            reasons.add('invalid-image-id')
        attachments = container.get('networks')
        if not isinstance(attachments, list) or not attachments:
            reasons.add('missing-network-identity')
            attachments = []
        attached = set()
        network_projection = []
        for attachment in attachments:
            if not isinstance(attachment, dict):
                reasons.add('invalid-network-attachment')
                continue
            network_name = attachment.get('name')
            aliases = attachment.get('aliases')
            if (not isinstance(network_name, str) or network_name in attached or expected_networks.get(network_name) != attachment.get('id')
                    or not _names(aliases) or service not in aliases):
                reasons.add('network-alias-mismatch')
                continue
            attached.add(network_name)
            network_projection.append({'name': network_name, 'id': attachment['id'], 'aliases': sorted(aliases)})
        wanted_attachments = expected_attachments.get(service, {})
        actual_attachments = {item['name']: item['aliases'] for item in network_projection}
        if actual_attachments != {network: sorted(aliases) for network, aliases in wanted_attachments.items()}:
            reasons.add('network-attachment-mismatch')
        for attachment in network_projection:
            for alias in attachment['aliases']:
                key = (attachment['name'], alias)
                owner = alias_owners.setdefault(key, service)
                if owner != service:
                    reasons.add('network-alias-collision')
        mounts = _normalized_mounts(container.get('mounts'), expected_volumes, reasons)
        expected = _normalized_mounts(expected_mounts.get(service), expected_volumes, reasons)
        if mounts != expected:
            reasons.add('mount-mismatch')
        projection.append({'service': service, 'id': container_id, 'name': name, 'imageId': image_id,
                           'networks': sorted(network_projection, key=lambda x: x['name']),
                           'mounts': mounts})
        running, health = container.get('running'), container.get('health')
        if type(running) is not bool or health not in ('healthy', 'unhealthy', 'starting', 'none'):
            reasons.add('invalid-service-state')
        else:
            state[service] = {'running': running, 'health': health}
    if seen_services != scope:
        reasons.add('service-set-mismatch')
    if reasons:
        return _result(reasons)
    canonical = {'daemonId': daemon, 'project': project,
                 'networks': sorted(({'name': x['name'], 'id': x['id']} for x in networks), key=lambda x: x['name']),
                 'volumes': sorted(({'name': x['name'], 'driver': x['driver'], 'options': x['options']}
                                    for x in volumes), key=lambda x: x['name']),
                 'containers': sorted(projection, key=lambda x: x['service'])}
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return _result(reasons, 'sha256:' + digest, state)
