#!/usr/bin/env python3
"""Read-only Compose batch screening. A candidate never authorizes or executes work."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
import deployment_compose_preflight as preflight
import deployment_prepare as planner

NAME = preflight.NAME
HASH = re.compile(r'sha256:[0-9a-f]{64}\Z')
SAFE_FIELDS = preflight.SUPPORTED_KEYS | {'volumes', 'container_name'}


def _names(value):
    return (isinstance(value, list)
            and all(isinstance(item, str) and NAME.fullmatch(item) for item in value)
            and len(value) == len(set(value)))


def _dependencies(service):
    value = service.get('depends_on', [])
    if isinstance(value, dict) and all(
            isinstance(k, str) and NAME.fullmatch(k)
            and isinstance(v, dict) and set(v) <= {'condition', 'required', 'restart'}
            and v.get('condition') == 'service_healthy'
            and v.get('required', True) is True
            and v.get('restart', False) is False for k, v in value.items()):
        return list(value)
    if value == []:
        return []
    return None


def _mounts(service, volumes):
    counts = {'namedVolume': 0, 'readOnlyBind': 0}
    unverified = set()
    mounts = service.get('volumes', [])
    if not isinstance(mounts, list):
        return None
    targets = set()
    for mount in mounts:
        if not isinstance(mount, dict) or set(mount) - {'type', 'source', 'target', 'read_only', 'bind', 'volume'}:
            return None
        kind, source, target = (mount.get(key) for key in ('type', 'source', 'target'))
        if (not isinstance(source, str) or not source or not isinstance(target, str)
                or not target.startswith('/') or target == '/' or target in targets):
            return None
        targets.add(target)
        if kind == 'volume' and source in volumes and NAME.fullmatch(source):
            if (type(mount.get('read_only', False)) is not bool or 'bind' in mount
                or mount.get('volume', {}) not in ({}, {'nocopy': True})):
                return None
            if mount.get('volume', {}) == {}:
                unverified.add('existing-volume-nocopy')
            counts['namedVolume'] += 1
        elif kind == 'bind' and source.startswith('/') and mount.get('read_only') is True:
            if 'volume' in mount or mount.get('bind', {}) not in ({}, {'create_host_path': False}):
                return None
            if mount.get('bind', {}) == {}:
                unverified.add('bind-create-host-path')
            counts['readOnlyBind'] += 1
        else:
            return None
    return counts, unverified


def assess(model: dict, policy: dict) -> dict:
    reasons = set()
    selected, protected, services = [], [], {}
    if not isinstance(model, dict) or not isinstance(model.get('services'), dict):
        reasons.add('invalid-compose-model')
    else:
        services = model['services']
    if len(services) > 128:
        reasons.add('compose-service-limit')
    if not isinstance(policy, dict):
        policy = {}
    if set(policy) - {'project', 'selectedServices', 'protectedServices', 'allowInterruption', 'migrations'}:
        reasons.add('unsupported-policy-fields')
    selected = policy.get('selectedServices')
    protected = policy.get('protectedServices')
    if not isinstance(policy.get('project'), str) or not NAME.fullmatch(policy['project']):
        reasons.add('invalid-project')
    elif policy['project'] != (model.get('name') if isinstance(model, dict) else None):
        reasons.add('project-identity-mismatch')
    if any(not isinstance(name, str) or not NAME.fullmatch(name) for name in services):
        reasons.add('invalid-service-name')
    identities = set()
    for name, service in services.items():
        if not isinstance(service, dict):
            reasons.add('invalid-compose-service')
            continue
        explicit = service.get('container_name')
        if explicit is not None and (not isinstance(explicit, str) or not NAME.fullmatch(explicit)):
            reasons.add('invalid-container-name')
        if (isinstance(policy.get('project'), str) and NAME.fullmatch(policy['project'])
                and isinstance(name, str) and NAME.fullmatch(name)):
            effective = explicit if isinstance(explicit, str) and NAME.fullmatch(explicit) else f"{policy['project']}-{name}-1"
            if effective in identities:
                reasons.add('container-name-conflict')
            identities.add(effective)
    if not _names(selected) or not selected:
        reasons.add('invalid-selected-services')
        selected = []
    if len(selected) > 32:
        reasons.add('selected-service-limit')
    if not _names(protected):
        reasons.add('invalid-protected-services')
        protected = []
    if set(selected) & set(protected):
        reasons.add('overlapping-service-scope')
    if set(selected) | set(protected) != set(services):
        reasons.add('incomplete-service-scope')
    if policy.get('allowInterruption') is not True:
        reasons.add('interruption-consent-required')
    migrations = policy.get('migrations')
    if not isinstance(migrations, dict) or set(migrations) != set(selected):
        reasons.add('migration-declarations-required')
        migrations = {}
    counts = {'namedVolume': 0, 'readOnlyBind': 0}
    unverified = set()
    graph = {}
    volumes = model.get('volumes', {})
    if not isinstance(volumes, dict):
        volumes = {}
        reasons.add('invalid-volume-declarations')
    for name in selected:
        service = services.get(name)
        if not isinstance(service, dict):
            reasons.add('missing-selected-service')
            continue
        if set(service) - SAFE_FIELDS:
            reasons.add('unsupported-service-fields')
        if 'container_name' in service and (not isinstance(service['container_name'], str)
                                            or not NAME.fullmatch(service['container_name'])):
            reasons.add('invalid-container-name')
        if service.get('command') is not None or service.get('entrypoint') is not None:
            reasons.add('command-override-unsupported')
        if not planner.registry_reference(service.get('image')):
            reasons.add('immutable-image-required')
        deps = _dependencies(service)
        if deps is None or any(dep not in services for dep in deps):
            reasons.add('invalid-service-dependencies')
        else:
            graph[name] = sorted(set(deps) & set(selected))
        mount_counts = _mounts(service, volumes)
        if mount_counts is None:
            reasons.add('unsupported-mount')
        else:
            mount_counts, mount_unverified = mount_counts
            for key in counts:
                counts[key] += mount_counts[key]
            unverified.update(mount_unverified)
        declaration = migrations.get(name)
        if (not isinstance(declaration, dict) or set(declaration) != {'source', 'target'}
                or not isinstance(declaration.get('source'), str)
                or not HASH.fullmatch(declaration['source'])
                or declaration.get('source') != declaration.get('target')):
            reasons.add('migration-set-mismatch')
    order, visiting, visited = [], set(), set()

    def visit(name):
        if name in visiting:
            reasons.add('service-dependency-cycle')
            return
        if name in visited:
            return
        visiting.add(name)
        for dependency in graph.get(name, []):
            visit(dependency)
        visiting.remove(name)
        visited.add(name)
        order.append(name)

    if len(services) <= 128 and len(selected) <= 32:
        for name in sorted(graph):
            visit(name)
    if len(order) != len(selected):
        order = []
    return {'schemaVersion': 1, 'kind': 'compose-batch-offline-plan',
            'structuralStatus': 'blocked' if reasons else 'candidate-unverified',
            'reasons': sorted(reasons), 'selectedServices': sorted(selected),
            'unverifiedConstraints': sorted(unverified),
            'protectedServices': sorted(protected), 'startOrder': order if not reasons else [],
            'stopOrder': list(reversed(order)) if not reasons else [],
            'mountTypes': counts, 'runtimeVerification': 'unknown',
            'authorityGranted': False, 'executionAvailable': False, 'productionReady': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        for path in (args.model, args.policy):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > preflight.MAX_MODEL:
                raise preflight.PreflightError('invalid-input-file')
        model = preflight.parse_model(args.model.read_bytes())
        policy = json.loads(args.policy.read_bytes(), object_pairs_hook=preflight._unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        print(json.dumps(assess(model, policy), sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError) as error:
        code = str(error) if isinstance(error, preflight.PreflightError) else 'invalid-input'
        print(json.dumps({'error': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
