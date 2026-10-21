#!/usr/bin/env python3
"""Project configuration and explicit local adoption. Python standard library only."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

# Importing this helper from a read-only tool must not create project bytecode.
sys.dont_write_bytecode = True
from workflow_lock import LifecycleLock, pending_upgrades

CAPABILITY_PACKS = {
    **dict.fromkeys(('api:rest-openapi', 'api:graphql', 'api:grpc', 'api:websocket', 'api:sse'), 'api-governance'),
    **dict.fromkeys(('containers:oci-docker', 'containers:compose'), 'containers'),
    **dict.fromkeys(('cicd:github-actions', 'cicd:gitlab-ci', 'cicd:jenkins', 'cicd:generic'), 'delivery-cicd'),
    **dict.fromkeys(('deployment:compose', 'deployment:kubernetes-helm', 'deployment:vm-systemd', 'deployment:serverless', 'deployment:generic'), 'deployment'),
    'release': 'release',
}
CONFIG_NAME = 'workflow.config.json'
MANIFEST_NAME = '.dev-workflow/manifest.json'
DEPLOYMENT_PHASES = ('preflight', 'deploy', 'health', 'smoke', 'rollback')
DEPLOYMENT_OPTIONAL_PHASES = ('backup', 'restore', 'migrate')


def portable_identifier(value: object) -> bool:
    return isinstance(value, str) and len(value) <= 128 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', value) is not None


def validate_deployment(deployment: object, commands: object) -> list[str]:
    """Validate declarations only; capability activation and execution stay explicit."""
    errors = []
    if not isinstance(deployment, dict) or set(deployment) != {'components', 'environments'}:
        return ['deployment must contain exactly components and environments']
    components = deployment['components']
    if (not isinstance(components, list) or not components
            or any(not portable_identifier(name) for name in components)
            or len(components) != len(set(components))):
        errors.append('deployment components must be unique portable identifiers')
    environments = deployment['environments']
    if not isinstance(environments, dict) or not environments:
        return errors + ['deployment environments must be a nonempty object']
    for name, environment in environments.items():
        if not portable_identifier(name):
            errors.append('deployment environment names must be portable identifiers')
        if not isinstance(environment, dict) or set(environment) != {'capability', 'target', 'commands', 'production', 'components'}:
            errors.append('deployment environment must contain exactly capability, target, production, components and commands')
            continue
        capability = environment['capability']
        if not isinstance(capability, str) or CAPABILITY_PACKS.get(capability) != 'deployment':
            errors.append('deployment capability must be a registered deployment capability ID')
        if not portable_identifier(environment['target']):
            errors.append('deployment target must be a portable identifier')
        if type(environment['production']) is not bool:
            errors.append('deployment production must be a boolean')
        selected = environment['components']
        if (not isinstance(selected, list) or not selected
                or any(not portable_identifier(name) for name in selected)
                or len(selected) != len(set(selected))
                or not isinstance(components, list) or any(name not in components for name in selected)):
            errors.append('deployment environment components must be a nonempty unique subset of deployment components')
        references = environment['commands']
        if not isinstance(references, dict) or set(references) - set(DEPLOYMENT_PHASES + DEPLOYMENT_OPTIONAL_PHASES):
            errors.append('deployment commands must contain only registered deployment phases')
            continue
        for reference in references.values():
            if not portable_identifier(reference) or not isinstance(commands, dict) or reference not in commands:
                errors.append('deployment commands must reference existing root command names')
    return errors


def safe_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if relative == '.':
        return root
    if path.is_absolute() or '..' in path.parts or '\\' in relative or not path.parts:
        raise ValueError('path must be relative and remain inside the project')
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('symbolic links are not allowed for workflow data')
    if not current.resolve().is_relative_to(root.resolve()):
        raise ValueError('path escapes project')
    return current


def read_object(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(obj, dict):
        raise ValueError('expected a JSON object')
    return obj


def validate_config(config: dict) -> list[str]:
    errors = []
    if type(config.get('schemaVersion')) is not int or config['schemaVersion'] != 1:
        errors.append('schemaVersion must be 1')
    unknown = set(config) - {'schemaVersion', 'enabledCapabilities', 'commands', 'documents', 'extensions'}
    if unknown:
        errors.append('unknown project configuration fields: ' + ', '.join(sorted(unknown)))
    caps = config.get('enabledCapabilities')
    if not isinstance(caps, list) or any(not isinstance(c, str) or c not in CAPABILITY_PACKS for c in caps):
        errors.append('enabledCapabilities must contain registered capability IDs')
    elif len(caps) != len(set(caps)):
        errors.append('enabledCapabilities contains duplicate IDs')
    for key in ('commands', 'documents', 'extensions'):
        if not isinstance(config.get(key, {}), dict):
            errors.append(key + ' must be an object')
    for name, spec in config.get('commands', {}).items() if isinstance(config.get('commands', {}), dict) else []:
        if not isinstance(spec, dict) or set(spec) - {'command', 'cwd'} or not isinstance(spec.get('command'), str) or not spec['command'].strip():
            errors.append('invalid command declaration: ' + name)
        else:
            cwd = spec.get('cwd', '.')
            if not isinstance(cwd, str) or Path(cwd).is_absolute() or '..' in Path(cwd).parts or '\\' in cwd:
                errors.append('command cwd must remain inside project: ' + name)
    for name, value in config.get('documents', {}).items() if isinstance(config.get('documents', {}), dict) else []:
        if not isinstance(value, str) or not value or Path(value).is_absolute() or '..' in Path(value).parts or '\\' in value:
            errors.append('document path must remain inside project: ' + name)
    extensions = config.get('extensions', {})
    if isinstance(extensions, dict):
        if set(extensions) - {'release', 'deployment'}:
            errors.append('unsupported extension')
        if 'deployment' in extensions:
            errors.extend(validate_deployment(extensions['deployment'], config.get('commands', {})))
        release = extensions.get('release')
        if release is not None:
            if not isinstance(release, dict) or set(release) - {'strategy', 'tagPrefix', 'components'}:
                errors.append('invalid release extension')
            elif release.get('strategy') not in {'none', 'commit-sha', 'semver-tag'}:
                errors.append('release strategy must be none, commit-sha or semver-tag')
            else:
                components = release.get('components', [])
                if not isinstance(components, list) or any(not isinstance(c, str) or not c or not all(ch.isalnum() or ch in '-_.' for ch in c) for c in components) or len(components) != len(set(components)):
                    errors.append('release components must be unique names')
                prefix = release.get('tagPrefix', 'v')
                if not isinstance(prefix, str) or any(ch.isspace() or ch in '~^:?*[\\' for ch in prefix):
                    errors.append('invalid release tagPrefix')
    return errors


def fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_configuration(root: Path) -> dict:
    root = root.resolve()
    result = dict(config={}, manifest={}, source='manifest', capabilities=[], errors=[], warnings=[])

    def issue(level, code, message):
        result[level].append(dict(code=code, message=message))

    try:
        manifest_path = safe_path(root, MANIFEST_NAME)
        manifest = read_object(manifest_path)
        if manifest.get('managedBy') != 'dev-workflow' or manifest.get('schemaVersion') not in (1, 2, 3, 4, 5):
            raise ValueError('not a supported dev-workflow installation')
        result['manifest'] = manifest
        caps = manifest.get('enabledCapabilities', [])
        if not isinstance(caps, list) or any(not isinstance(c, str) or c not in CAPABILITY_PACKS for c in caps) or len(caps) != len(set(caps)):
            raise ValueError('invalid manifest capabilities')
        result['capabilities'] = caps
    except (OSError, ValueError, TypeError):
        issue('errors', 'manifest.invalid', 'Installation manifest is missing or invalid.')
        return result
    marker = manifest.get('projectConfiguration')
    if marker is not None and (not isinstance(marker, dict) or type(marker.get('adopted')) is not bool):
        result['capabilities'] = []
        issue('errors', 'config.state_invalid', 'Invalid project configuration adoption marker.')
        return result
    if marker and not marker['adopted']:
        # Explicit withdrawal detaches the retained file, including later edits.
        return result
    try:
        config_path = safe_path(root, CONFIG_NAME)
        if not config_path.exists():
            if marker and marker['adopted']:
                result['capabilities'] = []
                issue('errors', 'config.missing', 'Adopted configuration is missing; restore it or explicitly withdraw using a valid configuration.')
            return result
        config = read_object(config_path)
        validation = validate_config(config)
        if validation:
            raise ValueError('; '.join(validation))
        result['config'] = config
    except (OSError, ValueError, TypeError):
        result['capabilities'] = []
        issue('errors', 'config.invalid', 'Project configuration is invalid; no manifest fallback is allowed.')
        return result
    if marker and marker['adopted']:
        result['source'] = 'project'
        result['capabilities'] = config['enabledCapabilities']
        if marker.get('sha256') != fingerprint(config_path) or caps != config['enabledCapabilities']:
            issue('warnings', 'config.drift', 'Project configuration differs from its local compatibility snapshot; explicitly sync it.')
    else:
        result['source'] = 'unadopted'
        result['capabilities'] = []
        issue('errors', 'config.unadopted', 'Project configuration requires explicit adoption on this machine.')
    return result


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'adopt', 'withdraw', 'sync', 'update', 'installer-capabilities', 'installer-sync', 'state'])
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--enable', default='')
    parser.add_argument('--disable', default='')
    parser.add_argument('--create', action='store_true', help='adopt: create an empty project configuration from existing capabilities')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    root = args.repo.resolve()
    try:
        result = resolve_configuration(root)
        config_path = safe_path(root, CONFIG_NAME)
        manifest_path = safe_path(root, MANIFEST_NAME)
        if args.action == 'check':
            print(json.dumps(result, ensure_ascii=True))
            return int(bool(result['errors']))
        if args.action == 'state':
            print(json.dumps(result['manifest'].get('projectConfiguration')))
            return int(any(e['code'] != 'config.unadopted' for e in result['errors']))
        errors = [e for e in result['errors'] if not (args.action in ('adopt', 'installer-capabilities', 'installer-sync') and e['code'] == 'config.unadopted')]
        if args.action == 'installer-capabilities' and not manifest_path.exists():
            # Bootstrap a clone with a shared config without silently adopting it.
            if config_path.exists():
                validation = validate_config(read_object(config_path))
                if validation:
                    raise ValueError('invalid project configuration')
            errors = []
        if errors:
            raise ValueError('; '.join(e['message'] for e in errors))
        config = deepcopy(result['config'])
        manifest = deepcopy(result['manifest'])
        enabled = [c.strip() for c in args.enable.split(',') if c.strip()]
        disabled = [c.strip() for c in args.disable.split(',') if c.strip()]
        if any(c not in CAPABILITY_PACKS for c in enabled + disabled):
            raise ValueError('unknown capability ID')
        if args.action in ('installer-capabilities', 'installer-sync') and not (enabled or disabled) and any(item['code'] == 'config.drift' for item in result['warnings']):
            raise ValueError('configuration drift requires explicit sync before reinstalling')
        if args.action == 'adopt':
            if not config_path.exists():
                if not args.create:
                    raise ValueError('adopt requires an existing configuration or --create')
                config = dict(schemaVersion=1, enabledCapabilities=list(manifest.get('enabledCapabilities', [])), commands={}, documents={}, extensions={})
            elif not config:
                config = read_object(config_path)
            if validate_config(config):
                raise ValueError('invalid project configuration')
        elif args.action in ('withdraw', 'sync') and result['source'] != 'project':
            raise ValueError('no adopted project configuration')
        caps = list(config['enabledCapabilities'] if args.action == 'adopt' else manifest.get('enabledCapabilities', []) if result['source'] == 'unadopted' else result['capabilities'])
        caps = [c for c in dict.fromkeys(caps + enabled) if c not in disabled]
        if args.action == 'installer-capabilities':
            print('\n'.join(caps))
            return 0
        project_active = args.action == 'adopt' or result['source'] == 'project'
        if args.action == 'withdraw':
            manifest['enabledCapabilities'] = caps
            manifest['projectConfiguration'] = {'adopted': False}
            writes = [(manifest_path, manifest)]
        elif project_active:
            config['enabledCapabilities'] = caps
            encoded = (json.dumps(config, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
            manifest['enabledCapabilities'] = caps
            manifest['projectConfiguration'] = {'adopted': True, 'sha256': hashlib.sha256(encoded).hexdigest()}
            writes = [(config_path, config), (manifest_path, manifest)]
        else:
            manifest['enabledCapabilities'] = caps
            writes = [(manifest_path, manifest)]
        output = dict(action=args.action, dryRun=args.dry_run, capabilities=caps, writes=[str(p.relative_to(root)) for p, _ in writes], permissionsChanged=False)
        if not args.dry_run:
            with LifecycleLock(root, 'configuration', borrow_parent=True):
                if pending_upgrades(root):
                    raise ValueError('Incomplete upgrade transaction; recover it before changing configuration')
                lock = safe_path(root, '.dev-workflow/configuration.lock')
                fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.close(fd)
                    # Recheck under both locks; interrupted writes are diagnosed as drift.
                    if read_object(manifest_path) != result['manifest']:
                        raise ValueError('manifest changed during preparation; retry')
                    if config_path.exists() and result['config'] and read_object(config_path) != result['config']:
                        raise ValueError('configuration changed during preparation; retry')
                    for path, value in writes:
                        atomic_json(path, value)
                finally:
                    lock.unlink()
        print(json.dumps(output, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        # Do not echo arbitrary JSON values, commands or paths that could contain secrets.
        message = str(exc) if isinstance(exc, ValueError) else 'configuration operation failed; check paths, JSON and configuration lock'
        print(json.dumps(dict(error=message)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
