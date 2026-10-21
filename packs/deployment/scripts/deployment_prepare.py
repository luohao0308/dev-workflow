#!/usr/bin/env python3
"""Offline deployment/rollback planning and comparisons of supplied snapshots only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve()
sys.path.insert(0, str(SCRIPT.parent))
if len(SCRIPT.parents) > 3:
    sys.path.append(str(SCRIPT.parents[3] / 'core/scripts'))
from workflow_config import resolve_configuration
from workflow_lock import LifecycleLock, linked, pending_upgrades

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
VERSION_LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z')
SHA = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
PHASES = ('preflight', 'deploy', 'health', 'smoke', 'rollback')
RECORDS = '.dev-workflow/releases/deployments/'
MAX_BYTES = 1024 * 1024
FIELDS = ('sourceSha', 'artifact', 'configurationDigest', 'migrationVersion')


class PlanningError(ValueError):
    pass


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value) -> datetime:
    if not isinstance(value, str):
        raise PlanningError('Snapshot capturedAt requires a timezone-aware timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise PlanningError('Invalid snapshot capturedAt') from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PlanningError('Snapshot capturedAt requires a timezone')
    return parsed.astimezone(timezone.utc)


def path_at(root: Path, relative: str, *, directory=False) -> Path:
    if relative == '.' and directory:
        return root
    if (not isinstance(relative, str) or not relative or '\\' in relative or ':' in relative
            or any(ord(c) < 32 or ord(c) == 127 for c in relative)):
        raise PlanningError('Expected a portable repository-relative path')
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or any(part in ('', '.', '..') for part in relative.split('/')):
        raise PlanningError('Path must remain inside the repository')
    result = root
    for part in parsed.parts:
        result = result / part
        if linked(result):
            raise PlanningError('Linked or reparsed deployment data path refused')
    if not result.resolve().is_relative_to(root):
        raise PlanningError('Deployment data escapes repository')
    return result


def relative_input(root: Path, path: Path) -> str:
    if path.is_absolute():
        try:
            value = path.relative_to(root).as_posix()
        except ValueError as error:
            raise PlanningError('Deployment inputs must remain inside repository') from error
    else:
        value = path.as_posix()
    path_at(root, value)
    return value


def read_data(root: Path, name: str, *, json_file=True):
    path = path_at(root, name)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise PlanningError('Deployment input must be a regular file no larger than 1 MiB')
    if json_file and path.suffix.lower() != '.json':
        raise PlanningError('Deployment manifests must be explicit JSON files')
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise PlanningError('Deployment input exceeds 1 MiB')
    record = dict(path=name, sha256=sha256(data), verification='supplied_unverified')
    if not json_file:
        return record

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PlanningError('Duplicate JSON field in deployment data')
            result[key] = value
        return result
    value = json.loads(data.decode('utf-8'), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise PlanningError('Deployment input must be a JSON object')
    return value, record


def git(root: Path, *args: str, input_text: str | None = None) -> str:
    try:
        result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', str(root), *args],
                                capture_output=True, timeout=30,
                                input=input_text.encode('utf-8') if input_text is not None else None,
                                env={**os.environ, 'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0'})
        result.stdout = result.stdout.decode('utf-8', errors='strict')
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        raise PlanningError('Local Git state could not be inspected') from error
    if result.returncode:
        raise PlanningError('Local Git state could not be inspected')
    return result.stdout.strip()


def offline_worktree_status(root: Path) -> str:
    # status can run clean/process filters or recurse into submodule worktrees.
    # Reject those unsupported inspections before reading worktree contents.
    entries = git(root, 'ls-files', '--stage', '-z').split('\0')
    paths = []
    for entry in entries:
        if not entry:
            continue
        metadata, name = entry.split('\t', 1)
        if metadata.split()[0] == '160000':
            raise PlanningError('Submodule worktree inspection is unsupported by the offline planner')
        paths.append(name)
    if paths:
        attributes = git(root, 'check-attr', '-z', '--stdin', 'filter', input_text='\0'.join(paths) + '\0').split('\0')
        for index in range(0, len(attributes) - 2, 3):
            if attributes[index + 2] not in ('unspecified', 'unset'):
                raise PlanningError('External Git content filters are unsupported by the offline planner')
    return git(root, 'status', '--porcelain', '--untracked-files=all', '--ignore-submodules=all',
               '--', '.', ':(exclude).dev-workflow/releases')


def registry_reference(value) -> bool:
    if not isinstance(value, str) or value.count('@') != 1:
        return False
    name, digest = value.split('@')
    if not DIGEST.fullmatch(digest) or '/' not in name or len(name) > 255:
        return False
    authority, path = name.split('/', 1)
    host, separator, port = authority.partition(':')
    label = r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?'
    if not re.fullmatch(label + r'(?:\.' + label + r')*', host):
        return False
    if separator and (not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535):
        return False
    segment = r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*'
    return all(re.fullmatch(segment, part) for part in path.split('/'))


def component(value: dict) -> dict:
    keys = {'name', 'sourceSha', 'artifact', 'configurationDigest', 'migrationVersion'}
    if not isinstance(value, dict) or set(value) != keys or not isinstance(value.get('name'), str) or not NAME.fullmatch(value['name']):
        raise PlanningError('Invalid deployment component fields')
    if not isinstance(value['sourceSha'], str) or not SHA.fullmatch(value['sourceSha']):
        raise PlanningError('Each component requires its own full source SHA')
    if not isinstance(value['configurationDigest'], str) or not DIGEST.fullmatch(value['configurationDigest']):
        raise PlanningError('Each component requires a sha256 configuration digest')
    migration = value['migrationVersion']
    if migration is not None and (not isinstance(migration, str) or not NAME.fullmatch(migration)):
        raise PlanningError('Migration version must be explicit or null')
    artifact = value['artifact']
    if not isinstance(artifact, dict):
        raise PlanningError('Artifact identity must be an object')
    kind = artifact.get('kind')
    if kind == 'registry':
        if (set(artifact) != {'kind', 'ref'} or not isinstance(artifact.get('ref'), str)
                or not registry_reference(artifact['ref'])):
            raise PlanningError('Registry artifacts require a qualified repository pinned by sha256 digest')
    elif kind == 'local-build':
        if (set(artifact) != {'kind', 'imageId', 'buildSourceSha'}
                or not isinstance(artifact.get('imageId'), str) or not DIGEST.fullmatch(artifact['imageId'])
                or artifact.get('buildSourceSha') != value['sourceSha']):
            raise PlanningError('Local builds require imageId and a matching declared build source SHA')
    elif kind == 'bundle':
        if (set(artifact) != {'kind', 'ref', 'sha256'} or not isinstance(artifact.get('ref'), str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,255}', artifact['ref'])
                or '..' in artifact['ref'].split('/')
                or not isinstance(artifact.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', artifact['sha256'])):
            raise PlanningError('Bundle artifacts require a named reference and sha256 checksum')
    else:
        raise PlanningError('Unknown artifact identity kind')
    return value


def manifest(value: dict, kind: str, environment: str, target: str, names: list[str]) -> dict:
    required = {'schemaVersion', 'kind', 'environment', 'target', 'version', 'components'}
    if kind == 'deployment-snapshot':
        required |= {'capturedAt', 'provenance'}
    if (set(value) != required or type(value.get('schemaVersion')) is not int or value['schemaVersion'] != 1
            or value.get('kind') != kind or value.get('environment') != environment or value.get('target') != target):
        raise PlanningError('Deployment manifest identity, environment or target does not match')
    if (not isinstance(value.get('version'), str) or not VERSION_LABEL.fullmatch(value['version'])
            or value['version'].lower() in ('latest', 'head', 'main', 'master', 'unknown')):
        raise PlanningError('An explicit version is required; mutable aliases are not deployment targets')
    if kind == 'deployment-snapshot':
        timestamp(value['capturedAt'])
        if not isinstance(value['provenance'], str) or not value['provenance'].strip() or len(value['provenance']) > 512:
            raise PlanningError('Supplied snapshots require a provenance reference')
    entries = value.get('components')
    if not isinstance(entries, list) or not entries:
        raise PlanningError('Deployment components must be a nonempty array')
    seen = set()
    for entry in entries:
        item = component(entry)
        if item['name'] in seen or item['name'] not in names:
            raise PlanningError('Duplicate or unconfigured environment component')
        seen.add(item['name'])
    return value


def snapshot_fresh(snapshot: dict, maximum: int) -> bool:
    age = (now() - timestamp(snapshot['capturedAt'])).total_seconds()
    return -30 <= age <= maximum


def prepare(root: Path, environment: str, target_manifest: str, current_snapshot: str | None = None,
            conditions_path: str | None = None, max_snapshot_age: int = 3600) -> dict:
    root = root.resolve()
    if type(max_snapshot_age) is not int or not 1 <= max_snapshot_age <= 86400:
        raise PlanningError('Snapshot age must be between 1 and 86400 seconds')
    if Path(git(root, 'rev-parse', '--show-toplevel')).resolve() != root:
        raise PlanningError('Use the exact Git repository root')
    config_names = git(root, 'config', '--null', '--name-only', '--list').lower().split('\0')
    if any(name == 'extensions.partialclone' or (name.startswith('remote.') and name.endswith(('.promisor', '.partialclonefilter'))) for name in config_names):
        raise PlanningError('Partial-clone or promisor repositories are unsupported by the offline planner')
    if pending_upgrades(root):
        raise PlanningError('Recover unfinished workflow upgrades before deployment planning')
    resolved = resolve_configuration(root)
    if resolved['source'] != 'project' or resolved['errors'] or any(item['code'] == 'config.drift' for item in resolved['warnings']):
        raise PlanningError('Deployment planning requires valid adopted and synchronized project configuration')
    config = resolved['config']
    deployment = config.get('extensions', {}).get('deployment')
    if not isinstance(environment, str) or not isinstance(deployment, dict) or environment not in deployment['environments']:
        raise PlanningError('Deployment environment must be explicitly configured')
    env = deployment['environments'][environment]
    if env['capability'] not in resolved['capabilities'] or 'deployment' not in resolved['manifest'].get('installedPacks', []):
        raise PlanningError('Enable the selected capability and install its deployment pack explicitly')
    if offline_worktree_status(root):
        raise PlanningError('Deployment planning requires a clean working tree')
    head = git(root, 'rev-parse', '--verify', 'HEAD^{commit}')
    config_bytes = path_at(root, 'workflow.config.json').read_bytes()
    names, blockers = env['components'], []
    commands = {}
    for phase, reference in env['commands'].items():
        declared = config['commands'][reference]
        cwd = declared.get('cwd', '.')
        directory = path_at(root, cwd, directory=True)
        exists = directory.is_dir()
        commands[phase] = dict(name=reference, command=declared['command'], cwd=cwd, cwdExists=exists)
        if not exists:
            blockers.append('command-cwd-missing:' + phase)
    blockers.extend('command-phase-missing:' + phase for phase in PHASES if phase not in commands)
    target_data, target_input = read_data(root, target_manifest)
    target_data = manifest(target_data, 'deployment-target', environment, env['target'], names)
    current, current_input = None, None
    if current_snapshot is not None:
        current, current_input = read_data(root, current_snapshot)
        current = manifest(current, 'deployment-snapshot', environment, env['target'], names)
        if not snapshot_fresh(current, max_snapshot_age):
            blockers.append('current-snapshot-stale-or-future')
    else:
        blockers.append('current-snapshot-missing')
    previous = {item['name']: item for item in current['components']} if current else {}
    requested = {item['name']: item for item in target_data['components']}
    desired = {**previous, **requested}
    if set(previous) != set(names):
        blockers.append('rollback-state-incomplete')
    if set(desired) != set(names):
        blockers.append('desired-state-incomplete')
    changes = []
    for name in names:
        before, after = previous.get(name), desired.get(name)
        fields = [key for key in FIELDS if before and after and before[key] != after[key]]
        changes.append(dict(component=name, selected=name in requested,
                            action='unknown' if before is None or after is None else 'change' if fields else 'unchanged',
                            changedFields=fields, previous=before, desired=after))
    migration_changed = any(before and desired.get(name) and before['migrationVersion'] != desired[name]['migrationVersion']
                            for name, before in previous.items())
    evidence = []
    conditions, conditions_input = None, None
    if conditions_path is not None:
        conditions, conditions_input = read_data(root, conditions_path)
        if (set(conditions) != {'schemaVersion', 'kind', 'environment', 'target', 'backup', 'migration'}
                or type(conditions.get('schemaVersion')) is not int or conditions['schemaVersion'] != 1
                or conditions.get('kind') != 'deployment-conditions' or conditions.get('environment') != environment
                or conditions.get('target') != env['target']):
            raise PlanningError('Conditions do not match the selected environment and target')
        backup, migration = conditions.get('backup'), conditions.get('migration')
        if (not isinstance(backup, dict) or set(backup) != {'required', 'reference', 'restoreEvidence'}
                or type(backup.get('required')) is not bool or not isinstance(migration, dict)
                or set(migration) != {'mode', 'evidence'} or migration.get('mode') not in ('none', 'reversible', 'irreversible', 'unknown')):
            raise PlanningError('Invalid backup or migration conditions')
        for field, reference in (('backup', backup['reference']), ('restore', backup['restoreEvidence']), ('migration', migration['evidence'])):
            if reference is None:
                continue
            path = path_at(root, reference)
            if path.suffix.lower() not in ('.json', '.md', '.txt') or path.name.startswith('.env'):
                raise PlanningError('Use explicit local evidence metadata, not backup data or credentials')
            if not path.exists():
                evidence.append(dict(role=field, path=reference, sha256=None, verification='missing'))
                blockers.append('evidence-file-missing:' + field)
            else:
                evidence.append(dict(role=field, **read_data(root, reference, json_file=False)))
        available = {item['role'] for item in evidence if item['sha256'] is not None}
        migration_required = migration_changed or migration['mode'] != 'none'
        if backup['required'] or migration_required:
            blockers.extend('backup-evidence-missing:' + field for field in ('backup', 'restore') if field not in available)
            blockers.extend('command-phase-missing:' + phase for phase in ('backup', 'restore') if phase not in commands)
        if migration_required:
            if migration['mode'] != 'reversible':
                blockers.append('migration-not-declared-reversible')
            if 'migration' not in available:
                blockers.append('migration-recovery-evidence-missing')
            if 'migrate' not in commands:
                blockers.append('command-phase-missing:migrate')
        if migration['mode'] in ('irreversible', 'unknown'):
            blockers.append('migration-recovery-unresolved')
    else:
        blockers.append('conditions-missing')
    blockers = sorted(set(blockers))
    return dict(schemaVersion=1, kind='deployment-plan', repository=str(root), headSha=head,
                configurationHash=sha256(config_bytes), environment=environment, target=env['target'],
                production=env['production'], executionAvailable=False, productionReady=False,
                arguments=dict(environment=environment, targetManifest=target_manifest, currentSnapshot=current_snapshot,
                               conditions=conditions_path, maxSnapshotAge=max_snapshot_age),
                inputs=dict(target=target_input, current=current_input, conditions=conditions_input, evidence=evidence),
                version=target_data['version'], requestedComponents=list(requested), changes=changes,
                desired=[desired[name] for name in names if name in desired], commands=commands,
                conditions=conditions, result='blocked' if blockers else 'prepared', blockers=blockers,
                rollback=dict(status='blocked' if blockers else 'planned_from_unverified_snapshot',
                              version=current['version'] if current else None,
                              components=[previous[name] for name in names if name in previous]),
                verification=dict(currentSnapshot='supplied_unverified' if current else 'missing',
                                  deployedVersion='unknown', health='unknown', smoke='unknown', backup='unknown', migration='unknown', authorization='unknown'))


def checked(root: Path, saved: dict) -> dict:
    if not isinstance(saved, dict) or saved.get('kind') != 'deployment-plan' or not isinstance(saved.get('arguments'), dict):
        raise PlanningError('Invalid deployment plan')
    arguments = saved['arguments']
    fresh = prepare(root, arguments.get('environment'), arguments.get('targetManifest'), arguments.get('currentSnapshot'),
                    arguments.get('conditions'), arguments.get('maxSnapshotAge'))
    if canonical(saved) != canonical(fresh):
        raise PlanningError('Deployment plan inputs or derived fields changed; prepare and review again')
    return fresh


def compare(root: Path, saved: dict, observed_snapshot: str, direction: str = 'deploy') -> dict:
    plan = checked(root, saved)
    if direction not in ('deploy', 'rollback'):
        raise PlanningError('Comparison direction must be deploy or rollback')
    config = resolve_configuration(root)['config']['extensions']['deployment']['environments'][plan['environment']]
    observed, source = read_data(root, observed_snapshot)
    observed = manifest(observed, 'deployment-snapshot', plan['environment'], plan['target'], config['components'])
    expected = plan['desired'] if direction == 'deploy' else plan['rollback']['components']
    desired = {item['name']: item for item in expected}
    actual = {item['name']: item for item in observed['components']}
    differences = []
    for name in config['components']:
        before, after = desired.get(name), actual.get(name)
        fields = [field for field in FIELDS if before and after and before[field] != after[field]]
        if before is None or after is None or fields:
            differences.append(dict(component=name, changedFields=fields,
                                    missingExpected=before is None, missingObserved=after is None))
    expected_version = plan['version'] if direction == 'deploy' else plan['rollback']['version']
    version_matches = observed['version'] == expected_version
    if not version_matches:
        differences.append(dict(component=None, changedFields=['version'], missingExpected=expected_version is None, missingObserved=False))
    fresh = snapshot_fresh(observed, plan['arguments']['maxSnapshotAge'])
    return dict(schemaVersion=1, kind='deployment-snapshot-comparison', environment=plan['environment'],
                target=plan['target'], direction=direction, identitiesMatch=not differences, snapshotFresh=fresh,
                expectedVersion=expected_version, observedVersion=observed['version'], versionMatches=version_matches,
                result='stale-supplied-snapshot' if not fresh else 'mismatches-supplied-snapshot' if differences else 'matches-supplied-snapshot',
                observation=source, differences=differences, executionAvailable=False, productionReady=False,
                verification=dict(runtime='unknown', health='unknown', smoke='unknown', backup='unknown', provenance='supplied_unverified'))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'plan', 'check-plan', 'compare'))
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--environment')
    parser.add_argument('--target-manifest', type=Path)
    parser.add_argument('--current-snapshot', type=Path)
    parser.add_argument('--conditions', type=Path)
    parser.add_argument('--max-snapshot-age', type=int, default=3600)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--observed-snapshot', type=Path)
    parser.add_argument('--direction', choices=('deploy', 'rollback'), default='deploy')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        root = args.repo.resolve()
        if args.action == 'status':
            result = dict(executionAvailable=False, productionReady=False, mode='offline-planning', runtimeVerification='unknown')
        elif args.action == 'plan':
            if not args.environment or args.target_manifest is None:
                raise PlanningError('plan requires --environment and --target-manifest')
            names = [relative_input(root, path) if path is not None else None
                     for path in (args.target_manifest, args.current_snapshot, args.conditions)]
            result = prepare(root, args.environment, *names, args.max_snapshot_age)
            if args.output is not None:
                output = relative_input(root, args.output)
                if not output.startswith(RECORDS):
                    raise PlanningError('Store local deployment plans inside ' + RECORDS)
                with LifecycleLock(root, 'deployment-plan'):
                    checked(root, result)
                    if git(root, 'ls-files', '--', ':(top,literal).dev-workflow'):
                        raise PlanningError('Local deployment metadata must not be tracked by Git')
                    git(root, 'check-ignore', '--no-index', '--', output)
                    destination = path_at(root, output)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open('x', encoding='utf-8', newline='\n') as stream:
                        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        else:
            if args.plan is None:
                raise PlanningError('This action requires --plan')
            saved, _ = read_data(root, relative_input(root, args.plan))
            if args.action == 'check-plan':
                plan = checked(root, saved)
                result = dict(valid=True, result=plan['result'], executionAvailable=False, productionReady=False,
                              verification='local-input-consistency-only')
            else:
                if args.observed_snapshot is None:
                    raise PlanningError('compare requires --observed-snapshot')
                result = compare(root, saved, relative_input(root, args.observed_snapshot), args.direction)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return int(args.action == 'compare' and result['result'] != 'matches-supplied-snapshot')
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps(dict(error=str(error)), ensure_ascii=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
