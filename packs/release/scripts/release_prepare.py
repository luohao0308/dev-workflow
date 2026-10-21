#!/usr/bin/env python3
"""Prepare release plans without creating tags, publishing, or deploying."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
# Both installed scripts/ and distribution packs/release/scripts/ layouts.
SCRIPT = Path(__file__).resolve()
sys.path.insert(0, str(SCRIPT.parent))
if len(SCRIPT.parents) > 3:
    sys.path.append(str(SCRIPT.parents[3] / 'core' / 'scripts'))
from workflow_config import resolve_configuration

SEMVER = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$')


class PreparationError(ValueError):
    pass


def git_result(root: Path, *args: str, input_text: str | None = None):
    try:
        result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', str(root), *args],
                              capture_output=True, timeout=30,
                              input=input_text.encode('utf-8') if input_text is not None else None,
                              env={**os.environ, 'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0'})
        result.stdout = result.stdout.decode('utf-8', errors='strict')
        return result
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        raise PreparationError('Local Git state could not be inspected') from error


def git(root: Path, *args: str, input_text: str | None = None) -> str:
    result = git_result(root, *args, input_text=input_text)
    if result.returncode:
        raise PreparationError('Local Git state could not be inspected')
    return result.stdout.strip()


def offline_repository(root: Path) -> None:
    # Configuration names are checked before any object/index/attribute inspection.
    names = git(root, 'config', '--null', '--name-only', '--list').lower().split('\0')
    if any(name == 'extensions.partialclone' or (name.startswith('remote.') and name.endswith(('.promisor', '.partialclonefilter'))) for name in names):
        raise PreparationError('Partial-clone or promisor repositories are unsupported by release preparation')


def offline_worktree_status(root: Path) -> str:
    # status can invoke content filters or recurse into submodule worktrees.
    paths = []
    for entry in git(root, 'ls-files', '--stage', '-z').split('\0'):
        if not entry:
            continue
        metadata, name = entry.split('\t', 1)
        if metadata.split()[0] == '160000':
            raise PreparationError('Submodule worktree inspection is unsupported by release preparation')
        paths.append(name)
    if paths:
        attributes = git(root, 'check-attr', '-z', '--stdin', 'filter', input_text='\0'.join(paths) + '\0').split('\0')
        for index in range(0, len(attributes) - 2, 3):
            if attributes[index + 2] not in ('unspecified', 'unset'):
                raise PreparationError('External Git content filters are unsupported by release preparation')
    return git(root, 'status', '--porcelain', '--untracked-files=all', '--ignore-submodules=all',
               '--', '.', ':(exclude).dev-workflow/releases')


def commit(root: Path, ref: str) -> str:
    return git(root, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}')


def configuration(root: Path) -> dict:
    resolved = resolve_configuration(root)
    if resolved['errors']:
        raise PreparationError('Invalid workflow configuration: ' + json.dumps(resolved['errors'], ensure_ascii=False))
    if any(item['code'] == 'config.drift' for item in resolved['warnings']):
        raise PreparationError('Project configuration drift requires explicit workflow_config.py sync before release preparation')
    config = resolved.get('config') or {}
    release = config.get('extensions', {}).get('release')
    if not isinstance(release, dict) or 'release' not in resolved.get('capabilities', []):
        raise PreparationError('Release capability must be explicitly configured and enabled')
    if release.get('strategy') not in ('none', 'commit-sha', 'semver-tag'):
        raise PreparationError('Release strategy must be none, commit-sha, or semver-tag')
    components = release.get('components', [])
    if not isinstance(components, list) or any(not isinstance(x, str) or not x for x in components) or len(set(components)) != len(components):
        raise PreparationError('Release components must be unique nonempty strings')
    if not isinstance(release.get('tagPrefix', 'v'), str):
        raise PreparationError('tagPrefix must be a string')
    return release


def fingerprint(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def declarations(values: list[str], names: list[str]) -> dict:
    output = {}
    for value in values:
        name, separator, detail = value.partition('=')
        if not separator or name not in names or not detail or name in output:
            raise PreparationError('Component declarations require unique configured NAME=VALUE entries')
        output[name] = detail
    return output


def prepare(root: Path, sha: str, version: str | None, sources: list[str], builds: list[str]) -> dict:
    offline_repository(root)
    release = configuration(root)
    head = commit(root, 'HEAD')
    target = commit(root, sha)
    if offline_worktree_status(root):
        raise PreparationError('Working tree is dirty; release preparation requires a clean tree')
    tag = None
    tag_status = 'not_requested'
    if release['strategy'] == 'semver-tag':
        normalized = (version or '').removeprefix('v')
        if not SEMVER.fullmatch(normalized):
            raise PreparationError('semver-tag requires a valid SemVer --version (optional v prefix)')
        tag = release.get('tagPrefix', 'v') + normalized
        git(root, 'check-ref-format', 'refs/tags/' + tag)
        found = git_result(root, 'show-ref', '--verify', '--quiet', 'refs/tags/' + tag)
        if found.returncode == 0:
            if commit(root, 'refs/tags/' + tag) != target:
                raise PreparationError('Tag conflict: existing tag points to a different commit')
            tag_status = 'already_exists_same_commit'
        elif found.returncode == 1:
            tag_status = 'available_locally'
        else:
            raise PreparationError('Cannot inspect existing tag')
        version = normalized
    names = release.get('components', [])
    source_map = declarations(sources, names)
    build_map = declarations(builds, names)
    components = []
    for name in names:
        source = commit(root, source_map[name]) if name in source_map else None
        components.append({'name': name, 'sourceSha': source, 'buildSource': build_map.get(name),
                           'artifactDigest': None, 'imageId': None, 'verification': 'unknown'})
    return {'schemaVersion': 1, 'kind': 'release-preparation', 'preparedAt': datetime.now(timezone.utc).isoformat(),
            'strategy': release['strategy'], 'version': version, 'headSha': head, 'targetRef': sha, 'targetSha': target,
            'configurationHash': fingerprint(release), 'tag': tag, 'tagStatus': tag_status,
            'components': components, 'states': {key: 'unknown' for key in ('ci', 'image', 'deployment', 'live')},
            'environment': None, 'configurationVersion': None, 'migrationVersion': None, 'previousDeployment': None,
            'scope': 'Preparation only; local tag inspection does not verify remote availability or grant execution authority.'}


def check_plan(root: Path, path: Path, sha: str) -> dict:
    offline_repository(root)
    plan = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(plan, dict) or plan.get('schemaVersion') != 1 or plan.get('kind') != 'release-preparation':
        raise PreparationError('Unsupported release plan')
    if plan.get('headSha') != commit(root, 'HEAD') or plan.get('targetSha') != commit(root, sha):
        raise PreparationError('Stale release plan: HEAD or target changed')
    if plan.get('configurationHash') != fingerprint(configuration(root)):
        raise PreparationError('Stale release plan: release configuration changed')
    if not isinstance(plan.get('version'), (str, type(None))):
        raise PreparationError('Invalid release plan version')
    components = plan.get('components')
    if not isinstance(components, list) or any(not isinstance(item, dict) for item in components):
        raise PreparationError('Invalid release plan components')
    sources, builds = [], []
    for item in components:
        if not isinstance(item.get('name'), str) or item.get('verification') != 'unknown':
            raise PreparationError('Invalid release plan component identity or verification')
        for key, destination in (('sourceSha', sources), ('buildSource', builds)):
            value = item.get(key)
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise PreparationError('Invalid release plan component declaration')
                destination.append(item['name'] + '=' + value)
    # Re-run preflight and compare the saved decision, not just the commit IDs.
    current = prepare(root, sha, plan.get('version'), sources, builds)
    for field in ('strategy', 'version', 'tag', 'tagStatus', 'components', 'states',
                  'environment', 'configurationVersion', 'migrationVersion', 'previousDeployment', 'scope'):
        if plan.get(field) != current[field]:
            raise PreparationError('Release plan contents differ from current preparation: ' + field)
    return {'valid': True, 'targetSha': plan['targetSha'], 'scope': 'Local preparation checks only'}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--sha', default=None, help='Exact commit or commit reference; default HEAD')
    parser.add_argument('--version')
    parser.add_argument('--component-source', action='append', default=[], metavar='NAME=SHA')
    parser.add_argument('--component-build', action='append', default=[], metavar='NAME=DESCRIPTION')
    parser.add_argument('--check-plan', type=Path)
    parser.add_argument('--output', type=Path, help='Explicit new JSON file inside .dev-workflow/releases/')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        root = args.repo.resolve()
        if args.check_plan:
            if args.output:
                raise PreparationError('--check-plan cannot write --output')
            plan_path = args.check_plan if args.check_plan.is_absolute() else root / args.check_plan
            existing = json.loads(plan_path.read_text(encoding='utf-8'))
            if not isinstance(existing, dict) or not isinstance(existing.get('targetRef'), str):
                raise PreparationError('Invalid release plan targetRef')
            result = check_plan(root, plan_path, args.sha or existing['targetRef'])
        else:
            result = prepare(root, args.sha or 'HEAD', args.version, args.component_source, args.component_build)
        if args.output:
            output = (root / args.output).resolve()
            boundary = (root / '.dev-workflow' / 'releases').resolve()
            if root not in boundary.parents or boundary not in output.parents:
                raise PreparationError('--output must be inside repository .dev-workflow/releases/')
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('x', encoding='utf-8') as handle:
                handle.write(json.dumps(result, indent=2, ensure_ascii=False) + '\n')
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=True))
        elif args.check_plan:
            print('Release preparation remains valid locally: ' + result['targetSha'])
        else:
            print('Release preparation: ' + result['strategy'] + '\nTarget: ' + result['targetSha'])
            print('Tag: ' + str(result['tag']) + ' (' + result['tagStatus'] + ')')
            print('CI / image / deployment / live: unknown\n' + result['scope'])
        return 0
    except (PreparationError, OSError, ValueError) as exc:
        print('Release preparation failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
