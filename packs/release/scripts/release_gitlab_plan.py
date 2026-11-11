#!/usr/bin/env python3
"""Create a read-only GitLab.com release intent from a fresh local preparation."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_contract_v2 import ProviderIdentity, valid_tag
from release_execute import ExecutionError, canonical, run_git, validate_preparation
from workflow_lock import linked

REMOTE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\Z')
PROJECT = re.compile(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\Z')


def remote_identity(root: Path, name: str) -> dict:
    if not isinstance(name, str) or not REMOTE_NAME.fullmatch(name):
        raise ExecutionError('Invalid GitLab remote name')
    fetch = run_git(root, 'remote', 'get-url', '--all', name).splitlines()
    push = run_git(root, 'remote', 'get-url', '--push', '--all', name).splitlines()
    if len(fetch) != 1 or fetch != push:
        raise ExecutionError('GitLab remote requires one identical fetch and push URL')
    url = fetch[0]
    if any(ord(char) < 33 or ord(char) == 127 for char in url):
        raise ExecutionError('Invalid GitLab remote URL')
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'gitlab.com'
            or parsed.query or parsed.fragment):
        raise ExecutionError('GitLab remote must use canonical GitLab.com HTTPS')
    path = parsed.path.removeprefix('/')
    if not path.endswith('.git'):
        raise ExecutionError('GitLab remote must end in .git')
    project = path[:-4]
    if not PROJECT.fullmatch(project):
        raise ExecutionError('Invalid GitLab project path')
    return {'name': name, 'url': url, 'project': project}


def build_intent(root: Path, saved: dict, *, remote: str, project_id: int) -> dict:
    root = root.resolve()
    if type(project_id) is not int or project_id <= 0:
        raise ExecutionError('A positive GitLab project ID declaration is required')
    saved = json.loads(canonical(saved))
    validate_preparation(root, saved)
    if saved['strategy'] != 'semver-tag' or not saved['tag']:
        raise ExecutionError('GitLab tag intent requires the semver-tag strategy')
    if not valid_tag(saved['tag']):
        raise ExecutionError('GitLab tag is incompatible with the v2 contract')
    destination = remote_identity(root, remote)
    try:
        ProviderIdentity('gitlab.com', destination['url'], project_id, destination['project'], saved['targetSha'])
    except ValueError as error:
        raise ExecutionError('GitLab project identity is incompatible with the v2 contract') from error
    return {'schemaVersion': 2, 'kind': 'release-platform-intent', 'platform': 'gitlab.com',
            'repository': str(root), 'preparation': saved, 'remote': destination,
            'projectIdDeclaration': project_id,
            'tag': {'name': saved['tag'], 'targetSha': saved['targetSha'], 'remoteStatus': 'unknown'},
            'authorityGranted': False, 'executionAvailable': False,
            'scope': 'Read-only local intent; project ID and remote state are unverified. No execution authority.'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExecutionError('Duplicate preparation JSON key')
        result[key] = value
    return result


def read_preparation(root: Path, path: Path) -> dict:
    # Restrict reads to a regular, non-linked file in the repository's release records.
    # This is a local preflight, not an atomic defense against a concurrent writer
    # with permission to replace ancestor directories during inspection.
    records = root / '.dev-workflow' / 'releases'
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(records)
    except ValueError as error:
        raise ExecutionError('Preparation must be inside .dev-workflow/releases/') from error
    if not relative.parts or any(part in ('.', '..') for part in relative.parts):
        raise ExecutionError('Invalid preparation path')
    current = root
    for part in ('.dev-workflow', 'releases', *relative.parts):
        current = current / part
        if linked(current):
            raise ExecutionError('Linked preparation path is unsupported')
    info = current.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ExecutionError('Preparation must be a regular JSON file of at most 1 MiB')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(current, flags)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise ExecutionError('Preparation file changed or exceeds 1 MiB')
        if linked(current) or (info.st_dev, info.st_ino) != (current.stat().st_dev, current.stat().st_ino):
            raise ExecutionError('Preparation path changed during inspection')
        raw = handle.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ExecutionError('Preparation exceeds 1 MiB')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--preparation', type=Path, required=True)
    parser.add_argument('--remote', required=True)
    parser.add_argument('--project-id', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        root = args.repo.resolve()
        saved = read_preparation(root, args.preparation)
        print(json.dumps(build_intent(root, saved, remote=args.remote, project_id=args.project_id),
                         indent=2, ensure_ascii=True))
        return 0
    except (ExecutionError, OSError, ValueError, TypeError, UnicodeError) as error:
        print('GitLab release intent failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
