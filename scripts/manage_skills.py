#!/usr/bin/env python3
"""Explicit, independent lifecycle for dev-workflow's optional Skills."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

SOURCE = Path(__file__).resolve().parents[1] / 'extensions' / 'skills'
NAMES = ('workflow-doctor', 'workflow-closeout', 'workflow-release', 'workflow-upgrade', 'workflow-deploy')
MARKER = '.dev-workflow-skill.json'
OWNER = 'dev-workflow/optional-skills/v1'


def safe_path(path):
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError(f'symlink path refused: {item}')
    return path


def inventory(directory):
    result = {}
    for item in sorted(directory.rglob('*')):
        if item.is_symlink():
            raise ValueError(f'symlink content refused: {item}')
        if item.is_file() and item.relative_to(directory).as_posix() != MARKER:
            result[item.relative_to(directory).as_posix()] = hashlib.sha256(item.read_bytes()).hexdigest()
        elif item.is_dir():
            result[item.relative_to(directory).as_posix() + '/'] = 'directory'
        elif not item.is_file():
            raise ValueError(f'unsupported content: {item}')
    return result


def owned(directory, name):
    marker = directory / MARKER
    if marker.is_symlink() or not marker.is_file():
        return False
    record = json.loads(marker.read_text(encoding='utf-8'))
    return (record.get('owner') == OWNER and record.get('skill') == name
            and bool(record.get('files')) and record['files'] == inventory(directory)
            and record['files'] == inventory(safe_path(SOURCE / name)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'uninstall'))
    parser.add_argument('--skills', nargs='+', required=True, help='Explicit skill names (space or comma separated)')
    parser.add_argument('--scope', choices=('project', 'user'), default='project')
    parser.add_argument('--target', type=Path, help='Project root; defaults to current directory')
    parser.add_argument('--skills-dir', type=Path, help='Explicit destination, useful for isolated user-scope installs')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        names = list(dict.fromkeys(name for value in args.skills for name in value.split(',')))
        if not names or any(name not in NAMES for name in names):
            raise ValueError('unknown skill name; choose ' + ', '.join(NAMES))
        if args.scope == 'user' and args.target:
            raise ValueError('--target applies only to project scope')
        destination = safe_path(args.skills_dir or (
            Path.home() / '.agents' / 'skills' if args.scope == 'user'
            else (args.target or Path.cwd()) / '.agents' / 'skills'))
        plans = []
        # Validate the entire request before performing any mutation.
        for name in names:
            target = safe_path(destination / name)
            if args.action == 'install':
                if target.exists():
                    raise ValueError(f'conflict: refusing to overwrite {target}')
                source = safe_path(SOURCE / name)
                files = inventory(source)
                if not (source / 'SKILL.md').is_file():
                    raise ValueError(f'missing Skill source: {name}')
                plans.append((name, target, files))
            else:
                if not target.exists():
                    continue
                if not target.is_dir() or not owned(target, name):
                    raise ValueError(f'preserved: ownership unknown or content modified: {target}')
                plans.append((name, target, None))
        for name, target, files in plans:
            if not args.dry_run:
                if args.action == 'install':
                    target.parent.mkdir(parents=True, exist_ok=True)
                    # copytree refuses a destination created after the preflight.
                    shutil.copytree(SOURCE / name, target)
                    (target / MARKER).write_text(json.dumps({
                        'owner': OWNER, 'skill': name, 'files': files,
                    }, indent=2) + '\n', encoding='utf-8')
                else:
                    shutil.rmtree(target)
            print(f'{"would " if args.dry_run else ""}{args.action}: {target}')
        return 0
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
