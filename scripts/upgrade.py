#!/usr/bin/env python3
"""Offline, planned upgrades with proven baselines and reversible local journals."""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE / 'core/scripts'))
from workflow_lock import LifecycleLock, linked, process_alive, pending_upgrades as pending

MANIFEST = '.dev-workflow/manifest.json'
START = b'<!-- AI-WORKFLOW:CORE:START -->'
END = b'<!-- AI-WORKFLOW:CORE:END -->'
EXCLUDE_START = b'# BEGIN dev-workflow managed excludes'
EXCLUDE_END = b'# END dev-workflow managed excludes'
VERSION = re.compile(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\Z')
TRANSACTION = re.compile(r'[0-9a-f]{32}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
ACTIONS = {'created', 'preserved', 'legacy', 'appended', 'managed-block'}
LOCAL = ('docs/project-memory/', 'docs/working-context/', 'docs/工作日志/', 'docs/development/ai/')
DOCUMENTS = ('docs/architecture/', 'docs/design/', 'docs/contracts/', 'docs/development/', 'docs/operations/')


def digest(data: bytes | None) -> str | None:
    return hashlib.sha256(data).hexdigest() if data is not None else None


def encoded(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def same_mode(actual: int, expected: int) -> bool:
    # Windows chmod/stat expose the read-only bit, not POSIX execute/ACL modes.
    return bool(actual & stat.S_IWRITE) == bool(expected & stat.S_IWRITE) if os.name == 'nt' else actual == expected


def relative(value: str) -> str:
    if not isinstance(value, str) or not value or '\\' in value or ':' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid relative workflow path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ('', '.', '..') for part in value.split('/')) or path.as_posix() != value:
        raise ValueError('Workflow path must be normalized and project-relative')
    return value


def path_at(root: Path, value: str) -> Path:
    value = relative(value)
    result = root
    for part in PurePosixPath(value).parts:
        result = result / part
        if linked(result):
            raise ValueError('Workflow path contains a symbolic link or reparse point: ' + value)
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError('Workflow path escapes its root')
    return result


def contents(path: Path) -> bytes | None:
    if not path.exists():
        return None
    if not path.is_file() or linked(path):
        raise ValueError('Expected a regular workflow file')
    return path.read_bytes()


def object_at(path: Path) -> dict:
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ValueError('Expected a JSON object')
    return value


def version(root: Path) -> str:
    value = path_at(root, 'VERSION').read_text(encoding='utf-8').strip()
    if not VERSION.fullmatch(value):
        raise ValueError('Invalid distribution VERSION')
    return value


def inventory(root: Path, packs: list[str]) -> dict[str, tuple[str, bytes]]:
    output = {}
    for owner in ['core', *packs]:
        directory = path_at(root, 'core' if owner == 'core' else 'packs/' + relative(owner))
        if not directory.is_dir():
            raise ValueError('Distribution pack is unavailable: ' + owner)
        for item in sorted(directory.rglob('*')):
            if linked(item):
                raise ValueError('Distribution contains a linked path')
            if '__pycache__' in item.parts or item.suffix == '.pyc' or item.is_dir():
                continue
            name = relative(item.relative_to(directory).as_posix())
            if name in output:
                raise ValueError('Distribution overlays overlap: ' + name)
            output[name] = (owner, item.read_bytes())
    return output


def document(name: str) -> bool:
    return (name in ('DESIGN.md', 'docs/PROJECT-SUMMARY.md') or name.startswith(DOCUMENTS)) and not name.startswith(LOCAL) and name.endswith('.md')


def block(data: bytes) -> tuple[bytes, int, int]:
    if data.count(START) != 1 or data.count(END) != 1:
        raise ValueError('Core block requires unique complete markers')
    first, last = data.index(START), data.index(END)
    if first >= last:
        raise ValueError('Core block markers are reversed')
    # Markers must occupy their own lines; never select an arbitrary inline span.
    if (first and data[first - 1:first] != b'\n') or (last and data[last - 1:last] != b'\n'):
        raise ValueError('Core markers must start on separate lines')
    finish = last + len(END)
    if data[finish:finish + 2] == b'\r\n':
        finish += 2
    elif data[finish:finish + 1] == b'\n':
        finish += 1
    elif finish != len(data):
        raise ValueError('Core end marker has trailing inline content')
    if data[first + len(START):first + len(START) + 1] not in (b'\r', b'\n'):
        raise ValueError('Core start marker has trailing inline content')
    return data[first:finish], first, finish


def load(root: Path) -> dict:
    manifest = object_at(path_at(root, MANIFEST))
    if manifest.get('managedBy') != 'dev-workflow' or type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 5:
        raise ValueError('Upgrade requires a schema 5 installation; migrate older metadata with its compatible installer first')
    if not isinstance(manifest.get('workflowVersion'), str) or not VERSION.fullmatch(manifest['workflowVersion']):
        raise ValueError('Invalid installed workflow version')
    packs = manifest.get('installedPacks')
    if not isinstance(packs, list) or any(not isinstance(p, str) or not re.fullmatch(r'[a-z0-9-]+', p) for p in packs) or len(packs) != len(set(packs)):
        raise ValueError('Invalid installed pack list')
    files = manifest.get('files')
    if not isinstance(files, list) or not files or not isinstance(manifest.get('gitPolicy'), dict):
        raise ValueError('Invalid installation inventory or permissions')
    seen = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError('Invalid file entry')
        name = relative(entry.get('path'))
        if name.casefold() in seen or entry.get('source') not in ['core', *packs] or entry.get('action') not in ACTIONS:
            raise ValueError('Invalid or duplicate installation ownership')
        seen.add(name.casefold())
        expected = entry.get('installedSha256')
        if entry['action'] == 'created':
            if not isinstance(expected, str) or not HASH.fullmatch(expected):
                raise ValueError('Created ownership requires a SHA-256 baseline')
        elif expected is not None:
            raise ValueError('Non-created ownership must not claim a file baseline')
    return manifest


def state_check(manifest: dict) -> None:
    state = manifest.get('upgradeState')
    if state is None:
        return
    if not isinstance(state, dict) or type(state.get('schemaVersion')) is not int or state['schemaVersion'] != 1:
        raise ValueError('Unsupported upgradeState')
    names = state.get('projectOwned')
    if not isinstance(names, list) or any(not isinstance(p, str) or not document(relative(p)) for p in names) or len(names) != len(set(names)):
        raise ValueError('Invalid project-owned document declaration')
    by_path = {e['path']: e for e in manifest['files']}
    if any(p in by_path and by_path[p]['action'] != 'preserved' for p in names):
        raise ValueError('Transferred documents must have preserved ownership')
    core = state.get('coreBlock')
    if core is not None:
        if not isinstance(core, dict) or not isinstance(core.get('version'), str) or not VERSION.fullmatch(core['version']):
            raise ValueError('Invalid independent core version')
        for key in ('baselineSha256', 'installedSha256'):
            if not isinstance(core.get(key), str) or not HASH.fullmatch(core[key]):
                raise ValueError('Invalid core block fingerprint')
    transaction = state.get('lastTransaction')
    if transaction is not None and (not isinstance(transaction, str) or not TRANSACTION.fullmatch(transaction)):
        raise ValueError('Invalid last upgrade transaction')
    snapshot = state.get('baselineSnapshot')
    if snapshot is not None and (not isinstance(snapshot, str) or not TRANSACTION.fullmatch(snapshot)):
        raise ValueError('Invalid baseline snapshot identity')


def git(root: Path, *arguments: str) -> str | None:
    discovery = arguments == ('rev-parse', '--show-toplevel')
    has_git_marker = any((parent / '.git').exists() or (parent / '.git').is_symlink()
                         for parent in (root, *root.parents))
    try:
        result = subprocess.run(['git', '--no-optional-locks', '-C', str(root), *arguments],
                                capture_output=True, encoding='utf-8', errors='strict', timeout=20,
                                env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
    except FileNotFoundError:
        if discovery and not has_git_marker:
            return None
        raise ValueError('Git is required to inspect this repository safely')
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise ValueError('Git repository inspection failed; no upgrade writes are allowed')
    if result.returncode == 0:
        return result.stdout.strip()
    if discovery and not has_git_marker and result.stderr.startswith('fatal: not a git repository'):
        return None
    raise ValueError('Git repository inspection failed; no upgrade writes are allowed')


def exclude_info(root: Path, manifest: dict) -> tuple[Path, bytes, bytes] | None:
    top = git(root, 'rev-parse', '--show-toplevel')
    if top is None:
        return None
    repository = Path(top).resolve()
    metadata_prefix = (root.relative_to(repository) / '.dev-workflow').as_posix()
    if git(root, 'ls-files', '--', ':(top,literal)' + metadata_prefix):
        raise ValueError('Git tracks local workflow metadata; upgrade will not create private backups there')
    location = git(root, 'rev-parse', '--git-path', 'info/exclude')
    if location is None:
        raise ValueError('Cannot locate Git info/exclude')
    path = Path(location)
    if not path.is_absolute():
        path = root / path
    for item in [path, *path.parents]:
        if linked(item):
            raise ValueError('Git exclude path is linked or reparsed')
    path = path.resolve()
    before = contents(path) or b''
    if before.count(EXCLUDE_START) != before.count(EXCLUDE_END) or before.count(EXCLUDE_START) > 1:
        raise ValueError('Invalid managed Git exclude block')
    if EXCLUDE_START in before and before.index(EXCLUDE_START) >= before.index(EXCLUDE_END):
        raise ValueError('Reversed managed Git exclude markers')
    prefix = root.relative_to(repository).as_posix()
    prefix = '' if prefix == '.' else prefix + '/'

    def escape(value):
        return ''.join('\\' + ch if ch in '\\ #![]*?' else ch for ch in value)

    paths = ['.dev-workflow/', 'docs/project-memory/']
    if 'delivery' in manifest['installedPacks']:
        paths += ['docs/working-context/', 'docs/工作日志/']
    paths += [e['path'] for e in manifest['files'] if e['action'] == 'created' and not e['path'].startswith('docs/operations/runbooks/')]
    newline = b'\r\n' if b'\r\n' in before else b'\n'
    managed = newline.join([EXCLUDE_START, *[('/' + escape(prefix + p)).encode('utf-8') for p in dict.fromkeys(paths)], EXCLUDE_END]) + newline
    if EXCLUDE_START in before:
        start = before.index(EXCLUDE_START)
        end = before.index(EXCLUDE_END) + len(EXCLUDE_END)
        if start and before[start - 1:start] != b'\n':
            raise ValueError('Inline Git exclude marker is invalid')
        if before[end:end + 2] == b'\r\n':
            end += 2
        elif before[end:end + 1] == b'\n':
            end += 1
        elif end != len(before):
            raise ValueError('Inline Git exclude marker is invalid')
        after = before[:start] + managed + before[end:]
    else:
        after = before + (newline if before and not before.endswith(b'\n') else b'') + managed
    return path, before, after


def check(root: Path, operation: str | None = None) -> dict:
    if not path_at(root, MANIFEST).exists():
        if pending(root):
            raise ValueError('Incomplete transaction remains without an installation manifest')
        return dict(status='uninstalled', projectOwned=[], coreBlock=None)
    manifest = load(root)
    state_check(manifest)
    unfinished = pending(root)
    if unfinished:
        raise ValueError('Incomplete transaction requires rollback: ' + ', '.join(unfinished))
    state = manifest.get('upgradeState') or {}
    if operation in ('install', 'uninstall'):
        if path_at(root, '.dev-workflow/configuration.lock').exists():
            raise ValueError('Configuration is locked; resolve it before changing lifecycle state')
        if state and manifest['workflowVersion'] != version(SOURCE):
            raise ValueError('Use upgrade.py plan/apply before changing an upgrade-managed installation version')
    core = state.get('coreBlock')
    warnings = []
    core_report = core
    if core:
        current = contents(path_at(root, 'AGENTS.md'))
        if current is None:
            raise ValueError('Recorded core block is missing')
        current_block = block(current)[0]
        core_report = dict(core, currentSha256=digest(current_block),
                           status='clean' if digest(current_block) == core['baselineSha256'] else 'customized')
        if digest(current_block) != core['installedSha256']:
            warnings.append('core-customized-since-upgrade')
    return dict(status='warning' if warnings else 'ready', projectOwned=state.get('projectOwned', []), coreBlock=core_report, warnings=warnings)


def merge(base: bytes, current: bytes, incoming: bytes) -> bytes:
    if current == base:
        return incoming
    if incoming == base or current == incoming:
        return current
    try:
        values = [x.decode('utf-8').replace('\r\n', '\n') for x in (current, base, incoming)]
    except UnicodeError:
        raise ValueError('Binary or non-UTF-8 customization requires manual review')
    if any('\x00' in x for x in values):
        raise ValueError('Binary customization requires manual review')
    with tempfile.TemporaryDirectory(prefix='workflow-merge-') as temporary:
        paths = []
        for index, value in enumerate(values):
            path = Path(temporary) / str(index)
            path.write_bytes(value.encode('utf-8'))
            paths.append(str(path))
        try:
            process = subprocess.run(['git', '--no-optional-locks', 'merge-file', '--stdout', *paths], capture_output=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError('Three-way text merge requires available Git; file was preserved')
    if process.returncode != 0:
        raise ValueError('Overlapping three-way changes require manual review; no conflict markers were written')
    result = process.stdout
    if b'\r\n' in current and b'\n' not in current.replace(b'\r\n', b''):
        result = result.replace(b'\n', b'\r\n')
    return result


def build_plan(root: Path, baseline: Path | None) -> tuple[dict, dict[str, bytes]]:
    check(root)
    manifest = load(root)
    state = manifest.get('upgradeState') or {}
    cached = path_at(root, '.dev-workflow/upgrades/' + state['baselineSnapshot'] + '/baseline') if state.get('baselineSnapshot') else None
    if baseline is None:
        if cached is None:
            raise ValueError('An explicit old distribution --baseline is required until a verified snapshot exists')
        baseline = cached
    if ((baseline.is_relative_to(root) and baseline != cached) or SOURCE.is_relative_to(root)
            or root.is_relative_to(SOURCE) or root.is_relative_to(baseline)):
        raise ValueError('Baseline, distribution and target must be separate directories')
    if version(baseline) != manifest['workflowVersion']:
        raise ValueError('Baseline VERSION does not match the installed version')
    old = inventory(baseline, manifest['installedPacks'])
    new = inventory(SOURCE, manifest['installedPacks'])
    existing = {e['path']: e for e in manifest['files']}
    project_owned = state.get('projectOwned', [])
    entries, output = [], {}
    for name in sorted(set(existing) | set(new)):
        local = contents(path_at(root, name))
        entry = existing.get(name)
        previous = old.get(name)
        incoming = new.get(name)
        row = dict(path=name, source=incoming[0] if incoming else entry['source'], beforeSha256=digest(local),
                   baselineSha256=digest(previous[1]) if previous else None,
                   nextBaselineSha256=digest(incoming[1]) if incoming else None)
        try:
            if entry and (previous is None or previous[0] != entry['source']):
                raise ValueError('Inventory ownership is not present in the old distribution')
            if entry and incoming and entry['source'] != incoming[0]:
                raise ValueError('Overlay ownership changed; manual migration required')
            if incoming is None:
                raise ValueError('Source removed this file; deletion is never automatic')
            if (name == 'scripts/workflow_lock.py' and local is not None and local != incoming[1]
                    and (entry is None or entry['action'] != 'created')):
                raise ValueError('Required workflow runtime helper collides with a project-owned file')
            if name in project_owned or (name != 'AGENTS.md' and entry and entry['action'] in ('preserved', 'legacy')):
                row.update(action='keep', reason='Project-owned or unproven historical file is preserved', afterSha256=digest(local))
            elif entry is None:
                if local is None:
                    row.update(action='create', reason='New distribution file', afterSha256=digest(incoming[1]))
                    output[name] = incoming[1]
                else:
                    row.update(action='keep', reason='Pre-existing project file', afterSha256=digest(local))
            else:
                if local is None:
                    raise ValueError('Managed file was deleted locally; preserve deletion until reviewed')
                proven = entry['action'] == 'created' and entry['installedSha256'] == digest(previous[1])
                if name == 'AGENTS.md':
                    old_block = block(previous[1])[0]
                    new_block = block(incoming[1])[0]
                    local_block, start, finish = block(local)
                    core_state = state.get('coreBlock')
                    if not proven and not (core_state and core_state['version'] == manifest['workflowVersion'] and core_state['baselineSha256'] == digest(old_block)):
                        raise ValueError('Core baseline is missing or unproven; version text alone is insufficient')
                    combined = merge(old_block, local_block, new_block)
                    merged = local[:start] + combined + local[finish:]
                    row['coreBlock'] = dict(version=version(SOURCE), baselineSha256=digest(new_block), installedSha256=digest(combined))
                else:
                    if not proven:
                        raise ValueError('Old baseline hash is missing or does not match the installation')
                    if name == 'scripts/delivery_guard.py' and local != previous[1]:
                        raise ValueError('Customized delivery guard cannot be automatically merged')
                    merged = merge(previous[1], local, incoming[1])
                if name.endswith('.json'):
                    json.loads(merged.decode('utf-8'))
                if name.endswith('.py'):
                    compile(merged, name, 'exec')
                row.update(action='keep' if merged == local else 'update' if local == previous[1] else 'merge',
                           reason='Verified three-way baseline', afterSha256=digest(merged))
                if merged != local:
                    output[name] = merged
        except (ValueError, SyntaxError, UnicodeError) as exc:
            row.update(action='conflict', reason=str(exc), afterSha256=digest(local))
        entries.append(row)
    conflicts = [e['path'] for e in entries if e['action'] == 'conflict']
    info = exclude_info(root, manifest)
    plan = dict(schemaVersion=1, kind='workflow-upgrade-plan', target=str(root), source=str(SOURCE), baseline=str(baseline),
                fromVersion=manifest['workflowVersion'], toVersion=version(SOURCE), manifestSha256=digest(path_at(root, MANIFEST).read_bytes()),
                configurationSha256=digest(contents(path_at(root, 'workflow.config.json'))),
                gitExclude=dict(path=str(info[0]), sha256=digest(info[1])) if info else None,
                entries=entries, conflicts=conflicts, ready=not conflicts)
    return plan, output


def after_manifest(before: dict, plan: dict) -> dict:
    result = deepcopy(before)
    current = {entry['path']: deepcopy(entry) for entry in before['files']}
    state = deepcopy(before.get('upgradeState') or dict(schemaVersion=1, coreBlock=None, projectOwned=[], lastTransaction=None))
    for row in plan['entries']:
        name = row['path']
        if name not in current:
            current[name] = dict(path=name, source=row['source'], action='created' if row['action'] == 'create' else 'preserved',
                                 installedSha256=row['nextBaselineSha256'] if row['action'] == 'create' else None)
        elif row.get('coreBlock'):
            state['coreBlock'] = row['coreBlock']
            if current[name]['action'] == 'created':
                current[name]['installedSha256'] = row['nextBaselineSha256']
        elif current[name]['action'] == 'created':
            current[name]['installedSha256'] = row['nextBaselineSha256']
    result['files'] = [current[key] for key in sorted(current)]
    result['workflowVersion'] = plan['toVersion']
    result['upgradeState'] = state
    result['updatedAt'] = now()
    return result


def write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    if any(linked(p) for p in (path, *path.parents)):
        raise ValueError('Refusing to replace a linked file')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def configuration_lock(root: Path, transaction: str, recover: bool = False):
    path = path_at(root, '.dev-workflow/configuration.lock')
    if recover and path.exists():
        owner = object_at(path)
        if owner.get('transaction') != transaction or process_alive(owner.get('pid')) is not False:
            raise ValueError('Configuration lock owner cannot be proven inactive for this transaction')
        path.unlink()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(dict(pid=os.getpid(), transaction=transaction), stream)
            stream.flush()
            os.fsync(stream.fileno())
        yield
    finally:
        path.unlink()


def destination(root: Path, key: str, exclude: str | None) -> Path:
    if key == '@git-exclude':
        current = exclude_info(root, load(root))
        if not current or str(current[0]) != exclude:
            raise ValueError('Git exclude destination changed')
        return current[0]
    if key != MANIFEST:
        name = relative(key)
        if name.startswith('.') or name == 'workflow.config.json':
            raise ValueError('Invalid transaction payload path')
    return path_at(root, key)


def transact(root: Path, manifest: dict, payloads: dict[str, bytes], operation: str, transaction: str,
             snapshot: dict[str, tuple[str, bytes]] | None = None,
             expected: dict[str, str | None] | None = None) -> dict:
    manifest = deepcopy(manifest)
    manifest['upgradeState']['lastTransaction'] = transaction
    if snapshot is not None:
        manifest['upgradeState']['baselineSnapshot'] = transaction
    payloads = dict(payloads)
    info = exclude_info(root, manifest)
    if info and info[1] != info[2]:
        payloads['@git-exclude'] = info[2]
    payloads[MANIFEST] = encoded(manifest)
    directory = path_at(root, '.dev-workflow/upgrades/' + transaction)
    items = []
    for key, after in payloads.items():
        path = info[0] if key == '@git-exclude' else path_at(root, key)
        before = contents(path)
        if expected is not None and key in expected and digest(before) != expected[key]:
            raise ValueError('Transaction input changed before backup; regenerate the plan: ' + key)
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
        if mode & ~0o777:
            raise ValueError('Special file mode requires manual migration')
        items.append(dict(path=key, before=base64.b64encode(before).decode('ascii') if before is not None else None,
                          after=base64.b64encode(after).decode('ascii'), beforeSha256=digest(before), afterSha256=digest(after), mode=mode))
    journal = dict(schemaVersion=1, target=str(root), transaction=transaction, operation=operation, createdAt=now(),
                   excludePath=str(info[0]) if info else None, status='prepared', items=items)
    journal_path = directory / 'journal.json'
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_bytes(journal_path, encoded(journal))
    try:
        if snapshot is not None:
            write_bytes(directory / 'baseline/VERSION', (manifest['workflowVersion'] + '\n').encode('utf-8'))
            for name, (owner, data) in snapshot.items():
                relative_path = ('core/' if owner == 'core' else 'packs/' + owner + '/') + name
                write_bytes(path_at(directory / 'baseline', relative_path), data)
        for item in items:
            path = info[0] if item['path'] == '@git-exclude' else path_at(root, item['path'])
            if digest(contents(path)) != item['beforeSha256']:
                raise ValueError('File changed before replacement; transaction interrupted: ' + item['path'])
            if path.exists() and not same_mode(stat.S_IMODE(path.stat().st_mode), item['mode']):
                raise ValueError('File mode changed before replacement; transaction interrupted')
            # A file replacement may succeed before its log update; both images are recorded first.
            write_bytes(path, base64.b64decode(item['after']), item['mode'])
        journal['status'] = 'committed'
        journal['completedAt'] = now()
        write_bytes(journal_path, encoded(journal))
    except BaseException:
        journal['status'] = 'interrupted'
        write_bytes(journal_path, encoded(journal))
        raise
    return dict(transaction=transaction, status='committed', paths=[i['path'] for i in items])


def apply(root: Path, saved: dict) -> dict:
    if saved.get('target') != str(root) or saved.get('source') != str(SOURCE) or saved.get('kind') != 'workflow-upgrade-plan':
        raise ValueError('Plan identity does not match this target and distribution')
    baseline = Path(saved.get('baseline', '')).resolve()
    transaction = uuid.uuid4().hex
    with LifecycleLock(root, 'upgrade', transaction=transaction), configuration_lock(root, transaction):
        fresh, payloads = build_plan(root, baseline)
        if json.dumps(fresh, sort_keys=True) != json.dumps(saved, sort_keys=True):
            raise ValueError('Upgrade plan is stale or modified; regenerate and review it')
        if not fresh['ready']:
            raise ValueError('Upgrade has conflicts; no files were changed')
        manifest = after_manifest(load(root), fresh)
        snapshot = inventory(SOURCE, manifest['installedPacks'])
        if version(SOURCE) != fresh['toVersion'] or any(digest(snapshot[row['path']][1]) != row['nextBaselineSha256'] for row in fresh['entries'] if row['path'] in snapshot):
            raise ValueError('Distribution changed during preparation')
        if digest(contents(path_at(root, 'workflow.config.json'))) != fresh['configurationSha256']:
            raise ValueError('Project configuration changed during preparation')
        expected = {row['path']: row['beforeSha256'] for row in fresh['entries']}
        expected[MANIFEST] = fresh['manifestSha256']
        if fresh['gitExclude']:
            expected['@git-exclude'] = fresh['gitExclude']['sha256']
        return transact(root, manifest, payloads, 'upgrade', transaction, snapshot, expected)


def rollback(root: Path, transaction: str) -> dict:
    if not TRANSACTION.fullmatch(transaction):
        raise ValueError('Invalid transaction ID')
    with LifecycleLock(root, 'rollback', transaction=transaction, recover=True), configuration_lock(root, transaction, recover=True):
        journal_path = path_at(root, '.dev-workflow/upgrades/' + transaction + '/journal.json')
        record = object_at(journal_path)
        if record.get('schemaVersion') != 1 or record.get('target') != str(root) or record.get('transaction') != transaction:
            raise ValueError('Rollback journal identity mismatch')
        if record.get('status') == 'rolled-back':
            return dict(transaction=transaction, status='rolled-back')
        items = record.get('items')
        if not isinstance(items, list) or not items or items[-1].get('path') != MANIFEST:
            raise ValueError('Invalid rollback inventory')
        # Only paths present in the before/after manifest inventory can be restored.
        manifest_item = items[-1]
        original = json.loads(base64.b64decode(manifest_item['before'], validate=True))
        following = json.loads(base64.b64decode(manifest_item['after'], validate=True))
        for key in set(original) | set(following):
            if key not in {'files', 'workflowVersion', 'upgradeState', 'updatedAt'} and original.get(key) != following.get(key):
                raise ValueError('Rollback journal cannot change permissions, configuration adoption or project declarations')
        registered = inventory(SOURCE, following['installedPacks'])
        allowed = {e['path'] for m in (original, following) for e in m['files']} | {MANIFEST, '@git-exclude'}
        seen, resolved = set(), []
        for item in items:
            key = item.get('path')
            if key not in allowed or key in seen:
                raise ValueError('Unknown or duplicate rollback path')
            seen.add(key)
            if key not in (MANIFEST, '@git-exclude') and key not in registered:
                raise ValueError('Rollback payload does not belong to the distribution')
            if type(item.get('mode')) is not int or not 0 <= item['mode'] <= 0o777:
                raise ValueError('Invalid rollback file mode')
            before = base64.b64decode(item['before'], validate=True) if item['before'] is not None else None
            after = base64.b64decode(item['after'], validate=True)
            if digest(before) != item['beforeSha256'] or digest(after) != item['afterSha256']:
                raise ValueError('Rollback backup integrity mismatch')
            path = destination(root, key, record.get('excludePath'))
            observed = contents(path)
            if observed not in (before, after):
                raise ValueError('User changed a file after the transaction; rollback refused: ' + key)
            observed_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
            if observed_mode is not None and not same_mode(observed_mode, item['mode']):
                raise ValueError('User changed file mode after the transaction; rollback refused: ' + key)
            resolved.append((key, before, item['mode'], observed, observed_mode))
        # Changes to config/permissions after upgrade also change manifest and are rejected above.
        record['status'] = 'rolling-back'
        write_bytes(journal_path, encoded(record))
        for key, before, mode, observed, observed_mode in reversed(resolved):
            path = destination(root, key, record.get('excludePath'))
            current_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
            if contents(path) != observed or current_mode != observed_mode:
                raise ValueError('User changed a file during rollback; stopped before overwriting: ' + key)
            if before is None:
                if path.exists():
                    path.unlink()
            else:
                write_bytes(path, before, mode)
        record['status'] = 'rolled-back'
        record['completedAt'] = now()
        write_bytes(journal_path, encoded(record))
        return dict(transaction=transaction, status='rolled-back')


def transfer(root: Path, names: list[str], dry_run: bool) -> dict:
    transaction = uuid.uuid4().hex
    # Dry-run never creates a lock or any project metadata.
    def prepare_transfer():
        check(root)
        manifest = load(root)
        active = {e['path']: e for e in manifest['files']}
        registered = inventory(SOURCE, manifest['installedPacks'])
        for name in names:
            relative(name)
            if not document(name) or name not in active or name not in registered:
                raise ValueError('Only registered project documents can be transferred: ' + name)
            path_at(root, name)
        manifest = deepcopy(manifest)
        state = manifest.setdefault('upgradeState', dict(schemaVersion=1, coreBlock=None, projectOwned=[], lastTransaction=None))
        state['projectOwned'] = sorted(set(state['projectOwned']) | set(names))
        for entry in manifest['files']:
            if entry['path'] in names:
                entry['action'], entry['installedSha256'] = 'preserved', None
        manifest['updatedAt'] = now()
        return manifest
    if dry_run:
        prepare_transfer()
        return dict(dryRun=True, projectOwned=names, permissionsChanged=False)
    with LifecycleLock(root, 'transfer', transaction=transaction), configuration_lock(root, transaction):
        original = digest(path_at(root, MANIFEST).read_bytes())
        manifest = prepare_transfer()
        return transact(root, manifest, {}, 'transfer', transaction, expected={MANIFEST: original})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'rollback', 'transfer', 'check', 'state', 'project-paths'))
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--transaction')
    parser.add_argument('--paths', nargs='+')
    parser.add_argument('--operation', choices=('install', 'audit', 'uninstall'))
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--strict', action='store_true', help='check: treat newly customized core blocks as failure')
    args = parser.parse_args()
    try:
        root = args.target.resolve()
        if not root.is_dir():
            raise ValueError('Target directory does not exist')
        if args.action == 'plan':
            result, _ = build_plan(root, args.baseline.resolve() if args.baseline else None)
            if args.output:
                output = args.output.absolute()
                if any(output.resolve().is_relative_to(directory) for directory in (root, SOURCE, Path(result['baseline']))):
                    raise ValueError('Save reviewed plans outside the target and distribution directories')
                if any(linked(p) for p in (output, *output.parents)):
                    raise ValueError('Plan output contains a linked path')
                with output.open('xb') as stream:
                    stream.write(encoded(result))
        elif args.action == 'apply':
            if not args.plan:
                raise ValueError('apply requires --plan')
            result = apply(root, object_at(args.plan))
        elif args.action == 'rollback':
            if not args.transaction:
                raise ValueError('rollback requires --transaction')
            result = rollback(root, args.transaction)
        elif args.action == 'transfer':
            if not args.paths:
                raise ValueError('transfer requires --paths')
            result = transfer(root, list(dict.fromkeys(args.paths)), args.dry_run)
        elif args.action == 'check':
            result = check(root, args.operation)
        elif args.action == 'state':
            manifest = load(root)
            state_check(manifest)
            result = manifest.get('upgradeState')
        else:
            manifest = load(root)
            state_check(manifest)
            print('\n'.join((manifest.get('upgradeState') or {}).get('projectOwned', [])))
            return 0
        print(json.dumps(result, ensure_ascii=True, indent=2))
        if args.action == 'check' and args.strict and result.get('warnings'):
            return 1
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps(dict(error=str(exc)), ensure_ascii=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
