#!/usr/bin/env python3
"""Scoped release execution for trusted embedding hosts; CLI remains preparation-only."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve()
sys.path.insert(0, str(SCRIPT.parent))
if len(SCRIPT.parents) > 3:
    sys.path.append(str(SCRIPT.parents[3] / 'core/scripts'))
import release_prepare as preparation_tool
from workflow_lock import LifecycleLock, linked, pending_upgrades

OPERATIONS = ('local-tag-create', 'remote-tag-push', 'remote-release-create')


class ExecutionError(ValueError):
    pass


class AuthorizationUnavailable(ExecutionError):
    pass


class IdentityConflict(ExecutionError):
    pass


class ProviderRejected(ExecutionError):
    """Host provider has definitive evidence that its mutation was rejected."""


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def fingerprint(value) -> str:
    return hashlib.sha256(canonical(value).encode('ascii')).hexdigest()


def clock() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ExecutionError('Invalid authorization timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise ExecutionError('Invalid authorization timestamp') from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExecutionError('Authorization timestamps require a timezone')
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class Request:
    operation: str
    repository: str
    head_sha: str
    target_ref: str
    target_sha: str
    configuration_hash: str
    tag: str
    tag_object_sha: str
    remote_name: str | None
    remote_url: str | None
    release_json: str | None
    plan_hash: str

    def digest(self) -> str:
        return fingerprint(asdict(self))


@dataclass(frozen=True)
class Grant:
    grant_id: str
    request_hash: str
    expires_at: str
    max_uses: int


@dataclass(frozen=True)
class Receipt:
    grant_id: str
    request_hash: str
    use_number: int
    consumed_at: str


def run_git(root: Path, *arguments: str, input_text: str | None = None) -> str:
    # No reference-transaction hooks, pre-push hooks or index refreshes from these operations.
    with tempfile.TemporaryDirectory(prefix='workflow-release-hooks-') as empty_hooks:
        result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.hooksPath=' + empty_hooks, '-c', 'core.fsmonitor=false',
                                 '-C', str(root), *arguments],
                                input=input_text.encode('utf-8') if input_text is not None else None,
                                capture_output=True, timeout=30,
                                env={**os.environ, 'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0'})
    if result.returncode:
        raise ExecutionError('Git release inspection or reference operation failed')
    return result.stdout.decode('utf-8', errors='strict').strip()


def safe_record(root: Path, relative: str) -> Path:
    destination = root
    for part in relative.split('/'):
        if part in ('', '.', '..'):
            raise ExecutionError('Invalid local release record path')
        destination = destination / part
        if linked(destination):
            raise ExecutionError('Local release record path is linked or reparsed')
    return destination


def remote_identity(root: Path, name: str) -> dict:
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name):
        raise ExecutionError('Invalid release remote name')
    fetch = run_git(root, 'remote', 'get-url', '--all', name).splitlines()
    push = run_git(root, 'remote', 'get-url', '--push', '--all', name).splitlines()
    if len(fetch) != 1 or fetch != push:
        raise ExecutionError('Release remote requires exactly one identical fetch and push URL')
    value = fetch[0]
    # A bounded GitHub.com integration contract; no transport credentials or URL aliases.
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise ExecutionError('Invalid release remote URL')
    if value.startswith('git@github.com:'):
        path = value[len('git@github.com:'):]
    else:
        parsed = urlsplit(value)
        if (parsed.scheme not in ('https', 'ssh') or parsed.hostname != 'github.com'
                or parsed.password is not None or parsed.query or parsed.fragment
                or parsed.netloc not in ('github.com', 'git@github.com')
                or (parsed.scheme == 'https' and parsed.username is not None)
                or (parsed.scheme == 'ssh' and parsed.username != 'git')):
            raise ExecutionError('Release remote must be a canonical GitHub HTTPS or SSH URL')
        path = parsed.path.removeprefix('/')
    slug = path.removesuffix('.git')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', slug) or any(part in ('.', '..') for part in slug.split('/')):
        raise ExecutionError('Invalid GitHub release repository path')
    return dict(name=name, url=value, repository=slug)


def validate_preparation(root: Path, saved: dict) -> dict:
    if not isinstance(saved, dict) or saved.get('kind') != 'release-preparation' or type(saved.get('schemaVersion')) is not int or saved['schemaVersion'] != 1:
        raise ExecutionError('Unsupported release preparation')
    if Path(run_git(root, 'rev-parse', '--show-toplevel')).resolve() != root:
        raise ExecutionError('Release execution requires the exact Git top-level repository')
    sources, builds = [], []
    components = saved.get('components')
    if not isinstance(components, list):
        raise ExecutionError('Invalid release preparation components')
    for item in components:
        if not isinstance(item, dict) or not isinstance(item.get('name'), str):
            raise ExecutionError('Invalid release preparation component')
        for key, output in (('sourceSha', sources), ('buildSource', builds)):
            value = item.get(key)
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise ExecutionError('Invalid component declaration')
                output.append(item['name'] + '=' + value)
    if not isinstance(saved.get('targetRef'), str):
        raise ExecutionError('Missing release target reference')
    fresh = preparation_tool.prepare(root, saved['targetRef'], saved.get('version'), sources, builds)
    # Tag existence is a current observation, not immutable intent. Other fields
    # remain exactly bound, including all independently unknown product states.
    observations = {'preparedAt', 'tagStatus'}
    if set(saved) != set(fresh) or any(saved[key] != fresh[key] for key in fresh if key not in observations):
        raise ExecutionError('Release preparation intent is stale or modified')
    if saved['tagStatus'] not in ('not_requested', 'available_locally', 'already_exists_same_commit'):
        raise ExecutionError('Invalid preparation tag observation')
    timestamp(saved['preparedAt'])
    return saved


def build_plan(root: Path, preparation: dict, *, remote: str | None = None, release: dict | None = None) -> dict:
    root = root.resolve()
    saved = json.loads(canonical(preparation))
    validate_preparation(root, saved)
    destination = remote_identity(root, remote) if remote is not None else None
    release_spec = None
    if release is not None:
        required = {'endpoint', 'repository', 'repositoryId', 'name', 'body', 'draft', 'prerelease'}
        if (not isinstance(release, dict) or set(release) != required or destination is None
                or release.get('endpoint') != 'https://api.github.com'
                or release.get('repository') != destination['repository']
                or type(release.get('repositoryId')) is not int or release['repositoryId'] <= 0
                or not isinstance(release.get('name'), str) or not release['name'].strip()
                or not isinstance(release.get('body'), str)
                or type(release.get('draft')) is not bool or type(release.get('prerelease')) is not bool):
            raise ExecutionError('Invalid or mismatched release identity and payload')
        release_spec = json.loads(canonical(release))
    return dict(schemaVersion=1, kind='release-execution-plan', repository=str(root),
                preparation=saved, remote=destination, tagObjectSha=saved['targetSha'],
                release=release_spec, requiresTrustedHost=True)


def recheck(root: Path, plan: dict) -> None:
    if not isinstance(plan, dict):
        raise ExecutionError('Invalid execution plan')
    destination = plan.get('remote')
    if destination is not None and not isinstance(destination, dict):
        raise ExecutionError('Invalid execution remote')
    fresh = build_plan(root, plan.get('preparation'), remote=destination.get('name') if destination else None,
                       release=plan.get('release'))
    if canonical(fresh) != canonical(plan):
        raise ExecutionError('Execution plan identity is stale or modified')


def request_for(root: Path, plan: dict, operation: str) -> Request:
    if operation not in OPERATIONS:
        raise ExecutionError('Unsupported release operation')
    recheck(root, plan)
    prepared = plan['preparation']
    if prepared['strategy'] != 'semver-tag' or not prepared['tag']:
        raise ExecutionError('This release strategy requests no tag or Release execution')
    destination = plan['remote']
    if operation != 'local-tag-create' and destination is None:
        raise ExecutionError('Remote release operations require an exact destination')
    if operation == 'remote-release-create' and plan['release'] is None:
        raise ExecutionError('Release creation requires an explicit identity and payload')
    return Request(operation, str(root), prepared['headSha'], prepared['targetRef'], prepared['targetSha'],
                   prepared['configurationHash'], prepared['tag'], plan['tagObjectSha'],
                   destination['name'] if destination else None, destination['url'] if destination else None,
                   canonical(plan['release']) if plan['release'] else None, fingerprint(plan))


def validate_grant(grant: Grant, request: Request) -> None:
    if (not isinstance(grant, Grant) or not isinstance(grant.grant_id, str)
            or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', grant.grant_id)
            or grant.request_hash != request.digest()
            or type(grant.max_uses) is not int or not 1 <= grant.max_uses <= 100):
        raise ExecutionError('Host authorization is invalid or has a different operation scope')
    if timestamp(grant.expires_at) <= clock():
        raise ExecutionError('Host authorization expired')


def validate_receipt(receipt: Receipt, grant: Grant, request: Request, started: datetime) -> None:
    validate_grant(grant, request)
    if (not isinstance(receipt, Receipt) or receipt.grant_id != grant.grant_id
            or receipt.request_hash != request.digest() or type(receipt.use_number) is not int
            or not 1 <= receipt.use_number <= grant.max_uses):
        raise ExecutionError('Host authorization consumption was not verified')
    consumed = timestamp(receipt.consumed_at)
    if not started - timedelta(seconds=1) <= consumed <= clock() + timedelta(seconds=30):
        raise ExecutionError('Host consumption receipt is stale or from the future')


def local_tag(root: Path, request: Request) -> dict | None:
    refs = run_git(root, 'for-each-ref', '--format=%(refname) %(objectname) %(objecttype) %(symref)', 'refs/tags/' + request.tag)
    lines = [line.split() for line in refs.splitlines() if line.split()[0] == 'refs/tags/' + request.tag]
    if not lines:
        return None
    if len(lines) != 1 or len(lines[0]) != 3 or lines[0][2] != 'commit':
        raise IdentityConflict('Executor supports lightweight tags only; annotated or symbolic tags require review')
    return dict(objectSha=lines[0][1], targetSha=lines[0][1])


def verified_tag(observation, request: Request) -> bool:
    if observation is None:
        return False
    if (not isinstance(observation, dict) or observation.get('objectSha') != request.tag_object_sha
            or observation.get('targetSha') != request.target_sha):
        raise IdentityConflict('Tag object conflicts with the approved immutable identity')
    return True


def verified_release(observation, request: Request) -> bool:
    if observation is None:
        return False
    expected = json.loads(request.release_json)
    expected.update(tag=request.tag, tagObjectSha=request.tag_object_sha, targetSha=request.target_sha)
    if (not isinstance(observation, dict) or any(type(observation.get(key)) is not type(value) or observation.get(key) != value for key, value in expected.items())
            or type(observation.get('releaseId')) is not int or observation['releaseId'] <= 0):
        raise IdentityConflict('Release identity or approved payload conflicts with authoritative observation')
    return True


def inspect(root: Path, request: Request, tag_provider, release_provider, before_remote=lambda: None):
    if request.operation == 'local-tag-create':
        observed = local_tag(root, request)
        return observed, verified_tag(observed, request)
    before_remote()
    tag = tag_provider.inspect(request)
    if request.operation == 'remote-tag-push':
        return tag, verified_tag(tag, request)
    if not verified_tag(tag, request):
        raise ExecutionError('Release creation requires an already verified remote tag')
    before_remote()
    observed = release_provider.inspect(request)
    present = verified_release(observed, request)
    before_remote()
    if not verified_tag(tag_provider.inspect(request), request):
        raise IdentityConflict('Remote tag changed during Release verification')
    return observed, present


def assert_private_output(root: Path, relative: str) -> None:
    safe_record(root, relative)
    if run_git(root, 'ls-files', '--', ':(top,literal).dev-workflow'):
        raise ExecutionError('Git tracks local workflow metadata; release records must remain local')
    if not run_git(root, 'check-ignore', '--no-index', '--', relative):
        raise ExecutionError('Local release records must be excluded from Git')


def assert_record_safety(root: Path, attempt: str) -> None:
    assert_private_output(root, '.dev-workflow/releases/execution-' + attempt + '.json')


def write_audit(root: Path, attempt: str, value: dict) -> None:
    assert_record_safety(root, attempt)
    directory = safe_record(root, '.dev-workflow/releases')
    directory.mkdir(parents=True, exist_ok=True)
    destination = safe_record(root, '.dev-workflow/releases/execution-' + attempt + '.json')
    descriptor, temporary = tempfile.mkstemp(prefix='.execution-', dir=directory)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def execute(root: Path, plan: dict, operation: str, *, approval=None, tag_provider=None, release_provider=None) -> dict:
    # The caller must be a trusted embedding host. No locally supplied approval
    # JSON, adapter path, environment switch or interactive prompt substitutes.
    if approval is None:
        raise AuthorizationUnavailable('Trusted host authorization is unavailable; preparation only')
    if operation not in OPERATIONS:
        raise ExecutionError('Unsupported release operation')
    if operation != 'local-tag-create' and tag_provider is None:
        raise ExecutionError('Trusted remote tag provider is unavailable')
    if operation == 'remote-release-create' and release_provider is None:
        raise ExecutionError('Trusted Release provider is unavailable')
    root = root.resolve()
    immutable_plan = json.loads(canonical(plan))
    request = request_for(root, immutable_plan, operation)
    grant = approval.validate(request)
    validate_grant(grant, request)
    with LifecycleLock(root, 'release'):
        if pending_upgrades(root):
            raise ExecutionError('Recover incomplete upgrade transactions before releasing')
        recheck(root, immutable_plan)
        validate_grant(grant, request)
        if operation == 'remote-tag-push' and not verified_tag(local_tag(root, request), request):
            raise ExecutionError('Create the approved local tag before pushing it')
        before_remote = lambda: validate_grant(grant, request)
        observed, present = inspect(root, request, tag_provider, release_provider, before_remote)
        result = dict(schemaVersion=1, kind='release-execution-result', attempt=uuid.uuid4().hex,
                      operation=operation, repository=str(root), requestHash=request.digest(),
                      targetSha=request.target_sha, tag=request.tag, tagObjectSha=request.tag_object_sha,
                      remoteUrl=request.remote_url, releaseId=observed.get('releaseId') if present and observed else None,
                      status='already_present_verified' if present else 'pending', grantId=grant.grant_id,
                      authorizationConsumed=False, createdAt=clock().isoformat(), observedAt=clock().isoformat(),
                      releasePayloadHash=fingerprint(json.loads(request.release_json)) if request.release_json else None,
                      phase='pre-dispatch',
                      states={key: 'unknown' for key in ('ci', 'image', 'deployment', 'live')})
        if present:
            result['phase'] = 'verified'
            write_audit(root, result['attempt'], result)
            return result
        # Validate local output safety before consuming authority or mutating tags.
        assert_record_safety(root, result['attempt'])
        started = clock()
        receipt = approval.consume(grant, request)
        validate_receipt(receipt, grant, request, started)
        result['authorizationConsumed'] = True
        result['useNumber'] = receipt.use_number
        result['consumedAt'] = receipt.consumed_at
        write_audit(root, result['attempt'], result)
        # Host callbacks may have taken time. Recheck immediately before dispatch.
        try:
            recheck(root, immutable_plan)
            validate_grant(grant, request)
            if operation == 'remote-tag-push' and not verified_tag(local_tag(root, request), request):
                raise IdentityConflict('Approved local tag changed before push')
        except Exception:
            result.update(status='failed', failureCode='pre-dispatch-validation-failed')
            write_audit(root, result['attempt'], result)
            raise
        result['phase'] = 'dispatch'
        write_audit(root, result['attempt'], result)
        mutation_error = None
        mutation_started = False
        try:
            validate_grant(grant, request)
            if operation == 'local-tag-create':
                # A production host may recheck revocation and its durable
                # receipt immediately before this local mutation as well.
                guard = getattr(approval, 'guard', None)
                if guard is not None:
                    guard(request)
                validate_grant(grant, request)
                mutation_started = True
                run_git(root, 'update-ref', '--no-deref', '--stdin',
                        input_text='create refs/tags/' + request.tag + ' ' + request.tag_object_sha + '\n')
            elif operation == 'remote-tag-push':
                mutation_started = True
                tag_provider.push(request)
            else:
                # Independent inspection is mandatory immediately before creation;
                # GitHub target_commitish does not constrain an existing tag.
                if not verified_tag(tag_provider.inspect(request), request):
                    raise IdentityConflict('Approved remote tag disappeared before Release creation')
                recheck(root, immutable_plan)
                validate_grant(grant, request)
                mutation_started = True
                release_provider.create(request)
        except Exception as error:
            mutation_error = error
        if mutation_error is not None:
            result['failureCode'] = 'provider-rejected' if isinstance(mutation_error, ProviderRejected) else 'dispatch-outcome-uncertain'
        if not mutation_started:
            result.update(status='failed', failureCode='pre-dispatch-validation-failed', phase='pre-dispatch')
            write_audit(root, result['attempt'], result)
            return result
        result['phase'] = 'verification'
        try:
            validate_grant(grant, request)
            observed, present = inspect(root, request, tag_provider, release_provider, before_remote)
            if present:
                result['status'] = 'already_present_verified' if mutation_error else 'created_verified'
                result['releaseId'] = observed.get('releaseId')
            else:
                result['status'] = 'failed' if isinstance(mutation_error, ProviderRejected) else 'outcome_unknown'
        except IdentityConflict:
            result.update(status='conflict', failureCode='observed-identity-conflict')
        except Exception:
            result.update(status='outcome_unknown', failureCode='verification-unavailable')
        result['observedAt'] = clock().isoformat()
        write_audit(root, result['attempt'], result)
        return result


def object_file(path: Path) -> dict:
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ExecutionError('Expected a JSON object')
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'plan', 'execute'))
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--preparation', type=Path)
    parser.add_argument('--remote')
    parser.add_argument('--release-spec', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == 'status':
            result = dict(executionAvailable=False, mode='preparation-only', reason='trusted-host-adapter-unavailable', operations=list(OPERATIONS))
        elif args.action == 'execute':
            raise AuthorizationUnavailable('Trusted host authorization is unavailable; preparation only')
        else:
            if args.preparation is None:
                raise ExecutionError('plan requires --preparation')
            root = args.repo.resolve()
            prepared_path = args.preparation if args.preparation.is_absolute() else root / args.preparation
            spec_path = args.release_spec if args.release_spec is None or args.release_spec.is_absolute() else root / args.release_spec
            result = build_plan(root, object_file(prepared_path), remote=args.remote,
                                release=object_file(spec_path) if spec_path else None)
            if args.output:
                output = args.output if args.output.is_absolute() else root / args.output
                relative = output.relative_to(root).as_posix()
                if not relative.startswith('.dev-workflow/releases/'):
                    raise ExecutionError('Plan output must be inside .dev-workflow/releases/')
                assert_private_output(root, relative)
                destination = safe_record(root, relative)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('x', encoding='utf-8', newline='\n') as stream:
                    stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (OSError, ValueError, preparation_tool.PreparationError, subprocess.TimeoutExpired) as error:
        print(json.dumps(dict(error=str(error)), ensure_ascii=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
