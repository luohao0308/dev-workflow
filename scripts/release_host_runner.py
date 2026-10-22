#!/usr/bin/env python3
"""Pinned Linux Actions host runner; candidate repositories are data only.

Run with ``python3 -I`` from a separately trusted distribution checkout. Policy
is administrator-owned host configuration, never an input from the target.
"""
from __future__ import annotations

import argparse
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, ProxyHandler

sys.dont_write_bytecode = True
DISTRIBUTION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DISTRIBUTION / 'packs/release/scripts'))
sys.path.insert(1, str(DISTRIBUTION / 'core/scripts'))
import release_execute as execution
import workflow_config
from release_github import GitHubClient, GitHubTagProvider, GitHubReleaseProvider, NoRedirect
from release_host import HostPolicy, GitHubActionsApproval, bundle_digest, AUDIENCE


def object_file(path):
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise execution.ExecutionError('Expected host JSON object')
    return value


def bootstrap(root):
    """Explicitly adopt configuration using trusted code; execute no project code."""
    execution.preparation_tool.offline_repository(root)
    directory = root / '.dev-workflow'
    if directory.exists():
        raise execution.ExecutionError('Host requires a fresh candidate checkout')
    exclude = root / '.git/info/exclude'
    if not exclude.is_file() or exclude.is_symlink():
        raise execution.ExecutionError('Host requires an ordinary isolated Git checkout')
    with exclude.open('a', encoding='utf-8') as stream:
        stream.write('\n.dev-workflow/\n')
    directory.mkdir()
    manifest = dict(managedBy='dev-workflow', schemaVersion=5, enabledCapabilities=[])
    manifest_path = directory / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    config_path = workflow_config.safe_path(root, workflow_config.CONFIG_NAME)
    source = config_path.read_bytes()
    config = workflow_config.read_object(config_path)
    if workflow_config.validate_config(config):
        raise execution.ExecutionError('Trusted configuration adoption failed')
    # The fresh host explicitly adopts the exact tracked bytes. Reformatting a
    # candidate file here would dirty an otherwise valid release checkout.
    manifest.update(enabledCapabilities=config['enabledCapabilities'],
                    projectConfiguration=dict(adopted=True, sha256=hashlib.sha256(source).hexdigest()))
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')


def policy_for(config, metadata):
    """Identity roots come from the trusted host, intent and deadline from preview."""
    host_sha = execution.run_git(DISTRIBUTION, 'rev-parse', 'HEAD')
    return HostPolicy(
        host_repository=config['hostRepository'], host_repository_id=config['hostRepositoryId'],
        workflow_ref=config['workflowRef'], workflow_sha=host_sha,
        run_id=int(os.environ['GITHUB_RUN_ID']), environment=config['environment'],
        reviewer_ids=tuple(config['reviewerIds']), target_repository=config['targetRepository'],
        target_repository_id=config['targetRepositoryId'],
        ledger_repository=config['hostRepository'], ledger_repository_id=config['hostRepositoryId'],
        ledger_sha=host_sha, expires_at=metadata['expiresAt'],
        prevent_self_review=config.get('preventSelfReview', True))


def oidc_token():
    url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname
            or not parsed.hostname.endswith('.actions.githubusercontent.com')
            or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None, 443)):
        raise execution.AuthorizationUnavailable('Untrusted runner OIDC endpoint')
    token = os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
    request = Request(url + ('&' if parsed.query else '?') + urlencode({'audience': AUDIENCE}),
                      headers={'Authorization': 'Bearer ' + token})
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise execution.AuthorizationUnavailable('Invalid runner identity response')
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get('value'), str):
        raise execution.AuthorizationUnavailable('Runner identity unavailable')
    return value['value']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'execute'))
    parser.add_argument('--policy', type=Path, required=True, help='Trusted host policy; never candidate data')
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--record', type=Path, required=True, help='Preview artifact outside candidate checkout')
    parser.add_argument('--version')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    phase = 'load-policy'
    try:
        config = object_file(args.policy)
        root = args.repo.resolve()
        if root != Path(config['candidatePath']) or root == DISTRIBUTION or DISTRIBUTION in root.parents or root in DISTRIBUTION.parents:
            raise execution.ExecutionError('Candidate must use the isolated host-defined path')
        # No argument may introduce a new trust root or operation.
        operations = tuple(config['operations'])
        if not operations or len(set(operations)) != len(operations) or any(op not in execution.OPERATIONS for op in operations):
            raise execution.ExecutionError('Invalid host operation policy')
        phase = 'adopt-candidate'
        bootstrap(root)
        if args.action == 'prepare':
            if not args.version:
                raise execution.ExecutionError('Preview requires an explicit release version')
            prepared = execution.preparation_tool.prepare(root, 'HEAD', args.version, [], [])
            spec = dict(endpoint='https://api.github.com', repository=config['targetRepository'],
                        repositoryId=config['targetRepositoryId'], **config['release'])
            plan = execution.build_plan(root, prepared, remote='origin', release=spec)
            record = dict(plan=plan, expiresAt=(execution.clock() + timedelta(minutes=55)).isoformat())
        else:
            phase = 'recheck-plan'
            record = object_file(args.record)
            plan = record['plan']
            execution.recheck(root, plan)
        phase = 'freeze-request'
        policy = policy_for(config, record)
        requests = tuple(execution.request_for(root, plan, operation) for operation in operations)
        digest = bundle_digest(requests, policy.expires_at, policy.bundle_context())
        if args.action == 'prepare':
            record.update(bundleHash=digest, approvalComment='dev-workflow approve ' + digest,
                          operations=list(operations), targetRepository=config['targetRepository'])
            args.record.parent.mkdir(parents=True, exist_ok=True)
            with args.record.open('x', encoding='utf-8') as stream:
                json.dump(record, stream, ensure_ascii=True, indent=2)
                stream.write('\n')
            summary = os.environ.get('GITHUB_STEP_SUMMARY')
            if summary:
                with Path(summary).open('a', encoding='utf-8') as stream:
                    stream.write('## Release approval request\n\nReview the full preview artifact.\n\n'
                        + 'Target: `' + config['targetRepository'] + '`\n\n'
                        + 'Commit: `' + plan['preparation']['targetSha'] + '`\n\n'
                        + 'Tag: `' + plan['preparation']['tag'] + '`\n\n'
                        + 'Operations: `' + ', '.join(operations) + '`\n\n'
                        + 'Expires: `' + record['expiresAt'] + '`\n\n'
                        + 'Approve the protected environment with this exact comment:\n\n`'
                        + record['approvalComment'] + '`\n')
            print(json.dumps(record, ensure_ascii=True, indent=2))
            return 0
        phase = 'verify-preview'
        if record.get('bundleHash') != digest or record.get('operations') != list(operations):
            raise execution.AuthorizationUnavailable('Preview differs from frozen host intent')
        phase = 'create-client'
        client = GitHubClient(os.environ['RELEASE_TOKEN'])
        phase = 'oidc-bootstrap'
        identity = oidc_token()
        phase = 'authority-verification'
        approval = GitHubActionsApproval(client, identity, requests, policy)
        tags = GitHubTagProvider(client, policy.target_repository, policy.target_repository_id, before_mutation=approval.guard)
        releases = GitHubReleaseProvider(client, policy.target_repository, policy.target_repository_id, before_mutation=approval.guard)
        results = []
        for operation in operations:
            phase = 'execute-' + operation
            result = execution.execute(root, plan, operation, approval=approval, tag_provider=tags, release_provider=releases)
            results.append(result)
            if result['status'] not in ('created_verified', 'already_present_verified'):
                break
        complete = len(results) == len(operations) and all(item['status'] in ('created_verified', 'already_present_verified') for item in results)
        # Re-inspect without issuing further mutations: consumption remains one use.
        repeated = []
        if complete:
            for operation in operations:
                phase = 'verify-existing-' + operation
                repeated.append(execution.execute(root, plan, operation, approval=approval, tag_provider=tags, release_provider=releases))
            complete = all(item['status'] == 'already_present_verified' and not item['authorizationConsumed'] for item in repeated)
        output = dict(complete=complete, bundleHash=digest, results=results, repeated=repeated)
        if args.output:
            with args.output.open('x', encoding='utf-8') as stream:
                json.dump(output, stream, ensure_ascii=True, indent=2)
                stream.write('\n')
        print(json.dumps(output, ensure_ascii=True, indent=2))
        return 0 if complete else 1
    except Exception as error:
        # Tokens, transport responses, paths with credentials and JWTs never enter logs.
        failure = dict(complete=False, error='Trusted release host failed; no automatic mutation retry',
                       phase=phase, errorType=type(error).__name__)
        code = getattr(error, 'failure_code', None)
        if isinstance(code, str) and re.fullmatch(r'authorization-[0-9a-f]{12}', code):
            failure['failureCode'] = code
        fields = getattr(error, 'mismatch_fields', ())
        identity_keys = {'iss', 'aud', 'repository', 'repository_id', 'workflow_ref', 'workflow_sha',
                         'run_id', 'run_attempt', 'environment', 'sub'}
        if isinstance(fields, tuple) and fields and all(field in identity_keys for field in fields):
            failure['mismatchedClaims'] = list(fields)
        if args.output:
            try:
                with args.output.open('x', encoding='utf-8') as stream:
                    json.dump(failure, stream, ensure_ascii=True, indent=2)
                    stream.write('\n')
            except OSError:
                pass
        print(json.dumps(failure), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
