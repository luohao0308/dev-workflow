#!/usr/bin/env python3
"""Authorization-only diagnostic bundle; never a deployment or runtime permit."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from deployment_compose_approval_host import AUDIENCE, PROFILE, ComposeApprovalPolicy
from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity
from release_host import bundle_digest

REPOSITORY = 'luohao0308/dev-workflow'
REPOSITORY_ID = 1327491026
REF = 'refs/heads/feat/compose-validation-20261028'
WORKFLOW = '.github/workflows/compose-protected-review.yml'
FIELDS = {'schema', 'issuedAt', 'request', 'policy', 'requestHash', 'policyHash', 'bundleHash'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('ascii')).hexdigest()


def stamp(now):
    return now.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_stamp(value):
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def identities(env):
    if (env.get('GITHUB_REPOSITORY') != REPOSITORY
            or env.get('GITHUB_REPOSITORY_ID') != str(REPOSITORY_ID)
            or env.get('GITHUB_REF') != REF or env.get('GITHUB_RUN_ATTEMPT') != '1'
            or env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'):
        raise ValueError('Unsupported diagnostic workflow identity or rerun')
    return dict(host_repository=REPOSITORY, host_repository_id=REPOSITORY_ID,
                workflow_ref=REPOSITORY + '/' + WORKFLOW + '@' + REF,
                workflow_sha=env['GITHUB_SHA'], run_id=int(env['GITHUB_RUN_ID']),
                environment='compose-review', reviewer_ids=(int(env['DW_AUTH_REVIEWER_ID']),),
                target_repository=REPOSITORY, target_repository_id=REPOSITORY_ID,
                ledger_repository=env['DW_AUTH_LEDGER_REPOSITORY'],
                ledger_repository_id=int(env['DW_AUTH_LEDGER_ID']), ledger_sha=env['DW_AUTH_LEDGER_SHA'])


def values(env, issued):
    expiry = stamp(issued + timedelta(minutes=30))
    policy_hash = digest({'purpose': 'authorization-only-diagnostic', 'executionAllowed': False})
    target = TargetIdentity('compose', 'dw-approval-contract', 'authorization-only')
    common = dict(operation='deploy', profile_version='1', production=False,
                  daemon_id='authorization-only', host_id='authorization-only',
                  components=('backend', 'frontend'), protected_components=(), policy_hash=policy_hash)
    policy = ComposeApprovalPolicy(**identities(env), **common, expires_at=expiry,
                                   approval_environment='compose-review', source_sha=env['GITHUB_SHA'],
                                   target=target, deployment_environment='staging')
    # These explicitly labelled synthetic digests assert no physical observation or backup.
    markers = {field: digest({'diagnosticOnly': field, 'source': env['GITHUB_SHA']})
               for field in ('before_hash', 'after_hash', 'artifact_digest', 'observation_hash', 'plan_hash')}
    request = RequestV2(schema_version=2, profile_id=PROFILE, **common, **markers,
                        source=SourceIdentity('github.com', 'https://github.com/' + REPOSITORY + '.git',
                                              REPOSITORY_ID, REPOSITORY, env['GITHUB_SHA']),
                        target=target, environment='staging', history_hash=None, expires_at=expiry, max_uses=1)
    return request, policy


def prepare(env, now=None):
    issued = parse_stamp(stamp(now or datetime.now(timezone.utc)))
    request, policy = values(env, issued)
    return dict(schema=1, issuedAt=stamp(issued), request=asdict(request), policy=asdict(policy),
                requestHash=request.digest(), policyHash=digest(asdict(policy)),
                bundleHash=bundle_digest([request], policy.expires_at, policy.bundle_context()))


def verify(raw, env, now=None):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate bundle key')
            result[key] = value
        return result
    if len(raw) > 65536:
        raise ValueError('Bundle exceeds limit')
    obj = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(obj, dict) or set(obj) != FIELDS or raw != canonical(obj) or type(obj['schema']) is not int or obj['schema'] != 1:
        raise ValueError('Invalid canonical diagnostic bundle')
    issued = parse_stamp(obj['issuedAt'])
    now = now or datetime.now(timezone.utc)
    if not issued <= now < issued + timedelta(minutes=30):
        raise ValueError('Diagnostic bundle expired or issued in the future')
    request = RequestV2.from_json(canonical(obj['request']))
    expected = prepare(env, issued)
    # Reconstruct against trusted workflow identity and fixed scope, not self-declared hashes.
    if canonical(obj) != canonical(expected):
        raise ValueError('Diagnostic bundle differs from fixed workflow scope')
    _, policy = values(env, issued)
    request.ensure_fresh(now, maximum_seconds=1800)
    return request, policy, obj['bundleHash']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('OIDC endpoint redirected')


def fetch_token(env):
    url = env['ACTIONS_ID_TOKEN_REQUEST_URL']
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ''
    if (parsed.scheme != 'https' or not host.endswith('.actions.githubusercontent.com')
            or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.fragment):
        raise ValueError('Unsupported OIDC endpoint')
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if any(key == 'audience' for key, _ in query):
        raise ValueError('Unexpected OIDC audience parameter')
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query + [('audience', AUDIENCE)])))
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + env['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('Oversized response')
        token = json.loads(raw)['value']
        if not isinstance(token, str) or len(token) > 32768 or token.count('.') != 2 or not token.isascii():
            raise ValueError('Invalid token')
        return token.encode('ascii')
    except Exception:
        raise ValueError('OIDC request failed') from None


def seal(raw, env, recipient, output):
    verify(raw, env)
    token = fetch_token(env)
    # Plaintext exists only in memory and the subprocess pipe, never a file or log.
    result = subprocess.run(['/usr/bin/openssl', 'cms', '-encrypt', '-binary', '-aes256',
                             '-outform', 'DER', str(recipient)], input=token, capture_output=True,
                            timeout=15, env={'PATH': '/usr/bin:/bin'})
    if result.returncode or not result.stdout:
        raise ValueError('OIDC encryption failed')
    Path(output).write_bytes(result.stdout)
    os.chmod(output, 0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'verify', 'seal'))
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--recipient', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'prepare':
            obj = prepare(os.environ)
            args.bundle.write_text(canonical(obj), encoding='ascii')
            print(obj['bundleHash'])
        elif args.command == 'verify':
            print(verify(args.bundle.read_text(encoding='ascii'), os.environ)[2])
        else:
            if not args.recipient or not args.output:
                raise ValueError('Recipient and output required')
            seal(args.bundle.read_text(encoding='ascii'), os.environ, args.recipient, args.output)
            print('Encrypted authorization-only evidence saved')
    except Exception:
        # Never interpolate HTTP errors, response bodies, environment or token material.
        print('Authorization-only contract failed closed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
