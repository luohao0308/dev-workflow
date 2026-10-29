"""Live protected review bridge. All plaintext credentials remain in memory."""
from dataclasses import asdict
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import zipfile

from deployment_compose_full_body_review_contract import (
    REPOSITORY, REPOSITORY_ID, REF, WORKFLOW, canonical, parse_stamp,
    verify_prepared_review)
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_contract_v2 import RequestV2
from deployment_compose_approval_v3_host import GitHubFullBodyApprovalV3
from release_github import GitHubClient, GitHubUnavailable

CONFIG = dict(DW_AUTH_LEDGER_REPOSITORY='luohao0308/dev-workflow-authority-ledger',
              DW_AUTH_LEDGER_ID='1436718662',
              DW_AUTH_LEDGER_SHA='9792b607154fb9a7ed331dc2b9c06c7dacbd7d12',
              DW_AUTH_REVIEWER_ID='84822776')
REPO_ROOT = Path(__file__).resolve().parents[1]


class LiveReviewBlocked(ValueError):
    """No authority was returned; ambiguous dispatch/consumption must not retry."""


def _private(path, mode, directory=False):
    path = Path(path).absolute()
    if path.is_relative_to(REPO_ROOT) or path.resolve() != path:
        raise LiveReviewBlocked('Private path must be outside repository without symlinks')
    info = path.lstat()
    if (stat.S_IMODE(info.st_mode) != mode or info.st_uid != os.getuid()
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise LiveReviewBlocked('Invalid private path permissions or type')
    return path


class GitHubLiveReviewV3:
    def __init__(self, private_root, *, source_sha, recipient_private_key):
        self.root = _private(private_root, 0o700, True)
        self.key = _private(recipient_private_key, 0o600)
        if not isinstance(source_sha, str) or not re.fullmatch('[0-9a-f]{40}', source_sha):
            raise LiveReviewBlocked('Invalid frozen workflow SHA')
        self.source_sha = source_sha
        self.client = self._client()

    def _command(self, args, *, timeout=30):
        try:
            return subprocess.run(args, capture_output=True, timeout=timeout, check=False)
        except Exception:
            raise LiveReviewBlocked('Private subprocess failed; do not retry mutations') from None

    def _client(self):
        result = self._command(['gh', 'auth', 'token', '--hostname', 'github.com'])
        if result.returncode:
            raise LiveReviewBlocked('GitHub credential unavailable')
        return GitHubClient(result.stdout.decode('ascii').strip())

    def _approval(self, token, request, policy):
        # Deliberately no verifier override: real issuer/JWKS verification is mandatory.
        return GitHubFullBodyApprovalV3(self.client, token, [request], policy)

    def _get(self, suffix):
        # Read-only polling may tolerate transient transport failures. Mutations
        # and approval consumption deliberately do not use this retry loop.
        for attempt in range(3):
            try:
                return self.client.request('GET', '/repos/' + REPOSITORY + suffix)[0]
            except GitHubUnavailable:
                if attempt == 2:
                    raise
                time.sleep(attempt + 1)

    def _environment(self):
        repo = self._get('')
        if repo.get('id') != REPOSITORY_ID or repo.get('full_name') != REPOSITORY:
            raise LiveReviewBlocked('Repository identity changed')
        for name, expected in CONFIG.items():
            if self._get('/actions/variables/' + name).get('value') != expected:
                raise LiveReviewBlocked('Authority configuration changed')
        env = self._get('/environments/compose-review')
        rules = [r for r in env.get('protection_rules', []) if r.get('type') == 'required_reviewers']
        if (env.get('name') != 'compose-review' or env.get('can_admins_bypass') is not False
                or len(rules) != 1 or rules[0].get('prevent_self_review') is not True
                or type(rules[0].get('reviewers')) is not list):
            raise LiveReviewBlocked('Protected reviewer policy changed')
        reviewers = rules[0]['reviewers']
        if (len(reviewers) != 1 or reviewers[0].get('type') != 'User'
                or reviewers[0].get('reviewer', {}).get('id') != 84822776):
            raise LiveReviewBlocked('Protected reviewer identity changed')
        return env

    def _env(self, run):
        return dict(CONFIG, GITHUB_REPOSITORY=REPOSITORY, GITHUB_REPOSITORY_ID=str(REPOSITORY_ID),
                    GITHUB_REF=REF, GITHUB_RUN_ATTEMPT='1', GITHUB_EVENT_NAME='workflow_dispatch',
                    GITHUB_WORKFLOW_REF=REPOSITORY + '/' + WORKFLOW + '@' + REF,
                    GITHUB_WORKFLOW_SHA=run['head_sha'], GITHUB_SHA=run['head_sha'],
                    GITHUB_RUN_ID=str(run['id']))

    def _artifact(self, run, name, filename, limit, directory):
        artifacts = self._get('/actions/runs/' + str(run['id']) + '/artifacts?per_page=100')
        if artifacts.get('total_count', 0) > 100:
            raise LiveReviewBlocked('Unexpected artifact count')
        found = [a for a in artifacts.get('artifacts', []) if a.get('name') == name]
        if not found:
            return None
        if len(found) != 1 or found[0].get('expired') or found[0].get('size_in_bytes', limit*2+1) > limit*2:
            raise LiveReviewBlocked('Invalid artifact metadata')
        # gh handles authenticated API redirects; ZIP members are read without extraction.
        result = self._command(['gh', 'api', '--hostname', 'github.com',
            '/repos/' + REPOSITORY + '/actions/artifacts/' + str(found[0]['id']) + '/zip'])
        if result.returncode:
            return None
        if len(result.stdout) > limit*2:
            raise LiveReviewBlocked('Oversized artifact archive')
        try:
            with zipfile.ZipFile(io.BytesIO(result.stdout)) as archive:
                entries = archive.infolist()
                if (len(entries) != 1 or entries[0].filename != filename
                        or entries[0].file_size > limit or entries[0].flag_bits & 1
                        or stat.S_ISLNK(entries[0].external_attr >> 16)):
                    raise ValueError()
                raw = archive.read(entries[0])
        except Exception:
            raise LiveReviewBlocked('Unsafe artifact archive') from None
        directory.mkdir(mode=0o700, exist_ok=True)
        _private(directory, 0o700, True)
        path = directory / filename
        if not path.exists():
            with path.open('xb') as output:
                os.chmod(path, 0o600)
                output.write(raw)
        elif _private(path, 0o600).read_bytes() != raw:
            raise LiveReviewBlocked('Artifact changed')
        return raw

    def consume_prepared(self, bundle, request, on_review):
        if type(bundle) is not ExecutionBundleV3 or type(request) is not RequestV2 or not callable(on_review):
            raise LiveReviewBlocked('Exact prepared types required')
        if request.plan_hash != bundle.digest:
            raise LiveReviewBlocked('Prepared request mismatch')
        self._environment()
        branch = self._get('/git/ref/heads/' + REF.removeprefix('refs/heads/'))
        if branch.get('object', {}).get('sha') != self.source_sha:
            raise LiveReviewBlocked('Published workflow ref differs from frozen SHA')
        deadline = min(time.time() + 900, parse_stamp(request.expires_at).timestamp())
        if deadline <= time.time():
            raise LiveReviewBlocked('Request expired')
        session = self.root / ('review-' + request.digest())
        session.mkdir(mode=0o700)  # Exclusive: never replay an ambiguous launch.
        payload = canonical(dict(ref=REF.removeprefix('refs/heads/'), inputs=dict(mode='launch',
            public_payload=canonical(dict(request=asdict(request), review=bundle.public_review())))))
        payload_path = session / 'dispatch.json'
        with payload_path.open('x') as output:
            os.chmod(payload_path, 0o600)
            output.write(payload)
        dispatched = datetime.now(timezone.utc).replace(microsecond=0)
        result = self._command(['gh', 'api', '--hostname', 'github.com', '--method', 'POST',
            '/repos/' + REPOSITORY + '/actions/workflows/compose-full-body-review.yml/dispatches',
            '--input', str(payload_path)])
        if result.returncode:
            raise LiveReviewBlocked('Dispatch outcome unknown; do not retry')
        selected = None
        raw = None
        while time.time() < deadline:
            if selected is None:
                listing = self._get('/actions/workflows/compose-full-body-review.yml/runs?event=workflow_dispatch&per_page=100')
                matches = []
                for run in listing.get('workflow_runs', []):
                    if (run.get('head_sha') == self.source_sha and run.get('path') == WORKFLOW
                            and run.get('run_attempt') == 1 and run.get('event') == 'workflow_dispatch'
                            and run.get('actor', {}).get('login') == 'github-actions[bot]'
                            and parse_stamp(run['created_at']) >= dispatched):
                        candidate = self._artifact(run, 'compose-full-body-public-review', 'bundle.json', 65536,
                                                   session / ('public-' + str(run['id'])))
                        if candidate is None:
                            continue
                        try:
                            verified = verify_prepared_review(candidate.decode('ascii'), self._env(run), bundle, request)
                        except ValueError:
                            continue
                        matches.append((run, candidate, verified))
                if len(matches) > 1:
                    raise LiveReviewBlocked('Multiple matching review runs')
                if matches:
                    selected, raw, (_, policy, approval_hash) = matches[0]
                    on_review(dict(url=selected['html_url'], comment='dev-workflow approve ' + approval_hash,
                        operation=request.operation, requestHash=request.digest(), expiresAt=request.expires_at,
                        host=request.host_id, daemon=request.daemon_id, project=request.target.namespace,
                        components=list(request.components), imagechanges=bundle.public_review()['services'],
                        runId=selected['id']))
            if selected is not None:
                run = self._get('/actions/runs/' + str(selected['id']))
                if any(run.get(k) != selected.get(k) for k in ('id', 'head_sha', 'run_attempt', 'event', 'path', 'actor')):
                    raise LiveReviewBlocked('Review run identity changed')
                if run.get('status') == 'completed':
                    raise LiveReviewBlocked('Review run ended before consumption')
                approvals = self._get('/actions/runs/' + str(run['id']) + '/approvals')
                if any(a.get('state') == 'rejected' for a in approvals):
                    raise LiveReviewBlocked('Review rejected')
                cipher = self._artifact(run, 'compose-full-body-sealed-oidc', 'oidc.cms.der', 1048576,
                                        session / 'sealed')
                if cipher is not None:
                    self._environment()
                    _, policy, _ = verify_prepared_review(raw.decode('ascii'), self._env(run), bundle, request)
                    _private(self.key, 0o600)
                    result = self._command(['/usr/bin/openssl', 'cms', '-decrypt', '-inform', 'DER',
                        '-in', str(session / 'sealed/oidc.cms.der'), '-inkey', str(self.key)])
                    token = result.stdout
                    if result.returncode or len(token) > 32768 or not token.isascii() or token.count(b'.') != 2:
                        raise LiveReviewBlocked('Invalid sealed OIDC evidence')
                    approval = self._approval(token.decode('ascii'), request, policy)
                    grant = approval.validate(request)
                    with (session / 'consumption-started').open('x') as marker:
                        os.chmod(marker.name, 0o600)
                    receipt = approval.consume(grant, request)
                    return approval, receipt, dict(runId=run['id'], url=selected['html_url'],
                        requestHash=request.digest(), privateSession=str(session), expiresAt=request.expires_at)
            time.sleep(min(5, max(0, deadline - time.time())))
        raise LiveReviewBlocked('Review expired; private evidence preserved')
