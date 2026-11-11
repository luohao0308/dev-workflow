"""Distribution-only GitLab tag preflight; observations confer no authority.

Load this module and dependencies from a pinned trusted checkout. The embedding
host supplies the expected identity independently of candidate intent. No CLI,
credential discovery, grant issuance, or mutation entry point is provided.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.parse import quote

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/release/scripts'))
from release_contract_v2 import ProviderIdentity
from release_execute import ExecutionError, IdentityConflict, canonical
from release_gitlab import GitLabClient
from release_gitlab_plan import build_intent

DOMAIN = b'dev-workflow:gitlab-read-preflight:v1\0'


class GitLabPreflightHost:
    """Bounded GET-only observation of one host-fixed project/source identity.

    Two matching reads detect observed drift, not concurrent changes between or
    after reads. The returned digest is evidence, never an execution capability.
    """

    def __init__(self, *, client: GitLabClient, expected_identity: ProviderIdentity,
                 repository: Path, remote: str, maximum_seconds: int = 60):
        if (type(client) is not GitLabClient or type(expected_identity) is not ProviderIdentity
                or expected_identity.provider_id != 'gitlab.com'
                or type(maximum_seconds) is not int or not 0 < maximum_seconds <= 60):
            raise ExecutionError('Invalid trusted GitLab preflight configuration')
        self.client = client
        self.identity = expected_identity
        self.repository = repository.resolve()
        self.remote = remote
        self.maximum_seconds = maximum_seconds

    def observe(self, intent: dict, *, operation: str = 'remote-tag-push') -> dict:
        if operation != 'remote-tag-push':
            raise ExecutionError('Unsupported GitLab preflight operation')
        # Copy before local validation or network reads; candidate mutation cannot
        # change what this observation commits to.
        try:
            supplied = json.loads(canonical(intent))
            if not isinstance(supplied, dict):
                raise ValueError('intent')
            prepared = supplied['preparation']
            rebuilt = build_intent(self.repository, prepared, remote=self.remote,
                                   project_id=self.identity.project_id)
            if (canonical(supplied) != canonical(rebuilt) or rebuilt['remote']['url'] != self.identity.origin
                    or rebuilt['remote']['project'] != self.identity.project_path
                    or rebuilt['tag']['targetSha'] != self.identity.source_sha):
                raise ValueError('identity')
        except (KeyError, TypeError, ValueError):
            raise IdentityConflict('GitLab intent differs from host-fixed identity or local preparation') from None
        base = '/projects/' + str(self.identity.project_id)
        started = time.monotonic()

        def get(path, *, missing=False):
            if time.monotonic() - started >= self.maximum_seconds:
                raise ExecutionError('GitLab preflight observation exceeded its time bound')
            value = self.client.request('GET', path, allow_missing=missing)
            if time.monotonic() - started >= self.maximum_seconds:
                raise ExecutionError('GitLab preflight observation exceeded its time bound')
            return value

        def snapshot():
            project = get(base)
            if (not isinstance(project, dict) or type(project.get('id')) is not int
                    or project['id'] != self.identity.project_id
                    or project.get('path_with_namespace') != self.identity.project_path):
                raise IdentityConflict('GitLab project identity differs from host configuration')
            commit = get(base + '/repository/commits/' + self.identity.source_sha, missing=True)
            if not isinstance(commit, dict) or commit.get('id') != self.identity.source_sha:
                raise IdentityConflict('Host-fixed source is unavailable in GitLab project')
            tag = get(base + '/repository/tags/' + quote(rebuilt['tag']['name'], safe=''), missing=True)
            if tag is not None:
                if (not isinstance(tag, dict) or tag.get('name') != rebuilt['tag']['name']
                        or tag.get('message', object()) is not None
                        or tag.get('target') != self.identity.source_sha
                        or not isinstance(tag.get('commit'), dict)
                        or tag['commit'].get('id') != self.identity.source_sha):
                    raise IdentityConflict('GitLab tag conflicts with expected lightweight source tag')
            return {'projectId': project['id'], 'projectPath': project['path_with_namespace'],
                    'sourceSha': commit['id'], 'tagStatus': 'missing' if tag is None else 'matching'}

        first = snapshot()
        if snapshot() != first:
            raise IdentityConflict('GitLab state changed across preflight reads')
        context = {'schemaVersion': 1, 'kind': 'gitlab-read-preflight', 'operation': operation,
                   'identity': asdict(self.identity),
                   'intentDigest': hashlib.sha256(canonical(rebuilt).encode('ascii')).hexdigest(),
                   'tag': rebuilt['tag']['name'], 'observation': first,
                   'authorityGranted': False, 'executionAvailable': False}
        return {'context': context, 'digest': hashlib.sha256(
            DOMAIN + canonical(context).encode('ascii')).hexdigest()}
