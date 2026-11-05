#!/usr/bin/env python3
"""Distribution-only, GitHub protected-review authorization for Compose requests.

This module authenticates and consumes a reviewed intent. Its evidence is not an
execution permit; runtime observation and mutation remain separate host duties.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys
import time

sys.dont_write_bytecode = True
DISTRIBUTION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DISTRIBUTION / 'packs/deployment/scripts'))
sys.path.insert(1, str(DISTRIBUTION / 'packs/release/scripts'))
from deployment_contract_v2 import RequestV2, TargetIdentity
from release_host import GitHubActionsApproval, HostPolicy, _deny, timestamp

AUDIENCE = 'dev-workflow-compose-approval-host'
PROFILE = 'compose-application-batch-v1'
HASH = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class ComposeAuthorizationEvidence:
    grant_id: str
    request_hash: str
    expires_at: str
    max_uses: int


@dataclass(frozen=True)
class ComposeConsumptionEvidence:
    grant_id: str
    request_hash: str
    use_number: int
    consumed_at: str


@dataclass(frozen=True, kw_only=True)
class ComposeApprovalPolicy(HostPolicy):
    approval_environment: str
    operation: str
    profile_version: str
    source_sha: str
    target: TargetIdentity
    deployment_environment: str
    production: bool
    daemon_id: str
    host_id: str
    components: tuple[str, ...]
    protected_components: tuple[str, ...]
    policy_hash: str

    def __post_init__(self):
        super().__post_init__()
        if (not isinstance(self.approval_environment, str)
                or not re.fullmatch(r'[A-Za-z0-9_-]+', self.approval_environment)
                or self.operation not in ('deploy', 'rollback')
                or self.profile_version != '1'
                or not isinstance(self.target, TargetIdentity)
                or self.target.runtime != 'compose'
                or not isinstance(self.source_sha, str)
                or not re.fullmatch(r'[0-9a-f]{40}', self.source_sha)
                or not isinstance(self.deployment_environment, str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', self.deployment_environment)
                or type(self.production) is not bool
                or not isinstance(self.daemon_id, str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}', self.daemon_id)
                or not isinstance(self.host_id, str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', self.host_id)
                or type(self.components) is not tuple or not self.components
                or type(self.protected_components) is not tuple
                or any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', v)
                       for v in self.components + self.protected_components)
                or tuple(sorted(set(self.components))) != self.components
                or tuple(sorted(set(self.protected_components))) != self.protected_components
                or set(self.components) & set(self.protected_components)
                or not isinstance(self.policy_hash, str) or not HASH.fullmatch(self.policy_hash)):
            _deny('Invalid trusted Compose approval policy')


class GitHubComposeApproval(GitHubActionsApproval):
    request_type = RequestV2
    operations = frozenset(('deploy', 'rollback'))
    audience = AUDIENCE
    grant_type = ComposeAuthorizationEvidence
    receipt_type = ComposeConsumptionEvidence
    ledger_namespace = 'workflow-compose-authorization-v2'
    grant_namespace = 'github-compose-authorization-v2'

    def __init__(self, client, oidc_token, requests, policy, *, verifier=None):
        if type(policy) is not ComposeApprovalPolicy:
            _deny('Explicit Compose approval policy required')
        super().__init__(client, oidc_token, requests, policy, verifier=verifier)

    def _approval_environment(self):
        return self.policy.approval_environment

    def _match(self, request):
        if type(request) is not RequestV2 or self._requests.get(request.digest()) != request:
            _deny('Compose operation differs from reviewed request')
        p = self.policy
        if (request.operation != p.operation or request.profile_id != PROFILE
                or request.profile_version != p.profile_version
                or request.source.provider_id != 'github.com'
                or request.source.origin != 'https://github.com/' + p.target_repository + '.git'
                or request.source.project_path != p.target_repository
                or request.source.project_id != p.target_repository_id
                or request.source.source_sha != p.source_sha
                or request.target != p.target
                or request.environment != p.deployment_environment
                or request.production is not p.production
                or request.daemon_id != p.daemon_id or request.host_id != p.host_id
                or request.components != p.components
                or request.protected_components != p.protected_components
                or request.policy_hash != p.policy_hash or request.max_uses != 1):
            _deny('Compose approval scope differs from trusted host policy')
        now = time.time()
        expiry = timestamp(request.expires_at).timestamp()
        if not now < expiry <= now + 3600:
            _deny('Compose request expired or exceeds one hour')

    def _check_authority(self):
        for request in self.requests:
            self._match(request)
        super()._check_authority()
        for request in self.requests:
            self._match(request)

    def _grant_expiry(self, request):
        return min(self._expires, timestamp(request.expires_at).timestamp())

    def guard(self, request):
        """No execution guard is exposed by this authorization-only foundation."""
        _deny('Compose approval evidence is not an execution permit')
