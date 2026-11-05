#!/usr/bin/env python3
"""Profile 4 full-body Compose intent approval; never runtime admission.

This module authenticates and consumes a reviewed intent. Its evidence is not an
execution permit; runtime observation and mutation remain separate host duties.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import json
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

AUDIENCE = 'dev-workflow-compose-full-body-v4-host'
PROFILE = 'compose-application-batch-v1'
HASH = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class FullBodyAuthorizationEvidenceV4:
    grant_id: str
    request_hash: str
    expires_at: str
    max_uses: int


@dataclass(frozen=True)
class FullBodyConsumptionEvidenceV4:
    grant_id: str
    request_hash: str
    use_number: int
    consumed_at: str


@dataclass(frozen=True, kw_only=True)
class FullBodyApprovalPolicyV4(HostPolicy):
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
    bundle_hash: str
    session_hash: str
    context_digest: str
    actor_epoch: str
    scope_ordinal: int
    plan_write_index: int
    action_digest: str
    expected_observation_hash: str
    expected_history_hash: str | None = None

    def __post_init__(self):
        super().__post_init__()
        if (not isinstance(self.approval_environment, str)
                or not re.fullmatch(r'[A-Za-z0-9_-]+', self.approval_environment)
                or self.operation not in ('deploy', 'recovery')
                or self.profile_version != '4'
                or not isinstance(self.target, TargetIdentity)
                or self.target.runtime != 'compose'
                or not re.fullmatch(r'dw-[A-Za-z0-9][A-Za-z0-9._-]{0,124}', self.target.namespace)
                or not isinstance(self.source_sha, str)
                or not re.fullmatch(r'[0-9a-f]{40}', self.source_sha)
                or not isinstance(self.deployment_environment, str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', self.deployment_environment)
                or self.production is not False
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
                or not isinstance(self.policy_hash, str) or not HASH.fullmatch(self.policy_hash)
                or not isinstance(self.bundle_hash, str) or not HASH.fullmatch(self.bundle_hash)
                or any(type(v) is not str or not HASH.fullmatch(v) for v in (self.session_hash,self.context_digest,self.actor_epoch,self.action_digest))
                or any(type(v) is not int or not 0 <= v < 32 for v in (self.scope_ordinal,self.plan_write_index))
                or self.context_digest != self.expected_observation_hash
                or type(self.expected_observation_hash) is not str or not HASH.fullmatch(self.expected_observation_hash)
                or (self.expected_history_hash is not None
                    and (not isinstance(self.expected_history_hash, str)
                         or not HASH.fullmatch(self.expected_history_hash)))
                or (self.operation == 'deploy' and self.expected_history_hash is not None)
                or (self.operation in ('recovery',) and self.expected_history_hash is None)):
            _deny('Invalid trusted Compose approval policy')


class GitHubFullBodyApprovalV4(GitHubActionsApproval):
    request_type = RequestV2
    operations = frozenset(('deploy', 'recovery'))
    audience = AUDIENCE
    grant_type = FullBodyAuthorizationEvidenceV4
    receipt_type = FullBodyConsumptionEvidenceV4
    ledger_namespace = 'workflow-compose-full-body-authorization-v4'
    grant_namespace = 'github-compose-full-body-authorization-v4'

    def __init__(self, client, oidc_token, requests, policy, *, verifier=None):
        if type(policy) is not FullBodyApprovalPolicyV4:
            _deny('Explicit Compose approval policy required')
        self._receipts = {}
        super().__init__(client, oidc_token, requests, policy, verifier=verifier)

    def _approval_environment(self):
        return self.policy.approval_environment

    def _match(self, request):
        if type(request) is not RequestV2 or self._requests.get(request.digest()) != request:
            _deny('Compose operation differs from reviewed request')
        p = self.policy
        if (request.operation != p.operation or request.profile_id != (PROFILE if p.operation == 'deploy' else 'compose-recovery-v4')
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
                or request.policy_hash != p.policy_hash or request.max_uses != 1
                or request.plan_hash != p.bundle_hash
                or request.observation_hash != p.expected_observation_hash
                or request.history_hash != p.expected_history_hash):
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
        _deny('Full-body approval intent has no runtimePermit')

    def check_consumed_intent(self, request):
        """Recheck live consent and consumed ledger only; never admit execution."""
        try:
            return GitHubActionsApproval.guard(self, request)
        except Exception:
            _deny('V4 consumed intent authority or ledger unavailable')

    def consume(self, grant, request, *, before_consume=None):
        receipt = super().consume(grant, request, before_consume=before_consume)
        material = json.dumps(asdict(receipt),sort_keys=True,separators=(',',':')).encode('ascii')
        self._receipts[id(receipt)] = (receipt, request.digest(), material)
        return receipt

    def receipt_hash(self, receipt, request):
        self._match(request)
        record = self._receipts.get(id(receipt))
        if (type(receipt) is not FullBodyConsumptionEvidenceV4 or record is None
                or record[0] is not receipt or record[1] != request.digest()
                or record[2] != json.dumps(asdict(receipt),sort_keys=True,separators=(',',':')).encode('ascii')):
            _deny('Registered V4 consumption receipt required')
        return hashlib.sha256(b'dev-workflow:compose-consumption-receipt:v4\0'+record[2]).hexdigest()
