#!/usr/bin/env python3
"""Distribution-only GitHub authority for the separate recovery domain."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys
import time

sys.dont_write_bytecode = True
DISTRIBUTION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DISTRIBUTION / 'scripts'))
import deployment_host as deployment
import deployment_recover as recovery
from release_host import GitHubActionsApproval, _deny, timestamp

AUDIENCE = 'dev-workflow-deployment-recovery-host'


@dataclass(frozen=True, kw_only=True)
class RecoveryHostPolicy(deployment.DeploymentHostPolicy):
    store_policy_hash: str
    gate_policy_hash: str

    def __post_init__(self):
        super().__post_init__()
        if any(type(v) is not str or not re.fullmatch(r'[0-9a-f]{64}', v)
               for v in (self.store_policy_hash, self.gate_policy_hash, self.execution_policy_hash)):
            _deny('Recovery requires explicit store, gate and execution policy hashes')


class GitHubRecoveryApproval(GitHubActionsApproval):
    request_type = recovery.RecoveryRequest
    operations = frozenset(('deployment-recover',))
    audience = AUDIENCE
    grant_type = recovery.RecoveryGrant
    receipt_type = recovery.RecoveryReceipt
    ledger_namespace = 'workflow-recovery-grants'
    grant_namespace = 'github-recovery'

    def __init__(self, client, oidc_token, requests, policy, *, verifier=None):
        if type(policy) is not RecoveryHostPolicy:
            _deny('Explicit recovery host policy required')
        super().__init__(client, oidc_token, requests, policy, verifier=verifier)

    def _approval_environment(self):
        return self.policy.approval_environment

    def _match(self, request):
        if type(request) is not recovery.RecoveryRequest or self._requests.get(request.digest()) != request:
            _deny('Recovery differs from reviewed request')
        p = self.policy
        if (request.operation != 'deployment-recover'
                or request.repository_slug != p.target_repository
                or type(request.repository_id) is not int or request.repository_id != p.target_repository_id
                or request.environment != p.deployment_environment or request.target != p.deployment_target
                or type(request.production) is not bool or request.production is not p.production
                or request.runtime_policy_hash != p.runtime_policy_hash
                or request.execution_policy_hash != p.execution_policy_hash
                or request.store_policy_hash != p.store_policy_hash or request.gate_policy_hash != p.gate_policy_hash
                or type(request.components) is not tuple or len(request.components) != 1
                or not set(request.components).issubset(p.allowed_components)
                or type(request.max_uses) is not int or request.max_uses != 1):
            _deny('Recovery scope differs from trusted host policy')
        expires = timestamp(request.expires_at).timestamp()
        now = time.time()
        if not now < expires <= now + 3600:
            _deny('Recovery request expired or exceeds one hour')

    def _check_authority(self):
        for request in self.requests:
            self._match(request)
        super()._check_authority()
        for request in self.requests:
            self._match(request)

    def _grant_expiry(self, request):
        return min(self._expires, timestamp(request.expires_at).timestamp())
