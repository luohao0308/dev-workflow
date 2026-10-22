#!/usr/bin/env python3
"""Distribution-only deployment approval host from a pinned trusted checkout.

Run trusted embeddings with python3 -I. These fixed distribution imports are
never selected by candidate configuration; the installed deployment pack does
not import the installed release pack. Runtime collection and candidate checks
belong to the deployment SDK, not this GitHub authority adapter.
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
sys.path.insert(2, str(DISTRIBUTION / 'core/scripts'))
import deployment_authorize as execution
from release_host import GitHubActionsApproval, HostPolicy, _deny, timestamp
from release_execute import ExecutionError
from workflow_config import portable_identifier

AUDIENCE = 'dev-workflow-deployment-host'


@dataclass(frozen=True, kw_only=True)
class DeploymentHostPolicy(HostPolicy):
    # environment inherited above is the signed OIDC caller environment. This
    # explicit second environment is where the protected human review occurs.
    deployment_environment: str
    deployment_target: str
    production: bool
    runtime_policy_hash: str
    allowed_components: tuple[str, ...]
    approval_environment: str
    execution_policy_hash: str | None = None

    def __post_init__(self):
        super().__post_init__()
        if not all(portable_identifier(value) for value in (self.deployment_environment, self.deployment_target)):
            _deny('Invalid trusted deployment scope')
        if not isinstance(self.approval_environment, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', self.approval_environment):
            _deny('Invalid trusted approval environment')
        if type(self.production) is not bool:
            _deny('Invalid trusted deployment production policy')
        if not isinstance(self.runtime_policy_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', self.runtime_policy_hash):
            _deny('Invalid trusted runtime policy hash')
        if (self.execution_policy_hash is not None
                and (not isinstance(self.execution_policy_hash, str)
                     or not re.fullmatch(r'[0-9a-f]{64}', self.execution_policy_hash))):
            _deny('Invalid trusted execution policy hash')
        if (type(self.allowed_components) is not tuple or not self.allowed_components
                or any(not portable_identifier(value) for value in self.allowed_components)
                or len(set(self.allowed_components)) != len(self.allowed_components)):
            _deny('Invalid trusted deployment component policy')


class GitHubDeploymentApproval(GitHubActionsApproval):
    request_type = execution.Request
    operations = execution.OPERATIONS
    audience = AUDIENCE
    grant_type = execution.Grant
    receipt_type = execution.Receipt
    ledger_namespace = 'workflow-deployment-grants'
    grant_namespace = 'github-deployment'

    def __init__(self, client, oidc_token, requests, policy, *, verifier=None):
        if type(policy) is not DeploymentHostPolicy:
            _deny('Deployment host requires explicit deployment policy')
        super().__init__(client, oidc_token, requests, policy, verifier=verifier)

    def _approval_environment(self):
        return self.policy.approval_environment

    def _match(self, request):
        if type(request) is not self.request_type or self._requests.get(request.digest()) != request:
            _deny('Operation differs from reviewed deployment bundle')
        policy = self.policy
        if (request.repository_slug != policy.target_repository
                or type(request.repository_id) is not int or request.repository_id != policy.target_repository_id
                or request.environment != policy.deployment_environment
                or request.target != policy.deployment_target
                or type(request.production) is not bool or request.production is not policy.production
                or request.runtime_policy_hash != policy.runtime_policy_hash):
            _deny('Reviewed deployment scope differs from host policy')
        if (type(request.components) is not tuple or not request.components
                or any(type(value) is not str for value in request.components)
                or len(set(request.components)) != len(request.components)
                or not set(request.components).issubset(policy.allowed_components)):
            _deny('Reviewed deployment components differ from host policy')
        if type(request.max_uses) is not int or request.max_uses != 1:
            _deny('Deployment authorization requires exactly one use')
        if request.execution_json is not None:
            import json
            binding = json.loads(request.execution_json)
            if (policy.execution_policy_hash is None
                    or binding.get('profile') != 'docker-container-replace-v1'
                    or binding.get('policyHash') != policy.execution_policy_hash
                    or len(request.components) != 1
                    or binding.get('component') != request.components[0]):
                _deny('Execution request differs from trusted executor policy')
        try:
            expires = timestamp(request.expires_at).timestamp()
        except (TypeError, ValueError, ExecutionError):
            _deny('Invalid deployment request expiry')
        now = time.time()
        if expires <= now or expires > now + 3600:
            _deny('Deployment request expired or lifetime exceeds one hour')

    def _check_authority(self):
        # Scope is frozen and checked before any API access, and again after
        # potentially slow authority reads, including immediately before CAS.
        for request in self.requests:
            self._match(request)
        super()._check_authority()
        for request in self.requests:
            self._match(request)

    def _grant_expiry(self, request):
        return min(self._expires, timestamp(request.expires_at).timestamp())
