#!/usr/bin/env python3
"""Profile 3 full-body Compose intent approval; never runtime admission.

This module authenticates and consumes a reviewed intent. Its evidence is not an
execution permit; runtime observation and mutation remain separate host duties.
"""
from __future__ import annotations

from dataclasses import dataclass
import importlib.util
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

AUDIENCE = 'dev-workflow-compose-full-body-v3-host'
PROFILE = 'compose-application-batch-v1'
SCENE_RECOVERY_PROFILE = 'compose-scene-recovery-intent-v3'
HASH = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class FullBodyAuthorizationEvidenceV3:
    grant_id: str
    request_hash: str
    expires_at: str
    max_uses: int


@dataclass(frozen=True)
class FullBodyConsumptionEvidenceV3:
    grant_id: str
    request_hash: str
    use_number: int
    consumed_at: str


@dataclass(frozen=True, kw_only=True)
class FullBodyApprovalPolicyV3(HostPolicy):
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
    expected_history_hash: str | None = None

    def __post_init__(self):
        super().__post_init__()
        if (not isinstance(self.approval_environment, str)
                or not re.fullmatch(r'[A-Za-z0-9_-]+', self.approval_environment)
                or self.operation not in ('deploy', 'rollback', 'recovery')
                or self.profile_version != '3'
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
                or (self.expected_history_hash is not None
                    and (not isinstance(self.expected_history_hash, str)
                         or not HASH.fullmatch(self.expected_history_hash)))
                or (self.operation == 'deploy' and self.expected_history_hash is not None)
                or (self.operation in ('rollback', 'recovery') and self.expected_history_hash is None)):
            _deny('Invalid trusted Compose approval policy')


class GitHubFullBodyApprovalV3(GitHubActionsApproval):
    profile_id = PROFILE
    policy_type = FullBodyApprovalPolicyV3
    request_type = RequestV2
    operations = frozenset(('deploy', 'rollback', 'recovery'))
    audience = AUDIENCE
    grant_type = FullBodyAuthorizationEvidenceV3
    receipt_type = FullBodyConsumptionEvidenceV3
    ledger_namespace = 'workflow-compose-full-body-authorization-v3'
    grant_namespace = 'github-compose-full-body-authorization-v3'

    def __init__(self, client, oidc_token, requests, policy, *, verifier=None):
        if type(policy) is not self.policy_type:
            _deny('Explicit Compose approval policy required')
        super().__init__(client, oidc_token, requests, policy, verifier=verifier)

    def _approval_environment(self):
        return self.policy.approval_environment

    def _prefetch_authority(self):
        # Only this distribution's exact live client opts into parallel reads.
        # Fake clients and other protocol versions keep the base read sequence.
        if type(self) not in (GitHubFullBodyApprovalV3, GitHubSceneRecoveryApprovalV3):
            return None
        name = 'deployment_compose_live_review_v3_host'
        path = DISTRIBUTION / 'scripts/deployment_compose_live_review_v3_host.py'
        module = sys.modules.get(name)
        if module is None:
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
        if Path(getattr(module, '__file__', '')).resolve() != path:
            _deny('Live approval client must come from trusted distribution')
        if type(self.client) is not module._ReadRetryGitHubClient:
            return None
        result = self.client.fetch_authority_reads(self._authority_queries())
        if result is None:
            _deny('Invalid GitHub authority batch')
        return result

    def _match(self, request):
        if type(request) is not RequestV2 or self._requests.get(request.digest()) != request:
            _deny('Compose operation differs from reviewed request')
        p = self.policy
        if (request.operation != p.operation or request.profile_id != self.profile_id
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
                or (p.expected_history_hash is not None and request.history_hash != p.expected_history_hash)):
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
        return GitHubActionsApproval.guard(self, request)


@dataclass(frozen=True, kw_only=True)
class SceneRecoveryApprovalPolicyV3(FullBodyApprovalPolicyV3):
    expected_observation_hash: str
    expected_scene_review_hash: str

    def __post_init__(self):
        super().__post_init__()
        if (self.operation != 'recovery' or len(self.components) != 1
                or any(type(value) is not str or not HASH.fullmatch(value) for value in
                       (self.expected_observation_hash, self.expected_scene_review_hash))):
            _deny('Invalid trusted scene recovery approval policy')


class GitHubSceneRecoveryApprovalV3(GitHubFullBodyApprovalV3):
    profile_id = SCENE_RECOVERY_PROFILE
    policy_type = SceneRecoveryApprovalPolicyV3
    operations = frozenset(('recovery',))
    ledger_namespace = 'workflow-compose-scene-recovery-v3'
    grant_namespace = 'github-compose-scene-recovery-v3'

    def _match(self, request):
        super()._match(request)
        if request.observation_hash != self.policy.expected_observation_hash:
            _deny('Scene recovery context differs from trusted host policy')

    def _ledger_marker(self, request):
        # A second approved run for the same immutable request shares this ref.
        return 'tags/' + self.ledger_namespace + '/' + request.digest()

    def consume(self, grant, request, *, before_consume=None):
        receipt = super().consume(grant, request, before_consume=before_consume)
        self._scene_receipt = receipt
        return receipt

    def verify_consumption_receipt(self, request, receipt):
        if (type(receipt) is not FullBodyConsumptionEvidenceV3
                or receipt is not getattr(self, '_scene_receipt', None)
                or receipt.request_hash != request.digest()):
            _deny('Original scene recovery consumption receipt required')
        self.check_consumed_intent(request)
