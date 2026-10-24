#!/usr/bin/env python3
"""Distribution-only recorder for a bounded, observed deployment acceptance run."""
from __future__ import annotations

from pathlib import Path
import json
import os
import sys
from types import MappingProxyType
import weakref

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
sys.path.insert(1, str(ROOT / 'packs/release/scripts'))
import deployment_acceptance as acceptance
import deployment_authorize as sdk
import deployment_execute as execution
import deployment_runtime as runtime
import deployment_verify as verification
from deployment_host import DeploymentHostPolicy, GitHubDeploymentApproval
from deployment_recovery_host import GitHubRecoveryApproval
import deployment_recover as recovery
from release_github import GitHubClient
from release_host import verify_oidc


class HostAcceptanceError(ValueError):
    pass


class _Stage:
    __slots__ = ('profile_hash', 'operation', 'request_hash', 'head_sha', 'repository',
                 'target_source_sha', 'status', 'health', 'smoke', 'evidence', '__weakref__')

    def __init__(self, profile_hash, operation, request_hash, result, evidence=None):
        object.__setattr__(self, 'profile_hash', profile_hash)
        object.__setattr__(self, 'operation', operation)
        object.__setattr__(self, 'request_hash', request_hash)
        object.__setattr__(self, 'head_sha', result.get('_acceptance_head_sha'))
        object.__setattr__(self, 'repository', result.get('_acceptance_repository'))
        object.__setattr__(self, 'target_source_sha', result.get('_acceptance_target_source_sha'))
        object.__setattr__(self, 'status', result.get('status'))
        verification = result.get('verification', {})
        object.__setattr__(self, 'health', verification.get('health'))
        object.__setattr__(self, 'smoke', verification.get('smoke'))
        object.__setattr__(self, 'evidence', MappingProxyType(dict(evidence or {})))

    def __setattr__(self, name, value):
        raise AttributeError('immutable host observation')


_ISSUED = weakref.WeakSet()


def _profile_ready(profile):
    if (type(profile) is not acceptance.AcceptanceProfile
            or not acceptance._supported(profile)
            or not acceptance._requirements(profile)):
        raise HostAcceptanceError('acceptance-profile-not-executable')


def _real_sdk(collector, executor):
    if (type(collector) is not runtime.TrustedDockerCollector
            or type(collector.client) is not runtime.DockerTLSClient
            or collector.client._transport is not None
            or collector.client._context is None
            or type(executor) is not execution.DockerExecutor
            or executor.collector is not collector
            or type(executor.client) is not execution.DockerMutationClient
            or executor.client._transport is not None
            or executor.client._context is None
            or type(executor.verifier) is not verification.TrustedProbeVerifier
            or executor.verifier._transport is not None
            or executor.verifier._trusted_transport is not None):
        raise HostAcceptanceError('acceptance-sdk-transport-untrusted')


def _run_attempt():
    raw = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if not raw.isdecimal() or not 1 <= int(raw) <= 1000000:
        raise HostAcceptanceError('github-run-attempt-unavailable')
    return int(raw)


def _evidence(profile, request, policy, observation, result):
    if observation is None or type(observation.evidence_hash) is not str:
        raise HostAcceptanceError('acceptance-observation-missing')
    return dict(profileHash=profile.identity_hash(), operation=request.operation,
                requestHash=request.digest(), repository=request.repository_slug,
                repositoryId=request.repository_id, environment=request.environment,
                target=request.target, component=profile.component,
                runtimePolicyHash=request.runtime_policy_hash,
                executionPolicyHash=profile.execution_policy_hash,
                verificationPolicyHash=profile.verification_policy_hash,
                storePolicyHash=profile.store_policy_hash, gatePolicyHash=profile.gate_policy_hash,
                workflowSha=policy.workflow_sha, workflowRunId=policy.run_id,
                workflowRunAttempt=_run_attempt(), observationHash=observation.evidence_hash,
                result=result.get('status'), health=result.get('health', result.get('verification', {}).get('health')),
                smoke=result.get('smoke', result.get('verification', {}).get('smoke')))


def run_recovery(profile, *, coordinator, request, approval):
    """Observe a directly executed, separately authorized recovery."""
    _profile_ready(profile)
    if (type(profile) is not acceptance.AcceptanceProfile
            or type(coordinator) is not recovery.HostCoordinator
            or type(request) is not recovery.RecoveryRequest
            or type(approval) is not GitHubRecoveryApproval
            or type(approval.client) is not GitHubClient
            or approval.client._transport is not None
            or approval.verifier is not verify_oidc
            or approval.requests != (request,)
            or request.repository_id != profile.repository_id
            or request.environment != profile.environment or request.target != profile.target
            or request.components != (profile.component,)
            or request.runtime_policy_hash != profile.runtime_policy_hash
            or request.execution_policy_hash != profile.execution_policy_hash
            or request.store_policy_hash != profile.store_policy_hash
            or request.gate_policy_hash != profile.gate_policy_hash
            or coordinator.collector.policy.identity_hash() != profile.runtime_policy_hash
            or coordinator.execution_policy.identity_hash() != profile.execution_policy_hash
            or coordinator.store.policy.identity_hash() != profile.store_policy_hash
            or coordinator.gate.policy.identity_hash() != profile.gate_policy_hash):
        raise HostAcceptanceError('recovery-scope-or-authority-mismatch')
    _run_attempt()
    _real_sdk(coordinator.collector, coordinator._executor())
    result = coordinator.recover(request, approval)
    observation = result.get('observation')
    if observation is None:
        raise HostAcceptanceError('recovery-observation-missing')
    coordinator.collector.validate(observation)
    stage = _Stage(profile.identity_hash(), 'deployment-recover', request.digest(),
                   {'status': result.get('status'), 'verification': result,
                    '_acceptance_head_sha': request.head_sha,
                    '_acceptance_repository': request.repository},
                   _evidence(profile, request, approval.policy, observation, result))
    _ISSUED.add(stage)
    return result, stage


def _bound(profile, root, request, collector, executor, intent, policy):
    if (type(profile) is not acceptance.AcceptanceProfile
            or type(request) is not sdk.Request
            or type(collector) is not runtime.TrustedDockerCollector
            or type(executor) is not execution.DockerExecutor
            or type(intent) is not execution.ExecutionIntent
            or type(policy) is not DeploymentHostPolicy
            or executor.collector is not collector
            or collector.policy != executor.policy.runtime_policy
            or executor.verifier is None
            or executor.verifier.policy.identity_hash() != profile.verification_policy_hash
            or request.runtime_policy_hash != profile.runtime_policy_hash
            or collector.policy.identity_hash() != profile.runtime_policy_hash
            or executor.policy.identity_hash() != profile.execution_policy_hash
            or executor.policy.history_policy_hash != profile.store_policy_hash
            or executor.policy.gateway_policy_hash != profile.gate_policy_hash
            or executor.coordinator is None
            or executor.coordinator.store.policy.identity_hash() != profile.store_policy_hash
            or executor.coordinator.gate.policy.identity_hash() != profile.gate_policy_hash
            or request.repository_id != profile.repository_id
            or request.environment != profile.environment or request.target != profile.target
            or request.components != (profile.component,)
            or policy.target_repository_id != profile.repository_id
            or policy.deployment_environment != profile.environment
            or policy.deployment_target != profile.target
            or policy.runtime_policy_hash != profile.runtime_policy_hash
            or policy.execution_policy_hash != profile.execution_policy_hash
            or Path(root).resolve() != Path(request.repository).resolve()):
        raise HostAcceptanceError('acceptance-scope-mismatch')


def run_stage(profile, *, root, plan, request, collector, observation, executor, intent,
              rollback_target=None, host_policy, github_token, oidc_token, host_operation=None):
    """Execute one exact, approved SDK stage; return result and opaque observation."""
    _profile_ready(profile)
    _bound(profile, root, request, collector, executor, intent, host_policy)
    _real_sdk(collector, executor)
    if (request.operation not in ('deployment-deploy', 'deployment-rollback')
            or type(github_token) is not str or not github_token
            or type(oidc_token) is not str or not oidc_token):
        raise HostAcceptanceError('acceptance-authority-unavailable')
    _run_attempt()
    client = GitHubClient(github_token)
    if type(client) is not GitHubClient or client._transport is not None:
        raise HostAcceptanceError('acceptance-client-untrusted')
    approval = GitHubDeploymentApproval(client, oidc_token, [request], host_policy)
    if approval.verifier is not verify_oidc:
        raise HostAcceptanceError('acceptance-verifier-untrusted')
    permit = sdk.authorize(root, plan, request, collector=collector, observation=observation,
                           approval=approval, rollback_target=rollback_target,
                           execution_intent=intent, host_operation=host_operation)
    result = executor.execute(root, permit, intent, host_operation=host_operation)
    desired = json.loads(request.after_json)['components']
    target = next((item for item in desired if item['name'] == profile.component), None)
    if target is None or type(target.get('sourceSha')) is not str:
        raise HostAcceptanceError('acceptance-target-unbound')
    stage = _Stage(profile.identity_hash(), request.operation, request.digest(),
                   dict(result, _acceptance_head_sha=request.head_sha,
                        _acceptance_repository=request.repository,
                        _acceptance_target_source_sha=target['sourceSha']),
                   _evidence(profile, request, host_policy, result.get('observation'), result))
    _ISSUED.add(stage)
    return result, stage


def assess_run(profile, deploy_stage, rollback_stage, *, recovery_stage=None):
    """Assess only stages issued in this process. Exports never restore trust."""
    if (type(profile) is not acceptance.AcceptanceProfile
            or type(deploy_stage) is not _Stage or deploy_stage not in _ISSUED
            or type(rollback_stage) is not _Stage or rollback_stage not in _ISSUED
            or deploy_stage.profile_hash != profile.identity_hash()
            or rollback_stage.profile_hash != profile.identity_hash()
            or deploy_stage.operation != 'deployment-deploy'
            or rollback_stage.operation != 'deployment-rollback'
            or deploy_stage.request_hash == rollback_stage.request_hash
            or deploy_stage.repository != rollback_stage.repository
            or deploy_stage.head_sha != rollback_stage.head_sha
            or any(deploy_stage.evidence.get(key) != rollback_stage.evidence.get(key)
                   for key in ('workflowSha', 'workflowRunId', 'workflowRunAttempt'))
            or rollback_stage.target_source_sha != profile.rollback_ref
            or deploy_stage.target_source_sha == profile.rollback_ref):
        raise HostAcceptanceError('acceptance-observation-untrusted')
    if recovery_stage is not None and (type(recovery_stage) is not _Stage
            or recovery_stage not in _ISSUED
            or recovery_stage.profile_hash != profile.identity_hash()
            or recovery_stage.operation != 'deployment-recover'
            or recovery_stage.repository != deploy_stage.repository
            or recovery_stage.head_sha != deploy_stage.head_sha
            or any(recovery_stage.evidence.get(key) != deploy_stage.evidence.get(key)
                   for key in ('workflowSha', 'workflowRunId', 'workflowRunAttempt'))
            or recovery_stage.request_hash in (deploy_stage.request_hash, rollback_stage.request_hash)):
        raise HostAcceptanceError('recovery-observation-untrusted')
    def good(stage):
        return stage.status == 'executed-verified' and stage.health == stage.smoke == 'passed'
    deployment, rollback = good(deploy_stage), good(rollback_stage)
    recovered = (recovery_stage is not None
                 and recovery_stage.status == 'recovered-runtime-verified'
                 and recovery_stage.health == recovery_stage.smoke == 'passed')
    observations = dict(approval='passed' if deployment and rollback else 'unknown',
                        deployment='passed' if deployment else 'blocked',
                        health='passed' if deployment and rollback else 'blocked',
                        smoke='passed' if deployment and rollback else 'blocked',
                        rollback='passed' if rollback else 'blocked',
                        recovery='passed' if recovered else 'unknown')
    report = acceptance._assess_trusted(profile, observations)
    report['evidenceRefs'] = {name: dict(stage.evidence) for name, stage in
                              (('recovery', recovery_stage), ('deployment', deploy_stage),
                               ('rollback', rollback_stage)) if stage is not None}
    return report
