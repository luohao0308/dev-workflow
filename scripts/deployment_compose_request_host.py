"""Host-only deploy intent recomputation; deliberately no execution permit.

All constructor inputs must be provisioned by the host, never loaded from a
project request. Safety attestations bind authenticated report assertions; actual
report producers, recovery history and writer authority remain separate gates.
Rollback/recovery are rejected until history is wired.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from deployment_compose_proof_host import ComposeProofHost, canonical
from deployment_compose_recovery_host import ComposeRecoveryHost
from deployment_compose_approval_host import ComposeApprovalPolicy, PROFILE
from deployment_compose_observation_host import ComposeObservationHost
from deployment_compose_operations import compile_operations
from deployment_compose_target_prepare import verify_target_recipes
from deployment_contract_v2 import RequestV2, SourceIdentity


class ComposeRequestHost:
    def __init__(self, *, policy, observer, candidate, baseline, target, recipes,
                 recipe_keys, dependencies, proof_host, recovery_host=None, recovery_reference=None):
        if (type(policy) is not ComposeApprovalPolicy or policy.operation != 'deploy'
                or type(observer) is not ComposeObservationHost):
            raise ValueError('deploy-host-policy-required')
        if type(proof_host) is not ComposeProofHost:
            raise ValueError('proof-host-required')
        if ((recovery_host is None) != (recovery_reference is None)
                or (recovery_host is not None and type(recovery_host) is not ComposeRecoveryHost)):
            raise ValueError('invalid-recovery-host')
        self._recovery_host, self._recovery_reference = recovery_host, recovery_reference
        self._proof_host = proof_host
        scope = observer._policy
        if (scope.get('project') != policy.target.namespace
                or scope.get('daemonId') != policy.daemon_id
                or tuple(scope.get('selectedServices', ())) != policy.components
                or tuple(scope.get('protectedServices', ())) != policy.protected_components):
            raise ValueError('observation-host-scope-mismatch')
        if (type(baseline) is not tuple
                or scope.get('selectedContainerIds') != {x.service: x.container_id for x in baseline}
                or tuple(x.service for x in baseline) != policy.components):
            raise ValueError('baseline-container-scope-mismatch')
        # Inputs are captured, so mutation of caller-owned dictionaries cannot
        # change what a later reviewed digest means.
        self._policy, self._observer = policy, observer
        self._candidate, self._baseline = deepcopy(candidate), baseline
        self._target, self._recipes = target, deepcopy(recipes)
        self._keys, self._dependencies = dict(recipe_keys), deepcopy(dependencies)

    def prepare_intent(self, observation, *, operation_nonce, expires_at):
        """Build unsigned-report intent for attestors; not the final review request."""
        p, host = self._policy, self._observer
        observation_hash = host.commitment(observation)
        old = host._baseline_artifacts
        plan = compile_operations(self._candidate, self._baseline, old, self._target,
                                  operation_nonce, self._dependencies, observation_hash)
        if (plan.selected_services != p.components or plan.protected_services != p.protected_components
                or plan.unverified_constraints):
            raise ValueError('unverified-operation-scope')
        if any(host._policy.get('containerNames', {}).get(item.service) != item.final_name
               for item in self._baseline):
            raise ValueError('baseline-name-scope-mismatch')
        request = RequestV2(2, 'deploy', PROFILE, p.profile_version,
            SourceIdentity('github.com', 'https://github.com/' + p.target_repository + '.git',
                           p.target_repository_id, p.target_repository, p.source_sha),
            p.target, p.deployment_environment, p.production, p.daemon_id,
            p.components, p.protected_components, old.digest(), self._target.digest(),
            self._target.digest(), observation_hash, None, p.host_id, plan.plan_hash,
            p.policy_hash, expires_at, 1)
        request.ensure_fresh(datetime.now(timezone.utc))
        verify_target_recipes(request, self._target, self._recipes,
                              container_names={x.service: x.final_name for x in self._baseline},
                              keys=self._keys)
        # Catch drift or expiry during recipe verification and compilation.
        if host.commitment(observation) != observation_hash:
            raise ValueError('observation-changed')
        request.ensure_fresh(datetime.now(timezone.utc))
        return request

    def verify_intent(self, request, observation, *, operation_nonce):
        """Compare preliminary intent only; does not verify safety reports."""
        if type(request) is not RequestV2:
            raise ValueError('exact-request-required')
        expected = self.prepare_intent(observation, operation_nonce=operation_nonce,
                                expires_at=request.expires_at)
        if request != expected:
            raise ValueError('request-differs-from-host-evidence')

    def prepare(self, observation, *, operation_nonce, expires_at, proofs):
        """Bind authenticated reports to a final review request; never a Permit."""
        intent = self.prepare_intent(observation, operation_nonce=operation_nonce,
                                     expires_at=expires_at)
        if self._recovery_host is None:
            raise ValueError('retained-recovery-archive-required')
        recovery_hash = self._recovery_host.verify(
            self._recovery_reference, self._observer, observation, require_recipe_equivalence=True)
        self._recovery_host.verify_target_configuration(self._recipes)
        proof_hash = self._proof_host.verify(intent, self._observer._baseline_artifacts,
                                             self._target, proofs)
        plan_hash = hashlib.sha256(b'dev-workflow:compose-reviewed-plan:v1\0' + canonical({
            'operationsHash': intent.plan_hash, 'proofHash': proof_hash,
            'recoveryArchiveHash': recovery_hash})).hexdigest()
        self._recovery_host.verify(self._recovery_reference, self._observer, observation, require_recipe_equivalence=True)
        # Evidence verification is inside the freshness window too.
        if self._observer.commitment(observation) != intent.observation_hash:
            raise ValueError('observation-changed')
        intent.ensure_fresh(datetime.now(timezone.utc))
        return replace(intent, plan_hash=plan_hash)

    def verify(self, request, observation, *, operation_nonce, proofs):
        if type(request) is not RequestV2:
            raise ValueError('exact-request-required')
        expected = self.prepare(observation, operation_nonce=operation_nonce,
                                expires_at=request.expires_at, proofs=proofs)
        if request != expected:
            raise ValueError('request-differs-from-host-evidence')

    def consume_approval(self, request, observation, *, operation_nonce, proofs,
                         client, oidc_token, verifier=None):
        """Authenticate and consume exact review after proof checks; no Permit.

        A post-consumption drift failure burns the grant. It never refunds or
        retries approval, and the returned receipt cannot authorize writes.
        """
        from deployment_compose_approval_host import GitHubComposeApproval
        self.verify(request, observation, operation_nonce=operation_nonce, proofs=proofs)
        approval = GitHubComposeApproval(client, oidc_token, [request], self._policy,
                                         verifier=verifier)
        grant = approval.validate(request)
        # Recheck after remote authentication but before consuming the one use.
        self.verify(request, observation, operation_nonce=operation_nonce, proofs=proofs)
        receipt = approval.consume(grant, request)
        self.verify(request, observation, operation_nonce=operation_nonce, proofs=proofs)
        return receipt
