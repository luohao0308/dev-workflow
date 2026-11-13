"""Live native host embedding for V2 frontend replacement and restoration.

The installed host supplies its scope registration, runtime source pins,
independent witness registrar and Caddy readiness probe. This module has no
CLI and does not install or enroll a production worker.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
import threading
import time

from deployment_compose_host_snapshot_v3_host import HostSnapshotV3, ProductionFrontendProtectionV1
from deployment_compose_native_writer_lifecycle_v3_host import _capture_current_origin
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_compose_production_frontend_approval_v1_host import (
    GitHubProductionFrontendApprovalV2, prepare_production_frontend_request,
)
from deployment_compose_production_frontend_v3_host import prepare_frontend_plan
from deployment_compose_production_scope_v1_host import ScopeRegistrationV1, acquire_scope
from deployment_compose_retained_phase_v1_host import (
    FrontendNotReady, original_projection, restored_phase, switched_phase, verify_phase,
)
from deployment_compose_retained_write_v1_host import RetainedWriteV1
from deployment_compose_retained_intent_relay_v1_host import RetainedIntentClientV1, IntentRelayRejected
from deployment_compose_witness_store import canonical, hex_value, pairs
from release_execute import AuthorizationUnavailable
from release_host import timestamp


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class RetainedWorkerBlocked(ValueError):
    pass


class RetainedReadinessFailed(RetainedWorkerBlocked):
    pass


POST_WRITE_OBSERVATION_STAGES = frozenset((
    'post-write-owner-check', 'post-write-protection-check', 'post-write-container-check',
))


class RetainedPostWriteObservationFailed(RetainedWorkerBlocked):
    def __init__(self, stage):
        if stage not in POST_WRITE_OBSERVATION_STAGES:
            raise ValueError('invalid post-write observation stage')
        super().__init__(stage)
        self.stage = stage


class RetainedFrontendWorkerV1:
    def __init__(self, private_plan, *, operation_nonce, observer, registration,
                 writer_source_sha, writer_archive_digest, policy_hash, witness_transport_factory,
                 readiness, readiness_timeout=60, loaded_source=None):
        if (hasattr(self, '_owner') or type(observer) is not HostSnapshotV3 or type(registration) is not ScopeRegistrationV1
                or not hex_value(policy_hash) or not callable(witness_transport_factory)
                or not callable(readiness) or type(readiness_timeout) not in (int, float)
                or not 1 <= readiness_timeout <= 180):
            raise RetainedWorkerBlocked('installed-production-host-required')
        self._owner = (os.getpid(), threading.current_thread())
        self._observer, self._registration = observer, registration
        self._runtime = (writer_source_sha, writer_archive_digest)
        self._origin = _capture_current_origin(*self._runtime)
        self._loaded_source = loaded_source
        self._verify_source()
        self._policy_hash = policy_hash
        self._factory, self._readiness = witness_transport_factory, readiness
        self._readiness_timeout = readiness_timeout
        self._private = deepcopy(private_plan)
        self._plan = prepare_retained_frontend_cutover(self._private, operation_nonce=operation_nonce)
        self._nonce = operation_nonce
        self._review = self._private['publicReview']
        identity = self._review['identity']
        if (identity['hostId'], identity['project'], identity['daemonId']) != (
                registration.host_id, registration.project, registration.daemon_id):
            raise RetainedWorkerBlocked('registered-production-scope-mismatch')
        version = self._get('/v1.45/version')
        if (version.get('Version'), version.get('GitCommit')) != ('29.8.2', '8af9fe3'):
            raise RetainedWorkerBlocked('production-engine-version-unverified')
        self._baseline = original_projection(self._container(self._plan.original_id))
        row = self._get('/v1.45/images/' + identity['imageId'] + '/json')
        image = {key: row[key] for key in ('Id', 'Os', 'Architecture', 'Config')}
        networks = {name: endpoint['NetworkID'] for name, endpoint in self._baseline['NetworkSettings']['Networks'].items()}
        rebuilt = prepare_frontend_plan(
            self._baseline, image, expected_identity=identity, expected_snapshot_digest=self._review['snapshotDigest'],
            network_ids=networks, protected_container_ids=self._review['protectedContainerIds'],
        )
        if canonical(rebuilt) != canonical(self._private):
            raise RetainedWorkerBlocked('production-create-body-drift')
        self._protection = ProductionFrontendProtectionV1(
            observer, daemon_id=registration.daemon_id, original_id=self._plan.original_id,
            protected_ids=self._plan.protected_ids,
        )
        self._candidate_id = None
        self._candidate_created_at = None
        self._candidate_started_at = None
        self._phase = switched_phase(self._plan, 0, candidate_present=False)
        self._prefix = 0
        self._lease = None
        self._parent = None
        self._deploy_witnesses = ()
        self._state = 'prepared'
        self._protection_digest = self._protection.verify()
        self._observation = self._observe()

    def __copy__(self):
        raise RetainedWorkerBlocked('production-worker-cannot-be-copied')

    def __deepcopy__(self, memo):
        raise RetainedWorkerBlocked('production-worker-cannot-be-copied')

    def __reduce_ex__(self, protocol):
        raise RetainedWorkerBlocked('production-worker-cannot-be-serialized')

    def _check_owner(self):
        if (os.getpid(), threading.current_thread()) != self._owner or self._state == 'closed':
            raise RetainedWorkerBlocked('production-worker-owner-mismatch')

    def _verify_source(self):
        if self._loaded_source is None:
            return
        from deployment_compose_retained_source_v1_host import check_loaded_source

        facts = check_loaded_source(self._loaded_source)
        if (facts['sourceSha'], facts['archiveDigest'], facts['originDigest']) != (
                *self._runtime, hashlib.sha256(self._origin).hexdigest()):
            raise RetainedWorkerBlocked('production-loaded-source-mismatch')

    def _get(self, path):
        return self._observer._get(path, time.monotonic() + 5, [2 * 1024 * 1024])

    def _container(self, container_id):
        return self._get('/v1.45/containers/' + container_id + '/json')

    def _observe(self, *, require_ready=False, refresh_candidate=False, after_write=False):
        stage = 'post-write-owner-check'
        try:
            self._verify_observer_owner()
            stage = 'post-write-protection-check'
            if self._protection.verify(candidate_id=self._candidate_id) != self._protection_digest:
                raise RetainedWorkerBlocked('production-protection-drift')
            stage = 'post-write-container-check'
            return self._observe_containers(require_ready=require_ready, refresh_candidate=refresh_candidate)
        except FrontendNotReady:
            raise
        except Exception:
            if after_write:
                raise RetainedPostWriteObservationFailed(stage) from None
            raise

    def _verify_observer_owner(self):
        self._check_owner()
        self._verify_source()
        if _capture_current_origin(*self._runtime) != self._origin:
            raise RetainedWorkerBlocked('production-writer-identity-changed')
        if self._lease is not None:
            self._lease.check()

    def _observe_containers(self, *, require_ready, refresh_candidate):
        def sample():
            original = self._container(self._plan.original_id)
            candidate = self._container(self._candidate_id) if self._candidate_id is not None else None
            phase = self._phase
            if refresh_candidate:
                phase = switched_phase(self._plan, 4, candidate_running=candidate['State']['Running'])
            stamp = candidate['State']['StartedAt'] if candidate is not None else None
            if phase.candidate_started:
                if stamp == self._candidate_created_at or (
                        self._candidate_started_at is not None and stamp != self._candidate_started_at):
                    raise RetainedWorkerBlocked('production-candidate-restarted')
            elif candidate is not None and self._candidate_created_at is not None and stamp != self._candidate_created_at:
                raise RetainedWorkerBlocked('production-candidate-started-unexpectedly')
            return (verify_phase(self._plan, self._baseline, original, candidate,
                                 candidate_id=self._candidate_id, phase=phase, require_ready=require_ready),
                    phase, stamp)

        first, second = sample(), sample()
        if first != second:
            raise RetainedWorkerBlocked('production-phase-observation-drift')
        raw, phase, stamp = first
        self._phase = phase
        if self._candidate_id is not None:
            if phase.candidate_started:
                self._candidate_started_at = stamp
            else:
                self._candidate_created_at = stamp
        return hashlib.sha256(raw).hexdigest()

    def _review_for(self, *, rollback=False):
        retained = dict(planDigest=self._plan.digest, operationNonce=self._nonce,
                        protectionDigest=self._protection_digest, runtimeArchiveDigest=self._runtime[1])
        if rollback:
            retained.update(candidateId=self._candidate_id, switchPrefix=self._prefix,
                            candidateRunning=self._phase.candidate_running, parentRequestHash=self._parent,
                            observationDigest=self._observation)
        return dict(deepcopy(self._review), retainedCutover=retained)

    def deploy_review(self):
        self._check_owner()
        if self._state != 'prepared' or self._observe() != self._observation:
            raise RetainedWorkerBlocked('production-deploy-review-stale')
        return self._review_for()

    def restore_review(self):
        self._check_owner()
        if self._state not in ('deployed', 'restoration-ready') or not 1 <= self._prefix <= 4:
            raise RetainedWorkerBlocked('production-restoration-prefix-unavailable')
        self._observation = self._observe(refresh_candidate=self._prefix == 4)
        return self._review_for(rollback=True)

    def _authorize(self, approval, grant, request, review, first):
        relayed = type(approval) is RetainedIntentClientV1
        if relayed:
            binding = approval.binding
            if (binding.runtime_sha, binding.archive_digest, binding.origin_digest, binding.protection_digest) != (
                    self._runtime[0], self._runtime[1], hashlib.sha256(self._origin).hexdigest(),
                    self._protection_digest):
                raise RetainedWorkerBlocked('retained-production-intent-binding-mismatch')
        elif (type(approval) is not GitHubProductionFrontendApprovalV2
              or approval.policy.workflow_sha != self._runtime[0]):
            raise RetainedWorkerBlocked('retained-production-approval-required')
        expected = prepare_production_frontend_request(
            review, policy_hash=self._policy_hash, expires_at=request.expires_at, operation=request.operation,
        )
        if request != expected or approval.validate(request) != grant:
            raise RetainedWorkerBlocked('retained-production-request-mismatch')
        if self._lease is None:
            self._lease = acquire_scope(self._registration, request.digest())

        def preflight():
            if self._observe() != self._observation:
                raise RetainedWorkerBlocked('retained-production-preflight-drift')

        if relayed:
            receipt = approval.consume(grant, request, before_consume=preflight, generation=self._lease.generation)
        else:
            receipt = approval.consume(grant, request, before_consume=preflight)
        preflight()
        receipt_hash = digest(asdict(receipt))
        execution_digest = digest(dict(plan=self._plan.digest, approvedReview=request.plan_hash,
                                       protection=self._protection_digest, scopeGeneration=self._lease.generation,
                                       writerOrigin=hashlib.sha256(self._origin).hexdigest()))
        transport = self._factory(self._observer, first, request.digest(), receipt_hash, execution_digest)
        if type(transport) is not RetainedWriteV1 or transport.observer is not self._observer:
            raise RetainedWorkerBlocked('retained-production-witness-transport-mismatch')
        expires_at = min(timestamp(request.expires_at).timestamp(), timestamp(grant.expires_at).timestamp())
        return transport, receipt_hash, execution_digest, expires_at

    def _write(self, transport, approval, request, operation, index, receipt_hash, execution_digest, expires_at):
        def guard():
            if self._observe() != self._observation:
                raise RetainedWorkerBlocked('retained-production-write-drift')
            checked = approval.check_consumed_intent(request)
            if type(approval) is RetainedIntentClientV1:
                return checked

        status, raw, witness = transport.write(
            operation, request_hash=request.digest(), receipt_hash=receipt_hash,
            plan_digest=execution_digest, index=index, before_dispatch=guard, expires_at=expires_at,
        )
        if not hex_value(witness) or (operation.phase == 'create' and status != 201
                                     or operation.phase != 'create' and (status != 204 or raw != b'')):
            raise RetainedWorkerBlocked('retained-production-write-unconfirmed')
        return raw, witness

    def _verify_readiness(self, active_id):
        deadline = time.monotonic() + self._readiness_timeout
        refresh = active_id == self._candidate_id
        while time.monotonic() < deadline:
            try:
                before = self._observe(require_ready=True, refresh_candidate=refresh)
                if self._readiness(active_id) is True and time.monotonic() < deadline:
                    after = self._observe(require_ready=True, refresh_candidate=refresh)
                    if before == after and time.monotonic() < deadline:
                        return after
            except FrontendNotReady:
                if refresh:
                    self._observe(refresh_candidate=True)
                    if not self._phase.candidate_running:
                        break
            time.sleep(min(0.25, max(0, deadline-time.monotonic())))
        raise RetainedReadinessFailed('retained-production-readiness-failed')

    def deploy(self, approval, grant, request):
        review = self.deploy_review()
        self._state = 'blocked'
        first = self._plan.create()
        transport, receipt_hash, execution_digest, expires_at = self._authorize(approval, grant, request, review, first)
        self._parent = request.digest()
        raw, witness = self._write(transport, approval, request, first, 0, receipt_hash, execution_digest, expires_at)
        response = json.loads(raw, object_pairs_hook=pairs)
        candidate = response['Id']
        self._plan._candidate(candidate)
        self._candidate_id = candidate
        self._phase = switched_phase(self._plan, 0)
        self._observation = self._observe(after_write=True)
        witnesses = [witness]
        self._deploy_witnesses = tuple(witnesses)
        for index, operation in enumerate(self._plan.switch(candidate), start=1):
            try:
                # A denial here precedes any new witness reservation or Docker
                # request. Only this known closed prefix can get a new approval.
                approval.check_consumed_intent(request)
            except (AuthorizationUnavailable, IntentRelayRejected):
                if self._prefix and self._observe() == self._observation:
                    self._state = 'restoration-ready'
                raise
            _, witness = self._write(transport, approval, request, operation, index, receipt_hash, execution_digest, expires_at)
            witnesses.append(witness)
            self._prefix = index
            self._phase = switched_phase(self._plan, index)
            self._observation = self._observe(refresh_candidate=index == 4, after_write=True)
            self._deploy_witnesses = tuple(witnesses)
        try:
            self._observation = self._verify_readiness(candidate)
        except RetainedReadinessFailed:
            self._observation = self._observe(refresh_candidate=True)
            self._state = 'restoration-ready'
            raise
        result = self._finish(request, witnesses)
        self._state = 'deployed'
        return result

    def restore(self, approval, grant, request):
        review = self.restore_review()
        self._state = 'blocked'
        operations = self._plan.restore(self._candidate_id, switch_prefix=self._prefix,
                                        candidate_running=self._phase.candidate_running)
        transport, receipt_hash, execution_digest, expires_at = self._authorize(approval, grant, request, review, operations[0])
        witnesses = []
        for index, operation in enumerate(operations):
            _, witness = self._write(transport, approval, request, operation, index, receipt_hash, execution_digest, expires_at)
            witnesses.append(witness)
            self._phase = restored_phase(self._plan, self._phase, operation)
            self._observation = self._observe(after_write=True)
        self._observation = self._verify_readiness(self._plan.original_id)
        result = self._finish(request, witnesses)
        self._state = 'restored'
        return result

    def _finish(self, request, witnesses):
        result = dict(requestHash=request.digest(), observationDigest=self._observation,
                      protectionDigest=self._protection_digest, witnessDigests=witnesses,
                      originalId=self._plan.original_id, candidateId=self._candidate_id)
        if request.operation == 'rollback':
            result.update(parentRequestHash=self._parent, parentWitnessDigests=list(self._deploy_witnesses))
        self._lease.complete(digest(result))
        self._lease.close()
        self._lease = None
        return result

    def close(self):
        self._check_owner()
        if self._lease is not None:
            self._lease.close()
            self._lease = None
        self._state = 'closed'
