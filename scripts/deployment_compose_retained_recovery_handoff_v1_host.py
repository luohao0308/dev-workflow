"""One-shot recovery lock handoff for a confirmed retained-frontend stop."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import time

from deployment_compose_host_snapshot_v3_host import (
    HostSnapshotV3, ProductionFrontendProtectionV1, _frontend_projection,
)
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_compose_production_frontend_approval_v1_host import (
    GitHubProductionFrontendApprovalV3, prepare_production_frontend_request,
)
from deployment_compose_production_frontend_v3_host import prepare_frontend_plan
from deployment_compose_production_scope_v1_host import _claim_pending_scope
from deployment_compose_retained_crash_evidence_v1_host import inspect_retained_crash_evidence
from deployment_compose_retained_phase_v1_host import switched_phase, verify_phase
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2
from release_host import timestamp


def _digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _reject():
    raise ValueError('retained-crash-recovery-handoff-rejected') from None


def prepare_crash_rollback_review(report, private_plan, *, observation_digest):
    """Bind a fresh restart-only review to one closed stop and its creation."""
    if (report['uncertain'] is not False or not hex_value(observation_digest)
            or [item['stage'] for item in report['stages']] != ['create', 'switch']):
        _reject()
    creation, switch = report['stages']
    if (any(item['checkpointMatches'] is not True or len(item['witnessDigests']) != 1
            for item in (creation, switch)) or creation['candidateId'] != switch['candidateId']):
        _reject()
    cutover = switch['cutover']
    plan = prepare_retained_frontend_cutover(private_plan, operation_nonce=cutover['operationNonce'])
    if plan.digest != cutover['planDigest']:
        _reject()
    plan._candidate(switch['candidateId'])
    retained = dict(cutover, stage='rollback', switchPrefix=1, candidateRunning=False,
                    parentRequestHash=switch['requestHash'], switchWitnessDigest=_digest(switch['witnessDigests']),
                    observationDigest=observation_digest, recoveryJournalDigest=report['pending']['journalDigest'],
                    recoveryEvidenceDigest=_digest(report))
    return dict(deepcopy(private_plan['publicReview']), retainedCutover=retained)


def observe_confirmed_stop(observer, private_plan, original_baseline, cutover, *, endpoint_digest):
    """Take a fresh, stable observation of the fixed first-stop recovery phase."""
    identity = private_plan['publicReview']['identity']
    if (type(observer) is not HostSnapshotV3 or observer._info_id != identity['daemonId']
            or not hex_value(endpoint_digest) or observer.descriptor()['endpointDigest'] != endpoint_digest
            or cutover.get('switchPrefix') != 1 or cutover.get('candidateRunning') is not False):
        _reject()
    plan = prepare_retained_frontend_cutover(private_plan, operation_nonce=cutover['operationNonce'])
    if plan.digest != cutover['planDigest']:
        _reject()
    candidate = cutover['candidateId']
    plan._candidate(candidate)

    def read(path):
        return observer._get(path, time.monotonic() + 5, [2 * 1024 * 1024])

    version = read('/v1.45/version')
    if (version.get('Version'), version.get('GitCommit')) != ('29.8.2', '8af9fe3'):
        _reject()
    image_row = read('/v1.45/images/' + identity['imageId'] + '/json')
    image = {key: image_row[key] for key in ('Id', 'Os', 'Architecture', 'Config')}
    networks = {name: value['NetworkID'] for name, value in original_baseline['NetworkSettings']['Networks'].items()}
    rebuilt = prepare_frontend_plan(
        original_baseline, image, expected_identity=identity,
        expected_snapshot_digest=private_plan['publicReview']['snapshotDigest'], network_ids=networks,
        protected_container_ids=private_plan['publicReview']['protectedContainerIds'],
    )
    if canonical(rebuilt) != canonical(private_plan):
        _reject()

    def sample():
        rows = [read('/v1.45/containers/' + cid + '/json') for cid in (plan.original_id, candidate)]
        return verify_phase(plan, original_baseline, *rows, candidate_id=candidate, phase=switched_phase(plan, 1))

    before = sample()
    snapshot = ProductionFrontendProtectionV1._observe(observer, 20, (plan.original_id, candidate))
    projection = _frontend_projection(snapshot, plan.original_id, plan.protected_ids, candidate)
    protection = hashlib.sha256(projection).hexdigest()
    if protection != cutover['protectionDigest'] or sample() != before:
        _reject()
    observer.verify_unchanged()
    return _digest(dict(endpointDigest=endpoint_digest, protectionDigest=protection,
                        phaseDigest=hashlib.sha256(before).hexdigest()))


def claim_crash_rollback(registration, root, pending, *, public_key, expected_key_hash,
                         private_plan, original_baseline, observer, endpoint_digest,
                         review, approval, grant, request, runtime_sha):
    """Verify fresh consent and live evidence under lock, then return the owned lease.

    Call the returned guard at the final write admission, then verify restoration
    before completing the lease. This helper does not dispatch Docker requests.
    """
    if (type(approval) is not GitHubProductionFrontendApprovalV3 or type(request) is not RequestV2
            or request.operation != 'rollback' or approval.policy.stage != 'rollback'
            or approval.policy.workflow_sha != runtime_sha or type(observer) is not HostSnapshotV3
            or (request.host_id, request.target.namespace, request.daemon_id)
            != (registration.host_id, registration.project, registration.daemon_id)):
        _reject()
    frozen_review = deepcopy(review)
    frozen_pending = deepcopy(pending)
    frozen_plan = deepcopy(private_plan)
    frozen_baseline = deepcopy(original_baseline)
    expected = prepare_production_frontend_request(frozen_review, policy_hash=approval.policy.policy_hash,
                                                   expires_at=request.expires_at, operation='rollback')
    if request != expected:
        _reject()
    cutover = frozen_review['retainedCutover']
    receipt = None
    expires = None

    def check_live():
        observation = observe_confirmed_stop(observer, frozen_plan, frozen_baseline, cutover,
                                             endpoint_digest=endpoint_digest)
        if observation != cutover['observationDigest']:
            _reject()

    def authorize():
        nonlocal receipt, expires
        report = inspect_retained_crash_evidence(root, frozen_pending, public_key=public_key,
                                                 expected_key_hash=expected_key_hash)
        rebuilt = prepare_crash_rollback_review(report, frozen_plan, observation_digest=cutover['observationDigest'])
        if canonical(rebuilt) != canonical(frozen_review) or approval.validate(request) != grant:
            _reject()
        expires = min(timestamp(request.expires_at).timestamp(), timestamp(grant.expires_at).timestamp())
        check_live()
        receipt = approval.consume(grant, request, before_consume=check_live)
        check_live()
        if time.time() >= expires:
            _reject()
        return _digest(dict(approval=request.digest(), receipt=asdict(receipt),
                            evidence=cutover['recoveryEvidenceDigest'], observation=cutover['observationDigest']))

    lease = _claim_pending_scope(registration, frozen_pending, request.digest(), authorize)
    plan = prepare_retained_frontend_cutover(frozen_plan, operation_nonce=cutover['operationNonce'])
    operation, = plan.restore(cutover['candidateId'], switch_prefix=1, candidate_running=False)

    def guard():
        lease.check()
        check_live()
        approval.check_consumed_intent(request)
        if time.time() >= expires:
            _reject()
        return expires

    return lease, receipt, operation, guard
