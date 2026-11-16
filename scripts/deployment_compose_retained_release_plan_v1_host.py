"""Review material and deterministic stage requests for a retained frontend release."""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re

from deployment_compose_production_frontend_approval_v1_host import (
    STAGED_OPERATIONS, STAGED_PROTECTION_MODE, prepare_production_frontend_request,
)
from deployment_compose_retained_crash_evidence_v1_host import inspect_retained_crash_evidence
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2


_PLAN_FIELDS = {'schemaVersion', 'kind', 'runtimeSha', 'policyHash', 'expiresAt', 'createReview',
                'stageOrder', 'automaticRollback', 'maxUsesPerStage'}
_STAGES = ('create', 'switch', 'rollback')


def _hash(value, domain=b''):
    return hashlib.sha256(domain + canonical(value)).hexdigest()


def _reject():
    raise ValueError('retained-frontend-release-plan-rejected') from None


def _request(plan, review, stage):
    return prepare_production_frontend_request(
        review, operation=STAGED_OPERATIONS[stage], policy_hash=plan['policyHash'], expires_at=plan['expiresAt'],
    )


def prepare_release_plan(create_review, *, policy_hash, runtime_sha, expires_at, now=None):
    """Describe one review of a same-image cutover and its bounded restoration."""
    if type(runtime_sha) is not str or re.fullmatch('[0-9a-f]{40}', runtime_sha) is None:
        _reject()
    plan = dict(schemaVersion=1, kind='retained-frontend-release-plan', runtimeSha=runtime_sha,
                policyHash=policy_hash, expiresAt=expires_at, createReview=deepcopy(create_review),
                stageOrder=list(_STAGES), maxUsesPerStage=1,
                automaticRollback=dict(outcome='readiness-failed', closedSwitchWrites=4, requireKnownEffects=True))
    request = _request(plan, plan['createReview'], 'create')
    cutover = plan['createReview'].get('retainedCutover', {})
    if (request.profile_version != '3' or cutover.get('stage') != 'create'
            or cutover.get('protectionMode') != STAGED_PROTECTION_MODE):
        _reject()
    request.ensure_fresh(now or datetime.now(timezone.utc), maximum_seconds=1800)
    if len(canonical(plan)) > 32768:
        _reject()
    return plan


def release_plan_digest(plan):
    return _hash(plan, b'dev-workflow:retained-frontend-release-plan:v1\0')


def verify_release_plan(plan, *, reviewed_digest, runtime_sha, now=None):
    """Check the exact public plan against an independently reviewed digest."""
    if type(plan) is not dict or set(plan) != _PLAN_FIELDS or not hex_value(reviewed_digest):
        _reject()
    expected = prepare_release_plan(
        plan['createReview'], policy_hash=plan['policyHash'], runtime_sha=runtime_sha,
        expires_at=plan['expiresAt'], now=now,
    )
    if canonical(plan) != canonical(expected) or release_plan_digest(expected) != reviewed_digest:
        _reject()
    return expected


@dataclass(frozen=True)
class VerifiedReadinessFailure:
    """Observation from the authenticated worker after a definitely closed switch."""
    request_hash: str
    scope_generation: int
    observation_digest: str
    candidate_running: bool


@dataclass(frozen=True)
class ProposedStage:
    """Request material. An online authorization and durable claim are still required."""
    request: RequestV2
    claim_key: str


def propose_release_stage(plan, *, reviewed_digest, runtime_sha, current_review,
                          stage, witness_source=None, readiness_failure=None, now=None):
    """Derive a request after authenticating prior signed witnesses."""
    approved = verify_release_plan(plan, reviewed_digest=reviewed_digest, runtime_sha=runtime_sha, now=now)
    if type(stage) is not str or stage not in _STAGES:
        _reject()
    if stage == 'create':
        if witness_source is not None or readiness_failure is not None:
            _reject()
        expected = approved['createReview']
    else:
        if (type(witness_source) is not dict
                or set(witness_source) != {'root', 'pending', 'public_key', 'expected_key_hash'}):
            _reject()
        report = inspect_retained_crash_evidence(**witness_source)
        expected = _successor_review(approved, report, stage, current_review, readiness_failure)
    if canonical(current_review) != canonical(expected):
        _reject()
    request = _request(approved, expected, stage)
    claim = _hash(dict(release=reviewed_digest, stage=stage), b'dev-workflow:retained-release-stage:v1\0')
    return ProposedStage(request, claim)


def _successor_review(plan, report, stage, live, readiness_failure):
    expected_stages = list(_STAGES[:_STAGES.index(stage)])
    if (report['uncertain'] is not False or [item['stage'] for item in report['stages']] != expected_stages
            or any(item['checkpointMatches'] is not True for item in report['stages'])
            or type(live) is not dict or type(live.get('retainedCutover')) is not dict):
        _reject()
    expected = deepcopy(plan['createReview'])
    cutover = expected['retainedCutover']
    created = report['stages'][0]
    creation_hash = _request(plan, expected, 'create').digest()
    if (created['requestHash'] != creation_hash or report['pending']['requestHash'] != creation_hash
            or canonical(created['cutover']) != canonical(cutover) or len(created['witnessDigests']) != 1):
        _reject()
    observation = live['retainedCutover'].get('observationDigest')
    if not hex_value(observation):
        _reject()
    generation = report['pending']['generation']
    cutover.update(stage=stage, candidateId=created['candidateId'], creationRequestHash=creation_hash,
                   creationWitnessDigest=created['witnessDigests'][0], scopeGeneration=generation,
                   observationDigest=observation)
    if stage == 'switch':
        if readiness_failure is not None:
            _reject()
        return expected

    switched = report['stages'][1]
    prior = deepcopy(expected)
    prior_cutover = prior['retainedCutover']
    prior_cutover.update(stage='switch', observationDigest=switched['cutover'].get('observationDigest'))
    switch_hash = _request(plan, prior, 'switch').digest()
    if (type(readiness_failure) is not VerifiedReadinessFailure
            or type(readiness_failure.scope_generation) is not int
            or type(readiness_failure.candidate_running) is not bool
            or readiness_failure.scope_generation != generation or readiness_failure.request_hash != switch_hash
            or readiness_failure.observation_digest != observation or switched['requestHash'] != switch_hash
            or switched['candidateId'] != created['candidateId'] or len(switched['witnessDigests']) != 4
            or canonical(prior_cutover) != canonical(switched['cutover'])):
        _reject()
    cutover.update(parentRequestHash=switch_hash, switchWitnessDigest=_hash(switched['witnessDigests']),
                   switchPrefix=4, candidateRunning=readiness_failure.candidate_running)
    return expected
