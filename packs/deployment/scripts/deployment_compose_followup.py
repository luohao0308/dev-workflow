"""Pure concrete follow-up proposal; supplied IDs are unverified assertions.

No Gate tuples, sessions, transport, permit or generation are issued here.
Replaying original compilation verifies the whole symbolic description, not its
provenance. A future writer still needs authenticated receipts and sequencing.
"""
from dataclasses import fields, is_dataclass
import hashlib
import json
import re
from urllib.parse import quote

from deployment_compose_operations import BatchOperations, compile_operations

DOMAIN = b'dev-workflow:compose-followup-proposal:v1\0'
HEX = re.compile(r'[0-9a-f]{64}\Z')
EMPTY_HASH = hashlib.sha256(b'').hexdigest()
MAX_PROTECTED = 128
BLOCKERS = (
    'schema1-create-name-not-supported-by-gate',
    'temporary-name-recipe-binding-required',
    'receipt-plan-binding-unverified',
    'rename-gateway-support-required',
    'independent-anchor-required',
    'source-generation-quiescence-required',
    'next-generation-authorization-required',
    'step-sequencing-authority-required',
    'fresh-protected-scope-evidence-required',
    'recovery-authorization-required',
)


def fail():
    raise ValueError('invalid-compose-followup-proposal')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _same(left, right):
    # Dataclass equality treats 0==False; JSON treats tuple/list identically.
    # Both distinctions matter before accepting a recompiled protocol.
    if type(left) is not type(right):
        return False
    if is_dataclass(left):
        return all(_same(getattr(left, field.name), getattr(right, field.name)) for field in fields(left))
    if type(left) in (tuple, list):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    if type(left) is dict:
        return left.keys() == right.keys() and all(_same(left[key], right[key]) for key in left)
    return left == right


def compile_followup(plan, *, candidate, baseline, old_artifacts, target_artifacts,
                     operation_nonce, dependencies, baseline_observation_hash,
                     candidate_ids, forbidden_container_ids, stop_timeout=10):
    """Substitute exact full IDs only after complete original-input recompilation.

    The host must supply the complete nonselected/forbidden ID scope; this pure
    function does not prove its completeness, receipt origin or freshness.
    """
    try:
        return _compile(plan, candidate, baseline, old_artifacts, target_artifacts,
            operation_nonce, dependencies, baseline_observation_hash, candidate_ids,
            forbidden_container_ids, stop_timeout)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError,
            RecursionError, OverflowError, UnicodeError):
        raise ValueError('invalid-compose-followup-proposal') from None


def _compile(plan, candidate, baseline, old, target, nonce, dependencies, observation,
             candidate_ids, forbidden, timeout):
    if type(plan) is not BatchOperations or type(timeout) is not int or not 1 <= timeout <= 60:
        fail()
    if (type(candidate) is not dict or len(candidate) > 64
            or type(candidate.get('protectedServices')) is not list
            or len(candidate['protectedServices']) > MAX_PROTECTED
            or candidate.get('unverifiedConstraints') != []
            or type(candidate.get('unverifiedConstraints')) is not list
            or type(dependencies) is not dict or len(dependencies) > 32
            or type(candidate_ids) is not dict or len(candidate_ids) > 32
            or type(plan.protected_services) is not tuple or len(plan.protected_services) > MAX_PROTECTED
            or type(plan.operations) is not tuple or len(plan.operations) > 192):
        fail()
    candidate = dict(candidate)
    for key, limit in (('selectedServices', 32), ('startOrder', 32), ('stopOrder', 32),
                       ('protectedServices', MAX_PROTECTED)):
        if type(candidate.get(key)) is not list or len(candidate[key]) > limit:
            fail()
        candidate[key] = list(candidate[key])
    candidate['unverifiedConstraints'] = []
    dependencies, candidate_ids = dict(dependencies), dict(candidate_ids)
    expected = compile_operations(candidate, baseline, old, target, nonce, dependencies, observation)
    if not _same(plan, expected) or plan.unverified_constraints:
        fail()
    if (type(forbidden) is not tuple or len(forbidden) > 512
            or any(type(value) is not str or not HEX.fullmatch(value) for value in forbidden)
            or len(set(forbidden)) != len(forbidden)
            or type(candidate_ids) is not dict or set(candidate_ids) != set(plan.selected_services)
            or any(type(value) is not str or not HEX.fullmatch(value) for value in candidate_ids.values())
            or len(set(candidate_ids.values())) != len(candidate_ids)):
        fail()
    baseline_ids = {item.container_id for item in baseline}
    if baseline_ids & set(forbidden) or set(candidate_ids.values()) & (baseline_ids | set(forbidden)):
        fail()
    steps = []
    for index, operation in enumerate(plan.operations):
        if operation.phase == 'precreate-stopped':
            continue
        if operation.phase in ('stop-old', 'remove-old'):
            identity = operation.container_ref
            if identity not in baseline_ids or identity in forbidden:
                fail()
        else:
            if operation.container_ref != 'candidate:' + operation.service:
                fail()
            identity = candidate_ids[operation.service]
        prefix = '/v1.45/containers/' + identity
        method, readiness = 'POST', []
        if operation.phase == 'stop-old':
            path = prefix + '/stop?t=' + str(timeout)
        elif operation.phase == 'remove-old':
            method, path = 'DELETE', prefix + '?force=false&v=false'
        elif operation.phase == 'rename-candidate':
            path = prefix + '/rename?name=' + quote(operation.name, safe='')
        elif operation.phase == 'start-candidate':
            path = prefix + '/start'
        elif operation.phase == 'check-readiness':
            method, path = 'GET', prefix + '/json'
            readiness = ['running', 'healthy', 'dns', 'business', 'protected-scope-unchanged']
        else:
            fail()
        steps.append({'index': index, 'phase': operation.phase, 'service': operation.service,
            'targetId': identity, 'method': method, 'path': path, 'bodySha256': EMPTY_HASH,
            'predecessorIndex': index - 1, 'kind': 'readiness-barrier' if readiness else 'write-intent',
            # Non-success outcomes cannot be inferred to authorize a retry.
            'expectedStatuses': [200] if readiness else [204], 'requiredChecks': readiness})
    value = {'schemaVersion': 1, 'kind': 'compose-followup-offline-proposal',
        'planHash': plan.plan_hash, 'operationNonce': plan.operation_nonce,
        'baselineObservationHash': plan.baseline_observation_hash,
        'baselineDigest': plan.baseline_digest, 'targetDigest': plan.target_digest,
        'selectedServices': list(plan.selected_services), 'protectedServices': list(plan.protected_services),
        'candidateIds': {service: candidate_ids[service] for service in plan.selected_services},
        'candidateIdVerification': 'host-asserted-unverified',
        'forbiddenContainerIds': sorted(forbidden), 'stopTimeout': timeout,
        'createActionIndexes': list(range(len(plan.selected_services))), 'steps': steps,
        'blockers': list(BLOCKERS), 'authorityGranted': False, 'executionAvailable': False,
        'productionReady': False, 'replaySafe': False, 'quiescenceProven': False,
        'nextGenerationAuthorized': False, 'sequencingEnforced': False}
    value['proposalDigest'] = hashlib.sha256(DOMAIN + canonical(value)).hexdigest()
    return value
