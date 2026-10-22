#!/usr/bin/env python3
"""Scoped deployment/rollback authorization for fixed trusted host embeddings.

Load from a pinned trusted checkout using an isolated Python bootstrap. Import
paths below prioritize trusted siblings; the embedding host must also control
preloaded modules and Python injection hooks.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import uuid
import weakref

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve()
sys.path.insert(0, str(SCRIPT.parent))
CORE = SCRIPT.parents[3] / 'core/scripts' if len(SCRIPT.parents) > 3 else SCRIPT.parent
# Installed packs and core helpers share <repository>/scripts.
sys.path.insert(1, str(CORE if CORE.is_dir() else SCRIPT.parent))
import deployment_prepare as planner
from workflow_lock import LifecycleLock, pending_upgrades

OPERATIONS = ('deployment-deploy', 'deployment-rollback')
DOMAIN = 'dev-workflow-deployment-authorization-v1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
SLUG = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z')
RECORDS = planner.RECORDS
_ISSUED_PERMITS = weakref.WeakSet()


class AuthorizationError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode('ascii')).hexdigest()


def clock():
    return datetime.now(timezone.utc)


def timestamp(value):
    return planner.timestamp(value)


@dataclass(frozen=True)
class Request:
    operation: str
    repository: str
    repository_slug: str
    repository_id: int
    head_sha: str
    configuration_hash: str
    environment: str
    target: str
    production: bool
    components: tuple[str, ...]
    before_json: str
    after_json: str
    conditions_json: str
    plan_hash: str
    observation_hash: str
    state_hash: str
    runtime_policy_hash: str
    expires_at: str
    max_uses: int = 1
    execution_json: str | None = None

    def __post_init__(self):
        if (self.operation not in OPERATIONS or not isinstance(self.repository, str) or not self.repository
                or not isinstance(self.repository_slug, str) or not SLUG.fullmatch(self.repository_slug)
                or any(part in ('.', '..') for part in self.repository_slug.split('/'))
                or type(self.repository_id) is not int or self.repository_id <= 0
                or not isinstance(self.head_sha, str) or not planner.SHA.fullmatch(self.head_sha)
                or type(self.production) is not bool or type(self.components) is not tuple
                or not self.components or len(set(self.components)) != len(self.components)
                or any(not isinstance(name, str) or not planner.NAME.fullmatch(name) for name in self.components)
                or any(not isinstance(value, str) or not planner.NAME.fullmatch(value) for value in (self.environment, self.target))
                or type(self.max_uses) is not int or self.max_uses != 1):
            raise AuthorizationError('Invalid frozen deployment request')
        for value in (self.configuration_hash, self.plan_hash, self.observation_hash, self.state_hash, self.runtime_policy_hash):
            if not isinstance(value, str) or not HEX.fullmatch(value):
                raise AuthorizationError('Invalid deployment identity digest')
        for value in (self.before_json, self.after_json, self.conditions_json):
            if not isinstance(value, str) or canonical(json.loads(value)) != value:
                raise AuthorizationError('Deployment request requires canonical immutable JSON')
        if self.execution_json is not None:
            binding = json.loads(self.execution_json)
            if (not isinstance(binding, dict) or canonical(binding) != self.execution_json
                    or binding.get('profile') != 'docker-container-replace-v1'
                    or not isinstance(binding.get('policyHash'), str)
                    or not HEX.fullmatch(binding['policyHash'])):
                raise AuthorizationError('Invalid immutable execution binding')
        timestamp(self.expires_at)

    def digest(self):
        return fingerprint(dict(domain=DOMAIN, schemaVersion=1, **asdict(self)))


@dataclass(frozen=True)
class Grant:
    grant_id: str
    request_hash: str
    expires_at: str
    max_uses: int


@dataclass(frozen=True)
class Receipt:
    grant_id: str
    request_hash: str
    use_number: int
    consumed_at: str


def ordered(components):
    result = {}
    for item in components:
        planner.component(item)
        if item['name'] in result:
            raise AuthorizationError('Duplicate component identity')
        result[item['name']] = json.loads(canonical(item))
    return [result[name] for name in sorted(result)]


def _deadline(expires):
    deadline = timestamp(expires)
    if deadline <= clock() or deadline > clock() + timedelta(hours=1):
        raise AuthorizationError('Deployment request expired or lifetime exceeds one hour')


def build_request(root, plan, operation, *, collector, observation, repository_slug,
                  repository_id, expires_at, rollback_target=None, execution_intent=None):
    if operation not in OPERATIONS:
        raise AuthorizationError('Unsupported deployment operation')
    root = Path(root).resolve()
    _deadline(expires_at)
    saved = planner.checked(root, json.loads(canonical(plan)))
    if saved['result'] != 'prepared' or saved['blockers']:
        raise AuthorizationError('Deployment plan is blocked')
    collector.validate(observation)
    snapshot = observation.snapshot()
    policy = collector.policy
    if (policy.repository != repository_slug or policy.environment != saved['environment']
            or policy.target != saved['target'] or policy.production is not saved['production']
            or observation.policy_hash != policy.identity_hash()):
        raise AuthorizationError('Runtime observation scope differs from deployment plan')
    config = planner.resolve_configuration(root)['config']['extensions']['deployment']
    names = config['environments'][saved['environment']]['components']
    if set(policy.components) != set(names) or set(item['name'] for item in snapshot['components']) != set(names):
        raise AuthorizationError('Runtime baseline must cover the complete configured environment')
    before = ordered(snapshot['components'])
    if saved['rollback']['version'] != snapshot['version'] or ordered(saved['rollback']['components']) != before:
        raise AuthorizationError('Plan baseline differs from authenticated runtime observation')
    supplied, _ = planner.read_data(root, saved['arguments']['currentSnapshot'])
    if canonical(supplied) != canonical(snapshot):
        raise AuthorizationError('Supplied snapshot does not match issued observation')
    desired = ordered(saved['desired'])
    selected = tuple(sorted(saved['requestedComponents']))
    previous = {item['name']: item for item in before}
    for item in desired:
        if item['name'] not in selected and item != previous[item['name']]:
            raise AuthorizationError('Unselected component identity changed')
    # This first authenticated runtime profile supports explicit no-migration
    # workloads. A deploy grant never silently grants backup or migration rights.
    conditions = saved['conditions']
    if (conditions['migration']['mode'] != 'none' or conditions['backup']['required']
            or any(item['migrationVersion'] is not None for item in before + desired)):
        raise AuthorizationError('Backup or migration requires separate trusted evidence and authority')
    history_hash = None
    if operation == 'deployment-rollback':
        if rollback_target is None:
            raise AuthorizationError('Rollback requires an explicit authenticated historical target')
        collector.validate_history(rollback_target, before=observation)
        history = {item['name']: item for item in ordered(rollback_target.snapshot()['components'])}
        if set(history) != set(names):
            raise AuthorizationError('Rollback history does not cover the configured environment')
        for item in desired:
            if item['name'] in selected and item != history[item['name']]:
                raise AuthorizationError('Rollback target differs from authenticated history')
        history_hash = rollback_target.evidence_hash
    elif rollback_target is not None:
        raise AuthorizationError('Deploy cannot borrow a rollback history capability')
    execution_json = None
    if execution_intent is not None:
        from deployment_execute import ExecutionIntent
        if type(execution_intent) is not ExecutionIntent:
            raise AuthorizationError('Execution requires an issued Docker intent')
        execution_intent.validate(root, saved, operation, collector=collector,
                                  observation=observation, rollback_target=rollback_target)
        execution_json = execution_intent.binding_json
    return Request(operation=operation, repository=str(root), repository_slug=repository_slug,
                   repository_id=repository_id, head_sha=saved['headSha'],
                   configuration_hash=saved['configurationHash'], environment=saved['environment'],
                   target=saved['target'], production=saved['production'], components=selected,
                   before_json=canonical(dict(version=snapshot['version'], components=before)),
                   after_json=canonical(dict(version=saved['version'], components=desired)),
                   conditions_json=canonical(dict(conditions=conditions, evidence=saved['inputs']['evidence'],
                                                   rollbackHistoryHash=history_hash)),
                   plan_hash=fingerprint(saved), observation_hash=observation.evidence_hash,
                   state_hash=observation.state_hash, runtime_policy_hash=observation.policy_hash,
                   expires_at=expires_at, execution_json=execution_json)


def validate_grant(grant, request):
    _deadline(request.expires_at)
    if (type(grant) is not Grant or not isinstance(grant.grant_id, str)
            or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', grant.grant_id)
            or grant.request_hash != request.digest() or type(grant.max_uses) is not int or grant.max_uses != 1
            or timestamp(grant.expires_at) > timestamp(request.expires_at)
            or timestamp(grant.expires_at) <= clock()):
        raise AuthorizationError('Invalid, expired or cross-domain deployment grant')


def validate_receipt(receipt, grant, request, started):
    validate_grant(grant, request)
    if (type(receipt) is not Receipt or receipt.grant_id != grant.grant_id
            or receipt.request_hash != request.digest() or type(receipt.use_number) is not int or receipt.use_number != 1
            or not started - timedelta(seconds=1) <= timestamp(receipt.consumed_at) <= clock() + timedelta(seconds=30)):
        raise AuthorizationError('Deployment grant consumption could not be verified')


def _assert_output(root, relative):
    planner.path_at(root, relative)
    if planner.git(root, 'ls-files', '--', ':(top,literal).dev-workflow'):
        raise AuthorizationError('Local workflow records are tracked by Git')
    if not planner.git(root, 'check-ignore', '--no-index', '--', relative):
        raise AuthorizationError('Authorization output must be ignored by Git')


def _audit(root, relative, value):
    _assert_output(root, relative)
    path = planner.path_at(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.authorization-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(json.dumps(value, ensure_ascii=True, indent=2) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class DeploymentPermit:
    """Host-local single-dispatch capability; JSON export is an audit only.

    The executor claims immediately before its bounded operation. Exported
    receipts are audits, never reloadable capabilities or automatic retries.
    """
    def __init__(self, *, request, grant, receipt, check, result, execution_guard=None):
        self._request, self._grant, self._receipt = request, grant, receipt
        self._check, self._result = check, canonical(result)
        self._execution_guard = execution_guard
        self._claimed, self._lock = False, threading.Lock()

    @property
    def request(self):
        return self._request

    @property
    def grant(self):
        return self._grant

    @property
    def receipt(self):
        return self._receipt

    def to_dict(self):
        return json.loads(self._result)

    def claim_for_dispatch(self):
        with self._lock:
            if self not in _ISSUED_PERMITS:
                raise AuthorizationError('Deployment permit was not issued by this authority session')
            if self._claimed:
                raise AuthorizationError('Deployment permit already claimed; no automatic retry')
            self._check()
            self._claimed = True
            return self.receipt

    def guard_for_execution(self, runtime_check):
        if (self not in _ISSUED_PERMITS or not self._claimed or self.request.execution_json is None
                or self._execution_guard is None or not callable(runtime_check)):
            raise AuthorizationError('A claimed execution-bound permit is required')
        self._execution_guard(runtime_check)


def authorize(root, plan, request, *, collector, observation, approval=None, rollback_target=None,
              execution_intent=None):
    if approval is None:
        raise AuthorizationError('Trusted deployment authority unavailable; no execution')
    if type(request) is not Request:
        raise AuthorizationError('A release or untyped request cannot authorize deployment')
    root = Path(root).resolve()
    frozen_plan = canonical(plan)
    def recheck():
        fresh = build_request(root, json.loads(frozen_plan), request.operation, collector=collector,
                              observation=observation, repository_slug=request.repository_slug,
                              repository_id=request.repository_id, expires_at=request.expires_at,
                              rollback_target=rollback_target, execution_intent=execution_intent)
        if fresh != request:
            raise AuthorizationError('Deployment request or plan changed')
    recheck()
    with LifecycleLock(root, 'deployment-authorization'):
        if pending_upgrades(root):
            raise AuthorizationError('Recover unfinished upgrade before deployment authorization')
        recheck()
        collector.recheck(observation)
        grant = approval.validate(request)
        validate_grant(grant, request)
        relative = RECORDS + 'authorization-' + uuid.uuid4().hex + '.json'
        _assert_output(root, relative)
        result = dict(schemaVersion=1, kind='deployment-authorization-result', operation=request.operation,
                      requestHash=request.digest(), planHash=request.plan_hash, stateHash=request.state_hash,
                      runtimePolicyHash=request.runtime_policy_hash, environment=request.environment,
                      target=request.target, production=request.production, components=list(request.components),
                      status='pending', authorizationConsumed=False, executionAvailable=False,
                      productionReady=False, execution='not-performed', createdAt=clock().isoformat(),
                      verification=dict(runtime='authenticated-observation', health='unknown', smoke='unknown',
                                        backup='unknown', deployment='unknown', rollback='unknown'))
        # Authentication callbacks may wait. Inspect again before consuming rights.
        recheck()
        collector.recheck(observation)
        validate_grant(grant, request)
        started = clock()
        def before_consume():
            collector.recheck(observation)
            recheck()
            validate_grant(grant, request)
        try:
            receipt = approval.consume(grant, request, before_consume=before_consume)
            validate_receipt(receipt, grant, request, started)
        except Exception:
            result.update(status='consumption-unverified', failureCode='consumption-rejected-or-unknown')
            _audit(root, relative, result)
            raise
        result.update(status='consumed-verified', authorizationConsumed=True, grantId=grant.grant_id,
                      useNumber=receipt.use_number, consumedAt=receipt.consumed_at)
        _audit(root, relative, result)
        def final_check():
            validate_grant(grant, request)
            recheck()
            collector.recheck(observation)
            approval.guard(request)
            collector.recheck(observation)
            recheck()
            validate_grant(grant, request)
        try:
            final_check()
        except Exception:
            result.update(status='consumed-invalidated', failureCode='post-consumption-validation-failed')
            _audit(root, relative, result)
            raise
        _audit(root, relative, result)
        def execution_guard(runtime_check):
            validate_grant(grant, request)
            recheck()
            approval.guard(request)
            runtime_check()
            # The fixed executor verifies its expected intermediate Docker state.
            recheck()
            validate_grant(grant, request)
        permit = DeploymentPermit(request=request, grant=grant, receipt=receipt, check=final_check,
                                  result=result, execution_guard=execution_guard)
        _ISSUED_PERMITS.add(permit)
        return permit


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'authorize', 'execute'))
    args = parser.parse_args(argv)
    if args.action == 'status':
        print(json.dumps(dict(executionAvailable=False, productionReady=False,
                              trustedHostRequired=True, operations=list(OPERATIONS),
                              mode='host-authorization-only')))
        return 0
    print(json.dumps(dict(error='Trusted deployment host required; no local execution or authorization')), file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
