"""Trusted host journal and bounded cleanup-before recovery. No authority loader.

Private store/gate APIs are intentionally concrete. A host must inject this
coordinator; candidate JSON and reconstructed dataclasses confer no authority.
Unknown writes or lifecycle owners are preserved and block recovery.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time

import deployment_authorize as sdk
import deployment_execute as engine
import deployment_gateway as gateway
import deployment_runtime as runtime
from deployment_store import HostStore
from workflow_lock import LifecycleLock, linked, pending_upgrades, process_alive

DOMAIN = b'dev-workflow/deployment-recovery/journal/v1\0'
ZERO = '0' * 64
MAX_RECORD = 4 * 1024 * 1024
HEX = re.compile(r'[0-9a-f]{64}\Z')


class RecoveryError(ValueError):
    """Fixed diagnostic; never includes raw inspect, recipe or response data."""


def _require(value, code):
    if not value:
        raise RecoveryError(code)


def _hash(value):
    return runtime.digest(value)


def _hex(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def _start_identity_matches(previous, current, fields):
    """Preserve identity while allowing Docker's first-start initialization."""
    generated = set(runtime.MANAGED_FILES.values())
    if any(current.get(k) != previous.get(k) for k in fields
           if k not in generated | {'HostConfig'}):
        return False
    before_host, after_host = dict(previous['HostConfig']), dict(current['HostConfig'])
    if ('OomKillDisable' in before_host and 'OomKillDisable' in after_host
            and (before_host['OomKillDisable'] is None or before_host['OomKillDisable'] is False)
            and (after_host['OomKillDisable'] is None or after_host['OomKillDisable'] is False)):
        before_host['OomKillDisable'] = after_host['OomKillDisable'] = False
    if runtime.canonical(before_host) != runtime.canonical(after_host):
        return False
    for filename, key in runtime.MANAGED_FILES.items():
        before, after = previous.get(key), current.get(key)
        if before == after:
            continue
        if (previous.get('State', {}).get('Status') != 'created' or before not in ('', None)
                or type(after) is not str or not after.startswith('/')
                or not after.endswith('/' + current['Id'] + '/' + filename)
                or any(ord(c) < 32 for c in after)):
            return False
    return True


@dataclass(frozen=True)
class RecoveryRequest:
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
    runtime_policy_hash: str
    execution_policy_hash: str
    expires_at: str
    request_id: str
    operation_id: str
    journal_hash: str
    partial_hash: str
    fence_hash: str
    actions_json: str
    store_policy_hash: str
    gate_policy_hash: str
    max_uses: int = 1

    def __post_init__(self):
        _require(self.operation == 'deployment-recover' and type(self.repository) is str
                 and Path(self.repository).is_absolute() and str(Path(self.repository).resolve()) == self.repository
                 and type(self.repository_slug) is str and sdk.SLUG.fullmatch(self.repository_slug)
                 and all(x not in ('.', '..') for x in self.repository_slug.split('/'))
                 and type(self.repository_id) is int and self.repository_id > 0
                 and type(self.head_sha) is str and sdk.planner.SHA.fullmatch(self.head_sha)
                 and type(self.production) is bool and type(self.max_uses) is int and self.max_uses == 1
                 and type(self.components) is tuple and len(self.components) == 1
                 and all(type(x) is str and runtime.NAME.fullmatch(x)
                         for x in (*self.components, self.environment, self.target)), 'invalid-recovery-scope')
        _require(all(_hex(getattr(self, x)) for x in (
            'configuration_hash', 'runtime_policy_hash', 'execution_policy_hash', 'request_id',
            'operation_id', 'journal_hash', 'partial_hash', 'fence_hash', 'store_policy_hash', 'gate_policy_hash')),
            'invalid-recovery-binding')
        actions = runtime.parse_json(self.actions_json)
        _require(type(actions) is list and len(actions) <= 3
                 and runtime.canonical(actions) == self.actions_json
                 and all(type(x) is dict and set(x) == {'action', 'ref'}
                         and x['action'] in ('remove', 'create', 'start') and type(x['ref']) is str
                         and re.fullmatch(r'[a-z0-9_.-]{1,128}', x['ref']) for x in actions),
                 'invalid-recovery-actions')
        sdk._deadline(self.expires_at)

    def digest(self):
        return _hash(dict(domain='deployment-recovery-request-v1', **asdict(self)))


@dataclass(frozen=True)
class RecoveryGrant:
    grant_id: str
    request_hash: str
    expires_at: str
    max_uses: int


@dataclass(frozen=True)
class RecoveryReceipt:
    grant_id: str
    request_hash: str
    use_number: int
    consumed_at: str


def validate_grant(grant, request):
    _require(type(request) is RecoveryRequest and type(grant) is RecoveryGrant,
             'recovery-grant-domain-rejected')
    sdk._deadline(request.expires_at)
    _require(type(grant.grant_id) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', grant.grant_id)
             and grant.request_hash == request.digest() and type(grant.max_uses) is int and grant.max_uses == 1
             and sdk.clock() < sdk.timestamp(grant.expires_at) <= sdk.timestamp(request.expires_at),
             'invalid-recovery-grant')


def validate_receipt(receipt, grant, request, started):
    validate_grant(grant, request)
    _require(type(receipt) is RecoveryReceipt and receipt.grant_id == grant.grant_id
             and receipt.request_hash == request.digest() and type(receipt.use_number) is int
             and receipt.use_number == 1 and started - timedelta(seconds=1)
             <= sdk.timestamp(receipt.consumed_at) <= sdk.clock() + timedelta(seconds=30),
             'invalid-recovery-consumption')


@dataclass(frozen=True, eq=False)
class RecoveryPermit:
    request: RecoveryRequest
    grant: RecoveryGrant
    receipt: RecoveryReceipt


@dataclass(frozen=True, eq=False)
class HostOperation:
    """Exact coordinator-issued capability, valid only inside operation context."""
    _coordinator: HostCoordinator
    operation_id: str

    def validate(self, root, intent):
        c = self._coordinator
        if c._active == 'recovery':
            _require(c._recovery_writer is self and c._thread == threading.get_ident()
                     and Path(root).resolve() == c._root and intent is None
                     and c._recovery_permit.request.operation_id == self.operation_id, 'unissued-recovery-writer')
            c._fixed()
            return self
        _require(c._active is self and c._thread == threading.get_ident()
                 and c._intent is intent and Path(root).resolve() == c._root
                 and self.operation_id == json.loads(intent.binding_json)['intentId'], 'host-operation-not-active')
        c._fixed()
        _require(type(intent) is engine.ExecutionIntent and type(intent._issuer) is engine.DockerExecutor
                 and intent._issuer._issued.get(id(intent)) is c._record
                 and c._record['intent'] is intent and intent.binding_json == c._record['binding'],
                 'host-intent-identity-changed')
        if c._record['used'] and not c._record.get('active', False):
            plan = json.loads(c._record['plan'])
            _require(c._root_state(c._root) == (plan['headSha'], plan['configurationHash']), 'host-root-changed')
        else:
            intent.validate(root, json.loads(c._record['plan']), c._record['operation'], c.collector,
                            c._record['observation'], c._record['rollback_target'])
        return self

    def lifecycle(self, operation_name):
        self.validate(self._coordinator._root, self._coordinator._intent)
        _require(operation_name in ('deployment-authorization', 'deployment-execution'), 'invalid-core-phase')
        return LifecycleLock(self._coordinator._root, operation_name, transaction=self.operation_id)

    def record_owner(self, lock):
        c = self._coordinator
        self.validate(c._root, c._intent)
        _require(type(lock) is LifecycleLock and lock.owned and lock.root == c._root
                 and lock.transaction == self.operation_id, 'unowned-core-lock')
        owner = c._owner(c._root)
        _require(owner == dict(pid=os.getpid(), token=lock.token, operation=lock.operation,
                               transaction=self.operation_id), 'core-owner-mismatch')
        c._append(self.operation_id, 'owner', owner)

    def record_authorization(self, request, grant, receipt):
        c = self._coordinator
        self.validate(c._root, c._intent)
        sdk.validate_grant(grant, request)
        sdk.validate_receipt(receipt, grant, request, sdk.timestamp(receipt.consumed_at))
        _require(any(p.request is request and p.grant is grant and p.receipt is receipt
                     for p in sdk._ISSUED_PERMITS), 'actual-sdk-permit-required')
        _require(request.execution_json == c._intent.binding_json
                 and request.repository_id == c.store.policy.repository_id
                 and request.repository == str(c._root), 'journal-authorization-scope')
        c._append(self.operation_id, 'authorization', dict(request=asdict(request),
                   requestHash=request.digest(), receiptHash=_hash(asdict(receipt))))

    def check_gateway(self):
        return self._coordinator.check_gateway()

    def validate_writer(self, policy):
        c = self._coordinator
        self.validate(c._root, c._intent)
        _require(type(policy) is engine.ExecutionPolicy and policy == c.execution_policy
                 and policy.gateway_policy_hash == c.gate.policy.identity_hash()
                 and policy.history_policy_hash == c.store.policy.identity_hash(), 'writer-policy-mismatch')
        events = c._load(self.operation_id)
        owner = c._owner(c._root)
        _require(owner is not None and owner['pid'] == os.getpid()
                 and owner['transaction'] == self.operation_id
                 and any(e['kind'] == 'owner' and e['data'] == owner for e in events), 'writer-core-owner-unattested')
        if c._active == 'recovery':
            permit = c._recovery_permit
            validate_grant(permit.grant, permit.request)
            auth = c._last(events, 'recovery-authorization')
            _require(auth is not None and auth['requestHash'] == permit.request.digest()
                     and auth['receiptHash'] == _hash(asdict(permit.receipt))
                     and permit.request.execution_policy_hash == policy.identity_hash(), 'recovery-writer-authorization-mismatch')
        else:
            auth = c._last(events, 'authorization')
            _require(auth is not None, 'writer-authorization-required')
            permits = [p for p in sdk._ISSUED_PERMITS if p.request.digest() == auth['requestHash']
                       and _hash(asdict(p.receipt)) == auth['receiptHash']]
            _require(len(permits) == 1, 'writer-issued-permit-required')
            sdk.validate_grant(permits[0].grant, permits[0].request)
        return self

    def before_write(self, method, path, wire_body: bytes):
        c = self._coordinator
        self.validate(c._root, c._intent)
        return c._before_write(self.operation_id, c._root, method, path, wire_body)

    def after_write(self, session, response_digest: str):
        self.validate(self._coordinator._root, self._coordinator._intent)
        self._coordinator._after_write(self.operation_id, session, response_digest)

    def finish(self, result):
        c = self._coordinator
        self.validate(c._root, c._intent)
        if result.get('status') not in ('executed-verified', 'executed-unhealthy'):
            return False
        observation = result.get('observation')
        c.collector.validate(observation)
        c.collector.recheck(observation)
        events = c._load(self.operation_id)
        auth = c._last(events, 'authorization')
        _require(auth and sdk.ordered(observation.snapshot()['components']) ==
                 sdk.ordered(json.loads(auth['request']['after_json'])['components']), 'terminal-map-mismatch')
        _require(result.get('intentId') == self.operation_id and result.get('requestHash') == auth['requestHash']
                 and result.get('verification', {}).get('runtime') == 'verified', 'unverified-terminal-result')
        engine.DockerExecutor._stage(c._executor(), c._record, 4, result.get('containerId'),
                                    time.monotonic() + c.collector.policy.capture_deadline)
        _require(len([e for e in events if e['kind'] == 'attempt']) == 4
                 and len([e for e in events if e['kind'] == 'response']) == 4, 'terminal-write-evidence-incomplete')
        c._fence(events)
        for event in events:
            if event['kind'] == 'attempt':
                with c.gate._locked():
                    state = c.gate._state(event['data']['generation'])
                _require(len(state['admissions']) == 1 and all(
                         value['status'] == 'done' for value in state['admissions'].values()),
                         'terminal-upstream-evidence-required')
        c._append(self.operation_id, 'terminal', dict(status=result['status'], observationHash=observation.evidence_hash))
        return True


class HostCoordinator:
    def __init__(self, store, gate, collector, execution_policy, *, executor=None):
        _require(type(store) is HostStore and type(gate) is gateway.FileWriterGate
                 and type(collector) is runtime.TrustedDockerCollector
                 and type(execution_policy) is engine.ExecutionPolicy, 'concrete-host-adapters-required')
        store._check_policy(collector)
        _require(execution_policy.runtime_policy == collector.policy
                 and gate.policy.store_id == store.policy.store_id and gate.policy.key_id == store.policy.key_id
                 and gate.policy.scope_hash == _hash(store.policy._scope())
                 and gate.policy.writer_certificate_sha256 == execution_policy.writer_certificate_sha256,
                 'host-policy-scope-mismatch')
        self.store, self.gate, self.collector, self.execution_policy = store, gate, collector, execution_policy
        self._adapters = (store, gate, collector, execution_policy)
        self._binding = self._identity()
        self._active = self._thread = self._intent = self._record = self._root = None
        self._requests, self._permits = {}, {}
        self.executor = executor
        self._recovery_writer = self._recovery_permit = None

    def _identity(self):
        return _hash(dict(domain='deployment-host-coordinator-v1', store=self.store.policy.identity_hash(),
                          gate=self.gate.policy.identity_hash(), runtime=self.collector.policy.identity_hash(),
                          execution=self.execution_policy.identity_hash()))

    def identity_hash(self):
        self._fixed()
        return self._binding

    def _fixed(self):
        _require(all(current is original for current, original in zip(
                 (self.store, self.gate, self.collector, self.execution_policy), self._adapters)),
                 'host-adapter-changed')
        _require(self._identity() == self._binding, 'host-policy-changed')
        self.store._check_policy(self.collector)

    def _boundary(self, root):
        root = Path(root).resolve()
        _require(not any(root == p or root in p.parents or p in root.parents
                         for p in (self.store.root, self.gate.root)), 'candidate-host-directory-overlap')
        _require(not pending_upgrades(root), 'unfinished-upgrade')
        return root

    def _seal(self, payload):
        return dict(payload=payload, signature=hmac.new(self.store._key,
                    DOMAIN + runtime.canonical(payload).encode(), hashlib.sha256).hexdigest())

    def _ids(self):
        with self.store._directory() as directory:
            names = os.listdir(directory if directory is not None else self.store.root)
        found = set()
        for name in names:
            if name.startswith('journal-'):
                match = re.fullmatch(r'journal-([0-9a-f]{64})-([0-9]{8})\.json', name)
                _require(match is not None, 'unknown-journal-entry')
                found.add(match[1])
        return sorted(found)

    def _load(self, operation_id):
        _require(_hex(operation_id), 'invalid-operation-id')
        prefix = 'journal-' + operation_id + '-'
        with self.store._directory() as directory:
            names = sorted(n for n in os.listdir(directory if directory is not None else self.store.root)
                           if n.startswith(prefix))
            events, previous = [], ZERO
            for index, name in enumerate(names):
                _require(name == prefix + format(index, '08d') + '.json', 'journal-sequence-gap')
                fd = self.store._open(directory, name, os.O_RDONLY)
                with os.fdopen(fd, 'rb') as stream:
                    raw = stream.read(MAX_RECORD + 1)
                try:
                    envelope = runtime.parse_json(raw.decode('ascii'))
                    payload = envelope['payload']
                    expected = self._seal(payload)
                    _require(len(raw) <= MAX_RECORD and runtime.canonical(envelope).encode() == raw
                             and set(envelope) == {'payload', 'signature'}
                             and hmac.compare_digest(envelope['signature'], expected['signature'])
                             and payload['operationId'] == operation_id and payload['sequence'] == index
                             and payload['previous'] == previous and payload['store'] == self.store.policy.identity_hash(),
                             'journal-authentication-failed')
                except (KeyError, TypeError, ValueError, UnicodeError):
                    raise RecoveryError('journal-authentication-failed') from None
                previous = _hash(envelope)
                events.append(payload)
        _require(events and events[0]['kind'] == 'begin', 'journal-not-found')
        return events

    def _append(self, operation_id, kind, data, *, new=False):
        events = [] if new else self._load(operation_id)
        _require(not events or events[-1]['kind'] != 'terminal', 'journal-already-terminal')
        previous = ZERO if not events else _hash(self._seal(events[-1]))
        payload = dict(operationId=operation_id, sequence=len(events), previous=previous,
                       store=self.store.policy.identity_hash(), kind=kind, data=data)
        raw = runtime.canonical(self._seal(payload)).encode()
        _require(len(raw) <= MAX_RECORD, 'journal-record-too-large')
        name = 'journal-' + operation_id + '-' + format(len(events), '08d') + '.json'
        with self.store._directory() as directory:
            fd = self.store._open(directory, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if directory is not None:
                os.fsync(directory)
        return payload

    @staticmethod
    def _last(events, kind):
        return next((e['data'] for e in reversed(events) if e['kind'] == kind), None)

    @staticmethod
    def _owner(root):
        directory = root / '.dev-workflow/lifecycle.lock'
        for p in (directory.parent, directory, directory / 'owner.json', directory / 'recovery.lock'):
            _require(not linked(p), 'linked-core-owner')
        _require(not (directory / 'recovery.lock').exists(), 'unknown-core-recovery-guard')
        path = directory / 'owner.json'
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4096,
                         'unsafe-core-owner-file')
                raw = stream.read(4097)
            after = path.lstat()
            _require((info.st_dev, info.st_ino) == (after.st_dev, after.st_ino) and len(raw) <= 4096,
                     'core-owner-identity-changed')
            value = runtime.parse_json(raw.decode('utf-8'))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, UnicodeError):
            raise RecoveryError('unreadable-core-owner') from None
        _require(type(value) is dict and set(value) == {'pid', 'token', 'operation', 'transaction'}
                 and type(value['pid']) is int and value['pid'] > 0
                 and type(value['token']) is str and re.fullmatch(r'[0-9a-f]{32}', value['token'])
                 and _hex(value['transaction'])
                 and value['operation'] in ('deployment-authorization', 'deployment-execution', 'deployment-recovery'),
                 'unknown-core-owner')
        return value

    def _stale(self, root, events):
        begin = events[0]['data']
        _require(process_alive(begin['producerPID']) is False, 'producer-alive-or-unknown')
        owner = self._owner(root)
        if owner is not None:
            _require(any(e['kind'] == 'owner' and e['data'] == owner for e in events)
                     and owner['transaction'] == events[0]['operationId']
                     and process_alive(owner['pid']) is False, 'unattested-or-live-core-owner')
        return owner

    def check_gateway(self):
        self._fixed()
        info = self.collector.client.get('/v1.45/workflow/gate-info',
                                         deadline=time.monotonic() + self.collector.policy.capture_deadline)
        self.gate.verify_info(info)
        return True

    @contextmanager
    def operation(self, root, plan, intent):
        _require(self._active is None, 'host-operation-already-active')
        root = self._boundary(root)
        _require(type(intent) is engine.ExecutionIntent and type(intent._issuer) is engine.DockerExecutor,
                 'issued-execution-intent-required')
        executor = intent._issuer
        record = executor._issued.get(id(intent))
        _require(record is not None and record['intent'] is intent and executor.policy == self.execution_policy
                 and executor.collector is self.collector, 'intent-coordinator-mismatch')
        intent.validate(root, plan, record['operation'], self.collector, record['observation'], record['rollback_target'])
        with self.store.target_lock():
            self._fixed()
            self.executor = executor
            for oid in self._ids():
                _require(self._load(oid)[-1]['kind'] == 'terminal', 'unresolved-host-operation')
            self.check_gateway()
            binding = json.loads(intent.binding_json)
            baseline = json.loads(record['baseline'])
            old = baseline[binding['beforeContainerId']]
            spec = engine._specifications(self.collector.policy).get((binding['component'], old['Image']))
            _require(spec is not None and spec.matches(old), 'retained-before-spec-required')
            history = self.store.capture_history(self.collector, record['observation'])
            fields = ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'Created', 'Name', 'Path', 'Args',
                      'RestartCount', 'HostsPath', 'HostnamePath', 'ResolvConfPath')
            begin = dict(root=str(root), producerPID=os.getpid(), binding=binding, planHash=_hash(plan),
                         coordinatorHash=self.identity_hash(), history=history,
                         before=record['observation'].to_dict(), oldSpecHash=_hash(spec.to_dict()),
                         oldStableHash=_hash({k: old.get(k) for k in fields}), oldName=old['Name'],
                         oldStartedAt=old['State']['StartedAt'], baseline={k: _hash(v) for k, v in baseline.items()},
                         knownNames={v['Name'].lstrip('/'): k for k, v in baseline.items()},
                         fields=list(fields))
            self._append(binding['intentId'], 'begin', begin, new=True)
            op = HostOperation(self, binding['intentId'])
            self._active, self._thread, self._intent, self._record, self._root = op, threading.get_ident(), intent, record, root
            try:
                yield op
            finally:
                self._active = self._thread = self._intent = self._record = self._root = None

    def _approved_write(self, oid, events):
        begin = events[0]['data']
        binding = begin['binding']
        if self._active == 'recovery':
            request = self._recovery_permit.request
            start = max(i for i, event in enumerate(events) if event['kind'] == 'recovery-authorization')
            phase = events[start + 1:]
            actions = json.loads(request.actions_json)
            old_image = next(x['imageId'] for x in begin['before']['instances']
                             if x['containerId'] == binding['beforeContainerId'])
            spec = engine._specifications(self.collector.policy)[(binding['component'], old_image)]
        else:
            phase = events
            actions = [dict(action=action, ref=(binding['resourceName'] if action in ('create', 'start')
                       else binding['beforeContainerId'])) for action in binding['actions']]
            spec = self._record['spec']
        attempts = [e['data']['generation'] for e in phase if e['kind'] == 'attempt']
        responses = [e['data']['generation'] for e in phase if e['kind'] == 'response']
        _require(attempts == responses and len(attempts) < len(actions), 'previous-write-unresolved-or-actions-exhausted')
        action = actions[len(attempts)]
        verb, ref = action['action'], action['ref']
        body = b''
        if verb == 'create':
            method, suffix = 'POST', 'create?name=' + ref
            body = engine.canonical(spec.to_create(self.collector.policy.project, oid)).encode()
        else:
            if not runtime.CONTAINER.fullmatch(ref):
                known = {cid for event in phase if event['kind'] == 'response'
                         for cid, value in event['data']['known'].items() if value['name'] == ref}
                _require(len(known) == 1, 'approved-resource-id-unknown')
                ref = known.pop()
            method, suffix = {
                'stop': ('POST', ref + '/stop?t=' + str(self.execution_policy.stop_timeout)),
                'remove': ('DELETE', ref + '?force=false&v=false'),
                'start': ('POST', ref + '/start')}[verb]
        return method, '/v1.45/containers/' + suffix, hashlib.sha256(body).hexdigest()

    def _before_write(self, oid, root, method, path, wire_body):
        _require(type(wire_body) is bytes, 'wire-body-required')
        events = self._load(oid)
        auth = self._last(events, 'recovery-authorization') or self._last(events, 'authorization')
        _require(auth is not None, 'consumed-authorization-required')
        owner = self._owner(root)
        _require(owner is not None and owner['pid'] == os.getpid()
                 and any(e['kind'] == 'owner' and e['data'] == owner for e in events), 'attested-core-owner-required')
        operation = (method, path, hashlib.sha256(wire_body).hexdigest())
        _require(operation == self._approved_write(oid, events), 'write-outside-exact-approved-action')
        generation = _hash(dict(domain='deployment-writer-generation-v1', operationId=oid,
                                requestHash=auth['requestHash'], operation=operation, nonce=secrets.token_hex(32)))
        gateway._operation(*operation)
        # Journal first: even failure to open leaves an explicit unresolved attempt.
        inventory = engine.DockerExecutor._inventory(self._executor(),
                    time.monotonic() + self.collector.policy.capture_deadline)
        known = {cid: dict(name=value['Name'].lstrip('/'), inspectHash=_hash(value))
                 for cid, value in inventory.items()}
        self._append(oid, 'attempt', dict(generation=generation, method=method, path=path,
                                        bodyHash=operation[2], owner=owner, known=known))
        return self.gate.open_generation(generation=generation, request_hash=auth['requestHash'],
                                        receipt_hash=auth['receiptHash'], operations=(operation,))

    def _after_write(self, oid, session, response_digest):
        _require(type(session) is gateway.WriterSession and session._gate is self.gate
                 and self.gate._sessions.get(session.generation) is session
                 and _hex(response_digest) and any(e['kind'] == 'attempt'
                 and e['data']['generation'] == session.generation for e in self._load(oid)), 'unknown-writer-session')
        proof = self.gate.close_generation(session.generation)
        self.gate.validate_proof(proof)
        inventory = engine.DockerExecutor._inventory(self._executor(),
                    time.monotonic() + self.collector.policy.capture_deadline)
        known = {cid: dict(name=value['Name'].lstrip('/'), inspectHash=_hash(value))
                 for cid, value in inventory.items()}
        self._append(oid, 'response', dict(generation=session.generation, responseHash=response_digest, known=known))

    def _fence(self, events):
        proofs = []
        for event in events:
            if event['kind'] == 'attempt':
                proof = self.gate.close_generation(event['data']['generation'])
                self.gate.validate_proof(proof)
                proofs.append(json.loads(proof.to_json()))
        return _hash(proofs)

    def _executor(self):
        executor = self.executor
        _require(type(executor) is engine.DockerExecutor and executor.policy == self.execution_policy
                 and executor.collector is self.collector, 'trusted-recovery-executor-required')
        engine.DockerExecutor._fixed(executor)
        return executor

    def inspect(self, root, operation_id):
        with self.store.target_lock():
            return self._inspect(root, operation_id)

    def _inspect(self, root, oid):
        self._fixed()
        root = self._boundary(root)
        events = self._load(oid)
        begin = events[0]['data']
        _require(begin['root'] == str(root) and begin['coordinatorHash'] == self.identity_hash()
                 and events[-1]['kind'] != 'terminal', 'journal-scope-or-terminal')
        fence = self._fence(events)
        owner = self._stale(root, events)
        fence = _hash(dict(gatewayProofs=fence, coreOwner=owner, producerPID=begin['producerPID']))
        deadline = time.monotonic() + self.collector.policy.capture_deadline
        current = engine.DockerExecutor._inventory(self._executor(), deadline)
        b = begin['binding']
        old_id, candidate_name = b['beforeContainerId'], b['resourceName']
        restore_name = 'dev-workflow-recover-' + oid
        # Direct lookups defeat relabelled or omitted known resources. Only the
        # fixed reader may interpret an actual server 404 as None.
        lookup = getattr(self.collector.client, 'lookup_container', None)
        _require(callable(lookup), 'trusted-direct-lookup-required')
        known_names = dict(begin['knownNames'])
        for event in events:
            if event['kind'] in ('attempt', 'response'):
                for cid, value in event['data']['known'].items():
                    name = value['name']
                    _require(name not in known_names or known_names[name] == cid, 'recorded-resource-name-reassigned')
                    known_names[name] = cid
        names = {old_id, begin['oldName'].lstrip('/'), candidate_name, restore_name, *known_names, *known_names.values(),
                 *begin['baseline'], *current}
        for event in events:
            if event['kind'] == 'attempt':
                match = re.match(r'/v1\.45/containers/([0-9a-f]{64})(?:/|\?)', event['data']['path'])
                if match:
                    names.add(match[1])
        direct = {}
        for ref in sorted(names):
            value = lookup(ref, deadline=deadline)
            expected_ids = [cid for cid, item in current.items()
                            if ref in (cid, item.get('Name', '').lstrip('/'))]
            _require(len(expected_ids) <= 1 and (value is not None) == bool(expected_ids),
                     'direct-lookup-presence-mismatch')
            if value is not None:
                _require(type(value) is dict and value.get('Id') == expected_ids[0] and value.get('Id') in current, 'known-resource-outside-inventory')
                actual = dict(current[value['Id']])
                actual.pop('_workflowManagedFiles', None)
                _require(actual == value, 'direct-inventory-mismatch')
                direct[ref] = value['Id']
        _require(all(name not in direct or direct[name] == cid for name, cid in known_names.items()),
                 'known-name-reassigned')
        for cid, before_hash in begin['baseline'].items():
            if cid != old_id:
                _require(cid in current and _hash(current[cid]) == before_hash, 'unselected-runtime-drift')
        candidate = current.get(direct.get(candidate_name))
        restored = current.get(direct.get(restore_name))
        old = current.get(old_id)
        allowed = set(begin['baseline']) - {old_id}
        allowed.update(x['Id'] for x in (old, candidate, restored) if x is not None)
        _require(set(current) == allowed and not (old and restored), 'foreign-or-ambiguous-inventory')
        history = self.store._read(begin['history'])
        _require(self.store._entries(self.collector.policy, begin['before']) == history['entries'],
                 'historical-catalog-or-recipe-changed')
        specs = engine._specifications(self.collector.policy)
        old_image = next(x['imageId'] for x in begin['before']['instances'] if x['containerId'] == old_id)
        old_spec = specs.get((b['component'], old_image))
        new_spec = specs.get((b['component'], b['imageId']))
        _require(old_spec is not None and _hash(old_spec.to_dict()) == begin['oldSpecHash']
                 and new_spec is not None and new_spec.configuration_digest() == b['specHash'], 'retained-spec-changed')
        executor = self._executor()
        catalog = runtime._catalog(self.collector.policy)
        for spec in (old_spec, new_spec):
            engine.DockerExecutor._image(executor, dict(spec=spec, entry=catalog[(spec.component, spec.image_id)]), deadline)
        if executor.verifier is not None:
            from deployment_verify import TrustedProbeVerifier
            TrustedProbeVerifier.bind(executor.verifier, b['component'], old_spec)
            TrustedProbeVerifier.bind(executor.verifier, b['component'], new_spec)
        forwarded = set()
        for event in events:
            if event['kind'] == 'attempt':
                with self.gate._locked():
                    state = self.gate._state(event['data']['generation'])
                if any(value['status'] == 'done' and state['attempts'][ref] == [event['data']['method'],
                       event['data']['path'], event['data']['bodyHash']]
                       for ref, value in state['admissions'].items()):
                    forwarded.add(event['data']['generation'])
        def attempted(method, suffix, body=None):
            return any(e['kind'] == 'attempt' and e['data']['generation'] in forwarded
                       and e['data']['method'] == method
                       and e['data']['path'] == '/v1.45/containers/' + suffix
                       and (body is None or e['data']['bodyHash'] == hashlib.sha256(body).hexdigest()) for e in events)
        def verify_created(value, spec, name):
            _require(spec.matches(value) and value.get('Name') == '/' + name
                     and value.get('Config', {}).get('Labels') ==
                     spec.to_create(self.collector.policy.project, oid)['Labels']
                     and value.get('RestartCount') == 0
                     and attempted('POST', 'create?name=' + name,
                                   engine.canonical(spec.to_create(self.collector.policy.project, oid)).encode()),
                     'unreachable-or-changed-created-resource')
        if old:
            _require(old_spec.matches(old) and _hash({k: old.get(k) for k in begin['fields']}) == begin['oldStableHash'],
                     'old-container-identity-changed')
            if engine.DockerExecutor._running(old):
                _require(_hash(old) == begin['baseline'][old_id]
                         or attempted('POST', old_id + '/start'), 'unreachable-old-running')
            else:
                _require(engine.DockerExecutor._stopped(old) and old['State']['StartedAt'] == begin['oldStartedAt']
                         and attempted('POST', old_id + '/stop?t=' + str(self.execution_policy.stop_timeout)),
                         'unreachable-old-stopped')
        else:
            _require(attempted('DELETE', old_id + '?force=false&v=false'), 'unreachable-old-absent')
        if candidate:
            verify_created(candidate, new_spec, candidate_name)
        if restored:
            verify_created(restored, old_spec, restore_name)
        actions = []
        if candidate and engine.DockerExecutor._running(candidate):
            _require(old is None and restored is None and attempted('POST', candidate['Id'] + '/start'),
                     'unreachable-after-complete')
            state = 'after-complete'
        else:
            if candidate:
                _require(engine.DockerExecutor._stopped(candidate, created=True), 'candidate-not-safely-stopped')
                actions.append(dict(action='remove', ref=candidate['Id']))
            if old:
                running = engine.DockerExecutor._running(old)
                state = ('candidate-stopped-old-running' if candidate else 'before-complete') if running else (
                    'candidate-stopped-old-stopped' if candidate else 'old-stopped-only')
                if not running:
                    actions.append(dict(action='start', ref=old_id))
            elif restored:
                running = engine.DockerExecutor._running(restored)
                _require(running or engine.DockerExecutor._stopped(restored, created=True), 'restoration-state-unknown')
                if running:
                    _require(attempted('POST', restored['Id'] + '/start'), 'unreachable-restoration-running')
                state = 'retained-restoration-running' if running else 'retained-restoration-stopped'
                if not running:
                    actions.append(dict(action='start', ref=restored['Id']))
            else:
                _require(candidate is not None, 'unsupported-empty-selected-state')
                state = 'old-absent-candidate-stopped'
                actions.extend((dict(action='create', ref=restore_name), dict(action='start', ref=restore_name)))
        return dict(state=state, operationId=oid, journalHash=_hash(self._seal(events[-1])),
                    partialHash=_hash(current), fenceHash=fence, coreOwnerHash=_hash(owner), actions=actions)

    def _root_state(self, root):
        resolved = sdk.planner.resolve_configuration(root)
        _require(resolved['source'] == 'project' and not resolved['errors']
                 and not any(x['code'] == 'config.drift' for x in resolved['warnings'])
                 and not sdk.planner.offline_worktree_status(root), 'recovery-root-invalid')
        return (sdk.planner.git(root, 'rev-parse', '--verify', 'HEAD^{commit}'),
                hashlib.sha256(sdk.planner.path_at(root, 'workflow.config.json').read_bytes()).hexdigest())

    def prepare_recovery(self, root, operation_id, *, expires_at):
        with self.store.target_lock():
            partial = self._inspect(root, operation_id)
            root = Path(root).resolve()
            head, configuration = self._root_state(root)
            p = self.collector.policy
            request = RecoveryRequest(operation='deployment-recover', repository=str(root), repository_slug=p.repository,
                repository_id=self.store.policy.repository_id, head_sha=head, configuration_hash=configuration,
                environment=p.environment, target=p.target, production=p.production,
                components=(self._load(operation_id)[0]['data']['binding']['component'],),
                runtime_policy_hash=p.identity_hash(), execution_policy_hash=self.execution_policy.identity_hash(),
                expires_at=expires_at, request_id=secrets.token_hex(32), operation_id=operation_id,
                journal_hash=partial['journalHash'], partial_hash=partial['partialHash'], fence_hash=partial['fenceHash'],
                actions_json=runtime.canonical(partial['actions']), store_policy_hash=self.store.policy.identity_hash(),
                gate_policy_hash=self.gate.policy.identity_hash())
            self._requests[id(request)] = (request, partial)
            return request

    def _ready(self, request):
        issued = self._requests.get(id(request))
        _require(type(request) is RecoveryRequest and issued is not None and issued[0] is request,
                 'unissued-recovery-request')
        sdk._deadline(request.expires_at)
        _require(self._root_state(Path(request.repository)) == (request.head_sha, request.configuration_hash),
                 'recovery-root-changed')
        _require(self._inspect(request.repository, request.operation_id) == issued[1], 'recovery-state-changed')
        self.check_gateway()

    def authorize_recovery(self, request, *, approval):
        _require(self._thread == threading.get_ident() and self._active == 'recovery', 'held-recovery-session-required')
        self._ready(request)
        grant = approval.validate(request)
        validate_grant(grant, request)
        started = sdk.clock()
        def before_consume():
            self._ready(request)
            validate_grant(grant, request)
        receipt = approval.consume(grant, request, before_consume=before_consume)
        validate_receipt(receipt, grant, request, started)
        self._ready(request)
        approval.guard(request)
        self._ready(request)
        permit = RecoveryPermit(request, grant, receipt)
        self._permits[id(permit)] = (permit, approval)
        return permit

    def recover(self, request, approval):
        _require(self._active is None, 'host-operation-already-active')
        with self.store.target_lock():
            self._active, self._thread = 'recovery', threading.get_ident()
            try:
                permit = self.authorize_recovery(request, approval=approval)
                return self.execute_recovery(permit)
            finally:
                self._active = self._thread = self._root = None
                self._recovery_writer = self._recovery_permit = None

    def execute_recovery(self, permit):
        _require(self._active == 'recovery' and self._thread == threading.get_ident()
                 and type(permit) is RecoveryPermit and id(permit) in self._permits
                 and self._permits[id(permit)][0] is permit, 'held-issued-recovery-permit-required')
        _, approval = self._permits.pop(id(permit))
        request = permit.request
        self._ready(request)
        validate_grant(permit.grant, request)
        approval.guard(request)
        self._ready(request)
        root, oid = Path(request.repository), request.operation_id
        events = self._load(oid)
        attested_owner = self._stale(root, events)
        _require(_hash(attested_owner) == self._requests[id(request)][1]['coreOwnerHash'],
                 'prepared-core-owner-changed')
        self._append(oid, 'recovery-authorization', dict(requestHash=request.digest(),
                     receiptHash=_hash(asdict(permit.receipt)), request=asdict(request)))
        # Reclaim only after new, typed, consumed authority and exact dead owner.
        with LifecycleLock(root, 'deployment-recovery', transaction=oid,
                           recover=attested_owner is not None, expected_owner=attested_owner) as lock:
            owner = self._owner(root)
            _require(lock.owned and owner['token'] == lock.token, 'recovery-core-owner-mismatch')
            self._append(oid, 'owner', owner)
            writer = HostOperation(self, oid)
            self._recovery_writer, self._recovery_permit, self._root = writer, permit, root
            # The root supplies the already-fenced mutation client explicitly.
            client = self._executor().client
            _require(type(client) is engine.DockerMutationClient and client.policy == self.execution_policy,
                     'recovery-mutation-client-required')
            expected = request.partial_hash
            deadline = time.monotonic() + self.execution_policy.execution_deadline
            executor = self._executor()
            previous_inventory = engine.DockerExecutor._inventory(executor, deadline)
            _require(_hash(previous_inventory) == expected, 'recovery-stage-drift')
            def guard():
                self._fixed()
                validate_grant(permit.grant, request)
                _require(self._root_state(root) == (request.head_sha, request.configuration_hash), 'recovery-root-changed')
                _require(self._owner(root) == owner, 'recovery-core-owner-changed')
                _require(_hash(engine.DockerExecutor._inventory(executor, deadline)) == expected, 'recovery-stage-drift')
                approval.guard(request)
                _require(_hash(engine.DockerExecutor._inventory(executor, deadline)) == expected, 'recovery-stage-drift')
                validate_grant(permit.grant, request)
                _require(self._root_state(root) == (request.head_sha, request.configuration_hash)
                         and self._owner(root) == owner, 'recovery-final-root-or-owner-changed')
                return deadline
            begin = events[0]['data']
            image = next(x['imageId'] for x in begin['before']['instances']
                         if x['containerId'] == begin['binding']['beforeContainerId'])
            spec = engine._specifications(self.collector.policy)[(request.components[0], image)]
            created = {}
            for action in json.loads(request.actions_json):
                guard()
                verb, ref = action['action'], action['ref']
                target = created.get(ref, ref)
                if verb == 'create':
                    payload = spec.to_create(self.collector.policy.project, oid)
                else:
                    _require(runtime.CONTAINER.fullmatch(target), 'recovery-target-id-required')
                # The actual mutation client journals/open/prepares the exact
                # generation via this issued HostOperation before its last guard.
                if verb == 'create':
                    response = client.create(ref, payload, before_send=guard, host_operation=writer)
                    created[ref] = response['Id']
                else:
                    response = getattr(client, verb)(target, before_send=guard, host_operation=writer)
                current = engine.DockerExecutor._inventory(executor, deadline)
                # Prove the exact post-write state before accepting a next write.
                before = expected
                if verb == 'remove':
                    _require(target not in current, 'recovery-remove-unverified')
                elif verb == 'create':
                    value = current.get(created[ref])
                    _require(value is not None and spec.matches(value)
                             and value.get('Config', {}).get('Labels') == payload['Labels']
                             and value['Name'] == '/' + ref and engine.DockerExecutor._stopped(value, created=True),
                             'recovery-create-unverified')
                else:
                    _require(target in current and spec.matches(current[target])
                             and engine.DockerExecutor._running(current[target]), 'recovery-start-unverified')
                # Whole-inventory transition is verified below, not accepted by
                # changing the guard baseline on an unexplained observation.
                _require(previous_inventory is not None and _hash(previous_inventory) == before,
                         'recovery-transition-baseline-required')
                allowed = set(previous_inventory)
                if verb == 'remove':
                    allowed.remove(target)
                elif verb == 'create':
                    allowed.add(created[ref])
                _require(set(current) == allowed and all(current[cid] == value for cid, value in previous_inventory.items()
                         if cid != target or verb == 'create'), 'recovery-unselected-transition-drift')
                if verb == 'start':
                    _require(_start_identity_matches(previous_inventory[target], current[target], begin['fields']),
                             'recovery-start-identity-drift')
                previous_inventory = current
                expected = _hash(current)
            guard()
            observation = self.collector.collect()
            self.collector.validate(observation)
            auth = self._last(events, 'authorization')
            wanted = (json.loads(auth['request']['after_json']) if self._requests[id(request)][1]['state'] == 'after-complete'
                      else begin['before']['snapshot'])
            _require(sdk.ordered(observation.snapshot()['components']) == sdk.ordered(wanted['components']),
                     'recovery-final-map-mismatch')
            guard()
            verification = dict(health='unknown', smoke='unknown', checks=[])
            if executor.verifier is not None:
                from deployment_verify import TrustedProbeVerifier
                selected = next(x['containerId'] for x in observation.to_dict()['instances']
                                if x['component'] == request.components[0])
                selected_spec = engine._specifications(self.collector.policy)[
                    (request.components[0], previous_inventory[selected]['Image'])]
                binding = TrustedProbeVerifier.bind(executor.verifier, request.components[0], selected_spec)
                verification = TrustedProbeVerifier.check(executor.verifier, binding,
                    container=previous_inventory[selected], guard=guard, deadline=deadline)
                guard()
                self.collector.recheck(observation)
            self._fence(self._load(oid))
            self._append(oid, 'terminal', dict(status='recovered-runtime-verified', requestHash=request.digest(),
                                             observationHash=observation.evidence_hash))
            return dict(status='recovered-runtime-verified', productionReady=False, health=verification['health'], smoke=verification['smoke'],
                        probeChecks=verification['checks'], observation=observation, actions=json.loads(request.actions_json))


def main(argv=None):
    raise SystemExit('Recovery requires an explicitly injected trusted host; no CLI replay is available')


if __name__ == '__main__':
    main()
