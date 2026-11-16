"""Independent, scoped admission for signed retained-frontend witness RPCs.

An installed controller registers an exact consumed approval with the receipt
returned by consume(), the private plan, and independently verified live scope
and writer-origin evidence. It authenticates the owned worker channel before
calling authorize_rpc(). None of these inputs is accepted from a witness RPC.
Each request uses its digest as the directory name under the controller's
registered witness root, and registration never resets an existing chain.
The broker has no server, Engine access, or restart/adoption path.
"""
import base64
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import threading

from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
from deployment_compose_operation_witness_client_v3 import (
    NAMESPACE, OperationWitnessClientV3, decode_material,
    dispatch_request, encode, validate_request,
)
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_compose_production_frontend_approval_v1_host import (
    GitHubProductionFrontendApprovalV2, GitHubProductionFrontendApprovalV3, ProductionFrontendReceiptV1,
    prepare_production_frontend_request,
)
from deployment_compose_retained_write_v1_host import RetainedWriteV1
from deployment_compose_witness_store import ZERO, canonical, hex_value, pairs
from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material
from deployment_gateway import GatePolicy
from release_host import timestamp

_ROOT = Path(__file__).resolve().parents[1]
_SSH_KEYGEN = '/usr/bin/ssh-keygen'
_METHODS = frozenset(('read', 'chain_status', 'check', 'events_after', 'append_event', 'transition_successor'))
_MAX_RPC = 4096
_LINEAGE_NAMESPACE = NAMESPACE + '-retained-lineage'
_CHECKPOINT_NAMESPACE = NAMESPACE + '-retained-checkpoint'
_APPROVAL_TYPES = {'2': GitHubProductionFrontendApprovalV2, '3': GitHubProductionFrontendApprovalV3}


def reject():
    raise ValueError('retained-frontend-witness-admission-rejected') from None


def _digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _signer_pin(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        reject()
    return info.st_dev, info.st_ino, info.st_ctime_ns


class RetainedWitnessAdmissionV1:
    """Own one approval's witness chain on the independent controller."""

    # The Gate event format and HMAC scope are unchanged. Request registration
    # and successor selection are specific to the retained production plan.
    _unseal = MacLiveAdmissionV3._unseal
    _validate_event = MacLiveAdmissionV3._validate_event
    _consent = staticmethod(MacLiveAdmissionV3._consent)
    _append = MacLiveAdmissionV3._append

    def __init__(self, *, store, gate_policy, gate_key, witness_signer, witness_public_key,
                 private_plan, review, request, approval, consumption,
                 scope_generation, writer_origin_digest, parent=None, recovery_source=None):
        if (type(store) is not OperationWitnessStoreV3 or type(gate_policy) is not GatePolicy
                or gate_policy.operation_profile != 'compose-v3' or gate_policy.witness_required is not True
                or type(gate_key) is not bytes or not 32 <= len(gate_key) <= 4096
                or type(request) is not RequestV2 or type(approval) is not _APPROVAL_TYPES.get(request.profile_version)
                or type(consumption) is not ProductionFrontendReceiptV1
                or type(scope_generation) is not int or not 1 <= scope_generation < 2**53
                or not hex_value(writer_origin_digest)):
            reject()
        if (consumption.request_hash != request.digest() or type(consumption.use_number) is not int
                or consumption.use_number != 1
                or consumption.grant_id != f'{approval.grant_namespace}:{approval.policy.run_id}:{request.operation}'
                or not timestamp(consumption.consumed_at) < timestamp(request.expires_at)
                or timestamp(consumption.consumed_at) > datetime.now(timezone.utc)):
            reject()

        frozen_review = deepcopy(review)
        expected = prepare_production_frontend_request(
            frozen_review, policy_hash=approval.policy.policy_hash,
            expires_at=request.expires_at, operation=request.operation,
        )
        if expected != request:
            reject()
        cutover = frozen_review.pop('retainedCutover')
        plan = prepare_retained_frontend_cutover(private_plan, operation_nonce=cutover['operationNonce'])
        if plan.digest != cutover['planDigest'] or canonical(private_plan['publicReview']) != canonical(frozen_review):
            reject()
        private = store.root.parent.resolve(strict=True)
        if (store.root.name != request.digest() or private.is_relative_to(_ROOT)
                or private.stat().st_uid != os.getuid()
                or stat.S_IMODE(private.stat().st_mode) != 0o700
                or not isinstance(witness_signer, Path) or witness_signer.parent != private):
            reject()
        self._lineage_parent_id = (private.stat().st_dev, private.stat().st_ino)
        self._signer = witness_signer
        self._signer_pin = _signer_pin(witness_signer)
        self._public = key_material(witness_public_key)
        actual = subprocess.run([_SSH_KEYGEN, '-y', '-f', str(witness_signer)], capture_output=True,
                                check=True, timeout=10, env={'PATH': '/usr/bin:/bin'}).stdout
        if (key_material(actual) != self._public or _signer_pin(witness_signer) != self._signer_pin
                or hashlib.sha256(self._public).hexdigest() != gate_policy.witness_key_sha256):
            reject()

        self._owner = os.getpid()
        self._lock = threading.RLock()
        self._store, self._policy, self._key = store, gate_policy, gate_key
        self._plan, self._cutover = plan, cutover
        self._stage = cutover.get('stage')
        self._scope_generation = scope_generation
        self._origin = writer_origin_digest
        self._entry = dict(request=request, approval=approval, receiptHash=_digest(asdict(consumption)))
        self._execution_digest = _digest(dict(
            plan=plan.digest, approvedReview=request.plan_hash, protection=cutover['protectionDigest'],
            scopeGeneration=scope_generation, writerOrigin=writer_origin_digest,
        ))
        self._epoch = secrets.token_hex(32)
        self._seen = set()
        self._scopes = []
        self._frozen = False
        self._candidate = None
        self._state = None
        self._lineage_digest = None
        self._consent(self._entry)
        if 'recoveryEvidenceDigest' in cutover:
            if parent is not None:
                reject()
            self._register_recovered(recovery_source, private_plan, review)
        elif recovery_source is not None:
            reject()
        elif self._stage is not None:
            self._register_staged(parent)
        elif request.operation == 'deploy':
            if parent is not None:
                reject()
            self._register(plan.create())
        elif request.operation == 'rollback' and type(parent) is RetainedWitnessAdmissionV1:
            with parent._lock:
                parent._check_parent(self)
                self._candidate = cutover['candidateId']
                # Do not leave an admitted parent writable if registration is
                # interrupted or its result becomes uncertain.
                parent._frozen = True
                self._register(self._restore_operations()[0])
        else:
            reject()

    def _register_recovered(self, source, private_plan, review):
        from deployment_compose_retained_recovery_handoff_v1_host import verify_crash_rollback_evidence

        if (type(source) is not dict or set(source) != {'root', 'pending', 'public_key', 'expected_key_hash'}
                or source['root'] == self._store.root.parent):
            reject()
        report = verify_crash_rollback_evidence(**source, private_plan=private_plan, review=review)
        if report['pending']['generation'] != self._scope_generation:
            reject()
        switch = report['stages'][-1]
        self._candidate = self._cutover['candidateId']
        operation, = self._restore_operations()
        self._register(operation, lineage=True, predecessor=(switch['firstBinding'], switch['lineageDigest']))

    def _register_staged(self, parent):
        if self._stage == 'create':
            if parent is not None:
                reject()
            self._register(self._plan.create(), lineage=True)
            return
        if type(parent) is not RetainedWitnessAdmissionV1:
            reject()
        with parent._lock:
            parent._check_staged_parent(self)
            self._candidate = self._cutover['candidateId']
            operations = self._plan.switch(self._candidate) if self._stage == 'switch' else self._restore_operations()
            parent._frozen = True
            self._register(operations[0], lineage=True, predecessor=(parent.first_binding, parent._lineage_digest))

    def __copy__(self):
        reject()

    def __deepcopy__(self, memo):
        reject()

    def __reduce_ex__(self, protocol):
        reject()

    @property
    def first_binding(self):
        return deepcopy(self._scopes[0]['binding'])

    @property
    def receipt_hash(self):
        return self._entry['receiptHash']

    @property
    def execution_digest(self):
        return self._execution_digest

    def _check_owner(self):
        if os.getpid() != self._owner:
            reject()

    def _state_pin(self):
        info = os.stat('state.json', dir_fd=self._store._dir, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            reject()
        return info.st_dev, info.st_ino, info.st_ctime_ns

    def _descriptor(self, operation, index):
        request = self._entry['request']
        desc = RetainedWriteV1.scope_descriptor(
            operation, request_hash=request.digest(), receipt_hash=self.receipt_hash,
            plan_digest=self.execution_digest, index=index,
        )
        binding = dict(scopeHash=desc['scopeHash'], epoch=self._epoch, generation=desc['generation'],
                       policyHash=self._policy.identity_hash())
        return dict(binding=binding, descriptor=desc, entry=self._entry, operation=operation)

    def _register(self, first, *, lineage=False, predecessor=(None, None)):
        scope = self._descriptor(first, 0)
        if self._policy.witness_scope_hash != scope['binding']['scopeHash']:
            reject()
        if lineage:
            self._persist_lineage(scope['binding'], predecessor)
        self._store.register_once(scope['binding'])
        self._state = self._state_pin()
        self._scopes.append(scope)
        if lineage:
            self._persist_checkpoint(None, [])

    def _persist_lineage(self, binding, predecessor):
        request = self._entry['request']
        evidence = dict(
            schemaVersion=1, kind='retained-stage-lineage', stage=self._stage,
            requestHash=request.digest(), receiptHash=self.receipt_hash, reviewHash=request.plan_hash,
            scopeGeneration=self._scope_generation, writerOrigin=self._origin, cutover=self._cutover,
            firstBinding=binding, parentBinding=predecessor[0], parentLineageDigest=predecessor[1],
        )
        name = self._lineage_name()
        self._lineage_digest = self._persist_signed(name, evidence, _LINEAGE_NAMESPACE)

    def _persist_signed(self, name, payload, namespace):
        signed = encode(self._sign(payload, namespace=namespace))
        with self._lineage_directory() as directory:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as output:
                output.write(signed)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(directory)
        return hashlib.sha256(signed).hexdigest()

    def _persist_checkpoint(self, candidate, evidence):
        with self._store._locked():
            if self._state_pin() != self._state:
                reject()
            state_digest = hashlib.sha256(self._store._seal(self._store._read())).hexdigest()
            if self._state_pin() != self._state:
                reject()
        request_hash = self._entry['request'].digest()
        payload = dict(schemaVersion=1, kind='retained-stage-checkpoint', stage=self._stage,
                       requestHash=request_hash, lineageDigest=self._lineage_digest, stateDigest=state_digest,
                       candidateId=candidate, witnessDigests=evidence)
        self._persist_signed(f'{request_hash}.retained-checkpoint-{len(evidence)}.json',
                             payload, _CHECKPOINT_NAMESPACE)

    def _lineage_name(self):
        return self._entry['request'].digest() + '.retained-lineage.json'

    @contextmanager
    def _lineage_directory(self):
        self._store._validate_paths()
        fd = os.open('..', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self._store._dir)
        try:
            if self._store._directory_id(fd) != self._lineage_parent_id:
                reject()
            yield fd
        finally:
            os.close(fd)

    def _check_lineage(self):
        with self._lineage_directory() as directory:
            fd = os.open(self._lineage_name(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 0 < info.st_size <= 8192):
                reject()
            if hashlib.sha256(source.read(8193)).hexdigest() != self._lineage_digest:
                reject()

    def _sign(self, payload, *, namespace=NAMESPACE):
        if _signer_pin(self._signer) != self._signer_pin:
            reject()
        result = subprocess.run(
            [_SSH_KEYGEN, '-Y', 'sign', '-f', str(self._signer), '-n', namespace],
            input=encode(payload), capture_output=True, check=True, timeout=10,
            env={'PATH': '/usr/bin:/bin'},
        )
        if _signer_pin(self._signer) != self._signer_pin:
            reject()
        return dict(payload=payload, signature=base64.b64encode(result.stdout).decode('ascii'))

    def client(self, binding):
        self._check_owner()
        with self._lock:
            if self._state_pin() != self._state or not any(scope['binding'] == binding for scope in self._scopes):
                reject()
            return OperationWitnessClientV3(binding, self._public, self.authorize_rpc)

    def _closed_scope(self, scope):
        binding = scope['binding']
        records = self._store.events_after(binding, seq=0, head=ZERO)
        if len(records) != 6:
            reject()
        previous = ZERO
        directory = attempt = finish = None
        events = []
        for index, record in enumerate(records):
            event, directory, attempt, finish = self._validate_event(
                scope, decode_material(record['externalMaterialBase64']), index, previous, directory, attempt, finish,
            )
            if record['event']['data'] != GateOperationWitnessAdapterV3._data(event, attempt):
                reject()
            previous = _digest(event)
            events.append(event)
        raw = base64.b64decode(finish['bodyBase64'], validate=True)
        if scope['operation'].phase == 'create' and finish['status'] == 201:
            value = json.loads(raw, object_pairs_hook=pairs)
            if type(value) is not dict:
                reject()
            candidate = value['Id']
            self._plan._candidate(candidate)
            return candidate, events, records
        if scope['operation'].phase == 'create' or finish['status'] != 204 or raw:
            reject()
        return None, events, records

    def _closed_response(self, scope):
        candidate, _, _ = self._closed_scope(scope)
        return candidate

    def closed_chain(self):
        self._check_owner()
        with self._lock:
            if self._state_pin() != self._state:
                reject()
            evidence = []
            candidate = self._candidate if self._stage in ('switch', 'rollback') else None
            for scope in self._scopes:
                result, events, records = self._closed_scope(scope)
                candidate = result or candidate
                binding = scope['binding']
                gate = dict(generation=binding['generation'], head=_digest(events[-1]),
                            binding=events[0]['data'], events=[
                                dict(kind=event['kind'], data=event['data']) for event in events[1:]
                            ], closed=True, authorityGranted=False)
                witness = dict(records=records, authorityGranted=False, productionReady=False)
                material = encode(dict(closure=canonical(events[-1]['data']).decode('ascii'),
                                       gate=gate, witness=witness, binding=binding))
                evidence.append(hashlib.sha256(material).hexdigest())
            if self._state_pin() != self._state:
                reject()
            return candidate, evidence

    def _check_staged_parent(self, child):
        self._check_owner()
        cutover = child._cutover
        request = self._entry['request']
        expected_stage = 'create' if child._stage == 'switch' else 'switch'
        parent_hash = cutover['creationRequestHash'] if expected_stage == 'create' else cutover['parentRequestHash']
        if (self._frozen or self._stage != expected_stage or request.digest() != parent_hash
                or self._scope_generation != child._scope_generation
                or cutover['scopeGeneration'] != child._scope_generation
                or self._plan.digest != child._plan.digest or self._origin != child._origin
                or self._public != child._public or self._key != child._key
                or self._policy.identity_hash() != child._policy.identity_hash()
                or self._store.root.parent != child._store.root.parent
                or request.policy_hash != child._entry['request'].policy_hash
                or self._entry['approval'].policy.workflow_sha != child._entry['approval'].policy.workflow_sha
                or any(self._cutover[key] != cutover[key] for key in ('planDigest', 'operationNonce', 'runtimeArchiveDigest'))
                or self._cutover.get('protectionMode') != cutover.get('protectionMode')
                or (self._cutover['protectionDigest'] != cutover['protectionDigest']
                    and (child._stage != 'rollback' or cutover['switchPrefix'] != 1 or cutover['candidateRunning']
                         or 'protectionMode' in cutover))):
            reject()
        self._check_lineage()
        candidate, evidence = self.closed_chain()
        if candidate != cutover['candidateId']:
            reject()
        if expected_stage == 'create':
            if evidence != [cutover['creationWitnessDigest']]:
                reject()
        elif (len(evidence) != cutover['switchPrefix'] or _digest(evidence) != cutover['switchWitnessDigest']
              or any(self._cutover[key] != cutover[key] for key in ('creationRequestHash', 'creationWitnessDigest'))):
            reject()

    def _restore_operations(self):
        return self._plan.restore(self._candidate, switch_prefix=self._cutover['switchPrefix'],
                                  candidate_running=self._cutover['candidateRunning'])

    def _check_parent(self, child):
        self._check_owner()
        cutover = child._cutover
        request = self._entry['request']
        if (self._frozen or self._state_pin() != self._state or request.operation != 'deploy'
                or cutover['parentRequestHash'] != request.digest() or child._plan.digest != self._plan.digest
                or self._origin != child._origin
                or self._entry['approval'].policy.workflow_sha != child._entry['approval'].policy.workflow_sha
                or request.policy_hash != child._entry['request'].policy_hash
                or any(self._cutover[key] != cutover[key] for key in
                       ('planDigest', 'operationNonce', 'runtimeArchiveDigest'))
                or (self._cutover['protectionDigest'] != cutover['protectionDigest']
                    and (cutover['switchPrefix'] != 1 or cutover['candidateRunning'] is not False))
                or len(self._scopes) != cutover['switchPrefix'] + 1):
            reject()
        for index, scope in enumerate(self._scopes):
            candidate = self._closed_response(scope)
            if index == 0 and candidate != cutover['candidateId']:
                reject()
        if self._state_pin() != self._state:
            reject()

    def _transition(self, request, scope):
        if scope is not self._scopes[-1]:
            reject()
        candidate = self._closed_response(scope) or self._candidate
        index = len(self._scopes)
        if self._stage == 'create':
            reject()
        if self._stage == 'switch':
            operations = self._plan.switch(candidate)
        elif self._entry['request'].operation == 'deploy':
            operations = (self._plan.create(), *self._plan.switch(candidate))
        else:
            operations = self._restore_operations()
        if index >= len(operations):
            reject()
        child = self._descriptor(operations[index], index)
        if request['childBinding'] != child['binding']:
            reject()
        self._consent(self._entry)
        result = dispatch_request(self._store, 'transition_successor', request,
                                  expected_state_identity=self._state[:2])
        self._scopes.append(child)
        self._candidate = candidate
        return result

    def authorize_rpc(self, method, request):
        """Sign exact admitted operations from an authenticated worker channel."""
        self._check_owner()
        with self._lock:
            try:
                if method not in _METHODS or self._state_pin() != self._state:
                    reject()
                request = deepcopy(request)
                validate_request(method, request)
                scope = next((item for item in self._scopes if item['binding'] == request['binding']), None)
                nonce = request['rpcNonce']
                if scope is None or nonce in self._seen or len(self._seen) >= _MAX_RPC:
                    reject()
                self._seen.add(nonce)
                if method in ('append_event', 'transition_successor'):
                    if self._frozen:
                        reject()
                    if method == 'append_event':
                        payload = self._append(request, scope, expected_state_identity=self._state[:2])
                    else:
                        payload = self._transition(request, scope)
                    self._state = self._state_pin()
                    if (self._stage is not None and method == 'append_event'
                            and request['event']['kind'] == 'closed'):
                        candidate, evidence = self.closed_chain()
                        self._persist_checkpoint(candidate, evidence)
                else:
                    payload = dispatch_request(self._store, method, request)
                return self._sign(payload)
            except Exception:
                reject()
