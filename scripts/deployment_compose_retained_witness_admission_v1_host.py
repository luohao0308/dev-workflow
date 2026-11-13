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
    NAMESPACE, OperationWitnessClientV3, binding_value, decode_material,
    dispatch_request, encode, validate_request,
)
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_compose_production_frontend_approval_v1_host import (
    GitHubProductionFrontendApprovalV2, ProductionFrontendReceiptV1,
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
                 scope_generation, writer_origin_digest, parent=None):
        if (type(store) is not OperationWitnessStoreV3 or type(gate_policy) is not GatePolicy
                or gate_policy.operation_profile != 'compose-v3' or gate_policy.witness_required is not True
                or type(gate_key) is not bytes or not 32 <= len(gate_key) <= 4096
                or type(request) is not RequestV2 or request.profile_version != '2'
                or type(approval) is not GitHubProductionFrontendApprovalV2
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
        self._consent(self._entry)
        if request.operation == 'deploy':
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

    def _register(self, first):
        scope = self._descriptor(first, 0)
        if self._policy.witness_scope_hash != scope['binding']['scopeHash']:
            reject()
        self._store.register_once(scope['binding'])
        self._state = self._state_pin()
        self._scopes.append(scope)

    def _sign(self, payload):
        if _signer_pin(self._signer) != self._signer_pin:
            reject()
        result = subprocess.run(
            [_SSH_KEYGEN, '-Y', 'sign', '-f', str(self._signer), '-n', NAMESPACE],
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

    def _closed_response(self, scope):
        binding = scope['binding']
        records = self._store.events_after(binding, seq=0, head=ZERO)
        if len(records) != 6:
            reject()
        previous = ZERO
        directory = attempt = finish = None
        for index, record in enumerate(records):
            event, directory, attempt, finish = self._validate_event(
                scope, decode_material(record['externalMaterialBase64']), index, previous, directory, attempt, finish,
            )
            if record['event']['data'] != GateOperationWitnessAdapterV3._data(event, attempt):
                reject()
            previous = _digest(event)
        raw = base64.b64decode(finish['bodyBase64'], validate=True)
        if scope['operation'].phase == 'create' and finish['status'] == 201:
            value = json.loads(raw, object_pairs_hook=pairs)
            if type(value) is not dict:
                reject()
            candidate = value['Id']
            self._plan._candidate(candidate)
            return candidate
        if scope['operation'].phase == 'create' or finish['status'] != 204 or raw:
            reject()
        return None

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
        if self._entry['request'].operation == 'deploy':
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
                else:
                    payload = dispatch_request(self._store, method, request)
                return self._sign(payload)
            except Exception:
                reject()
