"""Controller for one authenticated retained-frontend production channel.

The owner supplies the connected pipes and independent startup pins. The
controller holds GitHub credentials, the ledger client, and private signing
keys. Only public keys and the gate key cross the owned worker channel.
"""
import base64
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time

from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_production_cutover_v1_host import accepted_deployment_proof, prepare_retained_frontend_cutover
from deployment_compose_production_frontend_approval_v1_host import (
    STAGED_CANDIDATE_FIELDS, STAGED_PROTECTION_MODE, STAGED_ROLLBACK_FIELDS,
    prepare_production_frontend_request,
)
from deployment_compose_retained_intent_relay_v1_host import (
    IntentRelayRejected, RetainedIntentBindingV1, RetainedIntentIssuerV1,
)
from deployment_compose_retained_crash_evidence_v1_host import inspect_retained_crash_evidence
from deployment_compose_retained_recovery_handoff_v1_host import (
    prepare_crash_rollback_review, verify_crash_rollback_evidence,
)
from deployment_compose_retained_native_channel_v1_host import BLOCKED_FIELDS, FAILURE_STAGES
from deployment_compose_retained_witness_admission_v1_host import RetainedWitnessAdmissionV1, _signer_pin
from deployment_compose_retained_write_v1_host import RetainedWriteV1
from deployment_compose_v3_channel_worker import read_frame, write_frame
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material
from deployment_gateway import GatePolicy
from release_execute import AuthorizationUnavailable


class RetainedControllerBlocked(ValueError):
    pass


def reject():
    raise RetainedControllerBlocked('retained-production-controller-blocked') from None


def _closed(value, fields):
    if type(value) is not dict or set(value) != fields:
        reject()
    return value


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _check_signer(path, public):
    if not isinstance(path, Path) or not path.is_absolute() or path.resolve(strict=True) != path:
        reject()
    pin = _signer_pin(path)
    result = subprocess.run(['/usr/bin/ssh-keygen', '-y', '-f', str(path)],
                            capture_output=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
    if result.returncode or key_material(result.stdout) != public or _signer_pin(path) != pin:
        reject()


def _startup(actual, expected):
    if canonical(actual) != canonical(expected):
        reject()
    value = deepcopy(_closed(actual, {'kind', 'channelNonce', 'source', 'endpointDigest', 'scope'}))
    source = _closed(value['source'], {'profile', 'sourceSha', 'archiveDigest', 'channelNonce', 'originDigest'})
    scope = _closed(value['scope'], {'root', 'rootIdentity', 'journalIdentity', 'hostId', 'project', 'daemonId'})
    if (value['kind'] != 'production-startup' or source['profile'] != 'production-retained-v2'
            or not hex_value(value['channelNonce']) or source['channelNonce'] != value['channelNonce']
            or not all(hex_value(v) for v in (value['endpointDigest'], source['archiveDigest'], source['originDigest']))
            or type(source['sourceSha']) is not str or not re.fullmatch('[0-9a-f]{40}', source['sourceSha'])
            or scope['project'] != 'luohao-blog-prod' or type(scope['root']) is not str
            or not Path(scope['root']).is_absolute() or '..' in Path(scope['root']).parts):
        reject()
    for pin in (scope['rootIdentity'], scope['journalIdentity']):
        if type(pin) is not list or len(pin) != 2 or any(type(n) is not int or n < 0 for n in pin):
            reject()
    return value


class RetainedControllerV1:
    """Dispatch separately approved requests on one owned native channel."""

    def __init__(self, stdin, stdout, *, startup, expected_startup, private_plan, operation_nonce,
                 policy_hash, intent_signer, intent_public_key, witness_signer, witness_public_key,
                 witness_root, witness_key, gate_key, caddy_id, network_id, timeout=1200, staged=False, recovery=None):
        if type(self) is not RetainedControllerV1 or hasattr(self, '_owner'):
            reject()
        self._owner = (os.getpid(), threading.current_thread())
        self._stdin, self._stdout = stdin, stdout
        hello = _startup(startup, expected_startup)
        self._nonce, self._source = hello['channelNonce'], hello['source']
        if (not all(hex_value(v) for v in (operation_nonce, policy_hash, caddy_id, network_id))
                or type(gate_key) is not bytes or len(gate_key) != 32
                or type(witness_key) is not bytes or not 32 <= len(witness_key) <= 4096
                or type(staged) is not bool
                or (recovery is not None and staged)
                or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 1 <= timeout <= 1800
                or not isinstance(witness_root, Path) or not witness_root.is_absolute()
                or witness_root.resolve(strict=True) != witness_root
                or not isinstance(witness_signer, Path) or witness_signer.parent != witness_root):
            reject()
        info = witness_root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            reject()
        intent_key, witness_public = key_material(intent_public_key), key_material(witness_public_key)
        if intent_key == witness_public or witness_key == gate_key:
            reject()
        _check_signer(intent_signer, intent_key)
        _check_signer(witness_signer, witness_public)
        self._timeout = timeout
        self._intent_signer = intent_signer
        self._witness_root, self._witness_root_id = witness_root, (info.st_dev, info.st_ino)
        self._witness_signer, self._witness_public = witness_signer, witness_public
        self._witness_key, self._gate_key = witness_key, gate_key
        self._policy_hash, self._operation_nonce = policy_hash, operation_nonce
        self._private = deepcopy(private_plan)
        self._plan = prepare_retained_frontend_cutover(self._private, operation_nonce=operation_nonce)
        self._base_review = self._private['publicReview']
        identity = self._base_review['identity']
        networks = self._private['privateBody']['NetworkingConfig']['EndpointsConfig']
        if (any(identity[key] != hello['scope'][key] for key in ('hostId', 'project', 'daemonId'))
                or caddy_id not in self._plan.protected_ids or set(networks) != {'luohao-blog-prod_default'}
                or networks['luohao-blog-prod_default']['NetworkID'] != network_id):
            reject()

        self._staged = staged
        self._recovery_source = None
        recovery_fields = {}
        configuration = 'configure-staged' if staged else 'configure'
        if recovery is not None:
            source_fields = {'root', 'pending', 'public_key', 'expected_key_hash'}
            recovery = deepcopy(_closed(recovery, source_fields | {'original_baseline'}))
            self._recovery_source = {key: recovery[key] for key in source_fields}
            report = inspect_retained_crash_evidence(**self._recovery_source)
            proposal = prepare_crash_rollback_review(report, self._private, observation_digest='0'*64)
            pins = proposal['retainedCutover']
            if (pins['runtimeArchiveDigest'] != self._source['archiveDigest']
                    or pins['operationNonce'] != operation_nonce):
                reject()
            configuration = 'configure-crash-recovery'
            recovery_fields = dict(recoveryReview=proposal, pendingScope=recovery['pending'],
                                   originalBaseline=recovery['original_baseline'], endpointDigest=hello['endpointDigest'])
        self._creation_request = self._creation = None
        self._deploy_request = self._parent = None
        self._deployment_result = None
        self._state = 'blocked'
        self._deadline = time.monotonic() + timeout
        self._write(configuration, privatePlan=self._private, operationNonce=operation_nonce,
                    policyHash=policy_hash, intentPublicKey=base64.b64encode(intent_key).decode('ascii'),
                    witnessPublicKey=base64.b64encode(witness_public).decode('ascii'),
                    gateKey=base64.b64encode(gate_key).decode('ascii'), caddyId=caddy_id, networkId=network_id,
                    **recovery_fields)
        prepared = _closed(self._read(), {'kind', 'review', 'writerCertificateSha256'})
        if prepared['kind'] != 'prepared' or not hex_value(prepared['writerCertificateSha256']):
            reject()
        self._certificate = prepared['writerCertificateSha256']
        self._protection_digest = None
        if self._recovery_source is not None:
            self._review = deepcopy(prepared['review'])
            self._verify_recovery_evidence()
        else:
            self._review = self._validate_review(prepared['review'], stage='create' if staged else None)
        self._protection_digest = self._review['retainedCutover']['protectionDigest']
        self._state = 'rollback' if self._recovery_source is not None else 'create' if staged else 'deploy'

    def __copy__(self):
        reject()

    def __deepcopy__(self, memo):
        reject()

    def __reduce_ex__(self, protocol):
        reject()

    def _owned(self):
        if type(self) is not RetainedControllerV1 or self._owner != (os.getpid(), threading.current_thread()):
            reject()

    @property
    def review(self):
        self._owned()
        if self._state not in ('create', 'switch', 'deploy', 'rollback'):
            reject()
        return deepcopy(self._review)

    def _remaining(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            reject()
        return remaining

    def _write(self, kind, **value):
        write_frame(self._stdin, dict(kind=kind, channelNonce=self._nonce, **value),
                    timeout=min(30, self._remaining()))

    def _read(self):
        frame = read_frame(self._stdout, timeout=min(180, self._remaining()))
        if type(frame) is not dict or frame.get('channelNonce') != self._nonce:
            reject()
        del frame['channelNonce']
        return frame

    def _consume_challenge(self, challenge):
        fields = {'nonce', 'requestHash', 'scopeGeneration'}
        _closed(challenge, fields)
        if self._recovery_source is not None:
            if challenge['scopeGeneration'] != self._recovery_source['pending']['generation']:
                reject()
            self._verify_recovery_evidence()
        self._write('consume-check', **challenge)
        reply = _closed(self._read(), fields | {'kind'})
        if reply.pop('kind') != 'consume-confirmed' or canonical(reply) != canonical(challenge):
            reject()
        return reply

    def _verify_recovery_evidence(self):
        return verify_crash_rollback_evidence(**self._recovery_source, private_plan=self._private,
                                              review=self._review)

    def _validate_review(self, review, *, rollback=False, allow_restart_refresh=False, stage=None):
        review = deepcopy(_closed(review, set(self._base_review) | {'retainedCutover'}))
        cutover = review.pop('retainedCutover')
        fields = {'planDigest', 'operationNonce', 'protectionDigest', 'runtimeArchiveDigest'}
        if rollback:
            fields |= {'candidateId', 'switchPrefix', 'candidateRunning', 'parentRequestHash', 'observationDigest'}
        if stage is not None:
            fields.add('stage')
            if 'protectionMode' in cutover:
                fields.add('protectionMode')
                if cutover['protectionMode'] != STAGED_PROTECTION_MODE:
                    reject()
            if stage != 'create':
                fields |= STAGED_CANDIDATE_FIELDS
            if stage == 'rollback':
                fields |= STAGED_ROLLBACK_FIELDS
        _closed(cutover, fields)
        if (cutover.get('stage') != stage or canonical(review) != canonical(self._base_review)
                or cutover['planDigest'] != self._plan.digest
                or cutover['operationNonce'] != self._operation_nonce
                or cutover['runtimeArchiveDigest'] != self._source['archiveDigest']
                or not hex_value(cutover['protectionDigest'])
                or self._protection_digest is not None and cutover['protectionDigest'] != self._protection_digest
                and not (rollback and allow_restart_refresh and cutover['switchPrefix'] == 1
                         and cutover['candidateRunning'] is False and 'protectionMode' not in cutover)):
            reject()
        if stage in ('switch', 'rollback') and cutover.get('protectionMode') != self._review['retainedCutover'].get('protectionMode'):
            reject()
        if stage in ('switch', 'rollback'):
            candidate, creation_evidence = self._closed_chain(self._creation)
            if (cutover['candidateId'] != candidate
                    or cutover['creationRequestHash'] != self._creation_request.digest()
                    or [cutover['creationWitnessDigest']] != creation_evidence
                    or type(cutover['scopeGeneration']) is not int
                    or cutover['scopeGeneration'] != self._creation._scope_generation
                    or not hex_value(cutover['observationDigest'])):
                reject()
        if rollback:
            if (not hex_value(cutover['observationDigest']) or cutover['parentRequestHash'] != self._deploy_request.digest()):
                reject()
            self._plan.restore(cutover['candidateId'], switch_prefix=cutover['switchPrefix'],
                               candidate_running=cutover['candidateRunning'])
            candidate, evidence = self._closed_chain(self._parent)
            if (candidate != cutover['candidateId'] or len(evidence) != cutover['switchPrefix'] + (stage is None)
                    or stage == 'rollback' and cutover['switchWitnessDigest'] != _hash(canonical(evidence))):
                reject()
        review['retainedCutover'] = cutover
        return review

    def _register_witness(self, wire, issuer, approval, request):
        _closed(wire, {'requestHash', 'receiptHash', 'executionDigest', 'scopeGeneration'})
        receipt, generation = issuer.consumption, issuer.scope_generation
        if (wire['requestHash'] != request.digest() or wire['receiptHash'] != _hash(canonical(asdict(receipt)))
                or type(wire['scopeGeneration']) is not int or wire['scopeGeneration'] != generation):
            reject()
        execution = _hash(canonical(dict(
            plan=self._plan.digest, approvedReview=request.plan_hash, protection=self._protection_digest,
            scopeGeneration=generation, writerOrigin=self._source['originDigest'],
        )))
        if wire['executionDigest'] != execution:
            reject()
        cutover = self._review['retainedCutover']
        stage = cutover.get('stage')
        if stage == 'switch':
            first = self._plan.switch(cutover['candidateId'])[0]
        elif request.operation == 'rollback':
            first = self._plan.restore(cutover['candidateId'], switch_prefix=cutover['switchPrefix'],
                                       candidate_running=cutover['candidateRunning'])[0]
        else:
            first = self._plan.create()
        descriptor = RetainedWriteV1.scope_descriptor(
            first, request_hash=request.digest(), receipt_hash=wire['receiptHash'], plan_digest=execution, index=0,
        )
        policy = GatePolicy('blog-retained', 'retained-' + self._nonce[:16], self._policy_hash,
                            self._certificate, True, descriptor['scopeHash'], _hash(self._witness_public),
                            operation_profile='compose-v3')
        path = self._witness_root / request.digest()
        parent_fd = os.open(self._witness_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent_fd)
            if ((info.st_dev, info.st_ino) != self._witness_root_id
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                reject()
            os.mkdir(path.name, mode=0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
            child = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            store = OperationWitnessStoreV3(path, key=self._witness_key)
            if (child.st_dev, child.st_ino) != store._root_id:
                store.close()
                reject()
        finally:
            os.close(parent_fd)
        try:
            broker = RetainedWitnessAdmissionV1(
                store=store, gate_policy=policy, gate_key=self._gate_key,
                witness_signer=self._witness_signer, witness_public_key=self._witness_public,
                private_plan=self._private, review=self._review, request=request, approval=approval,
                consumption=receipt, scope_generation=generation, writer_origin_digest=self._source['originDigest'],
                parent=self._parent if request.operation == 'rollback' else self._creation if stage == 'switch' else None,
                recovery_source=self._recovery_source,
            )
        except BaseException:
            store.close()
            raise
        return broker

    @staticmethod
    def _closed_chain(broker):
        if type(broker) is not RetainedWitnessAdmissionV1:
            reject()
        return broker.closed_chain()

    def _reconcile(self, result, broker, request):
        if self._recovery_source is not None:
            fields = {'requestHash', 'scopeGeneration', 'creationRequestHash', 'originalId', 'candidateId',
                      'witnessDigest', 'observationDigest'}
            _closed(result, fields)
            candidate, evidence = self._closed_chain(broker)
            pins = self._review['retainedCutover']
            if (result['requestHash'] != request.digest() or type(result['scopeGeneration']) is not int
                    or result['scopeGeneration'] != self._recovery_source['pending']['generation']
                    or result['creationRequestHash'] != pins['creationRequestHash']
                    or result['originalId'] != self._plan.original_id or result['candidateId'] != candidate
                    or candidate != pins['candidateId'] or evidence != [result['witnessDigest']]
                    or not hex_value(result['observationDigest'])):
                reject()
            return deepcopy(result)
        fields = {'requestHash', 'observationDigest', 'protectionDigest', 'witnessDigests', 'originalId', 'candidateId'}
        rollback = request.operation == 'rollback'
        if rollback:
            fields |= {'parentRequestHash', 'parentWitnessDigests'}
        _closed(result, fields)
        candidate, evidence = self._closed_chain(broker)
        if rollback:
            cutover = self._review['retainedCutover']
            expected_writes = len(self._plan.restore(cutover['candidateId'], switch_prefix=cutover['switchPrefix'],
                                                     candidate_running=cutover['candidateRunning']))
            candidate, parent = self._closed_chain(self._parent)
            if (result['parentRequestHash'] != request.history_hash or result['parentWitnessDigests'] != parent
                    or candidate != cutover['candidateId']):
                reject()
        else:
            expected_writes = {'create': 1, 'switch': 4}.get(self._review['retainedCutover'].get('stage'), 5)
        if (result['requestHash'] != request.digest() or result['protectionDigest'] != self._protection_digest
                or not hex_value(result['observationDigest']) or result['originalId'] != self._plan.original_id
                or result['candidateId'] != candidate or result['witnessDigests'] != evidence
                or len(evidence) != expected_writes):
            reject()
        return deepcopy(result)

    def execute(self, approval, grant, request, *, accept_success=False):
        """Run one approved request and return its reconciled result or recovery review."""
        self._owned()
        phase = self._state
        if (phase not in ('create', 'switch', 'deploy', 'rollback') or type(request) is not RequestV2
                or type(accept_success) is not bool or (accept_success and phase != 'switch')):
            reject()
        operation = 'rollback' if phase == 'rollback' else 'deploy'
        expected = prepare_production_frontend_request(self._review, policy_hash=self._policy_hash,
                                                       expires_at=request.expires_at, operation=operation)
        if expected != request:
            reject()
        binding = RetainedIntentBindingV1(self._nonce, self._source['sourceSha'], self._source['archiveDigest'],
                                          self._source['originDigest'], self._protection_digest)
        issuer = RetainedIntentIssuerV1(approval, request, grant, binding=binding, signer=self._intent_signer,
                                       preflight_challenge=self._consume_challenge)
        self._deadline = time.monotonic() + self._timeout
        self._state = 'blocked'
        broker = None
        result = None
        try:
            self._write('execute', request=json.loads(request.canonical_json()))
            for _ in range(4096):
                frame = self._read()
                kind = frame.get('kind')
                if kind == 'rpc':
                    if result is not None:
                        reject()
                    _closed(frame, {'kind', 'service', 'method', 'request'})
                    service, method, wire = frame['service'], frame['method'], frame['request']
                    if service == 'intent' and method == 'authorize':
                        try:
                            response = issuer.authorize_rpc(wire)
                        except (AuthorizationUnavailable, IntentRelayRejected):
                            if (type(wire) is not dict or wire.get('method') != 'check'
                                    or wire.get('requestHash') != request.digest()):
                                raise
                            response = {'denied': True, 'request': wire}
                    elif service == 'witness' and method == 'register' and broker is None:
                        broker = self._register_witness(wire, issuer, approval, request)
                        response = broker.first_binding
                    elif service == 'witness' and broker is not None:
                        response = broker.authorize_rpc(method, wire)
                    else:
                        reject()
                    self._write('reply', response=response)
                elif kind == 'blocked':
                    blocked = _closed(frame, {'kind'} | BLOCKED_FIELDS)
                    stage = blocked['failureStage']
                    preparation = 'prepare-switch' if phase == 'create' else 'prepare-restore' if phase != 'rollback' else None
                    if (blocked['knownPrefix'] is not False or type(stage) is not str or stage not in FAILURE_STAGES
                            or (result is not None) != (stage == preparation)
                            or stage in ('prepare-switch', 'prepare-restore') and stage != preparation):
                        reject()
                    return {'result': result, 'restoreReview': None, 'blocked': True, 'failureStage': stage}
                elif kind == 'executed':
                    if result is not None:
                        reject()
                    result = self._reconcile(_closed(frame, {'kind', 'result'})['result'], broker, request)
                    if request.operation == 'rollback':
                        self._state = 'done'
                        return {'result': result, 'restoreReview': None, 'blocked': False}
                elif kind == 'switch-prepared' and phase == 'create' and result is not None:
                    self._creation_request, self._creation = request, broker
                    review = self._validate_review(_closed(frame, {'kind', 'review'})['review'], stage='switch')
                    if review['retainedCutover']['observationDigest'] != result['observationDigest']:
                        reject()
                    self._review, self._state = review, 'switch'
                    return {'result': result, 'switchReview': self.review, 'restoreReview': None, 'blocked': False}
                elif (kind == 'switch-retry' and phase == 'switch' and result is None and broker is None
                      and not issuer._attempted):
                    review = self._validate_review(_closed(frame, {'kind', 'review'})['review'], stage='switch')
                    if review != self._review:
                        reject()
                    self._state = 'switch'
                    return {'result': None, 'switchReview': self.review, 'restoreReview': None, 'blocked': True,
                            'failureStage': 'cutover-window-too-short'}
                elif kind == 'restore-prepared' and phase in ('deploy', 'switch') and broker is not None:
                    self._deploy_request, self._parent = request, broker
                    review = self._validate_review(_closed(frame, {'kind', 'review'})['review'], rollback=True,
                                                   allow_restart_refresh=result is None,
                                                   stage='rollback' if self._staged else None)
                    if result is not None and review['retainedCutover']['switchPrefix'] != 4:
                        reject()
                    self._review = review
                    self._protection_digest = review['retainedCutover']['protectionDigest']
                    self._state = 'rollback'
                    self._deployment_result = deepcopy(result) if phase == 'switch' else None
                    if accept_success and result is not None:
                        proof = self.accept_deployment()
                        if proof is not None:
                            return {'result': result, 'restoreReview': None, 'blocked': False, 'terminalProof': proof}
                    return {'result': result, 'restoreReview': self.review, 'blocked': False}
                else:
                    reject()
            reject()
        finally:
            if broker is not None and broker not in (self._parent, self._creation):
                broker._store.close()

    def finish(self):
        self._owned()
        if self._state not in ('create', 'switch', 'deploy', 'rollback'):
            reject()
        self._state = 'done'
        self._deadline = time.monotonic() + self._timeout
        self._write('finish')

    def accept_deployment(self):
        """Finalize a proven staged deployment without sending Docker writes."""
        self._owned()
        result = self._deployment_result
        if not self._staged or self._state != 'rollback' or result is None:
            reject()
        candidate, switch = self._closed_chain(self._parent)
        created, creation = self._closed_chain(self._creation)
        if (candidate != result['candidateId'] or created != candidate or switch != result['witnessDigests']
                or len(creation) != 1):
            reject()
        expected_proof = accepted_deployment_proof(
            creation_request=self._creation_request.digest(), creation_witness=creation[0],
            generation=self._creation._scope_generation, result=result,
        )
        self._state = 'blocked'
        self._deployment_result = None
        self._deadline = time.monotonic() + self._timeout
        self._write('accept-deployment', requestHash=result['requestHash'],
                    observationDigest=result['observationDigest'])
        reply = self._read()
        if reply == {'kind': 'acceptance-rejected'}:
            self._state = 'rollback'
            return None
        if reply != {'kind': 'deployment-accepted', 'terminalProof': expected_proof}:
            reject()
        self._state = 'done'
        return expected_proof

    def close(self):
        """Release local witness resources. The enclosing owner closes the pipes."""
        self._owned()
        self._state = 'done'
        for broker in (self._parent, self._creation):
            if broker is not None:
                broker._store.close()
        self._parent = self._creation = None
