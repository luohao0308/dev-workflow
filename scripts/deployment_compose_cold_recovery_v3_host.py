"""One-shot trusted-host recovery from bounded cold material.

The host independently configures the original baseline CAS, Unix Engine socket,
root/version pins, witness transports, writer quiescence and mTLS contexts.
Historical material alone never provides any of those execution inputs.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import os
import ssl
from pathlib import Path
import threading

from deployment_compose_approval_v3_host import GitHubFullBodyApprovalV3, FullBodyConsumptionEvidenceV3
from deployment_compose_bounded_restart_material_v3_host import reopen_material
from deployment_compose_coordinator_v3_host import Profile3StepExecutor, ComposeCoordinatorV3
from deployment_compose_history_v3_host import AuthenticatedHistoryV3, ANCESTRY_PROFILE
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3
from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_startup_fence_v3_host import Profile3RecoveryFenceV3
from deployment_compose_witness_store import canonical, ZERO, hex_value
from deployment_contract_v2 import RequestV2


def reject():
    raise ValueError('compose-cold-recovery-v3-rejected') from None


class ColdRecoveryHostV3:
    def __init__(self, raw, *, expected_digest, expected_context, gate_key, witness_public_key,
                 witness_transport, store, docker_socket, daemon_version, expected_docker_root, readiness):
        if (type(store) is not ComposeRecoveryStore or not isinstance(docker_socket, Path)
                or not docker_socket.is_absolute() or type(expected_docker_root) is not str
                or not Path(expected_docker_root).is_absolute() or not callable(readiness)):
            reject()
        socket_pin, root_pin = str(docker_socket), expected_docker_root
        version_pin = canonical(deepcopy(daemon_version))
        store_pin = (store._root, store._fd, store._identity, hashlib.sha256(store._key).digest())
        self._owner = (os.getpid(), threading.get_ident())
        self._issuer = self
        self._lock = threading.RLock()
        self._state = 'new'
        owner_pin, lock_pin = self._owner, self._lock
        self._socket = str(docker_socket)
        self._docker_root = expected_docker_root
        self._version = deepcopy(daemon_version)
        self._store, self._key, self._public, self._ready = store, gate_key, witness_public_key, readiness
        self._reader = reopen_material(raw, expected_digest=expected_digest, expected_context=expected_context,
            gate_key=gate_key, witness_public_key=witness_public_key, witness_transport=witness_transport)
        if (self._owner != owner_pin or self._lock is not lock_pin or self._issuer is not self or self._state != 'new'
                or self._socket != socket_pin or self._docker_root != root_pin or canonical(self._version) != version_pin
                or self._store is not store or self._ready is not readiness or self._key != gate_key or self._public != witness_public_key
                or (store._root, store._fd, store._identity, hashlib.sha256(store._key).digest()) != store_pin):
            reject()
        self._readonly_factory = self._reader.history._factory
        bundle = self._reader.history._bundle
        identity = bundle.to_dict()['identity']
        ids = {service['baselineContainerId'] for service in bundle.to_dict()['services']}
        ids.update(item['containerId'] for item in bundle.to_dict()['protectedContainers'])
        self._producer = TrustedPhaseStateProducerV3(socket_path=self._socket,
            project=identity['project'], daemon_id=identity['daemonId'], container_ids=tuple(sorted(ids)))
        rows = TrustedPhaseStateProducerV3.reload(store, bundle, read_json=self._producer._get,
            daemon_version=self._version, expected_docker_root=self._docker_root)
        self._guard = PhaseGuardV3(bundle, rows, read_json=self._producer._get,
            daemon_version=self._version, expected_docker_root=self._docker_root)
        self._preparation = RecoveryPreparationHostV3(original_history=self._reader.history, store=store,
            phase_guard=self._guard, readiness=self._checked_readiness, ancestry_profile=ANCESTRY_PROFILE)
        self._input_seal = self._input_fingerprint()
        self._candidate = None
        self._candidate_seal = None
        self._child_history = None
        self._runtime = None
        self._runtime_seal = None

    def _owned(self):
        if (type(self) is not ColdRecoveryHostV3 or getattr(self, '_issuer', None) is not self
                or getattr(self, '_owner', None) != (os.getpid(), threading.get_ident())):
            reject()

    def _input_fingerprint(self):
        return (self._owner, id(self._issuer), id(self._lock), id(self._reader), id(self._readonly_factory), self._reader.history._ancestry_fingerprint(),
            self._reader.snapshot.canonical, self._reader.baseline_bytes,
            id(self._store), self._store._root, self._store._fd, self._store._identity,
            hashlib.sha256(self._store._key).digest(), self._socket, self._docker_root, canonical(self._version),
            id(self._producer), self._producer._socket_path, self._producer.project, self._producer.daemon_id,
            self._producer.container_ids, self._producer._timeout,
            id(self._producer.operation_scope.__self__), id(self._producer.operation_scope.__func__),
            id(self._preparation), id(self._preparation._history), id(self._preparation._guard), id(self._preparation._store),
            id(self._preparation._ready), self._preparation._ancestry_profile,
            id(self._preparation._original), self._preparation._original.canonical_json(),
            id(self._preparation._bundle), self._preparation._bundle.canonical_bytes,
            id(self._guard), self._guard._bundle.canonical_bytes,
            canonical(self._guard._base), canonical(self._guard._v), canonical(self._guard._services),
            canonical(self._guard._protected), canonical(self._guard._version), self._guard._root,
            id(self._guard._read.__self__), id(self._guard._read.__func__), id(self._ready), self._key, self._public)

    def _runtime_fingerprint(self):
        server, client, pin, timeout, root = self._runtime
        if (not isinstance(server, ssl.SSLContext) or not isinstance(client, ssl.SSLContext)
                or server.verify_mode != ssl.CERT_REQUIRED or client.verify_mode != ssl.CERT_REQUIRED
                or client.check_hostname is not True or not hex_value(pin)
                or type(timeout) not in (int, float) or not 1 <= timeout <= 180):
            reject()
        def tls(context):
            return (id(context), context.verify_mode, context.check_hostname, context.minimum_version,
                    context.maximum_version, context.options, context.verify_flags)
        return tls(server), tls(client), pin, timeout, root

    def _check_inputs(self):
        # Gate witness callbacks run on the owned local gateway thread. Public
        # entrypoints retain the stricter PID/thread check before their lock.
        if type(self) is not ColdRecoveryHostV3 or self._issuer is not self or self._owner[0] != os.getpid():
            reject()
        if (any(name in self._preparation.__dict__ for name in ('prepare_intent', 'verify_context', '_derive', '_baseline'))
                or any(name in self._guard.__dict__ for name in ('_capture', 'capture_phase', '__call__', '_context', '_body', '_healthy'))
                or self._producer._socket_path != self._socket or self._input_fingerprint() != self._input_seal):
            reject()
        if self._runtime is not None and self._runtime_fingerprint() != self._runtime_seal:
            reject()

    def _checked_readiness(self, service, cid):
        self._check_inputs()
        result = self._ready(service, cid)
        self._check_inputs()
        return result

    def _candidate_fingerprint(self):
        candidate = self._candidate
        return (id(candidate['bundle']), candidate['bundle'].canonical_bytes,
            id(candidate['request']), candidate['request'].canonical_json(),
            id(candidate['reviewed_history']), candidate['reviewed_history'].canonical,
            candidate['recovery_context_reference'])

    def _check_prepared(self):
        self._check_inputs()
        if self._state != 'spent' or self._runtime is None or type(self._candidate) is not dict or self._candidate_fingerprint() != self._candidate_seal:
            reject()

    def prepare_intent(self, *, operation_nonce, expires_at):
        self._owned()
        with self._lock:
            if self._state != 'new':
                reject()
            self._state = 'blocked'
            succeeded = False
            try:
                self._check_inputs()
                candidate = self._preparation.prepare_intent(operation_nonce=operation_nonce, expires_at=expires_at)
                self._check_inputs()
                if self._state != 'blocked':
                    reject()
                self._candidate = candidate
                self._candidate_seal = self._candidate_fingerprint()
                response = dict(bundle=candidate['bundle'], request=candidate['request'], review=deepcopy(candidate['review']))
                succeeded = True
                return response
            finally:
                self._state = 'prepared' if succeeded else 'blocked'

    def execute(self, approval, *, witness_client_factory, quiesce_writer, gate_root,
                tls_server_context, tls_client_context, server_certificate_sha256, timeout=30):
        self._owned()
        with self._lock:
            if self._state != 'prepared':
                reject()
            self._state = 'spent'
            try:
                if (type(approval) is not GitHubFullBodyApprovalV3 or not callable(witness_client_factory)
                        or not callable(quiesce_writer) or not isinstance(gate_root, Path) or not gate_root.is_absolute()):
                    reject()
                self._runtime = (tls_server_context, tls_client_context, server_certificate_sha256, timeout, str(gate_root))
                self._runtime_seal = self._runtime_fingerprint()
                self._check_prepared()
                candidate = self._candidate
                bundle, request, reviewed = candidate['bundle'], candidate['request'], candidate['reviewed_history']
                if (len(approval.requests) != 1 or type(approval.requests[0]) is not RequestV2
                        or approval.requests[0].canonical_json() != request.canonical_json()):
                    reject()

                def verify_context():
                    self._check_prepared()
                    value = self._preparation.verify_context(candidate['recovery_context_reference'], request, reviewed)
                    self._check_prepared()
                    return value

                receipt = approval.consume(approval.validate(request), request, before_consume=verify_context)
                if (type(receipt) is not FullBodyConsumptionEvidenceV3 or receipt.request_hash != request.digest()
                        or type(receipt.use_number) is not int or receipt.use_number != 1):
                    reject()
                self._check_prepared()
                context = verify_context()
                receipt_hash = hashlib.sha256(canonical(asdict(receipt))).hexdigest()
                descriptor = Profile3StepExecutor.scope_descriptor(bundle, request, receipt_hash,
                    context['nextOperation'], context['startWriteIndex'], context['receiptMap'])
                tail = reviewed.snapshot['closedTail']
                binding = dict(tail['binding'], generation=descriptor['generation'], scopeHash=descriptor['scopeHash'])
                policy = replace(self._reader.history._policy, witness_scope_hash=descriptor['scopeHash'])

                def writable_factory(scope):
                    self._check_prepared()
                    client = witness_client_factory(scope)
                    self._check_prepared()
                    if (type(client) is not OperationWitnessClientV3 or client.binding != scope
                            or client.key_hash != self._reader.history._client.key_hash):
                        reject()
                    transport = client._transport
                    def checked_transport(method, rpc):
                        self._check_prepared()
                        reply = transport(method, rpc)
                        self._check_prepared()
                        return reply
                    return OperationWitnessClientV3(scope, self._public, checked_transport)

                def quiesce():
                    self._check_prepared()
                    result = quiesce_writer()
                    self._check_prepared()
                    return result

                fence = Profile3RecoveryFenceV3(preparation=self._preparation,
                    context_reference=candidate['recovery_context_reference'], reviewed_history=reviewed, quiesce_writer=quiesce)
                executor = Profile3StepExecutor(bundle, request, intent_authority=approval, phase_guard=self._guard,
                    gate_root=gate_root, gate_key=self._key, gate_policy=policy, consumption_receipt_hash=receipt_hash,
                    witness_client_factory=writable_factory, registered_binding=binding,
                    tls_server_context=tls_server_context, tls_client_context=tls_client_context,
                    server_certificate_sha256=server_certificate_sha256, docker_socket=Path(self._socket),
                    startup_fence=fence, timeout=timeout, operation_scope=self._producer.operation_scope)
                readonly_factory = self._readonly_factory
                child = AuthenticatedHistoryV3(bundle, request, gate_policy=policy, gate_key=self._key,
                    consumption_receipt_hash=receipt_hash, witness_client=readonly_factory(binding),
                    witness_client_factory=readonly_factory, parent_history=self._reader.history,
                    reviewed_parent_snapshot=reviewed, ancestry_profile=ANCESTRY_PROFILE)
                self._child_history = child
                original = readonly_factory(binding)
                if original.check(expected_seq=0, expected_head=ZERO)['active'] is not True:
                    reject()
                if original.chain_status() != writable_factory(binding).chain_status():
                    reject()
                self._check_prepared()

                def verify_candidates(receipts):
                    done = bundle.creation_operations()
                    following = bundle.resolve_operations(dict(receipts))[len(done)]
                    return self._guard(dict(phase_index=len(done), operation=following,
                        receipts=dict(receipts), completed_operations=done)) is True

                coordinator = ComposeCoordinatorV3(executor, verify_candidates=verify_candidates, readiness=self._checked_readiness)
                result = coordinator.run()
                first_history = child.capture()
                operations = bundle.resolve_operations(result['receipts'])
                terminal = dict(phase_index=sum(operation['method'] != 'GET' for operation in operations),
                                operation=None, receipts=result['receipts'], completed_operations=operations)
                self._guard.capture_phase(terminal, terminal=True)
                if (child.capture().canonical != first_history.canonical
                        or dict(first_history.snapshot['receiptMap']) != result['receipts']
                        or first_history.snapshot['pending'] is not None or first_history.snapshot['blocker'] is not None
                        or len(first_history.snapshot['knownPrefix']) != terminal['phase_index']):
                    reject()
                self._check_prepared()
                result.update(recoveryComplete=True, runtimePermit=False, authorityGranted=False)
                return result, child
            finally:
                self._state = 'spent'

    def inspect_history(self):
        self._owned()
        with self._lock:
            if self._child_history is None:
                reject()
            self._child_history.capture()
            return self._child_history
