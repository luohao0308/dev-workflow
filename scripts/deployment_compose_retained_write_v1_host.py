"""One witnessed Docker write at a time for a trusted retained-frontend worker.

The embedding owns consent consumption, the host scope lease, phase checks and
independent first-scope registration. This transport never retries a write.
"""
import base64
from dataclasses import replace
import hashlib
import http.client
import math
import os
from pathlib import Path
import ssl
import threading
import time

import deployment_runtime as runtime
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_host_snapshot_v3_host import HostSnapshotV3
from deployment_compose_operation_witness_client_v3 import (
    OperationWitnessClientV3, binding_value, encode, hex_value,
)
from deployment_compose_production_cutover_v1_host import ContainerOperation
from deployment_compose_write_gateway_v3_host import (
    ADMITTED_FAILURE_STAGES, MAX_BODY, _complete_response, create_gateway_v3,
)
from deployment_gate_witness import opening_scope
from deployment_gateway import FileWriterGate, GatePolicy, _profile_operation

_MAX_WRITES = 5
_EMPTY = '0' * 64
_PHASE_SUFFIX = {
    'stop-original': '/stop?t=10',
    'retain-original': '/rename?name=',
    'name-candidate': '/rename?name=',
    'start-candidate': '/start',
    'stop-candidate': '/stop?t=10',
    'unname-candidate': '/rename?name=',
    'rename-original': '/rename?name=',
    'start-original': '/start',
}


def _reject():
    raise ValueError('retained-frontend-write-blocked') from None


class RetainedDockerWriteUncertain(ValueError):
    def __init__(self, stage):
        if type(stage) is not str or stage not in ADMITTED_FAILURE_STAGES:
            _reject()
        super().__init__('retained-frontend-write-outcome-unknown')
        self.stage = stage


def _digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def _operation_tuple(operation):
    if (type(operation) is not ContainerOperation or type(operation.phase) is not str
            or type(operation.path) is not str or type(operation.body) is not bytes
            or len(operation.body) > MAX_BODY):
        _reject()
    if operation.phase == 'create':
        if not operation.path.startswith('/v1.45/containers/create?name=') or not operation.body:
            _reject()
    else:
        suffix = _PHASE_SUFFIX.get(operation.phase)
        if suffix is None or suffix not in operation.path or operation.body:
            _reject()
        if suffix != '/rename?name=' and not operation.path.endswith(suffix):
            _reject()
    return _profile_operation('compose-v3', 'POST', operation.path,
                              hashlib.sha256(operation.body).hexdigest())


class RetainedWriteV1:
    """Own one request's witness sequence on the lease-holding thread."""

    def __init__(self, *, gate_policy, gate_root, gate_key, witness_client_factory,
                 registered_binding, tls_server_context, tls_client_context,
                 server_certificate_sha256, observer, timeout=30):
        if (type(gate_policy) is not GatePolicy or gate_policy.operation_profile != 'compose-v3'
                or gate_policy.witness_required is not True
                or not isinstance(gate_root, Path) or not gate_root.is_absolute()
                or type(gate_key) is not bytes or len(gate_key) < 32
                or not callable(witness_client_factory)
                or not isinstance(tls_server_context, ssl.SSLContext)
                or tls_server_context.verify_mode != ssl.CERT_REQUIRED
                or not isinstance(tls_client_context, ssl.SSLContext)
                or tls_client_context.verify_mode != ssl.CERT_REQUIRED
                or not tls_client_context.check_hostname
                or not hex_value(server_certificate_sha256)
                or type(observer) is not HostSnapshotV3
                or type(timeout) not in (int, float) or not 1 <= timeout <= 180):
            _reject()
        self._initial = binding_value(registered_binding)
        if (self._initial['policyHash'] != gate_policy.identity_hash()
                or self._initial['scopeHash'] != gate_policy.witness_scope_hash):
            _reject()
        self._owner = (os.getpid(), threading.current_thread())
        self._policy, self._root, self._key = gate_policy, gate_root, gate_key
        self._factory = witness_client_factory
        self._server_tls, self._client_tls = tls_server_context, tls_client_context
        self._server_pin, self._observer, self._timeout = server_certificate_sha256, observer, timeout
        self._socket = HostSnapshotV3._write_socket(observer)
        self._blocked, self._index = False, 0
        self._request, self._client, self._head = None, None, None

    @property
    def observer(self):
        return self._observer

    def __copy__(self):
        _reject()

    def __deepcopy__(self, memo):
        _reject()

    def __reduce_ex__(self, protocol):
        _reject()

    @staticmethod
    def scope_descriptor(operation, *, request_hash, receipt_hash, plan_digest, index):
        if (any(not hex_value(pin) for pin in (request_hash, receipt_hash, plan_digest))
                or type(index) is not int or not 0 <= index < _MAX_WRITES):
            _reject()
        operations = (_operation_tuple(operation),)
        source = _digest(dict(plan=plan_digest, index=index, phase=operation.phase,
                              operation=list(operations[0])))
        generation = _digest(dict(request=request_hash, receipt=receipt_hash, source=source))
        return dict(generation=generation, source=source, operations=operations,
                    scopeHash=opening_scope(generation, request_hash, receipt_hash, operations, source))

    def _check(self, deadline, expires_at=None):
        if (self._owner != (os.getpid(), threading.current_thread()) or time.monotonic() >= deadline
                or expires_at is not None and time.time() >= expires_at
                or self._server_tls.verify_mode != ssl.CERT_REQUIRED
                or self._client_tls.verify_mode != ssl.CERT_REQUIRED or not self._client_tls.check_hostname
                or HostSnapshotV3._write_socket(self._observer) != self._socket):
            _reject()

    def write(self, operation, *, request_hash, receipt_hash, plan_digest, index, before_dispatch,
              expires_at=None):
        """Return a closed definitive response and its witness evidence digest.

        The dispatch guard may return a fresh authorization deadline, which
        can shorten the request's absolute expiry.
        A definitive non-success is returned for diagnosis and freezes further
        writes. An ambiguous response raises and also freezes the transport.
        """
        if expires_at is not None:
            if (type(expires_at) not in (int, float) or expires_at <= 0
                    or type(expires_at) is float and not math.isfinite(expires_at)):
                _reject()
        deadline = time.monotonic() + self._timeout
        self._check(deadline, expires_at)
        pins = request_hash, receipt_hash, plan_digest
        if (self._blocked or index != self._index or not callable(before_dispatch)
                or self._request is not None and pins != self._request):
            _reject()
        descriptor = self.scope_descriptor(operation, request_hash=request_hash,
                                          receipt_hash=receipt_hash, plan_digest=plan_digest, index=index)
        operation = ContainerOperation(operation.phase, operation.path, operation.body)
        self._blocked = True
        self._request = pins

        def guard():
            self._check(deadline, expires_at)
            fresh_until = before_dispatch()
            self._check(deadline, expires_at)
            if fresh_until is None:
                return expires_at
            if type(fresh_until) not in (int, float) or not math.isfinite(fresh_until) or time.time() >= fresh_until:
                _reject()
            return fresh_until if expires_at is None else min(expires_at, fresh_until)

        guard()
        binding = dict(self._initial, generation=descriptor['generation'], scopeHash=descriptor['scopeHash'])
        policy = replace(self._policy, witness_scope_hash=descriptor['scopeHash'])
        if binding['policyHash'] != policy.identity_hash():
            _reject()
        if self._client is None:
            if binding != self._initial:
                _reject()
        else:
            parent = self._client.check(expected_seq=6, expected_head=self._head)
            if parent['phase'] != 'closed' or parent['active'] is not True:
                _reject()
            self._client.transition_successor(expected_seq=6, expected_head=self._head, childBinding=binding)
        client = self._factory(dict(binding))
        if (type(client) is not OperationWitnessClientV3 or client.binding != binding
                or client.key_hash != policy.witness_key_sha256):
            _reject()
        empty = client.check(expected_seq=0, expected_head=_EMPTY)
        if (empty['phase'] != 'empty' or empty['active'] is not True
                or self._client is None and empty['lineage']):
            _reject()

        adapter = GateOperationWitnessAdapterV3(client)
        gate = FileWriterGate(policy, self._root, key=self._key, witness=adapter)
        self._check(deadline, expires_at)
        session = gate.open_generation(generation=descriptor['generation'], request_hash=request_hash,
            receipt_hash=receipt_hash, operations=descriptor['operations'], source_context_digest=descriptor['source'])
        attempt = session.prepare_attempt('POST', operation.path, operation.body)
        headers = session.headers(attempt)
        headers.update({'Content-Length': str(len(operation.body)), 'Content-Type': 'application/json',
                        'Connection': 'close'})

        def pre_dispatch(method, path, body, generation, attempt_ref):
            if ((method, path, body) != ('POST', operation.path, operation.body)
                    or generation != descriptor['generation'] or attempt_ref != attempt.ref):
                _reject()
            guard()

        # Witness preparation can outlast a signed intent reply. Bind the
        # listener and Docker connection to a fresh reply after preparation.
        dispatch_expires_at = guard()
        status, raw = self._relay(gate, pre_dispatch, operation, headers, deadline, dispatch_expires_at)
        # A response to an already dispatched write must still be closed even
        # when authorization has expired since the POST was sent.
        self._check(deadline)
        proof = gate.close_generation(descriptor['generation'])
        evidence = gate.generation_evidence(descriptor['generation'])
        finishes = [event['data'] for event in evidence['events'] if event['kind'] == 'finish']
        if (len(finishes) != 1 or finishes[0]['definitive'] is not True or finishes[0]['status'] != status
                or base64.b64decode(finishes[0]['bodyBase64'], validate=True) != raw):
            _reject()
        closed = client.read()
        if closed['seq'] != 6 or closed['phase'] != 'closed' or closed['active'] is not True:
            _reject()
        witness = adapter.authenticated_material_after()
        if len(witness['records']) != 6 or witness['records'][-1]['head'] != closed['head']:
            _reject()
        tail = client.check(expected_seq=6, expected_head=closed['head'])
        if tail['phase'] != 'closed' or tail['active'] is not True:
            _reject()
        self._check(deadline)
        evidence_digest = _digest(dict(closure=proof.to_json(), gate=evidence, witness=witness, binding=binding))
        if (operation.phase == 'create' and status == 201
                or operation.phase != 'create' and status == 204 and not raw):
            self._client, self._head = client, closed['head']
            self._index += 1
            self._blocked = False
        return status, raw, evidence_digest

    def _relay(self, gate, pre_dispatch, operation, headers, deadline, expires_at):
        self._check(deadline, expires_at)
        failure = []
        server = create_gateway_v3(gate, tls_context=self._server_tls, docker_socket=self._socket,
            pre_dispatch=pre_dispatch, timeout=self._timeout, control_deadline=deadline,
            bound_observer=self._observer, authorization_expires_at=expires_at,
            on_unknown=failure.append)
        outcome = []

        def client_exchange():
            connection = watchdog = None
            try:
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                connection = http.client.HTTPSConnection('localhost', server.server_port,
                                                          context=self._client_tls, timeout=left)
                connection.connect()
                watchdog = runtime.deadline_watchdog(connection.sock, deadline)
                if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest() != self._server_pin:
                    return
                connection.request('POST', operation.path, body=operation.body, headers=headers)
                response = connection.getresponse()
                outcome.append((response.status, _complete_response(response)))
            except Exception:
                return
            finally:
                if watchdog is not None:
                    watchdog.cancel()
                if connection is not None:
                    connection.close()

        thread = threading.Thread(target=client_exchange, daemon=True)
        try:
            thread.start()
            server.timeout = max(0, deadline - time.monotonic())
            # The actual write handler runs on the original lease owner.
            server.handle_request()
        finally:
            server.server_close()
            if thread.ident is not None:
                thread.join(max(0, deadline - time.monotonic()))
        if len(failure) == 1:
            raise RetainedDockerWriteUncertain(failure[0])
        if thread.is_alive() or len(outcome) != 1:
            _reject()
        return outcome[0]
