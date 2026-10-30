"""Experimental trusted-host orchestration. No CLI, source authentication or recovery.

The embedding owns authenticated source/HMAC construction, startup/session lifecycle,
consumption receipt validation and the initial independent witness registration.
Private results contain Engine response bodies; never publish them as review output.
"""
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import http.client
import json
from pathlib import Path
import ssl
import threading
import time
from types import MappingProxyType

from deployment_compose_approval_v3_host import GitHubFullBodyApprovalV3
from deployment_compose_intent_status_v3 import IntentStatusClientV3
from deployment_compose_bundle_v3 import ExecutionBundleV3, PROFILE
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
from deployment_contract_v2 import RequestV2
from deployment_gateway import FileWriterGate, GatePolicy
from deployment_gate_witness import opening_scope
from deployment_compose_write_gateway_v3_host import create_gateway_v3, _complete_response
import deployment_runtime as runtime
from deployment_compose_operation_witness_v3 import MAX_EVENTS, MAX_SCOPES


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def immutable(value):
    if type(value) is dict:
        return MappingProxyType({k: immutable(v) for k, v in value.items()})
    if type(value) in (list, tuple):
        return tuple(immutable(v) for v in value)
    return value


def reject():
    raise ValueError('compose-coordinator-v3-blocked')


def check_witness_capacity(bundle):
    """Reject unsupported plans before opening any generation or writing Docker."""
    writes = sum(op['phase'] != 'readiness' for op in bundle.to_dict()['operations'])
    if writes > MAX_SCOPES or writes * 6 > MAX_EVENTS:
        reject()


class Profile3StepExecutor:
    """One-shot steps with live host guards; intent status is never a permit."""
    def __init__(self, bundle, request, *, intent_authority, phase_guard,
                 gate_root, gate_key, gate_policy, consumption_receipt_hash,
                 witness_client_factory, registered_binding, tls_server_context,
                 tls_client_context, server_certificate_sha256, docker_socket, timeout=30,
                 startup_fence=None, control_timeout=180, operation_scope=None):
        if (type(bundle) is not ExecutionBundleV3 or type(request) is not RequestV2
                or type(intent_authority) not in (GitHubFullBodyApprovalV3, IntentStatusClientV3)
                or not callable(phase_guard) or not callable(witness_client_factory)
                or type(gate_policy) is not GatePolicy
                or gate_policy.operation_profile != 'compose-v3' or not gate_policy.witness_required
                or not isinstance(tls_client_context, ssl.SSLContext)
                or tls_client_context.verify_mode != ssl.CERT_REQUIRED
                or not tls_client_context.check_hostname
                or not isinstance(tls_server_context, ssl.SSLContext)
                or tls_server_context.verify_mode != ssl.CERT_REQUIRED
                or not isinstance(docker_socket, Path) or not docker_socket.is_absolute()
                or type(control_timeout) not in (int, float) or not 1 <= control_timeout <= 180
                or operation_scope is not None and not callable(operation_scope)
                or type(timeout) not in (int, float) or not 1 <= timeout <= 180):
            reject()
        check_witness_capacity(bundle)
        v = bundle.to_dict(); identity = v['identity']
        if (request.plan_hash != bundle.digest or request.profile_id != PROFILE
                or request.profile_version != '3' or request.production is not False
                or request.max_uses != 1 or request.host_id != identity['hostId']
                or request.daemon_id != identity['daemonId']
                or request.target.runtime != 'compose' or request.target.namespace != identity['project']
                or request.components != tuple(sorted(s['name'] for s in v['services']))
                or identity['sourceIdentity'] != canonical(asdict(request.source)).decode('ascii')):
            reject()
        for pin in (consumption_receipt_hash, server_certificate_sha256):
            if type(pin) is not str or len(pin) != 64 or any(c not in '0123456789abcdef' for c in pin):
                reject()
        self.bundle, self.request = bundle, request
        self._authority, self._guard = intent_authority, phase_guard
        self._root, self._key, self._policy = gate_root, gate_key, gate_policy
        self._receipt, self._factory = consumption_receipt_hash, witness_client_factory
        self._binding = deepcopy(registered_binding)
        self._server_tls, self._client_tls = tls_server_context, tls_client_context
        self._pin, self._socket, self._timeout = server_certificate_sha256, docker_socket, timeout
        self._client = None; self._blocked = False; self._index = 0
        self._resume = None
        self._lock = threading.Lock()
        self._evidence = []
        self._control_timeout = control_timeout
        self._operation_scope = operation_scope or (lambda deadline: nullcontext())
        from deployment_compose_witness_budget_v3_host import check_witness_byte_capacity
        if request.operation == 'deploy':
            check_witness_byte_capacity(bundle, request, gate_policy, self._receipt,
                                        registered_binding)
        if request.operation == 'rollback':
            from deployment_compose_startup_fence_v3_host import Profile3StartupFenceV3
            if type(startup_fence) is not Profile3StartupFenceV3:
                reject()
            first = self.scope_descriptor(bundle, request, self._receipt,
                                          bundle.creation_operations()[0], 0, {})
            if (registered_binding['scopeHash'] != first['scopeHash']
                    or registered_binding['generation'] != first['generation']
                    or registered_binding['policyHash'] != gate_policy.identity_hash()):
                reject()
            startup_fence.activate(bundle=bundle, request=request, binding=registered_binding,
                intent_authority=intent_authority, phase_guard=phase_guard,
                witness_client_factory=witness_client_factory, consumption_receipt_hash=self._receipt,
                gate_policy=gate_policy)
        elif request.operation == 'recovery':
            from deployment_compose_startup_fence_v3_host import Profile3RecoveryFenceV3
            if type(startup_fence) is not Profile3RecoveryFenceV3:
                reject()
            self._resume = startup_fence.activate(bundle=bundle, request=request,
                binding=registered_binding, intent_authority=intent_authority,
                phase_guard=phase_guard, witness_client_factory=witness_client_factory,
                consumption_receipt_hash=self._receipt, gate_policy=gate_policy)
            self._index = self._resume['startWriteIndex']
        elif startup_fence is not None:
            reject()

    @staticmethod
    def scope_descriptor(bundle, request, receipt_hash, operation, index, receipts):
        generation = digest(dict(nonce=bundle.to_dict()['operationNonce'], request=request.digest(),
                                 index=index, operation=operation['requestDigest']))
        source = digest(dict(bundle=bundle.digest, index=index, operation=operation,
                             receiptBindings=receipts))
        operations = ((operation['method'], operation['path'], operation['bodyDigest']),)
        scope = opening_scope(generation, request.digest(), receipt_hash, operations, source)
        return dict(generation=generation, source=source, operations=operations, scopeHash=scope)

    def execute(self, operation, *, phase_index, receipts, completed_operations):
        with self._lock:
            if self._blocked: reject()
            self._blocked = True
            deadline = time.monotonic() + self._control_timeout
            try:
                with self._operation_scope(deadline):
                    return self._execute(operation, phase_index=phase_index, receipts=receipts,
                                         completed_operations=completed_operations, deadline=deadline)
            except BaseException:
                self._blocked = True
                raise

    def _execute(self, operation, *, phase_index, receipts, completed_operations, deadline):
        operation = deepcopy(operation); receipts = deepcopy(receipts)
        if phase_index != self._index or operation['method'] not in ('POST', 'DELETE'):
            reject()
        expected = (self.bundle.creation_operations() if operation['phase'] == 'create'
                    else self.bundle.resolve_operations(receipts))
        writes = [op for op in expected if op['method'] != 'GET']
        if phase_index >= len(writes) or operation != writes[phase_index]:
            reject()
        body = b'' if operation['body'] is None else canonical(operation['body'])
        if (hashlib.sha256(body).hexdigest() != operation['bodyDigest']
                or digest({k: operation[k] for k in ('method', 'path', 'bodyDigest')}) != operation['requestDigest']):
            reject()
        snapshot = immutable(dict(phase_index=phase_index, operation=operation, receipts=receipts,
                                  completed_operations=deepcopy(completed_operations)))
        def guard(*args):
            if time.monotonic() >= deadline: reject()
            self._authority.check_consumed_intent(self.request)
            if time.monotonic() >= deadline: reject()
            if self._guard(snapshot) is not True or time.monotonic() >= deadline:
                reject()
        guard()
        desc = self.scope_descriptor(self.bundle, self.request, self._receipt, operation, phase_index, receipts)
        binding = dict(self._binding, generation=desc['generation'], scopeHash=desc['scopeHash'])
        policy = replace(self._policy, witness_scope_hash=desc['scopeHash'])
        if binding['policyHash'] != policy.identity_hash():
            reject()
        if self._client is None:
            if binding != self._binding:
                reject()
        else:
            parent = self._client.read()
            if parent['phase'] != 'closed' or parent['seq'] != 6 or not parent['active']:
                reject()
            self._client.transition_successor(expected_seq=6, expected_head=parent['head'], childBinding=binding)
        client = self._factory(deepcopy(binding))
        if type(client) is not OperationWitnessClientV3 or client.binding != binding:
            reject()
        empty = client.check(expected_seq=0, expected_head='0'*64)
        if (empty['active'] is not True or empty['phase'] != 'empty'
                or (self.request.operation == 'deploy' and self._index == 0 and empty['lineage'])):
            reject()
        adapter = GateOperationWitnessAdapterV3(client)
        gate = FileWriterGate(policy, self._root, key=self._key, witness=adapter)
        server = create_gateway_v3(gate, tls_context=self._server_tls, docker_socket=self._socket,
                                   pre_dispatch=guard, timeout=self._timeout, control_deadline=deadline)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        connection = watchdog = None
        try:
            guard()
            session = gate.open_generation(generation=desc['generation'], request_hash=self.request.digest(),
                receipt_hash=self._receipt, operations=desc['operations'], source_context_digest=desc['source'])
            attempt = session.prepare_attempt(operation['method'], operation['path'], body)
            headers = session.headers(attempt)
            headers.update({'Content-Length': str(len(body)), 'Content-Type': 'application/json', 'Connection': 'close'})
            thread.start()
            connection = http.client.HTTPSConnection('localhost', server.server_port,
                context=self._client_tls, timeout=max(.001,deadline-time.monotonic()))
            connection.connect()
            watchdog = runtime.deadline_watchdog(connection.sock, deadline)
            if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest() != self._pin:
                reject()
            connection.request(operation['method'], operation['path'], body=body, headers=headers)
            response = connection.getresponse(); raw = _complete_response(response)
            proof = gate.close_generation(desc['generation'])
            evidence = gate.generation_evidence(desc['generation'])
            # A gateway denial/unknown response cannot masquerade as a recorded Engine response.
            finishes = [e['data'] for e in evidence['events'] if e['kind'] == 'finish']
            import base64
            if len(finishes) != 1 or not finishes[0]['definitive'] or finishes[0]['status'] != response.status or base64.b64decode(finishes[0]['bodyBase64']) != raw:
                reject()
            result = dict(status=response.status, body=raw, closure=proof.to_json(),
                          gateEvidence=evidence, witness=adapter.authenticated_material_after(),
                          binding=binding, productionReady=False, fullTrust=False)
            self._evidence.append(deepcopy(result))
            if response.status != operation['expectedStatus']:
                reject()
            self._client = client; self._binding = binding; self._index += 1; self._blocked = False
            return result
        finally:
            server.cancel()
            if watchdog is not None: watchdog.cancel()
            if connection is not None:
                connection.close()
            if thread.is_alive():
                server.shutdown(); thread.join()
            server.server_close()

    def private_evidence(self):
        return deepcopy(self._evidence)

    def recovery_start(self):
        return deepcopy(self._resume)

    def public_review(self):
        return dict(self.bundle.public_review(), fullTrust=False, productionReady=False)


class ComposeCoordinatorV3:
    """Private one-shot workflow. Callbacks are mandatory trusted host code."""
    def __init__(self, executor, *, verify_candidates, readiness):
        if not callable(verify_candidates) or not callable(readiness):
            reject()
        self._executor = executor; self._verify = verify_candidates; self._ready = readiness
        self._used = False; self._evidence = []; self._receipts = {}; self._completed = []
        self._initial_write_count = 0
        self._resume = executor.recovery_start() if type(executor) is Profile3StepExecutor else None
        if self._resume is not None:
            self._initial_write_count = self._resume['startWriteIndex']
            self._receipts = deepcopy(self._resume['receiptMap'])
            self._completed = deepcopy(self._resume['completedOperations'])

    def run(self):
        if self._used:
            reject()
        self._used = True
        bundle = self._executor.bundle
        if self._resume is not None:
            for operation in self._completed:
                if operation['phase'] == 'readiness':
                    if self._ready(operation['service'], self._receipts[operation['service']]) is not True:
                        reject()
        def write(op):
            result = self._executor.execute(op, phase_index=self._initial_write_count+len(self._evidence),
                receipts=deepcopy(self._receipts), completed_operations=deepcopy(self._completed))
            self._evidence.append(result)
            if type(result['status']) is not int or result['status'] != op['expectedStatus']:
                reject()
            self._completed.append(deepcopy(op))
            return result
        forbidden = {s['baselineContainerId'] for s in bundle.to_dict()['services']} | {s['containerId'] for s in bundle.to_dict()['protectedContainers']}
        for op in bundle.creation_operations():
            if op['service'] in self._receipts:
                continue
            result = write(op)
            def pairs(items):
                value = {}
                for k, v in items:
                    if k in value: reject()
                    value[k] = v
                return value
            value = json.loads(result['body'], object_pairs_hook=pairs)
            cid = value.get('Id') if type(value) is dict else None
            if (result['status'] != 201 or type(cid) is not str or len(cid) != 64
                    or any(c not in '0123456789abcdef' for c in cid)
                    or cid in forbidden or cid in self._receipts.values()):
                reject()
            self._receipts[op['service']] = cid
        if self._resume is None or self._initial_write_count <= len(bundle.creation_operations()):
            if self._verify(immutable(self._receipts)) is not True:
                reject()
        for op in bundle.resolve_operations(self._receipts)[len(self._completed):]:
            if op['phase'] == 'readiness':
                if self._ready(op['service'], self._receipts[op['service']]) is not True:
                    reject()
                self._completed.append(deepcopy(op))
            else:
                write(op)
        return self.private_result()

    def private_result(self):
        return dict(receipts=deepcopy(self._receipts), evidence=deepcopy(self._evidence),
                    completedOperations=deepcopy(self._completed), initialWriteCount=self._initial_write_count,
                    fullTrust=False, productionReady=False)

    def public_review(self):
        return dict(self._executor.bundle.public_review(), fullTrust=False, productionReady=False)
