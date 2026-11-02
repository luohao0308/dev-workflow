"""Synthetic closed-create history for retained-Engine fixture preparation.

Gate events and the create response below are synthetic fixture assertions even
when candidate_id names a real seed container. No product writer, approval or
Engine API is invoked. Only real local HMAC, SSHSIG and witness machinery run.
The parent retains every signing/store key; readers receive signed reads only.
"""
import base64
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'packs/deployment/scripts', 'packs/release/scripts'))]
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_history_v3_host import AuthenticatedHistoryV3
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, dispatch_request, encode, NAMESPACE, hex_value
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_witness_store import canonical
from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material
from deployment_gateway import FileWriterGate, GatePolicy

_READS = frozenset({'read', 'check', 'events_after', 'chain_status'})


class SyntheticClosedCreateHistory:
    """One synthetic local scope; never real admission or execution authority."""
    syntheticFixtureHistory = True
    authorityGranted = False
    runtimePermit = False
    productionReady = False

    def __init__(self, root):
        self.store = None
        self._attempted = self._sealed = self._closed = False
        self.calls = []
        self._write_owner = None
        try:
            if (not isinstance(root, Path) or not root.is_absolute() or root.resolve(strict=True) != root
                    or root.is_relative_to(ROOT)):
                raise ValueError('synthetic-history-root')
            info = root.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('synthetic-history-root')
            self.root = root
            self.key = root/'witness-signing'
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)],
                           check=True, capture_output=True, timeout=10)
            self.key.chmod(0o600)
            self.public = self.key.with_suffix('.pub').read_bytes()
            self.gate_key = secrets.token_bytes(32)
            self.store_key = secrets.token_bytes(32)
            witness = root/'witness'
            witness.mkdir(mode=0o700)
            self.store = OperationWitnessStoreV3(witness, key=self.store_key)
            self.policy = GatePolicy('synthetic-retained-fixture', 'synthetic-retained-gate',
                secrets.token_hex(32), hashlib.sha256(b'synthetic-fixture-no-product-writer').hexdigest(),
                True, '0'*64, hashlib.sha256(key_material(self.public)).hexdigest(), operation_profile='compose-v3')
            self._epoch = secrets.token_hex(32)
        except BaseException:
            self.close()
            raise

    def transport(self, method, request):
        if (self._closed or method not in _READS and
                (self._sealed or self._write_owner != (os.getpid(),threading.get_ident()))):
            raise ValueError('synthetic-history-readonly')
        self.calls.append(method)
        payload = dispatch_request(self.store, method, request)
        signed = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(self.key), '-n', NAMESPACE],
            input=encode(payload), capture_output=True, check=True, timeout=10)
        return dict(payload=payload, signature=base64.b64encode(signed.stdout).decode('ascii'))

    def _client(self, binding):
        return OperationWitnessClientV3(binding, self.public, self.transport)

    def close_create(self, bundle, request, candidate_id):
        if self._closed or self._attempted:
            raise ValueError('synthetic-history-once')
        self._attempted = True
        if (type(bundle) is not ExecutionBundleV3 or type(request) is not RequestV2
                or request.policy_hash != self.policy.identity_hash() or request.plan_hash != bundle.digest
                or request.operation != 'deploy' or request.profile_version != '3' or request.production is not False
                or not hex_value(candidate_id) or len(bundle.to_dict()['services']) != 1):
            raise ValueError('synthetic-history-identity')
        value = bundle.to_dict()
        forbidden = {s['baselineContainerId'] for s in value['services']} | {p['containerId'] for p in value['protectedContainers']}
        creates = bundle.creation_operations()
        if len(creates) != 1 or creates[0]['phase'] != 'create' or candidate_id in forbidden:
            raise ValueError('synthetic-history-candidate')
        operation = creates[0]
        receipt = hashlib.sha256(b'synthetic-retained-engine-receipt-v3\0'+candidate_id.encode('ascii')).hexdigest()
        descriptor = Profile3StepExecutor.scope_descriptor(bundle, request, receipt, operation, 0, {})
        self.policy = replace(self.policy, witness_scope_hash=descriptor['scopeHash'])
        binding = dict(epoch=self._epoch, policyHash=self.policy.identity_hash(),
                       generation=descriptor['generation'], scopeHash=descriptor['scopeHash'])
        self.store.register_once(binding)
        client = self._client(binding)
        adapter = GateOperationWitnessAdapterV3(client)
        gate = FileWriterGate(self.policy, self.root/'gate', key=self.gate_key, witness=adapter)
        self._write_owner = (os.getpid(),threading.get_ident())
        try:
            session = gate.open_generation(generation=descriptor['generation'], request_hash=request.digest(),
                receipt_hash=receipt, operations=descriptor['operations'], source_context_digest=descriptor['source'])
            body = b'' if operation['body'] is None else canonical(operation['body'])
            attempt = session.prepare_attempt(operation['method'], operation['path'], body)
            ticket = gate.admit(descriptor['generation'], attempt.ref, method=attempt.method,
                path=attempt.path, body=body, writer_certificate_sha256=self.policy.writer_certificate_sha256)
            # Explicitly synthetic: this is not a retained product HTTP receipt.
            gate.finish_response(ticket, definitive=True, status=201, body=canonical({'Id':candidate_id}))
            gate.close_generation(descriptor['generation'])
            self._sealed = True
            history = AuthenticatedHistoryV3(bundle, request, gate_policy=self.policy, gate_key=self.gate_key,
                consumption_receipt_hash=receipt, witness_client=client, witness_client_factory=self._client)
            snapshot = history.capture().snapshot
            if snapshot['blocker'] is not None or dict(snapshot['receiptMap']) != {operation['service']:candidate_id}:
                raise ValueError('synthetic-history-closure')
            return history
        finally:
            self._sealed = True
            self._write_owner = None

    def close(self):
        self._closed = True
        if self.store is not None:
            self.store.close()
