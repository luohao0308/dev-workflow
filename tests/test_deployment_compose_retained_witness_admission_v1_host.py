"""Real Gate envelopes and SSH signatures with an explicit GitHub service double."""
import base64
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.test_deployment_compose_production_frontend_approval_v1_host import approved, fixture, host
from tests.test_deployment_compose_production_frontend_v3_host import adapter, material
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_compose_retained_witness_admission_v1_host import RetainedWitnessAdmissionV1, _digest, _LINEAGE_NAMESPACE
from deployment_compose_retained_write_v1_host import RetainedWriteV1
from deployment_compose_witness_store import ZERO, canonical
from deployment_gate_witness import key_material
from deployment_gateway import FileWriterGate, GatePolicy


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX and OpenSSH required')
class RetainedWitnessAdmissionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.signer = self.root/'witness-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.signer)],
                       check=True, capture_output=True)
        self.public = self.signer.with_suffix('.pub').read_bytes()
        row, image, options = material()
        self.protected = 'a'*64
        options['protected_container_ids'] = [self.protected]
        options['expected_snapshot_digest'] = adapter.snapshot_digest(row, image, [self.protected])
        self.private = adapter.prepare_frontend_plan(row, image, **options)
        self.plan = prepare_retained_frontend_cutover(self.private, operation_nonce='1'*64)
        self.key = b'g'*32
        self.cert = 'c'*64
        self.origin = '7'*64
        self.candidate = 'e'*64
        self.protection = '8'*64
        self.registration = self._registration()

    def _registration(self, *, parent=None, prefix=1, candidate=None, stage=None, creation=None,
                      creation_witness=None, switch_witness=None, generation=1, reviewed_generation=1):
        old, policy, _ = fixture()
        cutover = dict(planDigest=self.plan.digest, operationNonce='1'*64,
                       protectionDigest=self.protection, runtimeArchiveDigest='9'*64)
        operation = 'deploy'
        first = self.plan.create()
        if stage is not None:
            cutover['stage'] = stage
        if stage in ('switch', 'rollback'):
            candidate = candidate or self.candidate
            cutover.update(candidateId=candidate, creationRequestHash=creation.digest(),
                           creationWitnessDigest=creation_witness, observationDigest='6'*64,
                           scopeGeneration=reviewed_generation)
            if stage == 'switch':
                first = self.plan.switch(candidate)[0]
            else:
                cutover['switchWitnessDigest'] = switch_witness
        if parent is not None and stage != 'switch':
            operation = 'rollback'
            candidate = candidate or self.candidate
            cutover.update(candidateId=candidate, switchPrefix=prefix, candidateRunning=False,
                           parentRequestHash=parent.digest(), observationDigest='6'*64)
            first = self.plan.restore(candidate, switch_prefix=prefix, candidate_running=False)[0]
        review = dict(self.private['publicReview'], retainedCutover=cutover)
        request = host.prepare_production_frontend_request(review, policy_hash=old.policy_hash,
                                                           expires_at=old.expires_at, operation=operation)
        policy_type = host.ProductionFrontendApprovalPolicyV3 if stage else host.ProductionFrontendApprovalPolicyV2
        stage_fields = {'stage': stage} if stage else {}
        policy = policy_type(**dict(vars(policy), operation=operation,
            snapshot_hash=request.before_hash, body_hash=request.after_hash, plan_hash=request.plan_hash,
            protected_inventory_hash=host._digest(list(request.protected_components)), request_hash=request.digest(),
            observation_hash=request.observation_hash, history_hash=request.history_hash, **stage_fields))
        approval, _, _ = approved(policy, request)
        consumption = approval.consume(approval.validate(request), request)
        receipt_hash = _digest(asdict(consumption))
        execution_digest = _digest(dict(plan=self.plan.digest, approvedReview=request.plan_hash,
            protection=self.protection, scopeGeneration=generation, writerOrigin=self.origin))
        desc = RetainedWriteV1.scope_descriptor(first, request_hash=request.digest(), receipt_hash=receipt_hash,
                                                plan_digest=execution_digest, index=0)
        gate_policy = GatePolicy('retained-test', 'retained-key', '4'*64, self.cert, True, desc['scopeHash'],
                                 hashlib.sha256(key_material(self.public)).hexdigest(), operation_profile='compose-v3')
        root = self.root/request.digest()
        root.mkdir(mode=0o700)
        store = OperationWitnessStoreV3(root, key=b'w'*32)
        self.addCleanup(store.close)
        return dict(store=store, gate_policy=gate_policy, gate_key=self.key, witness_signer=self.signer,
                    witness_public_key=self.public, private_plan=self.private, review=review, request=request,
                    approval=approval, consumption=consumption, scope_generation=generation, writer_origin_digest=self.origin)

    def _complete(self, broker, binding, operation, index, *, body=b'', status=204, definitive=True):
        desc = self._descriptor(broker, operation, index)
        policy = replace(broker._policy, witness_scope_hash=desc['scopeHash'])
        client = broker.client(binding)
        gate = FileWriterGate(policy, self.root/('gate-'+desc['generation']), key=self.key,
                              witness=GateOperationWitnessAdapterV3(client))
        session = gate.open_generation(generation=desc['generation'], request_hash=broker._entry['request'].digest(),
            receipt_hash=broker.receipt_hash, operations=desc['operations'], source_context_digest=desc['source'])
        attempt = session.prepare_attempt('POST', operation.path, operation.body)
        ticket = gate.admit(session.generation, attempt.ref, method='POST', path=operation.path,
                            body=operation.body, writer_certificate_sha256=self.cert)
        gate.finish_response(ticket, definitive=definitive, status=status, body=body)
        if definitive:
            gate.close_generation(session.generation)
        return client

    def _descriptor(self, broker, operation, index):
        return RetainedWriteV1.scope_descriptor(operation, request_hash=broker._entry['request'].digest(),
            receipt_hash=broker.receipt_hash, plan_digest=broker.execution_digest, index=index)

    def _advance(self, broker, parent, operation, index):
        desc = self._descriptor(broker, operation, index)
        binding = dict(parent.binding, scopeHash=desc['scopeHash'], generation=desc['generation'])
        value = parent.read()
        parent.transition_successor(expected_seq=value['seq'], expected_head=value['head'], childBinding=binding)
        return binding

    def _create(self, broker, candidate=None):
        return self._complete(broker, broker.first_binding, self.plan.create(), 0, status=201,
                              body=json.dumps({'Id': candidate or self.candidate}).encode())

    def test_exact_signed_successor_and_separately_approved_restore(self):
        broker = RetainedWitnessAdmissionV1(**self.registration)
        create = self._create(broker)
        stop = self.plan.switch(self.candidate)[0]
        binding = self._advance(broker, create, stop, 1)
        stopped = self._complete(broker, binding, stop, 1)
        child = RetainedWitnessAdmissionV1(**self._registration(parent=self.registration['request']), parent=broker)
        operation = self.plan.restore(self.candidate, switch_prefix=1, candidate_running=False)[0]
        restored = self._complete(child, child.first_binding, operation, 0)
        self.assertEqual(restored.read()['phase'], 'closed')
        with self.assertRaises(ValueError):
            self._advance(broker, stopped, self.plan.switch(self.candidate)[1], 2)

    def _check_lineage_file(self, registration, broker, parent=None):
        raw = self._lineage_path(registration).read_bytes()
        value = json.loads(raw)
        payload = value['payload']
        self.assertEqual(payload['requestHash'], registration['request'].digest())
        self.assertEqual(payload['firstBinding'], broker.first_binding)
        self.assertEqual(payload['parentBinding'], parent.first_binding if parent else None)
        self.assertEqual(payload['parentLineageDigest'], parent._lineage_digest if parent else None)
        allowed = self.root/'allowed-lineage'
        allowed.write_bytes(b'fixture ' + key_material(self.public) + b'\n')
        signature = self.root/'lineage.sig'
        signature.write_bytes(base64.b64decode(value['signature'], validate=True))
        subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'fixture',
                        '-n', _LINEAGE_NAMESPACE, '-s', str(signature)], input=canonical(payload),
                       capture_output=True, check=True)

    def _lineage_path(self, registration):
        return self.root / (registration['request'].digest() + '.retained-lineage.json')

    def test_staged_brokers_bind_closed_evidence_and_persist_signed_lineage(self):
        creation = self._registration(stage='create')
        create = RetainedWitnessAdmissionV1(**creation)
        created = self._create(create)
        candidate, witnesses = create.closed_chain()
        self.assertEqual(candidate, self.candidate)
        stop = self.plan.switch(candidate)[0]
        with self.assertRaises(ValueError):
            self._advance(create, created, stop, 1)
        self._check_lineage_file(creation, create)
        switch = self._registration(stage='switch', creation=creation['request'], creation_witness=witnesses[0])
        cutover = RetainedWitnessAdmissionV1(**switch, parent=create)
        self._check_lineage_file(switch, cutover, create)
        self._complete(cutover, cutover.first_binding, stop, 0)
        _, stopped = cutover.closed_chain()
        invalid = self._registration(stage='rollback', parent=switch['request'], creation=creation['request'],
                                     creation_witness=witnesses[0], switch_witness='0'*64)
        with self.assertRaises(ValueError):
            RetainedWitnessAdmissionV1(**invalid, parent=cutover)
        rollback = self._registration(stage='rollback', parent=switch['request'], creation=creation['request'],
                                      creation_witness=witnesses[0], switch_witness=_digest(stopped))
        restore = RetainedWitnessAdmissionV1(**rollback, parent=cutover)
        self._check_lineage_file(rollback, restore, cutover)
        start = self.plan.restore(candidate, switch_prefix=1, candidate_running=False)[0]
        client = self._complete(restore, restore.first_binding, start, 0)
        self.assertEqual(client.read()['phase'], 'closed')

    def test_staged_switch_rejects_wrong_candidate_witness_generation_and_lineage(self):
        creation = self._registration(stage='create')
        create = RetainedWitnessAdmissionV1(**creation)
        self._create(create)
        _, witnesses = create.closed_chain()
        verified = dict(stage='switch', creation=creation['request'], creation_witness=witnesses[0])
        for changes in (dict(candidate='d'*64), dict(creation_witness='0'*64),
                        dict(generation=2, reviewed_generation=2), dict(reviewed_generation=3)):
            with self.subTest(changes=changes):
                invalid = self._registration(**(verified | changes))
                with self.assertRaises(ValueError):
                    RetainedWitnessAdmissionV1(**invalid, parent=create)
                self.assertFalse(self._lineage_path(invalid).exists())
        lineage = self._lineage_path(creation)
        lineage.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            RetainedWitnessAdmissionV1(**self._registration(**verified), parent=create)

    def test_successor_cannot_choose_candidate_or_skip_step(self):
        broker = RetainedWitnessAdmissionV1(**self.registration)
        create = self._create(broker)
        for operation in (self.plan.switch('d'*64)[2], self.plan.switch(self.candidate)[1]):
            with self.assertRaises(ValueError):
                self._advance(broker, create, operation, 1)
        self.assertEqual(create.chain_status()['activeBinding'], broker.first_binding)

    def test_protected_id_in_create_response_cannot_be_used(self):
        broker = RetainedWitnessAdmissionV1(**self.registration)
        create = self._create(broker, self.protected)
        with self.assertRaises(ValueError):
            self._advance(broker, create, self.plan.switch(self.candidate)[0], 1)

    def test_unknown_create_response_cannot_advance(self):
        broker = RetainedWitnessAdmissionV1(**self.registration)
        create = self._complete(broker, broker.first_binding, self.plan.create(), 0,
                                status=0, definitive=False)
        self.assertEqual(create.read()['phase'], 'blocked')
        with self.assertRaises(ValueError):
            self._advance(broker, create, self.plan.switch(self.candidate)[0], 1)

    def test_registered_store_cannot_be_reset_or_relocated(self):
        RetainedWitnessAdmissionV1(**self.registration)
        with self.assertRaises(ValueError):
            RetainedWitnessAdmissionV1(**self.registration)
        root = self.root/'other-request'
        root.mkdir(mode=0o700)
        store = OperationWitnessStoreV3(root, key=b'w'*32)
        self.addCleanup(store.close)
        with self.assertRaises(ValueError):
            RetainedWitnessAdmissionV1(**dict(self.registration, store=store))
        self.assertFalse((root/'state.json').exists())

    def test_wrong_hmac_or_valid_mac_with_wrong_receipt_never_appends(self):
        broker = RetainedWitnessAdmissionV1(**self.registration)
        binding = broker.first_binding
        desc = self._descriptor(broker, self.plan.create(), 0)
        for receipt in (broker.receipt_hash, '5'*64):
            payload = dict(generation=binding['generation'], directory=[1, 2], previous=ZERO, kind='open',
                data=dict(request_hash=self.registration['request'].digest(), receipt_hash=receipt,
                          operations=[list(desc['operations'][0])], source_binding_schema=1,
                          source_context_digest=desc['source']))
            envelope = dict(version=1, domain='dev-workflow.writer-gate.event',
                            policy=self.registration['gate_policy']._binding(), payload=payload)
            key = b'x'*32 if receipt == broker.receipt_hash else self.key
            envelope['mac'] = hmac.new(key, canonical(envelope), hashlib.sha256).hexdigest()
            raw = canonical(envelope)
            event = dict(binding=binding, sequence=1, previousHead=ZERO, kind='open', data={},
                         materialDigest=hashlib.sha256(raw).hexdigest())
            with self.assertRaises(ValueError):
                broker.client(binding).append_event(expected_seq=0, expected_head=ZERO, event=event, external_material=raw)
        self.assertEqual(broker.client(binding).read()['phase'], 'empty')

    def test_no_registration_with_drift_or_deserialized_parent(self):
        altered = deepcopy(self.private)
        altered['privateBody']['Env'].append('UNAPPROVED=1')
        with self.assertRaises(ValueError):
            RetainedWitnessAdmissionV1(**dict(self.registration, private_plan=altered))
        with self.assertRaises(ValueError):
            RetainedWitnessAdmissionV1(**self._registration(parent=self.registration['request']),
                                       parent={'requestHash': self.registration['request'].digest()})
