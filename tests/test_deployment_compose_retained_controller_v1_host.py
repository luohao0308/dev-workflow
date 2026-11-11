"""Framed controller tests with real signatures, witness and ledger double."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest

from tests.test_deployment_compose_production_frontend_approval_v1_host import approved, fixture, host
from tests.test_deployment_compose_production_frontend_v3_host import adapter, material
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, encode
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_compose_retained_controller_v1_host import RetainedControllerBlocked, RetainedControllerV1
from deployment_compose_retained_intent_relay_v1_host import RetainedIntentBindingV1, RetainedIntentClientV1
from deployment_compose_retained_native_channel_v1_host import _Channel, _binary
from deployment_compose_retained_write_v1_host import RetainedWriteV1
from deployment_compose_v3_channel_worker import read_frame
from deployment_compose_witness_store import canonical
from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material
from deployment_gateway import FileWriterGate, GatePolicy


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX and OpenSSH required')
class RetainedControllerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.intent = self.root/'intent'
        self.witness = self.root/'witness'
        for key in (self.intent, self.witness):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                           check=True, capture_output=True)
        self.public_intent = self.intent.with_suffix('.pub').read_bytes()
        self.public_witness = self.witness.with_suffix('.pub').read_bytes()
        row, image, options = material()
        old = next(iter(row['NetworkSettings']['Networks']))
        endpoint = row['NetworkSettings']['Networks'].pop(old)
        network = 'luohao-blog-prod_default'
        row['NetworkSettings']['Networks'][network] = endpoint
        row['HostConfig']['NetworkMode'] = network
        options['network_ids'] = {network: endpoint['NetworkID']}
        self.caddy = 'c'*64
        options['protected_container_ids'] = [self.caddy]
        options['expected_snapshot_digest'] = adapter.snapshot_digest(row, image, [self.caddy])
        self.private = adapter.prepare_frontend_plan(row, image, **options)
        self.nonce = '1'*64
        self.operation_nonce = '2'*64
        self.plan = prepare_retained_frontend_cutover(self.private, operation_nonce=self.operation_nonce)
        self.startup = dict(kind='production-startup', channelNonce=self.nonce, endpointDigest='3'*64,
            source=dict(profile='production-retained-v2', sourceSha='b'*40, archiveDigest='4'*64,
                        channelNonce=self.nonce, originDigest='5'*64),
            scope=dict(root='/var/lib/dev-workflow/retained', rootIdentity=[1, 2], journalIdentity=[1, 3],
                       hostId='host', project='luohao-blog-prod', daemonId='daemon'))
        self.kwargs = dict(startup=self.startup, expected_startup=self.startup, private_plan=self.private,
            operation_nonce=self.operation_nonce, policy_hash='f'*64, intent_signer=self.intent,
            intent_public_key=self.public_intent, witness_signer=self.witness, witness_public_key=self.public_witness,
            witness_root=self.root, witness_key=b'w'*32, gate_key=b'g'*32, caddy_id=self.caddy,
            network_id=endpoint['NetworkID'], timeout=75)
        self.cutover = dict(planDigest=self.plan.digest, operationNonce=self.operation_nonce,
                            protectionDigest='6'*64, runtimeArchiveDigest='4'*64)
        self.candidate = '7'*64
        self.certificate = '8'*64
        self.errors = []

    def _approval(self, review, operation):
        old, policy, _ = fixture()
        request = host.prepare_production_frontend_request(review, policy_hash=old.policy_hash,
                                                           expires_at=old.expires_at, operation=operation)
        policy = host.ProductionFrontendApprovalPolicyV2(**dict(vars(policy), operation=operation,
            snapshot_hash=request.before_hash, body_hash=request.after_hash, plan_hash=request.plan_hash,
            protected_inventory_hash=host._digest(list(request.protected_components)), request_hash=request.digest(),
            observation_hash=request.observation_hash, history_hash=request.history_hash))
        approval, client, _ = approved(policy, request)
        return approval, approval.validate(request), request, client

    def _peer(self, stream, scenario):
        channel = _Channel(self.nonce, stream, stream)
        shape = {'privatePlan', 'operationNonce', 'policyHash', 'intentPublicKey', 'witnessPublicKey',
                 'gateKey', 'caddyId', 'networkId'}
        _, config = channel.receive(('configure', shape), timeout=10)
        self.assertEqual(config['privatePlan'], self.private)
        review = dict(self.private['publicReview'], retainedCutover=self.cutover)
        channel.emit('prepared', review=review, writerCertificateSha256=self.certificate)
        _, frame = channel.receive(('execute', {'request'}), timeout=10)
        request = RequestV2.from_json(canonical(frame['request']).decode('ascii'))
        if scenario == 'wrong-nonce':
            from deployment_compose_v3_channel_worker import write_frame

            write_frame(stream, dict(kind='blocked', channelNonce='0'*64, knownPrefix=False))
            return
        source = self.startup['source']
        binding = RetainedIntentBindingV1(self.nonce, source['sourceSha'], source['archiveDigest'],
                                          source['originDigest'], self.cutover['protectionDigest'])

        def native_authority(req):
            def consume(rpc, before):
                if scenario != 'bad-challenge':
                    return channel.consume(rpc, before)
                channel.emit('rpc', service='intent', method='authorize', request=rpc)
                _, challenge = channel.receive(('consume-check', {'nonce', 'requestHash', 'scopeGeneration'}), timeout=10)
                channel.emit('consume-confirmed', **dict(challenge, scopeGeneration=2))
                return {}

            return RetainedIntentClientV1(req, binding=binding, public_key=_binary(config['intentPublicKey']),
                transport=lambda rpc: channel.rpc('intent', 'authorize', rpc), consume_transport=consume)

        def consume(req, generation):
            authority = native_authority(req)
            grant = authority.validate(req)
            if scenario == 'bad-challenge':
                with self.assertRaises(ValueError):
                    authority.consume(grant, req, before_consume=lambda: None, generation=generation)
                return None
            return authority.consume(grant, req, before_consume=lambda: None, generation=generation)

        def writes(req, receipt, generation, operations):
            receipt_hash = digest(vars(receipt))
            execution = digest(dict(plan=self.plan.digest, approvedReview=req.plan_hash,
                                     protection=self.cutover['protectionDigest'], scopeGeneration=generation,
                                     writerOrigin=source['originDigest']))
            first = channel.rpc('witness', 'register', dict(requestHash=req.digest(), receiptHash=receipt_hash,
                                executionDigest=execution, scopeGeneration=generation))
            evidence = []
            current = None
            public = _binary(config['witnessPublicKey'])
            for index, operation in enumerate(operations):
                desc = RetainedWriteV1.scope_descriptor(operation, request_hash=req.digest(), receipt_hash=receipt_hash,
                                                        plan_digest=execution, index=index)
                bound = dict(first, generation=desc['generation'], scopeHash=desc['scopeHash'])
                if current is not None:
                    previous = current.read()
                    current.transition_successor(expected_seq=previous['seq'], expected_head=previous['head'], childBinding=bound)
                current = OperationWitnessClientV3(bound, public, lambda method, rpc: channel.rpc('witness', method, rpc))
                policy = GatePolicy('blog-retained', 'retained-' + self.nonce[:16], config['policyHash'],
                    self.certificate, True, desc['scopeHash'], hashlib.sha256(key_material(public)).hexdigest(),
                    operation_profile='compose-v3')
                gate = FileWriterGate(policy, self.root/('gate-'+desc['generation']), key=_binary(config['gateKey']),
                                      witness=GateOperationWitnessAdapterV3(current))
                session = gate.open_generation(generation=desc['generation'], request_hash=req.digest(),
                    receipt_hash=receipt_hash, operations=desc['operations'], source_context_digest=desc['source'])
                attempt = session.prepare_attempt('POST', operation.path, operation.body)
                ticket = gate.admit(session.generation, attempt.ref, method='POST', path=operation.path,
                                    body=operation.body, writer_certificate_sha256=self.certificate)
                create = operation.phase == 'create'
                gate.finish_response(ticket, definitive=True, status=201 if create else 204,
                                     body=canonical({'Id': self.candidate}) if create else b'')
                proof = gate.close_generation(session.generation)
                material = GateOperationWitnessAdapterV3(current).authenticated_material_after()
                evidence.append(digest(dict(closure=proof.to_json(), gate=gate.generation_evidence(session.generation),
                                            witness=material, binding=bound)))
            return dict(requestHash=req.digest(), observationDigest='9'*64, protectionDigest=self.cutover['protectionDigest'],
                        witnessDigests=evidence, originalId=self.plan.original_id, candidateId=self.candidate)

        receipt = consume(request, 1)
        if scenario in ('dropped', 'bad-challenge'):
            return
        prefix = 1 if scenario == 'closed-prefix' else 4
        operations = (self.plan.create(), *self.plan.switch(self.candidate))
        deployed = writes(request, receipt, 1, operations[:prefix + 1])
        if scenario == 'forged-result':
            deployed['witnessDigests'][0] = '0'*64
            channel.emit('executed', result=deployed)
            return
        if prefix == 4:
            channel.emit('executed', result=deployed)
        retained = dict(self.cutover, candidateId=self.candidate, switchPrefix=prefix, candidateRunning=prefix == 4,
                        parentRequestHash=request.digest(), observationDigest=deployed['observationDigest'])
        channel.emit('restore-prepared', review=dict(review, retainedCutover=retained))
        kind, frame = channel.receive(('execute', {'request'}), ('finish', set()), timeout=10)
        if kind == 'finish':
            return
        rollback = RequestV2.from_json(canonical(frame['request']).decode('ascii'))
        generation = 1 if prefix < 4 else 2
        receipt = consume(rollback, generation)
        result = writes(rollback, receipt, generation, self.plan.restore(
            self.candidate, switch_prefix=prefix, candidate_running=prefix == 4))
        result.update(parentRequestHash=request.digest(), parentWitnessDigests=deployed['witnessDigests'])
        channel.emit('executed', result=result)

    def _connect(self, scenario):
        local, native = socket.socketpair()
        self.addCleanup(local.close)
        self.addCleanup(native.close)
        stream = local.makefile('rwb', buffering=0)
        self.addCleanup(stream.close)
        peer_stream = native.makefile('rwb', buffering=0)

        def peer():
            try:
                with peer_stream:
                    self._peer(peer_stream, scenario)
            except BaseException as error:
                self.errors.append(error)
            finally:
                native.close()

        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 10)
        controller = RetainedControllerV1(stream, stream, **self.kwargs)
        self.addCleanup(controller.close)
        return controller, thread

    def test_exact_deploy_and_separate_rollback_witness_reconciliation(self):
        controller, thread = self._connect('success')
        approval, grant, request, ledger = self._approval(controller.review, 'deploy')
        deployed = controller.execute(approval, grant, request)
        self.assertEqual(len(deployed['result']['witnessDigests']), 5)
        self.assertEqual(len(ledger.markers), 1)
        self.assertEqual(deployed['restoreReview']['retainedCutover']['parentRequestHash'], request.digest())
        approval, grant, rollback, ledger = self._approval(controller.review, 'rollback')
        restored = controller.execute(approval, grant, rollback)
        self.assertEqual(len(restored['result']['witnessDigests']), 4)
        self.assertEqual(len(ledger.markers), 1)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])

    def test_startup_drift_refuses_before_first_frame(self):
        with self.assertRaises(RetainedControllerBlocked):
            RetainedControllerV1(None, None, **dict(self.kwargs,
                expected_startup=dict(self.startup, endpointDigest='f'*64)))

    def test_closed_prefix_produces_recovery_review_without_claiming_deploy_success(self):
        controller, thread = self._connect('closed-prefix')
        approval, grant, request, _ = self._approval(controller.review, 'deploy')
        pending = controller.execute(approval, grant, request)
        self.assertIsNone(pending['result'])
        self.assertIs(pending['blocked'], False)
        self.assertEqual(pending['restoreReview']['retainedCutover']['switchPrefix'], 1)
        approval, grant, rollback, ledger = self._approval(controller.review, 'rollback')
        restored = controller.execute(approval, grant, rollback)
        self.assertEqual(len(restored['result']['witnessDigests']), 1)
        self.assertEqual(len(restored['result']['parentWitnessDigests']), 2)
        self.assertEqual(len(ledger.markers), 1)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])

    def test_lost_response_after_consumption_cannot_be_replayed(self):
        controller, thread = self._connect('dropped')
        approval, grant, request, ledger = self._approval(controller.review, 'deploy')
        with self.assertRaises(ValueError):
            controller.execute(approval, grant, request)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])
        self.assertEqual(len(ledger.markers), 1)
        with self.assertRaises(RetainedControllerBlocked):
            controller.execute(approval, grant, request)
        self.assertEqual(len(ledger.markers), 1)

    def test_wrong_challenge_echo_never_consumes(self):
        controller, thread = self._connect('bad-challenge')
        approval, grant, request, ledger = self._approval(controller.review, 'deploy')
        with self.assertRaises(Exception):
            controller.execute(approval, grant, request)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])
        self.assertFalse(ledger.markers)

    def test_wrong_channel_nonce_freezes_before_consumption(self):
        controller, thread = self._connect('wrong-nonce')
        approval, grant, request, ledger = self._approval(controller.review, 'deploy')
        with self.assertRaises(RetainedControllerBlocked):
            controller.execute(approval, grant, request)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])
        self.assertFalse(ledger.markers)

    def test_worker_result_cannot_replace_closed_evidence_digest(self):
        controller, thread = self._connect('forged-result')
        approval, grant, request, ledger = self._approval(controller.review, 'deploy')
        with self.assertRaises(RetainedControllerBlocked):
            controller.execute(approval, grant, request)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])
        self.assertEqual(len(ledger.markers), 1)
