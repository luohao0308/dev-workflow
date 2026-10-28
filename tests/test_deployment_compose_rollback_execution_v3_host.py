"""Fresh rollback consent and signed lineage through the real TLS write executor."""
import hashlib
import json
import os
import shutil
import socketserver
import ssl
import threading
import unittest
from copy import deepcopy
from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler

from tests import test_deployment_compose_history_v3_host as history_fixture
from tests.test_deployment_compose_gate_witness_v3 import GateFixture
from tests.test_deployment_compose_bundle_v3 import fixture, bind_baseline, baseline_rows
from tests import test_deployment_compose_write_gateway_v3_host as tls_fixture
from tests import test_deployment_compose_approval_v3_host as approval_fixture
from tests.test_release_host import claims
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_coordinator_v3_host import Profile3StepExecutor, canonical
from deployment_compose_startup_fence_v3_host import Profile3StartupFenceV3
import deployment_compose_approval_v3_host as approval_host


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'), 'TLS/SSH required')
class RollbackExecutionTests(GateFixture, unittest.TestCase):
    setUpClass = classmethod(tls_fixture.WriteGatewayTests.setUpClass.__func__)
    tearDownClass = classmethod(tls_fixture.WriteGatewayTests.tearDownClass.__func__)
    factory = history_fixture.HistoryTests.factory
    open_scope = history_fixture.HistoryTests.open_scope
    finish = history_fixture.HistoryTests.finish
    history = history_fixture.HistoryTests.history
    complete_deploy = history_fixture.HistoryTests.complete_deploy

    def setUp(self):
        self.setup_gate_fixture()
        value, self.defaults = fixture()
        value['identity']['project'] = 'dw-blog'
        for key in ('baselineCreateBody','targetCreateBody'):
            value['services'][0][key]['Labels']['com.docker.compose.project'] = 'dw-blog'
        bind_baseline(value)
        req = approval_fixture.request(target=replace(approval_fixture.request().target,
            namespace=value['identity']['project']))
        value['identity'].update(hostId=req.host_id, daemonId=req.daemon_id,
            sourceIdentity=canonical(asdict(req.source)).decode())
        self.bundle = ExecutionBundleV3(value, authenticated_image_defaults=self.defaults)
        self.req = replace(req, plan_hash=self.bundle.digest, components=('web',))
        cert = hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'client.pem').read_text())).hexdigest()
        self.cert = cert
        self.policy = replace(self.policy, writer_certificate_sha256=cert)
        self.binding = dict(self.binding, policyHash=self.policy.identity_hash())
        self.receipts = {}; self.index = 0
        self.open_scope()

    def test_fresh_rollback_executes_only_child_create(self):
        parent, reviewed = self.complete_deploy()
        original_request = self.req
        value = self.bundle.to_dict()
        # Restore the archived original image from a baseline representing the deployed target.
        original = deepcopy(value)
        for key in ('operations','resolverRules','resolverContract','imageDefaultsDigests'):
            value.pop(key)
        service = value['services'][0]
        original_body = deepcopy(service['baselineCreateBody'])
        service.update(baselineContainerId='a'*64, baselineImageId=service['targetImageId'],
                       baselineCreateBody=deepcopy(service['targetCreateBody']),
                       targetImageId=original_body['Image'], targetCreateBody=original_body)
        value['operationNonce'] = '8'*64
        rows = bind_baseline(value)
        original_rows = baseline_rows(original)
        value['protectedContainers'] = deepcopy(original['protectedContainers'])
        for protected in value['protectedContainers']:
            rows[protected['containerId']] = original_rows[protected['containerId']]
        from deployment_compose_phase_guard_v3_host import baseline_state_digest
        value['baselineStateDigest'] = baseline_state_digest(rows)
        self.bundle = ExecutionBundleV3(value, authenticated_image_defaults=self.defaults)
        self.req = replace(original_request, operation='rollback', history_hash=reviewed.digest,
                           plan_hash=self.bundle.digest)
        fixture_approval = approval_fixture.ComposeApprovalTests()
        fixture_approval.setUp()
        fixture_approval.req = self.req
        fixture_approval.policy = approval_fixture.policy(operation='rollback',
            expected_history_hash=reviewed.digest, bundle_hash=self.bundle.digest,
            host_id=self.req.host_id, daemon_id=self.req.daemon_id,
            components=self.req.components, target=self.req.target)
        fixture_approval.claims = dict(claims(fixture_approval.policy), aud=approval_host.AUDIENCE)
        fixture_approval.client = fixture_approval.client_for([self.req])
        authority = fixture_approval.approval()
        consumed = authority.consume(authority.validate(self.req), self.req)
        self.receipt = hashlib.sha256(str(consumed).encode()).hexdigest()
        operation = self.bundle.creation_operations()[0]
        desc = Profile3StepExecutor.scope_descriptor(self.bundle,self.req,self.receipt,operation,0,{})
        binding = dict(self.binding, generation=desc['generation'], scopeHash=desc['scopeHash'])
        self.policy = replace(self.policy, witness_scope_hash=desc['scopeHash'])
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.directory/'server.pem', self.directory/'server.key')
        server_tls.load_verify_locations(self.directory/'ca.pem'); server_tls.verify_mode = ssl.CERT_REQUIRED
        client_tls = ssl.create_default_context(cafile=self.directory/'ca.pem')
        client_tls.load_cert_chain(self.directory/'client.pem', self.directory/'client.key')
        writes = []
        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                writes.append((self.path, self.rfile.read(int(self.headers['Content-Length']))))
                body = json.dumps({'Id':'b'*64}).encode()
                self.send_response(201); self.send_header('Content-Length',str(len(body)))
                self.end_headers(); self.wfile.write(body)
        class Unix(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        backend = Unix(str(self.root/'rollback.sock'), Backend)
        threading.Thread(target=backend.serve_forever,daemon=True).start()
        self.addCleanup(backend.server_close); self.addCleanup(backend.shutdown)
        args = dict(intent_authority=authority, phase_guard=lambda _: True,
            gate_root=self.root/'rollback-gate', gate_key=b'g'*32, gate_policy=self.policy,
            consumption_receipt_hash=self.receipt, witness_client_factory=self.factory,
            registered_binding=binding, tls_server_context=server_tls, tls_client_context=client_tls,
            server_certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'server.pem').read_text())).hexdigest(),
            docker_socket=self.root/'rollback.sock', timeout=3)
        with self.assertRaises(ValueError):
            Profile3StepExecutor(self.bundle,self.req,**args)
        self.assertEqual(writes, [])
        old_status = parent._client.chain_status()
        fence = Profile3StartupFenceV3(original_history=parent, reviewed_history=reviewed,
                                       quiesce_writer=lambda: True)
        executor = Profile3StepExecutor(self.bundle,self.req,startup_fence=fence,**args)
        result = executor.execute(operation, phase_index=0, receipts={}, completed_operations=[])
        self.assertEqual(result['status'], 201)
        self.assertEqual(writes, [(operation['path'],canonical(operation['body']))])
        self.assertEqual(json.loads(writes[0][1])['Image'], original_body['Image'])
        tail = reviewed.snapshot['closedTail']
        with self.assertRaises(ValueError):
            self.factory(dict(tail['binding'])).transition_successor(expected_seq=tail['seq'],
                expected_head=tail['head'], childBinding=binding)
        self.client = self.factory(binding)
        child = self.history(parent_history=parent,reviewed_parent_snapshot=reviewed).capture()
        self.assertEqual(child.snapshot['schemaVersion'], 2)
        self.assertEqual(len(child.snapshot['knownPrefix']), 1)
        self.assertEqual(child.snapshot['receiptMap']['web'], 'b'*64)
        self.assertEqual(child.snapshot['parent']['historyDigest'], reviewed.digest)
        self.assertNotEqual(self.client.chain_status(), old_status)

    def test_fresh_deploy_cannot_omit_signed_ancestor(self):
        from unittest.mock import patch
        # One closed real Gate scope is sufficient to establish an ancestor.
        self.finish()
        self.req = replace(self.req, observation_hash='e'*64)
        approval = approval_fixture.ComposeApprovalTests(); approval.setUp()
        approval.req = self.req
        approval.policy = approval_fixture.policy(bundle_hash=self.bundle.digest,
            host_id=self.req.host_id, daemon_id=self.req.daemon_id,
            components=self.req.components, target=self.req.target)
        approval.claims = dict(claims(approval.policy), aud=approval_host.AUDIENCE)
        approval.client = approval.client_for([self.req])
        authority = approval.approval()
        consumed = authority.consume(authority.validate(self.req), self.req)
        receipt = hashlib.sha256(str(consumed).encode()).hexdigest()
        operation = self.bundle.creation_operations()[0]
        desc = Profile3StepExecutor.scope_descriptor(self.bundle,self.req,receipt,operation,0,{})
        binding = dict(self.binding,generation=desc['generation'],scopeHash=desc['scopeHash'])
        tail = self.client.read()
        self.client.transition_successor(expected_seq=tail['seq'],expected_head=tail['head'],childBinding=binding)
        child = self.factory(binding)
        before = child.chain_status()
        self.assertEqual(before['activeSeq'],0)
        self.assertTrue(before['lineage'])
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.directory/'server.pem',self.directory/'server.key')
        server_tls.load_verify_locations(self.directory/'ca.pem');server_tls.verify_mode=ssl.CERT_REQUIRED
        client_tls = ssl.create_default_context(cafile=self.directory/'ca.pem')
        client_tls.load_cert_chain(self.directory/'client.pem',self.directory/'client.key')
        executor = Profile3StepExecutor(self.bundle,self.req,intent_authority=authority,
            phase_guard=lambda _:True,gate_root=self.root/'ancestor-gate',gate_key=b'g'*32,
            gate_policy=replace(self.policy,witness_scope_hash=desc['scopeHash']),
            consumption_receipt_hash=receipt,witness_client_factory=self.factory,
            registered_binding=binding,tls_server_context=server_tls,tls_client_context=client_tls,
            server_certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'server.pem').read_text())).hexdigest(),
            docker_socket=self.root/'unused.sock',timeout=3)
        with patch('deployment_compose_coordinator_v3_host.create_gateway_v3') as gateway, \
             patch('deployment_compose_coordinator_v3_host.FileWriterGate.open_generation') as opening, \
             patch('deployment_compose_write_gateway_v3_host._UnixDocker') as docker:
            with self.assertRaises(ValueError):
                executor.execute(operation,phase_index=0,receipts={},completed_operations=[])
            gateway.assert_not_called();opening.assert_not_called();docker.assert_not_called()
        self.assertEqual(child.chain_status(),before)
        self.assertEqual(child.events_after(seq=0,head='0'*64),[])
