"""UNIT executor tests isolate workflow sequencing from cryptographic transport."""
from copy import deepcopy
import json
import unittest
from tests.test_deployment_compose_bundle_v3 import fixture
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_coordinator_v3_host import ComposeCoordinatorV3, check_witness_capacity


class UnitExecutor:
    def __init__(self, ids=None):
        v, d = fixture()
        api = deepcopy(v['services'][0]); api.update(name='api', finalName='api-1', baselineContainerId='7'*64, dependsOn=['web'])
        for key in ('baselineCreateBody', 'targetCreateBody'):
            api[key]['Labels']['com.docker.compose.service'] = 'api'
        v['services'].append(api); d['api'] = deepcopy(d['web']); v['mounts']['api'] = deepcopy(v['mounts']['web'])
        for net in v['networks'].values(): net['aliases']['api'] = ['web']
        self.bundle = ExecutionBundleV3(v, authenticated_image_defaults=d)
        self.calls = []; self.ids = ids or {'web':'a'*64, 'api':'b'*64}
    def execute(self, operation, **context):
        self.calls.append((deepcopy(operation), deepcopy(context)))
        return dict(status=201 if operation['phase']=='create' else 204,
                    body=json.dumps({'Id':self.ids[operation['service']]}).encode() if operation['phase']=='create' else b'', closure='UNIT')


class CoordinatorTests(unittest.TestCase):
    def test_oversized_witness_plan_rejected_before_execution(self):
        v, defaults = fixture()
        original = deepcopy(v['services'][0])
        for index in range(1, 7):
            service = deepcopy(original)
            name = 'service' + str(index)
            service.update(name=name, finalName=name+'-1', baselineContainerId=format(index+2, '064x'))
            for key in ('baselineCreateBody', 'targetCreateBody'):
                service[key]['Labels']['com.docker.compose.service'] = name
            v['services'].append(service)
            defaults[name] = deepcopy(defaults['web'])
            v['mounts'][name] = deepcopy(v['mounts']['web'])
            for network in v['networks'].values():
                network['aliases'][name] = ['web']
        bundle = ExecutionBundleV3(v, authenticated_image_defaults=defaults)
        with self.assertRaises(ValueError):
            check_witness_capacity(bundle)
        v['services'].pop()
        defaults.pop('service6'); v['mounts'].pop('service6')
        for network in v['networks'].values():
            network['aliases'].pop('service6')
        check_witness_capacity(ExecutionBundleV3(v, authenticated_image_defaults=defaults))

    def test_dependency_order_exact_ids_and_readiness(self):
        executor = UnitExecutor(); events = []
        def verify(receipts):
            self.assertEqual(len(executor.calls), 2)
            with self.assertRaises(TypeError): receipts['web'] = 'c'*64
            events.append('verified'); return True
        coordinator = ComposeCoordinatorV3(executor, verify_candidates=verify,
            readiness=lambda service,cid: events.append((service,cid)) or True)
        result = coordinator.run()
        self.assertEqual([(o['phase'],o['service']) for o,_ in executor.calls],
            [('create','web'),('create','api'),('stop','api'),('stop','web'),('delete','api'),('delete','web'),('rename','web'),('rename','api'),('start','web'),('start','api')])
        self.assertEqual(events, ['verified',('web','a'*64),('api','b'*64)])
        self.assertTrue(all(o['path'].endswith('?force=false&v=false') for o,_ in executor.calls if o['phase']=='delete'))
        self.assertEqual([ctx['phase_index'] for _,ctx in executor.calls], list(range(10)))
        self.assertFalse(result['productionReady']); self.assertNotIn('Env',json.dumps(coordinator.public_review()))
        with self.assertRaises(ValueError): coordinator.run()

    def test_candidate_failure_zero_old_stops(self):
        for ids in ({'web':'1'*64,'api':'b'*64},{'web':'2'*64,'api':'b'*64},
                    {'web':'short','api':'b'*64},{'web':'a'*64,'api':'a'*64}):
            executor=UnitExecutor(ids)
            coordinator=ComposeCoordinatorV3(executor,verify_candidates=lambda _:True,readiness=lambda *_:True)
            with self.assertRaises(ValueError): coordinator.run()
            self.assertTrue(all(o['phase']=='create' for o,_ in executor.calls))

    def test_candidate_verifier_and_health_stop_later_writes(self):
        executor=UnitExecutor()
        coordinator=ComposeCoordinatorV3(executor,verify_candidates=lambda _:False,readiness=lambda *_:True)
        with self.assertRaises(ValueError): coordinator.run()
        self.assertEqual(len(executor.calls),2)
        executor=UnitExecutor()
        coordinator=ComposeCoordinatorV3(executor,verify_candidates=lambda _:True,readiness=lambda *_:False)
        with self.assertRaises(ValueError): coordinator.run()
        self.assertEqual(executor.calls[-1][0]['service'],'web')
        self.assertEqual(executor.calls[-1][0]['phase'],'start')
        self.assertEqual(len(coordinator.private_result()['evidence']),9)

    def test_callbacks_required(self):
        with self.assertRaises(ValueError): ComposeCoordinatorV3(UnitExecutor(),verify_candidates=None,readiness=lambda *_:True)

    def test_unexpected_success_code_stops_before_next_write(self):
        executor = UnitExecutor()
        original = executor.execute
        def execute(operation, **context):
            result = original(operation, **context)
            if operation['phase'] == 'stop':
                result['status'] = 200
            return result
        executor.execute = execute
        coordinator = ComposeCoordinatorV3(executor, verify_candidates=lambda _:True,
                                           readiness=lambda *_:True)
        with self.assertRaises(ValueError):
            coordinator.run()
        self.assertEqual([op['phase'] for op,_ in executor.calls], ['create','create','stop'])

# Real transport fixture: cryptographic witness, consumed approval and mTLS Unix Engine.
import hashlib
import os
from pathlib import Path
import shutil
import socketserver
import ssl
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler
from tests import test_deployment_compose_write_gateway_v3_host as gateway_fixture
from tests.test_deployment_compose_gate_witness_v3 import GateFixture, signed
from tests import test_deployment_compose_approval_v3_host as approval_fixture_module
from tests.test_deployment_compose_approval_v3_host import policy, request
from deployment_contract_v2 import TargetIdentity
from deployment_compose_coordinator_v3_host import Profile3StepExecutor


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'), 'TLS/SSH required')
class ExecutorIntegrationTests(GateFixture, unittest.TestCase):
    setUpClass = classmethod(gateway_fixture.WriteGatewayTests.setUpClass.__func__)
    tearDownClass = classmethod(gateway_fixture.WriteGatewayTests.tearDownClass.__func__)

    def setUp(self):
        self.setup_gate_fixture()

    def test_actual_executor_consumed_approval_signed_gate_tls_unix(self):
        v,d = fixture(); v['identity']['project']='dw-blog'
        for key in ('baselineCreateBody','targetCreateBody'):
            v['services'][0][key]['Labels']['com.docker.compose.project']='dw-blog'
        from dataclasses import asdict
        from deployment_compose_coordinator_v3_host import canonical
        v['identity']['sourceIdentity']=canonical(asdict(request().source)).decode('ascii')
        bundle=ExecutionBundleV3(v, authenticated_image_defaults=d)
        target=TargetIdentity('compose','dw-blog','stack')
        req=request(plan_hash=bundle.digest, host_id='host', daemon_id='daemon', components=('web',), target=target)
        approval_fixture=approval_fixture_module.ComposeApprovalTests(); approval_fixture.setUp()
        approval_fixture.req=req
        approval_fixture.policy=policy(bundle_hash=bundle.digest, host_id='host', daemon_id='daemon', components=('web',),target=target)
        from tests.test_release_host import claims
        import deployment_compose_approval_v3_host as approval_host
        approval_fixture.claims=dict(claims(approval_fixture.policy),aud=approval_host.AUDIENCE)
        approval_fixture.client=approval_fixture.client_for([req])
        authority=approval_fixture.approval()
        consumed=authority.consume(authority.validate(req),req)
        receipt_hash=hashlib.sha256(str(consumed).encode()).hexdigest()
        cert=hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'client.pem').read_text())).hexdigest()
        operation=bundle.creation_operations()[0]
        desc=Profile3StepExecutor.scope_descriptor(bundle,req,receipt_hash,operation,0,{})
        gate_policy=replace(self.policy,writer_certificate_sha256=cert,witness_scope_hash=desc['scopeHash'])
        binding=dict(self.binding,scopeHash=desc['scopeHash'],generation=desc['generation'],policyHash=gate_policy.identity_hash())
        (self.root/'executor-witness').mkdir(mode=0o700)
        self.store=signed.OperationWitnessStoreV3(self.root/'executor-witness',key=b'w'*32)
        self.addCleanup(self.store.close); self.store.register_once(binding)
        server_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.directory/'server.pem',self.directory/'server.key')
        server_tls.load_verify_locations(self.directory/'ca.pem');server_tls.verify_mode=ssl.CERT_REQUIRED
        client_tls=ssl.create_default_context(cafile=self.directory/'ca.pem')
        client_tls.load_cert_chain(self.directory/'client.pem',self.directory/'client.key')
        writes=[]
        class Backend(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                writes.append((self.path,self.rfile.read(int(self.headers['Content-Length']))))
                created = '/create?' in self.path
                body=json.dumps({'Id':'a'*64}).encode() if created else b''
                self.send_response(201 if created else 204);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_DELETE(self):
                writes.append((self.path,b''))
                self.close_connection=True
        class Unix(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):daemon_threads=True
        backend=Unix(str(self.root/'docker.sock'),Backend)
        threading.Thread(target=backend.serve_forever,daemon=True).start()
        self.addCleanup(backend.server_close);self.addCleanup(backend.shutdown)
        guards=[]
        def guard(snapshot):
            guards.append(snapshot)
            with self.assertRaises(TypeError):snapshot['receipts']['x']='bad'
            return True
        executor=Profile3StepExecutor(bundle,req,intent_authority=authority,phase_guard=guard,
            gate_root=self.root/'executor-gate',gate_key=b'g'*32,gate_policy=gate_policy,
            consumption_receipt_hash=receipt_hash, witness_client_factory=lambda b:signed.OperationWitnessClientV3(b,self.public,self.transport),
            registered_binding=binding,tls_server_context=server_tls,tls_client_context=client_tls,
            server_certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'server.pem').read_text())).hexdigest(),
            docker_socket=self.root/'docker.sock',timeout=3)
        result=executor.execute(operation,phase_index=0,receipts={},completed_operations=[])
        self.assertEqual(result['status'],201); self.assertEqual(len(writes),1)
        self.assertEqual(len(result['witness']['records']),6);self.assertGreaterEqual(len(guards),3)
        self.assertFalse(result['productionReady'])
        receipts={'web':'a'*64}
        resolved=bundle.resolve_operations(receipts)
        stopped=executor.execute(resolved[1],phase_index=1,receipts=receipts,completed_operations=[operation])
        self.assertEqual(len(stopped['witness']['records']),6)
        self.assertEqual(len(executor.private_evidence()),2)
        with self.assertRaises(ValueError):
            executor.execute(resolved[2],phase_index=2,receipts=receipts,completed_operations=resolved[:2])
        with self.assertRaises(ValueError):
            executor.execute(resolved[2],phase_index=2,receipts=receipts,completed_operations=resolved[:2])
        self.assertEqual(len(writes),3)
