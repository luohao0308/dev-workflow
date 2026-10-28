"""Local signed-history recovery through genuine consent, fence, Gate and mTLS."""
import hashlib
import json
import os
import shutil
import socketserver
import ssl
import threading
import unittest
from copy import deepcopy
from dataclasses import replace
from http.server import BaseHTTPRequestHandler

from tests import test_deployment_compose_prepare_v3_host as prepare_fixture
from tests import test_deployment_compose_history_v3_host as history_fixture
from tests import test_deployment_compose_recovery_prepare_v3_host as recovery_fixture
from tests import test_deployment_compose_approval_v3_host as approval_fixture
from tests import test_deployment_compose_write_gateway_v3_host as tls_fixture
from tests.test_release_host import claims
from deployment_compose_prepare_v3_host import ComposePreparationHostV3
from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, baseline_state_bytes
from deployment_compose_reader_host import _UnixDocker
from deployment_compose_coordinator_v3_host import Profile3StepExecutor, ComposeCoordinatorV3, canonical
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_image_defaults import ZERO_DEFAULTS
from deployment_compose_startup_fence_v3_host import Profile3RecoveryFenceV3
import deployment_compose_approval_v3_host as approval_host


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'), 'TLS/SSH required')
class RecoveryExecutionTests(history_fixture.GateFixture, unittest.TestCase):
    setUpClass = classmethod(tls_fixture.WriteGatewayTests.setUpClass.__func__)
    tearDownClass = classmethod(tls_fixture.WriteGatewayTests.tearDownClass.__func__)

    def run_recovery(self, count, *, two_services=False, fail_resumed_readiness=False):
        kw, observation = prepare_fixture.fixture()
        kw['source'] = approval_fixture.request().source
        prepared = ComposePreparationHostV3(**kw).prepare_intent(observation, observation,
            operation_nonce='f'*64, expires_at=recovery_fixture.expiry())
        bundle = prepared['bundle']; rows = deepcopy(kw['whole_observer']._unit_rows)
        store = kw['recovery']._store
        request = replace(prepared['request'], expires_at='2020-01-01T00:00:00Z')
        if two_services:
            value = bundle.to_dict()
            for key in ('operations','resolverRules','resolverContract','imageDefaultsDigests'): value.pop(key)
            service = deepcopy(value['services'][0]); service.update(name='api',finalName='dw-api-1',
                baselineContainerId='7'*64, dependsOn=['web'])
            for key in ('baselineCreateBody','targetCreateBody'):
                service[key]['Labels']['com.docker.compose.service'] = 'api'
            value['services'].append(service)
            value['mounts']['api'] = deepcopy(value['mounts']['web'])
            for network in value['networks'].values(): network['aliases']['api'] = deepcopy(network['aliases']['web'])
            row = deepcopy(rows[value['services'][0]['baselineContainerId']])
            row.update(Id='7'*64, Name='/dw-api-1')
            row['Config']['Labels']['com.docker.compose.service'] = 'api'
            rows['7'*64] = row
            raw = baseline_state_bytes(rows)
            value['baselineStateReference'] = store.put(raw)
            value['baselineStateDigest'] = hashlib.sha256(raw).hexdigest()
            bundle = ExecutionBundleV3(value, authenticated_image_defaults={n:deepcopy(ZERO_DEFAULTS) for n in ('web','api')})
            request = replace(request, components=('api','web'), plan_hash=bundle.digest)
        baseline = deepcopy(rows)
        version = {'Version':'29.8.2','GitCommit':'8af9fe3'}
        timeline = []; writes = []
        services = {s['name']:s for s in bundle.to_dict()['services']}
        receipts = {n:('a' if n=='web' else 'b')*64 for n in services}

        def apply(operation):
            service = services[operation['service']]; phase = operation['phase']
            cid = receipts[operation['service']]
            if phase == 'create':
                row = deepcopy(baseline[service['baselineContainerId']]); body = operation['body']
                row.update(Id=cid, Name='/dwc-'+bundle.to_dict()['operationNonce'][:24]+'-'+service['name'], Image=body['Image'])
                row['Config'] = {k:deepcopy(v) for k,v in body.items() if k not in ('HostConfig','NetworkingConfig')}
                row['HostConfig'] = deepcopy(body['HostConfig'])
                row['State'].update(Pid=0,StartedAt='',Running=False,Status='created')
                rows[cid] = row
            elif phase == 'stop': rows[service['baselineContainerId']]['State'].update(Pid=0,Running=False,Status='exited')
            elif phase == 'delete': del rows[service['baselineContainerId']]
            elif phase == 'rename': rows[cid]['Name'] = '/'+service['finalName']
            elif phase == 'start': rows[cid]['State'].update(Pid=999,StartedAt='recovered',Running=True,Status='running')
            return json.dumps({'Id':cid}).encode() if phase=='create' else b''

        all_operations = bundle.resolve_operations(receipts)
        write_operations = [o for o in all_operations if o['method'] != 'GET']
        def read(path):
            if path.endswith('/version'): return version
            if path.endswith('/info'): return {'ID':kw['daemon_id']}
            if '/containers/json?' in path: return [{'Id':cid} for cid in rows]
            if '/containers/' in path: return deepcopy(rows[path.split('/')[-2]])
            if '/networks/' in path:
                name,pin = next((n,p) for n,p in bundle.to_dict()['networks'].items() if p['id']==path.split('/')[-1])
                return dict(Id=pin['id'],Name=name,Labels={'com.docker.compose.project':bundle.to_dict()['identity']['project']},Containers={cid:{} for cid in rows})
            if '/volumes/' in path:
                name=path.split('/')[-1]
                return dict(Name=name,Driver='local',Options=None,Mountpoint='/var/lib/docker/volumes/'+name+'/_data')
            raise AssertionError(path)
        class Backend(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def respond(self,status,body):
                self.send_response(status);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            def do_GET(self): self.respond(200,json.dumps(read(self.path)).encode())
            def write_operation(self):
                body=self.rfile.read(int(self.headers.get('Content-Length','0')))
                op=next(o for o in write_operations if o['method']==self.command and o['path']==self.path)
                if body != (b'' if op['body'] is None else canonical(op['body'])): raise AssertionError('wrong body')
                writes.append(op);timeline.append(('write',op['phase'],op['service']))
                self.respond(201 if op['phase']=='create' else 204,apply(op))
            do_POST=write_operation
            do_DELETE=write_operation
        class Unix(socketserver.ThreadingMixIn,socketserver.UnixStreamServer): daemon_threads=True
        socket_path = self.root/'recovery.sock'
        backend=Unix(str(socket_path),Backend)
        threading.Thread(target=backend.serve_forever,daemon=True).start()
        self.addCleanup(backend.server_close);self.addCleanup(backend.shutdown)
        def get(path):
            connection=_UnixDocker(str(socket_path),3)
            try:
                connection.request('GET',path);response=connection.getresponse()
                self.assertEqual(response.status,200)
                return json.loads(response.read())
            finally: connection.close()
        guard=PhaseGuardV3(bundle,baseline,read_json=get,daemon_version=version)
        def readiness(service,cid):
            timeline.append(('ready',service))
            row=get('/v1.45/containers/'+cid+'/json')
            return row['State']['Running'] is True and row['State']['Health']['Status']=='healthy'

        h=history_fixture.HistoryTests('test_two_scopes_and_no_local_files')
        h.setup_gate_fixture();self.addCleanup(h.doCleanups)
        h.bundle=bundle;h.req=request;h.receipts={};h.index=0
        cert=hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'client.pem').read_text())).hexdigest()
        h.cert=cert
        h.policy=replace(h.policy,writer_certificate_sha256=cert)
        h.binding=dict(h.binding,policyHash=h.policy.identity_hash())
        # Each historical write is genuinely signed, consumed and closed by FileWriterGate.
        for index,op in enumerate(write_operations[:count]):
            h.index=index
            # The shared one-service helper assumes all receipts after create one.
            # Build the same real scope explicitly for a partial multi-create prefix.
            if 0 < len(h.receipts) < len(services):
                from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
                h.op=op
                descriptor=Profile3StepExecutor.scope_descriptor(bundle,request,h.receipt,op,index,h.receipts)
                next_binding=dict(h.binding,generation=descriptor['generation'],scopeHash=descriptor['scopeHash'])
                view=h.client.read()
                h.client.transition_successor(expected_seq=view['seq'],expected_head=view['head'],childBinding=next_binding)
                h.binding=next_binding;h.client=h.factory(next_binding)
                h.adapter=GateOperationWitnessAdapterV3(h.client)
                h.policy=replace(h.policy,witness_scope_hash=descriptor['scopeHash'])
                h.gen=descriptor['generation'];h.request=request.digest();h.source=descriptor['source'];h.ops=descriptor['operations']
                h.body=b'' if op['body'] is None else canonical(op['body']);h.current_gate=h.gate()
            else:
                h.open_scope()
            body=apply(op)
            h.finish(status=201 if op['phase']=='create' else 204,body=body)
            if op['phase']=='create': h.receipts[op['service']]=receipts[op['service']]
        parent=h.history()
        prep=RecoveryPreparationHostV3(original_history=parent,store=store,phase_guard=guard,readiness=readiness)
        recovery=prep.prepare_intent(operation_nonce='e'*64,expires_at=recovery_fixture.expiry())
        req=recovery['request']; reviewed=recovery['reviewed_history']
        approval=approval_fixture.ComposeApprovalTests();approval.setUp();approval.req=req
        approval.policy=approval_fixture.policy(operation='recovery',expected_history_hash=reviewed.digest,
            bundle_hash=bundle.digest,host_id=req.host_id,daemon_id=req.daemon_id,components=req.components,
            protected_components=req.protected_components,target=req.target,deployment_environment=req.environment,
            policy_hash=req.policy_hash)
        approval.claims=dict(claims(approval.policy),aud=approval_host.AUDIENCE)
        approval.client=approval.client_for([req]);authority=approval.approval()
        consumed=authority.consume(authority.validate(req),req)
        receipt=hashlib.sha256(str(consumed).encode()).hexdigest()
        desc=Profile3StepExecutor.scope_descriptor(bundle,req,receipt,write_operations[count],count,h.receipts)
        binding=dict(h.binding,generation=desc['generation'],scopeHash=desc['scopeHash'])
        gate_policy=replace(h.policy,witness_scope_hash=desc['scopeHash'])
        server_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.directory/'server.pem',self.directory/'server.key')
        server_tls.load_verify_locations(self.directory/'ca.pem');server_tls.verify_mode=ssl.CERT_REQUIRED
        client_tls=ssl.create_default_context(cafile=self.directory/'ca.pem')
        client_tls.load_cert_chain(self.directory/'client.pem',self.directory/'client.key')
        fence=Profile3RecoveryFenceV3(preparation=prep,context_reference=recovery['recovery_context_reference'],
            reviewed_history=reviewed,quiesce_writer=lambda:True)
        args=dict(intent_authority=authority,phase_guard=guard,gate_root=self.root/'recovery-gate',
            gate_key=b'g'*32,gate_policy=gate_policy,consumption_receipt_hash=receipt,
            witness_client_factory=h.factory,registered_binding=binding,tls_server_context=server_tls,
            tls_client_context=client_tls,server_certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'server.pem').read_text())).hexdigest(),
            docker_socket=socket_path,timeout=3)
        with self.assertRaises(ValueError): Profile3StepExecutor(bundle,req,**args)
        self.assertEqual(writes,[])
        executor=Profile3StepExecutor(bundle,req,startup_fence=fence,**args)
        def verify_candidates(candidate_receipts):
            for cid in candidate_receipts.values():
                self.assertFalse(get('/v1.45/containers/'+cid+'/json')['State']['Running'])
            return True
        coordinator=ComposeCoordinatorV3(executor,verify_candidates=verify_candidates,readiness=readiness)
        timeline.clear()
        if fail_resumed_readiness:
            rows[receipts['web']]['State']['Health']['Status']='unhealthy'
            with self.assertRaises(ValueError): coordinator.run()
            self.assertEqual(writes,[])
            self.assertEqual(timeline,[('ready','web')])
            return
        result=coordinator.run()
        self.assertEqual(writes,write_operations[count:])
        self.assertEqual(result['initialWriteCount'],count)
        self.assertEqual(result['receipts'],receipts)
        child_client=h.factory(executor._binding)
        from deployment_compose_history_v3_host import AuthenticatedHistoryV3
        child=AuthenticatedHistoryV3(bundle,req,gate_policy=gate_policy,gate_key=b'g'*32,
            consumption_receipt_hash=receipt,witness_client=child_client,witness_client_factory=h.factory,
            parent_history=parent,reviewed_parent_snapshot=reviewed).capture().snapshot
        self.assertEqual(len(child['knownPrefix']),len(write_operations))
        self.assertEqual(len(child['scopes']),len(write_operations)-count)
        self.assertEqual(child['parent']['startWriteIndex'],count)
        if two_services:
            start=timeline.index(('write','start','api'))
            self.assertIn(('ready','web'),timeline[:start])
        return result

    def setUp(self):
        # Own a temporary POSIX root without importing another TestCase's tests.
        from tests.test_deployment_compose_operation_witness_client_v3 import SignedOperationWitnessTests
        SignedOperationWitnessTests.setUp(self)

    def test_recovery_after_create(self): self.run_recovery(1)
    def test_recovery_after_stop(self): self.run_recovery(2)
    def test_recovery_after_delete(self): self.run_recovery(3)
    def test_recovery_after_rename(self): self.run_recovery(4)
    def test_recovery_after_first_start_rechecks_dependency_readiness(self): self.run_recovery(9,two_services=True)

    def test_unhealthy_prior_start_blocks_dependent_before_write(self):
        self.run_recovery(9,two_services=True,fail_resumed_readiness=True)
