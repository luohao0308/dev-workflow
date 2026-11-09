"""Trusted cold SDK execution with Gate/mTLS/Unix and explicit host doubles.

GitHub authorization responses, Engine, source identity and writer quiescence
are test observations. No native scene-owner or production recovery is claimed.
"""
from copy import deepcopy, copy
from dataclasses import asdict, replace
import hashlib
import json
import os
import base64
import socketserver
import ssl
import subprocess
import sys
import threading
import selectors
import signal
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_recovery_execution_v3_host as execution
from tests import test_deployment_compose_approval_v3_host as approvals
from tests.test_release_host import claims
from tests.test_deployment_compose_recovery_prepare_v3_host import expiry
from deployment_compose_history_v3_host import ANCESTRY_PROFILE
from deployment_compose_reader_host import _UnixDocker
from deployment_compose_witness_store import canonical
from deployment_compose_bounded_restart_material_v3_host import capture_material
from deployment_compose_restart_material_v3_host import _context
from deployment_compose_image_defaults import ZERO_DEFAULTS
from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
import deployment_compose_approval_v3_host as approval_host


class ExpectedRejection(Exception):
    pass


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'), 'TLS/OpenSSH required')
class ColdRecoveryTests(execution.history_fixture.GateFixture, unittest.TestCase):
    setUpClass = classmethod(execution.RecoveryExecutionTests.setUpClass.__func__)
    tearDownClass = classmethod(execution.RecoveryExecutionTests.tearDownClass.__func__)
    setUp = execution.RecoveryExecutionTests.setUp
    run_recovery = execution.RecoveryExecutionTests.run_recovery

    def prefix(self, h, operations, socket_path, writes, store, bundle):
        self.engine_writes = writes
        h.req = replace(h.req, policy_hash=h.policy.identity_hash())
        h.index = 0
        h.open_scope()
        ticket = h.admitted(h.current_gate)
        connection = _UnixDocker(str(socket_path), 5)
        try:
            operation = operations[0]
            connection.request(operation['method'], operation['path'], canonical(operation['body']),
                               headers={'Content-Type':'application/json'})
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.status, 201)
            h.current_gate.finish_response(ticket, definitive=True, status=response.status, body=body)
            h.current_gate.close_generation(h.gen)
            h.receipts = {operation['service']:json.loads(body)['Id']}
        finally:
            connection.close()
        return lambda: True

    def approval(self, request):
        helper = approvals.ComposeApprovalTests()
        helper.setUp()
        helper.req = request
        helper.policy = approvals.policy(operation='recovery', expected_history_hash=request.history_hash,
            bundle_hash=request.plan_hash, host_id=request.host_id, daemon_id=request.daemon_id,
            components=request.components, protected_components=request.protected_components,
            target=request.target, deployment_environment=request.environment, policy_hash=request.policy_hash)
        helper.claims = dict(claims(helper.policy), aud=approval_host.AUDIENCE)
        helper.client = helper.client_for([request])
        return helper.approval()

    def run_case(self, attack=None):
        def consume_cold(**values):
            old = values['preparation']._history
            bundle = old._bundle
            h = values['h']
            if attack == 'subprocess':
                from deployment_compose_coordinator_v3_host import Profile3StepExecutor
                from deployment_compose_startup_fence_v3_host import Profile3RecoveryFenceV3
                from deployment_compose_history_v3_host import AuthenticatedHistoryV3
                prepared = values['prepared']
                context = values['context']
                executor = Profile3StepExecutor(bundle, prepared['request'], intent_authority=values['authority'],
                    phase_guard=values['guard'], gate_root=self.root/'before-cold-gate', gate_key=b'g'*32,
                    gate_policy=values['gate_policy'], consumption_receipt_hash=values['receipt'],
                    witness_client_factory=h.factory, registered_binding=values['binding'],
                    tls_server_context=values['tls'][0], tls_client_context=values['tls'][1],
                    server_certificate_sha256=values['tls'][2], docker_socket=values['socket_path'], timeout=5,
                    startup_fence=Profile3RecoveryFenceV3(preparation=values['preparation'],
                        context_reference=prepared['recovery_context_reference'],
                        reviewed_history=prepared['reviewed_history'], quiesce_writer=lambda: True))
                executor.execute(context['nextOperation'], phase_index=1, receipts=context['receiptMap'],
                                 completed_operations=context['completedOperations'])
                old = AuthenticatedHistoryV3(bundle, prepared['request'], gate_policy=values['gate_policy'],
                    gate_key=b'g'*32, consumption_receipt_hash=values['receipt'],
                    witness_client=h.factory(values['binding']), witness_client_factory=h.factory,
                    parent_history=old, reviewed_parent_snapshot=prepared['reviewed_history'], ancestry_profile=ANCESTRY_PROFILE)
                self.assertEqual(len(old.capture().snapshot['segments']), 2)
                self.assertEqual(len(old.capture().snapshot['knownPrefix']), 2)
            raw_baseline = values['store'].get(bundle.to_dict()['baselineStateReference'])
            raw = capture_material(old, baseline_bytes_by_bundle={bundle.digest:raw_baseline},
                authenticated_image_defaults_by_bundle={bundle.digest:{name:deepcopy(ZERO_DEFAULTS)
                    for name in ('web', 'api')}}, archive_digest='9'*64)
            pins = _context(old, old.capture(), '9'*64)
            server = next(fn.__self__ for fn,args,kwargs in self._cleanups if getattr(fn,'__name__','')=='shutdown')
            handler = server.RequestHandlerClass
            original_get = handler.do_GET
            expected_root = str(self.root/'engine-data')
            terminal_ready = False
            terminal_reads = 0
            def get_with_root(subject):
                nonlocal terminal_reads
                if subject.path == '/v1.45/info':
                    terminal_reads += int(terminal_ready)
                    root = expected_root+'-drift' if attack == 'terminal-drift' and terminal_reads == 2 else expected_root
                    subject.respond(200, json.dumps(dict(ID=old._request.daemon_id, DockerRootDir=root)).encode())
                elif subject.path.startswith('/test/readiness/'):
                    _, _, _, service, cid = subject.path.split('/')
                    subject.respond(200, canonical(values['readiness'](service, cid)))
                else:
                    original_get(subject)
            def readiness(service, cid):
                nonlocal terminal_ready
                if service == 'api':
                    terminal_ready = True
                if attack == 'readiness-failure':
                    return False
                return values['readiness'](service, cid)
            with patch.object(handler, 'do_GET', get_with_root):
                if attack == 'subprocess':
                    return self.cold_processes(values, raw, pins, expected_root, parent_history=old)
                preparation_fault = dict(host=None, calls=0)
                def readonly_transport(method, request):
                    if attack == 'prepare-state-mutation' and preparation_fault['host'] is not None:
                        preparation_fault['calls'] += 1
                        preparation_fault['host']._state = 'new'
                        raise ValueError('readonly callback failed during preparation')
                    return h.transport(method, request)
                host = ColdRecoveryHostV3(raw, expected_digest=hashlib.sha256(raw).hexdigest(), expected_context=pins,
                    gate_key=b'g'*32, witness_public_key=h.public, witness_transport=readonly_transport,
                    store=values['store'], docker_socket=values['socket_path'], daemon_version=values['guard']._version,
                    expected_docker_root=expected_root, readiness=readiness)
                if attack == 'prepare-state-mutation':
                    before_prepare = (h.store.root/'state.json').read_bytes()
                    preparation_fault['host'] = host
                    for _ in range(2):
                        with self.assertRaises(ValueError):
                            host.prepare_intent(operation_nonce='c'*64, expires_at=expiry())
                    self.assertEqual(preparation_fault['calls'], 1)
                    self.assertEqual(host._state, 'blocked')
                    self.assertEqual(self.engine_writes, [])
                    self.assertEqual((h.store.root/'state.json').read_bytes(), before_prepare)
                    raise ExpectedRejection()
                if attack == 'method-shadow':
                    with patch.object(host._preparation, 'verify_context', side_effect=AssertionError('shadow method called')) as verify:
                        with self.assertRaises(ValueError):
                            host.prepare_intent(operation_nonce='c'*64, expires_at=expiry())
                        verify.assert_not_called()
                    self.assertEqual(host._state, 'blocked')
                    self.assertEqual(self.engine_writes, [])
                    raise ExpectedRejection()
                candidate = host.prepare_intent(operation_nonce='c'*64, expires_at=expiry())
                approval_request = candidate['request']
                if attack == 'equivalent-request':
                    approval_request = replace(approval_request)
                elif attack == 'wrong-request':
                    approval_request = replace(approval_request, observation_hash='e'*64)
                approval = self.approval(approval_request)
                args = dict(witness_client_factory=h.factory, quiesce_writer=lambda: True,
                    gate_root=self.root/'cold-gate', tls_server_context=values['tls'][0],
                    tls_client_context=values['tls'][1], server_certificate_sha256=values['tls'][2], timeout=5)
                before = (h.store.root/'state.json').read_bytes()
                if attack == 'owner':
                    self.check_owner_guards(host, approval, args)
                    self.assertEqual(self.engine_writes, [])
                    self.assertEqual((h.store.root/'state.json').read_bytes(), before)
                    raise ExpectedRejection()
                if attack == 'fake-approval':
                    approval = {'request':asdict(candidate['request'])}
                elif attack == 'active-writer':
                    args['quiesce_writer'] = lambda: False
                elif attack == 'stale':
                    approval.verifier = lambda _: dict(claims(approval.policy), aud=approval_host.AUDIENCE, exp=0)
                elif attack in ('state-mutation', 'new-state-mutation'):
                    original_validate = approval.validate
                    def validate(request):
                        result = original_validate(request)
                        host._state = 'new' if attack == 'new-state-mutation' else 'prepared'
                        return result
                    approval.validate = validate
                elif attack == 'guard-mutation':
                    original_validate = approval.validate
                    def validate(request):
                        result = original_validate(request)
                        host._guard._services.clear()
                        return result
                    approval.validate = validate
                elif attack == 'tls-mutation':
                    def quiesce():
                        args['tls_client_context'].check_hostname = False
                        return True
                    args['quiesce_writer'] = quiesce
                elif attack == 'quiesce-raises':
                    def quiesce():
                        raise ValueError('writer stop observation failed')
                    args['quiesce_writer'] = quiesce
                elif attack == 'clone-witness':
                    from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
                    from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, dispatch_request
                    directory = self.root/'cloned-witness'
                    shutil.copytree(h.store.root, directory)
                    clone = OperationWitnessStoreV3(directory, key=h.store._key)
                    self.addCleanup(clone.close)
                    def transport(method, request):
                        return h.sign(dispatch_request(clone, method, request))
                    args['witness_client_factory'] = lambda binding: OperationWitnessClientV3(binding, h.public, transport)
                if attack not in (None, 'equivalent-request'):
                    with self.assertRaises(ValueError):
                        host.execute(approval, **args)
                    if attack in ('readiness-failure', 'terminal-drift'):
                        inspected = host.inspect_history()
                        self.assertEqual(len(inspected.capture().snapshot['knownPrefix']), 9 if attack == 'readiness-failure' else 10)
                    else:
                        self.assertEqual(self.engine_writes, [])
                        self.assertEqual((h.store.root/'state.json').read_bytes(), before)
                    self.assertEqual(host._state, 'spent')
                    with self.assertRaises(ValueError):
                        host.prepare_intent(operation_nonce='b'*64, expires_at=expiry())
                    if type(approval) is approval_host.GitHubFullBodyApprovalV3:
                        with patch.object(approval, 'validate', wraps=approval.validate) as validate:
                            with self.assertRaises(ValueError):
                                host.execute(approval, **args)
                            validate.assert_not_called()
                    else:
                        with self.assertRaises(ValueError):
                            host.execute(approval, **args)
                    raise ExpectedRejection()
                result, history = host.execute(approval, **args)
                self.assertTrue(result['recoveryComplete'])
                self.assertFalse(result['runtimePermit'])
                self.assertIs(host.inspect_history(), history)
                terminal_bytes = (h.store.root/'state.json').read_bytes()
                write_count = len(self.engine_writes)
                with self.assertRaises(ValueError):
                    ColdRecoveryHostV3(raw, expected_digest=hashlib.sha256(raw).hexdigest(), expected_context=pins,
                        gate_key=b'g'*32, witness_public_key=h.public, witness_transport=h.transport,
                        store=values['store'], docker_socket=values['socket_path'], daemon_version=values['guard']._version,
                        expected_docker_root=expected_root, readiness=readiness)
                self.assertEqual((h.store.root/'state.json').read_bytes(), terminal_bytes)
                self.assertEqual(len(self.engine_writes), write_count)
                with self.assertRaises(ValueError):
                    host.execute(approval, **args)
                with self.assertRaises(ValueError):
                    host.prepare_intent(operation_nonce='b'*64, expires_at=expiry())
                return result, history.capture().snapshot
        if attack in (None, 'subprocess', 'equivalent-request'):
            return self.run_recovery(1, two_services=True, ancestry_profile=ANCESTRY_PROFILE,
                prefix_runner=self.prefix, continuation_runner=consume_cold,
                expected_initial_write_count=2 if attack == 'subprocess' else None)
        with self.assertRaises(ExpectedRejection):
            self.run_recovery(1, two_services=True, ancestry_profile=ANCESTRY_PROFILE,
                prefix_runner=self.prefix, continuation_runner=consume_cold)

    def test_two_services_recover_from_cold_material_with_fresh_consumption(self):
        self.run_case()

    def test_equivalent_reconstructed_request_can_receive_fresh_approval(self):
        self.run_case('equivalent-request')

    def test_wrong_request_approval_rejects_before_mutation(self):
        self.run_case('wrong-request')

    def test_fake_approval_rejects_before_mutation(self):
        self.run_case('fake-approval')

    def test_expired_approval_rejects_before_mutation(self):
        self.run_case('stale')

    def test_active_writer_rejects_before_cas(self):
        self.run_case('active-writer')

    def test_preparation_method_shadow_rejected_before_context(self):
        self.run_case('method-shadow')

    def test_prepare_callback_failure_cannot_reset_host_to_new(self):
        self.run_case('prepare-state-mutation')

    def test_quiescence_callback_tls_downgrade_rejects_before_cas(self):
        self.run_case('tls-mutation')

    def test_callback_cannot_reset_spent_attempt_to_new(self):
        self.run_case('new-state-mutation')

    def test_approval_callback_state_mutation_rejects_before_cas(self):
        self.run_case('state-mutation')

    def test_quiescence_callback_failure_blocks_cas(self):
        self.run_case('quiesce-raises')

    def test_copied_witness_factory_blocks_before_engine_writes(self):
        self.run_case('clone-witness')

    def test_guard_callback_mutation_blocks_before_cas(self):
        self.run_case('guard-mutation')

    def test_failed_readiness_retains_inspectable_closed_history(self):
        self.run_case('readiness-failure')

    def check_owner_guards(self, host, approval, args):
        def calls(target):
            return (lambda: target.prepare_intent(operation_nonce='8'*64, expires_at=expiry()),
                    lambda: target.execute(approval, **args), target.inspect_history)
        rejected = []
        def foreign():
            for call in calls(host):
                try:
                    call()
                except ValueError:
                    rejected.append(True)
                else:
                    rejected.append(False)
        with host._lock:
            thread = threading.Thread(target=foreign, daemon=True)
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), 'owner rejection must precede lock acquisition')
            self.assertEqual(rejected, [True, True, True])
            for call in calls(copy(host)):
                with self.assertRaises(ValueError):
                    call()
            if hasattr(os, 'fork'):
                reader, writer = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(reader)
                    try:
                        host.inspect_history()
                    except ValueError:
                        os.write(writer, b'1')
                    else:
                        os.write(writer, b'0')
                    os._exit(0)
                os.close(writer)
                reaped = False
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(reader, selectors.EVENT_READ)
                        self.assertTrue(selector.select(5), 'fork must reject before inherited held lock')
                    self.assertEqual(os.read(reader, 1), b'1')
                    os.waitpid(pid, 0)
                    reaped = True
                finally:
                    os.close(reader)
                    if not reaped:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        os.waitpid(pid, 0)
        self.assertEqual(approval._consumed, set())

    def test_public_owner_guards_reject_copy_thread_and_fork_before_held_lock(self):
        self.run_case('owner')

    def test_terminal_engine_root_drift_rejects_after_closed_writes(self):
        self.run_case('terminal-drift')

    def cold_processes(self, values, raw, pins, expected_root, *, parent_history):
        from deployment_compose_operation_witness_client_v3 import dispatch_request
        from deployment_compose_history_v3_host import AuthenticatedHistoryV3, AuthenticatedHistorySnapshotV3
        from deployment_contract_v2 import RequestV2
        from deployment_gateway import GatePolicy
        h = values['h']
        class WitnessHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                size = int(self.headers['Content-Length'])
                if not 0 < size <= 4*1024*1024:
                    raise AssertionError('bounded witness request')
                value = json.loads(self.rfile.read(size))
                payload = h.sign(dispatch_request(h.store, value['method'], value['request']))
                response = canonical(payload)
                self.send_response(200)
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
        class WitnessServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        witness_socket = self.root/'cold-witness.sock'
        server = WitnessServer(str(witness_socket), WitnessHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        directory = self.root/'cold-processes'
        directory.mkdir(mode=0o700)
        private = dict(raw=base64.b64encode(raw).decode('ascii'), expected_digest=hashlib.sha256(raw).hexdigest(),
            expected_context=pins, public=base64.b64encode(h.public).decode('ascii'),
            witness_socket=str(witness_socket), engine_socket=str(values['socket_path']),
            store_root=values['store']._root, store_key=base64.b64encode(values['store']._key).decode('ascii'),
            version=values['guard']._version, expected_root=expected_root, tls_directory=str(self.directory),
            server_pin=values['tls'][2], gate_root=str(directory/'gate'), directory=str(directory))
        config = directory/'config.json'
        config.write_bytes(canonical(private))
        config.chmod(0o600)
        command = [sys.executable, '-m', 'tests.test_deployment_compose_cold_recovery_v3_host']
        produced = json.loads(subprocess.run([*command,'produce',str(config)], capture_output=True,
            text=True, check=True, timeout=90).stdout)
        consumed = json.loads(subprocess.run([*command,'consume',str(config)], capture_output=True,
            text=True, check=True, timeout=180).stdout)
        self.assertNotEqual(produced['pid'], consumed['pid'])
        self.assertNotEqual(consumed['pid'], os.getpid())
        self.assertTrue(consumed['recoveryComplete'])
        record = json.loads((directory/'terminal.json').read_bytes())
        request = RequestV2.from_json(canonical(record['request']).decode('ascii'))
        history = AuthenticatedHistoryV3(values['prepared']['bundle'], request,
            gate_policy=GatePolicy(**record['policy']), gate_key=b'g'*32,
            consumption_receipt_hash=record['receiptHash'], witness_client=h.factory(record['firstBinding']),
            witness_client_factory=h.factory, parent_history=parent_history,
            reviewed_parent_snapshot=AuthenticatedHistorySnapshotV3(canonical(record['reviewedParent'])),
            ancestry_profile=ANCESTRY_PROFILE)
        snapshot = history.capture()
        self.assertEqual(snapshot.canonical, canonical(record['snapshot']))
        self.assertEqual(len(snapshot.snapshot['knownPrefix']), 10)
        self.assertEqual(len(snapshot.snapshot['segments']), 3)
        self.assertEqual(consumed['initialWriteCount'], 2)
        return dict(initialWriteCount=consumed['initialWriteCount'], receipts=consumed['receipts']), snapshot.snapshot

    def test_exited_publisher_then_fresh_consumer_executes_remaining_two_service_writes(self):
        self.run_case('subprocess')


def process_fixture(action, config_path):
    from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
    from deployment_compose_bounded_restart_material_v3_host import reopen_material
    from deployment_compose_recovery_store import ComposeRecoveryStore
    from deployment_compose_witness_store import canonical
    value = json.loads(config_path.read_bytes())
    public = base64.b64decode(value['public'])
    directory = Path(value['directory'])
    def transport(method, request):
        connection = _UnixDocker(value['witness_socket'], 10)
        try:
            connection.request('POST', '/witness', canonical(dict(method=method, request=request)),
                               headers={'Content-Type':'application/json'})
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError('witness host rejected')
            return json.loads(response.read())
        finally:
            connection.close()
    with patch('deployment_compose_recovery_store.sys.platform', 'linux'):
        store = ComposeRecoveryStore(value['store_root'], key=base64.b64decode(value['store_key']))
    try:
        args = dict(expected_digest=value['expected_digest'], expected_context=value['expected_context'],
                    gate_key=b'g'*32, witness_public_key=public, witness_transport=transport)
        if action == 'produce':
            context = reopen_material(base64.b64decode(value['raw']), **args)
            baselines, defaults = {}, {}
            current = context.history
            while current is not None:
                bundle = current._bundle
                baselines[bundle.digest] = store.get(bundle.to_dict()['baselineStateReference'])
                defaults[bundle.digest] = {service['name']:deepcopy(ZERO_DEFAULTS) for service in bundle.to_dict()['services']}
                current = current._parent
            raw = capture_material(context.history, baseline_bytes_by_bundle=baselines,
                authenticated_image_defaults_by_bundle=defaults, archive_digest='9'*64)
            path = directory/'published.json'
            path.write_bytes(raw)
            path.chmod(0o600)
            return dict(pid=os.getpid())
        def get(path):
            connection = _UnixDocker(value['engine_socket'], 5)
            try:
                connection.request('GET', path)
                response = connection.getresponse()
                if response.status != 200:
                    raise ValueError('Engine read rejected')
                return json.loads(response.read())
            finally:
                connection.close()
        def ready(service, cid):
            return get('/test/readiness/'+service+'/'+cid)
        host = ColdRecoveryHostV3((directory/'published.json').read_bytes(), **args, store=store,
            docker_socket=Path(value['engine_socket']), daemon_version=value['version'],
            expected_docker_root=value['expected_root'], readiness=ready)
        prepared = host.prepare_intent(operation_nonce='c'*64, expires_at=expiry())
        approval = ColdRecoveryTests.approval(None, prepared['request'])
        tls_directory = Path(value['tls_directory'])
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(tls_directory/'server.pem', tls_directory/'server.key')
        server.load_verify_locations(tls_directory/'ca.pem')
        server.verify_mode = ssl.CERT_REQUIRED
        client = ssl.create_default_context(cafile=tls_directory/'ca.pem')
        client.load_cert_chain(tls_directory/'client.pem', tls_directory/'client.key')
        result, history = host.execute(approval,
            witness_client_factory=lambda binding: OperationWitnessClientV3(binding, public, transport),
            quiesce_writer=lambda: True, gate_root=Path(value['gate_root']), tls_server_context=server,
            tls_client_context=client, server_certificate_sha256=value['server_pin'], timeout=5)
        record = dict(request=asdict(history._request), policy=asdict(history._policy), receiptHash=history._receipt,
                      firstBinding=history._client.binding, reviewedParent=json.loads(history._reviewed_parent.canonical),
                      snapshot=json.loads(history.capture().canonical))
        path = directory/'terminal.json'
        path.write_bytes(canonical(record))
        path.chmod(0o600)
        return dict(pid=os.getpid(), recoveryComplete=result['recoveryComplete'],
                    initialWriteCount=result['initialWriteCount'], receipts=result['receipts'])
    finally:
        store.close()


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1] in ('produce','consume'):
        print(json.dumps(process_fixture(sys.argv[1], Path(sys.argv[2]))), flush=True)
    else:
        unittest.main()
