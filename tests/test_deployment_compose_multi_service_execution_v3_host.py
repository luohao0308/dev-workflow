"""Two-service SDK execution through signed Gate, mTLS and a local Unix Engine double.

GitHub responses, phase observations and readiness are trusted test doubles.
No production host or Docker daemon is contacted.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import os
import shutil
import socketserver
import ssl
import subprocess
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

from tests.test_deployment_compose_coordinator_v3_host import UnitExecutor
from tests.test_deployment_compose_gate_witness_v3 import GateFixture, signed
from tests.test_deployment_compose_bundle_v3 import bind_baseline
from tests import test_deployment_compose_write_gateway_v3_host as tls_fixture
from tests import test_deployment_compose_approval_v3_host as approvals
from tests.test_release_host import claims
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_coordinator_v3_host import canonical
from deployment_compose_startup_fence_v3_host import Profile3StartupFenceV3
from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
from tests.support.compose_profile3_ownership_fixture import FixtureOwnershipTrackerV3
import deployment_compose_live_worker_v3_host as worker


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX/OpenSSL/OpenSSH required')
class MultiServiceExecutionTests(GateFixture, unittest.TestCase):
    setUpClass = classmethod(tls_fixture.WriteGatewayTests.setUpClass.__func__)
    tearDownClass = classmethod(tls_fixture.WriteGatewayTests.tearDownClass.__func__)

    def setUp(self):
        self.setup_gate_fixture()
        value = UnitExecutor().bundle.to_dict()
        for key in ('operations', 'resolverRules', 'resolverContract', 'imageDefaultsDigests'):
            value.pop(key)
        from tests.test_deployment_compose_bundle_v3 import fixture
        _, defaults = fixture()
        defaults['api'] = deepcopy(defaults['web'])
        self.defaults = defaults
        self.request = approvals.request(components=('api', 'web'))
        value['identity'].update(hostId=self.request.host_id, daemonId=self.request.daemon_id,
                                 project=self.request.target.namespace,
                                 sourceIdentity=canonical(asdict(self.request.source)).decode('ascii'))
        for service in value['services']:
            for key in ('baselineCreateBody', 'targetCreateBody'):
                service[key]['Labels']['com.docker.compose.project'] = self.request.target.namespace
        bind_baseline(value)
        self.bundle = ExecutionBundleV3(value, authenticated_image_defaults=defaults)
        self.request = replace(self.request, plan_hash=self.bundle.digest, protected_components=('db',),
            after_hash=hashlib.sha256(canonical({s['name']: s['targetCreateBody'] for s in value['services']})).hexdigest())
        self.rows = {service['baselineContainerId']: dict(name=service['finalName'], running=True,
                     image=service['baselineImageId']) for service in value['services']}
        self.rows['2'*64] = dict(name='protected-db', running=True, image='protected-image')
        self.protected = deepcopy(self.rows['2'*64])
        self.events = []
        self.writes = []
        self.created = []
        self.consumptions = []
        self.server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_tls.load_cert_chain(self.directory/'server.pem', self.directory/'server.key')
        self.server_tls.load_verify_locations(self.directory/'ca.pem')
        self.server_tls.verify_mode = ssl.CERT_REQUIRED
        self.client_tls = ssl.create_default_context(cafile=self.directory/'ca.pem')
        self.client_tls.load_cert_chain(self.directory/'client.pem', self.directory/'client.key')
        self.server_pin = self.fingerprint('server')
        self.policy = replace(self.policy, writer_certificate_sha256=self.fingerprint('client'))
        self.binding = dict(self.binding, policyHash=self.policy.identity_hash())
        self.request = replace(self.request, policy_hash=self.policy.identity_hash())
        directory = self.root/'multi-witness'
        directory.mkdir(mode=0o700)
        self.store = signed.OperationWitnessStoreV3(directory, key=b'm'*32)
        self.addCleanup(self.store.close)
        intent_signer = self.root/'intent-signing'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(intent_signer)],
                       capture_output=True, check=True)
        intent_signer.chmod(0o600)
        self.intent_public = intent_signer.with_suffix('.pub').read_bytes()
        self.host = MacLiveAdmissionV3(store=self.store, gate_policy=self.policy, gate_key=b'g'*32,
            witness_signer=self.key, witness_public_key=self.public, intent_signer=intent_signer,
            intent_public_key=self.intent_public)
        self.tracker = FixtureOwnershipTrackerV3(project=self.request.target.namespace,
            daemon_id=self.request.daemon_id, policy_hash=self.policy.identity_hash(),
            witness_pub_hash=self.policy.witness_key_sha256, epoch=self.host._epoch,
            initial_confirmed_ids=['1'*64, '7'*64, '2'*64], protected_ids=['2'*64])
        self.session = SimpleNamespace(root=self.root, project=self.request.target.namespace,
            target=SimpleNamespace(socket=str(self.root/'multi.sock'), daemon_id=self.request.daemon_id),
            producer=SimpleNamespace(operation_scope=lambda _: nullcontext()),
            created_ids=['1'*64, '7'*64, '2'*64], unknown_write_result=False)
        test = self

        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, status, value=None):
                raw = b'' if value is None else canonical(value)
                self.send_response(status)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                path = urlsplit(self.path)
                body = self.rfile.read(int(self.headers['Content-Length']))
                test.writes.append(('POST', self.path, body))
                bits = path.path.split('/')
                if bits[-1] == 'create':
                    value = json.loads(body)
                    cid = 'abcd'[len(test.created)]*64
                    test.created.append(cid)
                    test.rows[cid] = dict(name=parse_qs(path.query)['name'][0], running=False, image=value['Image'])
                    test.events.append(('create', cid))
                    self.respond(201, {'Id': cid})
                else:
                    cid, phase = bits[-2:]
                    test.assertNotEqual(cid, '2'*64)
                    if phase == 'stop':
                        test.rows[cid]['running'] = False
                    elif phase == 'start':
                        test.rows[cid]['running'] = True
                    elif phase == 'rename':
                        test.rows[cid]['name'] = parse_qs(path.query)['name'][0]
                    else:
                        raise AssertionError(phase)
                    test.events.append((phase, cid))
                    self.respond(204)

            def do_DELETE(self):
                cid = urlsplit(self.path).path.split('/')[-1]
                test.assertNotEqual(cid, '2'*64)
                test.writes.append(('DELETE', self.path, b''))
                del test.rows[cid]
                test.events.append(('delete', cid))
                self.respond(204)

        class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        self.backend = UnixServer(str(self.root/'multi.sock'), Backend)
        threading.Thread(target=self.backend.serve_forever, daemon=True).start()
        self.addCleanup(self.backend.server_close)
        self.addCleanup(self.backend.shutdown)

    def fingerprint(self, name):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/(name+'.pem')).read_text())).hexdigest()

    def execute(self, bundle, request, *, parent=None, reviewed=None, candidates=True, healthy=True, terminal_match=True):
        approval = approvals.ComposeApprovalTests()
        approval.setUp()
        approval.req = request
        approval.policy = approvals.policy(operation=request.operation, components=request.components,
            host_id=request.host_id, daemon_id=request.daemon_id, target=request.target,
            bundle_hash=bundle.digest, expected_history_hash=request.history_hash, policy_hash=request.policy_hash,
            protected_components=request.protected_components)
        approval.claims = dict(claims(approval.policy), aud=approvals.host.AUDIENCE)
        approval.client = approval.client_for([request])
        authority = approval.approval()
        receipt = authority.consume(authority.validate(request), request)
        self.consumptions.append(receipt)
        binding = self.host.register_intent(bundle, request, authority, receipt, reviewed_parent=reviewed)
        policy = self.policy
        test = self

        class LocalChannel:
            epoch = test.host._epoch

            def receive(self, kind):
                test.assertEqual(kind, 'consume-intent')
                return dict(requestHash=request.digest(), receiptHash=hashlib.sha256(canonical(asdict(receipt))).hexdigest(),
                            firstBinding=binding)

            def rpc(self, service, method, rpc):
                return test.host.authorize_rpc(service, method, rpc)

            def operation_scope(self, deadline):
                return nullcontext()

        terminal_maps = []
        def capture(done, receipts):
            test.assertEqual(set(receipts), {'web', 'api'})
            test.assertEqual(len(done), len(bundle.resolve_operations(receipts)))
            test.assertTrue(all(test.rows[cid]['running'] for cid in receipts.values()))
            test.assertEqual(test.rows['2'*64], test.protected)
            terminal_maps.append(deepcopy(receipts))
            rows = deepcopy(test.rows)
            if not terminal_match and len(terminal_maps) == 2:
                rows['2'*64]['name'] = 'changed-protected-db'
            return rows

        guard = Mock(side_effect=lambda snapshot: candidates if snapshot['phase_index'] == 2 else True)
        guard._capture = capture
        self.session.guard = guard
        fence = None if parent is None else Profile3StartupFenceV3(
            original_history=parent, reviewed_history=reviewed, quiesce_writer=lambda: True)
        def readiness(service, cid):
            self.assertTrue(self.rows[cid]['running'])
            self.events.append(('ready-'+service, cid))
            if isinstance(healthy, Exception):
                raise healthy
            return healthy

        def run():
            return worker.execute_operation(LocalChannel(), self.session, dict(bundle=bundle, request=request),
                policy, b'g'*32, self.public, self.intent_public,
                (self.server_tls, self.client_tls, self.server_pin, self.policy.writer_certificate_sha256),
                self.tracker, parent=parent, reviewed=reviewed, fence=fence, readiness_probe=readiness)

        if not candidates or healthy is not True or not terminal_match:
            with self.assertRaises(ValueError):
                run()
            self.assertEqual(len(terminal_maps), 2 if not terminal_match else 0)
            return None, None
        result, history = run()
        self.assertEqual(terminal_maps, [result['receipts'], result['receipts']])
        snapshot = history.capture()
        self.assertEqual(len(snapshot.snapshot['knownPrefix']), 10)
        self.assertIsNone(snapshot.snapshot['blocker'])
        self.assertTrue(all(len(scope['records']) == 6 for scope in snapshot.snapshot['scopes']))
        self.assertEqual(self.rows['2'*64], self.protected)
        return result, history

    def test_two_service_deploy_then_fresh_full_rollback(self):
        deployed, parent = self.execute(self.bundle, self.request)
        self.assertEqual(deployed['receipts'], {'web': 'a'*64, 'api': 'b'*64})
        self.assertEqual(self.events, [('create', 'a'*64), ('create', 'b'*64), ('stop', '7'*64),
            ('stop', '1'*64), ('delete', '7'*64), ('delete', '1'*64), ('rename', 'a'*64),
            ('rename', 'b'*64), ('start', 'a'*64), ('ready-web', 'a'*64), ('start', 'b'*64), ('ready-api', 'b'*64)])
        reviewed = parent.capture()
        value = self.bundle.to_dict()
        for key in ('operations', 'resolverRules', 'resolverContract', 'imageDefaultsDigests'):
            value.pop(key)
        for service in value['services']:
            original = deepcopy(service['baselineCreateBody'])
            service.update(baselineContainerId=deployed['receipts'][service['name']],
                baselineImageId=service['targetImageId'], baselineCreateBody=deepcopy(service['targetCreateBody']),
                targetImageId=original['Image'], targetCreateBody=original)
        value['operationNonce'] = '8'*64
        protected = deepcopy(value['protectedContainers'])
        bind_baseline(value)
        value['protectedContainers'] = protected
        rollback = ExecutionBundleV3(value, authenticated_image_defaults=self.defaults)
        request = replace(self.request, operation='rollback', history_hash=reviewed.digest, plan_hash=rollback.digest,
            after_hash=hashlib.sha256(canonical({s['name']: s['targetCreateBody'] for s in value['services']})).hexdigest())
        rolled_back, child = self.execute(rollback, request, parent=parent, reviewed=reviewed)
        self.assertEqual(rolled_back['receipts'], {'web': 'c'*64, 'api': 'd'*64})
        self.assertEqual(self.events[12:], [('create', 'c'*64), ('create', 'd'*64), ('stop', 'b'*64),
            ('stop', 'a'*64), ('delete', 'b'*64), ('delete', 'a'*64), ('rename', 'c'*64),
            ('rename', 'd'*64), ('start', 'c'*64), ('ready-web', 'c'*64), ('start', 'd'*64), ('ready-api', 'd'*64)])
        self.assertEqual(len(self.writes), 20)
        self.assertEqual(len(self.consumptions), 2)
        self.assertNotEqual(self.consumptions[0].request_hash, self.consumptions[1].request_hash)
        self.assertEqual(child.capture().snapshot['parent']['historyDigest'], reviewed.digest)
        for service in self.bundle.to_dict()['services']:
            self.assertEqual(self.rows[rolled_back['receipts'][service['name']]]['image'], service['baselineImageId'])
        for method, path, _ in self.writes:
            if method == 'DELETE':
                self.assertTrue(path.endswith('?force=false&v=false'))

    def test_candidate_failure_leaves_both_old_services_running(self):
        self.execute(self.bundle, self.request, candidates=False)
        self.assertEqual([event[0] for event in self.events], ['create', 'create'])
        self.assertTrue(self.rows['1'*64]['running'])
        self.assertTrue(self.rows['7'*64]['running'])
        self.assertEqual(self.rows['2'*64], self.protected)

    def test_dependency_readiness_failure_blocks_dependent_start(self):
        self.execute(self.bundle, self.request, healthy=False)
        self.assertIn(('start', 'a'*64), self.events)
        self.assertNotIn(('start', 'b'*64), self.events)
        self.assertEqual(self.events[-1], ('ready-web', 'a'*64))
        self.assertEqual(self.rows['2'*64], self.protected)

    def test_terminal_snapshot_drift_rejects_completed_writes(self):
        self.execute(self.bundle, self.request, terminal_match=False)
        self.assertEqual(len(self.writes), 10)
        self.assertEqual([e for e in self.events if e[0].startswith('ready-')],
                         [('ready-web', 'a'*64), ('ready-api', 'b'*64)])
        self.assertEqual(self.rows['2'*64], self.protected)

    def test_truthy_readiness_result_blocks_dependent_start(self):
        self.execute(self.bundle, self.request, healthy='healthy')
        self.assertNotIn(('start', 'b'*64), self.events)

    def test_readiness_exception_blocks_dependent_start(self):
        self.execute(self.bundle, self.request, healthy=ValueError('probe failed'))
        self.assertNotIn(('start', 'b'*64), self.events)
