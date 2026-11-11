"""Real Unix phase reads and grant ledger checks, with explicit writer/Engine doubles."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from tests import test_deployment_compose_host_snapshot_v3_host as host_fixture
from tests.test_deployment_compose_production_frontend_approval_v1_host import approved, fixture, host
from tests.test_deployment_compose_production_frontend_v3_host import adapter, material
from tests.test_deployment_compose_gate_witness_v3 import GateFixture, signed
from tests import test_deployment_runtime as tls_fixture
from deployment_compose_retained_frontend_worker_v1_host import RetainedFrontendWorkerV1, RetainedWorkerBlocked
import deployment_compose_retained_frontend_worker_v1_host as worker_module
from deployment_compose_retained_write_v1_host import RetainedWriteV1
from deployment_compose_production_scope_v1_host import ScopeBlocked, acquire_scope, provision_scope
from release_execute import AuthorizationUnavailable
from deployment_gateway import GatePolicy


@unittest.skipUnless(os.name == 'posix', 'POSIX Unix sockets and scope lease required')
class RetainedWorkerTests(unittest.TestCase):
    command = host_fixture.HostTests.command
    observe = host_fixture.HostTests.observe
    sign = GateFixture.sign
    transport = GateFixture.transport

    def setUp(self):
        host_fixture.HostTests.setUp(self)
        original, image, options = material()
        options['protected_container_ids'] = [self.row['Id']]
        identity = options['expected_identity']
        identity.update(hostId='host', daemonId='production-one')
        self.original = original['Id']
        self.candidate = 'f' * 64
        original['State']['Health'] = {'Status': 'healthy'}
        for endpoint in original['NetworkSettings']['Networks'].values():
            endpoint.update(IPAddress='172.18.0.6', EndpointID='old-endpoint')
        options['expected_snapshot_digest'] = adapter.snapshot_digest(original, image, [self.row['Id']])
        self.private = adapter.prepare_frontend_plan(original, image, **options)
        self.other_rows[self.original] = original
        self.values[host_fixture.CONTAINERS].append({'Id': self.original})
        self.values['/v1.45/version'] = {'Version': '29.8.2', 'GitCommit': '8af9fe3'}
        self.values['/v1.45/images/' + image['Id'] + '/json'] = image
        scope = tempfile.TemporaryDirectory()
        self.addCleanup(scope.cleanup)
        self.registration = provision_scope(Path(scope.name).resolve(), host_id='host',
            project='luohao-blog-prod', daemon_id='production-one')
        observer = self.observe()
        self.writes = []
        self.error = None
        self.ready = True
        self.candidate_health = 'healthy'
        self.candidate_exits = False
        self.write_patch = patch.object(RetainedWriteV1, 'write', side_effect=self._write)
        for patcher in (patch.object(worker_module, '_capture_current_origin', return_value=b'native-origin'),
                        self.write_patch):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.worker = RetainedFrontendWorkerV1(self.private, operation_nonce='1'*64, observer=observer,
            registration=self.registration, writer_source_sha='b'*40, writer_archive_digest='b'*64,
            policy_hash='f'*64, witness_transport_factory=self._transport,
            readiness=lambda active: self.ready or active == self.original, readiness_timeout=1)
        self.addCleanup(self.worker.close)

    @staticmethod
    def _transport(observer, *_):
        value = object.__new__(RetainedWriteV1)
        value._observer = observer
        return value

    def _write(self, operation, *, before_dispatch, **_):
        before_dispatch()
        self.writes.append(operation.phase)
        if operation.phase == self.error:
            raise ValueError('unknown Engine response')
        path = urlsplit(operation.path)
        name = parse_qs(path.query).get('name', [None])[0]
        if operation.phase == 'create':
            body = json.loads(operation.body)
            config = {key: value for key, value in body.items() if key not in ('HostConfig', 'NetworkingConfig', 'ArgsEscaped')}
            networks = deepcopy(body['NetworkingConfig']['EndpointsConfig'])
            self.other_rows[self.candidate] = dict(
                Id=self.candidate, Name='/' + name, Image=body['Image'], Config=config,
                HostConfig=body['HostConfig'], Mounts=[], RestartCount=0,
                NetworkSettings={'Networks': networks, 'Ports': {}},
                State=dict(Running=False, Paused=False, Restarting=False, Dead=False, Status='created',
                           Pid=0, StartedAt='not-started', Health={'Status': 'starting'}),
            )
            self.values[host_fixture.CONTAINERS].append({'Id': self.candidate})
            return 201, json.dumps({'Id': self.candidate}).encode(), '1'*64
        row = self.other_rows[path.path.split('/')[-2]]
        action = path.path.split('/')[-1]
        if action == 'rename':
            row['Name'] = '/' + name
        elif action == 'stop':
            row['State'].update(Running=False, Pid=0, Status='exited')
        elif action == 'start':
            row['State'].update(Running=True, Pid=1000, StartedAt='new-start', Status='running',
                                Health={'Status': 'healthy'})
            for endpoint in row['NetworkSettings']['Networks'].values():
                endpoint.update(IPAddress='172.18.0.8', EndpointID='new-endpoint')
            if row['Id'] == self.candidate:
                row['State']['Health']['Status'] = self.candidate_health
                if self.candidate_exits:
                    row['State'].update(Running=False, Pid=0, Status='exited')
        else:
            raise AssertionError(action)
        return 204, b'', hashlib.sha256(operation.path.encode()).hexdigest()

    def _approval(self, review, operation):
        old, policy, _ = fixture()
        request = host.prepare_production_frontend_request(review, policy_hash=old.policy_hash,
            expires_at=old.expires_at, operation=operation)
        policy = host.ProductionFrontendApprovalPolicyV2(**dict(vars(policy), operation=operation,
            host_id=request.host_id, daemon_id=request.daemon_id,
            snapshot_hash=request.before_hash, body_hash=request.after_hash, plan_hash=request.plan_hash,
            protected_inventory_hash=host._digest(list(request.protected_components)), request_hash=request.digest(),
            observation_hash=request.observation_hash, history_hash=request.history_hash))
        approval, client, _ = approved(policy, request)
        return approval, approval.validate(request), request, client

    def test_successful_switch_and_separate_restoration_consent(self):
        approval, grant, request, ledger = self._approval(self.worker.deploy_review(), 'deploy')
        result = self.worker.deploy(approval, grant, request)
        self.assertEqual(len(result['witnessDigests']), 5)
        self.assertEqual(len(ledger.markers), 1)
        self.assertFalse(self.other_rows[self.original]['State']['Running'])
        approval, grant, rollback, ledger = self._approval(self.worker.restore_review(), 'rollback')
        self.assertEqual(rollback.history_hash, request.digest())
        restored = self.worker.restore(approval, grant, rollback)
        self.assertEqual(len(restored['parentWitnessDigests']), 5)
        self.assertEqual(len(ledger.markers), 1)
        self.assertEqual(self.other_rows[self.original]['Name'], '/blog-frontend')
        self.assertTrue(self.other_rows[self.original]['State']['Running'])
        self.assertFalse(self.other_rows[self.candidate]['State']['Running'])

    def test_known_unready_candidate_keeps_lease_until_fresh_restore_approval(self):
        self.ready = False
        approval, grant, request, _ = self._approval(self.worker.deploy_review(), 'deploy')
        with self.assertRaisesRegex(RetainedWorkerBlocked, 'readiness-failed'):
            self.worker.deploy(approval, grant, request)
        with self.assertRaisesRegex(ScopeBlocked, 'live writer'):
            acquire_scope(self.registration, '2'*64)
        approval, grant, rollback, _ = self._approval(self.worker.restore_review(), 'rollback')
        self.worker.restore(approval, grant, rollback)
        self.assertTrue(self.other_rows[self.original]['State']['Running'])

    def test_unknown_stop_blocks_restore_and_leaves_durable_scope(self):
        self.error = 'stop-original'
        approval, grant, request, _ = self._approval(self.worker.deploy_review(), 'deploy')
        with self.assertRaisesRegex(ValueError, 'unknown Engine'):
            self.worker.deploy(approval, grant, request)
        self.assertEqual(self.writes, ['create', 'stop-original'])
        with self.assertRaises(RetainedWorkerBlocked):
            self.worker.restore_review()
        self.worker._lease.close()
        self.worker._lease = None
        with self.assertRaisesRegex(ScopeBlocked, 'Unresolved'):
            acquire_scope(self.registration, '2'*64)

    def test_other_container_drift_prevents_consent_consumption(self):
        approval, grant, request, ledger = self._approval(self.worker.deploy_review(), 'deploy')
        self.row['RestartCount'] += 1
        with self.assertRaises(ValueError):
            self.worker.deploy(approval, grant, request)
        self.assertFalse(ledger.markers)
        self.assertFalse(self.writes)

    def test_closed_start_then_exit_can_restore_without_stopping_candidate(self):
        self.candidate_exits = True
        approval, grant, request, _ = self._approval(self.worker.deploy_review(), 'deploy')
        with self.assertRaisesRegex(RetainedWorkerBlocked, 'readiness-failed'):
            self.worker.deploy(approval, grant, request)
        review = self.worker.restore_review()
        self.assertEqual(review['retainedCutover']['switchPrefix'], 4)
        self.assertIs(review['retainedCutover']['candidateRunning'], False)
        approval, grant, rollback, _ = self._approval(review, 'rollback')
        self.worker.restore(approval, grant, rollback)
        self.assertNotIn('stop-candidate', self.writes)

    def test_native_health_starting_blocks_success_even_with_http_ready(self):
        self.candidate_health = 'starting'
        approval, grant, request, _ = self._approval(self.worker.deploy_review(), 'deploy')
        with self.assertRaisesRegex(RetainedWorkerBlocked, 'readiness-failed'):
            self.worker.deploy(approval, grant, request)
        review = self.worker.restore_review()
        self.assertIs(review['retainedCutover']['candidateRunning'], True)

    def test_exact_approval_stops_before_candidate_start_and_reverses_closed_prefix(self):
        approval, grant, request, _ = self._approval(self.worker.deploy_review(), 'deploy')
        check = approval.check_consumed_intent
        def deny_at_cutover(req):
            if self.writes[-1:] == ['name-candidate']:
                raise AuthorizationUnavailable('fixture denied before new dispatch')
            check(req)
        with patch.object(approval, 'check_consumed_intent', side_effect=deny_at_cutover):
            with self.assertRaises(AuthorizationUnavailable):
                self.worker.deploy(approval, grant, request)
        review = self.worker.restore_review()
        self.assertEqual(review['retainedCutover']['switchPrefix'], 3)
        self.assertIs(review['retainedCutover']['candidateRunning'], False)
        approval, grant, rollback, _ = self._approval(review, 'rollback')
        self.worker.restore(approval, grant, rollback)
        self.assertEqual(self.writes[-3:], ['unname-candidate', 'rename-original', 'start-original'])

    @unittest.skipUnless(shutil.which('openssl') and shutil.which('ssh-keygen'), 'OpenSSL and OpenSSH required')
    def test_worker_uses_mtls_native_connection_and_signed_witnesses_for_both_requests(self):
        self.write_patch.stop()
        GateFixture.setup_gate_fixture(self)

        class Certificates:
            pass

        tls_fixture.LocalTLSRuntimeTests.setUpClass.__func__(Certificates)
        self.addCleanup(Certificates.temp.cleanup)
        directory = Certificates.directory
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(directory/'server.pem', directory/'server.key')
        server_tls.load_verify_locations(directory/'ca.pem')
        server_tls.verify_mode = ssl.CERT_REQUIRED
        client_tls = ssl.create_default_context(cafile=directory/'ca.pem')
        client_tls.load_cert_chain(directory/'client.pem', directory/'client.key')

        def pin(name):
            return hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory/(name+'.pem')).read_text())).hexdigest()

        def factory(observer, first, request_hash, receipt_hash, execution_digest):
            descriptor = RetainedWriteV1.scope_descriptor(first, request_hash=request_hash,
                receipt_hash=receipt_hash, plan_digest=execution_digest, index=0)
            policy = GatePolicy('worker-test', 'worker-key', '4'*64, pin('client'), True,
                descriptor['scopeHash'], self.client.key_hash, operation_profile='compose-v3')
            binding = dict(scopeHash=descriptor['scopeHash'], epoch=secrets.token_hex(32),
                generation=descriptor['generation'], policyHash=policy.identity_hash())
            root = self.root/request_hash
            root.mkdir(mode=0o700)
            self.store = signed.OperationWitnessStoreV3(root, key=b'w'*32)
            self.addCleanup(self.store.close)
            self.store.register_once(binding)
            return RetainedWriteV1(gate_policy=policy, gate_root=self.root/('gate-'+request_hash),
                gate_key=b'g'*32, witness_client_factory=lambda value: signed.OperationWitnessClientV3(
                    value, self.public, self.transport), registered_binding=binding,
                tls_server_context=server_tls, tls_client_context=client_tls,
                server_certificate_sha256=pin('server'), observer=observer, timeout=30)

        plan = self.worker._plan
        operations = (plan.create(), *plan.switch(self.candidate),
                      *plan.restore(self.candidate, switch_prefix=4, candidate_running=True))
        by_path = {operation.path: operation for operation in operations}

        def engine_post(path, raw):
            operation = by_path[path]
            self.assertEqual(raw, operation.body)
            status, body, _ = self._write(operation, before_dispatch=lambda: None)
            return status, body

        self.worker._factory = factory
        self.engine_post = engine_post
        approval, grant, request, _ = self._approval(self.worker.deploy_review(), 'deploy')
        self.assertEqual(len(self.worker.deploy(approval, grant, request)['witnessDigests']), 5)
        approval, grant, request, _ = self._approval(self.worker.restore_review(), 'rollback')
        self.assertEqual(len(self.worker.restore(approval, grant, request)['witnessDigests']), 4)
        self.assertEqual(self.writes, [operation.phase for operation in operations])
