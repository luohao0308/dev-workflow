"""Managed preparation custody and review over a local control transport double."""
import base64
from copy import deepcopy
from pathlib import Path
import hashlib
import json
import os
import shutil
import socket
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import test_deployment_compose_recovery_daemon_v3_host as daemon_fixture
from tests.test_compose_profile3_prepare_fixture import CurrentPreparationUnixTests
from tests.test_deployment_compose_github_review_contract import environment
from deployment_gateway import GatePolicy
import deployment_compose_full_body_review_contract as review_contract
import compose_profile3_prepare_fixture as prepare_fixture
import deployment_compose_scene_create_controller_v3_host as controller
import deployment_compose_scene_preparation_v3_host as preparation
import deployment_compose_scene_service_v3_host as service


@unittest.skipUnless(os.name == 'posix' and hasattr(socket, 'AF_UNIX')
                     and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX Unix sockets, OpenSSL and OpenSSH required')
class SceneBatchReviewTests(unittest.TestCase):
    identity = daemon_fixture.DaemonTests.identity
    ticks = daemon_fixture.DaemonTests.ticks
    command = daemon_fixture.DaemonTests.command

    def setUp(self):
        engine = CurrentPreparationUnixTests()
        self.addCleanup(engine.doCleanups)
        def record_bodies(bodies):
            engine.bodies = bodies
            engine.session.raw_source = engine.rows['1'*64]

        with patch.object(engine, 'prepare_initial', side_effect=record_bodies):
            engine.setUp()
        self.engine = engine
        frontend = deepcopy(engine.rows['1'*64])
        frontend.update(Id='3'*64, Name='/'+engine.project+'-frontend')
        frontend['Config']['Labels']['com.docker.compose.service'] = 'frontend'
        frontend['NetworkSettings']['Networks'][engine.network_name]['Aliases'] = ['frontend']
        engine.rows[frontend['Id']] = frontend
        engine.bodies['frontend'] = dict(deepcopy(frontend['Config']),
            HostConfig=deepcopy(frontend['HostConfig']), NetworkingConfig={
                'EndpointsConfig': {engine.network_name: dict(NetworkID=engine.network, Aliases=['frontend'])}})
        self.keys = engine.keys
        self.scene_id = 'dw-scene-' + '1'*16
        self.archive = 'f'*64
        self.registries = dict.fromkeys(('backend', 'frontend'), engine.images[1]['RepoDigests'][0])

        daemon_fixture.DaemonTests.setUp(self)
        self.patches[-1].stop()
        self.enter_patch(patch.object(daemon_fixture.daemon, 'subprocess', SimpleNamespace(run=self.command)))
        observer = daemon_fixture.DaemonTests.observe(self)
        self.owner = preparation.PreparationOwnerV3(observer, 'b'*40, self.archive)

        def provision(root, info, **kwargs):
            self.assertIs(kwargs['batch'], True)
            self.assertEqual(kwargs['keys'], self.keys)
            self.assertEqual(kwargs['policy_hash'], self.policy.identity_hash())
            # Only the daemon ownership adapter is doubled. The subsequent
            # Engine reads run over the independent fake Unix HTTP endpoint.
            session = engine.session
            session.target.daemon_id = info['ID']
            socket_path = session.target.socket
            session.target.socket = str(root/'docker.sock')
            try:
                kwargs['on_session_created'](session)
            finally:
                session.target.socket = socket_path
            prepare_fixture._prepare_observed(session, root=engine.root, rows={
                row['Config']['Labels']['com.docker.compose.service']: row for row in engine.rows.values()},
                images=engine.images, references=[item['RepoDigests'][0] for item in engine.images], bodies=engine.bodies,
                network_name=engine.network_name, network=engine.network, volume=engine.volume,
                bind=Path('/sample/config'), source_sha=kwargs['source_sha'], host_id=kwargs['host_id'],
                expected_daemon_id=info['ID'], fresh={'ServerVersion': '29.8.2'}, keys=kwargs['keys'],
                policy_hash=kwargs['policy_hash'], environment=kwargs['environment'],
                expiry_seconds=kwargs['expiry_seconds'], purpose='initial', batch=True)
            session.enrolled_images = deepcopy(engine.images)
            return session

        self.enter_patch(patch.object(preparation, 'prepare_profile3', side_effect=provision))
        self.enter_patch(patch.object(preparation.live, 'writer_tls',
                                     return_value=(None, None, 'a'*64, 'b'*64)))
        directory = preparation.directory
        self.enter_patch(patch.object(preparation, 'directory', side_effect=lambda p: directory(p.resolve())))
        self.addCleanup(self.owner.cleanup)
        self.client = object.__new__(service.SceneClientV3)
        self.client._handle = SimpleNamespace(sceneId=self.scene_id)
        self.client._call = self.control
        self.requests = []
        self.drift = None
        self.hello = self.client.prepare_identity('host-one')['hello']
        key_prefix = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'
        self.witness = b'ssh-ed25519 ' + base64.b64encode(key_prefix + b'w'*32)
        self.intent = b'ssh-ed25519 ' + base64.b64encode(key_prefix + b'i'*32)
        self.policy = GatePolicy('test-gate', 'test-key', preparation.digest(preparation.canonical(self.hello)),
            self.hello['writerCertificateSha256'], True, '0'*64,
            hashlib.sha256(self.witness).hexdigest(), operation_profile='compose-v3')
        self.metadata = self.client.prepare_batch_staging(self.policy.identity_hash(), self.keys)['preparation']

    def enter_patch(self, context):
        result = context.start()
        self.addCleanup(context.stop)
        return result

    def control(self, command, args=None):
        self.requests.append(command)
        if command == 'prepare_identity':
            return {'hello': self.owner.identity(args['hostId'])}
        if command == 'prepare_batch_staging':
            keys = {name: base64.b64decode(value, validate=True) for name, value in args['keys'].items()}
            return {'preparation': self.owner.prepare(args['policyHash'], keys, batch=True)}
        if command == 'status':
            status = self.owner.status()
            reply = dict(status, sceneId=self.scene_id, daemonId=self.info['ID'], preparation=status['capsule'])
            if self.drift == 'metadata' or (self.drift == 'final-status' and 'preparation_chunk' in self.requests):
                reply['preparation']['capsuleDigest'] = '1'*64
            return reply
        if command == 'preparation_chunk':
            chunk = self.owner.chunk(args['preparationId'], args['capsuleDigest'], args['offset'], args['length'])
            if self.drift == 'chunk':
                chunk['offset'] += 1
            elif self.drift == 'bytes':
                original = base64.b64decode(chunk['dataBase64'], validate=True)
                chunk['dataBase64'] = base64.b64encode(bytes([original[0] ^ 1]) + original[1:]).decode('ascii')
            return {'preparationChunk': chunk}
        self.fail(f'Unexpected scene command {command}')

    def review(self, metadata=None):
        return controller.review_batch_preparation(self.client, hello=self.hello,
            metadata=self.metadata if metadata is None else metadata, policy=self.policy,
            integrity_keys=self.keys, expected_target_registries=self.registries)

    def test_managed_batch_review_reads_chunks_and_projects_only_public_data(self):
        public = self.review()
        self.assertEqual(set(public), {'request', 'review'})
        self.assertEqual(public['request']['components'], ['backend', 'frontend'])
        self.assertEqual(public['request']['plan_hash'], self.engine.session.prepared['bundle'].digest)
        self.assertEqual(public['review'], self.engine.session.prepared['bundle'].public_review())
        self.assertNotIn('HostConfig', json.dumps(public))
        self.assertNotIn('rawRows', public)
        self.assertGreater(self.requests.count('preparation_chunk'), 1)
        self.assertEqual(self.requests[:2], ['prepare_identity', 'prepare_batch_staging'])
        self.assertEqual(set(self.requests[2:]), {'status', 'preparation_chunk'})
        self.assertTrue(self.engine.calls)
        self.assertEqual({method for method, _ in self.engine.calls}, {'GET'})
        with self.assertRaises(ValueError):
            self.owner.business_inputs()

        env = environment()
        sha = self.hello['sourceSha']
        env.update(GITHUB_SHA=sha, GITHUB_WORKFLOW_SHA=sha,
                   GITHUB_WORKFLOW_REF=f'{review_contract.REPOSITORY}/{review_contract.WORKFLOW}@{review_contract.REF}')
        artifact = review_contract.prepare(review_contract.canonical(public), env)
        verified, _, _ = review_contract.verify_prepared_review(review_contract.canonical(artifact), env,
            self.engine.session.prepared['bundle'], self.engine.session.prepared['request'])
        self.assertEqual(verified, self.engine.session.prepared['request'])

    def test_review_rejects_caller_metadata_and_chunk_drift(self):
        altered = deepcopy(self.metadata)
        altered['observerFacts']['bootId'] = '9'*32
        with self.assertRaises(ValueError):
            self.review(altered)
        for drift in ('metadata', 'chunk', 'bytes', 'final-status'):
            with self.subTest(drift=drift):
                self.requests.clear()
                self.drift = drift
                with self.assertRaises(ValueError):
                    self.review()


    def execute_batch(self, **overrides):
        options = dict(channel=Mock(), policy=self.policy, gate_key=b'g'*32,
            witness_public_key=self.witness, intent_public_key=self.intent,
            epoch='a'*64, readiness_probe=lambda service, cid: True,
            preparation_id=self.metadata['preparationId'], capsule_digest=self.metadata['capsuleDigest'])
        options.update(overrides)
        session = self.engine.session
        # The owner was prepared with the daemon double, while the guard's GETs
        # use the independent fake Engine endpoint held by the producer.
        with patch.object(session.target, 'socket', str(self.root/'docker.sock')), \
                patch.object(session, 'root', self.root, create=True), \
                patch.object(session, 'created_ids', list(self.engine.rows)):
            return self.owner.execute_batch(**options)

    def test_batch_executes_held_request_after_fresh_phase_guard_and_cannot_replay(self):
        session = self.engine.session
        result = (Mock(), Mock())
        channel, readiness = Mock(), Mock(return_value=True)
        with patch.object(preparation, '_fresh', wraps=preparation._fresh) as fresh, \
                patch.object(session.guard, 'capture_phase', wraps=session.guard.capture_phase) as capture, \
                patch.object(preparation.live, 'execute_operation', return_value=result) as execute:
            self.assertIs(self.execute_batch(channel=channel, readiness_probe=readiness), result)
            self.assertEqual(fresh.call_count, 3)
            capture.assert_called_once_with(dict(phase_index=0,
                operation=session.prepared['bundle'].creation_operations()[0], receipts={}, completed_operations=[]))
            args, kwargs = execute.call_args
            self.assertIs(args[0], channel)
            self.assertIs(args[1], session)
            self.assertIs(args[2], session.prepared)
            self.assertIs(args[3], self.policy)
            self.assertEqual(args[4:7], (b'g'*32, self.witness, self.intent))
            self.assertEqual(set(args[8].owned_ids), set(self.engine.rows))
            self.assertIs(kwargs['readiness_probe'], readiness)
            with self.assertRaises(ValueError):
                self.execute_batch()
            execute.assert_called_once()

    def test_batch_wrong_pins_or_stale_phase_do_not_dispatch(self):
        with patch.object(preparation.live, 'execute_operation') as execute:
            for overrides in (
                {'preparation_id': '0'*64}, {'capsule_digest': '0'*64},
                {'witness_public_key': self.intent}, {'epoch': 'not-a-digest'}, {'readiness_probe': None},
            ):
                with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                    self.execute_batch(**overrides)
            with patch.object(self.engine.session.guard, 'capture_phase', side_effect=ValueError('phase drift')):
                with self.assertRaises(ValueError):
                    self.execute_batch()
            execute.assert_not_called()

    def test_batch_does_not_retry_an_attempt_that_raises(self):
        with patch.object(preparation.live, 'execute_operation', side_effect=TimeoutError('uncertain consume')) as execute:
            with self.assertRaises(TimeoutError):
                self.execute_batch()
            with self.assertRaises(ValueError):
                self.execute_batch()
            execute.assert_called_once()


    def test_batch_real_worker_rejects_wrong_consumption_without_rpc_or_engine_writes(self):
        channel = Mock()
        channel.receive.return_value = dict(requestHash='0'*64, receiptHash='1'*64, firstBinding={})
        self.engine.calls.clear()
        with self.assertRaisesRegex(ValueError, 'compose-live-worker-v3-rejected'):
            self.execute_batch(channel=channel)
        channel.receive.assert_called_once_with('consume-intent')
        channel.rpc.assert_not_called()
        channel.operation_scope.assert_not_called()
        self.assertTrue(self.engine.calls)
        self.assertEqual({method for method, _ in self.engine.calls}, {'GET'})
        self.assertFalse(self.engine.session.unknown_write_result)
        with self.assertRaises(ValueError):
            self.execute_batch(channel=channel)
        channel.receive.assert_called_once()


def load_tests(loader, tests, pattern):
    # The Unix Engine class supplies fixture setup only.
    return loader.loadTestsFromTestCase(SceneBatchReviewTests)
