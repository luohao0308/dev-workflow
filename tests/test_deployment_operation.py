"""Actual SDK, signed journal and fence issuance; synthetic daemon transports."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlsplit

from tests import test_deployment_verification as verification
from tests import test_deployment_execute as fixtures
import deployment_store as store
import deployment_gateway as gateway
import deployment_recover as recovery


class HostOperationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = verification.DeploymentVerificationTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture.base
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        private = Path(temp.name).resolve()
        self.store = store.HostStore(store.StorePolicy(123, 'host', 'key', self.f.collector.policy),
            private / 'store', key=b'host-key-for-isolated-test-only-1234567890')
        self.gate = gateway.FileWriterGate(gateway.GatePolicy('host', 'key',
            fixtures.runtime.digest(self.store.policy._scope()), 'a' * 64), private / 'gate',
            key=b'gate-key-for-isolated-test-only-1234567890')
        original_read = self.f.docker.read
        def read(path):
            if path == '/v1.45/workflow/gate-info':
                return self.gate.info()
            if path.startswith('/v1.45/containers/') and path.endswith('/json'):
                reference = path.split('/')[3]
                if reference not in self.f.docker.containers:
                    found = next((c for c in self.f.docker.containers.values() if c['Name'] == '/' + reference), None)
                    if found is None:
                        raise fixtures.runtime.DockerNotFound('trusted synthetic HTTP 404')
                    return found
            return original_read(path)
        self.f.collector.client._transport = read
        self.f.policy = replace(self.f.policy, history_policy_hash=self.store.policy.identity_hash(),
                                gateway_policy_hash=self.gate.policy.identity_hash())
        self.inject_failure = False
        def write(method, path, body, headers):
            raw = fixtures.runtime.canonical(body).encode('ascii') if body is not None else b''
            ticket = self.gate.admit(headers['X-Dev-Workflow-Generation'], headers['X-Dev-Workflow-Attempt'],
                method=method, path=path, body=raw, writer_certificate_sha256='a' * 64)
            status, value = self.f.docker.write(method, path, body)
            response = fixtures.runtime.canonical(value).encode('ascii') if value is not None else b''
            self.gate.finish(ticket, definitive=True,
                response_hash=hashlib.sha256(str(status).encode() + b'\0' + response).hexdigest())
            if self.inject_failure:
                raise ConnectionError('synthetic lost downstream response')
            return status, value
        self.f.client = fixtures.backend.DockerMutationClient(self.f.policy, ca_file=Path('unused'),
            cert_file=Path('unused'), key_file=Path('unused'), transport=write)
        self.coordinator = recovery.HostCoordinator(self.store, self.gate, self.f.collector, self.f.policy)
        self.f.engine = fixtures.backend.DockerExecutor(self.f.policy, self.f.client, self.f.collector,
            verifier=self.fixture.verifier, coordinator=self.coordinator)
        self.f.prepare()

    def request(self):
        return fixtures.sdk.build_request(self.f.root, self.f.plan, self.f.operation,
            collector=self.f.collector, observation=self.f.observation,
            repository_slug='fixture/example', repository_id=123,
            expires_at=(fixtures.sdk.clock() + fixtures.timedelta(minutes=20)).isoformat(),
            execution_intent=self.f.intent)

    def authorize(self, operation):
        return fixtures.sdk.authorize(self.f.root, self.f.plan, self.request(),
            collector=self.f.collector, observation=self.f.observation, approval=self.f.approval,
            execution_intent=self.f.intent, host_operation=operation)

    def test_real_issuance_fenced_deploy_closes_signed_journal(self):
        with self.coordinator.operation(self.f.root, self.f.plan, self.f.intent) as operation:
            permit = self.authorize(operation)
            result = self.f.engine.execute(self.f.root, permit, self.f.intent, host_operation=operation)
        self.assertEqual(result['status'], 'executed-verified', result)
        events = self.coordinator._load(json.loads(self.f.intent.binding_json)['intentId'])
        self.assertEqual(events[-1]['kind'], 'terminal')
        self.assertEqual(len([e for e in events if e['kind'] == 'attempt']), 4)
        self.assertEqual(len([e for e in events if e['kind'] == 'response']), 4)
        self.assertEqual(self.fixture.original_api, self.f.docker.containers[fixtures.API])
        with self.assertRaises(recovery.RecoveryError):
            recovery.HostOperation.validate_writer(operation, self.f.policy)

    def test_header_lock_delay_cannot_dispatch_after_grant_expiry(self):
        original_headers = gateway.WriterSession.headers
        original_clock = fixtures.sdk.clock
        offset = fixtures.timedelta()
        def clock():
            return original_clock() + offset
        def delayed_headers(session, attempt):
            nonlocal offset
            value = original_headers(session, attempt)
            offset = fixtures.timedelta(hours=2)
            return value
        with self.coordinator.operation(self.f.root, self.f.plan, self.f.intent) as operation:
            permit = self.authorize(operation)
            with mock.patch.object(gateway.WriterSession, 'headers', new=delayed_headers), \
                    mock.patch.object(fixtures.sdk, 'clock', side_effect=clock):
                result = self.f.engine.execute(self.f.root, permit, self.f.intent, host_operation=operation)
        self.assertFalse(self.f.docker.writes)
        self.assertEqual(result['execution'], 'not-performed')
        self.assertEqual(result['status'], 'failed')

    def test_no_operation_cannot_authorize_or_send(self):
        with self.assertRaisesRegex(fixtures.backend.ExecutionError, 'host-operation-required'):
            self.f.authorize()
        spec = self.f.docker.specs[('web', 'sha256:' + 'b' * 64)]
        with self.assertRaises(fixtures.backend.ExecutionError):
            self.f.client.create('dwf-' + 'd' * 64, spec.to_create('fixture', 'd' * 64), before_send=lambda: None)
        self.assertFalse(self.f.docker.writes)

    def test_unknown_response_preserves_journal_and_blocks_new_operation(self):
        self.inject_failure = True
        with self.coordinator.operation(self.f.root, self.f.plan, self.f.intent) as operation:
            result = self.f.engine.execute(self.f.root, self.authorize(operation), self.f.intent,
                                           host_operation=operation)
        self.assertEqual(result['status'], 'unknown')
        oid = json.loads(self.f.intent.binding_json)['intentId']
        self.assertNotEqual(self.coordinator._load(oid)[-1]['kind'], 'terminal')
        # Gate knows the upstream completed, but a living producer still blocks recovery.
        with self.assertRaisesRegex(recovery.RecoveryError, 'producer'):
            self.coordinator.inspect(self.f.root, oid)
        self.assertEqual(len(self.f.docker.writes), 1)


if __name__ == '__main__':
    unittest.main()
