"""Persistent store proof must survive observers without minting live authority."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from tests import test_deployment_verification as verification
from tests import test_deployment_execute as execution
import deployment_store as store


class DurableRollbackTests(unittest.TestCase):
    def setUp(self):
        self.fixture = verification.DeploymentVerificationTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.base
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.key = b'isolated-host-key-for-tests-only-' * 2
        self.policy = store.StorePolicy(123, 'fixture-host', 'key-one', self.base.collector.policy)
        self.store = store.HostStore(self.policy, Path(self.directory.name).resolve() / 'host', key=self.key)

    def test_new_collector_rolls_back_using_authenticated_persistent_history(self):
        ref = self.store.capture_history(self.base.collector, self.base.observation)
        old_snapshot = self.base.observation.snapshot()
        result = self.base.execute()
        self.assertEqual(result['status'], 'executed-verified')
        policy = self.base.collector.policy
        reader = execution.runtime.DockerTLSClient(policy, ca_file=Path('unused'), cert_file=Path('unused'),
            key_file=Path('unused'), transport=self.base.docker.read)
        self.base.collector = execution.runtime.TrustedDockerCollector(policy, reader)
        self.base.observation = self.base.collector.collect()
        reopened = store.HostStore(self.policy, self.store.root, key=self.key)
        history = reopened.load_history(ref, collector=self.base.collector, before=self.base.observation)
        self.assertEqual(history.snapshot(), old_snapshot)
        for candidate in (history, deepcopy(history)):
            with self.assertRaises(execution.runtime.RuntimeCollectionError):
                self.base.collector.validate(candidate)
        with self.assertRaises(store.StoreError):
            self.base.collector.validate_history(deepcopy(history), before=self.base.observation)
        # Construct a fresh verifier and executor; the retired issuer is irrelevant.
        import deployment_verify
        verifier = deployment_verify.TrustedProbeVerifier(self.fixture.verifier.policy, policy,
                                                         transport=self.fixture.http)
        self.base.engine = execution.backend.DockerExecutor(self.base.policy, self.base.client,
            self.base.collector, verifier=verifier)
        self.base.prepare('a', operation='deployment-rollback', rollback_target=history)
        permit = self.base.authorize()
        proof = execution.json.loads(permit.request.conditions_json)['rollbackHistoryProof']
        self.assertEqual(proof['proofHash'], history.proof_hash)
        self.assertEqual(proof['producerPolicyHash'], history.policy_hash)
        self.assertEqual(self.base.engine.execute(self.base.root, permit, self.base.intent)['status'],
                         'executed-verified')
        self.assertEqual(self.fixture.original_api, self.base.docker.containers[execution.API])

    def test_store_repository_id_cannot_be_substituted_by_request(self):
        ref = self.store.capture_history(self.base.collector, self.base.observation)
        result = self.base.execute()
        self.base.observation = result['observation']
        history = self.store.load_history(ref, collector=self.base.collector, before=self.base.observation)
        self.base.prepare('a', operation='deployment-rollback', rollback_target=history)
        with self.assertRaisesRegex(execution.sdk.AuthorizationError, 'repository identity'):
            execution.sdk.build_request(self.base.root, self.base.plan, 'deployment-rollback',
                collector=self.base.collector, observation=self.base.observation, rollback_target=history,
                execution_intent=self.base.intent, repository_slug='fixture/example', repository_id=999,
                expires_at=(execution.sdk.clock() + execution.timedelta(minutes=20)).isoformat())


if __name__ == '__main__':
    unittest.main()
