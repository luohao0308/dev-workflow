"""Probe acceptance integrated with actual deployment and rollback capabilities."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest
from unittest import mock

from tests import test_deployment_execute as execution
import deployment_verify as verify


class PublishedDocker(execution.MutableDocker):
    def __init__(self):
        super().__init__()
        for (component, image), spec in list(self.specs.items()):
            if component == 'web':
                self.specs[(component, image)] = execution.recipes.ContainerSpec.from_image(
                    component, self.images[image], port_bindings={
                        '8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18080'}]})
        spec = self.specs[('web', 'sha256:' + 'a' * 64)]
        self.containers[execution.OLD] = self.inspect(execution.OLD, 'initial-web',
            spec.to_create('fixture', 'initial'), running=True)

    def inspect(self, cid, name, body, *, running):
        value = super().inspect(cid, name, body, running=running)
        value['NetworkSettings']['Ports'] = deepcopy(body['HostConfig'].get('PortBindings', {})) if running else {}
        return value

    def write(self, method, path, body):
        result = super().write(method, path, body)
        for container in self.containers.values():
            container['NetworkSettings']['Ports'] = (deepcopy(container['HostConfig'].get('PortBindings', {}))
                if container['State']['Running'] else {})
        return result


class DeploymentVerificationTests(unittest.TestCase):
    def setUp(self):
        self.base = execution.DeploymentExecuteTests(methodName='runTest')
        with mock.patch.object(execution, 'MutableDocker', PublishedDocker):
            self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.calls, self.probe_failure = [], None
        self.original_api = deepcopy(self.base.docker.containers[execution.API])
        profiles = []
        for digit, version in (('a', 'v1'), ('b', 'v2')):
            spec = self.base.docker.specs[('web', 'sha256:' + digit * 64)]
            def probe(name, expected):
                return dict(id=name, path='/' + name, status=200, jsonExpectations=expected,
                            attempts=2, retryDelay=0, timeout=1, maxBodyBytes=1024)
            profiles.append(dict(component='web', imageId='sha256:' + digit * 64,
                specHash=spec.configuration_digest(), containerPort='8080/tcp', hostIp='127.0.0.1',
                hostPort='18080', address='127.0.0.1', scheme='http', tlsHostname=None,
                serverCertificateSha256=None, health=[probe('ready', {'/ready': True, '/version': version})],
                smoke=[probe('business', {'/value': 42, '/version': version})]))
        policy = verify.ProbePolicy(self.base.collector.policy.identity_hash(), json.dumps(dict(
            schemaVersion=1, kind='deployment-probe-policy', profiles=profiles)))
        self.verifier = verify.TrustedProbeVerifier(policy, self.base.collector.policy, transport=self.http)
        self.base.policy = replace(self.base.policy, verification_policy_hash=policy.identity_hash())
        self.base.client = execution.backend.DockerMutationClient(self.base.policy, ca_file=execution.Path('unused'),
            cert_file=execution.Path('unused'), key_file=execution.Path('unused'), transport=self.base.docker.write)
        self.base.engine = execution.backend.DockerExecutor(self.base.policy, self.base.client,
            self.base.collector, verifier=self.verifier)
        self.base.prepare()

    def http(self, profile, probe, deadline):
        self.calls.append(probe['id'])
        if self.probe_failure == 'drift':
            self.base.docker.managed_files[(execution.API, 'hosts')] = b'changed during HTTP'
        version = 'v1' if profile['imageId'].endswith('a' * 64) else 'v2'
        body = dict(ready=True, value=42, version=version)
        if self.probe_failure == 'business' and probe['id'] == 'business':
            body['value'] = 0
        status = 503 if self.probe_failure == 'health' else 200
        return status, [('Content-Type', 'application/json')], json.dumps(body).encode()

    def test_healthy_deploy_and_separately_authorized_rollback(self):
        old = self.base.observation
        result = self.base.execute()
        self.assertEqual(result['status'], 'executed-verified')
        self.assertEqual(result['verification']['health'], 'passed')
        self.assertEqual(result['verification']['smoke'], 'passed')
        self.base.observation = result['observation']
        self.base.prepare('a', operation='deployment-rollback', rollback_target=old)
        rolled = self.base.execute()
        self.assertEqual(rolled['status'], 'executed-verified')
        self.assertEqual(len(self.base.docker.writes), 8)
        self.assertEqual(self.original_api, self.base.docker.containers[execution.API])

    def test_failed_health_stops_smoke_without_automatic_rollback(self):
        self.probe_failure = 'health'
        result = self.base.execute()
        self.assertEqual(result['status'], 'executed-unhealthy')
        self.assertEqual(result['verification']['health'], 'failed')
        self.assertEqual(result['verification']['smoke'], 'not-run')
        self.assertEqual(self.calls, ['ready', 'ready'])
        self.assertEqual(len(self.base.docker.writes), 4)
        self.assertNotIn(execution.OLD, self.base.docker.containers)
        self.assertEqual(self.original_api, self.base.docker.containers[execution.API])

    def test_business_failure_returns_live_baseline_for_fresh_rollback(self):
        old = self.base.observation
        self.probe_failure = 'business'
        result = self.base.execute()
        self.assertEqual(result['status'], 'executed-unhealthy')
        self.assertEqual(result['verification']['health'], 'passed')
        self.assertEqual(result['verification']['smoke'], 'failed')
        self.assertEqual(len(self.base.docker.writes), 4)
        self.probe_failure = None
        self.base.observation = result['observation']
        self.base.prepare('a', operation='deployment-rollback', rollback_target=old)
        self.assertEqual(self.base.execute()['status'], 'executed-verified')
        self.assertEqual(len(self.base.docker.writes), 8)

    def test_runtime_drift_during_http_is_not_reported_as_unhealthy(self):
        self.probe_failure = 'drift'
        result = self.base.execute()
        self.assertEqual(result['status'], 'executed-unverified')
        self.assertTrue(result['reconcileRequired'])
        self.assertNotEqual(result['verification']['health'], 'failed')
        self.assertEqual(len(self.base.docker.writes), 4)

    def test_shadowed_verifier_method_cannot_bypass_required_checks(self):
        self.probe_failure = 'business'
        self.verifier.check = lambda *a, **k: dict(passed=True, health='passed', smoke='passed', checks=[])
        result = self.base.execute()
        self.assertEqual(result['status'], 'executed-unhealthy')
        self.assertTrue(result['probeChecks'])

    def test_changed_probe_cache_refused_before_authorization(self):
        key = ('web', 'sha256:' + 'b' * 64)
        profile = json.loads(self.verifier._profiles[key])
        profile['health'], profile['smoke'] = [], []
        self.verifier._profiles[key] = json.dumps(profile)
        with self.assertRaises(verify.VerificationError):
            self.base.authorize()
        self.assertFalse(self.base.docker.writes)

    def test_equivalent_policy_does_not_allow_replacing_verifier_instance(self):
        self.base.engine.verifier = verify.TrustedProbeVerifier(self.verifier.policy,
            self.base.collector.policy, transport=lambda *a: (200, [], b'{"ready":true}'))
        with self.assertRaisesRegex(execution.backend.ExecutionError, 'adapter-changed'):
            self.base.authorize()
        self.assertFalse(self.base.docker.writes)

    def test_required_verifier_cannot_be_omitted(self):
        with self.assertRaises(execution.backend.ExecutionError):
            execution.backend.DockerExecutor(self.base.policy, self.base.client, self.base.collector)
        self.assertFalse(self.base.docker.writes)


if __name__ == '__main__':
    unittest.main()
