"""Trusted acceptance observations must originate in the running host."""
from pathlib import Path
from dataclasses import replace
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
import deployment_acceptance as acceptance
import deployment_acceptance_host as host
import deployment_runtime as runtime
import deployment_execute as execution
import deployment_verify as verification


def profile():
    return acceptance.AcceptanceProfile(
        'one', 1, 'staging', 'isolated', 'web', *(['a' * 64] * 5),
        True, True, True, 'previous', 'linux', 'docker', 'stateless', True, ())


class HostAcceptanceTests(unittest.TestCase):
    def test_untrusted_serialized_evidence_cannot_become_accepted(self):
        p = profile()
        supplied = {stage: 'passed' for stage in
                    ('approval', 'deployment', 'health', 'smoke', 'rollback', 'recovery')}
        self.assertEqual(acceptance.assess_supplied(p, supplied)['status'], 'unknown')
        with self.assertRaises(host.HostAcceptanceError):
            host.assess_run(p, supplied, supplied, recovery_stage=supplied)

    def test_forged_in_process_stage_rejected_and_cannot_mutate(self):
        p = profile()
        fake = host._Stage(p.identity_hash(), 'deployment-deploy', '1' * 64,
                           {'status': 'executed-verified', 'verification':
                            {'health': 'passed', 'smoke': 'passed'}})
        with self.assertRaises(AttributeError):
            fake.status = 'blocked'
        with self.assertRaises(host.HostAcceptanceError):
            host.assess_run(p, fake, fake)

    def test_public_stage_rejects_wrong_scope_before_credential_use(self):
        with self.assertRaises(host.HostAcceptanceError):
            host.run_stage(profile(), root=ROOT, plan={}, request={}, collector=None,
                           observation=None, executor=None, intent=None, host_policy=None,
                           github_token='token', oidc_token='token')

    def test_unsupported_profile_stops_before_authority_or_execution(self):
        for p in (replace(profile(), allow_interruption=False),
                  replace(profile(), require_health=False),
                  replace(profile(), require_smoke=False),
                  replace(profile(), platform='windows')):
            with self.subTest(profile=p), patch.object(host.sdk, 'authorize') as authorize:
                with self.assertRaises(host.HostAcceptanceError):
                    host.run_stage(p, root=ROOT, plan={}, request={}, collector=None,
                                   observation=None, executor=None, intent=None, host_policy=None,
                                   github_token='token', oidc_token='token')
                authorize.assert_not_called()
            with patch.object(host.recovery.HostCoordinator, 'recover') as recover:
                with self.assertRaises(host.HostAcceptanceError):
                    host.run_recovery(p, coordinator=None, request={}, approval={})
                recover.assert_not_called()

    def test_recovery_rejects_caller_supplied_result(self):
        with self.assertRaises(host.HostAcceptanceError):
            host.run_recovery(profile(), coordinator=None, request={}, approval={})

    def test_simulated_sdk_transports_cannot_issue_host_evidence(self):
        collector = object.__new__(runtime.TrustedDockerCollector)
        reader = object.__new__(runtime.DockerTLSClient)
        writer = object.__new__(execution.DockerMutationClient)
        probe = object.__new__(verification.TrustedProbeVerifier)
        executor = object.__new__(execution.DockerExecutor)
        collector.client = reader
        executor.collector, executor.client, executor.verifier = collector, writer, probe
        reader._transport, reader._context = None, object()
        writer._transport, writer._context = None, object()
        probe._transport = probe._trusted_transport = None
        host._real_sdk(collector, executor)
        for adapter, field in ((reader, '_transport'), (writer, '_transport'),
                               (probe, '_transport'), (probe, '_trusted_transport')):
            setattr(adapter, field, lambda *args: None)
            with self.assertRaises(host.HostAcceptanceError):
                host._real_sdk(collector, executor)
            setattr(adapter, field, None)
        for adapter in (reader, writer):
            adapter._context = None
            with self.assertRaises(host.HostAcceptanceError):
                host._real_sdk(collector, executor)
            adapter._context = object()

    def test_report_exports_bounded_refs_and_rejects_mixed_workflow_attempts(self):
        p = profile()
        evidence = dict(workflowSha='a' * 40, workflowRunId=7, workflowRunAttempt=1,
                        repository='example/target', environment='staging', target='isolated',
                        component='web', observationHash='b' * 64)
        def stage(operation, target, attempt=1):
            value = host._Stage(p.identity_hash(), operation, operation, dict(
                status='recovered-runtime-verified' if operation == 'deployment-recover' else 'executed-verified',
                verification=dict(health='passed', smoke='passed'),
                _acceptance_head_sha='c' * 40, _acceptance_repository='/candidate',
                _acceptance_target_source_sha=target),
                dict(evidence, workflowRunAttempt=attempt, requestHash=operation))
            host._ISSUED.add(value)
            return value
        deploy = stage('deployment-deploy', 'new')
        rollback = stage('deployment-rollback', 'previous')
        recovery = stage('deployment-recover', None)
        report = host.assess_run(p, deploy, rollback, recovery_stage=recovery)
        self.assertEqual(report['status'], 'accepted')
        self.assertEqual(report['evidenceRefs']['deployment']['requestHash'], 'deployment-deploy')
        self.assertEqual(report['evidenceRefs']['rollback']['observationHash'], 'b' * 64)
        self.assertEqual(report['productionReady'], False)
        with self.assertRaises(TypeError):
            deploy.evidence['workflowRunId'] = 8
        with self.assertRaises(host.HostAcceptanceError):
            host.assess_run(p, deploy, stage('deployment-rollback', 'previous', 2),
                            recovery_stage=recovery)


if __name__ == '__main__':
    unittest.main()
