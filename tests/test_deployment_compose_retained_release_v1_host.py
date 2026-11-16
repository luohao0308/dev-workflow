"""Entry-point checks with no live dispatch, SSH, or Docker writes."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests.test_deployment_compose_production_frontend_approval_v1_host import fixture
import deployment_compose_retained_release_v1_host as cli


@unittest.skipUnless(os.name == 'posix', 'POSIX private workspace required')
class ReleaseCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.workspace.chmod(0o700)
        self.args = ['--runtime-sha', '1'*40, '--workspace', str(self.workspace)]

    def test_preflight_cannot_dispatch_and_changed_baseline_blocks_release(self):
        before = dict(runtimeSha='1'*40, baseline={'journalDigest': '2'*64}, privatePlanDigest='3'*64)
        after = dict(before, baseline={'journalDigest': '4'*64})
        with (patch.object(cli, '_published'), patch.object(cli, '_runtime'), patch.object(cli, '_emit'),
              patch('deployment_compose_retained_source_v1_host.production_archive', return_value=b'archive'),
              patch.object(cli, '_prepare', side_effect=[(before['baseline'], {}, before), (after['baseline'], {}, after)]),
              patch.object(cli, '_publish') as publish):
            self.assertEqual(cli.main(['preflight', *self.args]), 0)
            self.assertEqual(cli.main(['release', *self.args, '--recipient-private-key',
                                       str(self.workspace/'key')]), 2)
            publish.assert_not_called()
        self.assertEqual((self.workspace/'baseline.json').stat().st_mode & 0o777, 0o600)

    def _execute(self, switch, *, restored=None):
        req, _, _ = fixture()
        controller, reviewer, emit = Mock(), Mock(), Mock()
        controller.review = {'retainedCutover': {'creationRequestHash': '1'*64, 'scopeGeneration': 7}}
        parameters = [dict(blocked=False, switchReview=controller.review, result={'requestHash': '1'*64}), switch]
        if restored:
            parameters.append(restored)
        controller.execute.side_effect = parameters
        reviewer.release_stage_grant.side_effect = [
            (index, SimpleNamespace(request=req), object()) for index in range(1, len(parameters)+1)
        ]
        pending = dict(requestHash='1'*64,generation=7,journalDigest='5'*64)
        key = b'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPeDQCg9g6cakGZAd8WpSUpDDcxFWL2mS2vi7yszm4N'
        with patch('deployment_compose_retained_release_preflight_v1_host.inspect_active_release', return_value=pending):
            try:
                result = cli._execute_release(controller, reviewer, b'archive', {}, {}, self.workspace, key, emit)
            except ValueError as error:
                result = error
        self.assertEqual(reviewer.request_release_review.call_count, 1)
        return result, [call.args[0] for call in reviewer.release_stage_grant.call_args_list]

    def test_release_automatically_accepts_a_healthy_candidate(self):
        result, stages = self._execute(dict(blocked=False, terminalProof='a'*64, result={'candidateId': 'b'*64}))
        self.assertEqual(stages, ['create', 'switch'])
        self.assertEqual(result['disposition'], 'retained-candidate')
        self.assertEqual(result['proof'], 'a'*64)

    def test_release_does_not_restore_an_unknown_switch(self):
        result, stages = self._execute(dict(blocked=True, restoreReview=None, result=None))
        self.assertIsInstance(result, ValueError)
        self.assertEqual(stages, ['create', 'switch'])

    def test_release_requests_rollback_only_for_the_controller_readiness_failure(self):
        failure = object()
        result, stages = self._execute(dict(blocked=False, restoreReview={}, readinessFailure=failure, result=None),
                                       restored=dict(blocked=False, result={'originalId': 'c'*64}))
        self.assertEqual(stages, ['create', 'switch', 'rollback'])
        self.assertEqual(result['disposition'], 'restored-original')
