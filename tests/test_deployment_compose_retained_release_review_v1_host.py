"""Exact review, encrypted OIDC slots, and one-shot GitHub claim fixtures."""
from copy import deepcopy
from pathlib import Path
import hashlib
import tempfile
import time
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_production_frontend_approval_v1_host import approved, fixture, host, retained_review
from tests.test_release_host import claims
from deployment_compose_full_body_review_contract import canonical
from deployment_compose_retained_release_authority_v1_host import RetainedReleaseStageApprovalV1
from deployment_compose_retained_release_plan_v1_host import prepare_release_plan, release_plan_digest
from deployment_compose_retained_release_review_v1_host import (
    prepare_release_review, release_summary, seal_release_slot, slot_audience, verify_release_review,
)
from release_execute import AuthorizationUnavailable


class ReleaseReviewTests(unittest.TestCase):
    def setUp(self):
        self.configure()

    def configure(self, review=None):
        initial, base, source = fixture()
        if review is None:
            review = retained_review(source, 'deploy')
            review['retainedCutover'].update(stage='create', protectionMode=host.STAGED_PROTECTION_MODE)
        self.review = deepcopy(review)
        self.plan = prepare_release_plan(self.review, policy_hash=initial.policy_hash,
                                         runtime_sha=base.workflow_sha, expires_at=initial.expires_at)
        self.digest = release_plan_digest(self.plan)
        self.env = dict(GITHUB_REPOSITORY=host.RUNTIME, GITHUB_REPOSITORY_ID='1327491026',
                        GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch',
                        GITHUB_RUN_ATTEMPT='1', GITHUB_WORKFLOW_REF=host.WORKFLOW, GITHUB_RUN_ID='123',
                        GITHUB_WORKFLOW_SHA=base.workflow_sha, GITHUB_SHA=base.workflow_sha,
                        DW_AUTH_REVIEWER_ID='21', DW_AUTH_LEDGER_ID='1436718662',
                        DW_AUTH_LEDGER_REPOSITORY=host.LEDGER, DW_AUTH_LEDGER_SHA=base.ledger_sha,
                        DW_PROD_FRONTEND_POLICY_HASH=initial.policy_hash)
        self.raw = canonical(prepare_release_review(canonical(self.plan), self.env))
        artifact, policy = verify_release_review(self.raw, self.env, expected_digest=self.digest)
        self.policy, self.approval_hash = policy, artifact['approvalHash']
        self.request = host.prepare_production_frontend_request(
            self.review, policy_hash=initial.policy_hash, expires_at=initial.expires_at)
        staged = host.ProductionFrontendApprovalPolicyV3(**dict(
            vars(base), environment='compose-review', stage='create',
            host_id=self.request.host_id, daemon_id=self.request.daemon_id,
            snapshot_hash=self.request.before_hash, body_hash=self.request.after_hash,
            protected_inventory_hash=host._digest(list(self.request.protected_components)),
            observation_hash=self.request.observation_hash, plan_hash=self.request.plan_hash,
            request_hash=self.request.digest(),
        ))
        _, self.client, _ = approved(staged, self.request)
        self.review_path = f'/repos/{host.RUNTIME}/actions/runs/{policy.run_id}/approvals'
        self.client.data[self.review_path][0]['comment'] = 'dev-workflow approve ' + self.approval_hash
        self.tags, self.claims = {}, {}
        self.lose_ref_response = False
        original = self.client.request

        def transport(method, path, payload=None, *, before_send=lambda: None):
            if method == 'POST' and path.endswith('/git/tags'):
                before_send()
                sha = hashlib.sha1(canonical(payload).encode()).hexdigest()
                stored = dict(tag=payload['tag'], message=payload['message'], sha=sha,
                              object=dict(type=payload['type'], sha=payload['object']))
                self.tags[sha] = stored
                return deepcopy(stored), {}
            if method == 'GET' and '/git/tags/' in path:
                return deepcopy(self.tags[path.rsplit('/', 1)[1]]), {}
            if method == 'POST' and path.endswith('/git/refs'):
                before_send()
                marker = payload['ref'].removeprefix('refs/')
                if marker in self.claims:
                    raise RuntimeError('Ref already exists')
                self.claims[marker] = dict(ref=payload['ref'], object=dict(type='tag', sha=payload['sha']))
                if self.lose_ref_response:
                    raise OSError('Response lost after mutation')
                return deepcopy(self.claims[marker]), {}
            if method == 'GET' and '/git/ref/' in path:
                return deepcopy(self.claims[path.split('/git/ref/', 1)[1]]), {}
            return original(method, path, payload, before_send=before_send)

        self.client.request = transport

    def authority(self, slot, *, token_slot=None, token_seconds=300, stage='create',
                  review=None, witness_source=None, readiness_failure=None):
        token = claims(self.policy)
        token['exp'] = token['iat'] + token_seconds
        token['aud'] = slot_audience(self.approval_hash, slot if token_slot is None else token_slot)
        return RetainedReleaseStageApprovalV1(
            self.client, 'signed', self.raw, self.env, reviewed_digest=self.digest, slot=slot,
            stage=stage, current_review=self.review if review is None else review, witness_source=witness_source,
            readiness_failure=readiness_failure, verifier=lambda _: deepcopy(token),
        )

    def test_release_summary_and_slot_ciphertexts_are_bound_to_one_review(self):
        self.assertIn('dev-workflow approve ' + self.approval_hash, release_summary(self.raw, self.env))
        self.assertNotEqual(slot_audience(self.approval_hash, 1), slot_audience(self.approval_hash, 2))
        with self.assertRaises(ValueError):
            verify_release_review(self.raw, dict(self.env, GITHUB_RUN_ID='125'), expected_digest=self.digest)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'slot.cms'
            with (patch('deployment_compose_retained_release_review_v1_host.common._fetch_verified_audience',
                        return_value=b'a.b.c') as fetch,
                  patch('deployment_compose_retained_release_review_v1_host.common.encrypt_token',
                        side_effect=lambda token, key, path: Path(path).write_bytes(b'cipher'))):
                seal_release_slot(self.raw, self.env, 'public-cert', output, slot=2)
                fetch.assert_called_once_with(self.env, slot_audience(self.approval_hash, 2))
                self.assertEqual(output.read_bytes(), b'cipher')
                with self.assertRaises(FileExistsError):
                    seal_release_slot(self.raw, self.env, 'public-cert', output, slot=2)

    def test_fresh_slot_cannot_repeat_a_claim_and_wrong_slot_is_rejected(self):
        first = self.authority(1)
        receipt = first.consume(first.validate(first.request), first.request)
        self.assertEqual(receipt.request_hash, self.request.digest())
        first.check_consumed_intent(first.request)
        second = self.authority(2)
        with self.assertRaises(AuthorizationUnavailable):
            second.consume(second.validate(second.request), second.request)
        with self.assertRaises(AuthorizationUnavailable):
            second.check_consumed_intent(second.request)
        with self.assertRaises(AuthorizationUnavailable):
            self.authority(2, token_slot=1)
        with self.assertRaises(AuthorizationUnavailable):
            self.authority(3, token_seconds=301)
        self.assertEqual(len(self.claims), 1)

    def test_authority_is_rechecked_between_tag_creation_and_claim(self):
        first = self.authority(1)
        original = self.client.request

        def revoke(method, path, payload=None, **kwargs):
            result = original(method, path, payload, **kwargs)
            if method == 'POST' and path.endswith('/git/tags'):
                self.client.data[self.review_path][0]['comment'] = 'approval changed'
            return result

        with patch.object(self.client, 'request', side_effect=revoke), self.assertRaises(AuthorizationUnavailable):
            first.consume(first.validate(first.request), first.request)
        self.assertFalse(self.claims)
        self.assertEqual(len(self.tags), 1)

    def test_lost_claim_reply_never_grants_authority_or_replay(self):
        first = self.authority(1)
        self.lose_ref_response = True
        with self.assertRaises(AuthorizationUnavailable):
            first.consume(first.validate(first.request), first.request)
        self.assertEqual(len(self.claims), 1)
        with self.assertRaises(AuthorizationUnavailable):
            first.check_consumed_intent(first.request)
        self.lose_ref_response = False
        second = self.authority(2)
        with self.assertRaises(AuthorizationUnavailable):
            second.consume(second.validate(second.request), second.request)

    def test_exact_request_tampering_breaks_consumed_guard(self):
        first = self.authority(1)
        first.consume(first.validate(first.request), first.request)
        tag, = self.tags.values()
        tag['message'] = '{}'
        with self.assertRaises(AuthorizationUnavailable):
            first.check_consumed_intent(first.request)
