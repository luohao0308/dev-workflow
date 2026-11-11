"""Real OpenSSH signing and one-shot GitHub ledger fixture through the V2 relay."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

from tests.test_deployment_compose_production_frontend_approval_v1_host import approved, fixture, host, retained_review
from deployment_compose_retained_intent_relay_v1_host import (
    IntentRelayRejected, RetainedIntentBindingV1, RetainedIntentClientV1, RetainedIntentIssuerV1,
)


@unittest.skipUnless(os.name == 'posix' and Path('/usr/bin/ssh-keygen').is_file(), 'OpenSSH required')
class RetainedRelayTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.signer = Path(directory.name).resolve()/'issuer'
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.signer)],
                       capture_output=True, check=True, timeout=10)
        self.public = self.signer.with_suffix('.pub').read_bytes()
        original, policy, review = fixture()
        self.request = host.prepare_production_frontend_request(retained_review(review, 'deploy'),
            policy_hash=original.policy_hash, expires_at=original.expires_at)
        policy = host.ProductionFrontendApprovalPolicyV2(**dict(vars(policy), observation_hash=self.request.observation_hash,
            plan_hash=self.request.plan_hash, request_hash=self.request.digest()))
        approval, self.ledger, _ = approved(policy, self.request)
        self.grant = approval.validate(self.request)
        self.binding = RetainedIntentBindingV1('1'*64, policy.workflow_sha, '2'*64, '3'*64, '4'*64)
        self.issuer = RetainedIntentIssuerV1(approval, self.request, self.grant,
                                             binding=self.binding, signer=self.signer)

    def client(self, transport=None, binding=None):
        return RetainedIntentClientV1(self.request, binding=binding or self.binding, public_key=self.public,
                                     transport=transport or self.issuer.authorize_rpc)

    def test_real_signatures_bind_ledger_receipt_and_live_scope(self):
        client = self.client()
        grant = client.validate(self.request)
        receipt = client.consume(grant, self.request, before_consume=lambda: None, generation=7)
        self.assertEqual(receipt.request_hash, self.request.digest())
        self.assertIsInstance(client.check_consumed_intent(self.request), int)
        self.assertEqual(len(self.ledger.markers), 1)
        with self.assertRaises(IntentRelayRejected):
            client.consume(grant, self.request, before_consume=lambda: None, generation=7)
        client._scope = 8
        with self.assertRaises(IntentRelayRejected):
            client.check_consumed_intent(self.request)

    def test_wrong_origin_or_replayed_reply_cannot_validate(self):
        wrong = replace(self.binding, origin_digest='5'*64)
        with self.assertRaises(IntentRelayRejected):
            self.client(binding=wrong).validate(self.request)
        saved = []
        def replay(rpc):
            if not saved:
                saved.append(self.issuer.authorize_rpc(rpc))
            return saved[0]
        client = self.client(replay)
        client.validate(self.request)
        with self.assertRaises(IntentRelayRejected):
            client.validate(self.request)
        self.assertFalse(self.ledger.markers)

    def test_tampered_receipt_is_rejected_without_second_consumption(self):
        def corrupt(rpc):
            result = self.issuer.authorize_rpc(rpc)
            if rpc['method'] == 'consume':
                result = deepcopy(result)
                result['payload']['result']['use_number'] = 2
            return result
        client = self.client(corrupt)
        grant = client.validate(self.request)
        for _ in range(2):
            with self.assertRaises(IntentRelayRejected):
                client.consume(grant, self.request, before_consume=lambda: None, generation=7)
        self.assertEqual(len(self.ledger.markers), 1)
