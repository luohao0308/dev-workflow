"""V4 mock GitHub/OIDC provider, real approval base/ledger and SSH signatures."""
from copy import copy,deepcopy
from dataclasses import replace,asdict
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import deployment_compose_approval_v4_host as host
from deployment_compose_intent_status_v4_host import IntentStatusHostV4
from deployment_compose_intent_status_v4 import IntentStatusClientV4, IntentStatusRejected
from release_execute import AuthorizationUnavailable
from tests import test_deployment_compose_approval_v3_host as old


class ApprovalV4Tests(unittest.TestCase):
    def setUp(self):
        self.request=old.request(profile_version='4')
        values=vars(old.policy());values.update(profile_version='4',expected_observation_hash=self.request.observation_hash,
            session_hash='1'*64,context_digest=self.request.observation_hash,actor_epoch='2'*64,scope_ordinal=0,plan_write_index=0,action_digest='3'*64)
        self.policy=host.FullBodyApprovalPolicyV4(**values)
        harness=old.ComposeApprovalTests();harness.setUp();harness.policy=self.policy
        self.client=harness.client_for([self.request])
        self.claims=dict(old.claims(self.policy),aud=host.AUDIENCE)
        self.approval=host.GitHubFullBodyApprovalV4(self.client,'signed',[self.request],self.policy,
            verifier=lambda _:deepcopy(self.claims))

    def consume(self):return self.approval.consume(self.approval.validate(self.request),self.request)

    def test_receipt_is_actual_consumption_identity_and_replay_rejected(self):
        receipt=self.consume();value=self.approval.receipt_hash(receipt,self.request)
        self.assertEqual(len(value),64)
        for fake in (copy(receipt),asdict(receipt),old.host.FullBodyConsumptionEvidenceV3(*vars(receipt).values())):
            with self.assertRaises(AuthorizationUnavailable):self.approval.receipt_hash(fake,self.request)
        self.assertEqual(len(self.client.markers),1)
        self.assertEqual(self.client.posts,1)
        self.assertTrue(next(iter(self.client.markers)).startswith('tags/workflow-compose-full-body-authorization-v4/'))
        with self.assertRaises(AuthorizationUnavailable):self.consume()
        self.assertEqual(self.client.posts,1)
        with self.assertRaises(AuthorizationUnavailable):self.approval.guard(self.request)

    def test_online_authority_and_ledger_rechecked(self):
        self.consume();self.approval.check_consumed_intent(self.request)
        self.claims['aud']=old.host.AUDIENCE
        with self.assertRaises(AuthorizationUnavailable):self.approval.check_consumed_intent(self.request)
        self.claims['aud']=host.AUDIENCE
        self.client.markers.clear()
        with self.assertRaises(AuthorizationUnavailable):self.approval.check_consumed_intent(self.request)

    def test_scope_profile_context_and_default_verifier(self):
        for req in (replace(self.request,profile_version='3'),replace(self.request,observation_hash='0'*64),
                    replace(self.request,host_id='other'),replace(self.request,production=True)):
            with self.assertRaises(AuthorizationUnavailable):
                host.GitHubFullBodyApprovalV4(self.client,'signed',[req],self.policy,verifier=lambda _:self.claims)
        with patch('release_host.verify_oidc',side_effect=ValueError('real verifier selected')) as verifier:
            with self.assertRaises(ValueError):host.GitHubFullBodyApprovalV4(self.client,'signed',[self.request],self.policy)
            verifier.assert_called_once_with('signed')

    def test_recovery_has_independent_profile_and_history_policy(self):
        request=replace(self.request,operation='recovery',profile_id='compose-recovery-v4',history_hash='1'*64)
        policy=replace(self.policy,operation='recovery',expected_history_hash='1'*64)
        harness=old.ComposeApprovalTests();harness.setUp();harness.policy=policy
        client=harness.client_for([request]);claims=dict(old.claims(policy),aud=host.AUDIENCE)
        approval=host.GitHubFullBodyApprovalV4(client,'signed',[request],policy,verifier=lambda _:claims)
        receipt=approval.consume(approval.validate(request),request)
        self.assertEqual(receipt.request_hash,request.digest())

    def test_actor_and_action_change_human_review_bundle(self):
        for changed in (replace(self.policy,actor_epoch='0'*64),replace(self.policy,action_digest='0'*64),
                        replace(self.policy,scope_ordinal=1),replace(self.policy,session_hash='0'*64)):
            self.assertNotEqual(changed.bundle_context(),self.policy.bundle_context())
            with self.assertRaises(AuthorizationUnavailable):
                host.GitHubFullBodyApprovalV4(self.client,'signed',[self.request],changed,verifier=lambda _:self.claims)
        grant=self.approval.validate(self.request)
        legacy=old.host.FullBodyAuthorizationEvidenceV3(**vars(grant))
        with self.assertRaises(AuthorizationUnavailable):self.approval.consume(legacy,self.request)


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX real SSH signer')
class StatusHostV4Tests(unittest.TestCase):
    consume = ApprovalV4Tests.consume
    def setUp(self):
        ApprovalV4Tests.setUp(self);self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.key=Path(self.temp.name)/'key'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(self.key)],check=True,capture_output=True)
        self.receipt=self.consume()
        self.bindings=dict(session_hash='1'*64,context_digest=self.request.observation_hash,policy_hash=self.request.policy_hash,
            actor_epoch='2'*64,scope_ordinal=0,plan_write_index=0,action_digest='3'*64)
        self.signer=IntentStatusHostV4(authority=self.approval,request=self.request,receipt=self.receipt,signing_key=self.key,**self.bindings)
        self.status=IntentStatusClientV4(self.request,self.signer.public_key,self.signer.respond,
            consumption_receipt_hash=self.approval.receipt_hash(self.receipt,self.request),**self.bindings)

    def test_real_signatures_interoperate_without_another_ledger_post(self):
        first=self.status.check_consumed_intent(self.request)
        second=self.status.check_consumed_intent(self.request)
        self.assertNotEqual(first['rpcNonce'],second['rpcNonce'])
        self.assertEqual(len(self.client.markers),1)
        self.assertEqual(self.client.posts,1)
        for key in ('authorityGranted','runtimePermit','productionReady'):self.assertIs(first[key],False)
        self.claims['aud']=old.host.AUDIENCE
        with self.assertRaises(IntentStatusRejected):self.status.check_consumed_intent(self.request)

    def test_forged_authority_receipt_and_binding_rejected(self):
        for changes in (dict(authority=True),dict(receipt=copy(self.receipt)),dict(context_digest='0'*64),dict(actor_epoch='0'*64),dict(action_digest='0'*64),dict(scope_ordinal=True)):
            args=dict(authority=self.approval,request=self.request,receipt=self.receipt,signing_key=self.key,**self.bindings)
            args.update(changes)
            with self.assertRaises((ValueError,AuthorizationUnavailable)):IntentStatusHostV4(**args)
        challenge=dict(self.status._bindings,schemaVersion=4,purpose='check-consumed-intent-v4',bootNonce='a'*64,rpcNonce='b'*64)
        challenge['scopeOrdinal']=False
        with self.assertRaises(ValueError):self.signer.respond(challenge)
        self.client.markers.clear()
        with self.assertRaises(IntentStatusRejected):self.status.check_consumed_intent(self.request)

    def test_expired_authority_and_missing_consumption_cannot_sign(self):
        self.approval._verified_consumptions.clear()
        with self.assertRaises(IntentStatusRejected):self.status.check_consumed_intent(self.request)
        self.approval._verified_consumptions.add(self.request.digest())
        self.claims['exp']=0
        with self.assertRaises(IntentStatusRejected):self.status.check_consumed_intent(self.request)
