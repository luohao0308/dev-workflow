"""Real native authority/ledger/preparer/provider with explicit mock HTTP only."""
from copy import deepcopy
from dataclasses import replace
import os
import unittest
from unittest.mock import patch

from tests import test_release_gitlab_approval_v2_host as native
import release_gitlab_execute_v2_host as execution
from release_execute import Request as LegacyRequest,Grant as LegacyGrant
from pathlib import Path
import tempfile
from release_gitlab_preflight_host import GitLabPreflightHost
from release_gitlab_prepare_v2_host import GitLabRequestPreparationV2
import release_gitlab_plan
import release_gitlab_preflight_host


@unittest.skipUnless(os.name=='posix','POSIX native approval ledger')
class GitLabExecutionTests(unittest.TestCase):
    def setUp(self):
        self.h=native.NativeApprovalTests();self.h.setUp();self.addCleanup(self.h.doCleanups)
        self.posts=[];self.tag=None;self.failure=None;self.readback_drift=False
        original=self.h.fixture.client._transport
        def transport(method,path,payload):
            if method=='POST':
                self.assertEqual(path,'/projects/42/repository/tags')
                self.posts.append(deepcopy(payload))
                if self.failure=='http':return 403,{},dict(message='denied')
                if self.failure:raise TimeoutError('unknown POST outcome')
                self.tag=self.row()
                return 201,{},deepcopy(self.tag)
            if '/repository/tags/' in path:
                if self.tag is None:return 404,{},None
                value=deepcopy(self.tag)
                if self.readback_drift:value['target']='0'*40
                return 200,{},value
            return original(method,path,payload)
        self.h.fixture.client._transport=transport
        self.runner=self.make()
    def row(self):
        return dict(name='v1.2.3',message=None,target=self.h.request.target_sha,commit=dict(id=self.h.request.target_sha))
    def make(self,**changes):
        args=dict(authority=self.h.authority,preparer=self.h.preparer,approved_request=self.h.request)
        args.update(changes);return execution.GitLabTagExecutionHostV2(**args)
    def grant(self):return self.h.authority.validate(self.h.request)

    def test_exact_lightweight_post_and_readback_no_second_grant_dispatch(self):
        grant=self.grant();result=self.runner.execute(grant)
        self.assertEqual(self.posts,[dict(tag_name='v1.2.3',ref=self.h.request.target_sha)])
        self.assertTrue(result['postAttempted']);self.assertEqual(result['targetSha'],self.h.request.target_sha)
        self.assertEqual(len(self.h.ledger._read()['entries']),1)
        with self.assertRaises(execution.GitLabExecutionV2Error):self.make().execute(grant)
        self.assertEqual(len(self.posts),1)

    def failed_post(self, failure=False, drift=False):
        grant=self.grant();self.failure=failure;self.readback_drift=drift
        with self.assertRaises(execution.GitLabExecutionV2Error) as caught:self.runner.execute(grant)
        self.assertTrue(caught.exception.consumed);self.assertTrue(caught.exception.post_attempted)
        with self.assertRaises(execution.GitLabExecutionV2Error):self.make().execute(grant)
        if failure:
            # A new grant cannot evade the ledger's request-wide burn either.
            with self.assertRaises(execution.GitLabExecutionV2Error):self.make().execute(self.grant())
        self.assertEqual(len(self.posts),1)
        self.assertEqual(len(self.h.ledger._read()['entries']),1)

    def test_unknown_post_outcome_stays_consumed_without_retry(self):self.failed_post(failure=True)
    def test_bad_readback_stays_consumed_without_retry(self):self.failed_post(drift=True)

    def test_missing_review_and_invalid_grants_never_post(self):
        for grant in ({},True,None,object.__new__(LegacyGrant)):
            with self.assertRaises(execution.GitLabExecutionV2Error):self.runner.execute(grant)
        grant=self.grant()
        self.h.deployment['approval_summary']['rules'][0]['deployment_approvals']=[]
        with self.assertRaises(execution.GitLabExecutionV2Error):self.runner.execute(grant)
        self.assertEqual(self.posts,[])
        self.assertEqual(self.h.ledger._read()['entries'],[])

    def test_source_or_tag_drift_before_dispatch_never_post(self):
        grant=self.grant();self.tag=self.row();self.tag['target']='0'*40
        with self.assertRaises(execution.GitLabExecutionV2Error):self.runner.execute(grant)
        self.assertEqual(self.posts,[])

    def test_release_wrong_request_and_fake_authority_rejected(self):
        for changes in (dict(authority={}),dict(preparer={}),dict(approved_request={}),dict(approved_request=object.__new__(LegacyRequest)),
                        dict(approved_request=replace(self.h.request,operation='remote-release-create'))):
            with self.assertRaises((ValueError,TypeError)):self.make(**changes)
        self.assertEqual(self.posts,[])

    def test_matching_approved_tag_verifies_without_post(self):
        self.tag=self.row()
        # Matching-tag context requires its own request and exact human bundle.
        self.h.request=self.h.preparer.prepare(self.h.fixture.intent,expires_at=self.h.expiry)['request']
        self.h.bundle=native.host.digest({'requestHash':self.h.request.digest(),'policy':native.asdict(self.h.policy),
            'ledgerRegistration':self.h.policy.ledger_root})
        self.h.deployment['approval_summary']['rules'][0]['deployment_approvals'][0]['comment']='dev-workflow approve '+self.h.bundle
        self.h.authority=self.h.make();self.runner=self.make()
        result=self.runner.execute(self.grant())
        self.assertFalse(result['postAttempted']);self.assertEqual(self.posts,[])
        self.assertEqual(len(self.h.ledger._read()['entries']),1)

    def test_missing_ledger_and_replacement_ledger_never_post(self):
        grant=self.grant()
        (Path(self.h.policy.ledger_root)/'state.json').unlink()
        with self.assertRaises(execution.GitLabExecutionV2Error):self.runner.execute(grant)
        self.assertEqual(self.posts,[])
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();root.chmod(0o700)
            replacement=native.host.GitLabReleaseLedgerV2(root,key=b'k'*32,host_id='host-one',policy_hash=self.h.policy.digest())
            self.addCleanup(replacement.close);replacement.initialize()
            with self.assertRaises(ValueError):self.h.make(ledger=replacement)

    def test_local_git_preparation_is_real_through_native_approval_and_post(self):
        from tests import test_release_execute as local
        helper=local.ReleaseExecuteTests();helper.setUp();self.addCleanup(helper.doCleanups)
        helper.git('remote','set-url','origin',self.h.fixture.identity.origin)
        identity=replace(self.h.fixture.identity,source_sha=helper.sha)
        self.h.fixture.identity=identity
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name).resolve();root.chmod(0o700)
        self.h.policy=replace(self.h.policy,identity=identity,ledger_root=str(root))
        self.h.ledger=native.host.GitLabReleaseLedgerV2(root,key=b'k'*32,host_id='host-one',policy_hash=self.h.policy.digest())
        self.addCleanup(self.h.ledger.close);self.h.ledger.initialize()
        self.h.fixture.intent=release_gitlab_plan.build_intent(helper.root,helper.preparation,remote='origin',project_id=42)
        preflight=GitLabPreflightHost(client=self.h.fixture.client,expected_identity=identity,repository=helper.root,remote='origin')
        self.h.preparer=GitLabRequestPreparationV2(preflight=preflight,expected_identity=identity,host_id='host-one',policy_hash=self.h.policy.digest())
        with patch.object(release_gitlab_preflight_host,'build_intent',release_gitlab_plan.build_intent):
            self.h.request=self.h.preparer.prepare(self.h.fixture.intent,expires_at=self.h.expiry)['request']
            self.h.c['sha']=helper.sha;self.h.deployment['sha']=helper.sha
            self.h.pipeline_detail['sha']=helper.sha
            self.h.deployment['deployable']['pipeline']['sha']=helper.sha
            self.h.bundle=native.host.digest({'requestHash':self.h.request.digest(),'policy':native.asdict(self.h.policy),
                'ledgerRegistration':self.h.policy.ledger_root})
            self.h.deployment['approval_summary']['rules'][0]['deployment_approvals'][0]['comment']='dev-workflow approve '+self.h.bundle
            self.h.authority=self.h.make();self.runner=self.make()
            result=self.runner.execute(self.grant())
        self.assertEqual(result['targetSha'],helper.sha)
        self.assertEqual(self.posts,[dict(tag_name='v1.2.3',ref=helper.sha)])

    def drift_after_consumption(self,field):
        original=self.h.fixture.client._transport;burn=self.h.ledger.burn;consumed=[]
        def burn_and_drift(**values):
            receipt=burn(**values);consumed.append(True);return receipt
        def transport(method,path,payload):
            result=original(method,path,payload)
            if consumed and method=='GET':
                if field=='project' and path=='/projects/42':return 200,{},dict(id=99,path_with_namespace='group/project')
                if field=='commit' and '/commits/' in path:return 200,{},dict(id='0'*40)
            return result
        grant=self.grant()
        with patch.object(self.h.ledger,'burn',side_effect=burn_and_drift),patch.object(self.h.fixture.client,'_transport',side_effect=transport):
            with self.assertRaises(execution.GitLabExecutionV2Error):self.runner.execute(grant)
        self.assertEqual(self.posts,[])
        self.assertEqual(len(self.h.ledger._read()['entries']),1)

    def test_project_drift_after_consumption_blocks_post(self):self.drift_after_consumption('project')
    def test_commit_drift_after_consumption_blocks_post(self):self.drift_after_consumption('commit')

    def test_provider_callback_rejects_equal_but_unowned_command(self):
        push=execution.GitLabTagProvider.push
        def copied(provider,command):return push(provider,replace(command))
        with patch.object(execution.GitLabTagProvider,'push',copied),self.assertRaises(execution.GitLabExecutionV2Error):
            self.runner.execute(self.grant())
        self.assertEqual(self.posts,[])
        self.assertEqual(len(self.h.ledger._read()['entries']),1)

    def test_http_rejection_keeps_request_burned(self):self.failed_post(failure='http')

    def test_lost_ledger_acknowledgement_never_dispatches_or_refunds(self):
        grant=self.grant();burn=self.h.ledger.burn
        def lost(**values):
            burn(**values)
            raise OSError('lost acknowledgement')
        with patch.object(self.h.ledger,'burn',side_effect=lost) as called:
            with self.assertRaises(execution.GitLabExecutionV2Error) as caught:self.runner.execute(grant)
            self.assertIsNone(caught.exception.consumed)
            self.assertFalse(caught.exception.post_attempted)
            self.assertEqual(called.call_count,1)
        with self.assertRaises(execution.GitLabExecutionV2Error):self.make().execute(grant)
        self.assertEqual(self.posts,[])
        self.assertEqual(len(self.h.ledger._read()['entries']),1)

    def test_final_callback_local_deadline_after_receipt_io_blocks_expired_post(self):
        import time
        from datetime import datetime,timedelta,timezone
        self.h.request=replace(self.h.request,expires_at=(datetime.now(timezone.utc)+timedelta(seconds=30)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.h.bundle=native.host.digest({'requestHash':self.h.request.digest(),'policy':native.asdict(self.h.policy),
            'ledgerRegistration':self.h.policy.ledger_root})
        self.h.deployment['approval_summary']['rules'][0]['deployment_approvals'][0]['comment']='dev-workflow approve '+self.h.bundle
        self.h.authority=self.h.make();self.runner=self.make();grant=self.grant()
        clock=[time.time()];calls=[];receipt_hash=self.h.authority.receipt_hash
        def delayed(receipt,request):
            value=receipt_hash(receipt,request);calls.append(1)
            if len(calls)==2:clock[0]+=60
            return value
        with patch.object(native.host.time,'time',side_effect=lambda:clock[0]),patch.object(self.h.authority,'receipt_hash',side_effect=delayed):
            with self.assertRaises(execution.GitLabExecutionV2Error):self.runner.execute(grant)
        self.assertEqual(len(calls),2)
        self.assertEqual(self.posts,[])
        self.assertEqual(len(self.h.ledger._read()['entries']),1)
