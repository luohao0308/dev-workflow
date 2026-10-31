"""Synthetic GitLab native API; real local Git/preflight/CAS ledger and RSA."""
import base64
from copy import copy,deepcopy
from dataclasses import asdict,replace
from datetime import datetime,timedelta,timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import release_gitlab_approval_v2_host as host
from tests import test_release_gitlab_prepare_v2_host as prepare_fixture


@unittest.skipUnless(os.name=='posix','POSIX independent ledger')
class NativeApprovalTests(unittest.TestCase):
    def setUp(self):
        self.fixture=prepare_fixture.GitLabPreparationTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name).resolve();root.chmod(0o700)
        self.expiry=(datetime.now(timezone.utc)+timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.policy=host.NativeApprovalPolicyV2(self.fixture.identity,'host-one','v1.2.3','main','staging',3,4,5,6,7,
            (host.UserRuleV2(8,9),),str(root),self.expiry)
        self.ledger=host.GitLabReleaseLedgerV2(root,key=b'k'*32,host_id='host-one',policy_hash=self.policy.digest())
        self.addCleanup(self.ledger.close);self.ledger.initialize()
        self.preparer=self.fixture.make(policy_hash=self.policy.digest())
        self.request=self.preparer.prepare(self.fixture.intent,expires_at=self.expiry)['request']
        self.bundle=host.digest({'requestHash':self.request.digest(),'policy':asdict(self.policy),'ledgerRegistration':str(root)})
        self.c=dict(iss=host.ISSUER,aud=host.AUDIENCE,sha=self.fixture.identity.source_sha,ref='main',ref_path='refs/heads/main',
            ref_type='branch',pipeline_source='push',environment='staging',environment_action='start',
            ref_protected='true',environment_protected='true',iat=int(time.time())-1,nbf=int(time.time())-1,exp=int(time.time())+300)
        self.c.update({k:str(v) for k,v in dict(project_id=42,job_project_id=42,source_project_id=42,job_id=4,pipeline_id=5,user_id=7).items()})
        rule=asdict(self.policy.rules[0]);self.protected=dict(name='staging',approval_rules=[rule])
        vote=dict(user=dict(id=9,state='active'),status='approved',created_at=datetime.now(timezone.utc).isoformat(),comment='dev-workflow approve '+self.bundle)
        self.deployment=dict(id=6,status='running',sha=self.fixture.identity.source_sha,ref='main',environment=dict(id=3,name='staging'),
            user=dict(id=7),deployable=dict(id=4,user=dict(id=7),pipeline=dict(id=5,sha=self.fixture.identity.source_sha,ref='main',user=dict(id=7))),
            approval_summary=dict(required_approval_count=0,rules=[dict(rule,deployment_approvals=[vote])]))
        self.pipeline_detail=dict(id=5,project_id=42,sha=self.fixture.identity.source_sha,ref='main',source='push',
            status='running',tag=False,user=dict(id=7,state='active'))
        transport=self.fixture.client._transport
        self.native_calls=[]
        def native(method,path,payload):
            if '/pipelines/' in path:
                self.native_calls.append((method,path));self.assertEqual(method,'GET')
                if self.pipeline_detail is None:return 404,{},None
                return 200,{},deepcopy(self.pipeline_detail)
            if '/deployments/' in path or '/protected_environments/' in path:
                self.native_calls.append((method,path));self.assertEqual(method,'GET')
                return 200,{},deepcopy(self.deployment if '/deployments/' in path else self.protected)
            return transport(method,path,payload)
        self.fixture.client._transport=native
        self.authority=self.make()

    def make(self,**changes):
        args=dict(token='test-token',policy=self.policy,preparer=self.preparer,intent=self.fixture.intent,
            request=self.request,ledger=self.ledger,verifier=lambda _:deepcopy(self.c))
        args.update(changes);return host.GitLabNativeApprovalV2(**args)

    def test_exact_native_review_consumes_once_and_live_guard(self):
        grant=self.authority.validate(self.request);receipt=self.authority.consume(grant,self.request)
        self.assertIs(type(receipt),host.NativeReceiptV2)
        self.assertEqual(len(self.authority.receipt_hash(receipt,self.request)),64)
        for fake in (copy(receipt),{},True):
            with self.assertRaises(ValueError):self.authority.receipt_hash(fake,self.request)
        self.assertTrue(self.authority.guard(self.request))
        with self.assertRaises(ValueError):self.authority.consume(grant,self.request)
        self.assertFalse(any(method!='GET' for method,path,payload in self.fixture.calls))
        self.assertEqual(len(self.ledger._read()['entries']),1)

    def test_copy_grant_authority_and_json_cannot_consume(self):
        grant=self.authority.validate(self.request)
        for fake in (copy(grant),{},True):
            with self.assertRaises(ValueError):self.authority.consume(fake,self.request)
        with self.assertRaises(ValueError):copy(self.authority).validate(self.request)
        with self.assertRaises(ValueError):self.authority.guard(self.request)

    def test_claims_canonical_types_and_exact_native_identity(self):
        for field,value in [('job_id',4),('project_id','042'),('ref_protected',True),('aud',[host.AUDIENCE]),('iat',True),('sha','0'*40),('pipeline_source','merge_request_event')]:
            c=deepcopy(self.c);c[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.make(verifier=lambda _:c)

    def test_native_unknown_reviewer_duplicate_and_summary_not_sufficient(self):
        original=deepcopy(self.deployment)
        for mutation in ('missing-rules','duplicate','wrong-comment','triggerer','bad-state','job'):
            self.deployment=deepcopy(original);rule=self.deployment['approval_summary']['rules'][0]
            if mutation=='missing-rules':self.deployment['approval_summary'].pop('rules')
            elif mutation=='duplicate':rule['deployment_approvals']*=2
            elif mutation=='wrong-comment':rule['deployment_approvals'][0]['comment']='approved'
            elif mutation=='triggerer':rule['deployment_approvals'][0]['user']['id']=7
            elif mutation=='bad-state':rule['deployment_approvals'][0]['user']['state']='blocked'
            else:self.deployment['deployable']['id']=False
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.make()

    def test_online_drift_expiry_and_ledger_loss_block(self):
        receipt=self.authority.consume(self.authority.validate(self.request),self.request)
        self.deployment['status']='success'
        with self.assertRaises(ValueError):self.authority.guard(self.request)
        self.deployment['status']='running';self.c['exp']=0
        with self.assertRaises(ValueError):self.authority.guard(self.request)
        self.c['exp']=int(time.time())+300
        (Path(self.policy.ledger_root)/'state.json').unlink()
        with self.assertRaises(ValueError):self.authority.guard(self.request)

    def test_native_cross_round_drift_is_rejected(self):
        transport=self.fixture.client._transport;count=[]
        def drift(method,path,payload):
            result=transport(method,path,payload)
            if '/deployments/' in path:
                count.append(1)
                if len(count)==2:result[2]['extra_observed_change']='drift'
            return result
        with patch.object(self.fixture.client,'_transport',side_effect=drift),self.assertRaises(ValueError):self.make()

    def test_host_policy_changes_cannot_reuse_review_or_grant(self):
        grant=self.authority.validate(self.request)
        self.authority.policy=replace(self.policy,trigger_user_id=10)
        with self.assertRaises(ValueError):self.authority.consume(grant,self.request)
        self.assertEqual(self.ledger._read()['entries'],[])

    def short_request(self,seconds):
        self.request=replace(self.request,expires_at=(datetime.now(timezone.utc)+timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.bundle=host.digest({'requestHash':self.request.digest(),'policy':asdict(self.policy),'ledgerRegistration':self.policy.ledger_root})
        self.deployment['approval_summary']['rules'][0]['deployment_approvals'][0]['comment']='dev-workflow approve '+self.bundle

    def test_final_verifier_clock_advance_cannot_outlive_request(self):
        self.short_request(30);clock=[time.time()];calls=[]
        def verifier(_):
            calls.append(1)
            if len(calls)==2:clock[0]+=60
            return deepcopy(self.c)
        with patch.object(host.time,'time',side_effect=lambda:clock[0]),self.assertRaises(ValueError):
            self.make(verifier=verifier)
        self.assertEqual(len(calls),2)
        self.assertEqual(self.ledger._read()['entries'],[])

    def test_real_short_request_expiring_during_final_verification_rejected(self):
        self.short_request(2);calls=[]
        def verifier(_):
            calls.append(1)
            if len(calls)==2:time.sleep(2.1)
            return deepcopy(self.c)
        with self.assertRaises(ValueError):self.make(verifier=verifier)
        self.assertEqual(len(calls),2)

    def test_candidate_checkout_cannot_own_ledger_root(self):
        from release_gitlab_preflight_host import GitLabPreflightHost
        from release_gitlab_prepare_v2_host import GitLabRequestPreparationV2
        preflight=GitLabPreflightHost(client=self.fixture.client,expected_identity=self.policy.identity,
            repository=Path(self.policy.ledger_root).parent,remote='origin')
        preparer=GitLabRequestPreparationV2(preflight=preflight,expected_identity=self.policy.identity,
            host_id=self.policy.host_id,policy_hash=self.policy.digest())
        with self.assertRaises(ValueError):self.make(preparer=preparer)

    def test_guard_honors_second_jwt_expiry_after_blocking_ledger_read(self):
        self.authority.consume(self.authority.validate(self.request),self.request)
        clock=[time.time()];calls=[];check=self.ledger.check
        def verifier(_):
            calls.append(1);claims=deepcopy(self.c)
            if len(calls)==2:claims['exp']=int(clock[0])+5
            return claims
        def delayed(**values):
            value=check(**values);clock[0]+=10;return value
        self.authority._verifier=verifier
        with patch.object(host.time,'time',side_effect=lambda:clock[0]),patch.object(self.ledger,'check',side_effect=delayed):
            with self.assertRaises(ValueError):self.authority.guard(self.request)
        self.assertEqual(len(calls),2)

    def test_manual_executor_cannot_hide_pipeline_creator_self_review(self):
        self.deployment['deployable']['pipeline'].pop('user')
        self.pipeline_detail['user']['id']=9  # Reviewer is pipeline creator; manual executor/JWT remains 7.
        with self.assertRaises(ValueError):self.make()
        self.assertEqual(self.ledger._read()['entries'],[])

    def test_missing_full_pipeline_user_and_invalid_pipeline_fields_rejected(self):
        original=deepcopy(self.pipeline_detail)
        invalid=[None,dict(original,user=None),dict(original,id=True),dict(original,project_id=True),
                 dict(original,sha='0'*40),dict(original,ref='other'),dict(original,source='web'),
                 dict(original,status='success'),dict(original,tag=0),dict(original,user=dict(id=7,state='blocked'))]
        missing=deepcopy(original);missing.pop('user');invalid.append(missing)
        for value in invalid:
            self.pipeline_detail=value
            with self.subTest(value=value),self.assertRaises(ValueError):self.make()

    def test_full_pipeline_creator_drift_rechecked_during_online_guard(self):
        self.authority.consume(self.authority.validate(self.request),self.request)
        self.deployment['deployable']['pipeline'].pop('user')
        self.pipeline_detail['user']['id']=9
        with self.assertRaises(ValueError):self.authority.guard(self.request)

    def test_full_pipeline_cross_round_observation_drift_rejected(self):
        transport=self.fixture.client._transport;calls=[]
        def drift(method,path,payload):
            result=transport(method,path,payload)
            if '/pipelines/' in path:
                calls.append(1)
                if len(calls)==2:result[2]['observed_revision']='changed'
            return result
        with patch.object(self.fixture.client,'_transport',side_effect=drift),self.assertRaises(ValueError):self.make()
        self.assertEqual(len(calls),2)

    def test_pipeline_basic_without_user_requires_matching_full_creator(self):
        self.deployment['deployable']['pipeline'].pop('user')
        self.native_calls.clear()
        authority=self.make()
        self.assertEqual(sum(path=='/projects/42/pipelines/5' for _,path in self.native_calls),2)
        self.assertIs(type(authority),host.GitLabNativeApprovalV2)


@unittest.skipUnless(os.name=='posix' and Path('/usr/bin/openssl').is_file(),'fixed POSIX OpenSSL verifier')
class RSAVerificationTests(unittest.TestCase):
    def test_fixed_gitlab_jwks_real_signature_and_unsafe_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'key'
            subprocess.run(['/usr/bin/openssl','genrsa','-out',str(key),'2048'],check=True,capture_output=True)
            modulus=subprocess.run(['/usr/bin/openssl','rsa','-in',str(key),'-modulus','-noout'],check=True,capture_output=True).stdout.strip().split(b'=')[1]
            def b64(raw):return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()
            jwk=dict(kid='fixed',kty='RSA',alg='RS256',n=b64(bytes.fromhex(modulus.decode())),e=b64(b'\x01\x00\x01'))
            claims={'iss':host.ISSUER,'aud':host.AUDIENCE}
            def token(header,claims=claims):
                material=b64(host.encoded(header))+'.'+b64(host.encoded(claims))
                sig=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-sign',str(key)],input=material.encode(),check=True,capture_output=True).stdout
                return material+'.'+b64(sig)
            header=dict(alg='RS256',kid='fixed')
            class Opener:
                def open(self,url,timeout):
                    if url!=host.JWKS:raise AssertionError('unfixed JWKS')
                    return io.BytesIO(host.encoded({'keys':[jwk]}))
            with patch.object(host.urllib.request,'build_opener',return_value=Opener()):
                valid=token(header);self.assertEqual(host.verify_oidc(valid),claims)
                for bad in (token(dict(header,jku='https://evil/keys')),token(dict(header,kid='wrong')),
                            token(header,dict(claims,iss='https://github.com')),valid[:-4]+'AAAA'):
                    with self.assertRaises(ValueError):host.verify_oidc(bad)
