from copy import deepcopy
from dataclasses import replace
from datetime import datetime,timedelta,timezone
from pathlib import Path
import sys
import unittest
import base64,json,subprocess,tempfile
from unittest import mock
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import deployment_compose_production_frontend_approval_v1_host as host
import release_host as release
from release_execute import AuthorizationUnavailable
from tests.test_release_host import Client,claims,policy as base_policy
from tests.test_deployment_compose_production_frontend_v3_host import material
import deployment_compose_production_frontend_v3_host as adapter


def fixture():
    row,image,args=material();review=adapter.prepare_frontend_plan(row,image,**args)['publicReview']
    deadline=(datetime.now(timezone.utc)+timedelta(minutes=20)).strftime('%Y-%m-%dT%H:%M:%SZ')
    req=host.prepare_production_frontend_request(review,policy_hash='f'*64,expires_at=deadline)
    fields=dict(vars(base_policy()),host_repository=host.RUNTIME,host_repository_id=1327491026,
        target_repository=host.BLOG,target_repository_id=1395689651,ledger_repository=host.LEDGER,ledger_repository_id=1436718662,
        workflow_ref=host.RUNTIME+'/.github/workflows/production-frontend-review.yml@refs/heads/main',workflow_sha='b'*40,
        environment='production-frontend-review',source_sha=req.source.source_sha,host_id=req.host_id,daemon_id=req.daemon_id,
        current_image_id='sha256:'+req.artifact_digest,snapshot_hash=req.observation_hash,body_hash=req.after_hash,
        plan_hash=req.plan_hash,protected_inventory_hash=host._digest(list(req.protected_components)),request_hash=req.digest(),policy_hash=req.policy_hash)
    return req,host.ProductionFrontendApprovalPolicyV1(**fields),review


def approved(policy,req):
    client=Client(policy,[req]);data={}
    for key,value in client.data.items():
        key=key.replace('sample/host',host.RUNTIME).replace('sample/target',host.BLOG).replace('/environments/release','/environments/'+policy.environment).replace('/runs/123','/runs/'+str(policy.run_id))
        if key=='/repos/sample/ledger':
            data['/repos/'+host.LEDGER]={'id':1436718662,'full_name':host.LEDGER};continue
        if key=='/repos/'+host.RUNTIME:value=dict(value,id=1327491026,full_name=host.RUNTIME)
        elif key=='/repos/'+host.BLOG:value=dict(value,id=1395689651,full_name=host.BLOG)
        elif '/actions/runs/' in key and not key.endswith('approvals'):
            value=dict(value,id=policy.run_id,head_sha=policy.workflow_sha,repository={'id':1327491026})
        elif '/environments/' in key:value=dict(value,name=policy.environment)
        elif key.endswith('/approvals'):value[0]['environments'][0]['name']=policy.environment
        data[key]=value
    client.data=data
    token=dict(claims(policy),aud=host.AUDIENCE)
    approval=host.GitHubProductionFrontendApprovalV1(client,'signed',[req],policy,verifier=lambda _:deepcopy(token))
    return approval,client,token


class ProductionApprovalTests(unittest.TestCase):
    def test_production_consent_consumed_once_without_runtime_authority(self):
        req,p,review=fixture();approval,client,_=approved(p,req)
        grant=approval.validate(req);receipt=approval.consume(grant,req)
        self.assertIs(type(receipt),host.ProductionFrontendReceiptV1)
        approval.check_consumed_intent(req)
        self.assertEqual(list(client.markers),['tags/'+approval.ledger_namespace+'/'+req.digest()])
        with self.assertRaises(AuthorizationUnavailable):approval.guard(req)
        with self.assertRaises(AuthorizationUnavailable):approval.consume(grant,req)
        frozen=req.digest();review['identity']['sourceSha']='c'*40;self.assertEqual(req.digest(),frozen)

    def test_new_approved_run_cannot_reconsume_request(self):
        req,p,_=fixture();first,c,_=approved(p,req);first.consume(first.validate(req),req)
        second,d,_=approved(replace(p,run_id=456),req);d.markers=c.markers
        with self.assertRaises(AuthorizationUnavailable):second.consume(second.validate(req),req)

    def test_wrong_scope_refused_before_network(self):
        req,p,_=fixture()
        for field,value in (('production',False),('operation','rollback'),('operation','recovery'),('host_id','other'),
                            ('daemon_id','other'),('plan_hash','0'*64),('observation_hash','0'*64),('after_hash','0'*64),
                            ('source',replace(req.source,source_sha=p.workflow_sha)),('expires_at','2000-01-01T00:00:00Z')):
            with self.subTest(field=field),self.assertRaises(AuthorizationUnavailable):
                host.GitHubProductionFrontendApprovalV1(Mock(),'signed',[replace(req,**dict({field:value},**({'history_hash':'1'*64} if field=='operation' else {})))],p,verifier=lambda _: {})
        for changes in ({'target_repository_id':2},{'host_repository':'sample/host'},{'production':False},{'operation':'recovery'}):
            with self.subTest(changes=changes),self.assertRaises(AuthorizationUnavailable):replace(p,**changes)

    def test_oidc_runtime_sha_and_review_identity_are_live_checked(self):
        req,p,_=fixture();approval,client,token=approved(p,req)
        token['workflow_sha']=p.source_sha
        with self.assertRaises(AuthorizationUnavailable):approval.validate(req)
        token['workflow_sha']=p.workflow_sha
        path='/repos/'+host.RUNTIME+'/actions/runs/'+str(p.run_id)+'/approvals'
        client.data[path][0]['user']['id']=999
        with self.assertRaises(AuthorizationUnavailable):approval.validate(req)

    def test_factory_closed_review_and_exact_image_pins(self):
        _,_,review=fixture()
        for change in ('extra','identity-extra','image','selected-protected','expiry','false-name','other-name','blocked-null','blocked-duplicate','blocked-long','host-bool','daemon-long'):
            bad=deepcopy(review)
            if change=='extra':bad['unexpected']=True
            elif change=='identity-extra':bad['identity']['unexpected']=True
            elif change=='image':bad['identity']['imageId']='a'*64
            elif change=='selected-protected':bad['protectedContainerIds']=[bad['identity']['containerId']]
            elif change=='false-name':bad['identity']['containerName']=False
            elif change=='other-name':bad['identity']['containerName']='other-frontend'
            elif change=='blocked-null':bad['executionBlockedReasons']=None
            elif change=='blocked-duplicate':bad['executionBlockedReasons']=['pending','pending']
            elif change=='blocked-long':bad['executionBlockedReasons']=['x'*129]
            elif change=='host-bool':bad['identity']['hostId']=True
            elif change=='daemon-long':bad['identity']['daemonId']='x'*257
            expiry='2000-01-01T00:00:00Z' if change=='expiry' else (datetime.now(timezone.utc)+timedelta(minutes=20)).strftime('%Y-%m-%dT%H:%M:%SZ')
            with self.subTest(change=change),self.assertRaises(AuthorizationUnavailable):
                host.prepare_production_frontend_request(bad,policy_hash='f'*64,expires_at=expiry)

    def test_rollback_json_and_recovery_cannot_issue_request(self):
        _,_,review=fixture()
        for operation in ('rollback','recovery'):
            with self.subTest(operation=operation),self.assertRaises(AuthorizationUnavailable):
                host.prepare_production_frontend_request(review,operation=operation,policy_hash='f'*64,expires_at='2030-01-01T00:00:00Z')


class ProductionSignatureTests(unittest.TestCase):
    @unittest.skipUnless(Path('/usr/bin/openssl').is_file(),'OpenSSL required')
    def test_real_signed_oidc_consumes_exact_production_consent(self):
        req,p,_=fixture();_,client,token_claims=approved(p,req)
        encode=lambda raw:base64.urlsafe_b64encode(raw).decode().rstrip('=')
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'key.pem'
            subprocess.run(['/usr/bin/openssl','genrsa','-out',str(key),'2048'],capture_output=True,check=True)
            modulus=subprocess.run(['/usr/bin/openssl','rsa','-in',str(key),'-modulus','-noout'],capture_output=True,text=True,check=True).stdout.strip().split('=')[1]
            header=encode(json.dumps({'alg':'RS256','kid':'production-test'}).encode())
            body=encode(json.dumps(token_claims).encode());signed=(header+'.'+body).encode()
            signature=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-sign',str(key)],input=signed,capture_output=True,check=True).stdout
            token=header+'.'+body+'.'+encode(signature)
            keys=json.dumps({'keys':[{'kty':'RSA','kid':'production-test','n':encode(bytes.fromhex(modulus)),'e':encode(b'\x01\x00\x01')}]}).encode()
            response=mock.MagicMock();response.__enter__.return_value.read.return_value=keys
            opener=mock.Mock();opener.open.return_value=response
            with mock.patch.object(release.urllib.request,'build_opener',return_value=opener):
                approval=host.GitHubProductionFrontendApprovalV1(client,token,[req],p)
                self.assertEqual(approval.consume(approval.validate(req),req).request_hash,req.digest())
                with self.assertRaises(AuthorizationUnavailable):
                    host.GitHubProductionFrontendApprovalV1(client,header+'.'+body+'.'+encode(bytes(len(signature))),[req],p)
