"""Public workflow scope plus mandatory private-host review verification."""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, MagicMock, patch

from tests.test_deployment_compose_bundle_v3 import fixture, bind_baseline
from tests.test_deployment_compose_approval_v3_host import request
from tests.test_deployment_compose_github_review_contract import environment
from deployment_contract_v2 import SourceIdentity, TargetIdentity
from deployment_compose_bundle_v3 import ExecutionBundleV3
import deployment_compose_full_body_review_contract as contract
from release_host import bundle_digest


class FullBodyReviewTests(unittest.TestCase):
    def setUp(self):
        self.env=environment()
        self.env.update(GITHUB_WORKFLOW_REF=contract.REPOSITORY+'/'+contract.WORKFLOW+'@'+contract.REF,
                        GITHUB_WORKFLOW_SHA=self.env['GITHUB_SHA'])
        self.now=datetime.now(timezone.utc).replace(microsecond=0)
        source=SourceIdentity('github.com','https://github.com/'+contract.REPOSITORY+'.git',
                              contract.REPOSITORY_ID,contract.REPOSITORY,self.env['GITHUB_SHA'])
        value,defaults=fixture()
        value['identity']=dict(hostId='host-one',daemonId='daemon-1',project='dw-review',
                               sourceIdentity=contract.canonical(asdict(source)))
        for service in value['services']:
            for field in ('baselineCreateBody','targetCreateBody'):
                service[field]['Labels']['com.docker.compose.project']='dw-review'
        bind_baseline(value)
        self.bundle=ExecutionBundleV3(value,authenticated_image_defaults=defaults)
        self.request=request(source=source,target=TargetIdentity('compose','dw-review','stack'),
            components=('web',),protected_components=('db',),plan_hash=self.bundle.digest,
            expires_at=(self.now+timedelta(minutes=20)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.payload=dict(request=asdict(self.request),review=self.bundle.public_review())
        self.artifact=contract.prepare(contract.canonical(self.payload),self.env,self.now)

    def verify(self,value=None):
        return contract.verify(contract.canonical(self.artifact if value is None else value),self.env,self.now)

    def test_canonical_policy_and_real_approval_comment_digest(self):
        req,policy,digest=self.verify()
        self.assertEqual(req,self.request)
        self.assertEqual(policy.bundle_hash,self.bundle.digest)
        self.assertEqual(digest,bundle_digest([req],policy.expires_at,policy.bundle_context()))
        self.assertEqual(policy.workflow_ref,self.env['GITHUB_WORKFLOW_REF'])
        self.assertTrue(policy.prevent_self_review)
        contract.verify_prepared_review(contract.canonical(self.artifact),self.env,self.bundle,self.request,self.now)
        summary=contract.summary(contract.canonical(self.artifact),self.env)
        self.assertIn('dev-workflow approve '+digest,summary)
        self.assertIn(self.request.host_id,summary)
        self.assertIn(self.request.expires_at,summary)
        self.assertIn('Approving grants intent consent',summary)
        self.assertIn('create=1',summary)
        self.assertIn('readiness:web',summary)
        self.assertIn(self.bundle.to_dict()['services'][0]['targetImageId'],summary)
        self.assertNotIn('Env',contract.canonical(self.artifact))
        self.assertNotIn('HostConfig',contract.canonical(self.artifact))

    def test_rehashed_public_review_tampering_rejected_by_private_host(self):
        for mutation in ('body','protected','host','request'):
            payload=deepcopy(self.payload)
            if mutation=='body':payload['review']['services'][0]['targetBodyDigest']='0'*64
            elif mutation=='protected':payload['review']['protectedContainers'][0]['staticConfigDigest']='0'*64
            elif mutation=='host':
                payload['request']['host_id']='substituted'
                payload['review']['identity']['hostId']='substituted'
            else:payload['request']['after_hash']='0'*64
            # Public data has no private-bundle authentication. Even recomputed
            # self hashes must pass the explicit host comparison before consent.
            artifact=contract.prepare(contract.canonical(payload),self.env,self.now)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                contract.verify_prepared_review(contract.canonical(artifact),self.env,self.bundle,self.request,self.now)

    def test_private_fields_unknown_shapes_and_rehashed_artifact_rejected(self):
        for mutation in ('Env','HostConfig','operations','protected-count','identity'):
            payload=deepcopy(self.payload)
            if mutation in ('Env','HostConfig'):payload['review']['services'][0][mutation]=['secret']
            elif mutation=='operations':payload['review']['operations'][0]['body']={'secret':'value'}
            elif mutation=='protected-count':payload['review']['protectedContainers']=[]
            else:payload['review']['identity']['raw']='secret'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                contract.prepare(contract.canonical(payload),self.env,self.now)
        value=deepcopy(self.artifact);value['policy']['daemon_id']='substituted'
        value['policyHash']=contract.digest(value['policy'])
        with self.assertRaises(ValueError):self.verify(value)

    def test_wrong_profile_source_scope_environment_history_and_expiry(self):
        mutations=[('profile_version','1'),('production',True),('environment','production'),
            ('history_hash','c'*64),('max_uses',True),('expires_at','2020-01-01T00:00:00Z'),
            ('expires_at','2099-01-01T00:00:00Z')]
        for field,bad in mutations:
            payload=deepcopy(self.payload);payload['request'][field]=bad
            with self.subTest(field=field,bad=bad),self.assertRaises(Exception):
                contract.prepare(contract.canonical(payload),self.env,self.now)
        for field,bad in [('runtime','ssh'),('namespace','production')]:
            payload=deepcopy(self.payload);payload['request']['target'][field]=bad
            with self.assertRaises(ValueError):contract.prepare(contract.canonical(payload),self.env,self.now)
        for field,bad in [('project_id',2),('source_sha','b'*40),('project_path','other/repository')]:
            payload=deepcopy(self.payload);payload['request']['source'][field]=bad
            with self.assertRaises(ValueError):contract.prepare(contract.canonical(payload),self.env,self.now)
        for operation in ('rollback','recovery'):
            payload=deepcopy(self.payload);payload['request']['operation']=operation
            with self.assertRaises(ValueError):contract.prepare(contract.canonical(payload),self.env,self.now)
            payload['request']['history_hash']='c'*64
            artifact=contract.prepare(contract.canonical(payload),self.env,self.now)
            _,policy,_=self.verify(artifact)
            self.assertEqual(policy.expected_history_hash,'c'*64)

    def test_runner_identity_canonical_size_duplicate_and_expiry_guards(self):
        for field,bad in [('GITHUB_RUN_ATTEMPT','2'),('GITHUB_REPOSITORY_ID','2'),('GITHUB_EVENT_NAME','push'),
            ('GITHUB_REF','refs/heads/main'),('GITHUB_WORKFLOW_SHA','b'*40),('GITHUB_WORKFLOW_REF','other')]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                contract.prepare(contract.canonical(self.payload),dict(self.env,**{field:bad}),self.now)
        for raw in (json.dumps(self.payload),' '*32769,'{"request":{},'+contract.canonical(self.payload)[1:]):
            with self.assertRaises(ValueError):contract.prepare(raw,self.env,self.now)
        for now in (self.now-timedelta(seconds=1),self.now+timedelta(minutes=21)):
            with self.assertRaises(ValueError):contract.verify(contract.canonical(self.artifact),self.env,now)

    def test_oidc_fetch_uses_only_v3_audience_and_no_proxy(self):
        response=MagicMock();response.__enter__.return_value.read.return_value=b'{"value":"header.payload.signature"}'
        opener=Mock();opener.open.return_value=response
        env=dict(self.env,ACTIONS_ID_TOKEN_REQUEST_URL='https://foo.actions.githubusercontent.com/id?x=1',
                 ACTIONS_ID_TOKEN_REQUEST_TOKEN='private-bearer')
        with patch.object(contract.urllib.request,'build_opener',return_value=opener) as build:
            self.assertEqual(contract.fetch_token(env),b'header.payload.signature')
        self.assertEqual(build.call_args.args[0].proxies,{})
        self.assertIn('audience=dev-workflow-compose-full-body-v3-host',opener.open.call_args.args[0].full_url)
        for url in ('http://foo.actions.githubusercontent.com/id','https://evil.test/id',
                    'https://foo.actions.githubusercontent.com/id?audience=other'):
            with self.assertRaises(ValueError):contract.fetch_token(dict(env,ACTIONS_ID_TOKEN_REQUEST_URL=url))

    def test_cms_seal_uses_memory_pipe_and_writes_only_ciphertext(self):
        token=b'private.header.payload'
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'oidc.cms.der';stdout=io.StringIO()
            result=Mock(returncode=0,stdout=b'CMS-ciphertext')
            with patch.object(contract,'fetch_token',return_value=token),patch.object(contract.subprocess,'run',return_value=result) as run,patch('sys.stdout',stdout):
                contract.seal(contract.canonical(self.artifact),self.env,Path(directory)/'recipient.pem',output)
            self.assertEqual(run.call_args.kwargs['input'],token)
            self.assertEqual(run.call_args.kwargs['env'],{'PATH':'/usr/bin:/bin'})
            self.assertNotIn(token.decode(),repr(run.call_args.args))
            self.assertNotIn(token.decode(),stdout.getvalue())
            self.assertEqual(output.read_bytes(),b'CMS-ciphertext')
            if os.name!='nt':self.assertEqual(output.stat().st_mode&0o777,0o600)
            self.assertEqual([p.name for p in Path(directory).iterdir()],['oidc.cms.der'])

    def test_sealing_errors_never_write_or_log_plaintext(self):
        token=b'private.header.payload'
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'oidc.cms.der'
            with patch.object(contract,'fetch_token',return_value=token),patch.object(contract.subprocess,'run',
                return_value=Mock(returncode=1,stdout=token,stderr=token)),self.assertRaises(ValueError):
                contract.seal(contract.canonical(self.artifact),self.env,Path(directory)/'recipient.pem',output)
            self.assertFalse(output.exists())
        with patch.object(contract.sys,'argv',['contract','seal','--bundle','missing']),patch('sys.stderr',new_callable=io.StringIO) as stderr:
            self.assertEqual(contract.main(),1)
        self.assertEqual(stderr.getvalue(),'Full-body review contract failed closed\n')

    def test_workflow_is_fixed_bot_launch_and_sealed_public_only(self):
        text=(Path(__file__).resolve().parents[1]/contract.WORKFLOW).read_text()
        for value in ('options: [launch, review]','inputs: {mode: \'review\', public_payload: process.env.PUBLIC_PAYLOAD}',
            'github.run_attempt == 1','environment: compose-review','id-token: write',
            'artifact-ids:','PUBLIC_PAYLOAD: ${{ inputs.public_payload }}','run: sleep 300',
            'deployment_compose_full_body_review_contract.py seal','retention-days: 1'):
            self.assertIn(value,text)
        for use in re.findall(r'uses: ([^\s]+)',text):self.assertRegex(use,r'@[0-9a-f]{40}$')
        self.assertNotIn('deployment_compose_github_review_contract.py',text)
        self.assertNotIn('id-token.jwt',text)
        self.assertNotIn('docker ',text)
        self.assertNotIn('ssh ',text)


if __name__=='__main__':unittest.main()
