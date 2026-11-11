from copy import deepcopy
from dataclasses import asdict
from datetime import datetime,timedelta,timezone
from pathlib import Path
import sys,unittest,tempfile
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import deployment_compose_production_frontend_review_contract as contract
from tests.test_deployment_compose_production_frontend_approval_v1_host import fixture,retained_review

class ProductionReviewTests(unittest.TestCase):
    def setUp(self):
        self.req,self.policy,self.review=fixture()
        self.env=dict(GITHUB_REPOSITORY=contract.host.RUNTIME,GITHUB_REPOSITORY_ID='1327491026',GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_WORKFLOW_REF=contract.host.WORKFLOW,GITHUB_SHA=self.policy.workflow_sha,GITHUB_WORKFLOW_SHA=self.policy.workflow_sha,GITHUB_RUN_ID='123',DW_AUTH_REVIEWER_ID='42',DW_AUTH_LEDGER_REPOSITORY=contract.host.LEDGER,DW_AUTH_LEDGER_ID='1436718662',DW_AUTH_LEDGER_SHA=self.policy.ledger_sha,DW_PROD_FRONTEND_POLICY_HASH=self.req.policy_hash)
        self.payload=dict(request=asdict(self.req),review=self.review)
    def prepared(self):return contract.canonical(contract.prepare(contract.canonical(self.payload),self.env))
    def test_retained_rollback_artifact_binds_and_displays_scope(self):
        review=retained_review(self.review,'rollback')
        req=contract.host.prepare_production_frontend_request(
            review,operation='rollback',policy_hash=self.req.policy_hash,expires_at=self.req.expires_at)
        self.payload=dict(request=asdict(req),review=review)
        raw=self.prepared()
        _,policy,_=contract.verify_prepared_review(raw,self.env,req,review)
        self.assertIs(type(policy),contract.host.ProductionFrontendApprovalPolicyV2)
        self.assertEqual(policy.observation_hash,req.observation_hash)
        self.assertEqual(policy.snapshot_hash,req.before_hash)
        summary=contract.summary(raw,self.env)
        for value in ('Operation: `rollback`','Switch prefix: `4`','Candidate running: `true`',
                      req.history_hash,req.observation_hash,review['retainedCutover']['candidateId'],
                      'Runtime archive digest: `'+review['retainedCutover']['runtimeArchiveDigest']+'`'):
            self.assertIn(value,summary)
        review['retainedCutover']['switchPrefix']=3
        review['retainedCutover']['candidateRunning']=False
        with self.assertRaises(Exception):self.prepared()
    def test_roundtrip_private_binding_summary_and_separate_shas(self):
        raw=self.prepared();req,policy,digest=contract.verify_prepared_review(raw,self.env,self.req,self.review)
        self.assertEqual(req,self.req);self.assertEqual(policy.source_sha,self.req.source.source_sha)
        self.assertEqual(policy.workflow_sha,self.env['GITHUB_SHA'])
        summary=contract.summary(raw,self.env)
        for value in ('PRODUCTION','production=true',digest,self.req.host_id,self.req.daemon_id,self.req.source.source_sha):self.assertIn(value,summary)
        self.assertNotIn('Env',summary)
        with self.assertRaises(ValueError):contract.verify_prepared_review(raw,self.env,self.req,dict(self.review,extra=True))
    def test_scope_and_registered_hash_drift_rejected(self):
        for key,value in [('GITHUB_REF','refs/heads/other'),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_WORKFLOW_SHA','0'*40),('DW_PROD_FRONTEND_POLICY_HASH','0'*64),('DW_AUTH_LEDGER_ID','1')]:
            with self.subTest(key=key),self.assertRaises(Exception):contract.prepare(contract.canonical(self.payload),dict(self.env,**{key:value}))
        for key,value in [('production',False),('operation','recovery'),('host_id','other')]:
            p=deepcopy(self.payload);p['request'][key]=value
            with self.subTest(key=key),self.assertRaises(Exception):contract.prepare(contract.canonical(p),self.env)
        p=deepcopy(self.payload);p['review']['identity']['sourceSha']=self.policy.workflow_sha
        with self.assertRaises(Exception):contract.prepare(contract.canonical(p),self.env)
    def test_closed_json_artifact_and_expiry(self):
        with self.assertRaises(ValueError):contract.prepare(contract.canonical(dict(self.payload,policy={})),self.env)
        with self.assertRaises(ValueError):contract.prepare('{"request":{},"request":{}}',self.env)
        raw=self.prepared();v=contract.common._parse(raw,65536);v['review']['identity']['hostId']='x;$(bad)'
        with self.assertRaises(Exception):contract.verify(contract.canonical(v),self.env)
        with self.assertRaises(Exception):contract.verify(raw,self.env,datetime.now(timezone.utc)+timedelta(hours=1))
    def test_seal_rechecks_after_token_and_encryption(self):
        raw=self.prepared()
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'sealed'
            with patch.object(contract.common,'fetch_token',return_value=b'a.b.c') as fetch,patch.object(contract.common,'encrypt_token',side_effect=lambda t,r,o:Path(o).write_bytes(b'encrypted')):
                contract.seal(raw,self.env,'public-cert',output)
                fetch.assert_called_once_with(self.env,audience=contract.host.AUDIENCE)
                self.assertEqual(output.read_bytes(),b'encrypted')
            output.unlink()
            with patch.object(contract,'verify',side_effect=[None,None,ValueError('expired')]),patch.object(contract.common,'fetch_token',return_value=b'a.b.c'),patch.object(contract.common,'encrypt_token',side_effect=lambda t,r,o:Path(o).write_bytes(b'encrypted')):
                with self.assertRaises(ValueError):contract.seal(raw,self.env,'public-cert',output)
                self.assertFalse(output.exists())
    def test_seal_never_replaces_existing_file_or_symlink(self):
        raw=self.prepared()
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'sealed';output.write_bytes(b'sentinel')
            with patch.object(contract.common,'fetch_token') as fetch:
                with self.assertRaises(FileExistsError):contract.seal(raw,self.env,'public-cert',output)
                fetch.assert_not_called()
            self.assertEqual(output.read_bytes(),b'sentinel')
            output.unlink();target=Path(directory)/'other';target.write_bytes(b'other')
            try:output.symlink_to(target)
            except OSError: return  # Windows may not grant symlink privilege.
            with self.assertRaises(FileExistsError):contract.seal(raw,self.env,'public-cert',output)
            self.assertEqual(target.read_bytes(),b'other')

    def test_encryption_failure_cleans_only_own_temporary(self):
        raw=self.prepared()
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'sealed'
            def fail(token,recipient,temporary):
                Path(temporary).write_bytes(b'partial')
                output.write_bytes(b'concurrent-sentinel')
                raise ValueError('encryption failed')
            with patch.object(contract.common,'fetch_token',return_value=b'a.b.c'),patch.object(contract.common,'encrypt_token',side_effect=fail):
                with self.assertRaises(ValueError):contract.seal(raw,self.env,'public-cert',output)
            self.assertEqual(output.read_bytes(),b'concurrent-sentinel')
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()),['sealed'])

    def test_workflow_pins_and_shared_audience_allowlist(self):
        text=(Path(__file__).resolve().parents[1]/'.github/workflows/production-frontend-review.yml').read_text()
        for value in ('environment: compose-review','refs/heads/main','DW_PROD_FRONTEND_POLICY_HASH','production-frontend-sealed-oidc','persist-credentials: false'):self.assertIn(value,text)
        with self.assertRaises(ValueError):contract.common.fetch_token({},audience='arbitrary')
