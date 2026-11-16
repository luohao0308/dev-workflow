from copy import deepcopy
from dataclasses import asdict
from datetime import datetime,timedelta,timezone
from pathlib import Path
import os,sys,unittest,tempfile
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

    def test_release_plan_cli_keeps_stage_review_and_sealing_closed(self):
        from deployment_compose_retained_release_plan_v1_host import release_plan_digest

        create=retained_review(self.review,'deploy')
        create['retainedCutover'].update(stage='create',protectionMode=contract.host.STAGED_PROTECTION_MODE)
        private=dict(createReview=create,policyHash=self.req.policy_hash,runtimeSha=self.policy.workflow_sha,
                     expiresAt=self.req.expires_at)
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'release.json'
            with (patch.object(sys,'argv',['contract','release-prepare','--bundle',str(output)]),
                  patch.dict(os.environ,{'PUBLIC_PAYLOAD':contract.canonical(private)})):
                self.assertEqual(contract.main(),0)
            raw=output.read_text()
            release=contract.common._parse(raw,32768)
            digest=release_plan_digest(release)
            with patch.object(sys,'argv',['contract','release-verify','--bundle',str(output),'--reviewed-digest',
                                          digest,'--runtime-sha',self.policy.workflow_sha]):
                self.assertEqual(contract.main(),0)
            with patch.object(contract.common,'fetch_token') as mint,self.assertRaises(ValueError):
                contract.seal(raw,self.env,'recipient',Path(directory)/'sealed')
            mint.assert_not_called()

    def test_staged_reviews_bind_their_predecessors_and_independent_expiries(self):
        host=contract.host
        now=datetime.now(timezone.utc).replace(microsecond=0)
        create=retained_review(self.review,'deploy')
        create['retainedCutover']['stage']='create'
        create['retainedCutover']['protectionMode']=host.STAGED_PROTECTION_MODE

        def prepare(review,operation,seconds):
            request=host.prepare_production_frontend_request(review,operation=operation,policy_hash=self.req.policy_hash,
                expires_at=contract.common.stamp(now+timedelta(seconds=seconds)))
            data=dict(request=asdict(request),review=review)
            artifact=contract.prepare(contract.canonical(data),self.env,now)
            return request,contract.canonical(artifact),artifact['bundleHash']

        creation,create_raw,create_bundle=prepare(create,'deploy',120)
        switch=deepcopy(create)
        switch['retainedCutover'].update(stage='switch',candidateId='3'*64,creationRequestHash=creation.digest(),
            creationWitnessDigest='4'*64,observationDigest='5'*64,scopeGeneration=10)
        cutover,switch_raw,switch_bundle=prepare(switch,'deploy',30)
        rollback=deepcopy(switch)
        rollback['retainedCutover'].update(stage='rollback',parentRequestHash=cutover.digest(),switchWitnessDigest='6'*64,
            switchPrefix=3,candidateRunning=False,observationDigest='7'*64)
        restore,restore_raw,restore_bundle=prepare(rollback,'rollback',240)

        for stage,req,review,raw in (('create',creation,create,create_raw),('switch',cutover,switch,switch_raw),
                                    ('rollback',restore,rollback,restore_raw)):
            verified,policy,_=contract.verify_prepared_review(raw,self.env,req,review,now)
            self.assertEqual(verified.profile_version,'3')
            self.assertIs(type(policy),host.ProductionFrontendApprovalPolicyV3)
            self.assertEqual(policy.stage,stage)
            self.assertIn(f'Stage: `{stage}`',contract.summary(raw,self.env))
            self.assertIn(f'Protection mode: `{host.STAGED_PROTECTION_MODE}`',contract.summary(raw,self.env))
        self.assertEqual(len({create_bundle,switch_bundle,restore_bundle}),3)
        self.assertEqual(cutover.plan_hash,host._digest(switch))
        self.assertEqual(restore.history_hash,cutover.digest())
        with self.assertRaises(ValueError):
            contract.verify_prepared_review(create_raw,self.env,cutover,switch,now)
        for key,value in (('candidateId','8'*64),('creationWitnessDigest','9'*64),
                          ('scopeGeneration',11),('observationDigest','a'*64),('creationRequestHash','b'*64)):
            tampered=deepcopy(switch)
            tampered['retainedCutover'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                contract.verify_prepared_review(switch_raw,self.env,cutover,tampered,now)
        after_expiry=now+timedelta(seconds=31)
        with self.assertRaises(ValueError):
            contract.verify(switch_raw,self.env,after_expiry)
        self.assertEqual(contract.verify(restore_raw,self.env,after_expiry)[0],restore)

    def test_staged_review_rejects_invalid_scope_shapes(self):
        host=contract.host
        switch=retained_review(self.review,'deploy')
        switch['retainedCutover'].update(stage='switch',candidateId='3'*64,creationRequestHash='4'*64,
            creationWitnessDigest='5'*64,observationDigest='6'*64,scopeGeneration=10)
        for patch_values in (dict(stage='rollback'),dict(stage='create'),dict(stage=[]),
                             dict(scopeGeneration=True),dict(scopeGeneration=0),dict(scopeGeneration=2**53),
                             dict(protectionMode='ignore-network'),
                             dict(candidateId=self.review['identity']['containerId']),dict(switchPrefix=0)):
            invalid=deepcopy(switch)
            invalid['retainedCutover'].update(patch_values)
            with self.subTest(patch_values=patch_values),self.assertRaises(ValueError):
                host.prepare_production_frontend_request(invalid,policy_hash=self.req.policy_hash,expires_at=self.req.expires_at)

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
