"""Actual CMS/RSA; explicit GitHub responses, no live dispatch or ledger writes."""
import base64
from copy import copy,deepcopy
from dataclasses import asdict,replace
from datetime import datetime,timezone
import io,json,os,subprocess,sys,tempfile,threading,unittest,zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import deployment_compose_production_frontend_review_v1_host as bridge
import deployment_compose_production_frontend_review_contract as contract
from tests.test_deployment_compose_production_frontend_approval_v1_host import fixture,approved,host,release
from tests.test_deployment_compose_production_frontend_v3_host import material,adapter
from tests.test_release_host import claims


@unittest.skipUnless(os.name=='posix' and Path('/usr/bin/openssl').exists(),'POSIX/OpenSSL required')
class BridgeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
  self.key=self.root/'key.pem';self.cert=self.root/'cert.pem'
  subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(self.key),'-out',str(self.cert),'-days','1','-subj','/CN=test'],capture_output=True,check=True)
  self.key.chmod(0o600)
  req,p,_=fixture();row,image,args=material();self.plan=adapter.prepare_frontend_plan(row,image,**args);self.req=req
  self.client=Mock();self.client.close=Mock()
  with patch.object(bridge.GitHubLiveReviewV3,'_client',return_value=self.client):
   self.b=bridge.GitHubProductionFrontendReviewV1(self.root,runtime_sha=p.workflow_sha,recipient_private_key=self.key,registered_policy_hash=req.policy_hash)
  self.addCleanup(lambda:self.b.close() if not self.b._closed else None)
  self.run=dict(repository={'id':1327491026},id=123,head_sha=p.workflow_sha,path=bridge.WORKFLOW,run_attempt=1,event='workflow_dispatch',actor={'login':'github-actions[bot]','id':20},status='in_progress',created_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),html_url='https://github.com/luohao0308/dev-workflow/actions/runs/123')
  raw=contract.prepare(contract.canonical(dict(request=asdict(req),review=self.plan['publicReview'])),self.b._env(self.run));self.raw=contract.canonical(raw).encode()
  _,self.policy,_=contract.verify(self.raw.decode(),self.b._env(self.run));_,authclient,_=approved(replace(self.policy,reviewer_ids=(21,)),req)
  self.data=authclient.data
  env=self.data['/repos/'+host.RUNTIME+'/environments/compose-review'];env['protection_rules'][0]['reviewers'][0]['reviewer']['id']=84822776
  env['deployment_branch_policy']={'protected_branches':False,'custom_branch_policies':True}
  for name,value in dict(bridge.CONFIG,DW_PROD_FRONTEND_POLICY_HASH=req.policy_hash).items():self.data['/repos/'+host.RUNTIME+'/actions/variables/'+name]={'value':value}
  self.data['/repos/'+host.RUNTIME+'/environments/compose-review/deployment-branch-policies?per_page=100']={'total_count':1,'branch_policies':[{'name':'main','type':'branch'}]}
  self.data['/repos/'+host.RUNTIME+'/git/ref/heads/main']={'object':{'sha':p.workflow_sha}}
  self.data['/repos/'+host.RUNTIME+'/actions/workflows/production-frontend-review.yml']={'path':bridge.WORKFLOW,'state':'active'}
  self.data['/repos/'+host.RUNTIME+'/actions/workflows/production-frontend-review.yml/runs?event=workflow_dispatch&per_page=100']={'total_count':1,'workflow_runs':[self.run]}
  self.data['/repos/'+host.RUNTIME+'/actions/runs/123']=self.run
  self.data['/repos/'+host.RUNTIME+'/actions/runs/123/approvals'][0]['user']['id']=84822776
  self.data['/repos/'+host.RUNTIME+'/actions/runs/123/approvals'][0]['comment']='dev-workflow approve '+raw['bundleHash']
  frozen=datetime.strptime(self.run['created_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
  clock=patch.object(bridge,'datetime',wraps=datetime);clock_mock=clock.start();clock_mock.now.return_value=frozen;self.addCleanup(clock.stop)
  polling=patch.object(bridge,'time',SimpleNamespace(time=bridge.time.time,sleep=Mock(side_effect=AssertionError('Unexpected review polling'))));polling.start();self.addCleanup(polling.stop)
  self.posts=[]
  def request(method,path,payload=None,*,before_send=lambda:None):
   before_send()
   if method=='POST':raise AssertionError('Ledger client must not dispatch workflows')
   return deepcopy(self.data[path]),{}
  self.client.request.side_effect=request
  enc=lambda v:base64.urlsafe_b64encode(v).decode().rstrip('=')
  c=dict(claims(self.policy),aud=host.AUDIENCE)
  signed=(enc(json.dumps({'alg':'RS256','kid':'test'}).encode())+'.'+enc(json.dumps(c).encode())).encode()
  sig=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-sign',str(self.key)],input=signed,capture_output=True,check=True).stdout
  self.token=signed+b'.'+enc(sig).encode()
  self.cipher=subprocess.run(['/usr/bin/openssl','cms','-encrypt','-binary','-aes256','-outform','DER',str(self.cert)],input=self.token,capture_output=True,check=True).stdout
  modulus=subprocess.run(['/usr/bin/openssl','rsa','-in',str(self.key),'-modulus','-noout'],capture_output=True,text=True,check=True).stdout.strip().split('=')[1]
  keys=json.dumps({'keys':[{'kty':'RSA','kid':'test','n':enc(bytes.fromhex(modulus)),'e':enc(b'\x01\x00\x01')}]}).encode()
  reply=Mock();reply.__enter__=Mock(return_value=Mock(read=Mock(return_value=keys)));reply.__exit__=Mock(return_value=False)
  opener=Mock();opener.open.return_value=reply
  self.patch=patch.object(release.urllib.request,'build_opener',return_value=opener);self.patch.start();self.addCleanup(self.patch.stop)
  def zipped(filename,raw):
   stream=io.BytesIO()
   with zipfile.ZipFile(stream,'w') as z:z.writestr(filename,raw)
   return stream.getvalue()
  self.zips={1:zipped('bundle.json',self.raw),2:zipped('oidc.cms.der',self.cipher)}
  self.data['/repos/'+host.RUNTIME+'/actions/runs/123/artifacts?per_page=100']={'total_count':2,'artifacts':[{'id':1,'name':bridge.PUBLIC_ARTIFACT,'expired':False,'size_in_bytes':len(self.zips[1])},{'id':2,'name':bridge.SEALED_ARTIFACT,'expired':False,'size_in_bytes':len(self.zips[2])}]}
  self.b._command=lambda argv,**kwargs:SimpleNamespace(returncode=0,stdout=self.zips[int(argv[-1].split('/')[-2])])
  original_run=subprocess.run
  self.dispatch_exit=0
  self.dispatch_inputs=[]
  def command(argv,**kwargs):
   if argv[0]=='gh':
    self.assertEqual(argv[-2:],['--input','-'])
    self.assertIn('X-GitHub-Api-Version: 2022-11-28',argv)
    self.posts.append(argv[-3]);self.dispatch_inputs.append(kwargs['input'])
    return SimpleNamespace(returncode=self.dispatch_exit,stdout=b'',stderr=b'')
   return original_run(argv,**kwargs)
  self.commands=patch.object(subprocess,'run',side_effect=command);self.commands.start();self.addCleanup(self.commands.stop)

 def test_real_cms_signed_consent_returned_without_consumption(self):
  approval,grant,metadata=self.b.request_prepared_review(self.plan,self.req,lambda _:None)
  self.assertIs(type(approval),host.GitHubProductionFrontendApprovalV1);self.assertEqual(grant.request_hash,self.req.digest());self.assertFalse(metadata['consumed']);self.assertEqual(len(self.posts),1)
  sent=json.loads(self.dispatch_inputs[0]);self.assertEqual(sent['ref'],'main')
  self.assertEqual(json.loads(sent['inputs']['public_payload'])['request'],asdict(self.req)|{'components':list(self.req.components),'protected_components':list(self.req.protected_components)})
  self.assertNotIn('privateBody',self.dispatch_inputs[0].decode())
  for file in self.root.rglob('*'):
   if file.is_file():self.assertNotIn(self.token,file.read_bytes())
  with self.assertRaises(FileExistsError):self.b.request_prepared_review(self.plan,self.req,lambda _:None)
 def test_main_denied_before_post(self):
  self.data['/repos/'+host.RUNTIME+'/environments/compose-review/deployment-branch-policies?per_page=100']['branch_policies']=[]
  with self.assertRaises(bridge.LiveReviewBlocked):self.b.request_prepared_review(self.plan,self.req,lambda _:None)
  self.assertFalse(self.posts)
 def test_unknown_dispatch_not_retried(self):
  self.dispatch_exit=1
  for _ in range(2):
   with self.assertRaises((bridge.LiveReviewBlocked,FileExistsError)):self.b.request_prepared_review(self.plan,self.req,lambda _:None)
  self.assertEqual(len(self.posts),1)
 def test_callback_mutation_and_run_identity_change_reject(self):
  def mutate(_):self.plan['privateBody']['Env'].append('DRIFT=yes')
  with self.assertRaises(bridge.LiveReviewBlocked):self.b.request_prepared_review(self.plan,self.req,mutate)
 def test_run_identity_drift_rejected(self):
  def mutate(_):self.data['/repos/'+host.RUNTIME+'/actions/runs/123']['head_sha']='0'*40
  with self.assertRaises(bridge.LiveReviewBlocked):self.b.request_prepared_review(self.plan,self.req,mutate)
 def test_unsafe_artifact_rejected(self):
  self.zips[1]=b'invalid ZIP'
  with self.assertRaises(bridge.LiveReviewBlocked):self.b.request_prepared_review(self.plan,self.req,lambda _:None)
 def test_fork_and_client_replacement_rejected(self):
  original=self.b.client
  self.b.client=Mock()
  with self.assertRaises(bridge.LiveReviewBlocked):self.b._owned()
  self.b.client=original
  pid=os.fork()
  if pid==0:
   try:self.b._owned()
   except bridge.LiveReviewBlocked:os._exit(0)
   os._exit(1)
  self.assertEqual(os.waitpid(pid,0)[1],0)
 def test_copied_thread_and_closed_controller_reject(self):
  forged=copy(self.b);forged._owned=lambda:None
  with self.assertRaises(bridge.LiveReviewBlocked):forged.request_prepared_review(self.plan,self.req,lambda _:None)
  errors=[]
  def check():
   try:self.b._owned()
   except bridge.LiveReviewBlocked:errors.append(True)
  t=threading.Thread(target=check);t.start();t.join();self.assertEqual(errors,[True])
  self.b.close()
  with self.assertRaises(bridge.LiveReviewBlocked):self.b._owned()
 def test_multiple_valid_matching_runs_reject(self):
  other=dict(self.run,id=124)
  env=self.b._env(other);raw=contract.canonical(contract.prepare(contract.canonical(dict(request=asdict(self.req),review=self.plan['publicReview'])),env)).encode()
  original=self.b._artifact
  self.b._artifact=lambda run,*args:raw if run['id']==124 else original(run,*args)
  self.data['/repos/'+host.RUNTIME+'/actions/workflows/production-frontend-review.yml/runs?event=workflow_dispatch&per_page=100']['workflow_runs'].append(other)
  with self.assertRaises(bridge.LiveReviewBlocked):self.b.request_prepared_review(self.plan,self.req,lambda _:None)

 def test_inherited_legacy_entrypoints_cannot_dispatch(self):
  from tests.test_deployment_compose_bundle_v3 import fixture as legacy_fixture
  from deployment_compose_bundle_v3 import ExecutionBundleV3
  from tests.test_deployment_compose_approval_v3_host import request as legacy_request
  values,defaults=legacy_fixture();bundle=ExecutionBundleV3(values,authenticated_image_defaults=defaults)
  request=legacy_request()
  for name,args,kwargs in (
      ('consume_prepared',(bundle,request,lambda _:None),{}),
      ('_consume_prepared',(bundle,request,lambda _:None),{}),
      ('consume_scene_recovery',(object(),),dict(snapshot=object(),expected_draft_digest='a'*64,
          handle=object(),expected_request_digest=request.digest(),request=request,context_bytes=b'{}',on_review=lambda _:None))):
   before=set(self.root.iterdir())
   with self.subTest(entrypoint=name),patch.object(self.b,'_command') as command,patch.object(self.client,'request') as network:
    with self.assertRaises(bridge.LiveReviewBlocked):getattr(self.b,name)(*args,**kwargs)
    command.assert_not_called();network.assert_not_called()
   self.assertEqual(set(self.root.iterdir()),before)

 def test_known_artifact_download_failure_is_not_pending(self):
  self.b._command=Mock(return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=b'private diagnostic'))
  with self.assertRaisesRegex(bridge.LiveReviewBlocked,'^Production artifact download failed$'):
   self.b.request_prepared_review(self.plan,self.req,lambda _:None)
  self.assertEqual(self.b._command.call_count,1)
  self.assertEqual(len(self.posts),1)
