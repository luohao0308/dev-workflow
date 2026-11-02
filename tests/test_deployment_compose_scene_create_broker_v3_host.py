"""Native pipes/chunk FSM; creator, startup inputs and terminal history are doubles."""
import base64,hashlib,json,os,secrets,subprocess,sys,tempfile,time,threading
from pathlib import Path
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_scene_create_broker_v3_host as broker
from deployment_compose_witness_store import canonical


@unittest.skipUnless(os.name=='posix','POSIX pipe selectors required')
class BrokerWireTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
 def make(self,attack=''):
  nonce='4'*64;marker=self.root/(secrets.token_hex(4)+'.json')
  p=subprocess.Popen([sys.executable,str(ROOT/'tests/support/compose_scene_broker_wire_fixture.py'),nonce,attack,str(marker)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
  def clean():
   if p.poll() is None:p.kill();p.wait(timeout=3)
   for stream in (p.stdin,p.stdout,p.stderr):stream.close()
  self.addCleanup(clean)
  unit=SimpleNamespace(_process=p)
  slot=SimpleNamespace(drain=lambda generation:{'stopObservationDigest':'5'*64})
  subject=object.__new__(broker.SceneCreateBrokerV3)
  broker._RECORDS[subject]=dict(issuer=(os.getpid(),threading.get_ident()),state='active',process=p,unit=unit,
   nonce=nonce,scene='dw-scene-'+'a'*16,inputs={'metadata':{'preparationId':'6'*64,'capsuleDigest':'7'*64}},
   attempt='8'*64,generation=1,pending=None,staged=None,terminal=None,buffer=bytearray(),stdout_eof=False,stderr_eof=False,
   last_rpc=0,stop=None,lease=1,witness=b'witness fixture',intent=b'intent fixture',slot=slot,request_hash='1'*64,bundle_digest='2'*64)
  return subject,p,marker
 def poll_until(self,subject,predicate):
  end=time.monotonic()+5
  while True:
   value=subject.poll_worker()
   if predicate(value):return value
   self.assertLess(time.monotonic(),end);time.sleep(.005)
 def test_large_rpc_and_reply_are_hashed_chunked_and_committed_once(self):
  subject,process,marker=self.make();state=self.poll_until(subject,lambda value:'message' in value)
  meta=state['message'];self.assertGreater(meta['totalBytes'],8192)
  raw=bytearray()
  while len(raw)<meta['totalBytes']:
   piece=subject.read_worker_chunk(meta['attemptId'],meta['messageDigest'],len(raw),4096)
   self.assertEqual(piece['offset'],len(raw));raw.extend(base64.b64decode(piece['dataBase64']))
  self.assertEqual(hashlib.sha256(raw).hexdigest(),meta['messageDigest'])
  reply=canonical(dict(kind='reply',channelNonce='4'*64,rpcId=1,response={'large':'y'*17000}))
  subject.begin_worker_reply(meta['attemptId'],len(reply),hashlib.sha256(reply).hexdigest(),1)
  with self.assertRaises(ValueError):subject.worker_reply_chunk(meta['attemptId'],1,base64.b64encode(reply[:10]).decode())
  self.assertFalse(marker.exists())
  for offset in range(0,len(reply),4096):subject.worker_reply_chunk(meta['attemptId'],offset,base64.b64encode(reply[offset:offset+4096]).decode())
  self.assertFalse(marker.exists());subject.commit_worker_reply(meta['attemptId'])
  final=self.poll_until(subject,lambda value:value['businessState']=='transport-exited')
  self.assertEqual(json.loads(marker.read_bytes()),json.loads(reply))
  closed=subject.finish_worker(meta['attemptId']);self.assertEqual(closed['businessState'],'closed')
  with self.assertRaises(ValueError):subject.commit_worker_reply(meta['attemptId'])
 def test_disallowed_method_and_wrong_nonce_freeze_without_reply(self):
  for attack in ('method','nonce'):
   with self.subTest(attack=attack):
    subject,process,marker=self.make(attack)
    with self.assertRaises(ValueError):self.poll_until(subject,lambda value:'message' in value)
    self.assertEqual(subject.status()['businessState'],'failed');self.assertFalse(marker.exists())


@unittest.skipUnless(os.name=='posix' and __import__('shutil').which('ssh-keygen'),'POSIX/OpenSSH required')
class BrokerConfigurationBudgetTests(unittest.TestCase):
 def test_combined_oversize_rejects_before_pending_or_writer_start(self):
  from dataclasses import replace,asdict
  from unittest.mock import Mock,patch
  from tests.test_deployment_compose_live_admission_v3_host import AdmissionTests
  from deployment_gate_witness import key_material
  fixture=AdmissionTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
  hello=dict(sourceSha='a'*40,archiveDigest='b'*64,hostId='host-one',writerCertificateSha256='c'*64)
  policy=replace(fixture.policy,scope_hash=broker.digest(canonical(hello)),writer_certificate_sha256=hello['writerCertificateSha256'])
  request=replace(fixture.request,policy_hash=policy.identity_hash());receipt='d'*64
  descriptor=broker.Profile3StepExecutor.scope_descriptor(fixture.bundle,request,receipt,fixture.bundle.creation_operations()[0],0,{})
  binding={key:descriptor[key] for key in ('scopeHash','generation')};binding.update(policyHash=policy.identity_hash(),epoch='e'*64)
  slot=SimpleNamespace(status=lambda:dict(slotState='empty',slotGeneration=0),reserve_create=Mock())
  meta=dict(preparationId='1'*64,capsuleDigest='2'*64,observerFacts={})
  session=SimpleNamespace(prepared=dict(request=request,bundle=fixture.bundle),guard=SimpleNamespace(_version={}),unknown_write_result=False)
  inputs=dict(metadata=meta,session=session,hello=hello,daemonBinding={},capsule=b'x'*(2*1024*1024),keys={})
  subject=object.__new__(broker.SceneCreateBrokerV3)
  broker._RECORDS[subject]=dict(issuer=(os.getpid(),threading.get_ident()),state='new',unit=None,process=None,
   slot=slot,inputs=inputs,archive=b'y'*(2*1024*1024),witness=key_material(fixture.public[0]),intent=key_material(fixture.public[1]),preparation=object())
  args=dict(**{key:meta[key] for key in ('preparationId','capsuleDigest')},slotGeneration=0,policy=asdict(policy),
   gateKeyBase64=base64.b64encode(fixture.gate_key).decode(),requestHash=request.digest(),receiptHash=receipt,firstBinding=binding)
  with patch.object(broker.PreparationOwnerV3,'mark_product_pending') as pending:
   with self.assertRaises(ValueError):subject.start_first_create(args,1)
   pending.assert_not_called()
  slot.reserve_create.assert_not_called();self.assertFalse(session.unknown_write_result)
  self.assertEqual(broker._RECORDS[subject]['state'],'new')
