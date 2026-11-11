"""Bounded cached phase transport; native Unix reads with explicit endpoint double."""
import base64,os,shutil,unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import time
from types import SimpleNamespace
from contextlib import ExitStack
from unittest.mock import patch
from tests.support.compose_scene_create_integration_fixture import live_key, run_case
from deployment_compose_approval_v3_host import SCENE_RECOVERY_PROFILE
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_scene_recovery_handoff_v3_host import issue
from deployment_compose_scene_recovery_worker_v3_host import (
 INTENT_NAMESPACE,WITNESS_NAMESPACE,verify_worker_proof,worker_statement)
import deployment_compose_scene_recovery_worker_v3_host as recovery_worker
from deployment_compose_v3_channel_worker import read_frame
from tests.test_deployment_compose_live_controller_flow_v3_host import OwnedLocalProcess
import deployment_compose_scene_create_broker_v3_host as broker
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3,_plain
from deployment_compose_witness_store import canonical
from deployment_compose_scene_service_v3_host import _frame,_FALSE,_signed,SceneClientV3

@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'native POSIX tools required')
class ScenePhaseSnapshotTests(unittest.TestCase):
 def test_snapshot_cache_chunks_and_boundaries(self):
  self.check_scene_worker(relay=False)

 def test_recovery_worker_relays_signed_intent_and_witness(self):
  self.check_scene_worker(relay=True)

 def test_recovery_relay_disconnect_drains_and_freezes(self):
  self.check_scene_worker(relay=True,interrupt=True)

 def test_first_stop_uses_gate_and_unix_engine_once(self):
  self.check_scene_worker(relay=True,execute=True)

 def test_first_stop_lost_response_freezes_without_replay(self):
  self.check_scene_worker(relay=True,execute=True,lose_response=True,through_delete=True)

 def test_closed_stop_transitions_to_delete_once(self):
  self.check_scene_worker(relay=True,execute=True,through_delete=True)

 def test_full_recovery_renames_starts_and_checks_readiness(self):
  self.check_scene_worker(relay=True,execute=True,through_delete=True,full_recovery=True)

 def test_readiness_failure_preserves_closed_writes_without_completion(self):
  self.check_scene_worker(relay=True,execute=True,through_delete=True,full_recovery=True,readiness_failure=True)

 def check_scene_worker(self,*,relay,interrupt=False,execute=False,lose_response=False,through_delete=False,
                        full_recovery=False,readiness_failure=False):
  from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3

  signers={}
  admissions=[]
  initialize=MacLiveAdmissionV3.__init__
  def capture_admission(owner,*args,**kwargs):
   initialize(owner,*args,**kwargs)
   admissions.append(owner)
  def capture_signer(root,name):
   signer,public=live_key(root,name)
   signers[name]=signer
   return signer,public
  def hook(subject,prep,session):
   record=broker._RECORDS[subject];captures=[]
   def capture(observer,bundle,baseline,context,*,expected_version,timeout,terminal=False):
    guard=PhaseGuardV3(bundle,baseline,read_json=session.guard._read,daemon_version=expected_version,expected_docker_root=session.guard._root)
    raw=canonical(_plain(guard.capture_phase(context,terminal=terminal)));captures.append(raw)
    origin=broker.decode(record['origin']);ns=[origin['pidNamespaceDevice'],origin['pidNamespaceInode']]
    endpoint=canonical(dict(daemonBinding=observer.binding(),normalizationVersion=expected_version,
     pidNamespace=ns,daemonPidNamespace=ns,networkNamespace=[1,2],mountNamespace=[1,3],
     rootIdentity=[1,4],socketIdentity=[1,5],pidFileIdentity=['dockerd.pid',[1,6]]))
    return raw,endpoint
   with patch.object(ObservedRecoveryDaemonV3,'capture_recovery_phase',capture):
    descriptor=subject.capture_closed_phase_snapshot('a'*64)
    summary=subject.observe_closed_phase('b'*64)
   self.assertEqual(summary['phaseDigest'],descriptor['observation']['phaseDigest'])
   self.assertEqual(descriptor['chunkBytes'],4096)
   envelope=dict(phaseSnapshot=descriptor,**{key:False for key in _FALSE})
   unix=dict(kind='scene-result-v3',sceneId=summary['closure']['sceneId'],serverNonce='1'*64,clientNonce='2'*64,
    generation=2**53-1,leaseNonce='3'*64,seq=2**53-1,command='capture_closed_phase_snapshot',result=envelope)
   ssh=dict(kind='scene-control-result-v3',channelNonce='4'*64,seq=2**53-1,command='capture_closed_phase_snapshot',result=envelope)
   self.assertLessEqual(len(_frame(_signed(b'x'*32,unix)))-4,8192)
   self.assertLessEqual(len(_frame(ssh))-4,8192)
   checks=[]
   def stopped(origin,*,expected_digest,expected_source_sha,expected_archive_digest,timeout):
    self.assertEqual(origin,record['origin'])
    self.assertEqual(expected_digest,broker.digest(origin))
    self.assertEqual(expected_source_sha,record['inputs']['hello']['sourceSha'])
    self.assertEqual(expected_archive_digest,record['inputs']['hello']['archiveDigest'])
    self.assertLessEqual(timeout,5)
    checks.append('stop')
    return SimpleNamespace(writerStoppedObserved=True,origin_digest=expected_digest,observation_digest='e'*64)
   def read_phase(*args,**kwargs):
    checks.append('phase')
    return capture(*args,**kwargs)
   closure=summary['closure']
   operation=session.prepared['bundle'].resolve_operations(closure['receiptMap'])[1]
   pins=dict(historyDigest=closure['historyDigest'],slotGeneration=closure['slotGeneration'],
    nextOperationDigest=operation['requestDigest'],phaseDigest=summary['phaseDigest'],
    endpointBindingDigest=summary['endpointBindingDigest'])
   with patch.object(broker,'observe_stopped_writer',side_effect=stopped), patch.object(
     ObservedRecoveryDaemonV3,'capture_recovery_phase',read_phase):
    bracket=subject.observe_stopped_writer_phase('d'*64,pins)
   self.assertEqual(checks,['stop','phase','stop'])
   self.assertEqual(bracket['phaseObservation']['phaseDigest'],summary['phaseDigest'])
   self.assertEqual(bracket['writerStopObservationDigest'],'e'*64)
   self.assertEqual(bracket['firstWriteBindingDigest'],broker.digest(canonical(pins)))
   with patch.object(broker,'observe_stopped_writer',side_effect=AssertionError('bad pins must precede native reads')):
    for change in (dict(historyDigest='0'*64),dict(slotGeneration=True),dict(nextOperationDigest='0'*64),
                   dict(extraField=True)):
     with self.assertRaises(ValueError):subject.observe_stopped_writer_phase('d'*64,dict(pins,**change))
   with patch.object(broker,'observe_stopped_writer',side_effect=stopped), patch.object(
     ObservedRecoveryDaemonV3,'capture_recovery_phase',capture):
    for key in ('phaseDigest','endpointBindingDigest'):
     with self.assertRaises(ValueError):subject.observe_stopped_writer_phase('d'*64,dict(pins,**{key:'0'*64}))
   envelope=dict(writerPhaseObservation=bracket,**{key:False for key in _FALSE})
   self.assertLessEqual(len(_frame(_signed(b'x'*32,dict(unix,command='observe_stopped_writer_phase',result=envelope))))-4,8192)
   self.assertLessEqual(len(_frame(dict(ssh,command='observe_stopped_writer_phase',result=envelope)))-4,8192)
   good=SimpleNamespace(writerStoppedObserved=True,origin_digest=bracket['writerOriginDigest'],observation_digest='e'*64)
   bad=SimpleNamespace(writerStoppedObserved=True,origin_digest=bracket['writerOriginDigest'],observation_digest='f'*64)
   with patch.object(ObservedRecoveryDaemonV3,'capture_recovery_phase',capture):
    for observations in ([ValueError('active writer')], [good,ValueError('reappeared writer')], [good,bad]):
     with patch.object(broker,'observe_stopped_writer',side_effect=observations), self.assertRaises(ValueError):
      subject.observe_stopped_writer_phase('d'*64,pins)
    slot=record['slot'];status=slot.status()
    with patch.object(broker,'observe_stopped_writer',side_effect=stopped), patch.object(
      type(slot),'status',side_effect=[status,dict(status,slotGeneration=status['slotGeneration']+1)]):
     with self.assertRaises(ValueError):subject.observe_stopped_writer_phase('d'*64,pins)
    def different_daemon(*args,**kwargs):
     raw,endpoint=capture(*args,**kwargs)
     value=broker.decode(endpoint)
     value['daemonBinding']['invocationId']='f'*32
     return raw,canonical(value)
    with patch.object(broker,'observe_stopped_writer',side_effect=stopped), patch.object(
      ObservedRecoveryDaemonV3,'capture_recovery_phase',different_daemon):
     with self.assertRaises(ValueError):subject.observe_stopped_writer_phase('d'*64,pins)
   original=session.prepared['request']
   expires=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
   request=replace(original,operation='recovery',profile_id=SCENE_RECOVERY_PROFILE,
      history_hash=closure['historyDigest'],observation_hash='9'*64,expires_at=expires)
   parent=broker.decode(record['terminal'])['history']['closedTail']
   scope=Profile3StepExecutor.scope_descriptor(session.prepared['bundle'],request,'f'*64,operation,1,closure['receiptMap'])
   child=dict(parent['binding'],generation=scope['generation'],scopeHash=scope['scopeHash'])
   handoff=dict(sceneId=closure['sceneId'],nonce='d'*64,expiresAt=int(time.time())+45,request=asdict(request),
      receiptDigest='f'*64,firstBinding=child,parentTail=parent,firstWriteBindingDigest=bracket['firstWriteBindingDigest'],
      writerStopObservationDigest='e'*64)
   def sign(payload):
    return issue(payload,signers['intent-signing'],broker.digest(record['intent']))
   cert=sign(handoff)
   args=dict(requestNonce='d'*64,firstWrite=pins,recoveryHandoff=cert)
   command=dict(unix,kind='scene-command-v3',command='observe_stopped_writer_phase',args=args)
   del command['result']
   self.assertLessEqual(len(_frame(_signed(b'x'*32,command)))-4,8192)
   with patch.object(broker,'observe_stopped_writer',side_effect=AssertionError('untrusted handoff')):
    for candidate in (dict(cert,signature='AAAA'),sign(dict(handoff,nonce='0'*64)),
                      sign(dict(handoff,firstBinding=dict(child,generation='0'*64))),
                      sign(dict(handoff,expiresAt=1))):
     with self.assertRaises(ValueError):subject.observe_stopped_writer_phase('d'*64,pins,recovery_handoff=candidate)
   with patch.object(broker,'observe_stopped_writer',side_effect=stopped), patch.object(
     ObservedRecoveryDaemonV3,'capture_recovery_phase',capture):
    staged=subject.observe_stopped_writer_phase('d'*64,pins,recovery_handoff=cert,lease_generation=9)
    self.assertEqual(staged['recoveryHandoffDigest'],broker.digest(canonical(handoff)))
    self.assertEqual(record['recoveryHandoff'],canonical(dict(certificate=cert,firstWrite=pins)))
    with self.assertRaises(ValueError):subject.observe_stopped_writer_phase('d'*64,pins,recovery_handoff=cert)
   nonce=staged['recoveryWorkerNonce']
   statement=worker_statement(handoff,nonce,int(time.time())+15)
   proof=dict(intent=issue(statement,signers['intent-signing'],broker.digest(record['intent']),namespace=INTENT_NAMESPACE),
    witness=issue(statement,signers['witness-signing'],broker.digest(record['witness']),namespace=WITNESS_NAMESPACE))
   confirm_command=dict(command,command='confirm_recovery_worker',args=dict(proof=proof))
   self.assertLessEqual(len(_frame(_signed(b'x'*32,confirm_command)))-4,8192)
   with self.assertRaises(ValueError):subject.confirm_recovery_worker(proof,10)
   with self.assertRaises(ValueError):
    verify_worker_proof(dict(proof,witness=proof['intent']),handoff=handoff,nonce=nonce,
      intent_key=record['intent'],witness_key=record['witness'])
   with self.assertRaises(ValueError):
    verify_worker_proof(proof,handoff=handoff,nonce='0'*64,intent_key=record['intent'],witness_key=record['witness'])
   snapshot=descriptor['snapshotId'];phase_digest=summary['phaseDigest'];total=descriptor['totalBytes']
   self.assertGreater(total,4096)
   with patch.object(session.guard,'_read',side_effect=AssertionError('chunk must not read Engine')),patch.object(
     ObservedRecoveryDaemonV3,'capture_recovery_phase',side_effect=AssertionError('chunk must not recapture')):
    raw=b''
    for offset in range(0,total,4096):
     chunk=subject.read_closed_phase_chunk(snapshot,phase_digest,offset,4096)
     data=base64.b64decode(chunk['dataBase64'],validate=True);raw+=data
     self.assertEqual(len(data),min(4096,total-offset))
     self.assertEqual(chunk['offset'],offset);self.assertEqual(chunk['totalBytes'],total)
     envelope=dict(phaseChunk=chunk,**{key:False for key in _FALSE})
     unix=dict(kind='scene-result-v3',sceneId=summary['closure']['sceneId'],serverNonce='1'*64,clientNonce='2'*64,
      generation=2**53-1,leaseNonce='3'*64,seq=2**53-1,command='read_closed_phase_chunk',result=envelope)
     ssh=dict(kind='scene-control-result-v3',channelNonce='4'*64,seq=2**53-1,command='read_closed_phase_chunk',result=envelope)
     self.assertLessEqual(len(_frame(_signed(b'x'*32,unix)))-4,8192)
     self.assertLessEqual(len(_frame(ssh))-4,8192)
    self.assertEqual(raw,captures[0]);self.assertEqual(broker.digest(raw),phase_digest)
    for args in [(True,1),(0,True),(-1,1),(total,1),(0,0),(0,4097),(0,1.0)]:
     with self.assertRaises(ValueError):subject.read_closed_phase_chunk(snapshot,phase_digest,*args)
    for sid,digest in [('f'*64,phase_digest),(snapshot,'f'*64),(True,phase_digest),(snapshot,'bad')]:
     with self.assertRaises(ValueError):subject.read_closed_phase_chunk(sid,digest,0,1)
    saved=record['phase_snapshot']['raw'];record['phase_snapshot']['raw']=saved+b' '
    with self.assertRaises(ValueError):subject.read_closed_phase_chunk(snapshot,phase_digest,0,1)
    record['phase_snapshot']['raw']=saved
    slot=record['slot'];status=slot.status()
    with patch.object(type(slot),'status',return_value=dict(status,slotGeneration=status['slotGeneration']+1)):
     with self.assertRaises(ValueError):subject.read_closed_phase_chunk(snapshot,phase_digest,0,1)
    original_closure=record['closure'];record['closure']=original_closure+b' '
    with self.assertRaises(ValueError):subject.read_closed_phase_chunk(snapshot,phase_digest,0,1)
    record['closure']=original_closure
   seal=subject._closed_phase_seal()
   def candidate(raw):return dict(summary,phaseDigest=broker.digest(raw)),raw,seal
   # Boundary doubles isolate cache transport from native phase normalization.
   empty=canonical(dict(rows={},resources=''))
   exact=canonical(dict(rows={},resources='x'*(broker.MAX_MESSAGE-len(empty))))
   self.assertEqual(len(exact),4*1024*1024)
   for bad in (exact+b' ',b'{"rows":{}}',b'{"rows":{}, "resources":{}}'):
    with patch.object(type(subject),'_capture_closed_phase',return_value=candidate(bad)):
     with self.assertRaises(ValueError):subject.capture_closed_phase_snapshot('c'*64)
    self.assertEqual(subject.read_closed_phase_chunk(snapshot,phase_digest,0,1)['snapshotId'],snapshot)
   with patch.object(type(subject),'_capture_closed_phase',side_effect=ValueError('capture failed')):
    with self.assertRaises(ValueError):subject.capture_closed_phase_snapshot('c'*64)
   self.assertEqual(subject.read_closed_phase_chunk(snapshot,phase_digest,0,1)['snapshotId'],snapshot)
   with patch.object(type(subject),'_capture_closed_phase',return_value=candidate(exact)):
    new=subject.capture_closed_phase_snapshot('c'*64)
   self.assertNotEqual(new['snapshotId'],snapshot);self.assertEqual(new['totalBytes'],len(exact))
   with self.assertRaises(ValueError):subject.read_closed_phase_chunk(snapshot,phase_digest,0,1)
   last=subject.read_closed_phase_chunk(new['snapshotId'],new['observation']['phaseDigest'],len(exact)-1,4096)
   self.assertEqual(base64.b64decode(last['dataBase64']),exact[-1:])
   lifecycle=[]
   def start(unit,*,timeout):
    lifecycle.append('start')
    def run(owned):
     config=read_frame(owned.input,timeout=5)
     self.assertEqual(base64.b64decode(config.pop('archiveBase64')),record['archive'])
     recovery_worker.run(config,owned.input,owned.output)
    unit._process=OwnedLocalProcess(run)
   def origin(unit,*,timeout):
    return canonical(dict(broker.decode(record['origin']),unit=unit.unit))
   def stop(unit,*,timeout):
    if interrupt and not unit._process.stdin.closed:
     unit._process.stdin.close()
    self.assertEqual(unit._process.wait(timeout),1 if interrupt or lose_response or readiness_failure else 0)
    lifecycle.append('stop')
   def close(unit):
    lifecycle.append('close')
    for pipe in (unit._process.stdin,unit._process.stdout,unit._process.stderr):
     pipe.close()
   unit=recovery_worker.SceneRecoveryStartupUnitV3
   with ExitStack() as stack:
    for method,value in (('start',start),('capture_origin',origin),('stop',stop),('close',close)):
     stack.enter_context(patch.object(unit,method,value))
    stack.enter_context(patch('deployment_compose_scene_writer_slot_v3_host.observe_stopped_writer',return_value=good))
    if execute:
     binding=record['inputs']['daemonBinding']
     def capture_phase(*args,**kwargs):
      return capture(SimpleNamespace(binding=lambda:binding),*args,**kwargs)
     observer=SimpleNamespace(binding=lambda:binding,capture_recovery_phase=capture_phase,close=lambda:None,
                              _request=lambda path,*args,**kwargs:session.guard._read(path))
     stack.enter_context(patch('deployment_compose_recovery_daemon_v3_host.ObservedRecoveryDaemonV3',return_value=observer))
     stack.enter_context(patch('deployment_compose_cold_writer_v3_host.observe_stopped_writer',return_value=good))
     if full_recovery:
      def readiness_check(prepared,cid):
       self.assertEqual(cid,closure['receiptMap']['backend'])
       row=prepared.producer._get('/v1.45/containers/'+cid+'/json')
       self.assertEqual(row['State']['Health']['Status'],'healthy')
       self.assertTrue(row['State']['Running'])
       return not readiness_failure
      stack.enter_context(patch('deployment_compose_live_worker_v3_host.readiness',side_effect=readiness_check))
     host=admissions[0]
     host._store.transition_successor(parent['binding'],expected_seq=parent['seq'],expected_head=parent['head'],childBinding=child)
     authority_scope=dict(binding=child,descriptor=scope,
      entry=dict(request=request,receiptHash='f'*64,approval=SimpleNamespace(check_consumed_intent=lambda _:None)))
    else:host=authority_scope=None
    confirmed=subject.confirm_recovery_worker(proof,9,launch=not relay,relay=relay and not execute,execute=execute,
                                              through_delete=through_delete,full_recovery=full_recovery)
    if interrupt:
     subject.controller_lost()
     self.assertEqual(subject.poll_worker()['businessState'],'frozen')
     self.assertEqual(record['slot'].status()['slotState'],'drained')
    elif lose_response or readiness_failure:
     with self.assertRaises(ValueError):
      self.drive_relay(subject,confirmed,proof,signers,record,child,parent,host=host,scope=authority_scope,
                       through_delete=through_delete,full_recovery=full_recovery)
     subject.controller_lost()
     self.assertEqual(subject.poll_worker()['businessState'],'frozen')
     self.assertTrue(session.unknown_write_result)
    elif relay:self.drive_relay(subject,confirmed,proof,signers,record,child,parent,host=host,scope=authority_scope,
                               through_delete=through_delete,full_recovery=full_recovery)
   self.assertEqual(lifecycle,['start','stop','close'])
   self.assertEqual(confirmed['workerProofDigest'],broker.digest(canonical(statement)))
   self.assertEqual(record['recoveryWorkerProof'],canonical(proof))
   if not relay:
    self.assertEqual(confirmed['workerStartupDigest'],broker.digest(record['recoveryWorkerStartup']))
    startup=broker.decode(record['recoveryWorkerStartup'])
    self.assertEqual(startup['ready']['workerProofDigest'],confirmed['workerProofDigest'])
    self.assertIs(startup['workerStopped'],True)
    self.assertEqual(startup['slotGeneration'],closure['slotGeneration']+1)
   with self.assertRaises(ValueError):subject.confirm_recovery_worker(proof,9,launch=True)
  with patch('tests.support.compose_scene_create_integration_fixture.live_key',side_effect=capture_signer),patch.object(
    MacLiveAdmissionV3,'__init__',capture_admission):
   result=run_case(self,scene_controller=True,after_reconciled=hook,
                   scene_stop=('response-loss' if lose_response else 'readiness-failure' if readiness_failure else
                               'full-recovery' if full_recovery else 'through-delete' if through_delete else execute))
  self.assertEqual(result['postCount'],1)

 def drive_relay(self,subject,confirmation,proof,signers,record,child,parent,*,host=None,scope=None,
                 through_delete=False,full_recovery=False):
  from deployment_compose_intent_status_v3 import NAMESPACE as INTENT_STATUS
  from deployment_compose_operation_witness_client_v3 import NAMESPACE as WITNESS_STATUS, dispatch_request, request_digest
  from deployment_compose_scene_control_ssh_v3_host import SceneSSHClientV3
  from deployment_compose_scene_live_phase_v3_host import _drive_recovery_relay
  from deployment_compose_witness_store import ZERO

  client=object.__new__(SceneSSHClientV3)
  def call(_,command,args=None):
   args=args or {}
   handlers={
    'poll_worker':lambda:subject.poll_worker(),
    'read_worker_chunk':lambda:subject.read_worker_chunk(args['attemptId'],args['messageDigest'],args['offset'],args['length']),
    'begin_worker_reply':lambda:subject.begin_worker_reply(args['attemptId'],args['totalBytes'],args['messageDigest'],args['rpcId']),
    'worker_reply_chunk':lambda:subject.worker_reply_chunk(args['attemptId'],args['offset'],args['dataBase64']),
    'commit_worker_reply':lambda:subject.commit_worker_reply(args['attemptId']),
    'finish_worker':lambda:subject.finish_worker(args['attemptId']),
   }
   return {'business':handlers[command]()}
  calls=[]
  active=child
  active_scope=scope
  lineage=[parent]
  def authorize(service,method,rpc):
   nonlocal active,active_scope
   calls.append((service,method))
   if service=='intent':
    now=int(time.time())
    value=dict(rpc,purpose='consumed-intent-status-v3',issuedAt=now,expiresAt=now+10,
               consumed=True,authorityGranted=False,runtimePermit=False,productionReady=False)
    return issue(value,signers['intent-signing'],broker.digest(record['intent']),namespace=INTENT_STATUS)
   self.assertEqual(rpc['binding'],active)
   if host is not None:
    if method=='transition_successor':
     self.assertTrue(through_delete)
     prior=host._store.read(active)
     self.assertEqual((prior['phase'],prior['seq']),('closed',6))
     lineage.append(dict(binding=active,seq=6,head=prior['head']))
     prepared=record['inputs']['session'].prepared
     receipts=broker.decode(record['closure'])['receiptMap']
     index=len(lineage)
     desc=Profile3StepExecutor.scope_descriptor(prepared['bundle'],scope['entry']['request'],'f'*64,
         prepared['bundle'].resolve_operations(receipts)[index],index,receipts)
     successor=dict(child,generation=desc['generation'],scopeHash=desc['scopeHash'])
     self.assertEqual(rpc['childBinding'],successor)
     payload=dispatch_request(host._store,method,rpc)
     active=successor
     active_scope=dict(scope,binding=active,descriptor=desc)
    else:
     payload=host._append(rpc,active_scope) if method=='append_event' else dispatch_request(host._store,method,rpc)
    return host._sign(payload)
   result=dict(binding=child,seq=0,head=ZERO,phase='empty',active=True,lineage=[parent],
               authorityGranted=False,productionReady=False)
   value=dict(schemaVersion=1,method=method,binding=child,requestDigest=request_digest(method,rpc),
              bootNonce=rpc['bootNonce'],rpcNonce=rpc['rpcNonce'],result=result,authorityGranted=False,productionReady=False)
   return issue(value,signers['witness-signing'],broker.digest(record['witness']),namespace=WITNESS_STATUS)
  def verify_stop():
   view=host._store.read(active)
   self.assertEqual((view['seq'],view['phase'],view['lineage']),(6,'closed',lineage))
   return dict(head=view['head'],status=204)
  with patch.object(SceneSSHClientV3,'_call',call),patch(
    'deployment_compose_scene_control_ssh_v3_host._issued_scene_ssh_client',return_value=None):
   result=_drive_recovery_relay(client,confirmation['workerRelay'],proof,confirmation['workerProofDigest'],authorize,
                                stop_verifier=verify_stop if host is not None else None,
                                through_delete=through_delete,full_recovery=full_recovery)
  if host is None:self.assertEqual(calls,[('intent','check'),('witness','check')])
  else:self.assertEqual(calls.count(('witness','append_event')),24 if full_recovery else 12 if through_delete else 6)
  self.assertEqual(subject.poll_worker()['businessState'],'closed')
  self.assertEqual(subject.poll_worker()['relayDigest'],result)

 def test_client_argument_contract(self):
  client=object.__new__(SceneClientV3)
  with patch.object(SceneClientV3,'_call',return_value={}) as call:
   client.observe_stopped_writer_phase('d'*64,{'testPin':'1'*64})
   call.assert_called_with('observe_stopped_writer_phase',dict(requestNonce='d'*64,firstWrite={'testPin':'1'*64}))
   client.capture_closed_phase_snapshot('a'*64)
   call.assert_called_with('capture_closed_phase_snapshot',dict(requestNonce='a'*64))
   client.read_closed_phase_chunk('b'*64,'c'*64,0,4096)
   call.assert_called_with('read_closed_phase_chunk',dict(snapshotId='b'*64,phaseDigest='c'*64,offset=0,length=4096))
