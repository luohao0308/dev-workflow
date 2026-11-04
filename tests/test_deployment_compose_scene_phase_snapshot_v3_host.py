"""Bounded cached phase transport; native Unix reads with explicit endpoint double."""
import base64,os,shutil,unittest
from unittest.mock import patch
from tests.support.compose_scene_create_integration_fixture import run_case
import deployment_compose_scene_create_broker_v3_host as broker
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3,_plain
from deployment_compose_witness_store import canonical
from deployment_compose_scene_service_v3_host import _frame,_FALSE,_signed,SceneClientV3

@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'native POSIX tools required')
class ScenePhaseSnapshotTests(unittest.TestCase):
 def test_snapshot_cache_chunks_and_boundaries(self):
  def hook(subject,prep,session):
   record=broker._RECORDS[subject];captures=[]
   def capture(observer,bundle,baseline,context,*,expected_version,timeout):
    guard=PhaseGuardV3(bundle,baseline,read_json=session.guard._read,daemon_version=expected_version,expected_docker_root=session.guard._root)
    raw=canonical(_plain(guard.capture_phase(context)));captures.append(raw)
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
  result=run_case(self,scene_controller=True,after_reconciled=hook)
  self.assertEqual(result['postCount'],1)

 def test_client_argument_contract(self):
  client=object.__new__(SceneClientV3)
  with patch.object(SceneClientV3,'_call',return_value={}) as call:
   client.capture_closed_phase_snapshot('a'*64)
   call.assert_called_with('capture_closed_phase_snapshot',dict(requestNonce='a'*64))
   client.read_closed_phase_chunk('b'*64,'c'*64,0,4096)
   call.assert_called_with('read_closed_phase_chunk',dict(snapshotId='b'*64,phaseDigest='c'*64,offset=0,length=4096))
