"""Native Unix Engine/PhaseGuard; issuer/kernel endpoint capture are doubles."""
from types import SimpleNamespace
import os,shutil,unittest,time
from unittest.mock import patch
from tests.support.compose_scene_create_integration_fixture import run_case
import deployment_compose_scene_create_broker_v3_host as broker
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3,_plain
from deployment_compose_witness_store import canonical
from deployment_compose_scene_service_v3_host import _frame,_FALSE,_signed

@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'native POSIX tools required')
class ScenePhaseTests(unittest.TestCase):
 def test_original_phase_summary_and_fail_closed_boundaries(self):
  seen=[]
  def hook(subject,prep,session):
   record=broker._RECORDS[subject]
   def capture(observer,bundle,baseline,context,*,expected_version,timeout):
    self.assertGreater(timeout,0);self.assertLessEqual(timeout,15)
    guard=PhaseGuardV3(bundle,baseline,read_json=session.guard._read,daemon_version=expected_version,expected_docker_root=session.guard._root)
    phase=canonical(_plain(guard.capture_phase(context)))
    origin=broker.decode(record['origin']);ns=[origin['pidNamespaceDevice'],origin['pidNamespaceInode']]
    endpoint=canonical(dict(daemonBinding=observer.binding(),normalizationVersion=expected_version,
     pidNamespace=ns,daemonPidNamespace=ns,networkNamespace=[1,2],mountNamespace=[1,3],
     rootIdentity=[1,4],socketIdentity=[1,5],pidFileIdentity=['dockerd.pid',[1,6]]))
    return phase,endpoint
   with patch.object(ObservedRecoveryDaemonV3,'capture_recovery_phase',capture):
    with patch.object(type(session.prepared['request']),'ensure_fresh',side_effect=AssertionError('historical read must not use expired deploy authorization')):
     result=subject.observe_closed_phase('f'*64)
    seen.append(result)
    self.assertTrue(result['readOnly']);self.assertEqual(result['phaseIndex'],1)
    self.assertNotIn('rows',result);self.assertNotIn('phase_bytes',result)
    self.assertLessEqual(len(_frame(dict(phaseObservation=result,**{k:False for k in _FALSE})))-4,8192)
    envelope=dict(phaseObservation=result,**{k:False for k in _FALSE})
    unix=dict(kind='scene-result-v3',sceneId=result['closure']['sceneId'],serverNonce='1'*64,clientNonce='2'*64,
     generation=2**53-1,leaseNonce='3'*64,seq=2**53-1,command='observe_closed_phase',result=envelope)
    ssh=dict(kind='scene-control-result-v3',channelNonce='4'*64,seq=2**53-1,command='observe_closed_phase',result=envelope)
    self.assertLessEqual(len(_frame(_signed(b'x'*32,unix)))-4,8192)
    self.assertLessEqual(len(_frame(ssh))-4,8192)
    for key in ('phaseFreshnessVerified','daemonContinuityVerified','writerQuiescenceVerified','authorityGranted','executionAvailable','runtimePermit','recoveryAuthorized','productionReady','sourceRevalidated'):self.assertIs(result[key],False)
    for state in ('new','closed','frozen'):
     record['state']=state
     with self.assertRaises(ValueError):subject.observe_closed_phase('e'*64)
    record['state']='reconciled'
    for value in ('',True,'x'*64):
     with self.assertRaises(ValueError):subject.observe_closed_phase(value)
    original=session.unknown_write_result;session.unknown_write_result=True
    with self.assertRaises(ValueError):subject.observe_closed_phase('e'*64)
    session.unknown_write_result=original
    slot=record['slot'];status=slot.status()
    with patch.object(type(slot),'status',return_value=dict(status,slotGeneration=status['slotGeneration']+1)):
     with self.assertRaises(ValueError):subject.observe_closed_phase('e'*64)
    protected=next(iter(session.guard._protected));native_read=session.guard._read
    def drift(path):
     row=native_read(path)
     if path=='/v1.45/containers/'+protected+'/json':row['Config']['Env'].append('UNEXPECTED=drift')
     return row
    with patch.object(session.guard,'_read',side_effect=drift):
     with self.assertRaises(ValueError):subject.observe_closed_phase('e'*64)
    start=time.monotonic();ticks=iter((start,start+16))
    with patch.object(broker,'time',SimpleNamespace(monotonic=lambda:next(ticks))):
     with self.assertRaises(ValueError):subject.observe_closed_phase('e'*64)
  result=run_case(self,scene_controller=True,after_reconciled=hook)
  self.assertEqual(result['postCount'],1);self.assertEqual(len(seen),1)
