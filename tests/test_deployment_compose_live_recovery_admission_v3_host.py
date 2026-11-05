"""Real local SSHSIG/HMAC and ledger; Engine and provider are unit fixtures."""
from copy import copy, deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.parse import unquote

from tests.test_deployment_compose_live_admission_v3_host import AdmissionTests
from tests.test_deployment_compose_bundle_v3 import baseline_rows
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, baseline_state_bytes, _plain
from deployment_compose_intent_status_v3 import IntentStatusClientV3
from deployment_compose_recovery_phase_capsule_v3_host import VerifiedRecoveryPhaseV3
from deployment_compose_witness_store import canonical
import deployment_compose_live_admission_v3_host as admission


class RecoveryAdmissionTests(AdmissionTests):
    def material(self):
        value=self.bundle.to_dict();base=baseline_rows(value);rows=deepcopy(base)
        service=value['services'][0];body=service['targetCreateBody'];cid='d'*64
        row=deepcopy(base[service['baselineContainerId']])
        row.update(Id=cid,Name='/dwc-'+value['operationNonce'][:24]+'-web',Image=body['Image'])
        row['Config']={k:deepcopy(v) for k,v in body.items() if k not in ('HostConfig','NetworkingConfig')}
        row['HostConfig']=deepcopy(body['HostConfig'])
        row['State'].update(Pid=0,StartedAt='',Running=False,Status='created')
        rows[cid]=row
        self.version={'Version':'29.8.2','GitCommit':'8af9fe3'}
        def read(path):
            if path.endswith('/version'):return deepcopy(self.version)
            if path.endswith('/info'):return {'ID':self.request.daemon_id}
            if '/containers/json?' in path:return [{'Id':c} for c in rows]
            if '/containers/' in path:return deepcopy(rows[path.split('/')[-2]])
            if '/networks/' in path:
                name,pin=next((n,p) for n,p in value['networks'].items() if p['id']==path.split('/')[-1])
                return dict(Id=pin['id'],Name=name,Labels={'com.docker.compose.project':value['identity']['project']},Containers={c:{} for c in rows})
            if '/volumes/' in path:
                name=unquote(path.split('/')[-1])
                mount=next(m for r in base.values() for m in r['Mounts'] if m.get('Name')==name)
                return dict(Name=name,Driver='local',Options=None,Mountpoint=mount['Source'])
            raise AssertionError(path)
        history=self.host._history(self.host._root);snapshot=history.capture()
        ops=self.bundle.resolve_operations({'web':cid});following=[o for o in ops if o['method']!='GET'][1]
        completed=ops[:ops.index(following)]
        guard=PhaseGuardV3(self.bundle,base,read_json=read,daemon_version=self.version)
        phase=guard.capture_phase(dict(phase_index=1,operation=following,receipts={'web':cid},completed_operations=completed))
        context=dict(schemaVersion=1,kind='compose-recovery-context-v3',originalBundleDigest=self.bundle.digest,
            originalRequestHash=self.request.digest(),baselineStateReference=value['baselineStateReference'],
            baselineStateDigest=value['baselineStateDigest'],historyDigest=snapshot.digest,startWriteIndex=1,
            receiptMap={'web':cid},knownWritePrefix=[self.bundle.creation_operations()[0]],
            completedOperations=completed,nextOperation=following,currentPhaseSnapshot=_plain(phase),
            recoveryNonce='b'*64,expiresAt=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        request=replace(self.request,operation='recovery',history_hash=snapshot.digest,
            observation_hash=hashlib.sha256(canonical(context)).hexdigest(),expires_at=context['expiresAt'])
        self.recovery=request;self.capsule=dict(request=asdict(request),context=context)
        self.baseline=baseline_state_bytes(base)
        self.new_approval,self.new_receipt=self.consume(request)

    def register(self,raw=None,approval=None,receipt=None,**kwargs):
        return self.host.register_recovery(canonical(self.capsule) if raw is None else raw,
            self.new_approval if approval is None else approval,self.new_receipt if receipt is None else receipt,
            baseline_bytes=kwargs.get('baseline_bytes',self.baseline),
            expected_daemon_version=kwargs.get('expected_daemon_version',self.version))

    def state(self):
        return (self.host._root,self.host._current,self.host._pending,dict(self.host._bindings),
            (self.store.root/'state.json').read_bytes())

    def rejected(self,**kwargs):
        before=self.state()
        with self.assertRaises(admission.LiveAdmissionRejected):self.register(**kwargs)
        self.assertEqual(self.state(),before)

    def test_pending_only_then_existing_cas_completes_recovery_history(self):
        self.finish();self.material();before=self.state();posts=self.new_approval.client.posts
        with patch.object(self.store,'register_once',side_effect=AssertionError('write')), patch.object(self.store,'append_event',side_effect=AssertionError('write')), patch.object(self.store,'transition_successor',side_effect=AssertionError('write')), patch('deployment_compose_phase_state_v3_host.TrustedPhaseStateProducerV3._get',side_effect=AssertionError('Engine')):
            child=self.register()
        self.assertEqual(self.new_approval.client.posts,posts)
        self.assertEqual(self.state()[:2],before[:2]);self.assertEqual(self.state()[3:],before[3:])
        self.assertEqual(self.host._pending['index'],1)
        envelopes=[]
        def transport(request):
            result=self.host.authorize_rpc('intent','check',request);envelopes.append(result);return result
        self.assertIsNone(IntentStatusClientV3(self.recovery,self.public[1],transport).check_consumed_intent(self.recovery))
        for name in ('authorityGranted','runtimePermit','productionReady'):
            self.assertIs(envelopes[-1]['payload'][name],False)
        self.transition(child);self.request=self.recovery
        for index in range(1,5):
            self.assertEqual(self.index,index);self.finish()
            if index<4:self.transition()
        history=json.loads(self.host._history(self.host._current).capture().canonical)
        self.assertEqual(history['schemaVersion'],2);self.assertEqual(len(history['knownPrefix']),5)
        self.assertEqual(len(self.store._read()['scopes']),5)
        self.assertTrue(all(s['seq']==6 for s in history['scopes']))
        self.assertIsNone(history['blocker']);self.assertIsNone(self.host._pending)

    def test_old_approval_receipt_and_unverified_consumption_reject(self):
        self.finish();self.material()
        self.rejected(approval=self.approval);self.rejected(receipt=self.consumption)
        unconsumed=copy(self.new_approval);unconsumed._verified_consumptions=set()
        self.rejected(approval=unconsumed,receipt=replace(self.new_receipt))
        for receipt in (replace(self.new_receipt,use_number=True),replace(self.new_receipt,consumed_at='2020-01-01T00:00:00'),replace(self.new_receipt,consumed_at='2099-01-01T00:00:00+00:00')):
            self.rejected(receipt=receipt)

    def test_rehashed_unapproved_nonce_and_wrong_policy_reject(self):
        self.finish();self.material();candidate=deepcopy(self.capsule)
        candidate['context']['recoveryNonce']='c'*64
        candidate['request']['observation_hash']=hashlib.sha256(canonical(candidate['context'])).hexdigest()
        self.rejected(raw=canonical(candidate))
        candidate=deepcopy(self.capsule);candidate['request']['policy_hash']='0'*64
        self.rejected(raw=canonical(candidate))

    def test_raw_capsule_baseline_version_and_phase_checks_are_mandatory(self):
        self.finish();self.material()
        for raw in (True,VerifiedRecoveryPhaseV3(b'{}',b'{}','a'*64,'b'*64)):
            self.rejected(raw=raw)
        for baseline in (True,b'{}',self.baseline+b' '):self.rejected(baseline_bytes=baseline)
        for version in (True,{},dict(Version=True,GitCommit='x')):self.rejected(expected_daemon_version=version)
        changed=deepcopy(self.capsule);changed['context']['currentPhaseSnapshot']['rows']['d'*64]['State']['Pid']=9
        changed['request']['observation_hash']=hashlib.sha256(canonical(changed['context'])).hexdigest()
        self.rejected(raw=canonical(changed))

    def test_capacity_and_last_consent_fail_without_pending_or_store_mutation(self):
        self.finish();self.material()
        with patch.object(admission,'check_witness_byte_capacity',side_effect=ValueError('capacity')):self.rejected()
        real=self.new_approval.check_consumed_intent;calls=[]
        def consent(request):
            calls.append(True)
            if len(calls)==2:raise ValueError('revoked')
            return real(request)
        with patch.object(self.new_approval,'check_consumed_intent',side_effect=consent):self.rejected()
        self.assertEqual(len(calls),2)

    def test_duplicate_and_copied_issuer_reject(self):
        self.finish();self.material();copied=copy(self.host);before=self.state()
        with self.assertRaises(admission.LiveAdmissionRejected):copied.register_recovery(canonical(self.capsule),self.new_approval,self.new_receipt,baseline_bytes=self.baseline,expected_daemon_version=self.version)
        self.assertEqual(self.state(),before)
        self.register();self.rejected()

    def test_final_parent_read_and_expiry_are_rechecked(self):
        self.finish();self.material();original=self.host._history;history=original(self.host._root);real=history.capture;calls=[]
        def capture():
            result=real();calls.append(True)
            if len(calls)==5:return replace(result,canonical=result.canonical+b' ')
            return result
        with patch.object(self.host,'_history',side_effect=lambda entry:history if entry is self.host._root else original(entry)):
            with patch.object(history,'capture',side_effect=capture):self.rejected()
        self.assertEqual(len(calls),5)
        clock=Mock();clock.now.side_effect=[datetime.now(timezone.utc),datetime.now(timezone.utc)+timedelta(hours=2)]
        with patch.object(admission,'datetime',clock):self.rejected()

    def test_actual_parent_advance_at_final_read_is_not_rolled_back_or_registered(self):
        self.finish();self.material();original=self.host._history
        history=original(self.host._root);real=history.capture;calls=[];advanced=[]
        root=self.host._root
        def capture():
            calls.append(True)
            if len(calls)==5:
                # A separate valid old-intent successor wins before registration.
                # Its mutation must survive, with no recovery pending committed.
                with patch.object(self.host,'_history',side_effect=original):self.transition()
                advanced.append(self.state())
            return real()
        with patch.object(self.host,'_history',side_effect=lambda entry:history if entry is root else original(entry)), patch.object(history,'capture',side_effect=capture):
            with self.assertRaises(admission.LiveAdmissionRejected):self.register()
        self.assertEqual(len(advanced),1);self.assertEqual(self.state(),advanced[0])
        self.assertIs(self.host._current,root);self.assertIsNone(self.host._pending)

    def test_fork_rejects_before_held_inherited_lock(self):
        self.finish();self.material();ready=threading.Event();release=threading.Event()
        def hold():
            with self.host._lock:ready.set();release.wait(10)
        thread=threading.Thread(target=hold);thread.start();self.assertTrue(ready.wait(5))
        pid=os.fork()
        if pid==0:
            import signal
            signal.alarm(3)
            try:self.register()
            except admission.LiveAdmissionRejected:os._exit(0)
            except BaseException:os._exit(2)
            os._exit(1)
        try:
            _,status=os.waitpid(pid,0);self.assertEqual(status,0)
        finally:release.set();thread.join(5)

    def test_open_unknown_and_complete_parent_are_rejected(self):
        self.finish();self.material();self.transition();self.scope();self.rejected()

    def test_root_open_prepared_and_admitted_are_rejected(self):
        self.material();self.rejected()
        with patch.object(admission.FileWriterGate,'admit',side_effect=ValueError('pause before admit')):
            with self.assertRaises(ValueError):self.scope()
        self.assertEqual(self.store.read(self.binding)['phase'],'prepared');self.rejected()

    def test_root_admitted_is_rejected(self):
        self.material();self.scope()
        self.assertEqual(self.store.read(self.binding)['phase'],'admitted');self.rejected()

    def test_unknown_response_parent_is_rejected(self):
        self.finish();self.material();self.transition();self.finish(unknown=True);self.rejected()

    def test_complete_parent_is_rejected(self):
        self.finish();self.material()
        for _ in range(4):self.transition();self.finish()
        self.rejected()


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(RecoveryAdmissionTests(n) for n in RecoveryAdmissionTests.__dict__ if n.startswith('test_'))
