"""Signed partial history and real private CAS; daemon reads are trusted unit seams."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
import shutil
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_prepare_v3_host import fixture
from tests import test_deployment_compose_history_v3_host as signed
from deployment_compose_phase_guard_v3_host import PhaseGuardV3
from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
from deployment_compose_witness_store import canonical


def expiry():
    return (datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class RecoveryPreparationTests(unittest.TestCase):
    def setUp(self):
        from deployment_compose_prepare_v3_host import ComposePreparationHostV3
        kw,observation=fixture();self.kw=kw
        prepared=ComposePreparationHostV3(**kw).prepare_intent(observation,observation,
            operation_nonce='f'*64,expires_at=expiry())
        self.bundle=prepared['bundle'];self.store=kw['recovery']._store
        self.original=replace(prepared['request'],expires_at='2020-01-01T00:00:00Z')
        h=signed.HistoryTests('test_two_scopes_and_no_local_files');h.setup_gate_fixture()
        self.addCleanup(h.doCleanups)
        h.bundle=self.bundle;h.req=self.original;h.receipts={};h.index=0;h.open_scope()
        self.signed=h
        self.rows=deepcopy(kw['whole_observer']._unit_rows)
        self.version={'Version':'29.8.2','GitCommit':'8af9fe3'}
        self.guard=PhaseGuardV3(self.bundle,self.rows,read_json=self.read,daemon_version=self.version)
        self.ready_calls=[]
        def ready(service,cid):self.ready_calls.append((service,cid));return True
        self.ready=ready
        self.close_create()

    def close_create(self):
        h=self.signed;h.finish();h.receipts={'web':'a'*64}
        service=self.bundle.to_dict()['services'][0];body=service['targetCreateBody']
        row=deepcopy(self.rows[service['baselineContainerId']])
        row.update(Id='a'*64,Name='/dwc-'+'f'*24+'-web',Image=body['Image'])
        row['Config']['Image']=body['Image']
        row['State'].update(Pid=0,StartedAt='',Running=False,Status='created')
        self.rows['a'*64]=row

    def read(self,path):
        if path.endswith('/version'):return deepcopy(self.version)
        if path.endswith('/info'):return {'ID':self.kw['daemon_id']}
        if '/containers/json?' in path:return [{'Id':cid} for cid in self.rows]
        if '/containers/' in path:return deepcopy(self.rows[path.split('/')[-2]])
        if '/networks/' in path:
            name,pin=next(iter(self.bundle.to_dict()['networks'].items()))
            return dict(Id=pin['id'],Name=name,Labels={'com.docker.compose.project':'dw-test'},Containers={cid:{} for cid in self.rows})
        if '/volumes/' in path:
            name=path.split('/')[-1]
            return dict(Name=name,Driver='local',Options=None,Mountpoint='/var/lib/docker/volumes/'+name+'/_data')
        raise AssertionError(path)

    def host(self):
        return RecoveryPreparationHostV3(original_history=self.signed.history(),store=self.store,
                                         phase_guard=self.guard,readiness=self.ready)

    def prepare(self):
        return self.host().prepare_intent(operation_nonce='b'*64,expires_at=expiry())

    def test_fresh_recovery_request_preserves_original_bundle_and_fields(self):
        host=self.host();value=host.prepare_intent(operation_nonce='b'*64,expires_at=expiry())
        self.assertIs(value['bundle'],self.bundle)
        request=value['request'];context=host.verify_context(value['recovery_context_reference'],request,value['reviewed_history'])
        self.assertEqual(request.operation,'recovery')
        self.assertEqual(context['startWriteIndex'],1)
        self.assertEqual(context['receiptMap'],{'web':'a'*64})
        self.assertEqual(context['nextOperation']['phase'],'stop')
        self.assertEqual([op['phase'] for op in context['completedOperations']],['create'])
        expected=replace(self.original,operation='recovery',history_hash=value['reviewed_history'].digest,
            observation_hash=request.observation_hash,expires_at=request.expires_at)
        self.assertEqual(request,expected)
        self.assertFalse(value['review']['authorityGranted'])
        self.assertNotIn('Env',json.dumps(value['review']))

    def test_forged_offset_receipts_and_private_snapshot_rejected(self):
        host=self.host();value=host.prepare_intent(operation_nonce='b'*64,expires_at=expiry())
        original=host.verify_context(value['recovery_context_reference'],value['request'],value['reviewed_history'])
        for field,bad in (('startWriteIndex',2),('receiptMap',{'web':'c'*64}),('currentPhaseSnapshot',{})):
            context=deepcopy(original);context[field]=bad;raw=canonical(context)
            reference=self.store.put(raw)
            import hashlib
            request=replace(value['request'],observation_hash=hashlib.sha256(raw).hexdigest())
            with self.subTest(field=field),self.assertRaises(ValueError):
                host.verify_context(reference,request,value['reviewed_history'])

    def test_reviewed_history_and_request_identity_cannot_be_substituted(self):
        from deployment_compose_history_v3_host import AuthenticatedHistorySnapshotV3
        host=self.host();value=host.prepare_intent(operation_nonce='b'*64,expires_at=expiry())
        original=value['request']
        for request in (replace(original,after_hash='c'*64),replace(original,history_hash='c'*64)):
            with self.assertRaises(ValueError):
                host.verify_context(value['recovery_context_reference'],request,value['reviewed_history'])
        forged=json.loads(value['reviewed_history'].canonical)
        forged['receiptMap']['web']='c'*64
        with self.assertRaises(ValueError):
            host.verify_context(value['recovery_context_reference'],original,
                AuthenticatedHistorySnapshotV3(canonical(forged)))

    def test_current_drift_and_missing_original_baseline_fail_closed(self):
        host=self.host();value=host.prepare_intent(operation_nonce='b'*64,expires_at=expiry())
        self.rows['a'*64]['Config']['Env'].append('DRIFT=secret')
        with self.assertRaises(ValueError):
            host.verify_context(value['recovery_context_reference'],value['request'],value['reviewed_history'])
        get=self.store.get;baseline=self.bundle.to_dict()['baselineStateReference']
        def missing(reference):
            if reference==baseline:raise ValueError('missing')
            return get(reference)
        with patch.object(self.store,'get',side_effect=missing),self.assertRaises(ValueError):self.host()
        with patch.object(self.store,'get',return_value=b'{}'),self.assertRaises(ValueError):self.host()

    def test_open_and_unknown_scope_fail_closed(self):
        h=self.signed;h.index=1;h.open_scope()
        with self.assertRaises(ValueError):self.prepare()
        h.finish(status=0,body=b'',definitive=False)
        with self.assertRaises(ValueError):self.prepare()

    def test_invalid_nonce_and_expiry_rejected(self):
        host=self.host()
        for nonce,expires in [('bad',expiry()),('b'*64,'2020-01-01T00:00:00Z'),
                              ('b'*64,'2099-01-01T00:00:00Z')]:
            with self.subTest(nonce=nonce,expires=expires),self.assertRaises(ValueError):
                host.prepare_intent(operation_nonce=nonce,expires_at=expires)

    def test_capture_phase_is_private_immutable_and_context_checked(self):
        receipts={'web':'a'*64};ops=self.bundle.resolve_operations(receipts)
        context=dict(phase_index=1,operation=ops[1],receipts=receipts,completed_operations=ops[:1])
        captured=self.guard.capture_phase(context)
        with self.assertRaises(TypeError):captured['rows']['a'*64]['Config']['Env']=()
        self.assertIs(self.guard(context),True)
        shared={'facts':{'counter':0}};calls=[]
        def shared_capture(*args):
            if calls:shared['facts']['counter']=1
            calls.append(True)
            return shared
        with patch.object(self.guard,'_capture',side_effect=shared_capture),self.assertRaises(ValueError):
            self.guard.capture_phase(context)
        context['phase_index']=2
        with self.assertRaises(ValueError):self.guard.capture_phase(context)


if __name__=='__main__':unittest.main()
