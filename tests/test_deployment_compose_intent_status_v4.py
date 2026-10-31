"""Real signatures; synthetic consumed status only, no approval service or ledger."""
import base64
from dataclasses import replace
from datetime import datetime,timedelta,timezone
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'packs/deployment/scripts'),str(ROOT/'scripts')]
import deployment_compose_intent_status_v4 as status
from tests import test_deployment_compose_approval_v3_host as fixture


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX OpenSSH signatures')
class IntentStatusV4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        for name in ('key','other'):
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(cls.root/name)],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def setUp(self):
        self.request=fixture.request(profile_version='4')
        self.calls=[];self.changes={};self.namespace=status.NAMESPACE;self.key='key';self.extra=None
        self.settings=dict(session_hash='1'*64,context_digest=self.request.observation_hash,
            policy_hash=self.request.policy_hash,actor_epoch='2'*64,scope_ordinal=0,plan_write_index=0,
            action_digest='3'*64,consumption_receipt_hash='4'*64)
        self.client=self.make()

    def make(self,request=None,**changes):
        return status.IntentStatusClientV4(request or self.request,(self.root/'key.pub').read_bytes(),self.transport,
                                          **dict(self.settings,**changes))

    def transport(self,rpc):
        self.calls.append(rpc)
        now=int(time.time())
        payload=dict(rpc,purpose=status.REPLY_PURPOSE,issuedAt=now,expiresAt=now+30,
            consumptionReceiptHash='4'*64,consumed=True,authorityGranted=False,runtimePermit=False,productionReady=False)
        payload.update(self.changes)
        if self.extra:payload[self.extra]=True
        signature=subprocess.run(['ssh-keygen','-Y','sign','-f',str(self.root/self.key),'-n',self.namespace],
            input=status.encode(payload),check=True,capture_output=True).stdout
        return dict(payload=payload,signature=base64.b64encode(signature).decode('ascii'))

    def test_success_is_non_authorizing_and_every_call_is_fresh(self):
        first=self.client.check_consumed_intent(self.request);second=self.client.check_consumed_intent(self.request)
        self.assertEqual(len(self.calls),2)
        self.assertNotEqual(first['rpcNonce'],second['rpcNonce'])
        for key in ('authorityGranted','runtimePermit','productionReady'):self.assertIs(first[key],False)
        self.assertEqual(set(self.calls[0]),status.REQUEST_FIELDS)
        self.assertEqual(set(first),status.RESPONSE_FIELDS)

    def test_prepared_recovery_profile_accepted_but_wrong_profiles_rejected(self):
        recovery=replace(self.request,operation='recovery',profile_id='compose-recovery-v4',history_hash='5'*64)
        self.make(recovery).check_consumed_intent(recovery)
        for req in (replace(self.request,profile_version='3'),replace(self.request,production=True),
                    replace(self.request,operation='rollback',history_hash='5'*64),
                    replace(self.request,profile_id='compose-recovery-v4')):
            with self.assertRaises(status.IntentStatusRejected):self.make(req)
        self.assertEqual(len(self.calls),1)

    def test_wrong_key_or_v3_signature_domain_rejected(self):
        for key,namespace in [('other',status.NAMESPACE),('key','dev-workflow-compose-consumed-intent-status-v3')]:
            self.key,self.namespace=key,namespace
            with self.assertRaises(status.IntentStatusRejected) as caught:self.client.check_consumed_intent(self.request)
            self.assertEqual(caught.exception.stage,'signature-verification')
        self.assertEqual(len(self.calls),2)

    def test_every_binding_and_receipt_drift_rejected(self):
        changes=dict(sessionHash='a'*64,requestHash='b'*64,contextDigest='c'*64,policyHash='d'*64,
            actorEpoch='e'*64,scopeOrdinal=1,planWriteIndex=1,actionDigest='f'*64,bootNonce='0'*64,rpcNonce='0'*64,
            consumptionReceiptHash='0'*64,schemaVersion=True,consumed=1,authorityGranted=True,runtimePermit=True)
        for field,value in changes.items():
            self.changes={field:value}
            with self.subTest(field=field),self.assertRaises(status.IntentStatusRejected):self.client.check_consumed_intent(self.request)
        self.assertEqual(len(self.calls),len(changes))

    def test_closed_shape_and_no_json_or_fake_consumption_input(self):
        self.extra='approved'
        with self.assertRaises(status.IntentStatusRejected):self.client.check_consumed_intent(self.request)
        for receipt in ({'consumed':True},True,None):
            with self.assertRaises(status.IntentStatusRejected):self.make(consumption_receipt_hash=receipt)
        for field in ('scope_ordinal','plan_write_index'):
            with self.assertRaises(status.IntentStatusRejected):self.make(**{field:False})
        with patch.object(self.client,'_transport',return_value='{"payload":1,"payload":2}'):
            with self.assertRaises(status.IntentStatusRejected):self.client.check_consumed_intent(self.request)

    def test_transport_failure_never_retries_and_request_drift_never_calls(self):
        with patch.object(self.client,'_transport',side_effect=OSError('private details')) as transport:
            with self.assertRaises(status.IntentStatusRejected) as caught:self.client.check_consumed_intent(self.request)
            self.assertEqual(str(caught.exception),'intent-status-v4-rejected');self.assertEqual(transport.call_count,1)
            with self.assertRaises(status.IntentStatusRejected):self.client.check_consumed_intent(replace(self.request,host_id='other'))
            self.assertEqual(transport.call_count,1)

    def test_time_bounds_strict_integers_future_and_expired(self):
        now=int(time.time())
        for changes in ({'issuedAt':True},{'expiresAt':True},{'issuedAt':now+10,'expiresAt':now+20},
                        {'issuedAt':now-40,'expiresAt':now-10},{'issuedAt':now,'expiresAt':now+31}):
            self.changes=changes
            with self.subTest(changes=changes),self.assertRaises(status.IntentStatusRejected):self.client.check_consumed_intent(self.request)

    def test_one_second_lag_waits_without_accepting_future(self):
        now=int(time.time());self.changes={'issuedAt':now,'expiresAt':now+30}
        with patch.object(status.time,'time',side_effect=[now,now-1,now]),patch.object(status.time,'sleep') as sleep:
            self.client.check_consumed_intent(self.request)
        sleep.assert_called_once_with(1)

    def test_response_cannot_outlive_exact_request_expiry(self):
        request=replace(self.request,expires_at=(datetime.now(timezone.utc)+timedelta(seconds=10)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        with self.assertRaises(status.IntentStatusRejected):self.make(request).check_consumed_intent(request)
        expired=replace(self.request,expires_at='2020-01-01T00:00:00Z')
        with self.assertRaises(status.IntentStatusRejected):self.make(expired).check_consumed_intent(expired)

    def test_transport_mutation_during_verification_cannot_change_signed_result(self):
        captured={}; run=subprocess.run
        def transport(rpc):
            reply=self.transport(rpc);captured['payload']=reply['payload'];return reply
        def verify(argv,**kwargs):
            if argv[:3]==['ssh-keygen','-Y','verify']:
                captured['payload']['runtimePermit']=True
                captured['payload']['actionDigest']='0'*64
            return run(argv,**kwargs)
        with patch.object(self.client,'_transport',side_effect=transport),patch.object(status.subprocess,'run',side_effect=verify):
            result=self.client.check_consumed_intent(self.request)
        self.assertTrue(captured['payload']['runtimePermit'])
        self.assertIs(result['runtimePermit'],False)
        self.assertEqual(result['actionDigest'],'3'*64)
