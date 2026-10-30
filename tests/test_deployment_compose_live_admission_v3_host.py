"""Real local store/SSHSIG/Gate with mocked consumed GitHub authority; no network."""
import base64
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_bundle_v3 import fixture,bind_baseline
from tests import test_deployment_compose_approval_v3_host as approvals
from tests.test_release_host import claims
from deployment_compose_bundle_v3 import ExecutionBundleV3,FIELDS
from deployment_compose_approval_v3_host import GitHubFullBodyApprovalV3,AUDIENCE
from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3, LiveAdmissionRejected
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_intent_status_v3 import IntentStatusClientV3
from deployment_compose_witness_store import canonical,ZERO
from deployment_gate_witness import key_material
from deployment_gateway import FileWriterGate,GatePolicy


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.signers=[];self.public=[]
        for name in ('witness','intent'):
            key=self.root/(name+'-signing')
            subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],
                           check=True,capture_output=True)
            key.chmod(0o600);self.signers.append(key);self.public.append(key.with_suffix('.pub').read_bytes())
        directory=self.root/'witness';directory.mkdir(mode=0o700)
        self.store=OperationWitnessStoreV3(directory,key=b'w'*32);self.addCleanup(self.store.close)
        self.gate_key=b'g'*32
        self.policy=GatePolicy('live-test','gate-key','a'*64,'b'*64,True,'c'*64,
            hashlib.sha256(key_material(self.public[0])).hexdigest(),operation_profile='compose-v3')
        self.host=MacLiveAdmissionV3(store=self.store,gate_policy=self.policy,gate_key=self.gate_key,
            witness_signer=self.signers[0],witness_public_key=self.public[0],
            intent_signer=self.signers[1],intent_public_key=self.public[1])
        value,defaults=fixture();request=approvals.request(components=('web',),protected_components=('db',))
        value['identity']=dict(hostId=request.host_id,daemonId=request.daemon_id,project=request.target.namespace,
                               sourceIdentity=canonical(asdict(request.source)).decode())
        for service in value['services']:
            for field in ('baselineCreateBody','targetCreateBody'):
                service[field]['Labels']['com.docker.compose.project']=request.target.namespace
        bind_baseline(value)
        self.bundle=ExecutionBundleV3(value,authenticated_image_defaults=defaults);self.defaults=defaults
        self.request=replace(request,plan_hash=self.bundle.digest,policy_hash=self.policy.identity_hash(),
            after_hash=hashlib.sha256(canonical({s['name']:s['targetCreateBody'] for s in value['services']})).hexdigest())
        self.approval,self.consumption=self.consume(self.request)
        self.binding=self.host.register_intent(self.bundle,self.request,self.approval,self.consumption)
        self.receipts={};self.index=0;self.evidence=[]

    def consume(self,request):
        harness=approvals.ComposeApprovalTests();harness.setUp()
        harness.policy=approvals.policy(operation=request.operation,source_sha=request.source.source_sha,
            target=request.target,components=request.components,protected_components=request.protected_components,
            policy_hash=request.policy_hash,bundle_hash=request.plan_hash,expected_history_hash=request.history_hash)
        harness.claims=dict(claims(harness.policy),aud=AUDIENCE)
        harness.client=harness.client_for([request])
        authority=harness.approval([request])
        return authority,authority.consume(authority.validate(request),request)

    def client(self,binding=None):
        return OperationWitnessClientV3(binding or self.binding,self.public[0],
            lambda method,request:self.host.authorize_rpc('witness',method,request))

    def scope(self,bundle=None,request=None):
        bundle=bundle or self.bundle;request=request or self.request
        ops=bundle.resolve_operations(self.receipts) if len(self.receipts)==len(bundle.to_dict()['services']) else bundle.creation_operations()
        op=[o for o in ops if o['method']!='GET'][self.index]
        context=self.host._bindings[canonical(self.binding)]
        desc=context['descriptor']
        gate=FileWriterGate(replace(self.policy,witness_scope_hash=self.binding['scopeHash']),
            self.root/('gate-'+self.binding['generation']),key=self.gate_key,
            witness=GateOperationWitnessAdapterV3(self.client()))
        session=gate.open_generation(generation=self.binding['generation'],request_hash=request.digest(),
            receipt_hash=context['entry']['receiptHash'],operations=desc['operations'],source_context_digest=desc['source'])
        raw=b'' if op['body'] is None else canonical(op['body'])
        attempt=session.prepare_attempt(op['method'],op['path'],raw)
        ticket=gate.admit(self.binding['generation'],attempt.ref,method=op['method'],path=op['path'],
            body=raw,writer_certificate_sha256=self.policy.writer_certificate_sha256)
        return gate,ticket,op

    def finish(self,*,unknown=False):
        gate,ticket,op=self.scope()
        cid=('d' if self.request.operation=='deploy' else 'f')*64
        raw=canonical({'Id':cid}) if op['phase']=='create' else b''
        gate.finish_response(ticket,definitive=not unknown,status=0 if unknown else (201 if op['phase']=='create' else 204),
                             body=b'' if unknown else raw)
        if not unknown:gate.close_generation(self.binding['generation'])
        if op['phase']=='create' and not unknown:self.receipts[op['service']]=cid
        return gate

    def transition(self,child=None):
        snapshot=self.host._history(self.host._current).capture()
        value=json.loads(snapshot.canonical)
        scope=self.host._scope(self.host._current,len(value['knownPrefix']),value['receiptMap']) if child is None else None
        child=scope['binding'] if child is None else child
        client=self.client();view=client.read()
        client.transition_successor(expected_seq=view['seq'],expected_head=view['head'],childBinding=child)
        self.binding=child;self.index+=1

    def test_real_gate_two_steps_and_separate_intent_signature(self):
        intent=IntentStatusClientV3(self.request,self.public[1],
            lambda request:self.host.authorize_rpc('intent','check',request))
        self.assertIsNone(intent.check_consumed_intent(self.request))
        self.finish();self.transition();self.finish()
        value=json.loads(self.host._history(self.host._current).capture().canonical)
        self.assertEqual([o['phase'] for o in value['knownPrefix']],['create','stop'])
        self.assertEqual(len(self.store._read()['scopes']),2)
        self.assertEqual(value['receiptMap'],{'web':'d'*64})

    def test_forged_transition_and_replayed_nonce_leave_store_unchanged(self):
        self.finish();before=self.store._seal(self.store._read())
        with self.assertRaises(ValueError):self.transition(dict(self.binding,generation='e'*64,scopeHash='f'*64))
        self.assertEqual(self.store._seal(self.store._read()),before)
        request=dict(binding=self.binding,bootNonce=secrets.token_hex(32),rpcNonce=secrets.token_hex(32))
        self.host.authorize_rpc('witness','read',request)
        with self.assertRaises(ValueError):self.host.authorize_rpc('witness','read',request)
        self.transition()

    def test_invalid_full_open_operation_hmac_and_foreign_binding_before_mutation(self):
        scope=self.host._bindings[canonical(self.binding)];desc=scope['descriptor']
        opening=dict(request_hash=self.request.digest(),receipt_hash=scope['entry']['receiptHash'],
            operations=[list(x) for x in desc['operations']],source_binding_schema=1,source_context_digest=desc['source'])
        for mutation in ('operation','hmac','foreign','policy-type'):
            data=deepcopy(opening)
            if mutation=='operation':data['operations'][0][1]='/v1.45/containers/'+'0'*64+'/start'
            payload=dict(generation=self.binding['generation'],directory=[1,2],previous=ZERO,kind='open',data=data)
            import hmac
            envelope=dict(version=1,domain='dev-workflow.writer-gate.event',policy=self.policy._binding(),payload=payload)
            if mutation=='policy-type':envelope['policy']['witness_binding_schema']=True
            envelope['mac']=hmac.new(self.gate_key,canonical(envelope),hashlib.sha256).hexdigest()
            if mutation=='hmac':envelope['mac']='0'*64
            raw=canonical(envelope);binding=self.binding if mutation!='foreign' else dict(self.binding,generation='0'*64)
            event=dict(binding=binding,sequence=1,previousHead=ZERO,kind='open',data={},materialDigest=hashlib.sha256(raw).hexdigest())
            before=self.store._seal(self.store._read())
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                self.client(binding).append_event(expected_seq=0,expected_head=ZERO,event=event,external_material=raw)
            self.assertEqual(self.store._seal(self.store._read()),before)

    def test_unknown_permanently_blocks_next_scope(self):
        self.finish(unknown=True)
        value=json.loads(self.host._history(self.host._current).capture().canonical)
        self.assertEqual(value['blocker'],'unknown-response')
        with self.assertRaises(ValueError):self.transition(dict(self.binding,generation='e'*64,scopeHash='f'*64))
        self.assertEqual(len(self.store._read()['scopes']),1)

    def test_create_receipt_collision_blocks_independent_successor_derivation(self):
        gate,ticket,_=self.scope()
        gate.finish_response(ticket,definitive=True,status=201,body=canonical({'Id':'2'*64}))
        gate.close_generation(self.binding['generation'])
        value=json.loads(self.host._history(self.host._current).capture().canonical)
        self.assertEqual(value['blocker'],'unusable-receipt')
        with self.assertRaises(ValueError):self.transition(dict(self.binding,generation='e'*64,scopeHash='f'*64))
        self.assertEqual(len(self.store._read()['scopes']),1)

    def test_no_remote_registration_reset_or_generic_service(self):
        before=self.store._seal(self.store._read())
        for service,method in (('witness','register_once'),('witness','reset'),('shell','execute')):
            request=dict(binding=self.binding,bootNonce=secrets.token_hex(32),rpcNonce=secrets.token_hex(32))
            with self.assertRaises(ValueError):self.host.authorize_rpc(service,method,request)
        self.assertEqual(self.store._seal(self.store._read()),before)

    def test_revoked_after_admit_records_outcome_then_blocks_next_scope(self):
        gate,ticket,op=self.scope()
        with patch.object(self.approval,'check_consumed_intent',side_effect=ValueError('revoked')):
            gate.finish_response(ticket,definitive=True,status=201,body=canonical({'Id':'d'*64}))
            gate.close_generation(self.binding['generation'])
            self.assertEqual(self.store.read(self.binding)['phase'],'closed')
            with self.assertRaises(ValueError):self.transition()
        self.assertEqual(len(self.store._read()['scopes']),1)

    def test_revoked_consent_blocks_open_before_store_mutation(self):
        with patch.object(self.approval,'check_consumed_intent',side_effect=ValueError('revoked')):
            with self.assertRaises(ValueError):self.scope()
        self.assertEqual(self.store.read(self.binding)['seq'],0)

    def test_freshly_consumed_wrong_gate_policy_rejected_before_consent_or_write(self):
        directory=self.root/'wrong-policy-witness';directory.mkdir(mode=0o700)
        store=OperationWitnessStoreV3(directory,key=b'z'*32);self.addCleanup(store.close)
        host=MacLiveAdmissionV3(store=store,gate_policy=self.policy,gate_key=self.gate_key,
            witness_signer=self.signers[0],witness_public_key=self.public[0],
            intent_signer=self.signers[1],intent_public_key=self.public[1])
        request=replace(self.request,policy_hash='0'*64)
        approval,receipt=self.consume(request)
        with patch.object(approval,'check_consumed_intent') as check:
            with self.assertRaises(ValueError):host.register_intent(self.bundle,request,approval,receipt)
            check.assert_not_called()
        self.assertFalse((directory/'state.json').exists())
        self.assertIsNone(host._current)
        self.assertEqual(host._bindings,{})

    def test_consumed_registration_retries_read_without_reconsuming(self):
        from deployment_compose_live_review_v3_host import _ReadRetryGitHubClient as ReadRetryGitHubClient
        directory=self.root/'retry-witness';directory.mkdir(mode=0o700)
        store=OperationWitnessStoreV3(directory,key=b'z'*32);self.addCleanup(store.close)
        host=MacLiveAdmissionV3(store=store,gate_policy=self.policy,gate_key=self.gate_key,
            witness_signer=self.signers[0],witness_public_key=self.public[0],
            intent_signer=self.signers[1],intent_public_key=self.public[1])
        original=self.approval.client;posts=original.posts;methods=[]
        def transport(method,path,payload):
            methods.append(method)
            if len(methods)==1:raise OSError('transient synthetic failure')
            value,headers=original.request(method,path,payload)
            return 200,headers,value
        self.approval.client=ReadRetryGitHubClient('synthetic-test-only',transport=transport)
        with patch('deployment_compose_live_review_v3_host.time.sleep'):
            binding=host.register_intent(self.bundle,self.request,self.approval,self.consumption)
        self.assertEqual(store.read(binding)['seq'],0)
        self.assertEqual(original.posts,posts)
        self.assertTrue(all(method=='GET' for method in methods))
        self.assertGreater(len(methods),1)

    def test_registration_network_failure_has_private_stage_and_no_state(self):
        from release_github import GitHubUnavailable
        directory=self.root/'network-witness';directory.mkdir(mode=0o700)
        store=OperationWitnessStoreV3(directory,key=b'z'*32);self.addCleanup(store.close)
        host=MacLiveAdmissionV3(store=store,gate_policy=self.policy,gate_key=self.gate_key,
            witness_signer=self.signers[0],witness_public_key=self.public[0],
            intent_signer=self.signers[1],intent_public_key=self.public[1])
        with patch.object(self.approval,'check_consumed_intent',side_effect=GitHubUnavailable('private-secret')):
            with self.assertRaises(LiveAdmissionRejected) as caught:
                host.register_intent(self.bundle,self.request,self.approval,self.consumption)
        self.assertEqual(caught.exception.stage,'consent')
        self.assertEqual(caught.exception.cause_type,'GitHubUnavailable')
        self.assertNotIn('private-secret',str(caught.exception))
        self.assertFalse((directory/'state.json').exists())
        self.assertIsNone(host._current)

    def test_registration_capacity_fails_before_register_once(self):
        directory=self.root/'second-witness';directory.mkdir(mode=0o700)
        store=OperationWitnessStoreV3(directory,key=b'z'*32);self.addCleanup(store.close)
        host=MacLiveAdmissionV3(store=store,gate_policy=self.policy,gate_key=self.gate_key,
            witness_signer=self.signers[0],witness_public_key=self.public[0],
            intent_signer=self.signers[1],intent_public_key=self.public[1])
        with patch('deployment_compose_live_admission_v3_host.check_witness_byte_capacity',side_effect=ValueError('capacity')):
            with self.assertRaises(ValueError):host.register_intent(self.bundle,self.request,self.approval,self.consumption)
        self.assertFalse((directory/'state.json').exists())

    def test_registration_receipt_request_and_signer_substitution_rejected(self):
        for receipt in (replace(self.consumption,request_hash='0'*64),replace(self.consumption,use_number=2),
                        replace(self.consumption,grant_id='untrusted')):
            with self.assertRaises(ValueError):self.host.register_intent(self.bundle,self.request,self.approval,receipt)
        with self.assertRaises(ValueError):
            self.host.register_intent(self.bundle,replace(self.request,after_hash='0'*64),self.approval,self.consumption)
        with self.assertRaises(ValueError):
            MacLiveAdmissionV3(store=self.store,gate_policy=self.policy,gate_key=self.gate_key,
                witness_signer=self.signers[0],witness_public_key=self.public[0],
                intent_signer=self.signers[0],intent_public_key=self.public[0])

    def test_complete_five_step_deploy_then_new_inverse_rollback(self):
        for index in range(5):
            if index:self.transition()
            self.finish()
        snapshot=self.host._history(self.host._current).capture()
        old=self.bundle.to_dict();value={k:v for k,v in old.items() if k in FIELDS}
        service=value['services'][0];before=deepcopy(service)
        service.update(baselineContainerId='d'*64,baselineImageId=before['targetImageId'],targetImageId=before['baselineImageId'],
            baselineCreateBody=before['targetCreateBody'],targetCreateBody=before['baselineCreateBody'])
        value['operationNonce']='e'*64
        # The new baseline digest is supplied by host preparation; this admission
        # test exercises the signed history/body inverse, not daemon freshness.
        bundle=ExecutionBundleV3(value,authenticated_image_defaults=self.defaults)
        request=replace(self.request,operation='rollback',history_hash=snapshot.digest,plan_hash=bundle.digest,
            after_hash=hashlib.sha256(canonical({service['name']:service['targetCreateBody']})).hexdigest())
        approval,receipt=self.consume(request)
        pending=self.host.register_intent(bundle,request,approval,receipt,reviewed_parent=snapshot)
        self.assertEqual(len(self.store._read()['scopes']),5)
        intent=IntentStatusClientV3(request,self.public[1],lambda r:self.host.authorize_rpc('intent','check',r))
        self.assertIsNone(intent.check_consumed_intent(request))
        self.transition(pending)
        self.bundle,self.request,self.receipts,self.index=bundle,request,{},0
        self.finish()
        value=json.loads(self.host._history(self.host._current).capture().canonical)
        self.assertEqual(value['schemaVersion'],2)
        self.assertEqual(value['parent']['scopeCount'],5)
        self.assertEqual(len(value['knownPrefix']),1)
        self.assertEqual(len(self.store._read()['scopes']),6)


if __name__=='__main__':unittest.main()
