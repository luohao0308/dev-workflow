"""Local protocol wiring, plus opt-in delegated Linux/Unix Engine-double checks.

Pipe mocks prove framing only, never SSH or isolation. The Linux checks retain
real owned transport/fence/witness evidence; no Docker or real GitHub is used.
"""
import os
import base64
import json
import ssl
import subprocess
from contextlib import nullcontext
from dataclasses import replace
import hashlib
import tempfile
from dataclasses import dataclass
from types import SimpleNamespace
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
for directory in ('scripts','tests/support','packs/deployment/scripts'):
    sys.path.insert(0,str(ROOT/directory))
import deployment_compose_owned_recovery_worker_v3_host as worker
from deployment_compose_v3_channel_worker import read_frame, write_frame
from tests.test_deployment_compose_owned_recovery_fence_v3_host import OwnedRecoveryTests


def config():
    return dict(entrypoint=worker.ENTRYPOINT,channelNonce='1'*64,sourceSha='b'*40,
                archiveDigest='2'*64,hostId='private-host')


class ProtocolTests(unittest.TestCase):
    def test_fixed_entry_does_not_change_old_channel(self):
        old = worker.live.ENTRYPOINT
        worker.Channel(config(),None,None)
        self.assertEqual(worker.live.ENTRYPOINT,old)
        for changed in (dict(config(),entrypoint=old),dict(config(),program='x'),dict(config(),channelNonce='bad')):
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                worker.Channel(changed,None,None)
        with self.assertRaises(ValueError):worker.live.Channel(config(),None,None)

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'get_blocking'), 'POSIX pipe framing required')
    def test_pipe_order_and_nonce_fail_closed(self):
        for frame in (dict(kind='configure',channelNonce='0'*64),
                      dict(kind='consume-intent',channelNonce='1'*64)):
            readfd,writefd=os.pipe()
            with os.fdopen(readfd,'rb',buffering=0) as incoming,os.fdopen(writefd,'wb',buffering=0) as outgoing:
                write_frame(outgoing,frame,timeout=2)
                channel=worker.Channel(config(),incoming,None)
                with self.assertRaises(ValueError):channel.receive('configure')
                self.assertTrue(channel.failed)

    def test_consume_requires_all_exact_reference_and_binding_fields(self):
        bundle=Mock();request=Mock();request.digest.return_value='a'*64
        policy=Mock();policy.identity_hash.return_value='b'*64
        binding=dict(scopeHash='c'*64,generation='d'*64,policyHash='b'*64,epoch='e'*64)
        refs=dict(requestHash='a'*64,receiptHash='f'*64,firstBinding=binding)
        channel=Mock();channel.receive.return_value=refs
        with patch.object(worker.Profile3StepExecutor,'scope_descriptor',return_value=dict(scopeHash='c'*64,generation='d'*64)) as descriptor:
            self.assertEqual(worker.consume(channel,bundle,request,policy,'e'*64,{'phase':'stop'},1,{'backend':'9'*64}),('f'*64,binding))
            self.assertEqual(descriptor.call_args.args[-2:],(1,{'backend':'9'*64}))
            changed=[dict(refs,extra=True),dict(refs,requestHash='0'*64),dict(refs,receiptHash='bad')]
            for field in binding:
                changed.append(dict(refs,firstBinding=dict(binding,**{field:'0'*64})))
            changed.append(dict(refs,firstBinding=dict(binding,extra='0'*64)))
            for value in changed:
                channel.receive.return_value=value
                with self.subTest(value=value),self.assertRaises(ValueError):
                    worker.consume(channel,bundle,request,policy,'e'*64,{},1,{})

    def test_nondelegate_preflight_stops_before_probe(self):
        with patch.object(worker,'WriterCgroupV3',side_effect=ValueError('not-delegated')) as group, \
                patch('deployment_compose_profile3_prepare_ssh_probe._probe') as probe:
            with self.assertRaisesRegex(ValueError,'not-delegated'):worker.run(config(),None,None)
            probe.assert_not_called()
            group.assert_called_once_with('0'*64,'0'*64,65534,65534)

    def test_final_requires_outer_stop_cleanup_and_snapshot(self):
        payload=dict(success=True,cleanupCompleted=True,productionReady=False)
        report=dict(completed=True,stopped=True,productionSnapshotUnchanged=True)
        channel=Mock()
        for field in report:
            with self.subTest(field=field),self.assertRaises(ValueError):
                worker.live.finish_probe(channel,dict(report,**{field:False}),payload)
        with self.assertRaises(ValueError):worker.live.finish_probe(channel,report,dict(payload,cleanupCompleted=False))
        channel.emit.assert_not_called()
        worker.live.finish_probe(channel,report,payload)
        self.assertEqual(channel.emit.call_args.args,('final',))


    def test_full_run_wiring_keeps_local_record_and_waits_for_outer_cleanup(self):
        self._run_wiring()

    def test_cleanup_failure_preserves_original_and_blocks_engine_cleanup(self):
        self._run_wiring(fail=True)

    def _run_wiring(self,fail=False):
        # All fixture/product seams below are mocks. This proves protocol order
        # and ownership wiring only; the delegated test supplies OS evidence.
        @dataclass
        class Request:
            operation: str = 'recovery'
        request=Request()
        policy=Mock()
        policy.writer_certificate_sha256='c'*64
        policy.operation_profile='compose-v3'
        policy.witness_scope_hash='0'*64
        policy.witness_key_sha256=hashlib.sha256(b'public').hexdigest()
        policy.identity_hash.return_value='e'*64
        setup=dict(policy={},epoch='d'*64,witnessPublicKey=base64.b64encode(b'public').decode(),
            statusPublicKey=base64.b64encode(b'status').decode(),
            gateKey=base64.b64encode(b'g'*32).decode(),
            keys={k:base64.b64encode(b'k'*32).decode() for k in worker.live.KEYS})
        channel=Mock();channel.receive.return_value=setup
        bundle=Mock();bundle.to_dict.return_value={'protectedContainers':[]}
        session=Mock();session.prepared={'bundle':bundle};session.created_ids=[]
        session.project='private-project'
        reviewed=SimpleNamespace(canonical=b'local-reviewed')
        record=object();executor=Mock();history=object()
        preparation=Mock()
        prepared=dict(request=request,reviewed_history=reviewed,recovery_context_reference='local-cas')
        preparation.prepare_intent.return_value=prepared
        preparation.verify_context.return_value={'startWriteIndex':1}
        events=[]
        if fail:
            executor.retry_owned_cleanup.side_effect=ValueError('drain-failed')
            def cleanup():
                self.assertIs(session.unknown_write_result,True)
                raise ValueError('cleanup-blocked')
            session.cleanup.side_effect=cleanup
        def emit(kind,**payload):
            events.append(kind)
            if kind=='recovery-prepared-private':
                self.assertEqual(set(payload),{'request','context'})
                self.assertNotIn(record,payload.values())
        channel.emit.side_effect=emit
        def cut(*args):
            args[-1].update(executor=executor,record=record,history=history,reviewed=reviewed)
            events.append('cut')
        def recover(*args):
            self.assertIs(args[-1]['record'],record)
            events.append('suffix')
            if fail:
                session.unknown_write_result=False
                raise ValueError('original-failure')
            return {'productionReady':False},{'schemaVersion':2}
        def probe(workload):
            workload(Path('/private-fixture'),{'ID':'daemon'})
            events.append('outer-stopped')
            return dict(completed=True,stopped=True,productionSnapshotUnchanged=True)
        with patch.object(worker,'Channel',return_value=channel),patch.object(worker,'preflight'), \
             patch.object(worker.live,'writer_tls',return_value=(object(),object(),'b'*64,'c'*64)), \
             patch.object(worker,'GatePolicy',return_value=policy), \
             patch('deployment_gate_witness.key_material',return_value=b'public'), \
             patch('compose_profile3_prepare_fixture.prepare_profile3',return_value=session), \
             patch('compose_profile3_ownership_fixture.FixtureOwnershipTrackerV3'), \
             patch.object(worker.live,'emit_observer_facts',side_effect=lambda *a:events.append('observer-facts')), \
             patch.object(worker.live,'private_capsule',return_value={}), \
             patch.object(worker,'create_cut',side_effect=cut), \
             patch.object(worker,'RecoveryPreparationHostV3',return_value=preparation), \
             patch.object(worker,'recover_suffix',side_effect=recover), \
             patch('deployment_compose_profile3_prepare_ssh_probe._probe',side_effect=probe):
            if fail:
                with self.assertRaisesRegex(ValueError,'original-failure'):
                    worker.run(config(),None,None)
            else:
                worker.run(config(),None,None)
        if fail:
            self.assertNotIn('final',events)
            executor.retry_owned_cleanup.assert_called_once()
            session.cleanup.assert_called_once_with()
            return
        self.assertEqual(events,['hello','observer-facts','prepared-private','cut',
            'recovery-prepared-private','suffix','outer-stopped','final'])
        session.cleanup.assert_called_once_with()
        executor.retry_owned_cleanup.assert_not_called()


class DelegatedHistoryTests(OwnedRecoveryTests):
    """Real create + typed recovery fixture; exercise new schema-two final gate.

    Fixture provisioning and consent use the existing Engine/GitHub doubles.
    This is helper-composition evidence, not a full new-worker run or SSH test.
    """
    def fence(self,**kwargs):
        self.worker_reviewed=kwargs['reviewed_history']
        self.worker_parent=kwargs['preparation']._history
        return super().fence(**kwargs)

    def test_real_owned_pipeline_final_schema_two_gate(self):
        from deployment_compose_history_v3_host import AuthenticatedHistoryV3
        from deployment_compose_coordinator_v3_host import ComposeCoordinatorV3
        original=ComposeCoordinatorV3.run
        verified=[]
        def run(coordinator):
            result=original(coordinator)
            executor=coordinator._executor
            reviewed=self.worker_reviewed
            parent=self.worker_parent
            child=AuthenticatedHistoryV3(executor.bundle,executor.request,gate_policy=executor._policy,
                gate_key=executor._key,consumption_receipt_hash=executor._receipt,
                witness_client=self.initial_h.factory(executor._binding),witness_client_factory=self.initial_h.factory,
                parent_history=parent,reviewed_parent_snapshot=reviewed)
            final=worker.complete_history(child,reviewed,result)
            self.assertEqual((len(final['knownPrefix']),len(final['scopes']),final['parent']['scopeCount']),(5,4,1))
            for field,value in (('initialWriteCount',0),('receipts',{}),('productionReady',True)):
                with self.subTest(field=field),self.assertRaises(ValueError):worker.complete_history(child,reviewed,dict(result,**{field:value}))
            verified.append(final)
            return result
        with patch.object(ComposeCoordinatorV3,'run',run):self.run_typed()
        self.assertEqual(len(verified),1)


class DelegatedWorkerCompositionTests(OwnedRecoveryTests):
    """New helpers, actual signed status/witness, Linux child and Engine double."""
    def prefix(self,h,operations,socket,writes,store,bundle):
        from tests import test_deployment_compose_approval_v3_host as approvals
        from tests.test_release_host import claims
        from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
        from deployment_compose_phase_guard_v3_host import PhaseGuardV3
        from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
        from deployment_compose_reader_host import _UnixDocker
        from compose_profile3_ownership_fixture import FixtureOwnershipTrackerV3
        import deployment_compose_approval_v3_host as approval_host
        from deployment_compose_intent_status_v3 import issue_intent_status,encode,NAMESPACE
        request=h.req
        approval=approvals.ComposeApprovalTests();approval.setUp();approval.req=request
        approval.policy=approvals.policy(operation='deploy',bundle_hash=bundle.digest,
            host_id=request.host_id,daemon_id=request.daemon_id,components=request.components,
            protected_components=request.protected_components,target=request.target,
            deployment_environment=request.environment,policy_hash=request.policy_hash)
        approval.claims=dict(claims(approval.policy),aud=approval_host.AUDIENCE)
        approval.client=approval.client_for([request]);authority=approval.approval()
        consumed=authority.consume(authority.validate(request),request)
        self.initial_authority_for_status=authority
        receipt=hashlib.sha256(str(consumed).encode()).hexdigest()
        desc=worker.Profile3StepExecutor.scope_descriptor(bundle,request,receipt,operations[0],0,{})
        h.receipt=receipt
        h.policy=replace(h.policy,witness_scope_hash=desc['scopeHash'])
        h.binding=dict(h.binding,generation=desc['generation'],scopeHash=desc['scopeHash'])
        directory=h.root/'new-worker-witness';directory.mkdir(mode=0o700)
        h.store.close();h.store=OperationWitnessStoreV3(directory,key=b'h'*32)
        h.addCleanup(h.store.close);h.store.register_once(h.binding);h.client=h.factory(h.binding)
        def get(path):
            connection=_UnixDocker(str(socket),3)
            try:
                connection.request('GET',path);response=connection.getresponse()
                self.assertEqual(response.status,200);return json.loads(response.read())
            finally:connection.close()
        version=get('/v1.45/version')
        rows=TrustedPhaseStateProducerV3.reload(store,bundle,read_json=get,daemon_version=version)
        guard=PhaseGuardV3(bundle,rows,read_json=get,daemon_version=version)
        server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(self.directory/'server.pem',self.directory/'server.key')
        server.load_verify_locations(self.directory/'ca.pem');server.verify_mode=ssl.CERT_REQUIRED
        client=ssl.create_default_context(cafile=self.directory/'ca.pem')
        client.load_cert_chain(self.directory/'client.pem',self.directory/'client.key')
        self.worker_tls=(server,client,hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'server.pem').read_text())).hexdigest(),h.cert)
        tlsdir=self.root/'live-writer-tls';tlsdir.mkdir(mode=0o700)
        for source,dest in (('ca.pem','ca.pem'),('client.pem','writer.pem'),('client.key','writer.key')):
            path=tlsdir/dest;path.write_bytes((self.directory/source).read_bytes());path.chmod(0o600)
        value=bundle.to_dict();project=value['identity']['project']
        self.worker_session=SimpleNamespace(root=self.root,guard=guard,store=store,project=project,
            target=SimpleNamespace(socket=str(socket),daemon_id=request.daemon_id),
            producer=SimpleNamespace(operation_scope=lambda deadline:nullcontext()),
            created_ids=list(rows),unknown_write_result=False)
        self.worker_tracker=FixtureOwnershipTrackerV3(project=project,daemon_id=request.daemon_id,
            policy_hash=h.policy.identity_hash(),witness_pub_hash=h.policy.witness_key_sha256,
            epoch=h.binding['epoch'],initial_confirmed_ids=list(rows),
            protected_ids=[p['containerId'] for p in value['protectedContainers']])
        owner=self
        class SignedChannel(worker.Channel):
            def __init__(self):
                super().__init__(config(),None,None)
                self.refs=None;self.authority=None;self.request=None;self.consumptions=[];self.status_calls=[]
            def receive(self,kind):
                owner.assertEqual(kind,'consume-intent');owner.assertIsNotNone(self.refs)
                refs=self.refs;self.refs=None;self.consumptions.append(refs['receiptHash']);return refs
            def rpc(self,service,method,rpc_request):
                if service=='witness':return h.transport(method,rpc_request)
                owner.assertEqual((service,method),('intent','check'))
                payload=issue_intent_status(self.authority,self.request,rpc_request)
                signed=subprocess.run(['ssh-keygen','-Y','sign','-f',str(owner.key),'-n',NAMESPACE],
                    input=encode(payload),capture_output=True,check=True)
                self.status_calls.append(self.request.digest())
                return dict(payload=payload,signature=base64.b64encode(signed.stdout).decode())
            def enroll(self,request,authority,receipt,binding):
                self.request=request;self.authority=authority
                self.refs=dict(requestHash=request.digest(),receiptHash=receipt,firstBinding=binding)
        self.worker_channel=SignedChannel();self.retained={}
        self.worker_channel.enroll(request,authority,receipt,h.binding)
        self.actual_writes=writes
        worker.create_cut(self.worker_channel,self.worker_session,dict(bundle=bundle,request=request),
            h.policy,b'g'*32,h.public,self.public,self.worker_tls,self.worker_tracker,self.retained)
        self.assertFalse(self.worker_session.unknown_write_result)
        self.assertIn('a'*64,self.worker_session.created_ids)
        self.assertEqual(len(self.retained['reviewed'].snapshot['knownPrefix']),1)
        h.receipts={'backend':'a'*64};self.initial_h=h
        self.initial_receipt=receipt;self.initial_request_hash=request.digest()
        self.assertEqual(writes,operations)
        return None

    def continuation(self,**values):
        self.worker_session.guard=values['guard']
        h=values['h'];self.worker_channel.enroll(values['prepared']['request'],values['authority'],values['receipt'],values['binding'])
        if getattr(self,'bad_binding',False):
            self.worker_channel.refs['firstBinding']=dict(values['binding'],scopeHash='0'*64)
        if getattr(self,'old_authority',False):
            self.worker_channel.authority=self.initial_authority_for_status
        with patch.object(worker.live,'readiness',side_effect=lambda session,cid:values['readiness']('backend',cid)):
            result,final=worker.recover_suffix(self.worker_channel,self.worker_session,values['prepared'],
                values['preparation'],values['context'],values['gate_policy'],b'g'*32,h.public,self.public,
                self.worker_tls,self.worker_tracker,self.retained)
        self.assertFalse(self.worker_session.unknown_write_result)
        self.assertEqual(set(self.worker_session.created_ids),{'2'*64,'a'*64})
        self.assertEqual((len(final['knownPrefix']),len(final['scopes']),final['parent']['scopeCount']),(5,4,1))
        self.assertEqual(len(set(self.worker_channel.consumptions)),2)
        self.assertIn(self.initial_request_hash,self.worker_channel.status_calls)
        self.assertIn(values['prepared']['request'].digest(),self.worker_channel.status_calls)
        return result,final

    def run_worker(self):
        from tests import test_deployment_compose_recovery_prepare_v3_host as recovery_fixture
        return self.run_recovery(1,prefix_runner=self.prefix,continuation_runner=self.continuation,
            initial_request_factory=lambda req:replace(req,expires_at=recovery_fixture.expiry()),service_name='backend')

    def test_new_helpers_actual_owned_cut_fresh_status_and_suffix(self):
        self.run_worker()

    def test_bad_second_binding_rejects_before_suffix_write(self):
        self.bad_binding=True
        with self.assertRaises(ValueError):self.run_worker()
        self.assertFalse(self.worker_session.unknown_write_result)
        self.assertEqual(len(self.worker_channel.consumptions),2)
        self.assertEqual(self.worker_session.created_ids.count('a'*64),1)


    def test_old_authority_cannot_answer_fresh_recovery_status(self):
        self.old_authority=True
        with self.assertRaises(ValueError):self.run_worker()
        self.assertEqual(self.actual_writes,[])
        self.assertFalse(self.worker_session.unknown_write_result)

    def test_lost_root_response_keeps_engine_cleanup_blocked(self):
        original=worker.OwnedCreateTransportV3.request
        def lost(transport,**kwargs):
            original(transport,**kwargs)
            raise ValueError('test-lost-owned-response')
        with patch.object(worker.OwnedCreateTransportV3,'request',lost):
            with self.assertRaisesRegex(ValueError,'test-lost-owned-response'):self.run_worker()
        self.assertTrue(self.worker_session.unknown_write_result)
        self.assertEqual(len(self.actual_writes),1)
        self.assertEqual(self.actual_writes[0]['phase'],'create')
        self.assertNotIn('record',self.retained)


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(cls(name) for cls in (ProtocolTests,DelegatedHistoryTests,DelegatedWorkerCompositionTests)
        for name in cls.__dict__ if name.startswith('test_'))
