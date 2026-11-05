"""Typed local recovery; GitHub and Unix Engine are explicit test doubles."""
from dataclasses import replace
import copy
from unittest.mock import patch
import hashlib
import json
import os
import select
import signal
import ssl
import sys
import unittest

from tests.test_deployment_compose_recovery_execution_v3_host import RecoveryExecutionTests
from tests import test_deployment_compose_approval_v3_host as approval_fixture
from tests import test_deployment_compose_recovery_prepare_v3_host as recovery_fixture
from tests.test_release_host import claims
from deployment_compose_startup_fence_v3_host import Profile3RecoveryFenceV3
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_create_transport_v3_host import OwnedCreateTransportV3
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3
from deployment_compose_reader_host import _UnixDocker
import deployment_compose_approval_v3_host as approval_host


class ConstructorTests(unittest.TestCase):
    def test_partial_and_mixed_sources_reject(self):
        from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
        from deployment_compose_history_v3_host import AuthenticatedHistorySnapshotV3
        from deployment_compose_coordinator_v3_host import ClosedCreateDrainV3
        base=dict(preparation=object.__new__(RecoveryPreparationHostV3),context_reference='x',
            reviewed_history=AuthenticatedHistorySnapshotV3(b'{}'))
        executor=object.__new__(Profile3StepExecutor);record=ClosedCreateDrainV3()
        # Constructor shape only; activation must still validate real issuers.
        Profile3RecoveryFenceV3(**base,quiesce_writer=lambda:True)
        Profile3RecoveryFenceV3(**base,original_executor=executor,closed_create_drain=record)
        for args in ({}, {'original_executor':executor}, {'closed_create_drain':record},
                     {'original_executor':executor,'closed_create_drain':record,'quiesce_writer':lambda:True},
                     {'original_executor':object(),'closed_create_drain':record},
                     {'original_executor':executor,'closed_create_drain':object()}):
            with self.assertRaises(ValueError):Profile3RecoveryFenceV3(**base,**args)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0 and
    os.environ.get('DEV_WORKFLOW_PRIVILEGED_LINUX_TESTS')=='1','real delegated Linux unit')
class OwnedRecoveryTests(RecoveryExecutionTests):
    def prefix(self,h,operations,socket,writes,store,bundle):
        request=h.req
        approval=approval_fixture.ComposeApprovalTests();approval.setUp();approval.req=request
        approval.policy=approval_fixture.policy(operation='deploy',bundle_hash=bundle.digest,
            host_id=request.host_id,daemon_id=request.daemon_id,components=request.components,
            protected_components=request.protected_components,target=request.target,
            deployment_environment=request.environment,policy_hash=request.policy_hash)
        approval.claims=dict(claims(approval.policy),aud=approval_host.AUDIENCE)
        approval.client=approval.client_for([request]);authority=approval.approval()
        receipt=authority.consume(authority.validate(request),request)
        self.initial_authority=authority
        self.initial_h=h;self.prefix_writes=writes
        h.receipt=hashlib.sha256(str(receipt).encode()).hexdigest()
        op=operations[0]
        desc=Profile3StepExecutor.scope_descriptor(bundle,request,h.receipt,op,0,{})
        h.policy=replace(h.policy,witness_scope_hash=desc['scopeHash'])
        h.binding=dict(h.binding,generation=desc['generation'],scopeHash=desc['scopeHash'])
        h.store.close();path=h.root/'owned-prefix-witness';path.mkdir(mode=0o700)
        h.store=OperationWitnessStoreV3(path,key=b'h'*32);h.addCleanup(h.store.close)
        h.store.register_once(h.binding);h.client=h.factory(h.binding)
        server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(self.directory/'server.pem',self.directory/'server.key')
        server.load_verify_locations(self.directory/'ca.pem');server.verify_mode=ssl.CERT_REQUIRED
        client=ssl.create_default_context(cafile=self.directory/'ca.pem')
        client.load_cert_chain(self.directory/'client.pem',self.directory/'client.key')
        def get(path):
            connection=_UnixDocker(str(socket),3)
            try:
                connection.request('GET',path);response=connection.getresponse()
                self.assertEqual(response.status,200);return json.loads(response.read())
            finally:connection.close()
        version=get('/v1.45/version')
        rows=TrustedPhaseStateProducerV3.reload(store,bundle,read_json=get,daemon_version=version)
        guard=PhaseGuardV3(bundle,rows,read_json=get,daemon_version=version)
        owned=OwnedCreateTransportV3(worker_uid=65534,worker_gid=65534,
            ca_pem=(self.directory/'ca.pem').read_bytes(),
            client_cert_pem=(self.directory/'client.pem').read_bytes(),
            client_key_pem=(self.directory/'client.key').read_bytes())
        executor=Profile3StepExecutor(bundle,request,intent_authority=authority,phase_guard=guard,
            gate_root=self.root/'owned-initial-gate',gate_key=b'g'*32,gate_policy=h.policy,
            consumption_receipt_hash=h.receipt,witness_client_factory=h.factory,registered_binding=h.binding,
            tls_server_context=server,tls_client_context=client,
            server_certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/'server.pem').read_text())).hexdigest(),
            docker_socket=socket,timeout=3,owned_create_transport=owned)
        result=executor.execute(op,phase_index=0,receipts={},completed_operations=[])
        h.receipts={op['service']:json.loads(result['body'])['Id']}
        h.client=executor._client;h.binding=executor._binding
        self.original_executor=executor;self.closed_record=executor.capture_owned_closed_create(h.history())
        # Fresh public executors start at empty index0; an already closed
        # initial scope cannot be used to repeat create with the old receipt.
        replay=Profile3StepExecutor(bundle,request,intent_authority=authority,phase_guard=guard,
            gate_root=self.root/'replay-gate',gate_key=b'g'*32,gate_policy=h.policy,
            consumption_receipt_hash=h.receipt,witness_client_factory=h.factory,registered_binding=h.binding,
            tls_server_context=server,tls_client_context=client,server_certificate_sha256=executor._pin,
            docker_socket=socket,timeout=3)
        with self.assertRaises(ValueError):replay.execute(op,phase_index=0,receipts={},completed_operations=[])
        remaining=bundle.resolve_operations(h.receipts)[1]
        with self.assertRaises(ValueError):executor.execute(remaining,phase_index=1,receipts=h.receipts,completed_operations=[op])
        self.assertEqual(writes,operations)
        return None

    def fence(self,**kwargs):
        kwargs.pop('quiesce_writer')
        mode=getattr(self,'mode','ok')
        original=self.original_executor
        record=self.closed_record
        if mode=='copied_record':
            record=copy.copy(record)
            self.instance_verifier_calls=[]
            def replaced_verify(*args):
                self.instance_verifier_calls.append(True);return True
            original.verify_owned_closed_create=replaced_verify
        if mode=='foreign_issuer':original=copy.copy(original)
        fence=Profile3RecoveryFenceV3(**kwargs,original_executor=original,closed_create_drain=record)
        activate=fence.activate
        from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
        transition=OperationWitnessClientV3.transition_successor
        self.transitions=[];self.race_results=[]
        old_history=kwargs['preparation']._history
        old=old_history.capture().snapshot
        receipts=dict(old['receiptMap'])
        next_op=self.original_executor.bundle.resolve_operations(receipts)[1]
        descriptor=Profile3StepExecutor.scope_descriptor(self.original_executor.bundle,
            self.original_executor.request,self.original_executor._receipt,next_op,1,receipts)
        old_binding=dict(self.original_executor._binding,generation=descriptor['generation'],scopeHash=descriptor['scopeHash'])
        raced=[]
        def cas(client,**values):
            self.transitions.append(values['childBinding'])
            if mode in ('old_wins','recovery_wins') and not raced:
                raced.append(True)
                rival=self.initial_h.factory(dict(old['closedTail']['binding']))
                args=dict(expected_seq=6,expected_head=old['closedTail']['head'],childBinding=old_binding)
                if mode=='old_wins':
                    transition(rival,**args);self.race_results.append('old-won')
                    try:return transition(client,**values)
                    except ValueError:
                        self.race_results.append('recovery-lost');raise
                result=transition(client,**values);self.race_results.append('recovery-won')
                with self.assertRaises(ValueError):transition(rival,**args)
                self.race_results.append('old-lost');return result
            return transition(client,**values)
        patcher=patch.object(OperationWitnessClientV3,'transition_successor',cas)
        patcher.start();self.addCleanup(patcher.stop)
        def checked(**params):
            self.activated=True
            if mode=='expired':params['request']=replace(params['request'],expires_at='2020-01-01T00:00:00Z')
            if mode=='revoked':params['intent_authority'].client.data['/repos/sample/host/actions/runs/123/approvals'][0]['comment']='revoked'
            if mode=='old_authority':params['intent_authority']=self.initial_authority
            if mode=='wrong_history':kwargs['preparation']._history._receipt='e'*64
            if mode=='fork':
                readfd,writefd=os.pipe();fence._lock.acquire()
                pid=os.fork()
                if pid==0:
                    os.close(readfd)
                    try:activate(**params)
                    except ValueError:os.write(writefd,b'rejected');os._exit(0)
                    os._exit(1)
                os.close(writefd)
                try:
                    if not select.select([readfd],[],[],3)[0]:
                        os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);self.fail('fork entered inherited lock')
                    self.assertEqual(os.read(readfd,64),b'rejected')
                    _,status=os.waitpid(pid,0);self.assertEqual(status,0)
                finally:os.close(readfd);fence._lock.release()
                raise ValueError('fork-refused')
            return activate(**params)
        fence.activate=checked
        return fence

    def run_typed(self):
        return self.run_recovery(1,prefix_runner=self.prefix,fence_factory=self.fence,
            initial_request_factory=lambda req:replace(req,expires_at=recovery_fixture.expiry()))

    def test_actual_owned_create_then_fresh_recovery_without_duplicate_create(self):
        self.run_typed()

    def test_fresh_recovery_cas_wins_and_old_deploy_cannot_advance(self):
        self.mode='recovery_wins';self.run_typed()
        self.assertEqual(self.race_results,['recovery-won','old-lost'])

    def test_old_deploy_advance_after_fact_read_defeats_final_recovery_cas(self):
        self.mode='old_wins'
        with self.assertRaises(ValueError):self.run_typed()
        self.assertEqual(self.race_results,['old-won','recovery-lost'])
        self.assertEqual(self.prefix_writes,[])

    def test_typed_invalid_records_and_fresh_authority_reject_before_cas(self):
        # Each run needs its own independent roots, so individual scenarios are
        # separate test methods below rather than reusing a consumed fixture.
        self.reject_mode('copied_record')

    def reject_mode(self,mode):
        self.mode=mode
        with self.assertRaises(ValueError):self.run_typed()
        self.assertTrue(self.activated)
        self.assertEqual(self.transitions,[])
        self.assertEqual(self.prefix_writes,[])
        if mode=='copied_record':self.assertEqual(self.instance_verifier_calls,[])

    def test_fork_owner_rejects_before_inherited_lock(self):self.reject_mode('fork')
    def test_foreign_issuer_rejects(self):self.reject_mode('foreign_issuer')
    def test_wrong_history_rejects(self):self.reject_mode('wrong_history')
    def test_expired_recovery_rejects(self):self.reject_mode('expired')
    def test_revoked_recovery_rejects(self):self.reject_mode('revoked')
    def test_old_deploy_authority_rejects(self):self.reject_mode('old_authority')


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(cls(name) for cls in (ConstructorTests,OwnedRecoveryTests)
        for name in cls.__dict__ if name.startswith('test_'))
