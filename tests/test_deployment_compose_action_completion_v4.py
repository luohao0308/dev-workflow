"""Actual fixed PIPE actor completion facts; Engine and GitHub are doubles."""
import os,json,base64,copy,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from unittest.mock import patch
import deployment_compose_action_host_v4 as root4
from tests import test_compose_profile3_prepare_fixture as fixture

@unittest.skipUnless(os.name=='posix','actual Unix actor fixture')
class CompletionTests(unittest.TestCase):
    def setUp(self):
        import base64,json,ssl,subprocess,tempfile
        from copy import deepcopy
        from unittest.mock import patch
        from deployment_compose_action_actor_v4 import ActionActorSupervisorV4
        from deployment_compose_action_witness_v4 import ActionWitnessStoreV4
        from deployment_compose_approval_v4_host import GitHubFullBodyApprovalV4,FullBodyApprovalPolicyV4,AUDIENCE
        from deployment_compose_intent_status_v4_host import IntentStatusHostV4
        from deployment_compose_intent_status_v4 import IntentStatusClientV4
        from tests import test_deployment_compose_approval_v3_host as approval_fixture
        h=fixture.CurrentPreparationUnixTests('test_initial_and_current_real_unix_tls_cas_signed_history')
        h.setUp();self.addCleanup(h.doCleanups)
        session=h.session
        preparation=root4.RootActionPreparationV4(preparer=session.preparer,socket_path=Path(session.producer._socket_path))
        token=preparation.prepare(session.whole_observation,session.retention_observation,
            operation_nonce=session.prepared['bundle'].to_dict()['operationNonce'],expires_at=session.prepared['request'].expires_at)
        server=next(fn.__self__ for fn,args,kwargs in h._cleanups if getattr(fn,'__name__','')=='shutdown')
        writes=[]
        def post(handler):
            writes.append((handler.path,handler.rfile.read(int(handler.headers['Content-Length']))))
            body=json.dumps({'Id':'a'*64}).encode()
            handler.send_response(201);handler.send_header('Content-Length',str(len(body)));handler.end_headers();handler.wfile.write(body)
        server.RequestHandlerClass.do_POST=post
        counter=0
        def make():
            nonlocal counter
            counter+=1;directory=h.root/('action-witness-'+str(counter));directory.mkdir(mode=0o700)
            store=ActionWitnessStoreV4(directory,key=b'w'*32);self.addCleanup(store.close)
            supervisor=ActionActorSupervisorV4();self.addCleanup(supervisor.close)
            host=root4.SingleActionHostV4(preparation=preparation,prepared=token,supervisor=supervisor,
                                         witness=store,phase_guard=session.guard,session_hash='e'*64)
            return host,store,supervisor
        key=h.root/'action-status-key'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
        def consumed(host):
            req=host._root['request']
            policy=approval_fixture.policy(source_sha=req.source.source_sha,
                target_repository=req.source.project_path,target_repository_id=req.source.project_id,
                daemon_id=req.daemon_id,host_id=req.host_id,deployment_environment=req.environment,
                target=req.target,components=req.components,protected_components=req.protected_components,
                policy_hash=req.policy_hash,bundle_hash=req.plan_hash)
            values=vars(policy).copy();values.update(profile_version='4',expected_observation_hash=req.observation_hash,**host.approval_bindings())
            policy=FullBodyApprovalPolicyV4(**values)
            harness=approval_fixture.ComposeApprovalTests();harness.setUp();harness.policy=policy
            client=harness.client_for([req]);client.data['/repos/'+req.source.project_path]=dict(id=req.source.project_id,full_name=req.source.project_path)
            claims=dict(approval_fixture.claims(policy),aud=AUDIENCE)
            authority=GitHubFullBodyApprovalV4(client,'signed',[req],policy,verifier=lambda _:claims)
            receipt=authority.consume(authority.validate(req),req)
            signer=IntentStatusHostV4(authority=authority,request=req,receipt=receipt,signing_key=key,**host.approval_bindings())
            status=IntentStatusClientV4(req,signer.public_key,signer.respond,
                consumption_receipt_hash=authority.receipt_hash(receipt,req),**host.approval_bindings())
            return dict(authority=authority,receipt=receipt,status_client=status)
        self.make=make;self.consumed=consumed;self.writes=writes;self.server=server

    def completed(self):
        host,store,supervisor=self.make();host.dispatch(**self.consumed(host))
        return host,store,supervisor

    def test_success_readonly_queries_and_foreign_identity(self):
        host,store,sup=self.completed();record=host.capture_completed_action()
        with patch.object(sup,'stop_and_join',side_effect=AssertionError('query stopped actor')), \
             patch.object(host._preparation,'resolve',side_effect=AssertionError('query resolved phase')), \
             patch.object(host,'_phase',side_effect=AssertionError('query read phase')), \
             patch.object(type(host._root['request']),'ensure_fresh',side_effect=AssertionError('query renewed expiry')):
            result=host.verify_completed_action(record)
            self.assertEqual(result['candidateId'],'a'*64)
            self.assertEqual(result['cursor']['seq'],3)
            for name in ('authorityGranted','runtimePermit','productionReady','recoveryAuthorized'):self.assertIs(result[name],False)
            self.assertIs(host.capture_completed_action(),record)
        for bad in (copy.copy(record),root4.CompletedActionV4(),{},result):
            with self.assertRaises(ValueError):host.verify_completed_action(bad)
        with self.assertRaises(ValueError):copy.copy(host).verify_completed_action(record)
        other,_,_=self.make()
        with self.assertRaises(ValueError):other.verify_completed_action(record)
        old=host._completion_owner;host._completion_owner=-1
        try:
            with self.assertRaises(ValueError):host.capture_completed_action()
        finally:host._completion_owner=old
        from tests.test_deployment_compose_operation_witness_v4 import assert_fork_copies_rejected
        assert_fork_copies_rejected(self,[host.capture_completed_action,lambda:host.verify_completed_action(record)],[host._completion_lock])
        sup.close()
        with self.assertRaises(ValueError):host.verify_completed_action(record)
        self.assertEqual(len(self.writes),1)

    def test_durable_response_ack_loss_is_queryable_not_repeatable(self):
        host,store,sup=self.make();authorized=self.consumed(host);original=store.record_response
        def lose(*args,**kw):original(*args,**kw);raise OSError('ack loss')
        with patch.object(store,'record_response',side_effect=lose),self.assertRaises(OSError):host.dispatch(**authorized)
        record=host.capture_completed_action();self.assertEqual(host.verify_completed_action(record)['cursor']['seq'],3)
        with self.assertRaises(ValueError):host.dispatch(**authorized)
        self.assertEqual(len(self.writes),1)

    def test_admission_and_actor_response_loss_never_complete(self):
        for mode in ('admit','response'):
            host,store,sup=self.make();authorized=self.consumed(host)
            original=store.admit
            def lose(*args,**kw):original(*args,**kw);raise OSError('ack loss')
            target=patch.object(store,'admit',side_effect=lose) if mode=='admit' else patch.object(sup,'receive_response',side_effect=ValueError('lost response'))
            with target,self.assertRaises((OSError,ValueError)):host.dispatch(**authorized)
            with self.assertRaises(ValueError):host.capture_completed_action()
            self.assertEqual(len(store.read()['events']),2)

    def test_valid_hmac_rollback_response_or_binding_substitution_rejects(self):
        host,store,sup=self.completed();record=host.capture_completed_action();state=store.read()
        variants=[]
        for count in (1,2):
            changed=copy.deepcopy(state);changed['events']=changed['events'][:count];variants.append(changed)
        changed=copy.deepcopy(state);changed['binding']['actorEpoch']='f'*64;variants.append(changed)
        changed=copy.deepcopy(state);changed['events']=changed['events'][:2]
        store._append(changed,'response',{'status':201,'bodyBase64':base64.b64encode(b'{"Id":"b"}').decode()});variants.append(changed)
        for changed in variants:
            with store._locked():store._persist(changed)
            try:
                with self.assertRaises(ValueError):host.verify_completed_action(record)
            finally:
                with store._locked():store._persist(state)
        store.close()
        with self.assertRaises(ValueError):host.verify_completed_action(record)

    def test_invalid_cid_and_non201_have_no_completion(self):
        for body,status in ((b'{"Id":"bad"}',201),(b'{"Id":"'+b'1'*64+b'"}',201),
                (b'{"Id":"'+b'a'*64+b'","Id":"'+b'b'*64+b'"}',201),(b'{}',500)):
            def post(handler):
                self.writes.append(handler.rfile.read(int(handler.headers['Content-Length'])))
                handler.send_response(status);handler.send_header('Content-Length',str(len(body)))
                handler.end_headers();handler.wfile.write(body)
            self.server.RequestHandlerClass.do_POST=post
            host,store,sup=self.make();result=host.dispatch(**self.consumed(host))
            self.assertFalse(result['success'])
            with self.assertRaises(ValueError):host.capture_completed_action()
            if status==201 and b'1'*64 in body:
                from types import SimpleNamespace
                original=host._root['bundle']
                host._root['bundle']=SimpleNamespace(canonical_bytes=original.canonical_bytes,
                    to_dict=lambda:dict(services=[],protectedContainers=[]))
                try:
                    with self.assertRaises(ValueError):host.capture_completed_action()
                finally:host._root['bundle']=original

    def test_query_during_dispatch_rejects_before_lock_and_no_candidate(self):
        host,store,sup=self.make()
        with self.assertRaises(ValueError):host.capture_completed_action()
        authorized=self.consumed(host);original=store.record_response
        def observe(*args,**kw):
            with self.assertRaises(ValueError):host.capture_completed_action()
            return original(*args,**kw)
        with patch.object(store,'record_response',side_effect=observe):host.dispatch(**authorized)
        host.capture_completed_action()


def load_tests(loader,tests,pattern):
    return loader.loadTestsFromTestCase(CompletionTests)
