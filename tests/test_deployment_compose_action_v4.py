"""Real local Unix/mTLS/CAS preparation with an explicitly fake Engine."""
from copy import copy
from dataclasses import asdict
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import deployment_compose_action_host_v4 as root4
from tests import test_compose_profile3_prepare_fixture as fixture


@unittest.skipUnless(os.name=='posix','private Unix test Engine required')
class RootActionPreparationTests(unittest.TestCase):
    def test_host_recomputes_distinct_v4_root_without_grant_or_write(self):
        h=fixture.CurrentPreparationUnixTests('test_initial_and_current_real_unix_tls_cas_signed_history')
        h.setUp();self.addCleanup(h.doCleanups)
        session=h.session;original=session.prepared['request']
        host=root4.RootActionPreparationV4(preparer=session.preparer,
                                         socket_path=Path(session.producer._socket_path))
        token=host.prepare(session.whole_observation,session.retention_observation,
            operation_nonce=session.prepared['bundle'].to_dict()['operationNonce'],expires_at=original.expires_at)
        result=host.resolve(token);request=result['request']
        self.assertEqual(request.profile_version,'4')
        for field in ('source','host_id','daemon_id','target','components','protected_components',
                      'before_hash','after_hash','artifact_digest'):
            self.assertEqual(getattr(request,field),getattr(original,field))
        for field in ('plan_hash','policy_hash','observation_hash'):
            self.assertNotEqual(getattr(request,field),getattr(original,field))
        self.assertEqual(result['action']['payloadFormat'],'compose-bundle-v3')
        self.assertEqual(result['action']['scopeOrdinal'],0)
        self.assertEqual(result['action']['planWriteIndex'],0)
        self.assertEqual(result['action']['operation']['method'],'POST')
        self.assertEqual(result['action']['limits']['maximumWrites'],1)
        for field in ('authorityGranted','executionAvailable','productionReady'):
            self.assertIs(result[field],False)
        self.assertFalse(any(call[0]!='GET' for call in h.calls))
        with self.assertRaises(ValueError): host.resolve(copy(token))
        with self.assertRaises(ValueError): host.resolve(asdict(request))
        producer=session.preparer._phase_state
        original_project=producer.project;producer.project='dw-foreign'
        try:
            with self.assertRaises(ValueError): host.resolve(token)
        finally:producer.project=original_project
        old=producer._socket_path;producer._socket_path='/var/run/docker.sock'
        try:
            with self.assertRaises(ValueError): host.resolve(token)
        finally:producer._socket_path=old
        from dataclasses import replace
        preparer=session.preparer
        original_source=preparer._source
        preparer._source=replace(original_source,source_sha='a'*40)
        try:
            with self.assertRaises(ValueError): host.resolve(token)
        finally:preparer._source=original_source
        original_target=preparer._target_inputs['backend']['expected_image_id']
        preparer._target_inputs['backend']['expected_image_id']='sha256:'+'0'*64
        try:
            with self.assertRaises(ValueError): host.resolve(token)
        finally:preparer._target_inputs['backend']['expected_image_id']=original_target
        baseline_ref=result['bundle'].to_dict()['baselineStateReference']
        cas=Path(preparer._recovery._store._root)/baseline_ref
        retained=cas.read_bytes();cas.write_bytes(b'{}')
        try:
            with self.assertRaises(ValueError): host.resolve(token)
        finally:cas.write_bytes(retained)
        with self.assertRaises(ValueError):
            host.prepare(session.whole_observation,session.retention_observation,
                operation_nonce='f'*64,expires_at='2020-01-01T00:00:00Z')
        # Replace the actual Unix socket inode at the pinned path.
        import socket
        path=Path(old);moved=path.with_name('original-socket.saved');path.rename(moved)
        substitute=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            substitute.bind(str(path))
            with self.assertRaises(ValueError):host.resolve(token)
        finally:
            substitute.close();path.unlink();moved.rename(path)
        original_get=producer._get
        producer._get=lambda path: {}
        try:
            with self.assertRaises(ValueError): host.resolve(token)
        finally:producer._get=original_get
        with self.assertRaises(ValueError):
            root4.RootActionPreparationV4(preparer={},socket_path=Path(old))


@unittest.skipUnless(os.name=='posix','real fixed PIPE actor and Unix fake Engine')
class SingleActionExecutionTests(unittest.TestCase):
    def test_composite_gates_single_forward_and_durable_unknown(self):
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
        host,store,supervisor=make()
        with self.assertRaises(ValueError):host.dispatch(authority={},receipt={},status_client={})
        self.assertEqual(writes,[]);self.assertEqual(len(store.read()['events']),1)
        host,store,supervisor=make();authorized=consumed(host)
        result=host.dispatch(**authorized)
        self.assertTrue(result['success']);self.assertEqual(result['candidateId'],'a'*64)
        self.assertEqual(len(writes),1);self.assertEqual(len(store.read()['events']),3)
        self.assertEqual(base64.b64decode(store.read()['events'][-1]['data']['bodyBase64']),json.dumps({'Id':'a'*64}).encode())
        with self.assertRaises(ValueError):host.dispatch(**authorized)
        self.assertEqual(len(writes),1)
        replacement_host,replacement_store,replacement_supervisor=make()
        with self.assertRaises(ValueError):replacement_host.dispatch(**authorized)
        self.assertEqual(len(writes),1)
        self.assertEqual(len(replacement_store.read()['events']),1)
        host,store,supervisor=make();authorized=consumed(host)
        original=store.admit
        def lose_ack(*args,**kwargs):original(*args,**kwargs);raise OSError('lost durable admission ack')
        with patch.object(store,'admit',side_effect=lose_ack),self.assertRaises(OSError):host.dispatch(**authorized)
        self.assertEqual(len(writes),1);self.assertEqual(len(store.read()['events']),2)
        with self.assertRaises(ValueError):host.dispatch(**authorized)
        self.assertEqual(len(writes),1)

        with self.assertRaises(ValueError):
            store.record_response(store._cursor(store.read()),host=host,response_evidence={})
        self.assertEqual(len(store.read()['events']),2)

        # Fresh root phase drift rejects before admission and before any POST.
        host,store,supervisor=make();authorized=consumed(host)
        previous=h.rows['1'*64]['State']['Pid'];h.rows['1'*64]['State']['Pid']+=1
        try:
            with self.assertRaises(ValueError):host.dispatch(**authorized)
        finally:h.rows['1'*64]['State']['Pid']=previous
        self.assertEqual(len(writes),1);self.assertEqual(len(store.read()['events']),1)

        # The last real phase read may outlive a valid signed status window.
        host,store,supervisor=make();authorized=consumed(host)
        original_check=authorized['authority'].check_consumed_intent
        original_phase=host._phase;phase_calls=[]
        import time
        def short_check(request):
            original_check(request)
            authorized['authority']._expires=min(authorized['authority']._expires,time.time()+2.8)
        def slow_last_phase(deadline):
            value=original_phase(deadline);phase_calls.append(True)
            if len(phase_calls)==2:
                # Bound the fixture too: never sleep on a recomputed OIDC hour.
                time.sleep(min(3,max(0,authorized['authority']._expires-time.time())+0.1))
            return value
        with patch.object(authorized['authority'],'check_consumed_intent',side_effect=short_check), \
             patch.object(host,'_phase',side_effect=slow_last_phase),self.assertRaises(ValueError):
            host.dispatch(**authorized)
        self.assertEqual(len(phase_calls),2);self.assertEqual(len(writes),1)
        self.assertEqual(len(store.read()['events']),2)

        # Real child SIGKILL after Unix receipt but before response freezes it.
        import threading
        arrived=threading.Event();release=threading.Event()
        def hold(handler):
            writes.append((handler.path,handler.rfile.read(int(handler.headers['Content-Length']))))
            arrived.set();release.wait(10)
            try:
                handler.send_response(201);handler.send_header('Content-Length','2');handler.end_headers();handler.wfile.write(b'{}')
            except (OSError,BrokenPipeError):pass
        server.RequestHandlerClass.do_POST=hold
        host,store,supervisor=make();authorized=consumed(host);errors=[]
        def dispatch():
            try:host.dispatch(**authorized)
            except Exception as error:errors.append(error)
        thread=threading.Thread(target=dispatch);thread.start()
        try:
            self.assertTrue(arrived.wait(45),[(type(e).__name__,str(e)) for e in errors])
            process=supervisor._actors[host.actor][0];process.kill()
        finally:release.set();thread.join(20)
        self.assertFalse(thread.is_alive());self.assertEqual(len(errors),1)
        self.assertEqual(len(writes),2);self.assertEqual(len(store.read()['events']),2)
        with self.assertRaises(ValueError):host.dispatch(**authorized)
        self.assertEqual(len(writes),2)
        server.RequestHandlerClass.do_POST=post

        # A private pipe is the trusted parent capability; queued duplicate go
        # frames still cannot make this leaf send more than one request.
        from deployment_compose_action_actor_v4 import send,receive
        import time,secrets
        host,store,supervisor=make()
        go={k:host._config[k] for k in ('requestHash','contextDigest','actionDigest','sessionHash','actorEpoch')}
        go.update(kind='go-v4',nonce=secrets.token_hex(32),deadline=time.monotonic()+30,
                  cursor={'seq':2,'head':'d'*64},scopeOrdinal=0,planWriteIndex=0)
        process=supervisor._actors[host.actor][0]
        send(process.stdin,go);send(process.stdin,go)
        response=receive(process.stdout,time.monotonic()+10)
        self.assertEqual(response['status'],201);process.wait(timeout=5)
        self.assertEqual(len(writes),3)
        from deployment_compose_actor_supervisor_v4 import ActorSupervisorV4
        diagnostic=ActorSupervisorV4();self.addCleanup(diagnostic.close)
        diagnostic_actor=diagnostic.start_fixed_actor('e'*64)
        diagnostic_proof=diagnostic.stop_and_join(diagnostic_actor)
        with self.assertRaises(ValueError):supervisor.termination_digest(host.actor,diagnostic_proof,'e'*64)
        for path in ('/v1.45/containers/evil/stop','/v1.45/containers/create?name=arbitrary'):
            bad=deepcopy(host._config);bad['path']=path
            with self.assertRaises(ValueError):supervisor._start(bad)
        self.assertEqual(len(writes),3)

        # Start owns the real Popen before close can drain it.
        import deployment_compose_action_actor_v4 as actor_module
        from unittest.mock import patch
        racing=ActionActorSupervisorV4();self.addCleanup(racing.close)
        original_popen=actor_module.subprocess.Popen
        spawned=threading.Event();allow_return=threading.Event();owned=[];handles=[];failures=[]
        def blocked_spawn(*args,**kwargs):
            child=original_popen(*args,**kwargs);owned.append(child);spawned.set()
            if not allow_return.wait(5):raise AssertionError('test barrier timed out')
            return child
        def start():
            try:handles.append(racing._start(deepcopy(host._config)))
            except Exception as e:failures.append(e)
        with patch.object(actor_module.subprocess,'Popen',side_effect=blocked_spawn):
            starter=threading.Thread(target=start);starter.start();self.assertTrue(spawned.wait(5))
            closer=threading.Thread(target=racing.close);closer.start()
            self.assertTrue(closer.is_alive());allow_return.set();starter.join(10);closer.join(10)
        self.assertFalse(starter.is_alive());self.assertFalse(closer.is_alive());self.assertEqual(failures,[])
        self.assertIsNotNone(owned[0].poll())
        with self.assertRaises(ValueError):racing.send_go(handles[0],host=host,go_evidence={})

        # Inheriting a Popen object through fork does not make the child its
        # owning supervisor, and cannot mint a joined proof for a live leaf.
        forked=ActionActorSupervisorV4();self.addCleanup(forked.close)
        owned_actor=forked._start(deepcopy(host._config))
        owned_process=forked._actors[owned_actor][0]
        child_pid=os.fork()
        if child_pid==0:
            try:forked.stop_and_join(owned_actor)
            except ValueError:os._exit(0)
            os._exit(1)
        _,child_status=os.waitpid(child_pid,0)
        self.assertEqual(os.waitstatus_to_exitcode(child_status),0)
        self.assertIsNone(owned_process.poll())
        forked.stop_and_join(owned_actor)

        # A legal large configuration must not hang in write before readiness.
        silent=original_popen([sys.executable,'-I','-S','-c','import time; time.sleep(30)'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        large=deepcopy(host._config);body=json.loads(base64.b64decode(large['bodyBase64']))
        body['Env']=['LARGE='+'x'*50000];raw=root4.encode(body)
        self.assertLessEqual(len(raw),65536)
        large['bodyBase64']=base64.b64encode(raw).decode('ascii')
        import hashlib
        large['bodyDigest']=hashlib.sha256(raw).hexdigest()
        bounded=ActionActorSupervisorV4();self.addCleanup(bounded.close)
        started=time.monotonic()
        with patch.object(actor_module.subprocess,'Popen',return_value=silent),self.assertRaises(ValueError):
            bounded._start(large)
        self.assertLess(time.monotonic()-started,16)
        self.assertIsNotNone(silent.poll());self.assertTrue(silent.stdin.closed)

        def invalid_cid(handler):
            writes.append((handler.path,handler.rfile.read(int(handler.headers['Content-Length']))))
            body=b'{"Id":"not-a-container-id"}'
            handler.send_response(201);handler.send_header('Content-Length',str(len(body)));handler.end_headers();handler.wfile.write(body)
        server.RequestHandlerClass.do_POST=invalid_cid
        host,store,supervisor=make();authorized=consumed(host)
        result=host.dispatch(**authorized)
        self.assertFalse(result['success']);self.assertTrue(result['definitive']);self.assertIsNone(result['candidateId'])
        self.assertEqual(len(writes),4);self.assertEqual(len(store.read()['events']),3)


@unittest.skipUnless(os.name=='posix','Unix fixed actor primitive checks')
class ActorResponseBoundaryTests(unittest.TestCase):
    def test_oversize_truncated_and_missing_responses_each_forward_once_without_receipt(self):
        import base64,hashlib,socketserver,threading,tempfile,time,secrets
        from http.server import BaseHTTPRequestHandler
        from deployment_compose_action_actor_v4 import ActionActorSupervisorV4,send,receive,socket_facts
        for mode in ('oversize','truncated','missing'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve();root.chmod(0o700);path=root/'engine.sock';writes=[]
                class Handler(BaseHTTPRequestHandler):
                    def log_message(self,*args):pass
                    def do_POST(self):
                        writes.append(self.rfile.read(int(self.headers['Content-Length'])))
                        if mode=='missing':self.close_connection=True;return
                        self.send_response(201)
                        self.send_header('Content-Length','65537' if mode=='oversize' else '10')
                        self.end_headers()
                        try:self.wfile.write(b'{}')
                        except OSError:pass
                        self.close_connection=True
                server=socketserver.UnixStreamServer(str(path),Handler)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                supervisor=ActionActorSupervisorV4()
                try:
                    config=dict(schemaVersion=4,kind='single-create-leaf-v4',socket=str(path),socketIdentity=socket_facts(str(path)),
                        path='/v1.45/containers/create?name=dwc-'+'a'*24+'-service',bodyBase64=base64.b64encode(b'{}').decode(),
                        bodyDigest=hashlib.sha256(b'{}').hexdigest(),requestHash='b'*64,contextDigest='c'*64,
                        actionDigest='d'*64,sessionHash='e'*64,actorEpoch='f'*64)
                    actor=supervisor._start(config);process=supervisor._actors[actor][0]
                    # Primitive transport test only: the private parent pipe is
                    # exercised directly, not a claimed composite authorization.
                    go={k:config[k] for k in ('requestHash','contextDigest','actionDigest','sessionHash','actorEpoch')}
                    go.update(kind='go-v4',nonce=secrets.token_hex(32),deadline=time.monotonic()+5,
                        cursor={'seq':2,'head':'1'*64},scopeOrdinal=0,planWriteIndex=0)
                    send(process.stdin,go,go['deadline'])
                    with self.assertRaises(ValueError):receive(process.stdout,go['deadline'])
                    supervisor.stop_and_join(actor)
                    self.assertEqual(writes,[b'{}'])
                finally:
                    supervisor.close();server.shutdown();server.server_close();thread.join(5)


@unittest.skipUnless(os.name=='posix','real fork and held parent lock required')
class WriterForkOwnershipTests(unittest.TestCase):
    def test_all_entrypoints_reject_fork_before_inherited_parent_lock(self):
        import base64,hashlib,socket,tempfile,time
        from deployment_compose_action_actor_v4 import ActionActorSupervisorV4,socket_facts,WriterActorTerminationV4
        from tests import test_deployment_compose_operation_witness_v4 as witness_tests
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();root.chmod(0o700);path=root/'engine.sock'
            engine=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);engine.bind(str(path))
            supervisor=ActionActorSupervisorV4()
            try:
                config=dict(schemaVersion=4,kind='single-create-leaf-v4',socket=str(path),socketIdentity=socket_facts(str(path)),
                    path='/v1.45/containers/create?name=dwc-'+'a'*24+'-service',bodyBase64=base64.b64encode(b'{}').decode(),
                    bodyDigest=hashlib.sha256(b'{}').hexdigest(),requestHash='b'*64,contextDigest='c'*64,
                    actionDigest='d'*64,sessionHash='e'*64,actorEpoch='f'*64)
                actor=supervisor._start(config);process=supervisor._actors[actor][0]
                callbacks=[lambda:supervisor._start(config),lambda:supervisor.actor_identity(actor,'e'*64),
                    lambda:supervisor.send_go(actor,host=None,go_evidence=None),lambda:supervisor.stop_and_join(actor),
                    lambda:supervisor.termination_digest(actor,WriterActorTerminationV4(),'e'*64),
                    supervisor.close,lambda:supervisor.receive_response(actor,time.monotonic()+1)]
                witness_tests.assert_fork_copies_rejected(self,callbacks,[supervisor._mutex])
                self.assertIsNone(process.poll())
                proof=supervisor.stop_and_join(actor)
                self.assertEqual(len(supervisor.termination_digest(actor,proof,'e'*64)),64)
                self.assertIsNotNone(process.poll())
            finally:supervisor.close();engine.close()
