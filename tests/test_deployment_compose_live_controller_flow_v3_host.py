"""Owned local pipe integration, never SSH, Docker, systemd or external GitHub.

Seams: fixed source archive/loader, private Engine provisioning and host readiness
are test doubles; GitHub HTTP responses use the existing approval fixture.
Reader/writer TLS, CAS, capsule verification, controller/worker frames, admission,
intent/witness signatures, Store, coordinator and cleanup ownership are real.
macOS's /private/var/tmp prefix is normalized only in outbound host-root facts
so the Linux provenance spelling can be checked by the unmodified controller.
"""
import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import threading
import traceback
import unittest
from unittest.mock import patch
import urllib.parse

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts','tests/support')]
import deployment_compose_live_ssh_v3_host as controller
import deployment_compose_live_worker_v3_host as worker
import deployment_compose_profile3_prepare_ssh_probe as probe_module
import compose_profile3_prepare_fixture as preparation
from tests import test_compose_profile3_prepare_fixture as preparation_tests
from tests import test_deployment_compose_approval_v3_host as approval_tests
from tests.test_release_host import claims
from deployment_compose_namespaced_runtime_probe import PrivateDaemon
from deployment_compose_log_probe import IMAGE
from deployment_compose_namespaced_transition_probe import V2
from deployment_compose_v3_channel_worker import read_frame,write_frame


class OwnedLocalProcess:
    """One owned thread and real OS pipes; no simulated frame reads or RPCs."""
    def __init__(self, target):
        ri,wi=os.pipe();ro,wo=os.pipe();re,we=os.pipe()
        self.stdin=os.fdopen(wi,'wb',buffering=0)
        self.stdout=os.fdopen(ro,'rb',buffering=0)
        self.stderr=os.fdopen(re,'rb',buffering=0)
        self.input=os.fdopen(ri,'rb',buffering=0)
        self.output=os.fdopen(wo,'wb',buffering=0)
        self.error=os.fdopen(we,'wb',buffering=0)
        self.returncode=None;self.failure=None
        def main():
            try:target(self);self.returncode=0
            except BaseException as error:
                self.failure=error;self.returncode=1
                try:self.error.write(traceback.format_exc().encode())
                except BrokenPipeError:pass
            finally:
                self.input.close();self.output.close();self.error.close()
        self.thread=threading.Thread(target=main,daemon=True);self.thread.start()
    def poll(self):return self.returncode
    def wait(self,timeout=None):
        self.thread.join(timeout)
        if self.thread.is_alive():
            import subprocess
            raise subprocess.TimeoutExpired('owned-local-worker',timeout)
        return self.returncode
    def terminate(self):
        if not self.stdin.closed:self.stdin.close()
        # Also unblock a worker writing a capsule after the controller rejects
        # an earlier frame. This owns only our local read pipe, never a host PID.
        if self.poll() is None and not self.stdout.closed:self.stdout.close()
    def kill(self):self.terminate()


class LocalAcceptanceCase:
    def __init__(self, testcase, attack=None):
        self.testcase=testcase;self.attack=attack;self.process=None;self.harness=None
        self.worker_frames=[];self.controller_frames=[];self.reviewed=[];self.notices=[]
        self.alias='host-one';self.source='b'*40;self.archive=b'fixed-test-published-source'
        self.temp=tempfile.TemporaryDirectory(prefix='live-controller-')
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.engine_spelling=Path('/var/tmp')/('dw-engine-'+secrets.token_hex(8))
        self.engine_spelling.mkdir(mode=0o700)
        self.engine_root=self.engine_spelling.resolve()
        self.recipient=self.root/'recipient.private';self.recipient.write_bytes(b'test-recipient');self.recipient.chmod(0o600)
        self.settings=None;self.initial=None

    def close(self):
        if self.process is not None:
            self.process.terminate();self.process.wait(timeout=15)
        if self.harness is not None:
            if not self.harness.doCleanups():raise AssertionError('local Engine fixture cleanup failed')
        shutil.rmtree(self.engine_root,ignore_errors=True)
        self.temp.cleanup()

    def review_adapter(self,*args):
        owner=self
        class Review:
            def consume_prepared(self,bundle,request,on_review):
                owner.reviewed.append(request)
                on_review(dict(operation=request.operation,requestHash=request.digest()))
                harness=approval_tests.ComposeApprovalTests();harness.setUp()
                harness.policy=approval_tests.policy(operation=request.operation,source_sha=request.source.source_sha,
                    target_repository=request.source.project_path,target_repository_id=request.source.project_id,
                    daemon_id=request.daemon_id,host_id=request.host_id,deployment_environment=request.environment,
                    target=request.target,components=request.components,protected_components=request.protected_components,
                    policy_hash=request.policy_hash,bundle_hash=request.plan_hash,expected_history_hash=request.history_hash)
                harness.claims=dict(claims(harness.policy),aud=approval_tests.host.AUDIENCE)
                harness.client=harness.client_for([request])
                harness.client.data['/repos/'+request.source.project_path]=dict(id=request.source.project_id,full_name=request.source.project_path)
                authority=harness.approval([request])
                receipt=authority.consume(authority.validate(request),request)
                return authority,receipt,dict(operation=request.operation,requestHash=request.digest(),mockGitHub=True)
        return Review()

    def prepare(self,root,info,**settings):
        owner=self;self.settings=settings
        class ExistingRoot:
            name=str(owner.engine_root)
            def cleanup(self):pass
        original_temp=tempfile.TemporaryDirectory
        class Harness(preparation_tests.CurrentPreparationUnixTests):
            def prepare_initial(self,bodies):
                self.keys=settings['keys']
                self.images[0]['RepoDigests']=['public.ecr.aws/docker/library/'+IMAGE]
                self.images[1]['RepoDigests']=['public.ecr.aws/docker/library/'+V2]
                original=preparation._prepare_observed
                def observed(*args,**kwargs):
                    kwargs['policy_hash']=settings['policy_hash']
                    return original(*args,**kwargs)
                with patch.object(preparation,'_prepare_observed',side_effect=observed):super().prepare_initial(bodies)
        def temp_factory(*args,**kwargs):
            if kwargs.get('prefix')=='p3-':return ExistingRoot()
            return original_temp(*args,**kwargs)
        h=Harness('test_initial_and_current_real_unix_tls_cas_signed_history');self.harness=h
        with patch.object(preparation_tests.tempfile,'TemporaryDirectory',side_effect=temp_factory):h.setUp()
        server=next(fn.__self__ for fn,args,kwargs in h._cleanups if getattr(fn,'__name__','')=='shutdown')
        handler=server.RequestHandlerClass;created=[]
        def respond(handler,status,value=None):
            raw=b'' if value is None else worker.canonical(value)
            handler.send_response(status);handler.send_header('Content-Length',str(len(raw)))
            handler.end_headers()
            if raw:handler.wfile.write(raw)
        def post(handler):
            h.calls.append(('POST',handler.path))
            path=urllib.parse.urlsplit(handler.path);bits=path.path.split('/')
            body=handler.rfile.read(int(handler.headers.get('Content-Length','0')))
            if path.path=='/v1.45/containers/create':
                value=json.loads(body);cid=('a' if not created else 'b')*64;created.append(cid)
                row=deepcopy(h.rows['2'*64]);row.update(Id=cid,Image=value['Image'],Name='/'+urllib.parse.parse_qs(path.query)['name'][0])
                row['Config']={k:v for k,v in value.items() if k not in ('HostConfig','NetworkingConfig')}
                row['HostConfig']=value['HostConfig'];row['State'].update(Pid=0,StartedAt='',Running=False,Status='created')
                for name,endpoint in value['NetworkingConfig']['EndpointsConfig'].items():row['NetworkSettings']['Networks'][name].update(endpoint)
                row['State']['Health']['Status']='starting';h.rows[cid]=row;respond(handler,201,{'Id':cid})
            elif bits[-1]=='stop':
                h.rows[bits[-2]]['State'].update(Pid=0,Running=False,Status='exited');respond(handler,204)
            elif bits[-1]=='rename':h.rows[bits[-2]]['Name']='/'+urllib.parse.parse_qs(path.query)['name'][0];respond(handler,204)
            elif bits[-1]=='start':
                row=h.rows[bits[-2]];row['State'].update(Pid=456+len(created),StartedAt='started-'+str(len(created)),Running=True,Status='running')
                row['State']['Health']['Status']='healthy';respond(handler,204)
            else:raise AssertionError(handler.path)
        def delete(handler):
            h.calls.append(('DELETE',handler.path));del h.rows[urllib.parse.urlsplit(handler.path).path.split('/')[-1]];respond(handler,204)
        handler.do_POST=post;handler.do_DELETE=delete
        target=object.__new__(PrivateDaemon)
        target.socket=str(h.root/'docker.sock');target.daemon_id='daemon-one';target.host='unix://'+target.socket
        h.session.target=target;h.session.created_ids=['1'*64,'2'*64]
        return h.session

    def outer_probe(self,workload):
        workload(self.engine_root,{'ID':'daemon-one'})
        return dict(completed=True,stopped=True,productionSnapshotUnchanged=True)

    def worker_write(self,stream,value,timeout=30):
        frame=deepcopy(value)
        if frame['kind'] in ('hello','observer-facts'):frame['root']=str(self.engine_spelling)
        if self.attack=='bad-nonce' and frame['kind']=='hello':frame['channelNonce']='0'*64
        if self.attack=='no-facts' and frame['kind']=='observer-facts':return
        if self.attack=='false-final' and frame['kind']=='final':frame['daemonStopped']=False
        self.worker_frames.append(frame)
        write_frame(stream,frame,timeout=timeout)
        if self.attack=='extra-rpc' and frame['kind']=='hello':
            write_frame(stream,dict(kind='rpc',channelNonce=frame['channelNonce'],rpcId=1,service='witness',
                method='register_once',request={'rpcNonce':'f'*64}),timeout=timeout)

    def spawn(self,argv):
        self.testcase.assertEqual(argv[0],'ssh')
        def target(process):
            self.initial=read_frame(process.input)
            self.testcase.assertEqual(base64.b64decode(self.initial.pop('archiveBase64')),self.archive)
            worker.run(self.initial,process.input,process.output)
        self.process=OwnedLocalProcess(target)
        return self.process

    def controller_write(self,stream,value,timeout=30):
        self.controller_frames.append(deepcopy(value))
        return write_frame(stream,value,timeout=timeout)

    def run(self):
        with patch.object(controller,'published_live_archive',return_value=self.archive), \
             patch.object(controller,'_spawn_live',side_effect=self.spawn), \
             patch.object(controller,'_review_adapter',side_effect=self.review_adapter), \
             patch.object(controller,'write_frame',side_effect=self.controller_write), \
             patch.object(probe_module,'_probe',side_effect=self.outer_probe), \
             patch.object(preparation,'prepare_profile3',side_effect=self.prepare), \
             patch.object(worker,'readiness',return_value=True), \
             patch.object(worker,'write_frame',side_effect=self.worker_write):
            return controller.run_live_acceptance(self.root,self.alias,self.source,
                on_review=self.notices.append,recipient_private_key=self.recipient)


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'local pipes/OpenSSL/OpenSSH required')
class ControllerFlowTests(unittest.TestCase):
    def test_real_owned_pipe_controller_worker_deploy_and_rollback(self):
        case=LocalAcceptanceCase(self);self.addCleanup(case.close)
        result=case.run()
        self.assertTrue(result['success'])
        self.assertEqual(result['requestCount'],2)
        self.assertTrue(result['daemonStopped']);self.assertTrue(result['productionSnapshotUnchanged'])
        self.assertEqual([r.operation for r in case.reviewed],['deploy','rollback'])
        self.assertNotEqual(case.reviewed[0].digest(),case.reviewed[1].digest())
        self.assertIsNone(case.reviewed[0].history_hash);self.assertIsNotNone(case.reviewed[1].history_hash)
        self.assertEqual(len(case.notices),2)
        self.assertEqual(case.harness.rows,{})
        writes=[(method,path) for method,path in case.harness.calls if method!='GET']
        self.assertEqual(len(writes),14) # ten gated operations, four confirmed cleanup operations
        phases=[('delete' if method=='DELETE' else urllib.parse.urlsplit(path).path.split('/')[-1]) for method,path in writes[:10]]
        self.assertEqual(phases,['create','stop','delete','rename','start']*2)
        for (method,path),cid in zip(writes[10:],['b'*64,'b'*64,'2'*64,'2'*64]):self.assertIn(cid,path)
        self.assertEqual(len(result['witnessFinal']['lineage']),9)
        self.assertEqual(result['witnessFinal']['activePhase'],'closed')
        self.assertEqual(result['witnessFinal']['activeSeq'],6)
        rpc=[f for f in case.worker_frames if f['kind']=='rpc']
        self.assertTrue(rpc);self.assertTrue(any(f['service']=='intent' for f in rpc))
        self.assertFalse(any(f['method'] in ('register_once','reset') for f in rpc))
        self.assertEqual(sum(f['method']=='append_event' for f in rpc),60)
        self.assertEqual(sum(f['method']=='transition_successor' for f in rpc),9)
        self.assertEqual([f['rpcId'] for f in rpc],list(range(1,len(rpc)+1)))
        self.assertEqual(len({f['request']['rpcNonce'] for f in rpc}),len(rpc))
        facts=[f for f in case.worker_frames if f['kind']=='observer-facts']
        self.assertEqual(len(facts),2);self.assertNotEqual(facts[0]['bootId'],facts[1]['bootId'])
        self.assertEqual(case.worker_frames[-1]['kind'],'final')
        self.assertTrue(case.worker_frames[-1]['cleanupCompleted'])
        self.assertEqual(case.process.returncode,0)
        self.assertNotIn('archiveBase64',case.initial)
        encoded=json.dumps(case.controller_frames)
        for credential in ('GITHUB_TOKEN','GH_TOKEN','oidcToken','githubToken'):self.assertNotIn(credential,encoded)

    def test_bad_nonce_and_extra_rpc_rejected_before_review(self):
        for attack in ('bad-nonce','extra-rpc'):
            with self.subTest(attack=attack):
                case=LocalAcceptanceCase(self,attack);self.addCleanup(case.close)
                with self.assertRaises(ValueError):case.run()
                self.assertEqual(case.reviewed,[])
                self.assertFalse(any(case.root.glob('live-*/witness/state.json')))
                self.assertFalse(any(case.root.glob('live-*/result.private.json')))
                case.close()

    def test_missing_host_facts_rejected_before_review(self):
        case=LocalAcceptanceCase(self,'no-facts');self.addCleanup(case.close)
        with self.assertRaises(ValueError):case.run()
        self.assertEqual(case.reviewed,[])
        self.assertFalse(any(case.root.glob('live-*/witness/state.json')))
        self.assertFalse(any(case.root.glob('live-*/result.private.json')))

    def test_false_final_rejected_after_real_two_intents(self):
        case=LocalAcceptanceCase(self,'false-final');self.addCleanup(case.close)
        with self.assertRaises(ValueError):case.run()
        self.assertEqual([r.operation for r in case.reviewed],['deploy','rollback'])
        self.assertFalse(any(case.root.glob('live-*/result.private.json')))
        self.assertEqual(case.harness.rows,{})

@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'local signed admission fixtures require OpenSSH')
class ControllerCompletionHistoryTests(unittest.TestCase):
    """Real MAC/signature/Store/Gate history; no controller completion stubs."""
    def signed_admission(self):
        from tests import test_deployment_compose_live_admission_v3_host as admission_tests
        harness=admission_tests.AdmissionTests('test_real_gate_two_steps_and_separate_intent_signature')
        # setUp is invoked directly to reuse fixture construction only; no
        # inherited TestCase methods are discovered or executed by this suite.
        harness.setUp()
        self.addCleanup(lambda:self.assertTrue(harness.doCleanups()))
        return harness

    def complete_deployment(self,harness):
        for index in range(5):
            if index:harness.transition()
            harness.finish()
        return controller._complete_history(harness.host,'deploy')

    def test_closed_partial_deployment_is_not_complete(self):
        h=self.signed_admission();h.finish()
        snapshot=h.host._history(h.host._current).capture()
        value=json.loads(snapshot.canonical)
        self.assertEqual(len(value['knownPrefix']),1)
        self.assertEqual(value['chainStatus']['activePhase'],'closed')
        self.assertEqual(value['chainStatus']['activeSeq'],6)
        before=h.store._seal(h.store._read())
        with self.assertRaises(ValueError):controller._complete_history(h.host,'deploy')
        self.assertEqual(h.store._seal(h.store._read()),before)

    def test_complete_root_deployment_is_accepted(self):
        h=self.signed_admission()
        snapshot=self.complete_deployment(h)
        value=json.loads(snapshot.canonical)
        self.assertEqual(value['schemaVersion'],1)
        self.assertEqual(len(value['knownPrefix']),5)
        self.assertEqual(len(value['scopes']),5)
        self.assertEqual(snapshot.canonical,h.host._history(h.host._current).capture().canonical)

    def test_pending_and_partial_rollback_rejected_complete_inverse_accepted(self):
        from dataclasses import replace
        from deployment_compose_bundle_v3 import ExecutionBundleV3,FIELDS
        h=self.signed_admission();parent=self.complete_deployment(h)
        old=h.bundle.to_dict();value={k:v for k,v in old.items() if k in FIELDS}
        service=value['services'][0];before=deepcopy(service)
        service.update(baselineContainerId='d'*64,baselineImageId=before['targetImageId'],targetImageId=before['baselineImageId'],
            baselineCreateBody=before['targetCreateBody'],targetCreateBody=before['baselineCreateBody'])
        value['operationNonce']='e'*64
        # This is the existing admission fixture's trusted baseline seam. The
        # separate pipe test verifies actual fresh baseline/CAS preparation.
        bundle=ExecutionBundleV3(value,authenticated_image_defaults=h.defaults)
        request=replace(h.request,operation='rollback',history_hash=parent.digest,plan_hash=bundle.digest,
            after_hash=hashlib.sha256(worker.canonical({service['name']:service['targetCreateBody']})).hexdigest())
        authority,receipt=h.consume(request)
        pending=h.host.register_intent(bundle,request,authority,receipt,reviewed_parent=parent)
        self.assertIs(h.host._current,h.host._root)
        self.assertEqual(h.host._current['request'].operation,'deploy')
        self.assertIsNotNone(h.host._pending)
        before_state=h.store._seal(h.store._read())
        with self.assertRaises(ValueError):controller._complete_history(h.host,'rollback',parent)
        with self.assertRaises(ValueError):controller._complete_history(h.host,'deploy')
        self.assertEqual(h.store._seal(h.store._read()),before_state)
        h.transition(pending)
        h.bundle,h.request,h.receipts,h.index=bundle,request,{},0
        h.finish()
        partial=json.loads(h.host._history(h.host._current).capture().canonical)
        self.assertEqual(partial['schemaVersion'],2)
        self.assertEqual(len(partial['knownPrefix']),1)
        self.assertEqual(partial['chainStatus']['activePhase'],'closed')
        self.assertEqual(partial['chainStatus']['activeSeq'],6)
        before_state=h.store._seal(h.store._read())
        with self.assertRaises(ValueError):controller._complete_history(h.host,'rollback',parent)
        self.assertEqual(h.store._seal(h.store._read()),before_state)
        for _ in range(4):h.transition();h.finish()
        complete=controller._complete_history(h.host,'rollback',parent)
        result=json.loads(complete.canonical)
        self.assertEqual(len(result['knownPrefix']),5)
        self.assertEqual(len(result['scopes']),5)
        self.assertEqual(result['parent']['historyDigest'],parent.digest)
        self.assertEqual(result['parent']['originalRequestHash'],h.host._root['request'].digest())
        self.assertEqual(result['parent']['tail'],json.loads(parent.canonical)['closedTail'])
        self.assertEqual(len(h.store._read()['scopes']),10)

if __name__=='__main__':unittest.main()
