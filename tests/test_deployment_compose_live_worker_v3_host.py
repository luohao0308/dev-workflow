"""Worker tests use pipes, local TLS and fakes only; no live host execution."""
import base64
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
for directory in ('scripts','tests/support','packs/deployment/scripts'):
    sys.path.insert(0,str(ROOT/directory))
import deployment_compose_live_worker_v3_host as worker
from deployment_compose_v3_channel_worker import write_frame, read_frame


def config():
    return dict(entrypoint=worker.ENTRYPOINT,channelNonce='1'*64,sourceSha='b'*40,archiveDigest='2'*64,hostId='private-host')


@unittest.skipUnless(os.name == 'posix', 'owned POSIX pipes, namespaces and TLS files')
class WorkerTests(unittest.TestCase):
    def test_fixed_probe_only_enters_network_and_has_limits(self):
        cmd=worker.probe_command('dw-live-probe-'+'a'*32+'.service',123,
            dict(backend='172.20.0.2',peer='172.20.0.3'),dict(backend='3.13.2',peer='3.12.9'),'dw-restore-'+'a'*24)
        self.assertIn('--property=RuntimeMaxSec=30',cmd)
        self.assertIn('--property=MemorySwapMax=0',cmd)
        self.assertIn('--property=TasksMax=16',cmd)
        self.assertEqual(cmd[cmd.index('nsenter'):cmd.index('-c')],
            ['nsenter','--net=/proc/'+str(os.getpid())+'/fd/123','--','/usr/bin/python3','-I'])
        self.assertNotIn('docker',cmd)
        self.assertIn("('127.0.0.11',53)",worker.PROBE_CODE)
        self.assertIn("root/'cpu.max'",worker.PROBE_CODE)
        compile(worker.PROBE_CODE,'fixed-probe','exec')

    def test_probe_inputs_reject_arbitrary_pid_names_addresses(self):
        valid=['dw-live-probe-'+'a'*32+'.service',123,dict(backend='172.20.0.2',peer='172.20.0.3'),dict(backend='3.13.2',peer='3.12.9'),'dw-restore-'+'a'*24]
        for index,value in ((0,'other.service'),(1,True),(1,0),(2,dict(backend='127.0.0.1',peer='172.20.0.3')),
                            (3,dict(backend='x;sh',peer='3.12.9')),(4,'x;sh')):
            args=valid.copy();args[index]=value
            with self.subTest(index=index,value=value),self.assertRaises(ValueError):worker.probe_command(*args)

    def test_nonce_mismatch_permanently_closes_channel(self):
        r,w=os.pipe()
        try:
            with os.fdopen(r,'rb',buffering=0) as reader,os.fdopen(w,'wb',buffering=0) as writer:
                write_frame(writer,dict(kind='configure',channelNonce='3'*64))
                channel=worker.Channel(config(),reader,writer)
                with self.assertRaises(ValueError):channel.receive('configure')
                with self.assertRaises(ValueError):channel.timeout()
        except OSError: raise

    def test_rpc_count_bound_before_io(self):
        channel=worker.Channel(config(),Mock(),Mock());channel.count=4096
        with patch.object(worker,'write_frame') as output,self.assertRaises(ValueError):
            channel.rpc('witness','read',{})
        output.assert_not_called();self.assertTrue(channel.failed)

    def test_no_consent_has_zero_executor_or_product_io(self):
        channel=Mock();channel.receive.side_effect=EOFError('no consent')
        session=Mock();prepared=dict(bundle=Mock(),request=Mock())
        with patch.object(worker,'Profile3StepExecutor') as executor,patch.object(worker,'AuthenticatedHistoryV3') as history:
            with self.assertRaises(EOFError):
                worker.execute_operation(channel,session,prepared,Mock(),b'x'*32,b'public',b'status',(),Mock())
            executor.assert_not_called();history.assert_not_called();session.target.assert_not_called()

    def test_wrong_request_blocks_before_status_writer_or_history(self):
        channel=Mock(); channel.receive.return_value=dict(requestHash='a'*64,receiptHash='b'*64,firstBinding={})
        request=Mock();request.digest.return_value='c'*64
        with patch.object(worker,'Profile3StepExecutor') as executor,patch.object(worker,'IntentStatusClientV3') as status:
            with self.assertRaises(ValueError):
                worker.execute_operation(channel,Mock(),dict(bundle=Mock(),request=request),Mock(),b'x'*32,b'pub',b'pub',(),Mock())
            executor.assert_not_called();status.assert_not_called()

    def test_unsigned_status_failure_never_constructs_writer(self):
        channel=Mock(); request=Mock();request.digest.return_value='c'*64
        bundle=Mock();bundle.creation_operations.return_value=[{}]
        binding=dict(scopeHash='d'*64,generation='g',policyHash='e'*64,epoch='f'*64)
        channel.receive.return_value=dict(requestHash='c'*64,receiptHash='b'*64,firstBinding=binding)
        policy=Mock();policy.identity_hash.return_value='e'*64
        tracker=Mock();tracker.epoch='f'*64
        with patch.object(worker.Profile3StepExecutor,'scope_descriptor',return_value=dict(scopeHash='d'*64,generation='g')), \
             patch.object(worker,'IntentStatusClientV3') as status, \
             patch.object(worker,'AuthenticatedHistoryV3') as history:
            status.return_value.check_consumed_intent.side_effect=ValueError('bad signature')
            with self.assertRaisesRegex(ValueError,'bad signature'):
                worker.execute_operation(channel,Mock(),dict(bundle=bundle,request=request),policy,b'x'*32,b'pub',b'pub',(),tracker)
            history.assert_not_called();tracker.mark_product_pending.assert_not_called()

    def test_unknown_result_keeps_cleanup_frozen_when_history_unavailable(self):
        channel=Mock(); request=Mock();request.digest.return_value='c'*64
        bundle=Mock();bundle.creation_operations.return_value=[{}]
        binding=dict(scopeHash='d'*64,generation='g',policyHash='e'*64,epoch='f'*64)
        channel.receive.return_value=dict(requestHash='c'*64,receiptHash='b'*64,firstBinding=binding)
        policy=Mock();policy.identity_hash.return_value='e'*64
        tracker=Mock();tracker.epoch='f'*64
        tracker.apply_to_session.side_effect=ValueError('history unresolved')
        session=Mock();session.root=Path('/private');session.target.socket='/private/docker.sock'
        with patch.object(worker,'Profile3StepExecutor') as executor, \
             patch.object(worker,'IntentStatusClientV3'),patch.object(worker,'AuthenticatedHistoryV3'), \
             patch.object(worker,'OperationWitnessClientV3'),patch.object(worker,'ComposeCoordinatorV3') as coordinator:
            executor.scope_descriptor.return_value=dict(scopeHash='d'*64,generation='g')
            coordinator.return_value.run.side_effect=TimeoutError('unknown Engine result')
            with self.assertRaisesRegex(TimeoutError,'unknown Engine result'):
                worker.execute_operation(channel,session,dict(bundle=bundle,request=request),policy,b'x'*32,b'pub',b'pub',(Mock(),Mock(),'a'*64,'b'*64),tracker)
            self.assertTrue(session.unknown_write_result)
            tracker.mark_product_pending.assert_called_once()
            tracker.apply_to_session.assert_called_once()
            coordinator.return_value.run.assert_called_once()

    def test_collected_probe_stop_is_authoritatively_accepted(self):
        result=Mock(stdout=b'LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlGroup=\n',returncode=1)
        with patch.object(worker.subprocess,'run',return_value=result) as run:
            worker.stop_probe_unit('dw-live-probe-'+'a'*32+'.service')
        self.assertEqual(run.call_count,2)
        self.assertTrue(all(call.args[0][1]=='show' for call in run.call_args_list))

    def test_probe_stop_rejects_surviving_pid(self):
        result=Mock(stdout=b'LoadState=loaded\nActiveState=inactive\nMainPID=123\nControlGroup=\n',returncode=0)
        with patch.object(worker.subprocess,'run',return_value=result),self.assertRaises(ValueError):
            worker.stop_probe_unit('dw-live-probe-'+'a'*32+'.service')

    def test_executor_constructor_failure_starts_frozen_and_reconciles(self):
        channel=Mock();request=Mock();request.digest.return_value='c'*64
        bundle=Mock();bundle.creation_operations.return_value=[{}]
        binding=dict(scopeHash='d'*64,generation='g',policyHash='e'*64,epoch='f'*64)
        channel.receive.return_value=dict(requestHash='c'*64,receiptHash='b'*64,firstBinding=binding)
        policy=Mock();policy.identity_hash.return_value='e'*64
        tracker=Mock();tracker.epoch='f'*64
        session=Mock();session.root=Path('/private');session.target.socket='/private/docker.sock'
        def constructor(*args,**kwargs):
            self.assertTrue(session.unknown_write_result)
            tracker.mark_product_pending.assert_called_once()
            raise ValueError('startup unknown')
        with patch.object(worker,'Profile3StepExecutor') as executor, \
             patch.object(worker,'IntentStatusClientV3'),patch.object(worker,'AuthenticatedHistoryV3'), \
             patch.object(worker,'OperationWitnessClientV3'):
            executor.scope_descriptor.return_value=dict(scopeHash='d'*64,generation='g')
            executor.side_effect=constructor
            with self.assertRaisesRegex(ValueError,'startup unknown'):
                worker.execute_operation(channel,session,dict(bundle=bundle,request=request),policy,b'x'*32,b'pub',b'pub',(Mock(),Mock(),'a'*64,'b'*64),tracker)
            tracker.apply_to_session.assert_called_once()

    def test_readiness_waits_healthy_and_pins_namespace_fd(self):
        from copy import deepcopy
        image=dict(Id='sha256:'+'a'*64,Config={'Env':['PYTHON_VERSION=3.13.2']})
        peer=dict(Id='2'*64,Image=image['Id'],State=dict(Pid=123,StartedAt='pinned',Running=True,Health={'Status':'healthy'}),
            NetworkSettings={'Networks':{'private':{'IPAddress':'172.20.0.3'}}})
        backend=deepcopy(peer);backend['Id']='a'*64;backend['NetworkSettings']['Networks']['private']['IPAddress']='172.20.0.2'
        session=Mock();session.raw_rows={'peer':peer};session.project='dw-restore-'+'a'*24;session.enrolled_images=[image]
        calls=[]
        def get(path):
            calls.append(path)
            if '/images/' in path:return deepcopy(image)
            if peer['Id'] in path:return deepcopy(peer)
            result=deepcopy(backend)
            if len([p for p in calls if backend['Id'] in p])==1:result['State']['Health']['Status']='starting'
            return result
        session.producer._get.side_effect=get
        with patch('deployment_compose_phase_guard_v3_host.protected_state_digest',side_effect=worker.canonical), \
             patch.object(worker.time,'sleep') as sleep,patch.object(worker.os,'open',return_value=55), \
             patch.object(worker.os,'stat',return_value=Mock(st_ino=9)),patch.object(worker.os,'fstat',return_value=Mock(st_ino=9)), \
             patch.object(worker.os,'close') as close,patch.object(worker,'stop_probe_unit') as stop, \
             patch.object(worker.subprocess,'run',return_value=Mock(stdout=b'{"success":true}')) as run:
            self.assertTrue(worker.readiness(session,backend['Id']))
        sleep.assert_called_once()
        self.assertEqual(sum(call.args==(55,) for call in close.call_args_list),1)
        stop.assert_called_once()
        cmd=run.call_args.args[0]
        self.assertIn('--net=/proc/'+str(os.getpid())+'/fd/55',cmd)
        self.assertNotIn('--target',cmd)
        self.assertNotIn('123',cmd)
        with patch('deployment_compose_phase_guard_v3_host.protected_state_digest',side_effect=worker.canonical), \
             patch.object(worker.os,'open',return_value=55),patch.object(worker.os,'stat',return_value=Mock(st_ino=10)), \
             patch.object(worker.os,'fstat',return_value=Mock(st_ino=9)),patch.object(worker.os,'close') as close, \
             patch.object(worker,'stop_probe_unit') as stop,patch.object(worker.subprocess,'run') as run:
            with self.assertRaises(ValueError):worker.readiness(session,backend['Id'])
        run.assert_not_called();stop.assert_not_called();close.assert_called_once_with(55)

    def test_final_requires_outer_probe_shutdown_and_production_verification(self):
        payload=dict(result={'private':'result'},history={'private':'history'},success=True,cleanupCompleted=True)
        good=dict(completed=True,stopped=True,productionSnapshotUnchanged=True)
        for key in good:
            for value in (False,None,1):
                report=dict(good);report[key]=value
                channel=Mock()
                with self.subTest(key=key,value=value),self.assertRaises(ValueError):worker.finish_probe(channel,report,payload)
                channel.emit.assert_not_called()
        for payload_value in (None,dict(payload,cleanupCompleted=False),dict(payload,success=False)):
            channel=Mock()
            with self.assertRaises(ValueError):worker.finish_probe(channel,good,payload_value)
            channel.emit.assert_not_called()
        channel=Mock()
        self.assertIs(worker.finish_probe(channel,good,payload),good)
        channel.emit.assert_called_once_with('final',**payload,daemonStopped=True,productionSnapshotUnchanged=True)

    def test_outer_probe_failure_suppresses_final_and_preserves_error(self):
        channel=Mock();error=RuntimeError('owned outer shutdown failed')
        with patch.object(worker,'Channel',return_value=channel), \
             patch('deployment_compose_profile3_prepare_ssh_probe._probe',side_effect=error):
            with self.assertRaises(RuntimeError) as caught:worker.run(config(),Mock(),Mock())
        self.assertIs(caught.exception,error);channel.emit.assert_not_called()

    def test_tls_actual_contexts_and_restrictive_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            server,client,serverpin,writerpin=worker.writer_tls(root)
            self.assertEqual(server.verify_mode,ssl.CERT_REQUIRED)
            self.assertEqual(client.verify_mode,ssl.CERT_REQUIRED)
            self.assertTrue(client.check_hostname)
            self.assertNotEqual(serverpin,writerpin)
            for p in (root/'live-writer-tls').iterdir():self.assertEqual(p.stat().st_mode&0o777,0o600)
            import subprocess
            for name,usage in (('server','TLS Web Server Authentication'),('writer','TLS Web Client Authentication')):
                cert=subprocess.run(['openssl','x509','-in',str(root/'live-writer-tls'/(name+'.pem')),'-text','-noout'],capture_output=True,check=True).stdout.decode()
                self.assertIn('Digital Signature, Key Encipherment',cert);self.assertIn(usage,cert)

    def test_expiry_and_config_rejected_before_probe(self):
        for value in ({},dict(config(),entrypoint='arbitrary.run'),dict(config(),channelNonce='invalid')):
            with patch('deployment_compose_profile3_prepare_ssh_probe._probe') as probe:
                with self.assertRaises(ValueError):worker.run(value,Mock(),Mock())
                probe.assert_not_called()

    def test_private_json_preserves_bytes_explicitly(self):
        self.assertEqual(worker.private_json({'body':b'abc'}),{'body':{'bodyBase64':'YWJj'}})


@unittest.skipUnless(os.name == 'posix', 'private Unix Engine/TLS/CAS host')
class WorkerIntegrationTests(unittest.TestCase):
    def test_real_tls_gate_admission_deploy_then_fresh_rollback(self):
        """Local Unix Engine double; real reader/writer TLS, CAS, signatures and Gate."""
        from copy import deepcopy
        from dataclasses import replace
        import subprocess
        import urllib.parse
        from tests.test_compose_profile3_prepare_fixture import CurrentPreparationUnixTests
        from tests.test_deployment_compose_live_admission_v3_host import AdmissionTests
        import compose_profile3_prepare_fixture as fixture
        from compose_profile3_ownership_fixture import FixtureOwnershipTrackerV3
        from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
        from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
        from deployment_compose_rollback_prepare_v3_host import RollbackPreparationHostV3
        from deployment_compose_startup_fence_v3_host import Profile3StartupFenceV3
        from deployment_compose_namespaced_runtime_probe import PrivateDaemon
        from deployment_gate_witness import key_material
        from deployment_gateway import GatePolicy
        import json

        class Harness(CurrentPreparationUnixTests):
            def prepare_initial(self,bodies):
                self.tls=worker.writer_tls(self.root)
                self.signers=[];self.public=[]
                for name in ('witness','intent'):
                    key=self.root/(name+'-signing')
                    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True,capture_output=True)
                    key.chmod(0o600);self.signers.append(key);self.public.append(key.with_suffix('.pub').read_bytes())
                self.policy=GatePolicy('worker-local','gate-key','a'*64,self.tls[3],True,'0'*64,
                    hashlib.sha256(key_material(self.public[0])).hexdigest(),operation_profile='compose-v3')
                original=fixture._prepare_observed
                def prepare(*args,**kwargs):
                    kwargs['policy_hash']=self.policy.identity_hash()
                    return original(*args,**kwargs)
                with patch.object(fixture,'_prepare_observed',side_effect=prepare):super().prepare_initial(bodies)
        h=Harness('test_initial_and_current_real_unix_tls_cas_signed_history')
        try:
            h.setUp()
            # Existing helper owns a real local Unix HTTP server. Extend only its
            # Engine-double handlers to model the five approved operation types.
            server=next(fn.__self__ for fn,args,kwargs in h._cleanups if getattr(fn,'__name__','')=='shutdown')
            handler=server.RequestHandlerClass
            created=[]
            def respond(handler,status,value=None):
                raw=b'' if value is None else worker.canonical(value)
                handler.send_response(status);handler.send_header('Content-Length',str(len(raw)))
                handler.end_headers();handler.wfile.write(raw)
            def post(handler):
                h.calls.append(('POST',handler.path))
                path=urllib.parse.urlsplit(handler.path); bits=path.path.split('/')
                body=handler.rfile.read(int(handler.headers.get('Content-Length','0')))
                if path.path=='/v1.45/containers/create':
                    value=json.loads(body);cid=('a' if not created else 'b')*64;created.append(cid)
                    row=deepcopy(h.rows['2'*64]);row.update(Id=cid,Image=value['Image'],
                        Name='/'+urllib.parse.parse_qs(path.query)['name'][0])
                    row['Config']={k:v for k,v in value.items() if k not in ('HostConfig','NetworkingConfig')}
                    row['HostConfig']=value['HostConfig'];row['State'].update(Pid=0,StartedAt='',Running=False,Status='created')
                    for name,endpoint in value['NetworkingConfig']['EndpointsConfig'].items():
                        row['NetworkSettings']['Networks'][name].update(endpoint)
                    row['State']['Health']['Status']='starting'
                    h.rows[cid]=row;respond(handler,201,{'Id':cid})
                elif bits[-1]=='stop':
                    row=h.rows[bits[-2]];row['State'].update(Pid=0,Running=False,Status='exited');respond(handler,204)
                elif bits[-1]=='rename':
                    h.rows[bits[-2]]['Name']='/'+urllib.parse.parse_qs(path.query)['name'][0];respond(handler,204)
                elif bits[-1]=='start':
                    row=h.rows[bits[-2]];row['State'].update(Pid=456+len(created),StartedAt='started-'+str(len(created)),Running=True,Status='running')
                    row['State']['Health']['Status']='healthy';respond(handler,204)
                else:raise AssertionError(handler.path)
            def delete(handler):
                h.calls.append(('DELETE',handler.path));cid=urllib.parse.urlsplit(handler.path).path.split('/')[-1]
                del h.rows[cid];respond(handler,204)
            handler.do_POST=post;handler.do_DELETE=delete
            target=object.__new__(PrivateDaemon)
            target.socket=str(h.root/'docker.sock');target.daemon_id='daemon-one';target.host='unix://'+target.socket
            h.session.target=target;h.session.created_ids=['1'*64,'2'*64]
            directory=h.root/'witness-store';directory.mkdir(mode=0o700)
            store=OperationWitnessStoreV3(directory,key=b'w'*32)
            self.addCleanup(store.close)
            host=MacLiveAdmissionV3(store=store,gate_policy=h.policy,gate_key=b'g'*32,
                witness_signer=h.signers[0],witness_public_key=h.public[0],intent_signer=h.signers[1],intent_public_key=h.public[1])
            def consume(request):
                from tests import test_deployment_compose_approval_v3_host as approvals
                from tests.test_release_host import claims
                harness=approvals.ComposeApprovalTests();harness.setUp()
                harness.policy=approvals.policy(operation=request.operation,source_sha=request.source.source_sha,
                    target_repository=request.source.project_path,target_repository_id=request.source.project_id,
                    daemon_id=request.daemon_id,host_id=request.host_id,deployment_environment=request.environment,
                    target=request.target,components=request.components,protected_components=request.protected_components,
                    policy_hash=request.policy_hash,bundle_hash=request.plan_hash,expected_history_hash=request.history_hash)
                harness.claims=dict(claims(harness.policy),aud=approvals.host.AUDIENCE)
                harness.client=harness.client_for([request])
                harness.client.data['/repos/'+request.source.project_path]=dict(id=request.source.project_id,full_name=request.source.project_path)
                authority=harness.approval([request])
                return authority,authority.consume(authority.validate(request),request)
            class LocalChannel:
                def __init__(self):self.next=None;self.consumptions=0;self.calls=[];self.config=config();self.frames=[]
                def emit(self,kind,**payload):self.frames.append(dict(kind=kind,**payload))
                def receive(self,kind):
                    self.assert_kind=kind
                    assert kind=='consume-intent' and self.next is not None
                    value=self.next;self.next=None;self.consumptions+=1;return value
                def rpc(self,service,method,request):
                    self.calls.append((service,method));return host.authorize_rpc(service,method,request)
                def enroll(self,prepared,parent=None):
                    approval,receipt=consume(prepared['request'])
                    binding=host.register_intent(prepared['bundle'],prepared['request'],approval,receipt,reviewed_parent=parent)
                    self.next=dict(requestHash=prepared['request'].digest(),receiptHash=hashlib.sha256(worker.canonical(asdict(receipt))).hexdigest(),firstBinding=binding)
            channel=LocalChannel();prepared=h.session.prepared
            worker.emit_observer_facts(channel,h.session,prepared,h.root)
            capsule=worker.private_capsule(h.session,prepared)
            self.assertEqual(channel.frames[-1]['bootId'],capsule['observationMaterial']['boot'])
            self.assertIsNone(channel.frames[-1]['bindDigest'])
            self.assertEqual(channel.frames[-1]['operation'],'deploy')
            with patch.object(h.session.whole_observer._reader,'gateway_info',return_value={'bootId':'0'*32}):
                with self.assertRaises(ValueError):worker.emit_observer_facts(channel,h.session,prepared,h.root)
            self.assertEqual(len(channel.frames),1)
            self.assertEqual(capsule['publicReview'],prepared['bundle'].public_review())
            self.assertIn('baselineArtifacts',capsule)
            self.assertNotIn('key',capsule['targetInputs']['backend'])
            worker.canonical(worker.private_json(capsule))
            channel.enroll(prepared)
            tracker=FixtureOwnershipTrackerV3(project=h.project,daemon_id='daemon-one',policy_hash=h.policy.identity_hash(),
                witness_pub_hash=h.policy.witness_key_sha256,epoch=host._epoch,initial_confirmed_ids=h.session.created_ids,protected_ids=['2'*64])
            initial=deepcopy(h.rows['2'*64]);call_start=len(h.calls)
            with patch.object(worker,'readiness',return_value=True) as probe:
                result,history=worker.execute_operation(channel,h.session,prepared,h.policy,b'g'*32,h.public[0],h.public[1],h.tls,tracker)
                self.assertEqual(result['receipts'],{'backend':'a'*64})
                self.assertEqual(h.session.created_ids,['2'*64,'a'*64])
                self.assertFalse(h.session.unknown_write_result)
                snapshot=history.capture()
                self.assertEqual(len(json.loads(snapshot.canonical)['knownPrefix']),5)
                current=fixture.prepare_current_profile3(h.session,original_bundle=prepared['bundle'],original_request=prepared['request'],
                    authenticated_history=history,keys=h.keys,source_sha='b'*40,host_id='host-one',policy_hash=h.policy.identity_hash())
                rollback=RollbackPreparationHostV3(original_bundle=prepared['bundle'],original_request=prepared['request'],original_history=history,
                    original_archive_store=h.session.store,original_private_keys={'profile3-config':h.keys['config']},current_preparation=current['preparer'])
                # Isolated archive-validator seam: substitute only the bundle
                # reference projection; store.put/get still MACs real CAS bytes.
                # Neither altered archive can reach an executor or registration.
                from copy import copy
                original_archive=json.loads(h.session.store.get(prepared['bundle'].to_dict()['archiveReference']))
                for ids in (['1'*64],['1'*64,'2'*64,'e'*64]):
                    altered=deepcopy(original_archive)
                    altered['observationScope']['containerIds']=ids
                    reference=h.session.store.put(worker.canonical(altered))
                    check=copy(rollback);value=prepared['bundle'].to_dict();value['archiveReference']=reference
                    check._bundle=Mock();check._bundle.to_dict.return_value=value
                    with self.subTest(source_ids=ids),self.assertRaises(ValueError):check._archive()
                fresh=rollback.prepare_intent(current['whole_observation'],current['retention_observation'],operation_nonce='f'*64,
                    expires_at=current['prepared']['request'].expires_at)
                current['private_session'].enrolled_images=h.session.enrolled_images
                current['guard']=worker.bind_prepared_guard(current['private_session'],fresh,h.root)
                worker.emit_observer_facts(channel,current['private_session'],fresh,h.root)
                rollback_capsule=worker.private_capsule(current['private_session'],fresh)
                self.assertEqual(channel.frames[-1]['bootId'],rollback_capsule['observationMaterial']['boot'])
                self.assertEqual(channel.frames[-1]['operation'],'rollback')
                self.assertNotEqual(channel.frames[0]['bootId'],channel.frames[-1]['bootId'])
                self.assertEqual(fresh['request'].operation,'rollback')
                self.assertNotEqual(fresh['request'].digest(),prepared['request'].digest())
                before_review=len([c for c in h.calls if c[0]!='GET'])
                with self.assertRaises(AssertionError):
                    worker.execute_operation(channel,h.session,fresh,h.policy,b'g'*32,h.public[0],h.public[1],h.tls,tracker)
                self.assertEqual(len([c for c in h.calls if c[0]!='GET']),before_review)
                channel.enroll(fresh,snapshot)
                fence=Profile3StartupFenceV3(original_history=history,reviewed_history=snapshot,
                    quiesce_writer=lambda:history.capture().canonical==snapshot.canonical)
                h.session.guard=current['guard']
                result,child=worker.execute_operation(channel,h.session,fresh,h.policy,b'g'*32,h.public[0],h.public[1],h.tls,tracker,
                    parent=history,reviewed=snapshot,fence=fence)
                self.assertEqual(result['receipts'],{'backend':'b'*64})
                self.assertEqual(len(json.loads(child.capture().canonical)['knownPrefix']),5)
                self.assertEqual(h.session.created_ids,['2'*64,'b'*64])
                self.assertFalse(h.session.unknown_write_result)
                self.assertEqual(probe.call_count,2)
            writes=[(method,path) for method,path in h.calls[call_start:] if method!='GET']
            self.assertEqual(len(writes),10)
            self.assertEqual(channel.consumptions,2)
            self.assertIn(('intent','check'),channel.calls)
            self.assertEqual(h.rows['2'*64],initial)
            self.assertEqual(h.rows['b'*64]['Image'],prepared['bundle'].to_dict()['services'][0]['baselineImageId'])
            self.assertEqual(set(h.rows),{'2'*64,'b'*64})
            h.session.cleanup()
            self.assertEqual(h.rows,{})
        finally:
            # A failed assertion must never accidentally invoke real Docker CLI.
            # The helper's session has no external resources; any unresolved
            # product result retains its cleanup freeze exactly as production.
            h.doCleanups()

if __name__=='__main__':unittest.main()
