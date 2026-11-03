"""Native controller/broker/worker/cert/reconcile integration on a fake Engine.

Scene authentication transport and prepared startup are explicit local doubles;
service Unix/HMAC tests cover control authentication separately. Only Linux
kernel/issuer isolation and fresh daemon identity are doubled. No business
signature, approval/status validator, Gate, CAS, phase guard or receipt is mocked.
"""
import base64
import hashlib
import os
import secrets
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.support.compose_scene_create_integration_fixture import TLSLeafKernelDouble,OwnedLocalProcess,worker,transport_module
import deployment_compose_scene_create_broker_v3_host as broker_module
import deployment_compose_scene_create_controller_v3_host as controller_module
import deployment_compose_scene_preparation_v3_host as preparation_module
import deployment_compose_scene_writer_slot_v3_host as slot_module
import deployment_compose_owned_recovery_unit_v3_host as units
from deployment_compose_scene_service_v3_host import SceneClientV3,SceneHandleV3
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_restart_checkpoint_v3_host import directory,publish,read_file
from deployment_compose_v3_channel_worker import read_frame
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_witness_store import canonical
from deployment_gate_witness import key_material


def drive_scene(testcase,case,stack,admission,approval,consumption,session,capsule,hello,keys,archive,facts,attack,checkpoint_callback=None,scene_callback=None):
    processes=[];calls=[];origin_calls=[];pending_seen=[]
    boot=facts['bootId'];boot='-'.join((boot[:8],boot[8:12],boot[12:16],boot[16:20],boot[20:]))
    binding=dict(root=hello['root'],daemonId='daemon-one',kernelBoot=boot,unit=case.engine_root.name+'.service',invocationId='c'*32,cgroupDevice=1,cgroupInode=2,mainPid=123,mainStartTicks=1,daemonPid=124,daemonStartTicks=1)
    observer=object.__new__(ObservedRecoveryDaemonV3);observer.root=str(case.engine_root);observer.daemon_id='daemon-one'
    stack.enter_context(patch.object(ObservedRecoveryDaemonV3,'binding',return_value=binding))
    stack.enter_context(patch.object(preparation_module,'_fresh',return_value={'ID':'daemon-one','DockerRootDir':hello['root']+'/data'}))
    prep=preparation_module.PreparationOwnerV3(observer,hello['sourceSha'],hello['archiveDigest'])
    raw=encode(capsule);path=case.engine_root/'scene-preparation';path.mkdir(mode=0o700)
    fd,identity=directory(path)
    frame_sizes={}
    try:
        publish(fd,'capsule.private.json',raw);stored,file_identity=read_file(fd,'capsule.private.json',4*1024*1024)
        testcase.assertEqual(stored,raw)
    finally:os.close(fd)
    metadata=dict(preparationId=secrets.token_hex(32),capsuleDigest=hashlib.sha256(raw).hexdigest(),totalBytes=len(raw),observerFacts=facts)
    record=preparation_module._RECORDS[prep]
    record.update(state='prepared',identity=canonical(hello),session=session,raw=raw,metadata=metadata,
        fileIdentity=(identity,file_identity),host=hello['hostId'],keys=keys)
    stack.enter_context(patch.object(worker,'_fresh',return_value={'ID':'daemon-one','DockerRootDir':hello['root']+'/data'}))
    stack.enter_context(patch.object(worker.original,'preflight'))
    stack.enter_context(patch.object(worker,'PrivateDaemon',side_effect=lambda root,info:SimpleNamespace(socket=str(root/'docker.sock'),daemon_id=info['ID'])))
    stack.enter_context(patch.object(worker.original,'OwnedCreateTransportV3',TLSLeafKernelDouble))
    stack.enter_context(patch.object(transport_module,'OwnedCreateTransportV3',TLSLeafKernelDouble))
    stack.enter_context(patch.object(units,'_environment'));stack.enter_context(patch.object(units,'_boot',return_value=binding['kernelBoot']))
    def start(unit,**kwargs):
        def run(owned):
            config=read_frame(owned.input,timeout=10);config.pop('archiveBase64')
            if attack=='wrong-status-key':config['context']['intentPublicKey']=base64.b64encode(admission._public[0]).decode()
            worker.run(config,owned.input,owned.output)
            if attack=='unclean-worker-exit':raise RuntimeError('test post-terminal cleanup failure')
        unit._process=OwnedLocalProcess(run);processes.append(unit._process);pending_seen.append(session.unknown_write_result)
    def origin(unit,**kwargs):
        return canonical(dict(schemaVersion=1,kind='compose-owned-writer-origin-v3',sourceSha=hello['sourceSha'],archiveDigest=hello['archiveDigest'],
            unit=unit.unit,kernelBoot=binding['kernelBoot'],invocationId='b'*32,mainPid=os.getpid(),mainStartTicks=1,
            cgroupDevice=1,cgroupInode=1,parentDevice=1,parentInode=1,pidNamespaceDevice=1,pidNamespaceInode=1))
    def stop(unit,**kwargs):
        origin_calls.append('stop');unit._process.terminate();unit._process.wait(timeout=15)
    def close(unit):
        origin_calls.append('close')
        for stream in (unit._process.stdin,unit._process.stdout,unit._process.stderr):
            if not stream.closed:stream.close()
    stack.enter_context(patch.object(worker.SceneCreateUnitV3,'start',start))
    stack.enter_context(patch.object(worker.SceneCreateUnitV3,'capture_origin',origin))
    stack.enter_context(patch.object(worker.SceneCreateUnitV3,'stop',stop))
    stack.enter_context(patch.object(worker.SceneCreateUnitV3,'close',close))
    def observed(*args,**kwargs):
        origin_calls.append('observe');return SimpleNamespace(writerStoppedObserved=True,observation_digest='e'*64)
    stack.enter_context(patch.object(slot_module,'observe_stopped_writer',side_effect=observed))
    slot=slot_module.SlotOwnerV3(hello['sourceSha'],hello['archiveDigest']);scene='dw-scene-'+secrets.token_hex(8)
    broker=broker_module.SceneCreateBrokerV3(prep,archive,*admission._public,slot,scene)
    from deployment_compose_scene_control_ssh_v3_host import SceneSSHClientV3,SceneSSHHandleV3
    client_type=SceneClientV3 if scene_callback is None else SceneSSHClientV3
    clients=[];handle=SceneHandleV3(scene,str(case.root/'control.sock'),secrets.token_bytes(32))
    if scene_callback is not None:
        import deployment_compose_scene_control_ssh_v3_host as ssh_control
        stack.enter_context(patch.object(ssh_control,'_issued_scene_ssh_client',lambda client:None))
        handle=SceneSSHHandleV3(scene,'/var/tmp/'+scene+'/control.sock',handle.controlKey,hello['hostId'],hello['sourceSha'],archive)
        stack.enter_context(patch.object(client_type,'detach',SceneClientV3.detach))
        stack.enter_context(patch.object(client_type,'close',SceneClientV3.close))
    def new_client(subject,connection_handle):
        testcase.assertIs(connection_handle,handle);clients.append(subject)
        subject._handle=handle;subject._closed=False
        subject._owner=(os.getpid(),threading.get_ident());subject._socket=SimpleNamespace(close=lambda:broker.controller_lost())
    stack.enter_context(patch.object(client_type,'__init__',new_client))
    client=client_type(handle)
    def call(subject,command,args=None):
        testcase.assertIn(subject,clients);testcase.assertFalse(subject._closed);calls.append(command);args=args or {}
        if command=='detach':return {}
        if command=='status':return dict(sceneId=scene,preparation=metadata,slotGeneration=slot.status()['slotGeneration'],business=broker.status())
        if command=='start_first_create':
            value=broker.start_first_create(args,1)
            with testcase.assertRaises(ValueError):broker.start_first_create(args,1)
            testcase.assertEqual(len(processes),1)
        elif command=='poll_worker':
            value=broker.poll_worker()
            if attack=='controller-lost' and 'message' in value:
                broker.controller_lost();value=broker.status()
        elif command=='read_worker_chunk':value=broker.read_worker_chunk(args['attemptId'],args['messageDigest'],args['offset'],args['length'])
        elif command=='begin_worker_reply':value=broker.begin_worker_reply(args['attemptId'],args['totalBytes'],args['messageDigest'],args['rpcId'])
        elif command=='worker_reply_chunk':value=broker.worker_reply_chunk(args['attemptId'],args['offset'],args['dataBase64'])
        elif command=='commit_worker_reply':value=broker.commit_worker_reply(args['attemptId'])
        elif command=='finish_worker':value=broker.finish_worker(args['attemptId'])
        elif command=='reconcile_closure':
            if attack=='bad-closure':args['certificate']['payload']['receiptMap']={'web':'f'*64}
            if attack=='native-phase-drift':case.harness.rows['1'*64]['Name']='/tampered-baseline'
            value=broker.reconcile_closure(args['certificate'])
        else:raise AssertionError(command)
        return {'business':value}
    stack.enter_context(patch.object(client_type,'_call',call))
    native_register=type(admission).register_intent
    def register(subject,*args,**kwargs):
        testcase.assertTrue(all(item._closed for item in clients))
        return native_register(subject,*args,**kwargs)
    stack.enter_context(patch.object(type(admission),'register_intent',register))
    native_issue=controller_module.issue_create_closure
    def issue(*args,**kwargs):
        testcase.assertTrue(all(item._closed for item in clients))
        testcase.assertEqual(broker.status()['businessState'],'closed')
        return native_issue(*args,**kwargs)
    stack.enter_context(patch.object(controller_module,'issue_create_closure',issue))
    controller=controller_module.SceneCreateControllerV3(client=client,admission=admission,capsule_bytes=raw,hello=hello,
        integrity_keys=keys,preparation_id=metadata['preparationId'],capsule_digest=metadata['capsuleDigest'],trusted_boot_id=facts['bootId'])
    try:
        if attack:
            with testcase.assertRaises(ValueError):controller.run_first_create(approval=approval,consumption={'consumed':True} if attack=='fake-consumption' else consumption,timeout=60)
        else:
            final=controller.run_first_create(approval=approval,consumption=consumption,timeout=60,on_restart_checkpoint=checkpoint_callback,on_scene_checkpoint=scene_callback)
            testcase.assertEqual(final['businessState'],'reconciled');testcase.assertTrue(final['closureReconciled'])
            testcase.assertEqual(pending_seen,[True]);testcase.assertFalse(session.unknown_write_result)
            testcase.assertEqual(len(clients),4 if checkpoint_callback is not None or scene_callback is not None else 3);testcase.assertEqual(calls.count('start_first_create'),1)
            testcase.assertIn('a'*64,session.created_ids);testcase.assertEqual(origin_calls,['stop','observe','close'])
            testcase.assertEqual(admission._history(admission._root).capture().snapshot['chainStatus']['activeSeq'],6)
            with testcase.assertRaises(ValueError):controller.run_first_create(approval=approval,consumption=consumption)
            import deployment_compose_scene_service_v3_host as service
            prepared_status=prep.status();slot_status=slot.status()
            full_result=dict(sceneId=scene,controllerExclusive=True,leaseSeconds=30,daemonId=hello['daemonId'],
                daemonBinding=binding,generation=2**53-1,**{key:False for key in service._FALSE})
            full_result.update(writerSlot=slot_status,slotGeneration=slot_status['slotGeneration'],
                slotState=slot_status['slotState'],preparationState=prepared_status['preparationState'],
                preparationIdentity=prepared_status['preparationIdentity'],preparation=prepared_status['capsule'],
                business=broker.status())
            lease=dict(sceneId=scene,serverNonce='1'*64,clientNonce='2'*64,generation=2**53-1,leaseNonce='3'*64)
            unix=service._signed(handle.controlKey,dict(kind='scene-result-v3',**lease,seq=2**53-1,command='status',result=full_result))
            ssh=dict(kind='scene-control-result-v3',channelNonce='4'*64,seq=2**53-1,command='status',result=full_result)
            frame_sizes=dict(unixFrameBytes=len(service._frame(unix))-4,sshFrameBytes=len(service._frame(ssh))-4)
            testcase.assertLessEqual(max(frame_sizes.values()),service.MAX_FRAME)
            prep.cleanup();testcase.assertNotIn('a'*64,case.harness.rows)
        if attack:
            testcase.assertTrue(clients[-1]._closed)
            testcase.assertEqual(slot.status()['slotState'],'empty' if attack=='fake-consumption' else 'drained')
        posts=[v for v in case.harness.calls if v[0]=='POST' and '/containers/create?' in v[1]]
        expected_posts=0 if attack in ('fake-consumption','wrong-status-key','controller-lost') else 1
        testcase.assertEqual(len(posts),expected_posts)
        return dict(postCount=len(posts),controllerBrokerIntegrated=True,sceneAuthenticationTransportDouble=True,
            mockEngine=True,mockGitHub=True,kernelIsolationDouble=True,commands=calls,**frame_sizes)
    finally:
        try:
            broker.controller_lost()
            if session.unknown_write_result:
                # Unknown stays burned. Only the fake server/files are torn
                # down; production cleanup must reject and issue no DELETE.
                before=list(case.harness.calls)
                with testcase.assertRaisesRegex(ValueError,'profile3-cleanup-blocked-after-unknown'):prep.cleanup()
                testcase.assertEqual(case.harness.calls,before)
                case.harness._cleanups=[item for item in case.harness._cleanups
                    if not (getattr(item[0],'__self__',None) is session and getattr(item[0],'__name__','')=='cleanup')]
        finally:
            for process in processes:
                process.terminate();process.wait(timeout=15)
                for stream in (process.stdin,process.stdout,process.stderr):
                    if not stream.closed:stream.close()
