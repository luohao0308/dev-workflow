"""Full native Gate/TLS/signature scene create test; no real provider or Engine.

Kernel delegation and unprivileged-leaf isolation are explicit doubles only.
No production approval is minted or bypassed: native approval code runs against
its existing mock GitHub/OIDC/ledger provider and signs fresh test RPC replies.
"""
import base64
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import asdict
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),*(str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts','tests/support'))]
from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase,OwnedLocalProcess
import deployment_compose_scene_create_worker_v3_host as worker
import deployment_compose_live_worker_v3_host as live
import deployment_compose_create_transport_v3_host as transport_module
from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_v3_channel_worker import read_frame,write_frame
from deployment_compose_witness_store import canonical
from deployment_gateway import GatePolicy
from deployment_gate_witness import key_material


class TLSLeafKernelDouble:
    """Actual mTLS request to original gateway; only kernel drain facts doubled."""
    def __init__(self,*,worker_uid,worker_gid,ca_pem,client_cert_pem,client_key_pem):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name)
        for name,data in (('ca.pem',ca_pem),('cert.pem',client_cert_pem),('key.pem',client_key_pem)):(root/name).write_bytes(data)
        self.context=ssl.create_default_context(cafile=str(root/'ca.pem'))
        self.context.load_cert_chain(root/'cert.pem',root/'key.pem')
        self._group=SimpleNamespace(actor_epoch=secrets.token_hex(32));self.facts=None;self.response=None
    def request(self,*,request_hash,scope_hash,port,pin,operation,body,headers,docker_socket,deadline):
        connection=http.client.HTTPSConnection('localhost',port,context=self.context,timeout=10)
        try:
            connection.connect()
            if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()!=pin:raise ValueError('server-pin')
            connection.request(operation['method'],operation['path'],body,headers)
            response=connection.getresponse();raw=response.read(65537)
            if len(raw)>65536:raise ValueError('response-size')
            self.facts=(request_hash,scope_hash,self._group.actor_epoch,'kernel-double','drained',True)
            self.response=(response.status,hashlib.sha256(raw).hexdigest())
            return response.status,raw
        finally:connection.close()
    def close(self,deadline):self.temp.cleanup()
    def terminal_facts(self):return self.facts,self.response


def run_case(testcase,attack='',*,scene_controller=False,checkpoint_callback=None,scene_callback=None,published_source=None,after_reconciled=None,scene_stop=False):
    case=LocalAcceptanceCase(testcase);stack=ExitStack();process=None;store=None
    try:
        if scene_callback is not None and sys.platform=='darwin':
            # Explicit Linux filesystem-namespace double on macOS: root identity
            # stays /var/tmp while child I/O uses the native /private/var/tmp.
            # The original CAS/Gate constructors and verification run unchanged.
            class NamespaceRoot(type(Path())):
                def __truediv__(self,name):
                    return Path(super().__truediv__(name)).resolve()
            stack.enter_context(patch.object(worker,'Path',NamespaceRoot))
        witness,public=live_key(case.root,'witness-signing');intent,intent_public=live_key(case.root,'intent-signing')
        tls=live.writer_tls(case.engine_root)
        source_sha='b'*40 if published_source is None else published_source[0]
        archive=b'fixed-scene-archive-integration' if published_source is None else published_source[1]
        if published_source is not None:
            import deployment_compose_profile3_prepare_ssh_probe as source
            stack.enter_context(patch.object(source,'ROOT',published_source[2]))
        archive_digest=hashlib.sha256(archive).hexdigest()
        hello=dict(root=str(case.engine_spelling if scene_callback is not None else case.engine_root),daemonId='daemon-one',sourceSha=source_sha,archiveDigest=archive_digest,hostId='host-one',
            serverCertificateSha256=tls[2],writerCertificateSha256=tls[3])
        policy=GatePolicy('scene-test','scene-gate',hashlib.sha256(canonical(hello)).hexdigest(),tls[3],True,'0'*64,
            hashlib.sha256(key_material(public)).hexdigest(),operation_profile='compose-v3')
        keys={key:secrets.token_bytes(32) for key in live.KEYS};gate_key=secrets.token_bytes(32)
        if published_source is not None:
            import compose_profile3_prepare_fixture as preparation
            native_prepare=preparation._prepare_observed
            def prepare_source(*args,**kwargs):
                kwargs['source_sha']=source_sha
                return native_prepare(*args,**kwargs)
            stack.enter_context(patch.object(preparation,'_prepare_observed',prepare_source))
        session=case.prepare(case.engine_root,{'ID':'daemon-one'},source_sha=source_sha,host_id='host-one',expected_daemon_id='daemon-one',
            keys=keys,policy_hash=policy.identity_hash(),environment='staging',expiry_seconds=900)
        prepared=session.prepared;bundle=prepared['bundle'];request=prepared['request']
        capsule=live.private_json(live.private_capsule(session,prepared));facts=[]
        class Capture:
            config={'sourceSha':source_sha,'archiveDigest':archive_digest}
            def emit(self,kind,**data):facts.append(data)
        live.emit_observer_facts(Capture(),session,prepared,case.engine_spelling if scene_callback is not None else case.engine_root)
        directory=case.root/'witness';directory.mkdir(mode=0o700);store=OperationWitnessStoreV3(directory,key=secrets.token_bytes(32))
        admission=MacLiveAdmissionV3(store=store,gate_policy=policy,gate_key=gate_key,witness_signer=witness,
            witness_public_key=public,intent_signer=intent,intent_public_key=intent_public)
        approval,consumption,_=case.review_adapter().consume_prepared(bundle,request,lambda value:None)
        if scene_controller:
            from tests.support.compose_scene_controller_integration_fixture import drive_scene
            return drive_scene(testcase,case,stack,admission,approval,consumption,session,capsule,hello,keys,archive,facts[0],attack,checkpoint_callback=checkpoint_callback,scene_callback=scene_callback,after_reconciled=after_reconciled,scene_stop=scene_stop)
        binding=admission.register_intent(bundle,request,approval,consumption)
        from deployment_compose_coordinator_v3_host import digest
        refs=dict(requestHash=request.digest(),receiptHash=digest(asdict(consumption)),firstBinding=binding)
        if attack=='revoked-ledger':
            next(iter(approval.client.markers.values()))['object']['sha']='0'*40
        context=dict(daemonBinding={'root':str(case.engine_root),'daemonId':'daemon-one'},hello=hello,
            capsuleBase64=base64.b64encode(encode(capsule)).decode(),integrityKeys={k:base64.b64encode(v).decode() for k,v in keys.items()},
            gatePolicy=asdict(policy),gateKey=base64.b64encode(gate_key).decode(),witnessPublicKey=base64.b64encode(public).decode(),
            intentPublicKey=base64.b64encode(intent_public).decode(),consume=refs,observerFacts=facts[0],normalizationVersion=session.guard._version)
        if attack=='fake-consumption':context['consume']=dict(refs,receiptHash='0'*64)
        if attack=='wrong-status-key':
            other_signer,other_public=live_key(case.root,'other-intent-signing')
            context['intentPublicKey']=base64.b64encode(other_public).decode()
        stack.enter_context(patch.object(worker,'_fresh',return_value={'ID':'daemon-one','DockerRootDir':str(case.engine_root/'data')}))
        stack.enter_context(patch.object(worker.original,'preflight'))
        stack.enter_context(patch.object(worker,'PrivateDaemon',side_effect=lambda root,info:SimpleNamespace(socket=str(root/'docker.sock'),daemon_id=info['ID'])))
        stack.enter_context(patch.object(worker.original,'OwnedCreateTransportV3',TLSLeafKernelDouble))
        stack.enter_context(patch.object(transport_module,'OwnedCreateTransportV3',TLSLeafKernelDouble))
        config=dict(entrypoint=worker.ENTRYPOINT,sourceSha=source_sha,archiveDigest=archive_digest,channelNonce='d'*64,hostId='host-one',context=context)
        process=OwnedLocalProcess(lambda owned:worker.run(config,owned.input,owned.output))
        terminal=None;rpcs=[]
        while process.poll() is None:
            try:frame=read_frame(process.stdout,timeout=30)
            except ValueError:break
            if frame['kind']=='scene-create-closed':terminal=frame;break
            testcase.assertEqual(frame['kind'],'rpc');rpcs.append((frame['service'],frame['method']))
            try:reply=admission.authorize_rpc(frame['service'],frame['method'],frame['request'])
            except Exception:
                if attack!='revoked-ledger':raise
                process.stdin.close();break
            if attack=='unconsumed-status' and frame['service']=='intent':
                import subprocess
                from deployment_compose_intent_status_v3 import NAMESPACE
                reply=deepcopy(reply);reply['payload']['consumed']=False
                signed=subprocess.run(['ssh-keygen','-Y','sign','-f',str(intent),'-n',NAMESPACE],
                    input=encode(reply['payload']),capture_output=True,check=True,timeout=10)
                reply['signature']=base64.b64encode(signed.stdout).decode()
            if attack=='wrong-status-nonce' and frame['service']=='intent':
                reply=deepcopy(reply);reply['payload']['rpcNonce']='0'*64
            write_frame(process.stdin,dict(kind='reply',channelNonce=config['channelNonce'],rpcId=frame['rpcId'],response=reply),timeout=10)
        process.wait(timeout=15)
        writes=[(method,path) for method,path in case.harness.calls if method=='POST' and '/containers/create?' in path]
        if not attack:
            testcase.assertEqual(process.returncode,0,repr(process.failure));testcase.assertIsNotNone(terminal)
            proof=admission._history(admission._root).capture()
            testcase.assertEqual(proof.digest,terminal['historyDigest'])
            testcase.assertEqual(proof.snapshot['chainStatus']['activeSeq'],6)
        else:testcase.assertIsNone(terminal);testcase.assertNotEqual(process.returncode,0)
        return dict(terminal=terminal,postCount=len(writes),rpcMethods=rpcs,returncode=process.returncode,
            mockGitHub=True,mockEngine=True,kernelIsolationDouble=True,nativeGateTLSSSHSIG=True)
    finally:
        if process is not None:
            process.terminate();process.wait(timeout=15)
            for stream in (process.stdin,process.stdout,process.stderr):
                if not stream.closed:stream.close()
        stack.close()
        if store is not None:store.close()
        case.close()


def live_key(root,name):
    from deployment_compose_live_ssh_v3_host import _live_key
    return _live_key(root,name)
