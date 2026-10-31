"""Fixed local Popen peer. Engine/provider are fixtures, gate/history RPC real.

Never SSH, systemd, Docker, or external GitHub; no production entry point.
"""
import base64
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import time
import unittest
import uuid
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),*(str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts','tests/support'))]
from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase
import deployment_compose_live_worker_v3_host as live
from deployment_compose_owned_recovery_worker_v3_host import Channel, ENTRYPOINT
from deployment_compose_history_v3_host import AuthenticatedHistoryV3
from deployment_compose_intent_status_v3 import IntentStatusClientV3
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
from deployment_gateway import GatePolicy,FileWriterGate
from deployment_compose_witness_store import canonical


def run():
    attack=sys.argv[1]; engine=sys.argv[2]
    cfg=dict(entrypoint=ENTRYPOINT,channelNonce='1'*64,sourceSha='b'*40,archiveDigest='2'*64,hostId='host-one')
    channel=Channel(cfg,sys.stdin.buffer,sys.stdout.buffer)
    original_emit=channel.emit
    def emit(kind,**data):
        if kind=='hello':
            if attack=='bad-nonce':channel.config=dict(cfg,channelNonce='0'*64)
            if attack in ('bad-source','buffered-stderr'):data['sourceSha']='0'*40
            if attack=='bad-archive':data['archiveDigest']='0'*64
            if attack=='bad-daemon':data['daemonId']='foreign-daemon'
            if attack=='bad-root':data['root']='/var/tmp/dw-engine-'+'0'*16
        if kind=='observer-facts' and attack=='bad-observer':data['bootId']='0'*32
        if kind=='prepared-private' and attack=='bad-initial':data['request']['plan_hash']='0'*64
        if kind=='recovery-prepared-private':
            if attack=='bad-context':data['context']['startWriteIndex']=2
            if attack=='extra-context':data['history']={}
            if attack=='bad-phase':data['context']['currentPhaseSnapshot']['rows']['a'*64]['State']['Pid']=9
        if kind=='final':
            if attack=='false-final':data['daemonStopped']=False
            if attack=='false-history':data['history']['knownPrefix']=[]
            if attack=='false-schema':data['history']['schemaVersion']=1
            if attack=='false-count':data['history']['parent']['scopeCount']=5
            if attack=='bool-count':data['result']['initialWriteCount']=True
        original_emit(kind,**data)
    channel.emit=emit
    if attack=='eof':return
    if attack=='timeout':time.sleep(30);return
    if attack=='buffered-stderr':
        import subprocess
        subprocess.Popen([sys.executable,'-c','import time; time.sleep(3)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
    if attack=='stderr-overflow':
        sys.stderr.buffer.write(b'x'*(1024*1024+1));sys.stderr.buffer.flush();time.sleep(30);return
    channel.emit('hello',root=engine,daemonId='daemon-one',writerCertificateSha256='a'*64,
        serverCertificateSha256='c'*64,sourceSha=cfg['sourceSha'],archiveDigest=cfg['archiveDigest'],hostId=cfg['hostId'])
    setup=channel.receive('configure')
    if attack=='wrong-order':channel.emit('prepared-private');return
    case=LocalAcceptanceCase(unittest.TestCase())
    # The fixture owns only its own temporary fake Engine directory.
    import shutil
    shutil.rmtree(case.engine_root)
    case.engine_spelling=Path(engine);case.engine_spelling.mkdir(mode=0o700,exist_ok=True)
    case.engine_root=case.engine_spelling.resolve()
    policy=GatePolicy(**setup['policy'])
    keys={k:base64.b64decode(v) for k,v in setup['keys'].items()}
    public=base64.b64decode(setup['witnessPublicKey']);status=base64.b64decode(setup['statusPublicKey'])
    gate_key=base64.b64decode(setup['gateKey'])
    session=None
    try:
        with patch('deployment_compose_reader_host.uuid.uuid4',return_value=uuid.UUID('4'*32)):
            session=case.prepare(case.engine_root,{'ID':'daemon-one'},source_sha=cfg['sourceSha'],host_id=cfg['hostId'],
                expected_daemon_id='daemon-one',keys=keys,policy_hash=policy.identity_hash(),environment='staging',expiry_seconds=900)
        channel.emit('observer-facts',operation='deploy',root=engine,daemonId='daemon-one',
            sourceSha=cfg['sourceSha'],archiveDigest=cfg['archiveDigest'],bootId='4'*32,bindDigest=None)
        channel.emit('prepared-private',**live.private_capsule(session,session.prepared))
        if attack=='lost-consume':return
        bundle,request=session.prepared['bundle'],session.prepared['request']
        refs=channel.receive('consume-intent')
        factory=lambda binding:OperationWitnessClientV3(binding,public,lambda method,req:channel.rpc('witness',method,req))
        def history(request,refs,parent=None,reviewed=None):
            IntentStatusClientV3(request,status,lambda req:channel.rpc('intent','check',req)).check_consumed_intent(request)
            return AuthenticatedHistoryV3(bundle,request,gate_policy=policy,gate_key=gate_key,
                consumption_receipt_hash=refs['receiptHash'],witness_client=factory(refs['firstBinding']),
                witness_client_factory=factory,parent_history=parent,reviewed_parent_snapshot=reviewed)
        root_history=history(request,refs)
        binding=refs['firstBinding'];receipts={}
        def finish(index,request,refs,binding):
            ops=bundle.creation_operations() if index==0 else [o for o in bundle.resolve_operations(receipts) if o['method']!='GET']
            op=ops[index]
            desc=Profile3StepExecutor.scope_descriptor(bundle,request,refs['receiptHash'],op,index,receipts)
            gate=FileWriterGate(replace(policy,witness_scope_hash=binding['scopeHash']),
                case.root/('gate-'+binding['generation']),key=gate_key,witness=GateOperationWitnessAdapterV3(factory(binding)))
            opened=gate.open_generation(generation=binding['generation'],request_hash=request.digest(),
                receipt_hash=refs['receiptHash'],operations=desc['operations'],source_context_digest=desc['source'])
            raw=b'' if op['body'] is None else canonical(op['body'])
            attempt=opened.prepare_attempt(op['method'],op['path'],raw)
            ticket=gate.admit(binding['generation'],attempt.ref,method=op['method'],path=op['path'],
                body=raw,writer_certificate_sha256=policy.writer_certificate_sha256)
            gate.finish_response(ticket,definitive=True,status=201 if index==0 else 204,
                body=canonical({'Id':'a'*64}) if index==0 else b'')
            gate.close_generation(binding['generation'])
            if index==0:receipts['backend']='a'*64
        finish(0,request,refs,binding)
        if attack in ('early-transition','bad-method','replay-id','replay-nonce'):
            req=dict(binding=binding,bootNonce='8'*64,rpcNonce='9'*64)
            if attack=='early-transition':channel.rpc('witness','transition_successor',req)
            elif attack=='bad-method':channel.rpc('witness','register_once',req)
            else:
                channel.rpc('witness','read',req)
                if attack=='replay-id':channel.count-=1;req=dict(req,rpcNonce='7'*64)
                channel.rpc('witness','read',req)
            return
        # Update only the fake Engine after the authenticated create response.
        service=bundle.to_dict()['services'][0];body=service['targetCreateBody']
        row=deepcopy(case.harness.rows[service['baselineContainerId']])
        row.update(Id='a'*64,Image=body['Image'],Name='/dwc-'+bundle.to_dict()['operationNonce'][:24]+'-backend')
        row['Config']={k:deepcopy(v) for k,v in body.items() if k not in ('HostConfig','NetworkingConfig')}
        row['HostConfig']=deepcopy(body['HostConfig'])
        for name,endpoint in body['NetworkingConfig']['EndpointsConfig'].items():row['NetworkSettings']['Networks'][name].update(endpoint)
        row['State'].update(Pid=0,StartedAt='',Running=False,Status='created');row['State']['Health']['Status']='starting'
        case.harness.rows['a'*64]=row
        preparation=RecoveryPreparationHostV3(original_history=root_history,store=session.store,phase_guard=session.guard,readiness=lambda *args:True)
        prepared=preparation.prepare_intent(operation_nonce='5'*64,expires_at=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        context=preparation.verify_context(prepared['recovery_context_reference'],prepared['request'],prepared['reviewed_history'])
        channel.emit('recovery-prepared-private',request=asdict(prepared['request']),context=context)
        if attack=='lost-second-consume':return
        child_refs=channel.receive('consume-intent');request=prepared['request']
        child_history=history(request,child_refs,parent=root_history,reviewed=prepared['reviewed_history'])
        for index in range(1,5):
            if index==1:following=child_refs['firstBinding']
            else:
                op=[o for o in bundle.resolve_operations(receipts) if o['method']!='GET'][index]
                desc=Profile3StepExecutor.scope_descriptor(bundle,request,child_refs['receiptHash'],op,index,receipts)
                following=dict(scopeHash=desc['scopeHash'],generation=desc['generation'],policyHash=policy.identity_hash(),epoch=setup['epoch'])
            client=factory(binding);view=client.read()
            client.transition_successor(expected_seq=view['seq'],expected_head=view['head'],childBinding=following)
            binding=following;finish(index,request,child_refs,binding)
        value=json.loads(child_history.capture().canonical)
        channel.emit('final',result=dict(receipts=receipts,initialWriteCount=1,productionReady=False),history=value,
            success=True,cleanupCompleted=True,daemonStopped=True,productionSnapshotUnchanged=True,productionReady=False)
        if attack=='nonzero':raise RuntimeError('fixed nonzero fixture')
        if attack=='held-stderr':
            import subprocess
            subprocess.Popen([sys.executable,'-c','import time; time.sleep(7)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
    finally:
        # Local fixture rows are synthetic. Clear before its ordinary cleanup.
        if session is not None:case.harness.rows.clear();session.created_ids.clear()
        case.close()


if __name__=='__main__':run()
