"""Linux-only Gate/journal/CAS fault fixture. No Docker forwarding occurs."""
import base64
import hashlib
import json
import os
import time
from pathlib import Path
import secrets
import selectors
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'packs/deployment/scripts'),str(ROOT/'scripts')]
from deployment_gate_witness import OnlineWitnessClient,key_material,opening_scope
from deployment_gateway import GatePolicy,FileWriterGate
if os.name=='posix':
    from deployment_compose_journal_host import BatchJournal
    from deployment_compose_recovery_store import ComposeRecoveryStore

MODES=('joint-rollback','lost-ack','local-write-fail','cached-reply','offline')
LIMIT=65536

def read_frame(stream,timeout=30):
    pending=getattr(stream,'_witness_pending',b'')
    deadline=time.monotonic()+timeout
    with selectors.DefaultSelector() as selector:
        selector.register(stream,selectors.EVENT_READ)
        while b'\n' not in pending:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not selector.select(remaining):raise TimeoutError('witness-frame-deadline')
            if len(pending)>LIMIT:raise ValueError('invalid-witness-frame')
            chunk=os.read(stream.fileno(),LIMIT+1-len(pending))
            if not chunk:raise ValueError('invalid-witness-frame')
            pending+=chunk
    line,rest=pending.split(b'\n',1)
    if len(line)>LIMIT:raise ValueError('invalid-witness-frame')
    stream._witness_pending=rest
    return json.loads(line)

def material(generation,public):
    bodies=(b'{"fixture":1}',b'{"fixture":2}')
    ops=tuple(('POST','/v1.45/containers/create?name=dev-workflow-witness-'+str(i),hashlib.sha256(b).hexdigest()) for i,b in enumerate(bodies))
    request='b'*64;receipt='c'*64;cert='d'*64
    scope=opening_scope(generation,request,receipt,ops)
    policy=GatePolicy('ssh-witness','fixture-key','e'*64,cert,True,scope,hashlib.sha256(key_material(public)).hexdigest())
    return policy,ops,bodies,request,receipt,cert

def snapshot(root):return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}

def restore(root,old):
    for p in root.rglob('*'):
        if p.is_file() and str(p.relative_to(root)) not in old:p.unlink()
    for name,data in old.items():(root/name).write_bytes(data)

def run_case(config,exchange):
    if os.name!='posix':raise ValueError('posix-fixture-required')
    if config.get('mode') not in MODES:raise ValueError('unsupported-witness-case')
    mode=config['mode'];public=base64.b64decode(config['publicKey'],validate=True)
    key=base64.b64decode(config['gateKey'],validate=True);binding=config['binding'];gen=binding['generation']
    policy,ops,bodies,request,receipt,cert=material(gen,public)
    if binding['policyHash']!=policy.identity_hash() or binding['scopeHash']!=policy.witness_scope_hash:raise ValueError('fixture-binding-mismatch')
    root=Path(tempfile.mkdtemp(prefix='dw-witness-state-',dir='/var/tmp')).resolve()
    for name in ('journal','cas'):(root/name).mkdir(mode=0o700)
    actions=tuple(hashlib.sha256(json.dumps(x).encode()).hexdigest() for x in ops)
    calls=[];cached=[];fault=[False];forwarded=[0]
    def transport(method,data):
        calls.append({'method':method,'seq':data['expectedSeq'],'head':data['expectedHead']})
        if fault[0] and mode=='offline' and method=='reserve':raise ConnectionError('fixture-offline')
        if fault[0] and mode=='cached-reply' and method=='check':return cached[0]
        reply=exchange(method,data)
        if method=='check' and not fault[0]:cached[:]=[reply]
        if fault[0] and mode=='lost-ack' and method=='reserve':raise ConnectionError('fixture-lost-ack')
        return reply
    def client():return OnlineWitnessClient(binding,public,transport)
    gate=FileWriterGate(policy,root/'gate',key=key,witness=client())
    session=gate.open_generation(generation=gen,request_hash=request,receipt_hash=receipt,operations=ops)
    journal=BatchJournal(root/'journal','a'*64,request,actions,key)
    archive=ComposeRecoveryStore(root/'cas',key=key)
    def operation(index):
        attempt=session.prepare_attempt(ops[index][0],ops[index][1],bodies[index])
        journal.record_attempt(index,actions[index],attempt.ref)
        ticket=gate.admit(gen,attempt.ref,method=ops[index][0],path=ops[index][1],body=bodies[index],writer_certificate_sha256=cert)
        forwarded[0]+=1 # Synthetic upstream only: there is no Docker call.
        response=hashlib.sha256(('synthetic-'+str(index)).encode()).hexdigest()
        gate.finish(ticket,definitive=True,response_hash=response)
        ref=archive.put(('synthetic-'+str(index)).encode())
        journal.record_complete(index,actions[index],attempt.ref,response)
        return ref
    result={'mode':mode,'root':str(root),'codeRoot':str(ROOT),'blocked':False,'dockerWrites':0,'productionReady':False,
            'approvalAvailable':False,'witnessSelfRollbackProtected':False,'crashRecoveryValidated':False,
            'subjectPlatform':sys.platform}
    try:
        if mode=='joint-rollback':
            first=operation(0);gate.generation_evidence(gen)
            old=snapshot(root);operation(1)
            journal.close();archive.close();restore(root,old)
            journal=BatchJournal(root/'journal','a'*64,request,actions,key)
            archive=ComposeRecoveryStore(root/'cas',key=key)
            result['restoredJournalLocallyValid']=len(journal.snapshot()['completed'])==1
            result['restoredCasLocallyValid']=archive.get(first)==b'synthetic-0'
            fresh=FileWriterGate(policy,root/'gate',key=key,witness=client())
            before=len(calls)
            try:fresh.generation_evidence(gen)
            except ValueError:result['blocked']=True
            result['freshWitnessCheckReached']=len(calls)>before and calls[-1]['method']=='check'
            result['restoredSequence']=calls[-1]['seq']
        else:
            attempt=session.prepare_attempt(ops[0][0],ops[0][1],bodies[0])
            gate.generation_evidence(gen);fault[0]=True
            def admit():
                return gate.admit(gen,attempt.ref,method=ops[0][0],path=ops[0][1],body=bodies[0],writer_certificate_sha256=cert)
            try:
                if mode=='local-write-fail':
                    original_write=gate._write
                    def fail_event(path,value):
                        if path.name.endswith('.json') and path.name[:8].isdigit():raise OSError('fixture-local-event-write-failure')
                        return original_write(path,value)
                    with patch.object(gate,'_write',side_effect=fail_event):admit()
                else:admit()
                forwarded[0]+=1
            except (ValueError,OSError):result['blocked']=True
            if mode in ('lost-ack','local-write-fail'):
                try:gate.generation_evidence(gen)
                except ValueError:result['retryBlocked']=True
        result['forwardedSyntheticCount']=forwarded[0]
        result['success']=bool(result['blocked'] and forwarded[0]==(2 if mode=='joint-rollback' else 0)
            and (mode!='joint-rollback' or result.get('restoredJournalLocallyValid') and result.get('restoredCasLocallyValid') and result.get('freshWitnessCheckReached'))
            and (mode not in ('lost-ack','local-write-fail') or result.get('retryBlocked')))
        result['rpcCalls']=calls
        result['subjectArchive']={name:base64.b64encode(data).decode() for name,data in snapshot(root).items()}
        if len(json.dumps(result).encode())>LIMIT-1000:raise ValueError('fixture-result-too-large')
        return result
    finally:journal.close();archive.close()

def main():
    if sys.platform!='linux':raise ValueError('linux-fixture-required')
    config=read_frame(sys.stdin.buffer)
    def exchange(method,request):
        print(json.dumps({'kind':'witness-rpc','method':method,'request':request}),flush=True)
        return read_frame(sys.stdin.buffer)
    try:result=run_case(config,exchange)
    except Exception as error:result={'success':False,'failureType':type(error).__name__,'productionReady':False}
    print(json.dumps({'kind':'fixture-result','result':result}),flush=True)

if __name__=='__main__':main()
