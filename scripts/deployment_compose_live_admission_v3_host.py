"""Private Mac admission for owned SSH frames; no server or registration RPC.

The embedding authenticates an owned SSH process before authorize_rpc. Registration
is controller-only, after exact private/public preparation checks and real consent
consumption. In particular the consumption object must come directly from consume,
never from Linux or deserialization; its timestamp has no separate crypto proof.
No return value replaces Linux phase guards, startup fencing or Engine receipts.
"""
import base64
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading

from deployment_compose_approval_v3_host import GitHubFullBodyApprovalV3, FullBodyConsumptionEvidenceV3
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_history_v3_host import AuthenticatedHistoryV3, AuthenticatedHistorySnapshotV3, pairs
from deployment_compose_intent_status_v3 import issue_intent_status, NAMESPACE as INTENT_NAMESPACE
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_operation_witness_client_v3 import (OperationWitnessClientV3, dispatch_request,
    validate_request, decode_material, encode, NAMESPACE)
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_witness_budget_v3_host import check_witness_byte_capacity
from deployment_compose_witness_store import canonical, hex_value, ZERO
from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material
from deployment_gateway import FileWriterGate, GatePolicy

ROOT=Path(__file__).resolve().parents[1]
SSH_KEYGEN='/usr/bin/ssh-keygen'


class LiveAdmissionRejected(ValueError):
    """Private fixed-stage diagnostics; never includes provider payloads."""
    def __init__(self, stage, cause_type):
        super().__init__('compose-live-admission-v3-rejected')
        self.stage = stage
        self.cause_type = cause_type


def reject():
    raise ValueError('compose-live-admission-v3-rejected') from None


def _digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class MacLiveAdmissionV3:
    def __init__(self, *, store, gate_policy, gate_key, witness_signer, witness_public_key,
                 intent_signer, intent_public_key):
        try:
            if (type(store) is not OperationWitnessStoreV3 or type(gate_policy) is not GatePolicy
                    or gate_policy.operation_profile!='compose-v3' or gate_policy.witness_required is not True
                    or type(gate_key) is not bytes or not 32<=len(gate_key)<=4096):reject()
            private=store.root.parent.resolve(strict=True)
            if (private.is_relative_to(ROOT) or private.stat().st_uid!=os.getuid()
                    or private.stat().st_mode&0o777!=0o700):reject()
            self._store,self._policy,self._key=store,gate_policy,gate_key
            self._signers=[];self._public=[]
            for path,public in ((witness_signer,witness_public_key),(intent_signer,intent_public_key)):
                if not isinstance(path,Path) or path.is_symlink():reject()
                path=path.resolve(strict=True)
                if (path.parent!=private or not path.is_file() or path.stat().st_uid!=os.getuid()
                        or path.stat().st_mode&0o777!=0o600):reject()
                actual=subprocess.run([SSH_KEYGEN,'-y','-f',str(path)],capture_output=True,check=True,
                    timeout=10,env={'PATH':'/usr/bin:/bin'}).stdout
                public=key_material(public)
                if key_material(actual)!=public:reject()
                self._signers.append(path);self._public.append(public)
            if (self._signers[0]==self._signers[1] or self._public[0]==self._public[1]
                    or hashlib.sha256(self._public[0]).hexdigest()!=gate_policy.witness_key_sha256):reject()
            self._lock=threading.RLock();self._seen=set();self._bindings={}
            self._current=None;self._pending=None;self._root=None;self._epoch=secrets.token_hex(32)
        except Exception:reject()

    def _sign(self,payload,*,intent=False):
        result=subprocess.run([SSH_KEYGEN,'-Y','sign','-f',str(self._signers[int(intent)]),'-n',
            INTENT_NAMESPACE if intent else NAMESPACE],input=encode(payload),capture_output=True,
            check=True,timeout=10,env={'PATH':'/usr/bin:/bin'})
        return dict(payload=payload,signature=base64.b64encode(result.stdout).decode('ascii'))

    def _client(self,binding):
        def transport(method,request):
            if method not in ('read','chain_status','events_after','check'):reject()
            return self._sign(dispatch_request(self._store,method,request))
        return OperationWitnessClientV3(binding,self._public[0],transport)

    def _history(self,entry):
        return AuthenticatedHistoryV3(entry['bundle'],entry['request'],gate_policy=self._policy,
            gate_key=self._key,consumption_receipt_hash=entry['receiptHash'],
            witness_client=self._client(entry['first']),witness_client_factory=self._client,
            parent_history=entry['parentHistory'],reviewed_parent_snapshot=entry['parentSnapshot'])

    def _binding(self,desc):
        return dict(epoch=self._epoch,policyHash=self._policy.identity_hash(),
                    generation=desc['generation'],scopeHash=desc['scopeHash'])

    @staticmethod
    def _consent(entry):
        entry['approval'].check_consumed_intent(entry['request'])

    def _scope(self,entry,index,receipts):
        bundle=entry['bundle']
        ops=(bundle.resolve_operations(receipts) if len(receipts)==len(bundle.to_dict()['services'])
             else bundle.creation_operations())
        writes=[op for op in ops if op['method']!='GET']
        if not 0<=index<len(writes):reject()
        op=writes[index]
        desc=Profile3StepExecutor.scope_descriptor(bundle,entry['request'],entry['receiptHash'],op,index,receipts)
        return dict(entry=entry,index=index,receipts=deepcopy(receipts),operation=op,
                    descriptor=desc,binding=self._binding(desc))

    def _inverse(self,entry,parent,snapshot):
        old,new=parent['bundle'].to_dict(),entry['bundle'].to_dict()
        previous=json.loads(snapshot.canonical)
        old_request,new_request=parent['request'],entry['request']
        if (any(getattr(old_request,k)!=getattr(new_request,k) for k in
                ('source','target','environment','production','host_id','daemon_id','components',
                 'protected_components','policy_hash'))
                or any(old['identity'][k]!=new['identity'][k] for k in ('hostId','daemonId','project','sourceIdentity'))
                or any(canonical(old[k])!=canonical(new[k]) for k in ('protectedContainers','networks','mounts'))
                or len(old['services'])!=len(new['services'])):reject()
        for before,after in zip(old['services'],new['services']):
            if (any(before[k]!=after[k] for k in ('name','finalName','dependsOn'))
                    or after['baselineContainerId']!=previous['receiptMap'][before['name']]
                    or after['baselineImageId']!=before['targetImageId']
                    or after['targetImageId']!=before['baselineImageId']
                    or canonical(after['baselineCreateBody'])!=canonical(before['targetCreateBody'])
                    or canonical(after['targetCreateBody'])!=canonical(before['baselineCreateBody'])):reject()

    def register_intent(self,bundle,request,approval,consumption,reviewed_parent=None):
        """Controller-only registration after trusted preparation and real consume."""
        with self._lock:
            stage = 'identity'
            try:
                if (type(bundle) is not ExecutionBundleV3 or type(request) is not RequestV2
                        or type(approval) is not GitHubFullBodyApprovalV3
                        or type(consumption) is not FullBodyConsumptionEvidenceV3
                        or request.operation not in ('deploy','rollback')
                        or request not in approval.requests or consumption.request_hash!=request.digest()
                        or consumption.use_number!=1 or type(consumption.use_number) is not int
                        or consumption.grant_id!=approval.grant_namespace+':'+str(approval.policy.run_id)+':'+request.operation
                        or request.plan_hash!=bundle.digest
                        or request.policy_hash!=self._policy.identity_hash()
                        or len(request.protected_components)!=len(bundle.to_dict()['protectedContainers'])
                        or request.after_hash!=_digest({s['name']:s['targetCreateBody'] for s in bundle.to_dict()['services']})):
                    reject()
                stage = 'consumption-time'
                when=datetime.fromisoformat(consumption.consumed_at)
                if when.tzinfo is None or when>datetime.now(timezone.utc):reject()
                entry=dict(bundle=bundle,request=request,approval=approval,consumption=consumption,
                    receiptHash=_digest(asdict(consumption)),parentHistory=None,parentSnapshot=None)
                stage = 'consent'
                self._consent(entry)
                stage = 'scope'
                scope=self._scope(entry,0,{})
                entry['first']=scope['binding']
                # Constructor validates full RequestV2/bundle identity, even before a read.
                stage = 'history'
                self._history(entry)
                if request.operation=='deploy':
                    if self._root is not None or self._current is not None or reviewed_parent is not None:reject()
                    stage = 'capacity'
                    check_witness_byte_capacity(bundle,request,self._policy,entry['receiptHash'],entry['first'])
                    stage = 'consent'
                    self._consent(entry)
                    stage = 'register'
                    self._store.register_once(entry['first'])
                    self._root=self._current=entry
                    self._bindings[canonical(entry['first'])]=scope
                else:
                    stage = 'parent-history'
                    if (self._root is None or self._current is not self._root or self._pending is not None
                            or type(reviewed_parent) is not AuthenticatedHistorySnapshotV3):reject()
                    history=self._history(self._root);fresh=history.capture()
                    value=json.loads(fresh.canonical)
                    total=sum(op['phase']!='readiness' for op in self._root['bundle'].to_dict()['operations'])
                    if (fresh.canonical!=reviewed_parent.canonical or fresh.digest!=request.history_hash
                            or value['schemaVersion']!=1 or value['blocker'] is not None or value['pending'] is not None
                            or len(value['knownPrefix'])!=total or len(value['scopes'])!=total
                            or value['chainStatus']['activePhase']!='closed'):reject()
                    stage = 'inverse'
                    self._inverse(entry,self._root,fresh)
                    entry['parentHistory'],entry['parentSnapshot']=history,fresh
                    stage = 'history'
                    self._history(entry)
                    stage = 'capacity'
                    check_witness_byte_capacity(bundle,request,self._policy,entry['receiptHash'],entry['first'],fresh)
                    stage = 'consent'
                    self._consent(entry)
                    self._pending=scope
                return deepcopy(scope['binding'])
            except Exception as error:
                name = type(error).__name__
                category = name if name in ('GitHubUnavailable','AuthorizationUnavailable','ValueError','GateError','OSError') else 'Other'
                raise LiveAdmissionRejected(stage, category) from None

    def _unseal(self,envelope,domain):
        if (type(envelope) is not dict or set(envelope)!={'version','domain','policy','payload','mac'}
                or type(envelope['version']) is not int or envelope['version']!=1
                or envelope['domain']!='dev-workflow.writer-gate.'+domain
                or canonical(envelope['policy'])!=canonical(self._policy._binding()) or not hex_value(envelope['mac'])):reject()
        unsigned={k:v for k,v in envelope.items() if k!='mac'}
        expected=hmac.new(self._key,canonical(unsigned),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected,envelope['mac']):reject()
        return envelope['payload']

    def _validate_event(self,scope,raw,ordinal,previous,directory,attempt,finish):
        envelope=json.loads(raw,object_pairs_hook=pairs)
        if canonical(envelope)!=raw:reject()
        event=self._unseal(envelope,'event');desc=scope['descriptor'];entry=scope['entry']
        kinds=('open','prepare','admit','finish','close','proof')
        if (type(event) is not dict or set(event)!={'generation','directory','previous','kind','data'}
                or ordinal>=6 or event['kind']!=kinds[ordinal]
                or event['generation']!=scope['binding']['generation'] or event['previous']!=previous):reject()
        actual=event['directory']
        if (type(actual) is not list or len(actual)!=2
                or any(type(n) is not int or not 0<=n<=2**64-1 for n in actual)
                or directory is not None and actual!=directory):reject()
        data=event['data']
        if ordinal==0:
            expected=dict(request_hash=entry['request'].digest(),receipt_hash=entry['receiptHash'],
                operations=[list(op) for op in desc['operations']],source_binding_schema=1,source_context_digest=desc['source'])
            if canonical(data)!=canonical(expected):reject()
        elif ordinal==1:
            if (type(data) is not dict or set(data)!={'ref','operation'} or not hex_value(data['ref'])
                    or data['operation']!=list(desc['operations'][0])):reject()
            attempt=data['ref']
        elif ordinal==2:
            if data!=attempt:reject()
        elif ordinal==3:
            FileWriterGate._response_data(data)
            if data['ref']!=attempt or len(base64.b64decode(data['bodyBase64'],validate=True))>4096:reject()
            finish=data
        elif ordinal==4:
            if data is not None or finish is None or finish['definitive'] is not True:reject()
        else:
            if self._unseal(data,'proof')!=dict(generation=scope['binding']['generation'],head=previous):reject()
        return event,actual,attempt,finish

    def _append(self,request,scope):
        records=self._store.events_after(scope['binding'],seq=0,head=ZERO)
        view=self._store.read(scope['binding'])
        if (view['active'] is not True or request['expectedSeq']!=len(records)
                or request['expectedHead']!=view['head']):reject()
        previous=ZERO;directory=attempt=finish=None
        for index,record in enumerate(records):
            raw=decode_material(record['externalMaterialBase64'])
            event,directory,attempt,finish=self._validate_event(scope,raw,index,previous,directory,attempt,finish)
            if record['event']['data']!=GateOperationWitnessAdapterV3._data(event,attempt):reject()
            previous=_digest(event)
        raw=decode_material(request['externalMaterialBase64'])
        event,directory,attempt,finish=self._validate_event(scope,raw,len(records),previous,directory,attempt,finish)
        if request['event']['data']!=GateOperationWitnessAdapterV3._data(event,attempt):reject()
        if len(records)<3:self._consent(scope['entry'])
        # dispatch_request/store validate witness sequence, binding, material hash,
        # nonce, event grammar and CAS cursor before the single persisted mutation.
        return dispatch_request(self._store,'append_event',request)

    def _transition(self,request,scope):
        if scope['entry'] is not self._current:reject()
        history=self._history(self._current);snapshot=history.capture();value=json.loads(snapshot.canonical)
        if (value['blocker'] is not None or value['pending'] is not None
                or value['chainStatus']['activePhase']!='closed'
                or value['closedTail']!=dict(binding=request['binding'],seq=request['expectedSeq'],head=request['expectedHead'])):
            reject()
        if self._pending is not None:
            child=self._pending
            if snapshot.canonical!=child['entry']['parentSnapshot'].canonical:reject()
        else:
            child=self._scope(self._current,len(value['knownPrefix']),value['receiptMap'])
        if request['childBinding']!=child['binding']:reject()
        self._consent(child['entry'])
        response=dispatch_request(self._store,'transition_successor',request)
        self._bindings[canonical(child['binding'])]=child
        if self._pending is not None:
            self._current=child['entry'];self._pending=None
        return response

    def authorize_rpc(self,service,method,request):
        """Private embedding entry: only authenticated owned SSH frames may call."""
        with self._lock:
            try:
                if type(request) is not dict or not hex_value(request.get('rpcNonce')):reject()
                nonce=request['rpcNonce']
                if nonce in self._seen:reject()
                self._seen.add(nonce)  # An unknown response never permits a retry.
                if service=='intent' and method=='check':
                    candidates=([self._pending['entry']] if self._pending is not None else [])
                    if self._current is not None:candidates.append(self._current)
                    entry=next((e for e in candidates if request.get('requestHash')==e['request'].digest()),None)
                    if entry is None:reject()
                    return self._sign(issue_intent_status(entry['approval'],entry['request'],request),intent=True)
                if service!='witness' or method not in ('read','chain_status','check','events_after','append_event','transition_successor'):
                    reject()
                validate_request(method,request)
                scope=self._bindings.get(canonical(request['binding']))
                if scope is None:reject()
                if method=='append_event':payload=self._append(request,scope)
                elif method=='transition_successor':payload=self._transition(request,scope)
                else:payload=dispatch_request(self._store,method,request)
                return self._sign(payload)
            except Exception:reject()
