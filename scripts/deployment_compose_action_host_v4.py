"""Private root-action preparation, not execution authority or a writer ticket.

Only the first create is compiled. V3 is reused as a payload compiler, while
root policy, plan and observation use separate V4 domains. Actor/session binding
belongs to a subsequently constructed V4 approval policy, avoiding hash cycles.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
import weakref

_CLAIM_LOCK=threading.RLock()
_CLAIMS=weakref.WeakKeyDictionary()
_RECEIPT_CLAIMS={}
_CLAIM_OWNER_PID=os.getpid()

from deployment_compose_prepare_v3_host import ComposePreparationHostV3
from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
from deployment_compose_bundle_v3 import _operation

POLICY_DOMAIN = b'dev-workflow:compose-root-action-policy:v4\0'
PLAN_DOMAIN = b'dev-workflow:compose-root-action-plan:v4\0'
CONTEXT_DOMAIN = b'dev-workflow:compose-root-action-context:v4\0'
ACTION_DOMAIN = b'dev-workflow:compose-root-action:v4\0'
LIMITS = dict(maxBodyBytes=65536, maxResponseBytes=65536, engineSeconds=30,
              stepSeconds=180, maximumWrites=1)


def reject():
    raise ValueError('root-action-preparation-v4-rejected')


def encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')


def digest(domain, value):
    return hashlib.sha256(domain+encode(value)).hexdigest()


class PreparedRootActionV4:
    """Only its issuing live preparation host can resolve this object."""
    pass


class RootActionPreparationV4:
    def __init__(self, *, preparer, socket_path):
        if (type(preparer) is not ComposePreparationHostV3
                or type(preparer._phase_state) is not TrustedPhaseStateProducerV3
                or not isinstance(socket_path,Path) or not socket_path.is_absolute()
                or preparer._phase_state._socket_path != str(socket_path)
                or preparer._phase_state.project != preparer._target.namespace
                or preparer._phase_state.daemon_id != preparer._daemon):
            reject()
        self._preparer, self._producer, self._socket = preparer, preparer._phase_state, socket_path
        self._records = {}
        self._socket_identity = self._socket_facts()

    def _socket_facts(self):
        path=self._socket
        root=path.parent
        # Ownership and path identity are checked here. The embedding independently
        # registers the daemon purpose; a private path does not prove test-only
        # status. Standard production paths and socket substitutions are rejected.
        if root.resolve() != root or path == Path('/var/run/docker.sock'):
            reject()
        directory=root.stat(); sock=path.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or stat.S_IMODE(directory.st_mode)!=0o700
                or directory.st_uid!=os.getuid() or not stat.S_ISSOCK(sock.st_mode)
                or sock.st_uid!=os.getuid()):
            reject()
        return (directory.st_dev,directory.st_ino,sock.st_dev,sock.st_ino)

    def _recheck_host(self):
        p=self._preparer
        methods=((p, 'prepare_intent', ComposePreparationHostV3.prepare_intent),
                 (p, 'verify_intent', ComposePreparationHostV3.verify_intent),
                 (self._producer, 'capture', TrustedPhaseStateProducerV3.capture),
                 (self._producer, '_get', TrustedPhaseStateProducerV3._get))
        if any(getattr(getattr(owner,name),'__self__',None) is not owner
               or getattr(getattr(owner,name),'__func__',None) is not function
               for owner,name,function in methods):
            reject()
        if (p._phase_state is not self._producer or type(p._phase_state) is not TrustedPhaseStateProducerV3
                or self._producer._socket_path!=str(self._socket)
                or self._producer.project!=p._target.namespace or self._producer.daemon_id!=p._daemon
                or self._socket_facts()!=self._socket_identity):
            reject()

    def prepare(self, whole_observation, retention_observation, *, operation_nonce, expires_at):
        self._recheck_host()
        p=self._preparer
        initial=p.prepare_intent(whole_observation,retention_observation,
                                operation_nonce=operation_nonce,expires_at=expires_at)
        p.verify_intent(initial,whole_observation,retention_observation,
                        operation_nonce=operation_nonce,expires_at=expires_at)
        self._recheck_host()
        value=initial['bundle'].to_dict(); original=initial['request']
        if original.operation!='deploy' or original.profile_version!='3' or original.production is not False:
            reject()
        first=value['operations'][0]
        if first['phase']!='create': reject()
        service=next(s for s in value['services'] if s['name']==first['service'])
        operation=_operation(value,first,service,None)
        if (operation['method']!='POST' or not operation['path'].startswith('/v1.45/containers/create?name=dwc-')
                or len(encode(operation['body']))>LIMITS['maxBodyBytes']):
            reject()
        action=dict(payloadFormat='compose-bundle-v3',bundleDigest=initial['bundle'].digest,
                    scopeOrdinal=0,planWriteIndex=0,operation=operation,limits=deepcopy(LIMITS))
        action_hash=digest(ACTION_DOMAIN,action)
        policy=dict(kind='compose-single-create-policy-v4',compilationPolicyHash=original.policy_hash,
                    payloadFormat='compose-bundle-v3',actionDigest=action_hash,limits=deepcopy(LIMITS))
        plan=dict(kind='compose-single-create-plan-v4',payloadFormat='compose-bundle-v3',
                  bundleDigest=initial['bundle'].digest,action=action,policyDigest=digest(POLICY_DOMAIN,policy))
        context=dict(kind='compose-single-create-root-context-v4',sourceObservationHash=original.observation_hash,
                     baselineStateReference=value['baselineStateReference'],baselineStateDigest=value['baselineStateDigest'],
                     planDigest=digest(PLAN_DOMAIN,plan),actionDigest=action_hash)
        request=replace(original,profile_version='4',policy_hash=plan['policyDigest'],
                        plan_hash=context['planDigest'],observation_hash=digest(CONTEXT_DOMAIN,context))
        request.ensure_fresh(datetime.now(timezone.utc))
        token=PreparedRootActionV4()
        self._records[token]=dict(request=request,request_bytes=request.canonical_json(),bundle=initial['bundle'],action=action,context=context,
                                  source_prepared=initial,whole=whole_observation,retention=retention_observation,
                                  nonce=operation_nonce,expires=expires_at)
        return token

    def resolve(self, prepared):
        if type(prepared) is not PreparedRootActionV4 or prepared not in self._records:
            reject()
        self._recheck_host()
        record=self._records[prepared]
        if record['request'].canonical_json()!=record['request_bytes']:
            reject()
        self._preparer.verify_intent(record['source_prepared'],record['whole'],record['retention'],
                                    operation_nonce=record['nonce'],expires_at=record['expires'])
        self._recheck_host()
        record['request'].ensure_fresh(datetime.now(timezone.utc))
        return dict(request=record['request'],bundle=record['bundle'],action=deepcopy(record['action']),
                    context=deepcopy(record['context']),authorityGranted=False,executionAvailable=False,
                    productionReady=False)


class CompositeActionAuthorizationV4:pass
class CompleteActionResponseV4:pass
class CompositeGoV4:pass


class SingleActionHostV4:
    """One consumed, freshly checked first create; no successor or CLI."""
    def __init__(self,*,preparation,prepared,supervisor,witness,phase_guard,session_hash):
        from deployment_compose_action_actor_v4 import ActionActorSupervisorV4,socket_facts
        from deployment_compose_action_witness_v4 import ActionWitnessStoreV4
        from deployment_compose_phase_guard_v3_host import PhaseGuardV3
        import base64,secrets
        if (type(preparation) is not RootActionPreparationV4 or type(supervisor) is not ActionActorSupervisorV4
                or type(witness) is not ActionWitnessStoreV4 or type(phase_guard) is not PhaseGuardV3
                or type(session_hash) is not str or len(session_hash)!=64 or any(c not in '0123456789abcdef' for c in session_hash)):reject()
        self._preparation,self._prepared,self._supervisor,self._witness=preparation,prepared,supervisor,witness
        self._root=preparation.resolve(prepared);self._guard=phase_guard;self._producer=preparation._producer
        self._session=session_hash;self._used=False;self._authorizations={};self._responses={};self._go_tokens={}
        self._check_guard()
        action=self._root['action'];request=self._root['request'];raw=encode(action['operation']['body'])
        self._action_hash=digest(ACTION_DOMAIN,action)
        self._config=dict(schemaVersion=4,kind='single-create-leaf-v4',socket=str(preparation._socket),
            socketIdentity=socket_facts(str(preparation._socket)),path=action['operation']['path'],
            bodyBase64=base64.b64encode(raw).decode('ascii'),bodyDigest=hashlib.sha256(raw).hexdigest(),
            requestHash=request.digest(),contextDigest=request.observation_hash,actionDigest=self._action_hash,
            sessionHash=session_hash,actorEpoch=secrets.token_hex(32))
        self.actor=supervisor._start(self._config)
        self._binding={k:self._config[k] for k in ('requestHash','contextDigest','actionDigest','sessionHash','actorEpoch')}
        self._binding['supervisorBoot']=supervisor.boot
        try:self._cursor=witness.register_once(self._binding)
        except BaseException:supervisor.stop_and_join(self.actor);raise

    def _check_guard(self):
        p=self._producer;g=self._guard
        if (getattr(g._read,'__self__',None) is not p or getattr(g._read,'__func__',None) is not TrustedPhaseStateProducerV3._get
                or g._bundle.canonical_bytes!=self._root['bundle'].canonical_bytes
                or p.project!=self._root['request'].target.namespace or p.daemon_id!=self._root['request'].daemon_id
                or p._socket_path!=str(self._preparation._socket)):reject()
        self._preparation._recheck_host()

    def approval_bindings(self):
        request=self._root['request']
        return dict(session_hash=self._session,context_digest=request.observation_hash,policy_hash=request.policy_hash,
            actor_epoch=self._config['actorEpoch'],scope_ordinal=0,plan_write_index=0,action_digest=self._action_hash)

    def _phase(self,deadline):
        from deployment_compose_phase_guard_v3_host import _plain
        self._check_guard()
        with self._producer.operation_scope(deadline):
            return _plain(self._guard.capture_phase(dict(phase_index=0,operation=self._root['action']['operation'],
                                                         receipts={},completed_operations=[])))

    def _authorization_for_witness(self,authorization,witness,binding):
        import time
        record=self._authorizations.get(authorization)
        if (type(authorization) is not CompositeActionAuthorizationV4 or record is None or self._witness is not witness
                or encode(binding)!=encode(self._binding) or time.monotonic()>=record['deadline']):reject()
        return deepcopy(record['facts'])

    def _response_for_witness(self,evidence,witness,binding,cursor):
        if type(evidence) is not CompleteActionResponseV4 or evidence not in self._responses:
            reject()
        record=self._responses[evidence]
        if (self._witness is not witness or encode(binding)!=encode(self._binding)
                or encode(cursor)!=encode(record['cursor'])):reject()
        self._supervisor.termination_digest(self.actor,record['termination'],self._session)
        return deepcopy(record['data'])

    def _go_for_supervisor(self,evidence,supervisor,actor):
        import time
        if (type(evidence) is not CompositeGoV4 or evidence not in self._go_tokens
                or supervisor is not self._supervisor or actor is not self.actor):reject()
        go=self._go_tokens.pop(evidence)
        self._root['request'].ensure_fresh(datetime.now(timezone.utc))
        if time.monotonic()>=go['deadline']:reject()
        return deepcopy(go)

    def dispatch(self,*,authority,receipt,status_client):
        from deployment_compose_approval_v4_host import GitHubFullBodyApprovalV4
        from deployment_compose_intent_status_v4 import IntentStatusClientV4
        import base64,secrets,time
        if self._used or os.getpid()!=_CLAIM_OWNER_PID:reject()
        self._used=True
        request=self._root['request']
        utc_expiry=datetime.strptime(request.expires_at,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
        deadline=min(time.monotonic()+180,time.monotonic()+utc_expiry-time.time())
        try:
            if type(authority) is not GitHubFullBodyApprovalV4 or type(status_client) is not IntentStatusClientV4:reject()
            receipt_hash=authority.receipt_hash(receipt,request)
            # Burn this actual receipt before any admission or go, across all
            # host instances/witness directories in this authority lifetime.
            with _CLAIM_LOCK:
                claims=_CLAIMS.setdefault(authority,{})
                key=(id(receipt),request.digest(),self._action_hash)
                if key in claims or id(receipt) in _RECEIPT_CLAIMS or len(_RECEIPT_CLAIMS)>=4096:reject()
                claims[key]=receipt
                _RECEIPT_CLAIMS[id(receipt)]=receipt
            bindings=self.approval_bindings()
            if (encode({k:getattr(authority.policy,k) for k in bindings})!=encode(bindings)
                    or status_client._expected.canonical_json()!=request.canonical_json()
                    or status_client._receipt!=receipt_hash):reject()
            expected_status=dict(sessionHash=self._session,requestHash=request.digest(),contextDigest=request.observation_hash,
                policyHash=request.policy_hash,actorEpoch=self._config['actorEpoch'],scopeOrdinal=0,
                planWriteIndex=0,actionDigest=self._action_hash)
            if encode(status_client._bindings)!=encode(expected_status):reject()
            fresh=self._preparation.resolve(self._prepared)
            if fresh['request'].canonical_json()!=request.canonical_json() or encode(fresh['action'])!=encode(self._root['action']):reject()
            authority.check_consumed_intent(request);status_client.check_consumed_intent(request)
            phase=self._phase(deadline)
            facts=dict(receiptHash=receipt_hash,phaseDigest=digest(b'dev-workflow:action-phase:v4\0',phase),
                       actionDigest=self._action_hash,actorEpoch=self._config['actorEpoch'])
            token=CompositeActionAuthorizationV4()
            self._authorizations[token]=dict(facts=facts,deadline=deadline)
            admitted=self._witness.admit(self._cursor,host=self,authorization=token)
            # Admission is now durable. Any subsequent failure remains unknown;
            # no retry, even if the actor never received go.
            authority.check_consumed_intent(request);status=status_client.check_consumed_intent(request)
            deadline=min(deadline,time.monotonic()+min(utc_expiry,authority._expires,status['expiresAt'])-time.time())
            if encode(self._phase(deadline))!=encode(phase) or time.monotonic()>=deadline:reject()
            nonce=secrets.token_hex(32)
            go={k:self._config[k] for k in ('requestHash','contextDigest','actionDigest','sessionHash','actorEpoch')}
            go.update(kind='go-v4',nonce=nonce,deadline=deadline,cursor=admitted,scopeOrdinal=0,planWriteIndex=0)
            request.ensure_fresh(datetime.now(timezone.utc))
            go_evidence=CompositeGoV4();self._go_tokens[go_evidence]=go
            self._supervisor.send_go(self.actor,host=self,go_evidence=go_evidence)
            response=self._supervisor.receive_response(self.actor,deadline)
            if (type(response) is not dict or set(response)!={'kind','nonce','status','bodyBase64'}
                    or response['kind']!='response-v4' or response['nonce']!=nonce):reject()
            body=base64.b64decode(response['bodyBase64'],validate=True)
            termination=self._supervisor.stop_and_join(self.actor)
            evidence=CompleteActionResponseV4()
            self._responses[evidence]=dict(termination=termination,cursor=deepcopy(admitted),
                data=dict(status=response['status'],bodyBase64=base64.b64encode(body).decode('ascii')))
            self._witness.record_response(admitted,host=self,response_evidence=evidence)
            # A complete response is definitive, but 201 alone is not a valid CID.
            success=False;cid=None
            if response['status']==201:
                from deployment_compose_witness_store import pairs
                try:value=json.loads(body,object_pairs_hook=pairs,parse_constant=lambda _:reject())
                except ValueError:value=None
                cid=value.get('Id') if type(value) is dict else None
                forbidden={row['baselineContainerId'] for row in self._root['bundle'].to_dict()['services']}
                forbidden.update(row['containerId'] for row in self._root['bundle'].to_dict()['protectedContainers'])
                success=(type(cid) is str and len(cid)==64 and all(c in '0123456789abcdef' for c in cid) and cid not in forbidden)
            return dict(success=success,status=response['status'],candidateId=cid if success else None,
                        definitive=True,productionReady=False)
        finally:
            self._authorizations.clear();self._responses.clear();self._go_tokens.clear()
            self._supervisor.stop_and_join(self.actor)
