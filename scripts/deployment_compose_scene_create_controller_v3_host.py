"""Mac first-create controller: real consent and witness signing remain on Mac.

The trusted embedding supplies authenticated scene/preparation pins and integrity
keys. Control credentials alone cannot consume an intent or sign business status.
"""
import base64
from dataclasses import asdict
from datetime import datetime,timezone
import hashlib
import math
import os
import threading
import time
import weakref

from deployment_compose_scene_service_v3_host import SceneClientV3
from deployment_compose_scene_control_ssh_v3_host import SceneSSHClientV3
from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
from deployment_compose_live_ssh_v3_host import verify_private_capsule
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical
from deployment_compose_scene_create_certificate_v3_host import issue_create_closure

_ISSUED=weakref.WeakKeyDictionary()


def _fingerprint(controller):
    return (id(controller._admission),id(controller._handle),controller._client_type,
        controller._raw,canonical(controller._hello),tuple(sorted(controller._keys.items())),
        controller._boot,controller._bind,controller._seal,controller._prep,controller._digest,
        controller._request.digest(),controller._bundle.canonical_bytes)


MAX_MESSAGE=4*1024*1024
_METHODS={'intent':{'check'},'witness':{'read','check','events_after','chain_status','append_event'}}


def reject():raise ValueError('compose-scene-create-controller-v3-rejected') from None


def digest(raw):return hashlib.sha256(raw).hexdigest()


class SceneCreateControllerV3:
    def __copy__(self):reject()
    def __deepcopy__(self,memo):reject()
    def __reduce_ex__(self,protocol):reject()

    def __init__(self,*,client,admission,capsule_bytes,hello,integrity_keys,preparation_id,capsule_digest,
                 trusted_boot_id,trusted_bind_digest=None):
        try:
            if type(client) not in (SceneClientV3,SceneSSHClientV3) or type(admission) is not MacLiveAdmissionV3:reject()
            if admission._owner_pid!=os.getpid() or admission._issuer is not admission:reject()
            if type(capsule_bytes) is not bytes or not 0<len(capsule_bytes)<=MAX_MESSAGE or digest(capsule_bytes)!=capsule_digest:reject()
            self._client=client;self._client_type=type(client);self._handle=client._handle;self._admission=admission
            self._owner=(os.getpid(),threading.get_ident());self._attempted=False
            self._hello=decode(canonical(hello));self._keys=dict(integrity_keys)
            self._raw=capsule_bytes;self._prep=preparation_id;self._digest=capsule_digest
            self._boot=trusted_boot_id;self._bind=trusted_bind_digest
            self._bundle,self._request=SceneCreateControllerV3._verify(self)
            self._seal=(admission._policy,admission._key,tuple(admission._public),tuple(admission._signers),admission._store)
            _ISSUED[self]=(self._owner,_fingerprint(self))
        except Exception:reject()

    def _owned(self):
        record=_ISSUED.get(self)
        if (record is None or record!=(self._owner,_fingerprint(self))
                or any(name in self.__dict__ for name in ('_owned','_status','_verify','run_first_create','_save_restart_checkpoint'))):reject()
        a=self._admission
        if (self._owner!=(os.getpid(),threading.get_ident()) or type(self._client) is not self._client_type
                or self._client_type not in (SceneClientV3,SceneSSHClientV3) or self._client._handle is not self._handle
                or a._owner_pid!=os.getpid() or a._issuer is not a
                or (a._policy,a._key,tuple(a._public),tuple(a._signers),a._store)!=self._seal):reject()

    def _verify(self):
        return verify_private_capsule(decode(self._raw),hello=self._hello,source_sha=self._hello['sourceSha'],
            ssh_alias=self._hello['hostId'],policy=self._admission._policy,keys=self._keys,
            trusted_boot_id=self._boot,trusted_bind_digest=self._bind)

    def _status(self):
        status=self._client.status();business=status['business']
        if (status['sceneId']!=self._handle.sceneId or status['preparation']['preparationId']!=self._prep
                or status['preparation']['capsuleDigest']!=self._digest
                or business.get('witnessKeyHash')!=digest(self._admission._public[0])
                or business.get('intentKeyHash')!=digest(self._admission._public[1])):reject()
        return status

    def run_first_create(self,*,review=None,on_review=None,approval=None,consumption=None,timeout=900,on_restart_checkpoint=None,on_scene_checkpoint=None):
        try:
            self._owned()
            if self._attempted or type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=900:reject()
            if on_restart_checkpoint is not None and on_scene_checkpoint is not None:reject()
            notify=on_scene_checkpoint if on_scene_checkpoint is not None else on_restart_checkpoint
            if notify is not None:
                if not callable(notify):reject()
                case=self._admission._store.root.parent
                if (self._admission._store.root!=case/'witness'
                        or self._admission._signers[0]!=case/'witness-signing'
                        or any((case/name).exists() or (case/name).is_symlink()
                               for name in ('restart-material','restart-custody','scene-checkpoint'))):reject()
            if on_scene_checkpoint is not None:
                from deployment_compose_scene_checkpoint_v3_host import validate_scene_checkpoint_source
                validate_scene_checkpoint_source(self)
            self._attempted=True;end=time.monotonic()+timeout
            def left():
                if time.monotonic()>=end:reject()
            status=self._status();bundle,request=self._verify()
            if bundle.canonical_bytes!=self._bundle.canonical_bytes or request!=self._request:reject()
            request.ensure_fresh(datetime.now(timezone.utc))
            if review is not None:
                from deployment_compose_live_review_v3_host import GitHubLiveReviewV3
                if type(review) is not GitHubLiveReviewV3 or approval is not None or consumption is not None or not callable(on_review):reject()
                self._client.detach()
                approval,consumption,_=review.consume_prepared(bundle,request,on_review)
            else:self._client.detach()
            left()
            # Original registration checks exact approval/consumption classes,
            # live consent, protected/full-body scope and the independent ledger.
            binding=self._admission.register_intent(bundle,request,approval,consumption)
            # Network-backed registration runs with no idle controller lease.
            # Authenticate only when ready to launch; this never retries create.
            self._client=self._client_type(self._handle)
            status=self._status();left()
            result=self._client.start_first_create(preparationId=self._prep,capsuleDigest=self._digest,
                slotGeneration=status['slotGeneration'],policy=asdict(self._admission._policy),
                gateKeyBase64=base64.b64encode(self._admission._key).decode('ascii'),requestHash=request.digest(),
                receiptHash=digest(canonical(asdict(consumption))),firstBinding=binding)['business']
            attempt=result['attemptId'];nonce=result['pendingNonce'];last_rpc=0
            heartbeat_due=[time.monotonic()+10]
            def heartbeat(force=False):
                if force or time.monotonic()>=heartbeat_due[0]:
                    self._status();heartbeat_due[0]=time.monotonic()+10
            while True:
                self._owned();left();heartbeat();request.ensure_fresh(datetime.now(timezone.utc))
                state=self._client.poll_worker()['business']
                if state['attemptId']!=attempt or state['pendingNonce']!=nonce:reject()
                if state['businessState'] in ('failed','frozen'):reject()
                message=state.get('message')
                if message is not None:
                    if (message['attemptId']!=attempt or type(message['totalBytes']) is not int
                            or not 0<message['totalBytes']<=MAX_MESSAGE or type(message['rpcId']) is not int
                            or message['rpcId']<=last_rpc or message['service'] not in _METHODS
                            or message['method'] not in _METHODS[message['service']]):reject()
                    raw=bytearray()
                    while len(raw)<message['totalBytes']:
                        left();heartbeat();chunk=self._client.read_worker_chunk(attempt,message['messageDigest'],len(raw),4096)['business']
                        if (chunk['attemptId']!=attempt or chunk['messageDigest']!=message['messageDigest']
                                or chunk['totalBytes']!=message['totalBytes'] or chunk['offset']!=len(raw)):reject()
                        data=base64.b64decode(chunk['dataBase64'],validate=True)
                        if not 0<len(data)<=4096 or len(raw)+len(data)>message['totalBytes']:reject()
                        raw.extend(data)
                    if digest(raw)!=message['messageDigest']:reject()
                    frame=decode(bytes(raw))
                    if (type(frame) is not dict or set(frame)!={'kind','channelNonce','rpcId','service','method','request'}
                            or frame['kind']!='rpc' or frame['channelNonce']!=nonce or frame['rpcId']!=message['rpcId']
                            or frame['service']!=message['service'] or frame['method']!=message['method']):reject()
                    heartbeat(force=True)  # Full authentication before the bounded Mac RPC.
                    response=self._admission.authorize_rpc(frame['service'],frame['method'],frame['request'])
                    reply=encode(dict(kind='reply',channelNonce=nonce,rpcId=frame['rpcId'],response=response))
                    self._client.begin_worker_reply(attempt,len(reply),digest(reply),frame['rpcId'])
                    for offset in range(0,len(reply),4096):
                        left();heartbeat();self._client.worker_reply_chunk(attempt,offset,base64.b64encode(reply[offset:offset+4096]).decode('ascii'))
                    self._client.commit_worker_reply(attempt);last_rpc=frame['rpcId'];continue
                if state['businessState']=='transport-exited':
                    self._client.finish_worker(attempt);continue
                if state['businessState']=='closed':
                    challenge=state['closureChallenge']
                    if (challenge['sceneId']!=self._handle.sceneId or challenge['attemptId']!=attempt
                            or challenge['attemptNonce']!=nonce or challenge['preparationId']!=self._prep
                            or challenge['capsuleDigest']!=self._digest or challenge['requestHash']!=request.digest()
                            or challenge['bundleDigest']!=bundle.digest):reject()
                    # This original worker is already stopped and closed. A
                    # fresh connection may finalize this immutable result; no
                    # active RPC or writer attempt is moved between leases.
                    self._client.detach()
                    certificate=issue_create_closure(self._admission,challenge=challenge,worker_terminal=state['closedResult'])
                    left();self._client=self._client_type(self._handle);self._status()
                    reopened=self._client.poll_worker()['business']
                    if (reopened['businessState']!='closed' or reopened['attemptId']!=attempt or reopened['pendingNonce']!=nonce
                            or canonical(reopened['closureChallenge'])!=canonical(challenge)
                            or canonical(reopened['closedResult'])!=canonical(state['closedResult'])):reject()
                    final=self._client.reconcile_closure(certificate)['business'];left()
                    if final['businessState']!='reconciled':reject()
                    if notify is not None:
                        if on_scene_checkpoint is not None:
                            from deployment_compose_scene_checkpoint_v3_host import capture_scene_checkpoint
                            capture=capture_scene_checkpoint(self,certificate,final)
                            self._save_restart_checkpoint(certificate,final,notify,left,scene_capture=capture)
                        else:self._save_restart_checkpoint(certificate,final,notify,left)
                    return final
                time.sleep(.01)
        except BaseException as error:
            # End this controller lease immediately so the owning service can
            # drain/freeze its original attempt; never wait for an idle timeout
            # or reuse this connection after a Mac authorization failure.
            try:self._client.close()
            except Exception:pass
            if isinstance(error,Exception):reject()
            raise

    def _save_restart_checkpoint(self,certificate,final,notify,left,*,scene_capture=None):
        """Read-only material custody; no writer-origin or source-archive seal."""
        from deployment_compose_restart_checkpoint_v3_host import save_checkpoint
        from deployment_compose_phase_guard_v3_host import baseline_state_bytes
        from deployment_compose_live_ssh_v3_host import derive_defaults,ZERO_DEFAULTS
        admission=self._admission;entry=admission._root
        if entry is None or admission._current is not entry or admission._pending is not None:reject()
        history=admission._history(entry);snapshot=history.capture()
        payload=certificate['payload']
        if (entry['request']!=self._request or entry['bundle'].canonical_bytes!=self._bundle.canonical_bytes
                or payload['historyDigest']!=snapshot.digest
                or canonical(payload['receiptMap'])!=canonical(dict(snapshot.snapshot['receiptMap']))):reject()
        frozen=decode(self._raw);defaults={}
        for service in entry['bundle'].to_dict()['services']:
            name=service['name'];target=frozen['targetInputs'][name]
            derived=derive_defaults(target['image'],target['commitment'],self._keys['target'],
                **{key:target[key] for key in ('expected_image_id','expected_registry_digest','expected_architecture')})
            if target['commitment']['keyId']!=target['expected_key_id']:reject()
            defaults[name]={key:derived[key] for key in ZERO_DEFAULTS}
        baseline=baseline_state_bytes({row['Id']:row for row in frozen['rawRows'].values()})
        expected=canonical(final)
        if canonical(self._status()['business'])!=expected:reject()
        self._client.detach()
        case=admission._store.root.parent
        descriptor=save_checkpoint(case,original_history=history,baseline_bytes=baseline,
            authenticated_image_defaults=defaults,archive_digest=self._hello['archiveDigest'],
            witness_store=admission._store,witness_signer=admission._signers[0])
        self._owned();left()
        if (admission._root is not entry or admission._current is not entry or admission._pending is not None
                or entry['request']!=self._request
                or entry['bundle'].canonical_bytes!=self._bundle.canonical_bytes):reject()
        if admission._history(entry).capture().canonical!=snapshot.canonical:reject()
        if scene_capture is not None:
            from deployment_compose_scene_checkpoint_v3_host import retain_scene_checkpoint
            descriptor=retain_scene_checkpoint(scene_capture,descriptor)
        # Local custody callbacks can outlast a scene connection lease. Keep
        # them detached, then authenticate and recheck the same closed result.
        notify(decode(canonical(descriptor)))
        self._owned();left()
        if (admission._root is not entry or admission._current is not entry or admission._pending is not None
                or entry['request']!=self._request
                or entry['bundle'].canonical_bytes!=self._bundle.canonical_bytes
                or admission._history(entry).capture().canonical!=snapshot.canonical):reject()
        self._client=self._client_type(self._handle)
        if canonical(self._status()['business'])!=expected:reject()
