"""Draft-only checkpoint recovery intents, isolated from the old approval profile.

The embedding independently authenticates restart material and the live observer.
This module neither admits work nor reopens the subject's original baseline CAS.
Filesystem, crypto and witness flock operations retain their existing limits.
"""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import math
import os
import secrets
import threading
import time
import weakref

from deployment_compose_restart_material_v3_host import reopen_material, _prefix
from deployment_compose_live_phase_v3_host import LiveRecoveryPhaseCaptureV3
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_history_v3_host import AuthenticatedHistorySnapshotV3
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2

PROFILE = 'compose-checkpoint-recovery-intent-v3'
KIND = 'compose-checkpoint-recovery-context-v3'
_FIELDS = {'schemaVersion','kind','checkpointMaterialDigest','originalBundleDigest','originalRequestHash',
    'checkpointBaselineReference','baselineStateDigest','historyDigest','startWriteIndex','receiptMap',
    'knownWritePrefix','completedOperations','nextOperation','currentPhaseSnapshot','liveEndpointBinding',
    'normalizationVersion','recoveryNonce','expiresAt'}
_RECORDS = weakref.WeakKeyDictionary()
_FALSE = ('approvalReady','sourceRevalidated','daemonContinuityVerified','writerQuiescenceVerified',
          'authorityGranted','executionAvailable','runtimePermit','recoveryAuthorized','productionReady')
_BLOCKERS = ['source-revalidation','writer-quiescence','fresh-approval','admission-and-tail-CAS','retained-lifecycle']


def reject():raise ValueError('compose-checkpoint-recovery-preparation-v3-rejected') from None


def digest(raw):return hashlib.sha256(raw).hexdigest()


def deadline(timeout):
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 30:reject()
    return time.monotonic()+timeout


def left(end):
    result=end-time.monotonic()
    if result<=0:reject()
    return result


class CheckpointRecoveryPreparationHostV3:
    def __copy__(self):reject()
    def __deepcopy__(self,memo):reject()
    def __reduce_ex__(self,protocol):reject()

    def __init__(self,*,restart_material,expected_material_digest,expected_context,gate_key,
                 witness_public_key,witness_transport,daemon,expected_version,store):
        try:
            if type(store) is not ComposeRecoveryStore:reject()
            version=canonical(expected_version)
            pins=canonical(expected_context)
            self._context=reopen_material(restart_material,expected_digest=expected_material_digest,
                expected_context=decode(pins),gate_key=gate_key,witness_public_key=witness_public_key,
                witness_transport=witness_transport)
            if (self._context.history._request.profile_version!='3'
                    or self._context.history._request.production is not False):reject()
            self._store=store
            self._version=version
            self._capture=LiveRecoveryPhaseCaptureV3(original_history=self._context.history,
                baseline_bytes=self._context.baseline_bytes,daemon=daemon,expected_version=decode(self._version))
            _RECORDS[self]=dict(owner=(os.getpid(),threading.get_ident()),identity=CheckpointRecoveryPreparationHostV3._identity(self),
                               material=self._context.material_digest,version=self._version,
                               material_bytes=restart_material,pins=pins,gate_key=self._context.history._key,
                               public=self._context.history._client._public,transport=witness_transport)
        except Exception:reject()

    def _identity(self):
        context=self._context;store=self._store;capture=self._capture
        return (context,context.history,context.snapshot.canonical,context.baseline_bytes,context.material_digest,
                store,store._root,store._key,store._fd,store._identity,capture,self._version,
                capture._history,capture._baseline,capture._version,capture._daemon,
                capture._seal,LiveRecoveryPhaseCaptureV3._identity(capture))

    def _record(self):
        record=_RECORDS.get(self)
        if record is None or record['owner']!=(os.getpid(),threading.get_ident()):reject()
        if CheckpointRecoveryPreparationHostV3._identity(self)!=record['identity']:reject()
        return record

    def _fresh(self,expires_at):
        original=self._context.history._request
        request=replace(original,operation='recovery',profile_id=PROFILE,profile_version='3',
                        history_hash='0'*64,expires_at=expires_at)
        request.ensure_fresh(datetime.now(timezone.utc))
        return request

    def _derive(self,nonce,expires_at,baseline_reference,end,reviewed=None):
        record=self._record();left(end)
        if not hex_value(nonce) or nonce==self._context.history._bundle.to_dict()['operationNonce']:reject()
        self._fresh(expires_at)
        fresh=reopen_material(record['material_bytes'],expected_digest=record['material'],
            expected_context=decode(record['pins']),gate_key=record['gate_key'],
            witness_public_key=record['public'],witness_transport=record['transport'])
        if fresh.snapshot.canonical!=self._context.snapshot.canonical:reject()
        history=self._context.history;bundle=history._bundle
        before=history.capture();value=_prefix(history,before)
        if reviewed is not None and (type(reviewed) is not AuthenticatedHistorySnapshotV3
                                    or before.canonical!=reviewed.canonical):reject()
        if before.canonical!=self._context.snapshot.canonical:reject()
        if self._store.get(baseline_reference)!=self._context.baseline_bytes:reject()
        phase=LiveRecoveryPhaseCaptureV3.capture(self._capture,timeout=left(end))
        if phase.history_digest!=before.digest or phase.baseline_digest!=digest(self._context.baseline_bytes):reject()
        ops=bundle.resolve_operations(value['receiptMap']);writes=[op for op in ops if op['method']!='GET']
        following=writes[1]
        result=dict(schemaVersion=1,kind=KIND,checkpointMaterialDigest=record['material'],
            originalBundleDigest=bundle.digest,originalRequestHash=history._request.digest(),
            checkpointBaselineReference=baseline_reference,baselineStateDigest=phase.baseline_digest,
            historyDigest=before.digest,startWriteIndex=1,receiptMap=value['receiptMap'],
            knownWritePrefix=value['knownPrefix'],completedOperations=ops[:ops.index(following)],nextOperation=following,
            currentPhaseSnapshot=decode(phase.phase_bytes),liveEndpointBinding=decode(phase.endpoint_binding),
            normalizationVersion=decode(record['version']),recoveryNonce=nonce,expiresAt=expires_at)
        if history.capture().canonical!=before.canonical:reject()
        self._record();self._fresh(expires_at);left(end)
        return result,before

    def prepare_intent(self,*,operation_nonce=None,expires_at,timeout=15):
        try:
            self._record();end=deadline(timeout)
            if operation_nonce is None:operation_nonce=secrets.token_hex(32)
            self._fresh(expires_at)
            if not hex_value(operation_nonce) or operation_nonce==self._context.history._bundle.to_dict()['operationNonce']:reject()
            baseline_reference=self._store.put(self._context.baseline_bytes)
            if self._store.get(baseline_reference)!=self._context.baseline_bytes:reject()
            value,snapshot=self._derive(operation_nonce,expires_at,baseline_reference,end)
            raw=canonical(value);reference=self._store.put(raw)
            original=self._context.history._request;bundle=self._context.history._bundle
            request=replace(original,operation='recovery',profile_id=PROFILE,profile_version='3',
                history_hash=snapshot.digest,observation_hash=digest(raw),expires_at=expires_at)
            self._verify(reference,request,snapshot,end)
            review=bundle.public_review()
            review.update(requestDigest=request.digest(),historyDigest=snapshot.digest,
                recoveryContextDigest=request.observation_hash,checkpointMaterialDigest=self._context.material_digest,
                startWriteIndex=1,expiresAt=expires_at,draftOnly=True,requestProfileId=PROFILE,
                originalBundleProfileId=bundle.to_dict()['profile'],blockers=list(_BLOCKERS),
                **{key:False for key in _FALSE})
            self._record();request.ensure_fresh(datetime.now(timezone.utc));left(end)
            return dict(bundle=bundle,request=request,recovery_context_reference=reference,
                        review=review,reviewed_history=snapshot)
        except Exception:reject()

    def _verify(self,reference,request,reviewed_history,end):
        self._record();left(end)
        if type(request) is not RequestV2 or type(reviewed_history) is not AuthenticatedHistorySnapshotV3:reject()
        request.ensure_fresh(datetime.now(timezone.utc))
        raw=self._store.get(reference);value=decode(raw)
        if (type(value) is not dict or set(value)!=_FIELDS or type(value['schemaVersion']) is not int
                or value['schemaVersion']!=1 or value['kind']!=KIND or type(value['startWriteIndex']) is not int
                or value['startWriteIndex']!=1 or digest(raw)!=request.observation_hash):reject()
        expected=replace(self._context.history._request,operation='recovery',profile_id=PROFILE,profile_version='3',
            history_hash=reviewed_history.digest,observation_hash=digest(raw),expires_at=value['expiresAt'])
        if request!=expected:reject()
        current,_=self._derive(value['recoveryNonce'],value['expiresAt'],value['checkpointBaselineReference'],end,reviewed_history)
        if canonical(current)!=raw:reject()
        self._record();request.ensure_fresh(datetime.now(timezone.utc));left(end)
        return current

    def verify_context(self,reference,request,reviewed_history,timeout=15):
        try:
            self._record()
            return self._verify(reference,request,reviewed_history,deadline(timeout))
        except Exception:reject()
