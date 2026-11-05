"""Prepare a new recovery request for a signed, closed partial root deployment.

Private contexts contain full phase facts. This module issues no capability,
renews no old grant and exposes no resume or execution API.
"""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json

from deployment_compose_history_v3_host import AuthenticatedHistoryV3, AuthenticatedHistorySnapshotV3, pairs
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, baseline_state_digest, _plain
from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2

_FIELDS={'schemaVersion','kind','originalBundleDigest','originalRequestHash',
         'baselineStateReference','baselineStateDigest','historyDigest','startWriteIndex',
         'receiptMap','knownWritePrefix','completedOperations','nextOperation',
         'currentPhaseSnapshot','recoveryNonce','expiresAt'}


def reject():
    raise ValueError('compose-recovery-preparation-v3-rejected') from None


class RecoveryPreparationHostV3:
    def __init__(self, *, original_history, store, phase_guard, readiness):
        try:
            if (type(original_history) is not AuthenticatedHistoryV3
                    or original_history._request.operation != 'deploy'
                    or original_history._parent is not None
                    or type(store) is not ComposeRecoveryStore
                    or type(phase_guard) is not PhaseGuardV3 or not callable(readiness)
                    or phase_guard._bundle.canonical_bytes != original_history._bundle.canonical_bytes):
                reject()
            self._history,self._store,self._guard,self._ready=original_history,store,phase_guard,readiness
            self._bundle,self._original=original_history._bundle,original_history._request
            self._baseline()
        except Exception:
            reject()

    def _baseline(self):
        rows=TrustedPhaseStateProducerV3.reload(self._store,self._bundle,
            read_json=self._guard._read,daemon_version=self._guard._version,
            expected_docker_root=self._guard._root)
        if baseline_state_digest(rows) != baseline_state_digest(self._guard._base):
            reject()
        return rows

    def _derive(self, nonce, expires_at, reviewed=None):
        if not hex_value(nonce):
            reject()
        # Freshness belongs to this new request, never to the historical grant.
        fresh=replace(self._original,operation='recovery',history_hash='0'*64,expires_at=expires_at)
        fresh.ensure_fresh(datetime.now(timezone.utc))
        snapshot=self._history.capture()
        if reviewed is not None and (type(reviewed) is not AuthenticatedHistorySnapshotV3
                                    or snapshot.canonical != reviewed.canonical):
            reject()
        value=json.loads(snapshot.canonical,object_pairs_hook=pairs)
        bundle=self._bundle.to_dict()
        tail=value['closedTail'];status=value['chainStatus']
        k=len(value['knownPrefix'])
        total=sum(op['phase'] != 'readiness' for op in bundle['operations'])
        if (type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                or value['bundleDigest'] != self._bundle.digest
                or value['originalRequestHash'] != self._original.digest()
                or value['sourceArchiveRef'] != bundle['archiveReference']
                or value['blocker'] is not None or value['pending'] is not None
                or not 0 < k < total or len(value['scopes']) != k
                or len(status['lineage'])+1 != k or status['activePhase'] != 'closed'
                or tail != dict(binding=status['activeBinding'],seq=status['activeSeq'],head=status['activeHead'])
                or any(scope['seq'] != 6 for scope in value['scopes'])):
            reject()
        self._baseline()
        receipts=value['receiptMap']
        ops=(self._bundle.resolve_operations(receipts) if len(receipts)==len(bundle['services'])
             else self._bundle.creation_operations())
        writes=[op for op in ops if op['method'] != 'GET']
        if k >= len(writes) or canonical(value['knownPrefix']) != canonical(writes[:k]):
            reject()
        next_operation=writes[k]
        next_index=next(index for index,op in enumerate(ops) if op==next_operation)
        completed=ops[:next_index]
        started={op['service'] for op in completed if op['phase']=='start'}
        for service in sorted(started):
            if self._ready(service,receipts[service]) is not True:
                reject()
        context=dict(phase_index=k,operation=next_operation,receipts=receipts,completed_operations=completed)
        phase=_plain(self._guard.capture_phase(context))
        # Recheck the signed witness after all private reads/readiness checks.
        if self._history.capture().canonical != snapshot.canonical:
            reject()
        result=dict(schemaVersion=1,kind='compose-recovery-context-v3',
            originalBundleDigest=self._bundle.digest,originalRequestHash=self._original.digest(),
            baselineStateReference=bundle['baselineStateReference'],baselineStateDigest=bundle['baselineStateDigest'],
            historyDigest=snapshot.digest,startWriteIndex=k,receiptMap=receipts,
            knownWritePrefix=value['knownPrefix'],completedOperations=completed,nextOperation=next_operation,
            currentPhaseSnapshot=phase,recoveryNonce=nonce,expiresAt=expires_at)
        return result,snapshot

    def prepare_intent(self, *, operation_nonce, expires_at):
        try:
            context,reviewed=self._derive(operation_nonce,expires_at)
            raw=canonical(context);reference=self._store.put(raw)
            request=replace(self._original,operation='recovery',history_hash=reviewed.digest,
                observation_hash=hashlib.sha256(raw).hexdigest(),expires_at=expires_at)
            self.verify_context(reference,request,reviewed)
            review=self._bundle.public_review()
            review.update(requestDigest=request.digest(),historyDigest=reviewed.digest,
                recoveryContextDigest=request.observation_hash,startWriteIndex=context['startWriteIndex'],
                expiresAt=expires_at,authorityGranted=False,executionAvailable=False,productionReady=False,
                blockers=['fresh-approval-required','coordinator-admission-and-recovery-required','startup-fence-required'])
            return dict(bundle=self._bundle,request=request,recovery_context_reference=reference,
                        review=review,reviewed_history=reviewed)
        except Exception:
            reject()

    def verify_context(self, reference, request, reviewed_history):
        """Reload private CAS bytes and rederive every history/phase field freshly."""
        try:
            if type(request) is not RequestV2 or type(reviewed_history) is not AuthenticatedHistorySnapshotV3:
                reject()
            raw=self._store.get(reference)
            context=json.loads(raw,object_pairs_hook=pairs)
            if (type(context) is not dict or set(context) != _FIELDS or canonical(context) != raw
                    or hashlib.sha256(raw).hexdigest() != request.observation_hash):
                reject()
            expected=replace(self._original,operation='recovery',history_hash=reviewed_history.digest,
                observation_hash=hashlib.sha256(raw).hexdigest(),expires_at=context['expiresAt'])
            if request != expected:
                reject()
            current,_=self._derive(context['recoveryNonce'],context['expiresAt'],reviewed_history)
            if canonical(current) != raw:
                reject()
            return current
        except Exception:
            reject()
