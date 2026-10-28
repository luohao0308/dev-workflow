"""One-use host startup fence for completed deployment to fresh rollback.

The embedding owns process quiescence and trusted phase checks. The independent
closed-parent CAS fences competing coordinators; evidence alone grants no permit.
Partial recovery and unknown outcomes are deliberately outside this first lane.
"""
import json
import threading
from datetime import datetime, timezone

from deployment_compose_history_v3_host import AuthenticatedHistoryV3, AuthenticatedHistorySnapshotV3
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
from deployment_compose_operation_witness_v3 import MAX_EVENTS, MAX_SCOPES
from deployment_compose_coordinator_v3_host import Profile3StepExecutor, canonical, immutable


def reject():
    raise ValueError('compose-startup-fence-v3-blocked')


class Profile3StartupFenceV3:
    def __init__(self, *, original_history, reviewed_history, quiesce_writer):
        if (type(original_history) is not AuthenticatedHistoryV3
                or type(reviewed_history) is not AuthenticatedHistorySnapshotV3
                or not callable(quiesce_writer)):
            reject()
        self._history, self._reviewed = original_history, reviewed_history
        self._quiesce = quiesce_writer
        self._used = False
        self._lock = threading.Lock()

    def activate(self, *, bundle, request, binding, intent_authority, phase_guard,
                 witness_client_factory, consumption_receipt_hash, gate_policy):
        """CAS exactly once; a lost acknowledgement cannot be retried here."""
        with self._lock:
            if self._used:
                reject()
            self._used = True
            try:
                old = self._history._request
                request.ensure_fresh(datetime.now(timezone.utc))
                if (old.operation != 'deploy' or request.operation != 'rollback'
                        or request.plan_hash != bundle.digest
                        or request.history_hash != self._reviewed.digest
                        or request.digest() == old.digest()
                        or request.source != old.source or request.target != old.target
                        or request.host_id != old.host_id or request.daemon_id != old.daemon_id
                        or request.components != old.components
                        or request.protected_components != old.protected_components):
                    reject()
                descriptor = Profile3StepExecutor.scope_descriptor(bundle, request,
                    consumption_receipt_hash, bundle.creation_operations()[0], 0, {})
                if (binding['scopeHash'] != descriptor['scopeHash']
                        or binding['generation'] != descriptor['generation']):
                    reject()
                if self._quiesce() is not True:
                    reject()
                current = self._history.capture()
                if current.canonical != self._reviewed.canonical:
                    reject()
                value = json.loads(current.canonical)
                receipts = value['receiptMap']
                original, rollback = self._history._bundle.to_dict(), bundle.to_dict()
                if (any(canonical(original[k]) != canonical(rollback[k])
                        for k in ('protectedContainers', 'networks', 'mounts', 'identity'))
                        or len(original['services']) != len(rollback['services'])):
                    reject()
                for before, after in zip(original['services'], rollback['services']):
                    if (any(canonical(before[k]) != canonical(after[k])
                            for k in ('name', 'finalName', 'dependsOn'))
                            or after['baselineContainerId'] != receipts[before['name']]
                            or after['baselineImageId'] != before['targetImageId']
                            or after['targetImageId'] != before['baselineImageId']
                            or canonical(after['baselineCreateBody']) != canonical(before['targetCreateBody'])
                            or canonical(after['targetCreateBody']) != canonical(before['baselineCreateBody'])):
                        reject()
                expected = [o for o in self._history._bundle.resolve_operations(receipts) if o['method'] != 'GET']
                status, tail = value['chainStatus'], value['closedTail']
                if (value['blocker'] is not None or value['pending'] is not None
                        or canonical(value['knownPrefix']) != canonical(expected)
                        or tail is None or status['activePhase'] != 'closed'
                        or status['activeSeq'] != 6 or tail != dict(binding=status['activeBinding'],
                                seq=status['activeSeq'], head=status['activeHead'])):
                    reject()
                writes = sum(o['phase'] != 'readiness' for o in bundle.to_dict()['operations'])
                scopes = len(status['lineage']) + 1
                if scopes + writes > MAX_SCOPES or (scopes + writes) * 6 > MAX_EVENTS:
                    reject()
                if any(binding[k] != tail['binding'][k] for k in ('epoch', 'policyHash')):
                    reject()
                from deployment_compose_witness_budget_v3_host import check_witness_byte_capacity
                check_witness_byte_capacity(bundle, request, gate_policy,
                    consumption_receipt_hash, binding, prior_snapshot=current)
                intent_authority.check_consumed_intent(request)
                operation = bundle.creation_operations()[0]
                snapshot = immutable(dict(phase_index=0, operation=operation,
                                          receipts={}, completed_operations=[]))
                if phase_guard(snapshot) is not True:
                    reject()
                parent = witness_client_factory(tail['binding'])
                if (type(parent) is not OperationWitnessClientV3
                        or parent.binding != tail['binding']
                        or parent.key_hash != self._history._client.key_hash):
                    reject()
                # Fresh consent and current phase are checked before the only mutation.
                intent_authority.check_consumed_intent(request)
                parent.transition_successor(expected_seq=tail['seq'], expected_head=tail['head'],
                                            childBinding=binding)
                child = witness_client_factory(binding)
                if (type(child) is not OperationWitnessClientV3 or child.key_hash != parent.key_hash
                        or child.binding != binding):
                    reject()
                view = child.check(expected_seq=0, expected_head='0'*64)
                if (view['active'] is not True or not view['lineage']
                        or view['lineage'][-1] != tail):
                    reject()
                return child.binding
            except Exception:
                reject()


class Profile3RecoveryFenceV3:
    """Continue only a closed successful prefix with fresh reviewed context."""
    def __init__(self, *, preparation, context_reference, reviewed_history, quiesce_writer):
        from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
        if (type(preparation) is not RecoveryPreparationHostV3
                or type(reviewed_history) is not AuthenticatedHistorySnapshotV3
                or not callable(quiesce_writer)):
            reject()
        self._preparation, self._reference = preparation, context_reference
        self._reviewed, self._quiesce = reviewed_history, quiesce_writer
        self._used = False
        self._lock = threading.Lock()

    def activate(self, *, bundle, request, binding, intent_authority, phase_guard,
                 witness_client_factory, consumption_receipt_hash, gate_policy):
        with self._lock:
            if self._used:
                reject()
            self._used = True
            try:
                request.ensure_fresh(datetime.now(timezone.utc))
                if request.operation != 'recovery' or self._quiesce() is not True:
                    reject()
                context = self._preparation.verify_context(self._reference, request, self._reviewed)
                history = self._preparation._history
                if (bundle.canonical_bytes != history._bundle.canonical_bytes
                        or phase_guard is not self._preparation._guard):
                    reject()
                live = history.capture()
                if live.canonical != self._reviewed.canonical:
                    reject()
                value = json.loads(live.canonical)
                status, tail = value['chainStatus'], value['closedTail']
                if (tail is None or status['activePhase'] != 'closed'
                        or tail != dict(binding=status['activeBinding'], seq=status['activeSeq'],
                                        head=status['activeHead']) or tail['seq'] != 6):
                    reject()
                descriptor = Profile3StepExecutor.scope_descriptor(bundle, request,
                    consumption_receipt_hash, context['nextOperation'],
                    context['startWriteIndex'], context['receiptMap'])
                if (binding['scopeHash'] != descriptor['scopeHash']
                        or binding['generation'] != descriptor['generation']
                        or any(binding[k] != tail['binding'][k] for k in ('epoch', 'policyHash'))):
                    reject()
                from deployment_compose_witness_budget_v3_host import check_witness_byte_capacity
                check_witness_byte_capacity(bundle, request, gate_policy,
                    consumption_receipt_hash, binding, prior_snapshot=live)
                intent_authority.check_consumed_intent(request)
                parent = witness_client_factory(tail['binding'])
                if (type(parent) is not OperationWitnessClientV3
                        or parent.binding != tail['binding']
                        or parent.key_hash != history._client.key_hash):
                    reject()
                parent.transition_successor(expected_seq=tail['seq'], expected_head=tail['head'],
                                            childBinding=binding)
                child = witness_client_factory(binding)
                if (type(child) is not OperationWitnessClientV3 or child.binding != binding
                        or child.key_hash != parent.key_hash):
                    reject()
                view = child.check(expected_seq=0, expected_head='0'*64)
                if view['active'] is not True or not view['lineage'] or view['lineage'][-1] != tail:
                    reject()
                return context
            except Exception:
                reject()
