"""Readonly recovery data checks against the embedding's signed root history.

The phase snapshot remains a Linux assertion, not fresh machine evidence. This
module never registers, consumes or authorizes an intent.
"""
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json

from deployment_contract_v2 import RequestV2
from deployment_compose_history_v3_host import AuthenticatedHistoryV3, pairs
from deployment_compose_recovery_prepare_v3_host import _FIELDS
from deployment_compose_witness_store import canonical, hex_value

MAX_CAPSULE = 4 * 1024 * 1024


def reject():
    raise ValueError('recovery-capsule-v3-rejected') from None


@dataclass(frozen=True)
class VerifiedRecoveryCapsuleV3:
    request_bytes: bytes = field(repr=False)
    context_bytes: bytes = field(repr=False)
    history_digest: str
    phaseFreshnessVerified: bool = field(default=False, init=False)
    linuxQuiescenceVerified: bool = field(default=False, init=False)
    authorityGranted: bool = field(default=False, init=False)
    executionAvailable: bool = field(default=False, init=False)
    runtimePermit: bool = field(default=False, init=False)
    productionReady: bool = field(default=False, init=False)


def verify_recovery_capsule(capsule_bytes, *, original_history, expected_source,
                            expected_host_id, expected_daemon_id, expected_target,
                            expected_policy_hash):
    try:
        if (type(capsule_bytes) is not bytes or not 0 < len(capsule_bytes) <= MAX_CAPSULE
                or type(original_history) is not AuthenticatedHistoryV3): reject()
        capsule = json.loads(capsule_bytes, object_pairs_hook=pairs,
            parse_constant=lambda _: reject())
        if (type(capsule) is not dict or set(capsule) != {'request', 'context'}
                or canonical(capsule) != capsule_bytes): reject()
        context = capsule['context']
        if type(context) is not dict or set(context) != _FIELDS: reject()
        phase = context['currentPhaseSnapshot']
        if (type(phase) is not dict or set(phase) != {'rows', 'resources'}
                or any(type(v) is not dict for v in phase.values())
                or not hex_value(context['recoveryNonce'])): reject()
        original = original_history._request
        bundle = original_history._bundle
        value = bundle.to_dict()
        if (original_history._parent is not None or original.operation != 'deploy'
                or original.profile_version != '3' or original.production is not False
                or len(value['services']) != 1
                or original.source != expected_source or original.host_id != expected_host_id
                or original.daemon_id != expected_daemon_id or original.target != expected_target
                or original.policy_hash != expected_policy_hash): reject()
        request = RequestV2.from_json(canonical(capsule['request']).decode('ascii'))
        request.ensure_fresh(datetime.now(timezone.utc))
        snapshot = original_history.capture()
        history = json.loads(snapshot.canonical, object_pairs_hook=pairs)
        status, tail = history['chainStatus'], history['closedTail']
        first = bundle.creation_operations()[0]
        if (type(history['schemaVersion']) is not int or history['schemaVersion'] != 1
                or history['bundleDigest'] != bundle.digest
                or history['originalRequestHash'] != original.digest()
                or history['sourceArchiveRef'] != value['archiveReference']
                or history['pending'] is not None or history['blocker'] is not None
                or len(history['scopes']) != 1 or status['lineage']
                or status['activePhase'] != 'closed' or type(status['activeSeq']) is not int
                or status['activeSeq'] != 6 or history['scopes'][0]['seq'] != 6
                or canonical(tail) != canonical(dict(binding=status['activeBinding'],
                    seq=6, head=status['activeHead']))
                or canonical(history['knownPrefix']) != canonical([first])): reject()
        receipts = history['receiptMap']
        if (set(receipts) != {first['service']} or not hex_value(receipts[first['service']])): reject()
        ops = bundle.resolve_operations(receipts)
        writes = [op for op in ops if op['method'] != 'GET']
        if len(writes) <= 1: reject()
        following = writes[1]
        completed = ops[:ops.index(following)]
        expected_context = dict(schemaVersion=1, kind='compose-recovery-context-v3',
            originalBundleDigest=bundle.digest, originalRequestHash=original.digest(),
            baselineStateReference=value['baselineStateReference'],
            baselineStateDigest=value['baselineStateDigest'], historyDigest=snapshot.digest,
            startWriteIndex=1, receiptMap=receipts, knownWritePrefix=[first],
            completedOperations=completed, nextOperation=following,
            currentPhaseSnapshot=phase, recoveryNonce=context['recoveryNonce'],
            expiresAt=context['expiresAt'])
        if canonical(expected_context) != canonical(context): reject()
        raw = canonical(context)
        expected = replace(original, operation='recovery', history_hash=snapshot.digest,
            observation_hash=hashlib.sha256(raw).hexdigest(), expires_at=context['expiresAt'])
        if request.canonical_json() != expected.canonical_json(): reject()
        if original_history.capture().canonical != snapshot.canonical: reject()
        request.ensure_fresh(datetime.now(timezone.utc))
        return VerifiedRecoveryCapsuleV3(request.canonical_json().encode('ascii'), raw, snapshot.digest)
    except Exception:
        reject()
