"""Static recovery declarations checked under a pinned normalization version.

Neither repeated static reads nor synthesized inventory establish actual machine
freshness, absence of omitted containers, daemon version, or writer shutdown.
"""
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from urllib.parse import quote

from deployment_contract_v2 import RequestV2
from deployment_compose_history_v3_host import pairs
from deployment_compose_recovery_capsule_v3_host import verify_recovery_capsule
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, baseline_state_bytes, _plain
from deployment_compose_witness_store import canonical

MAX_BASELINE = 8 * 1024 * 1024


def reject():
    raise ValueError('recovery-phase-capsule-v3-rejected') from None


def decode(raw):
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: reject())
    if canonical(value) != raw: reject()
    return value


def inflate(rows):
    if type(rows) is not dict or not rows: reject()
    result = deepcopy(rows)
    for row in result.values():
        row['State']['Health'] = {'Status': row.pop('Health')}
    if baseline_state_bytes(result) != canonical(rows): reject()
    return result


@dataclass(frozen=True)
class VerifiedRecoveryPhaseV3:
    request_bytes: bytes = field(repr=False)
    context_bytes: bytes = field(repr=False)
    history_digest: str
    consistency_digest: str
    phaseConsistencyVerified: bool = field(default=True, init=False)
    phaseFreshnessVerified: bool = field(default=False, init=False)
    linuxQuiescenceVerified: bool = field(default=False, init=False)
    authorityGranted: bool = field(default=False, init=False)
    executionAvailable: bool = field(default=False, init=False)
    runtimePermit: bool = field(default=False, init=False)
    productionReady: bool = field(default=False, init=False)


def verify_captured_recovery_phase(capsule_bytes, *, original_history, baseline_bytes,
        expected_daemon_version, expected_source, expected_host_id, expected_daemon_id,
        expected_target, expected_policy_hash):
    try:
        verified = verify_recovery_capsule(capsule_bytes, original_history=original_history,
            expected_source=expected_source, expected_host_id=expected_host_id,
            expected_daemon_id=expected_daemon_id, expected_target=expected_target,
            expected_policy_hash=expected_policy_hash)
        if (type(baseline_bytes) is not bytes or not 0 < len(baseline_bytes) <= MAX_BASELINE
                or type(expected_daemon_version) is not dict
                or set(expected_daemon_version) != {'Version', 'GitCommit'}
                or any(type(v) is not str or not v for v in expected_daemon_version.values())): reject()
        version = deepcopy(expected_daemon_version)
        bundle = original_history._bundle
        value = bundle.to_dict()
        if hashlib.sha256(baseline_bytes).hexdigest() != value['baselineStateDigest']: reject()
        baseline = inflate(decode(baseline_bytes))
        context = decode(verified.context_bytes)
        phase = context['currentPhaseSnapshot']
        rows = inflate(phase['rows'])
        resources = deepcopy(phase['resources'])
        # This map is fixed private data. No Engine endpoint or callback exists.
        responses = {'/v1.45/version': version, '/v1.45/info': {'ID': expected_daemon_id}}
        filters = json.dumps({'label': ['com.docker.compose.project=' + value['identity']['project']]}, sort_keys=True, separators=(',', ':'))
        responses['/v1.45/containers/json?all=1&filters=' + quote(filters, safe='')] = [{'Id': cid} for cid in rows]
        for cid, row in rows.items(): responses['/v1.45/containers/' + cid + '/json'] = row
        for name, pin in value['networks'].items():
            responses['/v1.45/networks/' + pin['id']] = resources['network:' + name]
        volumes = {m['Name'] for row in baseline.values() for m in row['Mounts'] if m['Type'] == 'volume'}
        for name in volumes: responses['/v1.45/volumes/' + quote(name, safe='')] = resources['volume:' + name]
        def captured_read(path):
            if path not in responses: reject()
            return deepcopy(responses[path])
        guard = PhaseGuardV3(bundle, baseline, read_json=captured_read,
            daemon_version=version, expected_docker_root=None)
        captured = guard.capture_phase(dict(phase_index=1, operation=context['nextOperation'],
            receipts=context['receiptMap'], completed_operations=context['completedOperations']))
        if canonical(_plain(captured)) != canonical(phase): reject()
        if original_history.capture().digest != verified.history_digest: reject()
        RequestV2.from_json(verified.request_bytes.decode('ascii')).ensure_fresh(datetime.now(timezone.utc))
        digest = hashlib.sha256(canonical(dict(historyDigest=verified.history_digest,
            baselineDigest=value['baselineStateDigest'], normalizationVersion=version,
            contextDigest=hashlib.sha256(verified.context_bytes).hexdigest()))).hexdigest()
        return VerifiedRecoveryPhaseV3(verified.request_bytes, verified.context_bytes,
            verified.history_digest, digest)
    except Exception:
        reject()
