"""Private cold reconstruction of bounded schema-3 ancestry, without authority.

The embedding independently provisions material/context pins, one gate key and
an authenticated read-only witness transport. It must retain original baseline
CAS entries and their key separately for subsequent recovery preparation.
"""
from dataclasses import asdict
import hashlib
import re

from deployment_compose_history_v3_host import (
    ANCESTRY_PROFILE, MAX_ANCESTRY_DEPTH, AuthenticatedHistoryV3, AuthenticatedHistorySnapshotV3,
)
from deployment_compose_coordinator_v3_host import check_witness_capacity
from deployment_compose_operation_witness_v3 import MAX_SCOPES
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
from deployment_compose_restart_material_v3_host import (
    MAX_MATERIAL, ReadonlyRestartContextV3, _bundle, _baseline, _context,
)
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2
from deployment_gateway import GatePolicy

_KIND = 'compose-bounded-restart-material-v3'
_FIELDS = {'schemaVersion', 'kind', 'nodes', 'baselinesByBundle',
           'authenticatedImageDefaultsByBundle', 'snapshot', 'archiveDigest'}
_NODE_FIELDS = {'bundle', 'request', 'gatePolicy', 'consumptionReceiptHash', 'firstBinding', 'reviewedParent'}
_CONTEXT = {'sourceSha', 'hostId', 'daemonId', 'archiveDigest', 'historyDigest', 'baselineStateDigest'}
_READS = frozenset({'read', 'check', 'events_after', 'chain_status'})
_IDENTITY = ('source', 'target', 'host_id', 'daemon_id', 'environment', 'production',
             'components', 'protected_components', 'policy_hash')


def reject():
    raise ValueError('compose-bounded-restart-material-v3-rejected') from None


def _prefix(history, snapshot):
    value = decode(snapshot.canonical)
    count = len(value['knownPrefix'])
    total = sum(operation['phase'] != 'readiness' for operation in history._bundle.to_dict()['operations'])
    if (type(value['schemaVersion']) is not int or value['schemaVersion'] != 3
            or value['ancestryProfile'] != ANCESTRY_PROFILE
            or value['pending'] is not None or value['blocker'] is not None
            or not 0 < count < total or not 1 <= len(value['scopes']) <= MAX_SCOPES
            or value['chainStatus']['activePhase'] != 'closed'
            or any(type(scope['seq']) is not int or scope['seq'] != 6 for scope in value['scopes'])
            or value['closedTail'] != {key:value['scopes'][-1][key] for key in ('binding', 'seq', 'head')}):
        reject()
    return value


def _validate_nodes(nodes, snapshot):
    value = decode(snapshot.canonical)
    segments, scopes = value['segments'], value['scopes']
    if len(segments) != len(nodes):
        reject()
    for node, segment in zip(nodes, segments):
        index = segment['scopeStart']
        if (type(index) is not int or not 0 <= index < len(scopes)
                or node._request.policy_hash != node._policy.identity_hash()
                or segment['requestHash'] != node._request.digest()
                or segment['bundleDigest'] != node._bundle.digest
                or segment['receiptHash'] != node._receipt
                or segment['parentHistoryDigest'] != (None if node._reviewed_parent is None else node._reviewed_parent.digest)
                or canonical(node._client.binding) != canonical(scopes[index]['binding'])):
            reject()


def capture_material(history, *, baseline_bytes_by_bundle, authenticated_image_defaults_by_bundle, archive_digest):
    """Capture a closed incomplete logical prefix and all authenticated ancestors."""
    try:
        if (type(history) is not AuthenticatedHistoryV3 or not hex_value(archive_digest)
                or type(baseline_bytes_by_bundle) is not dict
                or type(authenticated_image_defaults_by_bundle) is not dict
                or not 1 <= len(baseline_bytes_by_bundle) <= MAX_ANCESTRY_DEPTH
                or not 1 <= len(authenticated_image_defaults_by_bundle) <= MAX_ANCESTRY_DEPTH):
            reject()
        fingerprint = history._ancestry_fingerprint()
        nodes = []
        current = history
        while current is not None:
            if (current._key != history._key or current._request.policy_hash != current._policy.identity_hash()
                    or any(getattr(current._request, key) != getattr(history._request, key) for key in _IDENTITY)):
                reject()
            nodes.append(current)
            current = current._parent
        nodes.reverse()
        used = {node._bundle.digest for node in nodes}
        if set(baseline_bytes_by_bundle) != used or set(authenticated_image_defaults_by_bundle) != used:
            reject()
        baselines = dict(baseline_bytes_by_bundle)
        defaults = decode(canonical(authenticated_image_defaults_by_bundle))
        baseline_rows = {}
        for node in nodes:
            bundle = _bundle(node._bundle.to_dict(), defaults[node._bundle.digest])
            check_witness_capacity(bundle)
            rows = _baseline(baselines[bundle.digest], bundle)
            if canonical(rows) != baselines[bundle.digest]:
                reject()
            baseline_rows[bundle.digest] = rows
        snapshot = history.capture()
        value = _prefix(history, snapshot)
        _validate_nodes(nodes, snapshot)
        material = dict(schemaVersion=1, kind=_KIND, nodes=[dict(
            bundle=node._bundle.to_dict(), request=asdict(node._request), gatePolicy=asdict(node._policy),
            consumptionReceiptHash=node._receipt, firstBinding=node._client.binding,
            reviewedParent=None if node._reviewed_parent is None else decode(node._reviewed_parent.canonical))
            for node in nodes], baselinesByBundle=baseline_rows,
            authenticatedImageDefaultsByBundle=defaults, snapshot=value, archiveDigest=archive_digest)
        raw = canonical(material)
        if (not 0 < len(raw) <= MAX_MATERIAL or history.capture().canonical != snapshot.canonical
                or history._ancestry_fingerprint() != fingerprint
                or set(baseline_bytes_by_bundle) != used
                or any(type(raw_baseline) is not bytes or raw_baseline != baselines[key]
                       for key, raw_baseline in baseline_bytes_by_bundle.items())
                or canonical(authenticated_image_defaults_by_bundle) != canonical(defaults)):
            reject()
        return raw
    except Exception:
        reject()


def reopen_material(raw, *, expected_digest, expected_context, gate_key, witness_public_key, witness_transport):
    """Rebuild opted histories and reauthenticate every signed ancestor freshly."""
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_MATERIAL
                or not hex_value(expected_digest) or hashlib.sha256(raw).hexdigest() != expected_digest
                or type(expected_context) is not dict or set(expected_context) != _CONTEXT
                or any(type(value) is not str or not value for value in expected_context.values())
                or re.fullmatch('[a-f0-9]{40}', expected_context['sourceSha']) is None
                or any(not hex_value(expected_context[key]) for key in ('archiveDigest', 'historyDigest', 'baselineStateDigest'))
                or type(gate_key) is not bytes or len(gate_key) < 32 or not callable(witness_transport)):
            reject()
        pins = decode(canonical(expected_context))
        value = decode(raw)
        if (type(value) is not dict or set(value) != _FIELDS
                or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                or value['kind'] != _KIND or not hex_value(value['archiveDigest'])
                or type(value['nodes']) is not list or not 1 <= len(value['nodes']) <= MAX_ANCESTRY_DEPTH
                or type(value['baselinesByBundle']) is not dict
                or type(value['authenticatedImageDefaultsByBundle']) is not dict
                or not 1 <= len(value['baselinesByBundle']) <= MAX_ANCESTRY_DEPTH
                or not 1 <= len(value['authenticatedImageDefaultsByBundle']) <= MAX_ANCESTRY_DEPTH):
            reject()

        def read_only(method, request):
            if type(method) is not str or method not in _READS:
                reject()
            return witness_transport(method, request)

        def factory(binding):
            return OperationWitnessClientV3(binding, witness_public_key, read_only)

        history = None
        nodes = []
        used = set()
        baseline_bytes = None
        for node in value['nodes']:
            if type(node) is not dict or set(node) != _NODE_FIELDS:
                reject()
            request = RequestV2.from_json(canonical(node['request']).decode('ascii'))
            bundle = _bundle(node['bundle'], value['authenticatedImageDefaultsByBundle'][request.plan_hash])
            if bundle.digest != request.plan_hash:
                reject()
            if history is not None and any(getattr(request, key) != getattr(history._request, key) for key in _IDENTITY):
                reject()
            check_witness_capacity(bundle)
            used.add(bundle.digest)
            baseline_bytes = canonical(value['baselinesByBundle'][bundle.digest])
            _baseline(baseline_bytes, bundle)
            policy = GatePolicy(**node['gatePolicy'])
            if canonical(asdict(policy)) != canonical(node['gatePolicy']):
                reject()
            reviewed = None if node['reviewedParent'] is None else AuthenticatedHistorySnapshotV3(canonical(node['reviewedParent']))
            history = AuthenticatedHistoryV3(bundle, request, gate_policy=policy, gate_key=gate_key,
                consumption_receipt_hash=node['consumptionReceiptHash'], witness_client=factory(node['firstBinding']),
                witness_client_factory=factory, parent_history=history, reviewed_parent_snapshot=reviewed,
                ancestry_profile=ANCESTRY_PROFILE)
            nodes.append(history)
        if set(value['baselinesByBundle']) != used or set(value['authenticatedImageDefaultsByBundle']) != used:
            reject()
        snapshot = history.capture()
        _prefix(history, snapshot)
        _validate_nodes(nodes, snapshot)
        if (snapshot.canonical != canonical(value['snapshot'])
                or _context(history, snapshot, value['archiveDigest']) != pins
                or canonical(expected_context) != canonical(pins)):
            reject()
        return ReadonlyRestartContextV3(history, snapshot, baseline_bytes, expected_digest)
    except Exception:
        reject()
