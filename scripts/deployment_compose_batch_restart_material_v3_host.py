"""Reauthenticate a private root-deploy batch checkpoint at a closed prefix.

Trusted embeddings retain material and independent context pins separately.
Reopening performs signed witness reads and confers no execution authority.
"""
from dataclasses import asdict
import hashlib
import re

from deployment_compose_history_v3_host import AuthenticatedHistoryV3
from deployment_compose_coordinator_v3_host import check_witness_capacity
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
from deployment_compose_restart_material_v3_host import (
    MAX_MATERIAL, ReadonlyRestartContextV3, _bundle, _baseline, _context,
)
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2
from deployment_gateway import GatePolicy

_KIND = 'compose-batch-restart-material-v3'
_FIELDS = {'schemaVersion', 'kind', 'bundle', 'authenticatedImageDefaults', 'request',
           'gatePolicy', 'consumptionReceiptHash', 'firstBinding', 'baseline', 'snapshot', 'archiveDigest'}
_CONTEXT = {'sourceSha', 'hostId', 'daemonId', 'archiveDigest', 'historyDigest', 'baselineStateDigest'}
_READS = frozenset({'read', 'check', 'events_after', 'chain_status'})


def reject():
    raise ValueError('compose-batch-restart-material-v3-rejected') from None


def _root(history):
    if (type(history) is not AuthenticatedHistoryV3 or history._parent is not None
            or history._request.operation != 'deploy'
            or history._policy.operation_profile != 'compose-v3'
            or history._policy.witness_required is not True
            or history._request.policy_hash != history._policy.identity_hash()):
        reject()


def _prefix(history, snapshot):
    _root(history)
    value = decode(snapshot.canonical)
    status = value['chainStatus']
    count = len(value['knownPrefix'])
    bundle = history._bundle
    total = sum(operation['phase'] != 'readiness' for operation in bundle.to_dict()['operations'])
    scopes = value['scopes']
    tails = [dict(binding=scope['binding'], seq=scope['seq'], head=scope['head']) for scope in scopes]
    live = list(status['lineage']) + [dict(binding=status['activeBinding'], seq=status['activeSeq'], head=status['activeHead'])]
    if (type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['pending'] is not None or value['blocker'] is not None
            or not 0 < count < total or len(scopes) != count
            or status['activePhase'] != 'closed' or tails != live or value['closedTail'] != tails[-1]
            or any(type(scope['seq']) is not int or scope['seq'] != 6 for scope in scopes)
            or type(status['activeSeq']) is not int or status['activeSeq'] != 6
            or scopes[0]['binding'] != history._client.binding):
        reject()
    receipts = value['receiptMap']
    creates = bundle.creation_operations()
    created_services = {operation['service'] for operation in creates[:min(count, len(creates))]}
    if (set(receipts) != created_services or len(set(receipts.values())) != len(receipts)
            or any(not hex_value(cid) for cid in receipts.values())):
        reject()
    operations = bundle.resolve_operations(receipts) if len(receipts) == len(creates) else creates
    writes = [operation for operation in operations if operation['method'] != 'GET']
    if canonical(value['knownPrefix']) != canonical(writes[:count]):
        reject()
    return value


def capture_material(original_history, *, baseline_bytes, authenticated_image_defaults, archive_digest):
    try:
        _root(original_history)
        defaults = decode(canonical(authenticated_image_defaults))
        bundle = _bundle(original_history._bundle.to_dict(), defaults)
        baseline = _baseline(baseline_bytes, bundle)
        if not hex_value(archive_digest):
            reject()
        check_witness_capacity(bundle)
        snapshot = original_history.capture()
        value = _prefix(original_history, snapshot)
        material = dict(schemaVersion=1, kind=_KIND, bundle=bundle.to_dict(),
            authenticatedImageDefaults=defaults, request=asdict(original_history._request),
            gatePolicy=asdict(original_history._policy), consumptionReceiptHash=original_history._receipt,
            firstBinding=original_history._client.binding, baseline=baseline, snapshot=value, archiveDigest=archive_digest)
        raw = canonical(material)
        if not 0 < len(raw) <= MAX_MATERIAL or original_history.capture().canonical != snapshot.canonical:
            reject()
        return raw
    except Exception:
        reject()


def reopen_material(raw, *, expected_digest, expected_context, gate_key, witness_public_key, witness_transport):
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_MATERIAL
                or not hex_value(expected_digest) or hashlib.sha256(raw).hexdigest() != expected_digest
                or type(expected_context) is not dict or set(expected_context) != _CONTEXT
                or any(type(value) is not str or not value for value in expected_context.values())
                or re.fullmatch('[0-9a-f]{40}', expected_context['sourceSha']) is None
                or any(not hex_value(expected_context[key]) for key in ('archiveDigest', 'historyDigest', 'baselineStateDigest'))
                or not callable(witness_transport)):
            reject()
        pins = decode(canonical(expected_context))
        value = decode(raw)
        if (type(value) is not dict or set(value) != _FIELDS or value['kind'] != _KIND
                or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1):
            reject()
        bundle = _bundle(value['bundle'], value['authenticatedImageDefaults'])
        check_witness_capacity(bundle)
        request = RequestV2.from_json(canonical(value['request']).decode('ascii'))
        policy = GatePolicy(**value['gatePolicy'])
        if canonical(asdict(policy)) != canonical(value['gatePolicy']):
            reject()
        baseline_bytes = canonical(value['baseline'])
        _baseline(baseline_bytes, bundle)

        def read_only(method, request):
            if type(method) is not str or method not in _READS:
                reject()
            return witness_transport(method, request)

        def factory(binding):
            return OperationWitnessClientV3(binding, witness_public_key, read_only)

        history = AuthenticatedHistoryV3(bundle, request, gate_policy=policy, gate_key=gate_key,
            consumption_receipt_hash=value['consumptionReceiptHash'], witness_client=factory(value['firstBinding']),
            witness_client_factory=factory)
        _root(history)
        snapshot = history.capture()
        _prefix(history, snapshot)
        if (snapshot.canonical != canonical(value['snapshot'])
                or _context(history, snapshot, value['archiveDigest']) != pins):
            reject()
        return ReadonlyRestartContextV3(history, snapshot, baseline_bytes, expected_digest)
    except Exception:
        reject()
