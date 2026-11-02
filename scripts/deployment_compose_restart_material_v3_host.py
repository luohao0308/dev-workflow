"""Private restart inputs for reauthenticating one closed create, never authority.

The trusted embedding privately retains these bytes and independently provisions
its digest/context pins, gate key and authenticated read-only witness transport.
Neither a self-provided digest nor fresh RPC nonces establish monotonic storage,
current Engine state, writer termination, or permission to resume execution.
"""
from dataclasses import asdict, dataclass, field
import hashlib
import re

from deployment_compose_bundle_v3 import ExecutionBundleV3, FIELDS
from deployment_compose_history_v3_host import AuthenticatedHistoryV3, AuthenticatedHistorySnapshotV3
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, hex_value
from deployment_compose_recovery_phase_capsule_v3_host import MAX_BASELINE, decode, inflate
from deployment_compose_witness_store import canonical
from deployment_contract_v2 import RequestV2
from deployment_gateway import GatePolicy

MAX_MATERIAL = 16 * 1024 * 1024
_KIND = 'compose-mac-restart-material-v3'
_FIELDS = {'schemaVersion', 'kind', 'bundle', 'authenticatedImageDefaults', 'request',
           'gatePolicy', 'consumptionReceiptHash', 'firstBinding', 'baseline',
           'snapshot', 'archiveDigest'}
_CONTEXT = {'sourceSha', 'hostId', 'daemonId', 'archiveDigest', 'historyDigest', 'baselineStateDigest'}
_READS = frozenset({'read', 'check', 'events_after', 'chain_status'})


def reject():
    raise ValueError('compose-restart-material-v3-rejected') from None


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ReadonlyRestartContextV3:
    history: AuthenticatedHistoryV3 = field(repr=False)
    snapshot: AuthenticatedHistorySnapshotV3 = field(repr=False)
    baseline_bytes: bytes = field(repr=False)
    material_digest: str
    historyAuthenticated: bool = field(default=True, init=False)
    phaseFreshnessVerified: bool = field(default=False, init=False)
    linuxQuiescenceVerified: bool = field(default=False, init=False)
    authorityGranted: bool = field(default=False, init=False)
    executionAvailable: bool = field(default=False, init=False)
    runtimePermit: bool = field(default=False, init=False)
    recoveryAuthorized: bool = field(default=False, init=False)
    productionReady: bool = field(default=False, init=False)

    def public_summary(self):
        return dict(digest=self.material_digest, historyDigest=self.snapshot.digest,
                    completedWriteCount=1, historyAuthenticated=True,
                    phaseFreshnessVerified=False, linuxQuiescenceVerified=False,
                    authorityGranted=False, executionAvailable=False, runtimePermit=False,
                    recoveryAuthorized=False, productionReady=False)


def _bundle(value, defaults):
    if type(value) is not dict or not FIELDS <= set(value):
        reject()
    result = ExecutionBundleV3({key: value[key] for key in FIELDS},
                               authenticated_image_defaults=defaults)
    if result.canonical_bytes != canonical(value):
        reject()
    return result


def _baseline(raw, bundle):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BASELINE:
        reject()
    rows = decode(raw)
    inflate(rows)
    if _digest(raw) != bundle.to_dict()['baselineStateDigest']:
        reject()
    return rows


def _root(history):
    if (type(history) is not AuthenticatedHistoryV3 or history._parent is not None
            or history._request.operation != 'deploy'
            or len(history._bundle.to_dict()['services']) != 1
            or history._policy.operation_profile != 'compose-v3'
            or history._policy.witness_required is not True
            or history._request.policy_hash != history._policy.identity_hash()):
        reject()


def _prefix(history, snapshot):
    _root(history)
    value = decode(snapshot.canonical)
    status = value['chainStatus']
    first = history._bundle.creation_operations()[0]
    binding = history._client.binding
    tail = dict(binding=status['activeBinding'], seq=6, head=status['activeHead'])
    if (type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['pending'] is not None or value['blocker'] is not None
            or status['lineage'] != [] or status['activePhase'] != 'closed'
            or type(status['activeSeq']) is not int or status['activeSeq'] != 6
            or len(value['scopes']) != 1 or type(value['scopes'][0]['seq']) is not int
            or value['scopes'][0]['seq'] != 6 or value['scopes'][0]['binding'] != binding
            or status['activeBinding'] != binding or value['closedTail'] != tail
            or first['phase'] != 'create' or canonical(value['knownPrefix']) != canonical([first])
            or set(value['receiptMap']) != {first['service']}
            or not hex_value(value['receiptMap'][first['service']])):
        reject()
    return value


def _context(history, snapshot, archive_digest):
    request = history._request
    if not hex_value(archive_digest):
        reject()
    return dict(sourceSha=request.source.source_sha, hostId=request.host_id,
                daemonId=request.daemon_id, archiveDigest=archive_digest,
                historyDigest=snapshot.digest,
                baselineStateDigest=history._bundle.to_dict()['baselineStateDigest'])


def capture_material(original_history, *, baseline_bytes, authenticated_image_defaults, archive_digest):
    """Capture verified private inputs; the caller separately retains trusted pins."""
    try:
        _root(original_history)
        defaults = decode(canonical(authenticated_image_defaults))
        bundle = _bundle(original_history._bundle.to_dict(), defaults)
        baseline = _baseline(baseline_bytes, bundle)
        if not hex_value(archive_digest):
            reject()
        snapshot = original_history.capture()
        value = _prefix(original_history, snapshot)
        material = dict(schemaVersion=1, kind=_KIND, bundle=bundle.to_dict(),
                        authenticatedImageDefaults=defaults,
                        request=asdict(original_history._request),
                        gatePolicy=asdict(original_history._policy),
                        consumptionReceiptHash=original_history._receipt,
                        firstBinding=original_history._client.binding, baseline=baseline,
                        snapshot=value, archiveDigest=archive_digest)
        raw = canonical(material)
        if not 0 < len(raw) <= MAX_MATERIAL:
            reject()
        # Refuse an advance during serialization or independent baseline work.
        if original_history.capture().canonical != snapshot.canonical:
            reject()
        return raw
    except Exception:
        reject()


def reopen_material(raw, *, expected_digest, expected_context, gate_key,
                    witness_public_key, witness_transport):
    """Reauthenticate persisted history with new signed reads, without admission.

    Supplied keys/transport and pins are trusted embedding inputs, not fields
    extracted from this material. The returned history supports existing static
    recovery checks; it establishes no freshness, fencing or execution authority.
    """
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_MATERIAL
                or not hex_value(expected_digest) or _digest(raw) != expected_digest
                or type(expected_context) is not dict or set(expected_context) != _CONTEXT
                or any(type(v) is not str or not v for v in expected_context.values())
                or re.fullmatch('[0-9a-f]{40}', expected_context['sourceSha']) is None
                or any(not hex_value(expected_context[k]) for k in
                       ('archiveDigest', 'historyDigest', 'baselineStateDigest'))
                or not callable(witness_transport)):
            reject()
        context_pin = decode(canonical(expected_context))
        value = decode(raw)
        if (type(value) is not dict or set(value) != _FIELDS
                or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                or value['kind'] != _KIND):
            reject()
        bundle = _bundle(value['bundle'], value['authenticatedImageDefaults'])
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
            consumption_receipt_hash=value['consumptionReceiptHash'],
            witness_client=factory(value['firstBinding']), witness_client_factory=factory)
        _root(history)
        snapshot = history.capture()
        _prefix(history, snapshot)
        if (snapshot.canonical != canonical(value['snapshot'])
                or _context(history, snapshot, value['archiveDigest']) != context_pin):
            reject()
        return ReadonlyRestartContextV3(history, snapshot, baseline_bytes, expected_digest)
    except Exception:
        reject()
