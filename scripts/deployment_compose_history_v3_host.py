"""Read-only authenticated recovery input. This module issues no execution authority.

The explicit bounded-recovery-v1 profile uses cumulative schema-3 scopes and
per-generation segments. Default construction retains schema-1/2 contracts.
"""
import base64
from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json

from deployment_compose_bundle_v3 import ExecutionBundleV3, PROFILE
from deployment_compose_coordinator_v3_host import Profile3StepExecutor, canonical, digest, immutable
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, ZERO, hex_value
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_contract_v2 import RequestV2
from deployment_gateway import FileWriterGate, GatePolicy


def reject():
    raise ValueError('authenticated-history-v3-rejected')


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            reject()
        result[key] = value
    return result


@dataclass(frozen=True)
class AuthenticatedHistorySnapshotV3:
    """Canonical private evidence; immutable and never a RuntimePermit."""
    canonical: bytes

    @property
    def digest(self):
        return hashlib.sha256(self.canonical).hexdigest()

    @property
    def snapshot(self):
        return immutable(json.loads(self.canonical))

    def public_summary(self):
        value = json.loads(self.canonical)
        return dict(digest=self.digest, completedWriteCount=len(value['knownPrefix']),
                    blocker=value['blocker'], authorityGranted=False,
                    productionReady=False, runtimePermit=False)


ANCESTRY_PROFILE = 'bounded-recovery-v1'
MAX_ANCESTRY_DEPTH = 8


class AuthenticatedHistoryV3:
    def __init__(self, bundle, original_request, *, gate_policy, gate_key,
                 consumption_receipt_hash, witness_client, witness_client_factory,
                 parent_history=None, reviewed_parent_snapshot=None, ancestry_profile=None):
        if (type(bundle) is not ExecutionBundleV3 or type(original_request) is not RequestV2
                or type(gate_policy) is not GatePolicy or gate_policy.operation_profile != 'compose-v3'
                or not gate_policy.witness_required or type(gate_key) is not bytes or len(gate_key) < 32
                or not hex_value(consumption_receipt_hash)
                or type(witness_client) is not OperationWitnessClientV3
                or not callable(witness_client_factory)
                or witness_client.key_hash != gate_policy.witness_key_sha256):
            reject()
        if not (ancestry_profile is None or type(ancestry_profile) is str and ancestry_profile == ANCESTRY_PROFILE):
            reject()
        self._ancestry_profile = ancestry_profile
        request = original_request; value = bundle.to_dict(); identity = value['identity']
        if (request.plan_hash != bundle.digest or request.profile_id != PROFILE
                or request.profile_version != '3' or request.production is not False
                or request.max_uses != 1 or request.host_id != identity['hostId']
                or request.daemon_id != identity['daemonId'] or request.target.runtime != 'compose'
                or request.target.namespace != identity['project']
                or request.components != tuple(sorted(s['name'] for s in value['services']))
                or identity['sourceIdentity'] != canonical(asdict(request.source)).decode('ascii')):
            reject()
        if (parent_history is None) != (reviewed_parent_snapshot is None):
            reject()
        if parent_history is not None:
            if (type(parent_history) is not AuthenticatedHistoryV3
                    or type(reviewed_parent_snapshot) is not AuthenticatedHistorySnapshotV3
                    or request.operation not in ('rollback', 'recovery')
                    or request.history_hash != reviewed_parent_snapshot.digest
                    or (ancestry_profile is None and (parent_history._request.operation != 'deploy'
                                                     or parent_history._parent is not None))
                    or (ancestry_profile is not None and parent_history._ancestry_profile != ancestry_profile)):
                reject()
            if ancestry_profile and request.operation == 'rollback' and (parent_history._parent is not None or parent_history._request.operation != 'deploy'):
                reject()
            if request.operation == 'recovery':
                old = parent_history._request
                if (bundle.canonical_bytes != parent_history._bundle.canonical_bytes
                        or any(getattr(request, field) != getattr(old, field) for field in (
                            'source', 'target', 'host_id', 'daemon_id', 'environment', 'components',
                            'protected_components', 'policy_hash', 'before_hash', 'after_hash',
                            'artifact_digest'))):
                    reject()
                reviewed = json.loads(reviewed_parent_snapshot.canonical)
                total = sum(op['phase'] != 'readiness' for op in value['operations'])
                if not 0 < len(reviewed['knownPrefix']) < total:
                    reject()
        self._parent, self._reviewed_parent = parent_history, reviewed_parent_snapshot
        self._bundle, self._request = bundle, request
        self._policy, self._key, self._receipt = gate_policy, gate_key, consumption_receipt_hash
        self._client, self._factory = witness_client, witness_client_factory
        self._validate_ancestry()

    def _validate_ancestry(self):
        if self._ancestry_profile is None:
            if self._parent is not None and self._parent._ancestry_profile is not None:
                reject()
            return
        seen_objects, seen_requests, seen_bindings = set(), set(), set()
        current = self
        while current is not None:
            if (type(current) is not AuthenticatedHistoryV3
                    or type(getattr(current, '_ancestry_profile', None)) is not str
                    or current._ancestry_profile != ANCESTRY_PROFILE
                    or id(current) in seen_objects or len(seen_objects) >= MAX_ANCESTRY_DEPTH):
                reject()
            request_hash = current._request.digest()
            binding = canonical(current._client.binding)
            if request_hash in seen_requests or binding in seen_bindings:
                reject()
            seen_objects.add(id(current))
            seen_requests.add(request_hash)
            seen_bindings.add(binding)
            parent = current._parent
            if parent is None:
                if current._request.operation != 'deploy' or current._reviewed_parent is not None:
                    reject()
            elif (type(parent) is not AuthenticatedHistoryV3
                  or current._client.key_hash != parent._client.key_hash
                  or current._policy.identity_hash() != parent._policy.identity_hash()
                  or current._client.binding['epoch'] != parent._client.binding['epoch']
                  or current._request.operation not in ('rollback', 'recovery')
                  or type(current._reviewed_parent) is not AuthenticatedHistorySnapshotV3
                  or current._request.history_hash != current._reviewed_parent.digest
                  or (current._request.operation == 'rollback' and (parent._parent is not None or parent._request.operation != 'deploy'))):
                reject()
            current = parent

    def _ancestry_fingerprint(self):
        """Snapshot only in-memory inputs across untrusted transport callbacks."""
        if type(self._ancestry_profile) is not str or self._ancestry_profile != ANCESTRY_PROFILE:
            reject()
        self._validate_ancestry()
        nodes = []
        current = self
        while current is not None:
            reviewed = current._reviewed_parent
            nodes.append((id(current), id(current._parent), id(reviewed),
                None if reviewed is None else hashlib.sha256(reviewed.canonical).digest(),
                id(current._request), current._request.canonical_json(), current._request.digest(),
                id(current._bundle), current._bundle.canonical_bytes, current._bundle.digest,
                id(current._policy), canonical(asdict(current._policy)),
                hashlib.sha256(current._key).digest(), current._receipt,
                id(current._client), canonical(current._client.binding), current._client.key_hash,
                id(current._client._transport), id(current._factory), current._ancestry_profile))
            current = current._parent
        return tuple(nodes)

    def _unseal(self, envelope, domain):
        if (type(envelope) is not dict or set(envelope) != {'version','domain','policy','payload','mac'}
                or type(envelope['version']) is not int or envelope['version'] != 1
                or envelope['domain'] != 'dev-workflow.writer-gate.' + domain
                or canonical(envelope['policy']) != canonical(self._policy._binding())
                or not hex_value(envelope['mac'])):
            reject()
        unsigned = {k:v for k,v in envelope.items() if k != 'mac'}
        expected = hmac.new(self._key, canonical(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, envelope['mac']):
            reject()
        return envelope['payload']

    def capture(self):
        try:
            return self._capture()
        except Exception:
            reject()

    def verify_prefix(self, reviewed_snapshot, live_chain_status, *, require_complete=True):
        """Reauthenticate a reviewed closed prefix within the selected history profile."""
        try:
            if (type(reviewed_snapshot) is not AuthenticatedHistorySnapshotV3
                    or (self._ancestry_profile is None and self._parent is not None)
                    or type(require_complete) is not bool):
                reject()
            reviewed = json.loads(reviewed_snapshot.canonical)
            expected = [dict(binding=s['binding'], seq=s['seq'], head=s['head']) for s in reviewed['scopes']]
            live = deepcopy(live_chain_status['lineage']) + [dict(
                binding=live_chain_status['activeBinding'], seq=live_chain_status['activeSeq'],
                head=live_chain_status['activeHead'])]
            if (not expected or live[:len(expected)] != expected
                    or type(reviewed['schemaVersion']) is not int
                    or reviewed['schemaVersion'] != (3 if self._ancestry_profile else 1) or reviewed['blocker'] is not None
                    or reviewed['pending'] is not None or reviewed['closedTail'] != expected[-1]
                    or (self._ancestry_profile is None and self._request.operation != 'deploy')
                    or reviewed['bundleDigest'] != self._bundle.digest
                    or reviewed['originalRequestHash'] != self._request.digest()):
                reject()
            status = deepcopy(live_chain_status)
            status.update(lineage=expected[:-1], activeBinding=expected[-1]['binding'],
                          activeSeq=expected[-1]['seq'], activeHead=expected[-1]['head'], activePhase='closed')
            verified = self._capture(status=status, recheck=False)
            total = sum(op['phase'] != 'readiness' for op in self._bundle.to_dict()['operations'])
            count = len(reviewed['knownPrefix'])
            if (verified.canonical != reviewed_snapshot.canonical
                    or (self._ancestry_profile is None and len(expected) != count)
                    or (count != total if require_complete else not 0 < count < total)):
                reject()
            return verified
        except Exception:
            reject()

    def _capture(self, *, status=None, recheck=True):
        self._validate_ancestry()
        ancestry_profile = self._ancestry_profile
        ancestry_fingerprint = self._ancestry_fingerprint() if self._ancestry_profile else None
        status = self._client.chain_status() if status is None else status
        if status['policyHash'] != self._policy.identity_hash():
            reject()
        tails = deepcopy(status['lineage']) + [dict(binding=status['activeBinding'],
                   seq=status['activeSeq'], head=status['activeHead'])]
        from deployment_compose_operation_witness_v3 import MAX_SCOPES, MAX_EVENTS
        if self._ancestry_profile and (len(tails) > MAX_SCOPES or sum(tail['seq'] for tail in tails) > MAX_EVENTS):
            reject()
        parent = None
        receipts, completed, scopes, segments = {}, [], [], []
        start_index = 0
        if self._parent is not None:
            recovery = self._request.operation == 'recovery'
            verified = self._parent.verify_prefix(self._reviewed_parent, status,
                                                   require_complete=not recovery)
            reviewed = json.loads(verified.canonical)
            count = len(reviewed['scopes'])
            if self._ancestry_profile:
                scopes = deepcopy(reviewed['scopes'])
                segments = deepcopy(reviewed['segments'])
                if reviewed['segments'][-1]['scopeCount'] == 0 or any(scope['seq'] != 6 for scope in scopes):
                    reject()
            if recovery:
                receipts = deepcopy(reviewed['receiptMap'])
                completed = deepcopy(reviewed['knownPrefix'])
                start_index = len(completed)
            if len(tails) <= count:
                reject()
            parent = dict(historyDigest=verified.digest,
                originalRequestHash=reviewed['originalRequestHash'],
                bundleDigest=reviewed['bundleDigest'], tail=reviewed['closedTail'],
                scopeCount=count, startWriteIndex=start_index)
            tails = tails[count:]
        blocker = None; pending = None; closed_tail = None
        forbidden = {s['baselineContainerId'] for s in self._bundle.to_dict()['services']}
        forbidden |= {s['containerId'] for s in self._bundle.to_dict()['protectedContainers']}
        scope_start = len(scopes)
        for local_index, tail in enumerate(tails):
            index = start_index + local_index
            if blocker is not None:
                reject()  # A successor cannot bypass a failed or unresolved predecessor.
            binding = tail['binding']
            client = self._factory(deepcopy(binding))
            if (type(client) is not OperationWitnessClientV3 or client.binding != binding
                    or client.key_hash != self._client.key_hash
                    or binding['epoch'] != status['epoch']
                    or binding['policyHash'] != status['policyHash']):
                reject()
            ops = self._bundle.creation_operations()
            if len(receipts) == len(self._bundle.to_dict()['services']):
                ops = self._bundle.resolve_operations(receipts)
            writes = [op for op in ops if op['method'] != 'GET']
            if index >= len(writes):
                reject()
            operation = writes[index]
            desc = Profile3StepExecutor.scope_descriptor(self._bundle, self._request,
                          self._receipt, operation, index, receipts)
            if binding['generation'] != desc['generation'] or binding['scopeHash'] != desc['scopeHash']:
                reject()
            records = client.events_after(seq=0, head=ZERO)
            if len(records) != tail['seq'] or (records[-1]['head'] if records else ZERO) != tail['head']:
                reject()
            # The signed client verifies event-chain heads, nonce, binding and exact material digest.
            previous = ZERO; directory = None; attempt = None; finish = None
            for ordinal, record in enumerate(records):
                raw = base64.b64decode(record['externalMaterialBase64'], validate=True)
                envelope = json.loads(raw, object_pairs_hook=pairs)
                if canonical(envelope) != raw:
                    reject()
                event = self._unseal(envelope, 'event')
                if (set(event) != {'generation','directory','previous','kind','data'}
                        or event['generation'] != binding['generation'] or event['previous'] != previous
                        or ordinal >= 6 or event['kind'] != ('open','prepare','admit','finish','close','proof')[ordinal]):
                    reject()
                if ordinal == 0:
                    directory = event['directory']
                    if (type(directory) is not list or len(directory) != 2
                            or any(type(v) is not int or v < 0 for v in directory)):
                        reject()
                if event['directory'] != directory:
                    reject()
                data = event['data']
                if ordinal == 0:
                    expected = dict(request_hash=self._request.digest(), receipt_hash=self._receipt,
                        operations=[list(o) for o in desc['operations']], source_binding_schema=1,
                        source_context_digest=desc['source'])
                    if canonical(data) != canonical(expected):
                        reject()
                elif ordinal == 1:
                    if (type(data) is not dict or set(data) != {'ref','operation'}
                            or not hex_value(data['ref']) or data['operation'] != list(desc['operations'][0])):
                        reject()
                    attempt = data['ref']
                elif ordinal == 2:
                    if data != attempt: reject()
                elif ordinal == 3:
                    FileWriterGate._response_data(data)
                    if data['ref'] != attempt: reject()
                    finish = data
                elif ordinal == 4:
                    if data is not None or not finish['definitive']: reject()
                else:
                    if self._unseal(data, 'proof') != dict(generation=binding['generation'], head=previous):
                        reject()
                if record['event']['data'] != GateOperationWitnessAdapterV3._data(event, attempt):
                    reject()
                previous = digest(event)
            scopes.append(dict(binding=binding, seq=tail['seq'], head=tail['head'], records=records))
            if len(records) != 6:
                if local_index != len(tails)-1: reject()
                blocker = 'unknown-response' if finish and not finish['definitive'] else 'active-pending'
                pending = dict(type=blocker, operation=operation,
                               sourceArchiveRef=self._bundle.to_dict()['archiveReference'])
                continue
            closed_tail = deepcopy(tail)
            if not 200 <= finish['status'] < 300:
                blocker = 'known-http-failure'
            elif finish['status'] != operation['expectedStatus']:
                blocker = 'unexpected-http-status'
            elif operation['phase'] == 'create':
                try:
                    response = json.loads(base64.b64decode(finish['bodyBase64']), object_pairs_hook=pairs)
                    cid = response.get('Id') if type(response) is dict else None
                    if (finish['status'] != 201 or not hex_value(cid)
                            or cid in forbidden or cid in receipts.values()):
                        raise ValueError
                except Exception:
                    blocker = 'unusable-receipt'
                else:
                    receipts[operation['service']] = cid
            if blocker is None:
                completed.append(deepcopy(operation))
            else:
                pending = dict(type=blocker, operation=operation,
                               sourceArchiveRef=self._bundle.to_dict()['archiveReference'])
        if recheck and self._client.chain_status() != status:
            reject()
        result = dict(schemaVersion=1,
            bundleDigest=self._bundle.digest, originalRequestHash=self._request.digest(),
            consumptionReceiptHash=self._receipt, chainStatus=status, scopes=scopes,
            knownPrefix=completed, receiptMap=receipts, closedTail=closed_tail,
            pending=pending, blocker=blocker, sourceArchiveRef=self._bundle.to_dict()['archiveReference'],
            authorityGranted=False, productionReady=False, runtimePermit=False)
        if parent is not None:
            result.update(schemaVersion=2, parent=parent)
        if self._ancestry_profile:
            segments.append(dict(requestHash=self._request.digest(), bundleDigest=self._bundle.digest,
                receiptHash=self._receipt, parentHistoryDigest=None if self._reviewed_parent is None else self._reviewed_parent.digest,
                scopeStart=scope_start, scopeCount=len(tails), startWriteIndex=start_index))
            result.update(schemaVersion=3, ancestryProfile=ANCESTRY_PROFILE, segments=segments)
        if type(self._ancestry_profile) is not type(ancestry_profile) or self._ancestry_profile != ancestry_profile:
            reject()
        if ancestry_fingerprint is not None and self._ancestry_fingerprint() != ancestry_fingerprint:
            reject()
        return AuthenticatedHistorySnapshotV3(canonical(result))
