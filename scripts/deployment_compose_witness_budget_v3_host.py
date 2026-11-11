"""Host byte admission for the existing v3 witness serialization.

The caller supplies freshly authenticated history. This computes capacity only;
no returned value grants authority or reserves independent witness storage.
"""
import base64
from copy import deepcopy
import hashlib
import json

from deployment_compose_operation_witness_v3 import MAX_SCOPES, MAX_EVENTS
from deployment_compose_witness_store import MAX_BYTES, ZERO, binding_value, canonical
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_compose_write_gateway_v3_host import MAX_RESPONSE
from deployment_gateway import GatePolicy

UINT64_MAX = 2**64 - 1
_HASH = 'f' * 64


def _reject():
    raise ValueError('compose-witness-byte-capacity-v3-rejected') from None


def _sealed_size(scopes):
    return len(canonical(dict(state=dict(schemaVersion=3, scopes=scopes), hmac=_HASH)))


def _seal(policy, domain, payload):
    return dict(version=1, domain='dev-workflow.writer-gate.' + domain,
                policy=policy._binding(), payload=payload, mac=_HASH)


def _scope_upper_bound(binding, policy, descriptor, request_hash, receipt_hash, parent):
    """Model all six actual Gate/adapter/store record layers at their size bound."""
    attempt = _HASH
    body = base64.b64encode(b'\xff' * MAX_RESPONSE).decode('ascii')
    data = [dict(request_hash=request_hash, receipt_hash=receipt_hash,
                 operations=descriptor['operations'], source_binding_schema=1,
                 source_context_digest=descriptor['source']),
            dict(ref=attempt, operation=descriptor['operations'][0]), attempt,
            dict(ref=attempt, definitive=True, status=599, bodyBase64=body,
                 response_binding_schema=1, response_hash=_HASH), None,
            _seal(policy, 'proof', dict(generation=binding['generation'], head=_HASH))]
    records=[]
    for index, (kind, value) in enumerate(zip(('open','prepare','admit','finish','close','proof'), data)):
        event=dict(generation=binding['generation'], directory=[UINT64_MAX,UINT64_MAX],
                   previous=ZERO if index == 0 else _HASH, kind=kind, data=value)
        raw=canonical(_seal(policy, 'event', event))
        witness=dict(binding=binding, sequence=index+1, previousHead=ZERO if index == 0 else _HASH,
            kind=('open','prepared','admitted','response','completed','closed')[index],
            data=GateOperationWitnessAdapterV3._data(event, attempt),
            materialDigest=hashlib.sha256(raw).hexdigest())
        records.append(dict(event=witness, canonicalEvent=canonical(witness).decode('ascii'),
            head=_HASH, bootNonce=_HASH, rpcNonce=_HASH, hasExternalMaterial=True,
            externalMaterialBase64=base64.b64encode(raw).decode('ascii')))
    return dict(binding=deepcopy(binding), events=records, parent=deepcopy(parent))


def _prior_scopes(snapshot):
    from deployment_compose_history_v3_host import AuthenticatedHistorySnapshotV3
    if type(snapshot) is not AuthenticatedHistorySnapshotV3:
        _reject()
    value=json.loads(snapshot.canonical)
    if value.get('schemaVersion') != 1:
        _reject()
    scopes=[]
    parent=None
    for scope in value['scopes']:
        binding=binding_value(scope['binding'])
        records=deepcopy(scope['records'])
        if scope['seq'] != len(records) or scope['head'] != (records[-1]['head'] if records else ZERO):
            _reject()
        for record in records:
            envelope=json.loads(base64.b64decode(record['externalMaterialBase64'], validate=True))
            directory=envelope['payload']['directory']
            if (type(directory) is not list or len(directory) != 2
                    or any(type(n) is not int or not 0 <= n <= UINT64_MAX for n in directory)):
                _reject()
        scopes.append(dict(binding=binding, events=records, parent=deepcopy(parent)))
        parent=dict(binding=binding,seq=scope['seq'],head=scope['head'])
    status=value['chainStatus']
    if (not scopes or len(status['lineage']) + 1 != len(scopes)
            or status['activeBinding'] != scopes[-1]['binding']):
        _reject()
    return value,scopes


def check_witness_byte_capacity(bundle, request, gate_policy, receipt_hash, binding, prior_snapshot=None):
    """Bound sealed state after all remaining writes, before any writer opens.

    Prior schema-1 history may be the same request's complete/active prefix or a
    reviewed original deployment before rollback. Prior bytes are retained in
    full, including historical responses up to the old 64KiB verification limit.
    Unsupported composed history is rejected instead of silently undercounted.
    """
    from deployment_compose_bundle_v3 import ExecutionBundleV3
    from deployment_contract_v2 import RequestV2
    from deployment_compose_coordinator_v3_host import Profile3StepExecutor
    try:
        if (type(bundle) is not ExecutionBundleV3 or type(request) is not RequestV2
                or type(gate_policy) is not GatePolicy or gate_policy.operation_profile != 'compose-v3'
                or MAX_RESPONSE != 4096 or bundle.to_dict()['resolverRules']['maxResponseBytes'] != MAX_RESPONSE):
            _reject()
        binding=binding_value(binding)
        if binding['policyHash'] != gate_policy.identity_hash():
            _reject()
        if type(receipt_hash) is not str or len(receipt_hash) != 64 or any(c not in '0123456789abcdef' for c in receipt_hash):
            _reject()
        scopes=[]; start=0; active=False
        if prior_snapshot is not None:
            prior,scopes=_prior_scopes(prior_snapshot)
            if any(s['binding']['epoch'] != binding['epoch'] or s['binding']['policyHash'] != binding['policyHash'] for s in scopes):
                _reject()
            if (prior['bundleDigest'] == bundle.digest and request.operation == 'recovery'
                    and request.history_hash == prior_snapshot.digest):
                start=len(prior['knownPrefix'])
                total=sum(op['phase'] != 'readiness' for op in bundle.to_dict()['operations'])
                if (not 0 < start < total or len(scopes) != start
                        or prior['blocker'] is not None or prior['pending'] is not None
                        or prior['chainStatus']['activePhase'] != 'closed'
                        or any(len(s['events']) != 6 for s in scopes)):
                    _reject()
            elif prior['bundleDigest'] == bundle.digest and prior['originalRequestHash'] == request.digest():
                start=len(scopes)
                if len(scopes[-1]['events']) < 6:
                    active=True;start-=1
            elif any(len(s['events']) != 6 for s in scopes):
                _reject()
        # Full IDs all have the same encoded length. Pick disjoint hypothetical
        # receipts: hashes and nonces vary in value, never in serialized length.
        forbidden={s['baselineContainerId'] for s in bundle.to_dict()['services']}
        forbidden|={p['containerId'] for p in bundle.to_dict()['protectedContainers']}
        receipts={};candidate=0
        for service in bundle.to_dict()['services']:
            while format(candidate,'064x') in forbidden:
                candidate+=1
            cid=format(candidate,'064x');candidate+=1;forbidden.add(cid)
            receipts[service['name']]=cid
        writes=[op for op in bundle.resolve_operations(receipts) if op['method'] != 'GET']
        if start > len(writes):
            _reject()
        current_bytes=_sealed_size(scopes if scopes else [dict(binding=binding,events=[],parent=None)])
        for index in range(start,len(writes)):
            desc=Profile3StepExecutor.scope_descriptor(bundle,request,receipt_hash,writes[index],index,receipts)
            child=dict(binding,generation=desc['generation'],scopeHash=desc['scopeHash'])
            previous=scopes[-1] if scopes else None
            parent=None if previous is None else dict(binding=previous['binding'],
                seq=len(previous['events']),head=previous['events'][-1]['head'] if previous['events'] else ZERO)
            model=_scope_upper_bound(child,gate_policy,desc,request.digest(),receipt_hash,parent)
            if active and index == start:
                actual=scopes.pop()
                model['binding']=actual['binding']
                model['parent']=actual['parent']
                # Existing records are exact, including old larger responses.
                model['events'][:len(actual['events'])]=actual['events']
            scopes.append(model)
        final_bytes=_sealed_size(scopes)
        events=sum(len(s['events']) for s in scopes)
        if len(scopes)>MAX_SCOPES or events>MAX_EVENTS or max(current_bytes,final_bytes)>MAX_BYTES:
            _reject()
        return dict(currentBytes=current_bytes,requiredBytes=max(current_bytes,final_bytes),
                    maxBytes=MAX_BYTES,scopeCount=len(scopes),eventCount=events,maxResponseBytes=MAX_RESPONSE)
    except Exception:
        _reject()
