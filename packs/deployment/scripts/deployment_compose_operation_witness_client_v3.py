"""Signed, fresh V3 witness evidence; never an operation permit.

Private signing keys and witness storage stay outside subject Linux. The pure
host dispatch helper is NOT an authenticated server: its host embedding must
first authenticate and authorize the caller before dispatching or signing.
"""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from deployment_gate_witness import key_material

NAMESPACE = 'dev-workflow-compose-operation-witness-v3'
PRINCIPAL = 'compose-operation-witness-v3'
HEAD_DOMAIN = b'dev-workflow:compose-operation-event:v3\0'
REQUEST_DOMAIN = b'dev-workflow:compose-operation-request:v3\0'
ZERO = '0' * 64
HEX = re.compile('[0-9a-f]{64}\\Z')
MAX_WIRE_BYTES = 4 * 1024 * 1024
METHOD_FIELDS = {
    'read': set(), 'chain_status': set(), 'check': {'expectedSeq', 'expectedHead'},
    'append_event': {'expectedSeq', 'expectedHead', 'event', 'externalMaterialBase64'},
    'events_after': {'seq', 'head'},
    'transition_successor': {'expectedSeq', 'expectedHead', 'childBinding'},
}
KINDS = ['open', 'prepared', 'admitted', 'response', 'completed', 'closed']


def fail():
    raise ValueError('operation-witness-v3-rejected')


def hex_value(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def binding_value(value):
    if type(value) is not dict or set(value) != {'scopeHash', 'epoch', 'generation', 'policyHash'} or not all(hex_value(v) for v in value.values()):
        fail()
    return deepcopy(value)


def encode(value):
    def validate(item):
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is list:
            for v in item:
                validate(v)
            return
        if type(item) is dict and all(type(k) is str for k in item):
            for v in item.values():
                validate(v)
            return
        fail()
    validate(value)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    if len(raw) > MAX_WIRE_BYTES:
        fail()
    return raw


def cursor(seq, head):
    if type(seq) is not int or not 0 <= seq <= 6 or not hex_value(head) or (seq == 0) != (head == ZERO):
        fail()


def decode_material(encoded):
    if encoded is None:
        return None
    if type(encoded) is not str or len(encoded) > 349528:
        fail()
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > 262144 or base64.b64encode(raw).decode('ascii') != encoded:
        fail()
    return raw


def validate_event(event, binding, seq, head, external):
    fields = {'binding', 'sequence', 'previousHead', 'kind', 'data'}
    if external is not None:
        fields.add('materialDigest')
    if (type(event) is not dict or set(event) != fields or binding_value(event['binding']) != binding
            or type(event['sequence']) is not int or event['sequence'] != seq + 1
            or event['previousHead'] != head or seq >= 6 or event['kind'] != KINDS[seq]
            or type(event['data']) is not dict):
        fail()
    if external is not None and event['materialDigest'] != hashlib.sha256(external).hexdigest():
        fail()
    data = event['data']
    if seq in (0, 5):
        if data != {}:
            fail()
    elif seq in (1, 2, 4):
        if set(data) != {'attemptRef'} or not hex_value(data['attemptRef']):
            fail()
    else:
        if (set(data) != {'attemptRef', 'definitive', 'status', 'bodyBase64'}
                or not hex_value(data['attemptRef']) or type(data['definitive']) is not bool
                or type(data['status']) is not int
                or not (100 <= data['status'] <= 599 or (not data['definitive'] and data['status'] == 0))
                or type(data['bodyBase64']) is not str or len(data['bodyBase64']) > 87384):
            fail()
        body = base64.b64decode(data['bodyBase64'], validate=True)
        if len(body) > 65536 or base64.b64encode(body).decode('ascii') != data['bodyBase64']:
            fail()
    material = encode(event)
    if len(material) > 98304:
        fail()
    return material.decode('ascii'), hashlib.sha256(HEAD_DOMAIN + head.encode('ascii') + material).hexdigest()


def validate_request(method, request):
    if method not in METHOD_FIELDS or type(request) is not dict or set(request) != METHOD_FIELDS[method] | {'binding', 'bootNonce', 'rpcNonce'}:
        fail()
    binding = binding_value(request['binding'])
    if not all(hex_value(request[k]) for k in ('bootNonce', 'rpcNonce')):
        fail()
    encode(request)
    if method in ('check', 'append_event', 'transition_successor'):
        cursor(request['expectedSeq'], request['expectedHead'])
    if method == 'events_after':
        cursor(request['seq'], request['head'])
    if method == 'append_event':
        validate_event(request['event'], binding, request['expectedSeq'], request['expectedHead'], decode_material(request['externalMaterialBase64']))
    if method == 'transition_successor':
        child = binding_value(request['childBinding'])
        if (request['expectedSeq'] != 6 or any(child[k] != binding[k] for k in ('epoch', 'policyHash'))
                or any(child[k] == binding[k] for k in ('scopeHash', 'generation'))):
            fail()


def request_digest(method, request):
    return hashlib.sha256(REQUEST_DOMAIN + encode({'method': method, 'request': request})).hexdigest()


def validate_view(value, binding):
    if (type(value) is not dict or set(value) != {'binding', 'seq', 'head', 'phase', 'lineage', 'active', 'authorityGranted', 'productionReady'}
            or binding_value(value['binding']) != binding or value['authorityGranted'] is not False
            or value['productionReady'] is not False or type(value['active']) is not bool
            or type(value['lineage']) is not list or len(value['lineage']) > 31):
        fail()
    cursor(value['seq'], value['head'])
    expected = ['empty', 'open', 'prepared', 'admitted', 'response', 'completed', 'closed'][value['seq']]
    if value['phase'] != expected and not (value['seq'] == 4 and value['phase'] == 'blocked'):
        fail()
    seen_scope, seen_generation = set(), set()
    for link in value['lineage']:
        if type(link) is not dict or set(link) != {'binding', 'seq', 'head'}:
            fail()
        b = binding_value(link['binding']); cursor(link['seq'], link['head'])
        if (link['seq'] != 6 or any(b[k] != binding[k] for k in ('epoch', 'policyHash'))
                or b['scopeHash'] in seen_scope or b['generation'] in seen_generation):
            fail()
        seen_scope.add(b['scopeHash']); seen_generation.add(b['generation'])
    current_links = [link for link in value['lineage'] if link['binding'] == binding]
    if value['active']:
        if binding['scopeHash'] in seen_scope or binding['generation'] in seen_generation:
            fail()
    elif value['phase'] != 'closed' or current_links != [{'binding': binding, 'seq': value['seq'], 'head': value['head']}]:
        fail()


def validate_chain_status(result, binding):
    fields = {'epoch', 'policyHash', 'activeBinding', 'activeSeq', 'activeHead',
              'activePhase', 'lineage', 'authorityGranted', 'productionReady'}
    if (type(result) is not dict or set(result) != fields
            or result['epoch'] != binding['epoch'] or result['policyHash'] != binding['policyHash']
            or result['authorityGranted'] is not False or result['productionReady'] is not False):
        fail()
    active = binding_value(result['activeBinding'])
    if any(active[k] != binding[k] for k in ('epoch', 'policyHash')):
        fail()
    view = dict(binding=active, seq=result['activeSeq'], head=result['activeHead'], phase=result['activePhase'],
                lineage=result['lineage'], active=True, authorityGranted=False, productionReady=False)
    validate_view(view, active)
    if binding != active and not any(link['binding'] == binding for link in result['lineage']):
        fail()


def validate_result(method, request, result):
    binding = request['binding']
    if method == 'chain_status':
        validate_chain_status(result, binding)
        return
    if method == 'events_after':
        if type(result) is not list or len(result) > 6 - request['seq']:
            fail()
        seq, head, attempt, blocked = request['seq'], request['head'], None, False
        for record in result:
            if type(record) is not dict or set(record) != {'event', 'canonicalEvent', 'head', 'bootNonce', 'rpcNonce', 'hasExternalMaterial', 'externalMaterialBase64'}:
                fail()
            external = decode_material(record['externalMaterialBase64'])
            if (type(record['hasExternalMaterial']) is not bool or record['hasExternalMaterial'] != (external is not None)
                    or not all(hex_value(record[k]) for k in ('bootNonce', 'rpcNonce')) or blocked):
                fail()
            canonical_event, next_head = validate_event(record['event'], binding, seq, head, external)
            if record['canonicalEvent'] != canonical_event or record['head'] != next_head:
                fail()
            data = record['event']['data']
            if 'attemptRef' in data:
                if attempt is not None and attempt != data['attemptRef']:
                    fail()
                attempt = data['attemptRef']
            blocked = record['event']['kind'] == 'response' and not data['definitive']
            seq += 1; head = next_head
        return
    target = request['childBinding'] if method == 'transition_successor' else binding
    validate_view(result, target)
    if method == 'check' and (result['seq'], result['head']) != (request['expectedSeq'], request['expectedHead']):
        fail()
    if method == 'append_event':
        _, head = validate_event(request['event'], binding, request['expectedSeq'], request['expectedHead'], decode_material(request['externalMaterialBase64']))
        phase = request['event']['kind']
        if phase == 'response' and not request['event']['data']['definitive']:
            phase = 'blocked'
        if (result['seq'], result['head'], result['phase'], result['active']) != (request['expectedSeq'] + 1, head, phase, True):
            fail()
    if method == 'transition_successor':
        parent = {'binding': binding, 'seq': request['expectedSeq'], 'head': request['expectedHead']}
        if ((result['seq'], result['head'], result['phase'], result['active']) != (0, ZERO, 'empty', True)
                or not result['lineage'] or result['lineage'][-1] != parent):
            fail()


def dispatch_request(store, method, request):
    """Host-only unsigned dispatch; embedding must authenticate caller first."""
    try:
        request = deepcopy(request); validate_request(method, request)
        binding = request['binding']
        if method == 'read':
            result = store.read(binding)
        elif method == 'chain_status':
            result = store.chain_status(binding)
        elif method == 'check':
            result = store.check(binding, expected_seq=request['expectedSeq'], expected_head=request['expectedHead'])
        elif method == 'events_after':
            result = store.events_after(binding, seq=request['seq'], head=request['head'])
        elif method == 'append_event':
            result = store.append_event(binding, expected_seq=request['expectedSeq'], expected_head=request['expectedHead'],
                                        event=request['event'], external_material=decode_material(request['externalMaterialBase64']),
                                        boot_nonce=request['bootNonce'], rpc_nonce=request['rpcNonce'])
        else:
            result = store.transition_successor(binding, expected_seq=request['expectedSeq'], expected_head=request['expectedHead'], childBinding=request['childBinding'])
        validate_result(method, request, result)
        return dict(schemaVersion=1, method=method, binding=binding, requestDigest=request_digest(method, request),
                    bootNonce=request['bootNonce'], rpcNonce=request['rpcNonce'], result=deepcopy(result),
                    authorityGranted=False, productionReady=False)
    except Exception:
        raise ValueError('operation-witness-v3-rejected') from None


class OperationWitnessClientV3:
    def __init__(self, binding, public_key, transport):
        try:
            self._binding = binding_value(binding)
            self._public = key_material(public_key)
            if not callable(transport):
                fail()
            self._transport = transport
            self._boot = secrets.token_hex(32)
        except Exception:
            raise ValueError('operation-witness-v3-rejected') from None

    @property
    def binding(self):
        return deepcopy(self._binding)

    @property
    def key_hash(self):
        return hashlib.sha256(self._public).hexdigest()

    def _call(self, method, fields):
        try:
            request = dict(binding=self.binding, bootNonce=self._boot, rpcNonce=secrets.token_hex(32), **deepcopy(fields))
            validate_request(method, request)
            response = self._transport(method, deepcopy(request))  # Exactly one attempt, including mutations.
            if type(response) is not dict or set(response) != {'payload', 'signature'}:
                fail()
            payload = response['payload']
            if type(payload) is not dict or set(payload) != {'schemaVersion', 'method', 'binding', 'requestDigest', 'bootNonce', 'rpcNonce', 'result', 'authorityGranted', 'productionReady'}:
                fail()
            expected = dict(schemaVersion=1, method=method, binding=self.binding, requestDigest=request_digest(method, request),
                            bootNonce=request['bootNonce'], rpcNonce=request['rpcNonce'], result=payload['result'],
                            authorityGranted=False, productionReady=False)
            material = encode(payload)
            if material != encode(expected) or type(response['signature']) is not str or len(response['signature']) > 8192:
                fail()
            signature = base64.b64decode(response['signature'], validate=True)
            if len(signature) > 4096:
                fail()
            with tempfile.TemporaryDirectory(prefix='dw-operation-witness-verify-') as directory:
                root = Path(directory); signers = root / 'signers'; sig = root / 'response.sig'
                signers.write_bytes(PRINCIPAL.encode() + b' ' + self._public + b'\n'); signers.chmod(0o600)
                sig.write_bytes(signature); sig.chmod(0o600)
                checked = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(signers), '-I', PRINCIPAL,
                                          '-n', NAMESPACE, '-s', str(sig)], input=material, capture_output=True, timeout=10)
                if checked.returncode:
                    fail()
            validate_result(method, request, payload['result'])
            return deepcopy(payload['result'])
        except Exception:
            raise ValueError('operation-witness-v3-rejected') from None

    def read(self):
        return self._call('read', {})

    def chain_status(self):
        return self._call('chain_status', {})

    def check(self, *, expected_seq, expected_head):
        return self._call('check', dict(expectedSeq=expected_seq, expectedHead=expected_head))

    def append_event(self, *, expected_seq, expected_head, event, external_material=None):
        if external_material is not None and (type(external_material) is not bytes or len(external_material) > 262144):
            fail()
        encoded = base64.b64encode(external_material).decode('ascii') if external_material is not None else None
        return self._call('append_event', dict(expectedSeq=expected_seq, expectedHead=expected_head, event=event, externalMaterialBase64=encoded))

    def events_after(self, *, seq, head):
        return self._call('events_after', dict(seq=seq, head=head))

    def transition_successor(self, *, expected_seq, expected_head, childBinding):
        return self._call('transition_successor', dict(expectedSeq=expected_seq, expectedHead=expected_head, childBinding=childBinding))
