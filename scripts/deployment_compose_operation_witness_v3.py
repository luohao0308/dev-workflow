"""Non-authorizing full-event witness, using the original POSIX storage boundary."""
import base64
import hashlib
import hmac
import json
import os
from copy import deepcopy

from deployment_compose_witness_store import (
    ComposeWitnessStore, ZERO, MAX_BYTES, binding_value, canonical, fail, hex_value, pairs,
)

DOMAIN = b'dev-workflow:compose-operation-witness:v3\0'
HEAD_DOMAIN = b'dev-workflow:compose-operation-event:v3\0'
MAX_EVENTS = 256
MAX_EVENT_BYTES = 98304
MAX_SCOPES = 32
MAX_EXTERNAL_MATERIAL_BYTES = 256 * 1024


def json_material(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is list:
        for item in value:
            json_material(item)
        return
    if type(value) is dict and all(type(k) is str for k in value):
        for item in value.values():
            json_material(item)
        return
    fail()


def advance(phase, attempt, event):
    kind, data = event['kind'], event['data']
    if type(data) is not dict:
        fail()
    if kind == 'open' and phase == 'empty' and data == {}:
        return 'open', None
    if kind == 'prepared' and phase == 'open' and set(data) == {'attemptRef'} and hex_value(data['attemptRef']):
        return 'prepared', data['attemptRef']
    if kind in ('admitted', 'completed') and phase == {'admitted': 'prepared', 'completed': 'response'}[kind] and data == {'attemptRef': attempt}:
        return kind, attempt
    if kind == 'response' and phase == 'admitted' and set(data) == {'attemptRef', 'definitive', 'status', 'bodyBase64'}:
        if (data['attemptRef'] != attempt or type(data['definitive']) is not bool
                or type(data['status']) is not int
                or not (100 <= data['status'] <= 599 or (not data['definitive'] and data['status'] == 0))
                or type(data['bodyBase64']) is not str or len(data['bodyBase64']) > 87384):
            fail()
        try:
            body = base64.b64decode(data['bodyBase64'], validate=True)
        except Exception:
            fail()
        if len(body) > 65536 or base64.b64encode(body).decode('ascii') != data['bodyBase64']:
            fail()
        return ('response' if data['definitive'] else 'blocked'), attempt
    if kind == 'closed' and phase == 'completed' and data == {}:
        return 'closed', attempt
    fail()


def external_material_base64(event, external_material):
    if external_material is None:
        if 'materialDigest' in event:
            fail()
        return None
    if (type(external_material) is not bytes or len(external_material) > MAX_EXTERNAL_MATERIAL_BYTES
            or not hex_value(event.get('materialDigest'))
            or event['materialDigest'] != hashlib.sha256(external_material).hexdigest()):
        fail()
    return base64.b64encode(external_material).decode('ascii')


def stored_external_material(record):
    encoded = record['externalMaterialBase64']
    if type(record['hasExternalMaterial']) is not bool:
        fail()
    if not record['hasExternalMaterial']:
        if encoded is not None:
            fail()
        return None
    if type(encoded) is not str or len(encoded) > 4 * ((MAX_EXTERNAL_MATERIAL_BYTES + 2) // 3):
        fail()
    try:
        material = base64.b64decode(encoded, validate=True)
    except Exception:
        fail()
    if external_material_base64(record['event'], material) != encoded:
        fail()
    return material


def event_material(event, binding, seq, head):
    if (type(event) is not dict or set(event) not in ({'binding', 'sequence', 'previousHead', 'kind', 'data'},
                                                       {'binding', 'sequence', 'previousHead', 'kind', 'data', 'materialDigest'})
            or binding_value(event['binding']) != binding or type(event['sequence']) is not int
            or event['sequence'] != seq + 1 or event['previousHead'] != head or type(event['kind']) is not str):
        fail()
    json_material(event)
    raw = canonical(event)
    if len(raw) > MAX_EVENT_BYTES:
        fail()
    return raw.decode('ascii'), hashlib.sha256(HEAD_DOMAIN + head.encode('ascii') + raw).hexdigest()


class OperationWitnessStoreV3(ComposeWitnessStore):
    """Separate V3 schema; never emits a receipt, permit, or operation authority.

    Each scope holds one operation. Unknown responses freeze that operation forever.
    Nonces, event heads, generation IDs, and scope IDs cannot be reused in this store.
    Optional external bytes are bound by event.materialDigest and persisted alongside
    the event. Only records with hasExternalMaterial preserve those original bytes;
    a generic event alone does not reconstruct a FileWriterGate sealed envelope.
    """
    def _seal(self, state):
        return canonical({'state': state, 'hmac': hmac.new(self._key, DOMAIN + canonical(state), hashlib.sha256).hexdigest()})

    def _read(self):
        fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._dir)
        try:
            self._file_id(fd)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_BYTES:
            fail()
        value = json.loads(raw, object_pairs_hook=pairs)
        if type(value) is not dict or set(value) != {'state', 'hmac'}:
            fail()
        state = value['state']
        if (type(state) is not dict or set(state) != {'schemaVersion', 'scopes'}
                or type(state['schemaVersion']) is not int or state['schemaVersion'] != 3
                or type(state['scopes']) is not list or not 1 <= len(state['scopes']) <= MAX_SCOPES
                or not hmac.compare_digest(raw, self._seal(state))):
            fail()
        nonces, heads, generations, scopes = set(), set(), set(), set()
        total = 0
        for i, scope in enumerate(state['scopes']):
            if type(scope) is not dict or set(scope) != {'binding', 'events', 'parent'}:
                fail()
            binding = binding_value(scope['binding'])
            if binding['generation'] in generations or binding['scopeHash'] in scopes:
                fail()
            generations.add(binding['generation']); scopes.add(binding['scopeHash'])
            if i == 0:
                if scope['parent'] is not None:
                    fail()
            else:
                previous = state['scopes'][i - 1]
                if (self._phase(previous)[0] != 'closed' or scope['parent'] != self._parent(previous)
                        or any(binding[k] != previous['binding'][k] for k in ('epoch', 'policyHash'))):
                    fail()
            if type(scope['events']) is not list:
                fail()
            phase, attempt, head = 'empty', None, ZERO
            for seq, record in enumerate(scope['events']):
                if type(record) is not dict or set(record) != {'event', 'canonicalEvent', 'head', 'bootNonce', 'rpcNonce', 'hasExternalMaterial', 'externalMaterialBase64'}:
                    fail()
                external = stored_external_material(record)
                external_material_base64(record['event'], external)
                material, next_head = event_material(record['event'], binding, seq, head)
                if (material != record['canonicalEvent'] or next_head != record['head'] or next_head in heads
                        or next_head == ZERO or not hex_value(record['bootNonce']) or not hex_value(record['rpcNonce'])
                        or record['rpcNonce'] in nonces):
                    fail()
                phase, attempt = advance(phase, attempt, record['event'])
                nonces.add(record['rpcNonce']); heads.add(next_head); head = next_head
                total += 1
        if total > MAX_EVENTS:
            fail()
        return state

    @staticmethod
    def _phase(scope):
        phase, attempt = 'empty', None
        for record in scope['events']:
            phase, attempt = advance(phase, attempt, record['event'])
        return phase, attempt

    @staticmethod
    def _cursor(scope):
        return len(scope['events']), scope['events'][-1]['head'] if scope['events'] else ZERO

    def _parent(self, scope):
        seq, head = self._cursor(scope)
        return {'binding': deepcopy(scope['binding']), 'seq': seq, 'head': head}

    def _view_scope(self, state, scope):
        return dict(self._parent(scope), phase=self._phase(scope)[0],
                    lineage=[deepcopy(s['parent']) for s in state['scopes'][1:]],
                    active=scope is state['scopes'][-1], authorityGranted=False, productionReady=False)

    @staticmethod
    def _find(state, binding):
        binding = binding_value(binding)
        for scope in state['scopes']:
            if scope['binding'] == binding:
                return scope
        fail()

    def register_once(self, binding):
        binding = binding_value(binding)
        with self._locked():
            if 'state.json' in os.listdir(self._dir):
                fail()
            scope = {'binding': binding, 'events': [], 'parent': None}
            state = {'schemaVersion': 3, 'scopes': [scope]}
            self._persist(state)
            return self._view_scope(state, scope)

    def read(self, binding):
        with self._locked():
            state = self._read()
            return self._view_scope(state, self._find(state, binding))

    def chain_status(self, binding):
        """Read current chain evidence from a known scope; grants no recovery authority."""
        with self._locked():
            state = self._read()
            self._find(state, binding)
            active = state['scopes'][-1]
            view = self._view_scope(state, active)
            return dict(epoch=active['binding']['epoch'], policyHash=active['binding']['policyHash'],
                        activeBinding=deepcopy(active['binding']), activeSeq=view['seq'],
                        activeHead=view['head'], activePhase=view['phase'], lineage=view['lineage'],
                        authorityGranted=False, productionReady=False)

    def check(self, binding, *, expected_seq, expected_head):
        if type(expected_seq) is not int or not hex_value(expected_head):
            fail()
        value = self.read(binding)
        if (value['seq'], value['head']) != (expected_seq, expected_head):
            fail()
        return value

    def append_event(self, binding, *, expected_seq, expected_head, event, boot_nonce, rpc_nonce, external_material=None):
        if type(expected_seq) is not int or not all(hex_value(v) for v in (expected_head, boot_nonce, rpc_nonce)):
            fail()
        event = deepcopy(event)
        if type(event) is not dict:
            fail()
        encoded = external_material_base64(event, external_material)
        with self._locked():
            state = self._read(); scope = self._find(state, binding)
            if scope is not state['scopes'][-1] or self._cursor(scope) != (expected_seq, expected_head):
                fail()
            records = [r for s in state['scopes'] for r in s['events']]
            material, head = event_material(event, scope['binding'], expected_seq, expected_head)
            advance(*self._phase(scope), event)
            if len(records) >= MAX_EVENTS or head == ZERO or any(r['rpcNonce'] == rpc_nonce or r['head'] == head for r in records):
                fail()
            scope['events'].append(dict(event=event, canonicalEvent=material, head=head, bootNonce=boot_nonce, rpcNonce=rpc_nonce,
                                       hasExternalMaterial=external_material is not None, externalMaterialBase64=encoded))
            self._persist(state)
            return self._view_scope(state, scope)

    def events_after(self, binding, *, seq, head):
        with self._locked():
            state = self._read(); scope = self._find(state, binding)
            if (type(seq) is not int or not 0 <= seq <= len(scope['events']) or not hex_value(head)
                    or head != (scope['events'][seq - 1]['head'] if seq else ZERO)):
                fail()
            return deepcopy(scope['events'][seq:])

    def transition_successor(self, parentBinding, *, expected_seq, expected_head, childBinding):
        child = binding_value(childBinding)
        with self._locked():
            state = self._read(); parent = self._find(state, parentBinding)
            if (type(expected_seq) is not int or not hex_value(expected_head) or parent is not state['scopes'][-1]
                    or self._cursor(parent) != (expected_seq, expected_head) or self._phase(parent)[0] != 'closed'
                    or len(state['scopes']) >= MAX_SCOPES
                    or any(child[k] != parent['binding'][k] for k in ('epoch', 'policyHash'))
                    or any(child['generation'] == s['binding']['generation'] or child['scopeHash'] == s['binding']['scopeHash'] for s in state['scopes'])):
                fail()
            scope = {'binding': child, 'events': [], 'parent': self._parent(parent)}
            state['scopes'].append(scope)
            self._persist(state)
            return self._view_scope(state, scope)

    def reserve(self, *args, **kwargs):
        fail()  # V1 reservation interface cannot mutate the V3 schema.
