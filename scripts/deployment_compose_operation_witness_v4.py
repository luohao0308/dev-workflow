"""Independent non-authorizing V4 ledger. Never migrates or activates V3.

Admission is a conservative observation, not an approval, ticket or proof of
Docker dispatch. Successors remain pending-authorization with no activation API.
Only the fixed diagnostic actor is supported; real writer ownership, approval,
phase checks and budget binding require separate integration.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os

from deployment_compose_witness_store import ComposeWitnessStore, MAX_BYTES, canonical, pairs, hex_value, fail
from deployment_compose_actor_supervisor_v4 import ActorSupervisorV4

DOMAIN = b'dev-workflow:compose-operation-witness:v4\0'
SESSION_FIELDS = {'sessionHash', 'bundleDigest', 'policyHash', 'baselineReference', 'rootRequestHash', 'supervisorBoot'}
INTENT_FIELDS = SESSION_FIELDS | {'schemaVersion', 'profile', 'historyHead', 'actorEpoch', 'scopeOrdinal', 'planWriteIndex', 'nonce', 'expiresAt', 'recoveryRequestHash', 'recoveryContextDigest'}


def digest(value):
    return hashlib.sha256(DOMAIN + canonical(value)).hexdigest()


class OperationWitnessStoreV4(ComposeWitnessStore):
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
        value = json.loads(raw, object_pairs_hook=pairs)
        if len(raw) > MAX_BYTES or type(value) is not dict or set(value) != {'state', 'hmac'}:
            fail()
        state = value['state']
        if (type(state) is not dict or set(state) != {'schemaVersion', 'session', 'scopes', 'sequence', 'head'}
                or type(state['schemaVersion']) is not int or state['schemaVersion'] != 4
                or not hmac.compare_digest(raw, self._seal(state))):
            fail()
        self._validate(state)
        return state

    @staticmethod
    def _validate(state):
        session = state['session']
        scopes = state['scopes']
        if (type(session) is not dict or set(session) != SESSION_FIELDS
                or not all(hex_value(x) for x in session.values())
                or session['sessionHash'] != digest({k:v for k,v in session.items() if k != 'sessionHash'})
                or type(state['sequence']) is not int or state['sequence'] < 1
                or not hex_value(state['head']) or type(scopes) is not list or not 1 <= len(scopes) <= 2):
            fail()
        epochs = set(); nonces = set()
        for index, scope in enumerate(scopes):
            if (type(scope) is not dict or set(scope) != {'scopeOrdinal', 'planWriteIndex', 'actorEpoch', 'phase', 'attemptRef', 'certificate'}
                    or type(scope['scopeOrdinal']) is not int or scope['scopeOrdinal'] != index
                    or type(scope['planWriteIndex']) is not int or scope['planWriteIndex'] != 0
                    or not hex_value(scope['actorEpoch']) or scope['actorEpoch'] in epochs
                    or scope['phase'] not in ('open', 'prepared', 'admitted', 'abandoned', 'pending-authorization')):
                fail()
            epochs.add(scope['actorEpoch'])
            if (scope['phase'] in ('prepared', 'admitted') and not hex_value(scope['attemptRef'])
                    or scope['phase'] in ('open', 'pending-authorization') and scope['attemptRef'] is not None
                    or scope['phase'] == 'abandoned' and scope['attemptRef'] is not None and not hex_value(scope['attemptRef'])):
                fail()
            if index < len(scopes)-1:
                cert = scope['certificate']
                if (scope['phase'] != 'abandoned' or type(cert) is not dict
                        or set(cert) != {'oldHead', 'terminationDigest', 'intentDigest', 'nonce', 'successorActorEpoch'}
                        or not all(hex_value(v) for v in cert.values()) or cert['nonce'] in nonces
                        or cert['successorActorEpoch'] != scopes[index+1]['actorEpoch']):
                    fail()
                nonces.add(cert['nonce'])
            elif scope['certificate'] is not None or scope['phase'] == 'abandoned':
                fail()

    @staticmethod
    def _view(state):
        return dict(deepcopy(state), authorityGranted=False, executionAvailable=False, productionReady=False)

    def read(self):
        with self._locked():
            return self._view(self._read())

    def register_once(self, session, *, supervisor, actor):
        session = deepcopy(session)
        if (type(supervisor) is not ActorSupervisorV4 or type(session) is not dict
                or set(session) != SESSION_FIELDS or session['supervisorBoot'] != supervisor.boot):
            fail()
        if session['sessionHash'] != digest({k:v for k,v in session.items() if k != 'sessionHash'}): fail()
        epoch = supervisor.actor_identity(actor, session['sessionHash'])
        state = dict(schemaVersion=4, session=session, scopes=[dict(scopeOrdinal=0, planWriteIndex=0,
                     actorEpoch=epoch, phase='open', attemptRef=None, certificate=None)], sequence=1, head=digest(session))
        self._validate(state)
        with self._locked():
            if 'state.json' in os.listdir(self._dir): fail()
            self._persist(state)
            return self._view(state)

    @staticmethod
    def _match(state, cursor, supervisor, actor):
        if (type(cursor) is not dict or set(cursor) != {'sequence', 'head'}
                or type(cursor['sequence']) is not int or cursor['sequence'] != state['sequence']
                or cursor['head'] != state['head'] or type(supervisor) is not ActorSupervisorV4
                or supervisor.boot != state['session']['supervisorBoot']
                or supervisor.actor_identity(actor, state['session']['sessionHash']) != state['scopes'][-1]['actorEpoch']):
            fail()

    def _write(self, state, action):
        state['sequence'] += 1
        state['head'] = digest({'previous': state['head'], 'action': action, 'sequence': state['sequence'], 'scopes': state['scopes']})
        self._validate(state)
        self._persist(state)
        return self._view(state)

    def record_prepared(self, cursor, *, supervisor, actor, attempt):
        if not hex_value(attempt): fail()
        with self._locked():
            state = self._read(); self._match(state, cursor, supervisor, actor)
            scope = state['scopes'][-1]
            if scope['phase'] != 'open': fail()
            scope.update(phase='prepared', attemptRef=attempt)
            return self._write(state, 'prepared')

    def record_admitted(self, cursor, *, supervisor, actor, attempt):
        with self._locked():
            state = self._read(); self._match(state, cursor, supervisor, actor)
            scope = state['scopes'][-1]
            if scope['phase'] != 'prepared' or not hex_value(attempt) or attempt != scope['attemptRef']: fail()
            scope['phase'] = 'admitted'
            return self._write(state, 'admitted-observation')

    def abandon_and_reserve(self, cursor, *, supervisor, actor, termination, recovery_intent):
        intent = deepcopy(recovery_intent)
        with self._locked():
            state = self._read(); self._match(state, cursor, supervisor, actor)
            scope = state['scopes'][-1]
            if scope['phase'] not in ('open', 'prepared') or len(state['scopes']) >= 32: fail()
            if (type(intent) is not dict or set(intent) != INTENT_FIELDS
                    or type(intent['schemaVersion']) is not int or intent['schemaVersion'] != 4
                    or intent['profile'] != 'compose-recovery-v4'
                    or not all(hex_value(intent[k]) for k in ('recoveryRequestHash', 'recoveryContextDigest'))
                    or any(intent[k] != v for k,v in state['session'].items())
                    or intent['historyHead'] != state['head'] or intent['actorEpoch'] != scope['actorEpoch']
                    or any(type(intent[k]) is not int or intent[k] != scope[k] for k in ('scopeOrdinal', 'planWriteIndex'))
                    or not hex_value(intent['nonce'])): fail()
            expires = intent['expiresAt']
            if type(expires) is not str: fail()
            until = datetime.strptime(expires, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
            if until.strftime('%Y-%m-%dT%H:%M:%SZ') != expires or not 0 < (until-datetime.now(timezone.utc)).total_seconds() <= 900: fail()
            termination_digest = supervisor.termination_digest(actor, termination, state['session']['sessionHash'])
            if any(s['certificate'] and s['certificate']['nonce'] == intent['nonce'] for s in state['scopes']): fail()
            successor = digest({'intent': intent, 'terminationDigest': termination_digest})
            scope.update(phase='abandoned', certificate=dict(oldHead=state['head'], terminationDigest=termination_digest,
                intentDigest=digest(intent), nonce=intent['nonce'], successorActorEpoch=successor))
            state['scopes'].append(dict(scopeOrdinal=scope['scopeOrdinal']+1, planWriteIndex=scope['planWriteIndex'],
                actorEpoch=successor, phase='pending-authorization', attemptRef=None, certificate=None))
            return self._write(state, 'abandon-and-reserve')

    def reserve(self, *args, **kwargs):
        fail()
