"""Pinned signed lifecycle bridge for a diagnostic leaf, never a writer fence.

The embedding provisions key/boot independently and owns a bounded RPC transport.
No CLI, PID lookup, arbitrary command, Engine access or recovery authority.
sourceDigest is a host assertion requiring independently registered keys and pinned
source deployment, never remote code attestation. Cursor is signed challenge
context, not server-verified witness state; the consumer must match current state.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time

from deployment_compose_actor_supervisor_v4 import ActorSupervisorV4

NAMESPACE = 'dev-workflow-compose-diagnostic-supervisor-v4'
PRINCIPAL = 'diagnostic-supervisor'
DOMAIN = b'dev-workflow:compose-remote-diagnostic-termination:v4\0'
MAX_BYTES = 16384
FIELDS = {'operation', 'supervisorBoot', 'sessionHash', 'actorEpoch', 'rpcNonce', 'challenge', 'sourceDigest', 'cursor'}


def reject():
    raise ValueError('remote-diagnostic-supervisor-v4-rejected')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def hex_value(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def request_valid(value):
    if (type(value) is not dict or set(value) != FIELDS
            or value['operation'] not in ('start', 'stop-and-joined')
            or not all(hex_value(value[k]) for k in FIELDS - {'operation', 'cursor'})
            or type(value['cursor']) is not dict or set(value['cursor']) != {'sequence', 'head'}
            or type(value['cursor']['sequence']) is not int or not 0 <= value['cursor']['sequence'] <= 4096
            or not hex_value(value['cursor']['head'])):
        reject()


class RemoteActorHandle:
    pass


class RemoteActorTermination:
    pass


class DiagnosticSupervisorServerV4:
    def __init__(self, *, supervisor, signing_key, source_digest):
        if type(supervisor) is not ActorSupervisorV4 or not isinstance(signing_key, Path) or not hex_value(source_digest):
            reject()
        self._owner_pid = os.getpid()
        supervisor._check_owner()
        # Ownership belongs to this live supervisor object, not its boot string.
        # Never clear this registration: reconstructing a server must not reset
        # epoch/nonce history while any original leaf can still exist.
        with supervisor._mutex:
            if supervisor._closed or hasattr(supervisor, '_remote_diagnostic_owner_v4'):
                reject()
            self._supervisor, self._key = supervisor, signing_key
            self._source = source_digest
            self._actors, self._nonces = {}, set()
            self._lock = threading.RLock()
            supervisor._remote_diagnostic_owner_v4 = self

    def _check_owner(self):
        if os.getpid() != self._owner_pid:
            reject()
        self._supervisor._check_owner()

    def respond(self, request):
        self._check_owner()
        with self._lock:
            if getattr(self._supervisor, '_remote_diagnostic_owner_v4', None) is not self:
                reject()
            try:
                material = canonical(request)
                if len(material) > MAX_BYTES:
                    reject()
                request = json.loads(material)
            except Exception:
                reject()
            request_valid(request)
            if (request['sourceDigest'] != self._source or request['supervisorBoot'] != self._supervisor.boot
                    or request['rpcNonce'] in self._nonces or len(self._nonces) >= 1024):
                reject()
            # Burn nonce even if startup, joining or signing fails. Never attest
            # timeout or PID text as a completed process lifecycle.
            self._nonces.add(request['rpcNonce'])
            session, epoch = request['sessionHash'], request['actorEpoch']
            if request['operation'] == 'start':
                if epoch in self._actors or len(self._actors) >= 128:
                    reject()
                actor = self._supervisor.start_fixed_actor(session)
                self._actors[epoch] = (session, actor, canonical(request['cursor']))
            else:
                record = self._actors.get(epoch)
                if record is None or record[0] != session:
                    reject()
                proof = self._supervisor.stop_and_join(record[1])
                self._supervisor.termination_digest(record[1], proof, session)
            issued = int(time.time())
            payload = dict(request, issuedAt=issued, expiresAt=issued+30,
                           diagnosticOnly=True, writerDrained=False)
            signature = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(self._key), '-n', NAMESPACE],
                input=canonical(payload), capture_output=True, check=True, timeout=5).stdout
            return dict(payload=payload, signature=base64.b64encode(signature).decode('ascii'))

    def close(self):
        self._check_owner()
        self._supervisor.close()


class RemoteActorSupervisorV4:
    def __init__(self, *, public_key, expected_boot, source_digest, expected_cursor, transport):
        if (type(public_key) is not bytes or not 0 < len(public_key) <= 8192
                or not public_key.startswith(b'ssh-ed25519 ') or b'\n' in public_key.rstrip(b'\n')
                or not hex_value(expected_boot) or not hex_value(source_digest) or not callable(transport)):
            reject()
        self._owner_pid = os.getpid()
        self.boot, self._public, self._transport = expected_boot, public_key.strip(), transport
        self._source = source_digest
        self._cursor = json.loads(canonical(expected_cursor))
        request_valid(dict(operation='start', supervisorBoot=expected_boot, sessionHash='0'*64,
                           actorEpoch='0'*64, rpcNonce='0'*64, challenge='0'*64,
                           sourceDigest=source_digest, cursor=self._cursor))
        self._actors, self._terminations = {}, {}
        self._closed = False
        self._mutex = threading.RLock()

    def _check_owner(self):
        if os.getpid() != self._owner_pid:
            reject()

    def _rpc(self, operation, session, epoch, cursor=None):
        self._check_owner()
        request = dict(operation=operation, supervisorBoot=self.boot, sessionHash=session,
                       actorEpoch=epoch, rpcNonce=secrets.token_hex(32), challenge=secrets.token_hex(32),
                       sourceDigest=self._source, cursor=json.loads(canonical(self._cursor if cursor is None else cursor)))
        request_valid(request)
        try:
            expected_request = canonical(request)
            response = self._transport(json.loads(expected_request))
            if (type(response) is not dict or set(response) != {'payload', 'signature'}
                    or len(canonical(response)) > MAX_BYTES):
                reject()
            response = json.loads(canonical(response))
            payload, encoded = response['payload'], response['signature']
            if (type(payload) is not dict or set(payload) != FIELDS | {'issuedAt', 'expiresAt', 'diagnosticOnly', 'writerDrained'}
                    or type(encoded) is not str or len(encoded) > 8192):
                reject()
            signature = base64.b64decode(encoded, validate=True)
            if len(signature) > 4096:
                reject()
            with tempfile.TemporaryDirectory(prefix='remote-diagnostic-verify-') as directory:
                root = Path(directory)
                (root/'signers').write_bytes(PRINCIPAL.encode()+b' '+self._public+b'\n')
                (root/'signature').write_bytes(signature)
                result = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(root/'signers'),
                    '-I', PRINCIPAL, '-n', NAMESPACE, '-s', str(root/'signature')],
                    input=canonical(payload), capture_output=True, timeout=5)
                if result.returncode:
                    reject()
            issued, expires = payload['issuedAt'], payload['expiresAt']
            if (type(issued) is not int or type(expires) is not int
                    or not issued <= time.time() < expires <= issued+30
                    or canonical({k: payload[k] for k in FIELDS}) != expected_request
                    or payload['diagnosticOnly'] is not True or payload['writerDrained'] is not False):
                reject()
            return payload
        except Exception:
            raise ValueError('remote-diagnostic-supervisor-v4-rejected') from None

    def start_fixed_actor(self, session_hash):
        self._check_owner()
        with self._mutex:
            if self._closed or not hex_value(session_hash) or len(self._actors) >= 128:
                reject()
            epoch = secrets.token_hex(32)
            self._rpc('start', session_hash, epoch)
            handle = RemoteActorHandle()
            self._actors[handle] = (session_hash, epoch)
            return handle

    def actor_identity(self, handle, session_hash):
        self._check_owner()
        with self._mutex:
            if (self._closed or type(handle) is not RemoteActorHandle or handle not in self._actors
                    or self._actors[handle][0] != session_hash):
                reject()
            return self._actors[handle][1]

    def stop_and_join(self, handle, *, expected_cursor=None):
        self._check_owner()
        with self._mutex:
            if type(handle) is not RemoteActorHandle or handle not in self._actors:
                reject()
            session, epoch = self._actors[handle]
            self.actor_identity(handle, session)
            if handle not in self._terminations:
                payload = self._rpc('stop-and-joined', session, epoch, expected_cursor)
                self._terminations[handle] = (RemoteActorTermination(),
                    hashlib.sha256(DOMAIN+canonical(payload)).hexdigest(), canonical(payload['cursor']))
            if expected_cursor is not None and self._terminations[handle][2] != canonical(expected_cursor):
                reject()
            return self._terminations[handle][0]

    def termination_digest(self, handle, proof, session_hash, *, expected_cursor=None):
        self._check_owner()
        with self._mutex:
            self.actor_identity(handle, session_hash)
            record = self._terminations.get(handle)
            if (type(proof) is not RemoteActorTermination or record is None or record[0] is not proof
                    or expected_cursor is not None and record[2] != canonical(expected_cursor)):
                reject()
            return record[1]

    def close(self):
        # A disconnect is not proof. Server/transport owner must drain its actors.
        self._check_owner()
        with self._mutex:
            self._closed = True
