"""Local diagnostic leaf ownership; no Engine, gateway or execution authority.

wait proves this fixed process and its threads exited, never a process tree.
Proofs are usable only in this live supervisor's identity registry. A restart
cannot reconstruct them from serialized PID, exit code or historical evidence.
"""
import hashlib
import json
import os
import select
import secrets
import subprocess
import sys
import threading
from functools import wraps


TERMINATION_DOMAIN = b'dev-workflow:compose-actor-termination:v4\0'


def serialized(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._mutex:
            return method(self, *args, **kwargs)
    return locked


class ActorHandle:
    pass


class ActorTermination:
    pass


class ActorSupervisorV4:
    def __init__(self):
        self._mutex = threading.RLock()
        self.boot = secrets.token_hex(32)
        self._actors = {}
        self._terminations = {}
        self._closed = False

    @serialized
    def start_fixed_actor(self, session_hash):
        if (os.name != 'posix' or self._closed or type(session_hash) is not str or len(session_hash) != 64
                or any(c not in '0123456789abcdef' for c in session_hash)):
            raise ValueError('actor-supervisor-v4-rejected')
        # Fixed diagnostic worker has no socket, key, writer capability or children.
        process = subprocess.Popen([sys.executable, '-I', '-S', '-c', "import os; os.write(1, b'R'); os.read(0, 1)"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, close_fds=True, env={}, start_new_session=True)
        try:
            if not select.select([process.stdout], [], [], 5)[0] or process.stdout.read(1) != b'R':
                raise ValueError('actor-startup-v4-rejected')
        except BaseException:
            if process.poll() is None: process.kill()
            process.wait(timeout=5)
            process.stdin.close()
            raise
        finally:
            process.stdout.close()
        handle = ActorHandle()
        self._actors[id(handle)] = (handle, process, session_hash, secrets.token_hex(32))
        return handle

    @serialized
    def actor_identity(self, handle, session_hash):
        record = self._actors.get(id(handle))
        if (self._closed or type(handle) is not ActorHandle or record is None
                or record[0] is not handle or record[2] != session_hash):
            raise ValueError('actor-supervisor-v4-rejected')
        return record[3]

    @serialized
    def stop_and_join(self, handle):
        record = self._actors.get(id(handle))
        if record is None:
            raise ValueError('actor-supervisor-v4-rejected')
        self.actor_identity(handle, record[2])
        if id(handle) in self._terminations:
            return self._terminations[id(handle)][0]
        process = record[1]
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)
        process.stdin.close()
        proof = ActorTermination()
        material = json.dumps({'supervisorBoot': self.boot, 'sessionHash': record[2],
                               'actorEpoch': record[3], 'returnCode': process.returncode},
                              sort_keys=True, separators=(',', ':')).encode('ascii')
        digest = hashlib.sha256(TERMINATION_DOMAIN + material).hexdigest()
        self._terminations[id(handle)] = (proof, digest)
        return proof

    @serialized
    def termination_digest(self, handle, proof, session_hash):
        self.actor_identity(handle, session_hash)
        registered = self._terminations.get(id(handle))
        if type(proof) is not ActorTermination or registered is None or registered[0] is not proof:
            raise ValueError('actor-supervisor-v4-rejected')
        return registered[1]

    @serialized
    def close(self):
        if self._closed:
            return
        for handle, _, _, _ in list(self._actors.values()):
            self.stop_and_join(handle)
        self._closed = True
