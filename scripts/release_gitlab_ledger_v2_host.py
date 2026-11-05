"""Independent POSIX release intent ledger; cannot resist its own host rollback.

Provision once in a private host-owned directory. A persisted reservation is burned
regardless of acknowledgement; this module issues no grant or provider capability.
"""
import hashlib
import hmac
import json
import os
import re

from deployment_compose_witness_store import ComposeWitnessStore, canonical, pairs, MAX_BYTES, hex_value

DOMAIN = b'dev-workflow:gitlab-release-ledger:v2\0'
RECORD_DOMAIN = b'dev-workflow:gitlab-release-consumption:v2\0'
MAX_ENTRIES = 4096
FIELDS = {'requestHash', 'bundleHash', 'grantNonce', 'policyHash'}


def reject():
    raise ValueError('gitlab-release-ledger-v2-rejected') from None


class GitLabReleaseLedgerV2(ComposeWitnessStore):
    def __init__(self, root, *, key, host_id, policy_hash):
        if (type(host_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', host_id)
                or not hex_value(policy_hash)):
            reject()
        self._host_id, self._policy_hash = host_id, policy_hash
        super().__init__(root, key=key)

    def _seal(self, state):
        return canonical({'state': state, 'hmac': hmac.new(self._key, DOMAIN + canonical(state), hashlib.sha256).hexdigest()})

    def _read(self):
        fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._dir)
        try:
            self._file_id(fd)
            with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(MAX_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_BYTES: reject()
        value = json.loads(raw, object_pairs_hook=pairs)
        if type(value) is not dict or set(value) != {'state', 'hmac'}: reject()
        state = value['state']
        if (type(state) is not dict or set(state) != {'schemaVersion', 'kind', 'hostId', 'policyHash', 'entries'}
                or type(state['schemaVersion']) is not int or state['schemaVersion'] != 2
                or state['kind'] != 'gitlab-release-consumption-ledger'
                or state['hostId'] != self._host_id or state['policyHash'] != self._policy_hash
                or type(state['entries']) is not list or len(state['entries']) > MAX_ENTRIES
                or not hmac.compare_digest(raw, self._seal(state))): reject()
        requests, nonces = set(), set()
        for record in state['entries']:
            if (type(record) is not dict or set(record) != FIELDS or not all(hex_value(v) for v in record.values())
                    or record['policyHash'] != self._policy_hash or record['requestHash'] in requests
                    or record['grantNonce'] in nonces): reject()
            requests.add(record['requestHash']); nonces.add(record['grantNonce'])
        return state

    def initialize(self):
        with self._locked():
            if 'state.json' in os.listdir(self._dir): reject()
            self._persist(dict(schemaVersion=2, kind='gitlab-release-consumption-ledger',
                               hostId=self._host_id, policyHash=self._policy_hash, entries=[]))

    def _record(self, request_hash, bundle_hash, grant_nonce):
        if not all(hex_value(v) for v in (request_hash, bundle_hash, grant_nonce)): reject()
        return dict(requestHash=request_hash, bundleHash=bundle_hash,
                    grantNonce=grant_nonce, policyHash=self._policy_hash)

    def burn(self, *, request_hash, bundle_hash, grant_nonce):
        record = self._record(request_hash, bundle_hash, grant_nonce)
        with self._locked():
            state = self._read()
            if (len(state['entries']) >= MAX_ENTRIES
                    or any(e['requestHash'] == request_hash or e['grantNonce'] == grant_nonce for e in state['entries'])): reject()
            state['entries'].append(record)
            self._persist(state)
            return hashlib.sha256(RECORD_DOMAIN + canonical(record)).hexdigest()

    def check(self, *, request_hash, bundle_hash, grant_nonce, receipt_hash):
        record = self._record(request_hash, bundle_hash, grant_nonce)
        if not hex_value(receipt_hash): reject()
        with self._locked():
            state = self._read()
            if record not in state['entries'] or receipt_hash != hashlib.sha256(RECORD_DOMAIN + canonical(record)).hexdigest(): reject()
        return True

    def register_once(self, *args, **kwargs): reject()
    def reserve(self, *args, **kwargs): reject()
    def read(self, *args, **kwargs): reject()
