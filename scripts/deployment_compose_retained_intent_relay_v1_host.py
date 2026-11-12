"""Signed V2 consent relay for one authenticated production worker session.

The controller owns GitHub credentials and durable consumption. The native
worker verifies short-lived, nonce-bound replies using a pinned public key.
The enclosing channel must independently authenticate the worker origin.
"""
import base64
from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import threading
import time

from deployment_compose_production_frontend_approval_v1_host import (
    PROFILE, GitHubProductionFrontendApprovalV2, ProductionFrontendGrantV1,
    ProductionFrontendReceiptV1,
)
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material
from release_host import timestamp

NAMESPACE = 'dev-workflow-retained-production-intent-v1'
PRINCIPAL = 'retained-production-intent-v1'
RPC_FIELDS = {'method', 'requestHash', 'binding', 'nonce', 'generation', 'grantHash', 'receiptHash'}
RESPONSE_FIELDS = {'request', 'issuedAt', 'expiresAt', 'result', 'runtimePermit'}
METHODS = frozenset(('validate', 'consume', 'check'))
_MAX_CLOCK_SKEW = 2


class IntentRelayRejected(ValueError):
    pass


class ConsumedReceiptRejected(IntentRelayRejected):
    pass


def reject():
    raise IntentRelayRejected('retained-production-intent-relay-rejected') from None


def _wait_for_clock(issued_at):
    now = time.time()
    if 0 < issued_at - now <= _MAX_CLOCK_SKEW:
        time.sleep(issued_at - now)
        now = time.time()
    return now


@dataclass(frozen=True)
class RetainedIntentBindingV1:
    channel_nonce: str
    runtime_sha: str
    archive_digest: str
    origin_digest: str
    protection_digest: str

    def __post_init__(self):
        if (type(self.runtime_sha) is not str or not re.fullmatch('[0-9a-f]{40}', self.runtime_sha)
                or any(not hex_value(value) for value in (self.channel_nonce, self.archive_digest,
                                                          self.origin_digest, self.protection_digest))):
            reject()


def _request_pin(request, binding):
    if (type(request) is not RequestV2 or request.profile_id != PROFILE or request.profile_version != '2'
            or request.production is not True or request.operation not in ('deploy', 'rollback')
            or type(binding) is not RetainedIntentBindingV1):
        reject()
    return request.digest(), asdict(binding)


def _material(value):
    raw = canonical(value)
    if len(raw) > 8192:
        reject()
    return raw


def _digest(value):
    return hashlib.sha256(_material(value)).hexdigest()


def _generation(value):
    return type(value) is int and 1 <= value < 2**53


class _OriginalOwner:
    def __copy__(self):
        reject()

    def __deepcopy__(self, memo):
        reject()

    def __reduce_ex__(self, protocol):
        reject()

    def _owned(self):
        if self._owner != (os.getpid(), threading.current_thread()):
            reject()


class RetainedIntentIssuerV1(_OriginalOwner):
    """Issue replies for one fixed request. No retry of consumption is accepted."""

    def __init__(self, approval, request, grant, *, binding, signer, preflight_challenge=None):
        self._pin = _request_pin(request, binding)
        if (type(approval) is not GitHubProductionFrontendApprovalV2
                or type(grant) is not ProductionFrontendGrantV1
                or approval.policy.workflow_sha != binding.runtime_sha or approval.validate(request) != grant
                or preflight_challenge is not None and not callable(preflight_challenge)):
            reject()
        self._owner = (os.getpid(), threading.current_thread())
        self._approval, self._request, self._grant = approval, request, grant
        self._signer = Path(signer)
        self._preflight_challenge = preflight_challenge
        self._key_identity = self._key()
        self._seen = set()
        self._attempted = False
        self._receipt = self._scope = None

    @property
    def consumption(self):
        self._owned()
        if self._receipt is None:
            reject()
        return self._receipt

    @property
    def scope_generation(self):
        self._owned()
        if self._receipt is None:
            reject()
        return self._scope

    def _key(self):
        path = self._signer
        if not path.is_absolute() or path.resolve() != path:
            reject()
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid() or info.st_nlink != 1):
            reject()
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    def _seal(self, payload):
        if self._key() != self._key_identity:
            reject()
        result = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-n', NAMESPACE,
                                 '-f', str(self._signer)], input=_material(payload),
                                capture_output=True, timeout=10, check=False, env={'PATH': '/usr/bin:/bin'})
        if (result.returncode or not 0 < len(result.stdout) <= 4096
                or self._key() != self._key_identity or time.time() >= payload['expiresAt']):
            reject()
        return {'payload': payload, 'signature': base64.b64encode(result.stdout).decode('ascii')}

    def authorize_rpc(self, rpc):
        self._owned()
        if type(rpc) is not dict or set(rpc) != RPC_FIELDS:
            reject()
        frozen = _material(rpc)
        rpc = deepcopy(rpc)
        method, nonce = rpc['method'], rpc['nonce']
        if (type(method) is not str or method not in METHODS or not hex_value(nonce)
                or nonce in self._seen or len(self._seen) >= 256
                or (rpc['requestHash'], rpc['binding']) != self._pin or _material(rpc) != frozen):
            reject()
        self._seen.add(nonce)
        expiry = min(timestamp(self._grant.expires_at).timestamp(), timestamp(self._request.expires_at).timestamp())
        if time.time() >= expiry or self._key() != self._key_identity:
            reject()
        if method == 'validate':
            if self._attempted or any(rpc[key] is not None for key in ('generation', 'grantHash', 'receiptHash')):
                reject()
            if self._approval.validate(self._request) != self._grant:
                reject()
            result = asdict(self._grant)
        elif method == 'consume':
            if (self._attempted or not _generation(rpc['generation']) or rpc['receiptHash'] is not None
                    or rpc['grantHash'] != _digest(asdict(self._grant))):
                reject()
            self._attempted = True
            self._scope = rpc['generation']
            def before_consume():
                if self._preflight_challenge is not None:
                    challenge = dict(nonce=secrets.token_hex(32), requestHash=self._pin[0],
                                     scopeGeneration=self._scope)
                    if _material(self._preflight_challenge(deepcopy(challenge))) != _material(challenge):
                        reject()

            self._receipt = self._approval.consume(self._grant, self._request, before_consume=before_consume)
            result = asdict(self._receipt)
        else:
            if (self._receipt is None or type(rpc['generation']) is not int or rpc['generation'] != self._scope
                    or rpc['grantHash'] is not None or rpc['receiptHash'] != _digest(asdict(self._receipt))):
                reject()
            self._approval.check_consumed_intent(self._request)
            result = {'consumed': True}
        issued = int(time.time())
        expires = min(issued + 30, int(expiry))
        if time.time() >= expires:
            reject()
        return self._seal(dict(request=rpc, issuedAt=issued, expiresAt=expires,
                               result=result, runtimePermit=False))


class RetainedIntentClientV1(_OriginalOwner):
    """Native verifier for the fixed issuer. Only a verified receipt is exposed."""

    def __init__(self, request, *, binding, public_key, transport, consume_transport=None):
        self._pin = _request_pin(request, binding)
        if not callable(transport) or consume_transport is not None and not callable(consume_transport):
            reject()
        self._owner = (os.getpid(), threading.current_thread())
        self._request, self._binding = request, binding
        self._public, self._transport = key_material(public_key), transport
        self._consume_transport = consume_transport
        self._attempted = False
        self._grant = self._receipt = self._scope = None

    @property
    def binding(self):
        self._owned()
        return self._binding

    def _match(self, request):
        self._owned()
        if type(request) is not RequestV2 or request != self._request:
            reject()

    def _call(self, method, *, grant_hash=None, receipt_hash=None, before_consume=None):
        rpc = dict(method=method, requestHash=self._pin[0], binding=deepcopy(self._pin[1]), nonce=secrets.token_hex(32),
                   generation=self._scope, grantHash=grant_hash, receiptHash=receipt_hash)
        if method == 'consume' and self._consume_transport is not None:
            response = self._consume_transport(deepcopy(rpc), before_consume)
        else:
            response = self._transport(deepcopy(rpc))
        # A denial carries no permission. Its exact binding lets a live worker
        # distinguish a rejected status read from a lost mutation response.
        if (method == 'check' and type(response) is dict and set(response) == {'denied', 'request'}
                and response['denied'] is True and _material(response['request']) == _material(rpc)):
            reject()
        if type(response) is not dict or set(response) != {'payload', 'signature'}:
            reject()
        payload, encoded = response['payload'], response['signature']
        if (type(payload) is not dict or set(payload) != RESPONSE_FIELDS or payload['runtimePermit'] is not False
                or _material(payload['request']) != _material(rpc) or type(encoded) is not str or len(encoded) > 8192):
            reject()
        signature = base64.b64decode(encoded, validate=True)
        if not 0 < len(signature) <= 4096:
            reject()
        with tempfile.TemporaryDirectory(prefix='dw-retained-intent-') as directory:
            signers, sig = Path(directory)/'signers', Path(directory)/'reply.sig'
            signers.write_bytes(PRINCIPAL.encode() + b' ' + self._public + b'\n')
            sig.write_bytes(signature)
            verified = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(signers), '-I', PRINCIPAL,
                '-n', NAMESPACE, '-s', str(sig)], input=_material(payload), capture_output=True, timeout=10)
            if verified.returncode:
                reject()
        issued, expires = payload['issuedAt'], payload['expiresAt']
        if type(issued) is not int or type(expires) is not int:
            reject()
        now = _wait_for_clock(issued)
        expiry = timestamp(self._request.expires_at).timestamp()
        if self._grant is not None:
            expiry = min(expiry, timestamp(self._grant.expires_at).timestamp())
        if not issued <= now < expires <= min(issued + 30, expiry):
            reject()
        return deepcopy(payload['result']), issued, expires

    def validate(self, request):
        self._match(request)
        if self._attempted:
            reject()
        result, _, _ = self._call('validate')
        grant = ProductionFrontendGrantV1(**result)
        expiry = timestamp(grant.expires_at).timestamp()
        if (grant.request_hash != self._pin[0] or type(grant.max_uses) is not int or grant.max_uses != 1
                or type(grant.grant_id) is not str or not 0 < len(grant.grant_id) <= 256
                or not time.time() < expiry <= timestamp(request.expires_at).timestamp()
                or self._grant is not None and grant != self._grant):
            reject()
        self._grant = grant
        return grant

    def consume(self, grant, request, *, before_consume, generation):
        self._match(request)
        if (self._attempted or not _generation(generation) or self._grant is None
                or type(grant) is not ProductionFrontendGrantV1 or grant != self._grant or not callable(before_consume)):
            reject()
        self._attempted = True
        self._scope = generation
        before_consume()
        result, issued, expires = self._call(
            'consume', grant_hash=_digest(asdict(grant)), before_consume=before_consume,
        )
        receipt = ProductionFrontendReceiptV1(**result)
        consumed = timestamp(receipt.consumed_at).timestamp()
        if (receipt.grant_id != grant.grant_id or receipt.request_hash != self._pin[0]
                or type(receipt.use_number) is not int or receipt.use_number != 1
                or consumed >= min(issued + 1, expires, timestamp(grant.expires_at).timestamp())):
            raise ConsumedReceiptRejected('retained-production-consumed-receipt-rejected') from None
        # The signed envelope floors its issue time to whole seconds. Wait for
        # the fractional receipt time without extending the verified expiry.
        if not consumed <= _wait_for_clock(consumed) < expires:
            raise ConsumedReceiptRejected('retained-production-consumed-receipt-rejected') from None
        self._receipt = receipt
        return receipt

    def check_consumed_intent(self, request):
        self._match(request)
        if self._receipt is None or time.time() >= timestamp(self._grant.expires_at).timestamp():
            reject()
        result, _, expires_at = self._call('check', receipt_hash=_digest(asdict(self._receipt)))
        if result != {'consumed': True}:
            reject()
        return expires_at
