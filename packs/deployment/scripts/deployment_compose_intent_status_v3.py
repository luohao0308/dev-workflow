"""Fresh consumed-intent status, never authority or a runtime permit.

The authenticated host embedding must authorize the caller before calling the
issuer and signing its output. This status checks no phase or inventory and
must never let Root directly openGeneration. Coordinators and gateways still
require bundle, step, protected-component and receipt constraints.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material

NAMESPACE = 'dev-workflow-compose-consumed-intent-status-v3'
PRINCIPAL = 'compose-consumed-intent-status-v3'
ERROR = 'intent-status-v3-rejected'
REQUEST_FIELDS = {'schemaVersion', 'purpose', 'requestHash', 'bundleHash', 'bootNonce', 'rpcNonce'}
RESPONSE_FIELDS = REQUEST_FIELDS | {'issuedAt', 'expiresAt', 'consumed', 'authorityGranted', 'runtimePermit', 'productionReady'}
HEX = re.compile(r'[0-9a-f]{64}\Z')


def fail():
    raise ValueError(ERROR)


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    if len(raw) > 8192:
        fail()
    return raw


def validate_request(request, expected):
    if (type(expected) is not RequestV2 or expected.profile_version != '3'
            or expected.production is not False
            or expected.profile_id != 'compose-application-batch-v1'
            or type(request) is not dict or set(request) != REQUEST_FIELDS
            or type(request['schemaVersion']) is not int or request['schemaVersion'] != 1
            or request['purpose'] != 'check-consumed-intent-v3'
            or request['requestHash'] != expected.digest() or request['bundleHash'] != expected.plan_hash
            or any(type(request[k]) is not str or not HEX.fullmatch(request[k]) for k in ('bootNonce', 'rpcNonce'))):
        fail()


def _approval_type():
    # Load only the distribution-owned sibling host script; never a supplied path.
    path = Path(__file__).resolve().parents[3] / 'scripts/deployment_compose_approval_v3_host.py'
    name = 'deployment_compose_approval_v3_host'
    module = sys.modules.get(name)
    if module is not None:
        if Path(module.__file__).resolve() != path:
            fail()
    else:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module.GitHubFullBodyApprovalV3


def issue_intent_status(approval, registered_request, rpc_request, *, now=None):
    """Unsigned status after live authority/ledger recheck; caller authenticates first."""
    try:
        validate_request(rpc_request, registered_request)
        if (type(approval) is not _approval_type()
                or registered_request not in approval.requests):
            fail()
        approval.check_consumed_intent(registered_request)
        current = time.time() if now is None else now
        if type(current) not in (int, float):
            fail()
        issued = int(current)
        expiry = min(issued + 30, int(datetime.strptime(registered_request.expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()), int(approval._expires))
        if not issued <= current < expiry:
            fail()
        return dict(deepcopy(rpc_request), purpose='consumed-intent-status-v3', issuedAt=issued,
                    expiresAt=expiry, consumed=True, authorityGranted=False, runtimePermit=False, productionReady=False)
    except Exception:
        raise ValueError(ERROR) from None


class IntentStatusClientV3:
    def __init__(self, expected_request: RequestV2, public_key, transport):
        try:
            self._expected = expected_request
            self._boot = secrets.token_hex(32)
            validate_request(self._request(), expected_request)
            self._public = key_material(public_key)
            if not callable(transport):
                fail()
            self._transport = transport
        except Exception:
            raise ValueError(ERROR) from None

    def _request(self):
        return dict(schemaVersion=1, purpose='check-consumed-intent-v3',
                    requestHash=self._expected.digest(), bundleHash=self._expected.plan_hash,
                    bootNonce=self._boot, rpcNonce=secrets.token_hex(32))

    def check_consumed_intent(self, request):
        try:
            if type(request) is not RequestV2 or request != self._expected:
                fail()
            rpc = self._request()
            response = self._transport(deepcopy(rpc))  # One attempt, no cached status.
            if type(response) is not dict or set(response) != {'payload', 'signature'}:
                fail()
            payload = response['payload']
            if type(payload) is not dict or set(payload) != RESPONSE_FIELDS:
                fail()
            material = encode(payload)
            encoded = response['signature']
            if type(encoded) is not str or len(encoded) > 8192:
                fail()
            signature = base64.b64decode(encoded, validate=True)
            if len(signature) > 4096:
                fail()
            with tempfile.TemporaryDirectory(prefix='dw-intent-status-verify-') as directory:
                root = Path(directory)
                signers, sig = root / 'signers', root / 'response.sig'
                signers.write_bytes(PRINCIPAL.encode() + b' ' + self._public + b'\n')
                signers.chmod(0o600)
                sig.write_bytes(signature)
                sig.chmod(0o600)
                checked = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(signers), '-I', PRINCIPAL,
                                          '-n', NAMESPACE, '-s', str(sig)], input=material, capture_output=True, timeout=10)
                if checked.returncode:
                    fail()
            expected = dict(rpc, purpose='consumed-intent-status-v3', issuedAt=payload['issuedAt'],
                            expiresAt=payload['expiresAt'], consumed=True, authorityGranted=False,
                            runtimePermit=False, productionReady=False)
            if material != encode(expected):
                fail()
            issued, expiry = payload['issuedAt'], payload['expiresAt']
            current = time.time()
            request_expiry = datetime.strptime(request.expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
            if (type(issued) is not int or type(expiry) is not int
                    or not issued <= current < expiry <= min(issued + 30, request_expiry)):
                fail()
        except Exception:
            raise ValueError(ERROR) from None
