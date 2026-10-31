"""Single-use RPC freshness check for V4 consumed-intent observations.

There is deliberately no issuer or consumption adapter here. Independent host
configuration pins every binding and the signing key. A successful observation
is neither approval nor a permit, and cannot activate a writer or successor.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material

NAMESPACE = 'dev-workflow-compose-consumed-intent-status-v4'
PRINCIPAL = 'compose-consumed-intent-status-v4'
PURPOSE = 'check-consumed-intent-v4'
REPLY_PURPOSE = 'consumed-intent-status-v4'
HASH = re.compile(r'[0-9a-f]{64}\Z')
BINDINGS = {'sessionHash','requestHash','contextDigest','policyHash','actorEpoch',
            'scopeOrdinal','planWriteIndex','actionDigest'}
REQUEST_FIELDS = BINDINGS | {'schemaVersion','purpose','bootNonce','rpcNonce'}
RESPONSE_FIELDS = REQUEST_FIELDS | {'issuedAt','expiresAt','consumptionReceiptHash',
                                     'consumed','authorityGranted','runtimePermit','productionReady'}


def encode(value):
    raw = json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    if len(raw) > 8192: raise ValueError('intent-status-v4-rejected')
    return raw


class IntentStatusRejected(ValueError):
    def __init__(self, stage):
        super().__init__('intent-status-v4-rejected')
        self.stage = stage


class IntentStatusClientV4:
    def __init__(self, expected_request, public_key, transport, *, session_hash, context_digest,
                 policy_hash, actor_epoch, scope_ordinal, plan_write_index, action_digest,
                 consumption_receipt_hash):
        try:
            if (type(expected_request) is not RequestV2 or expected_request.profile_version != '4'
                    or expected_request.production is not False or expected_request.target.runtime != 'compose'
                    or (expected_request.operation,expected_request.profile_id) not in (
                        ('deploy','compose-application-batch-v1'),('recovery','compose-recovery-v4'))
                    or context_digest != expected_request.observation_hash or policy_hash != expected_request.policy_hash
                    or any(type(v) is not str or not HASH.fullmatch(v) for v in (
                        session_hash,context_digest,policy_hash,actor_epoch,action_digest,consumption_receipt_hash))
                    or any(type(v) is not int or not 0 <= v < 32 for v in (scope_ordinal,plan_write_index))
                    or not callable(transport)):
                raise ValueError()
            self._expected = RequestV2.from_json(expected_request.canonical_json())
            self._public = key_material(public_key)
            self._transport = transport
            self._receipt = consumption_receipt_hash
            self._boot = secrets.token_hex(32)
            self._bindings = dict(sessionHash=session_hash,requestHash=self._expected.digest(),contextDigest=context_digest,
                policyHash=policy_hash,actorEpoch=actor_epoch,scopeOrdinal=scope_ordinal,
                planWriteIndex=plan_write_index,actionDigest=action_digest)
        except Exception:
            raise IntentStatusRejected('configuration') from None

    def check_consumed_intent(self, request):
        stage='request'
        try:
            if type(request) is not RequestV2 or request.canonical_json() != self._expected.canonical_json():
                raise ValueError()
            request.ensure_fresh(datetime.now(timezone.utc))
            rpc = dict(self._bindings,schemaVersion=4,purpose=PURPOSE,bootNonce=self._boot,rpcNonce=secrets.token_hex(32))
            stage='transport'
            response=self._transport(deepcopy(rpc))  # Exactly one request; no retry or cached result.
            stage='response-shape'
            if type(response) is not dict or set(response) != {'payload','signature'}: raise ValueError()
            payload=response['payload']
            if type(payload) is not dict or set(payload) != RESPONSE_FIELDS: raise ValueError()
            material=encode(payload)
            payload=json.loads(material)  # Verify and return the signed private snapshot only.
            stage='signature-encoding'
            encoded=response['signature']
            if type(encoded) is not str or len(encoded)>8192: raise ValueError()
            signature=base64.b64decode(encoded,validate=True)
            if len(signature)>4096 or base64.b64encode(signature).decode('ascii') != encoded: raise ValueError()
            stage='signature-verification'
            with tempfile.TemporaryDirectory(prefix='dw-intent-status-v4-') as directory:
                root=Path(directory); signers=root/'signers'; sig=root/'response.sig'
                signers.write_bytes(PRINCIPAL.encode()+b' '+self._public+b'\n');signers.chmod(0o600)
                sig.write_bytes(signature);sig.chmod(0o600)
                checked=subprocess.run(['ssh-keygen','-Y','verify','-f',str(signers),'-I',PRINCIPAL,
                    '-n',NAMESPACE,'-s',str(sig)],input=material,capture_output=True,timeout=10)
                if checked.returncode: raise ValueError()
            stage='response-binding'
            expected=dict(rpc,purpose=REPLY_PURPOSE,issuedAt=payload['issuedAt'],expiresAt=payload['expiresAt'],
                consumptionReceiptHash=self._receipt,consumed=True,authorityGranted=False,runtimePermit=False,productionReady=False)
            if material != encode(expected): raise ValueError()
            stage='time-validity'
            issued,expiry=payload['issuedAt'],payload['expiresAt']
            if type(issued) is not int or type(expiry) is not int: raise ValueError()
            current=time.time()
            if 0 < issued-current <= 2:
                time.sleep(issued-current);current=time.time()
            request_expiry=datetime.strptime(request.expires_at,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
            if not issued <= current < expiry <= min(issued+30,request_expiry): raise ValueError()
            return deepcopy(payload)
        except Exception:
            raise IntentStatusRejected(stage) from None
