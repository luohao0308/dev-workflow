"""Distribution-only V4 consumed status signer, never a runtime permit.

Actor/session/action bindings are independent host assertions, not verified
Engine phase facts. The caller must authenticate challenge senders separately.
"""
from pathlib import Path
import os
import stat
import subprocess
import tempfile
import time
import base64

from deployment_compose_approval_v4_host import GitHubFullBodyApprovalV4
from deployment_compose_intent_status_v4 import IntentStatusClientV4, REQUEST_FIELDS, PURPOSE, REPLY_PURPOSE, NAMESPACE, encode, HASH
from deployment_gate_witness import key_material
from release_host import timestamp


class IntentStatusHostV4:
    def __init__(self, *, authority, request, receipt, signing_key, **bindings):
        if type(authority) is not GitHubFullBodyApprovalV4 or not isinstance(signing_key,Path):
            raise ValueError('intent-status-v4-host-rejected')
        fd=os.open(signing_key,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if (not signing_key.is_absolute() or not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid!=os.getuid()
                    or info.st_nlink!=1 or info.st_size>8192):
                raise ValueError('intent-status-v4-host-rejected')
            with os.fdopen(fd,'rb',closefd=False) as stream:self._key=stream.read(8193)
            if len(self._key)>8192:raise ValueError('intent-status-v4-host-rejected')
        finally:os.close(fd)
        fields=('session_hash','context_digest','policy_hash','actor_epoch','scope_ordinal','plan_write_index','action_digest')
        if encode(bindings)!=encode({k:getattr(authority.policy,k) for k in fields}):
            raise ValueError('intent-status-v4-host-rejected')
        self._authority,self._request,self._receipt=authority,request,receipt
        self._receipt_hash=authority.receipt_hash(receipt,request)
        with tempfile.TemporaryDirectory(prefix='dw-v4-status-key-') as directory:
            key=Path(directory)/'key';key.write_bytes(self._key);key.chmod(0o600)
            public=subprocess.run(['ssh-keygen','-y','-f',str(key)],check=True,capture_output=True,timeout=10).stdout
        self.public_key=key_material(public)
        # Reuse only the client configuration validator; never call transport.
        client=IntentStatusClientV4(request,self.public_key,lambda _:None,
            consumption_receipt_hash=self._receipt_hash,**bindings)
        self._bindings=dict(client._bindings)

    def respond(self, challenge):
        if (type(challenge) is not dict or set(challenge)!=REQUEST_FIELDS
                or any(type(challenge[k]) is not str or not HASH.fullmatch(challenge[k]) for k in ('bootNonce','rpcNonce'))):
            raise ValueError('intent-status-v4-host-rejected')
        expected=dict(self._bindings,schemaVersion=4,purpose=PURPOSE,
                      bootNonce=challenge['bootNonce'],rpcNonce=challenge['rpcNonce'])
        if encode(challenge)!=encode(expected):raise ValueError('intent-status-v4-host-rejected')
        if self._authority.receipt_hash(self._receipt,self._request)!=self._receipt_hash:
            raise ValueError('intent-status-v4-host-rejected')
        self._authority.check_consumed_intent(self._request)
        now=time.time();issued=int(now)
        expiry=min(issued+30,int(timestamp(self._request.expires_at).timestamp()),int(self._authority._expires))
        if not issued<=now<expiry:raise ValueError('intent-status-v4-host-rejected')
        payload=dict(expected,purpose=REPLY_PURPOSE,issuedAt=issued,expiresAt=expiry,
            consumptionReceiptHash=self._receipt_hash,consumed=True,authorityGranted=False,runtimePermit=False,productionReady=False)
        with tempfile.TemporaryDirectory(prefix='dw-v4-status-sign-') as directory:
            key=Path(directory)/'key';key.write_bytes(self._key);key.chmod(0o600)
            signature=subprocess.run(['ssh-keygen','-Y','sign','-f',str(key),'-n',NAMESPACE],
                input=encode(payload),check=True,capture_output=True,timeout=10).stdout
        if time.time()>=expiry:raise ValueError('intent-status-v4-host-rejected')
        return dict(payload=payload,signature=base64.b64encode(signature).decode('ascii'))
