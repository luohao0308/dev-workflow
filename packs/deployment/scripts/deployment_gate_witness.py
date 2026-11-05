"""Fresh signed online witness client; not a production approval issuer.

Transport is a trusted host-provisioned live RPC channel, never a saved JSON
checkpoint. Private signing key stays on the witness machine. Trusted startup
code/policy/public key and witness state are outside the tested rollback set.
"""
from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

HEX=re.compile('[0-9a-f]{64}\\Z')
NAMESPACE='dev-workflow-test-witness'
PRINCIPAL='witness-test'


def fail():raise ValueError('online-witness-rejected')


def encode(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    if len(raw)>32768:fail()
    return raw


def opening_scope(generation,request_hash,receipt_hash,operations,source_context_digest=None):
    return hashlib.sha256(b'dev-workflow:online-witness-opening:v1\0'+encode({
        'generation':generation,'requestHash':request_hash,'receiptHash':receipt_hash,
        'operations':operations,'sourceContextDigest':source_context_digest})).hexdigest()


def key_material(public_key):
    if type(public_key) is not bytes or len(public_key)>8192:fail()
    parts=public_key.strip().split()
    if len(parts)<2 or parts[0]!=b'ssh-ed25519':fail()
    blob=base64.b64decode(parts[1],validate=True)
    if len(blob)!=51 or blob[:19]!=b'\0\0\0\x0bssh-ed25519\0\0\0\x20':fail()
    return b' '.join(parts[:2])


class OnlineWitnessClient:
    def __init__(self, binding, public_key, transport):
        try:
            if (type(binding) is not dict or set(binding)!={'scopeHash','epoch','generation','policyHash'}
                    or any(type(v) is not str or not HEX.fullmatch(v) for v in binding.values())
                    or not callable(transport)):
                fail()
            self._binding=deepcopy(binding)
            self._public=key_material(public_key)
            self._transport=transport
            self._boot=secrets.token_hex(32)
        except Exception:raise ValueError('online-witness-rejected') from None

    @property
    def binding(self):return deepcopy(self._binding)

    @property
    def key_hash(self):return hashlib.sha256(self._public).hexdigest()

    def _call(self,method,fields):
        try:
            nonce=secrets.token_hex(32)
            request=dict(binding=self.binding,bootNonce=self._boot,rpcNonce=nonce,**fields)
            encode(request)
            response=self._transport(method,deepcopy(request))
            if type(response) is not dict or set(response)!={'payload','signature'}:fail()
            payload=response['payload'];material=encode(payload)
            if (type(payload) is not dict or type(response['signature']) is not str
                    or len(response['signature'])>8192):fail()
            signature=base64.b64decode(response['signature'],validate=True)
            if len(signature)>4096:fail()
            expected=dict(binding=self.binding,seq=fields['expectedSeq'],head=fields['expectedHead'],
                          authorityGranted=False,productionReady=False,bootNonce=self._boot,rpcNonce=nonce)
            if method=='reserve':
                expected.update(seq=fields['expectedSeq']+1,head=fields['nextHead'],
                                previousHead=fields['expectedHead'],eventDigest=fields['eventDigest'])
            if encode(payload)!=encode(expected):fail()
            with tempfile.TemporaryDirectory(prefix='dw-witness-verify-') as directory:
                root=Path(directory);signers=root/'signers';sig=root/'response.sig'
                signers.write_bytes(PRINCIPAL.encode()+b' '+self._public+b'\n');signers.chmod(0o600)
                sig.write_bytes(signature);sig.chmod(0o600)
                result=subprocess.run(['ssh-keygen','-Y','verify','-f',str(signers),'-I',PRINCIPAL,
                                       '-n',NAMESPACE,'-s',str(sig)],input=material,capture_output=True,timeout=10)
                if result.returncode:fail()
            return deepcopy(payload)
        except Exception:raise ValueError('online-witness-rejected') from None

    def _scope(self,generation,sequence,head):
        if (generation!=self._binding['generation'] or type(sequence) is not int or sequence<0
                or type(head) is not str or not HEX.fullmatch(head)):fail()

    def check(self,generation,sequence,head):
        self._scope(generation,sequence,head)
        return self._call('check',{'expectedSeq':sequence,'expectedHead':head})

    def reserve(self,generation,sequence,head,next_head):
        self._scope(generation,sequence,head)
        if type(next_head) is not str or not HEX.fullmatch(next_head) or next_head==head:fail()
        return self._call('reserve',{'expectedSeq':sequence,'expectedHead':head,
                                     'nextHead':next_head,'eventDigest':next_head})
