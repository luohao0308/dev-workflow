"""Short-lived signed handoff for the first operation of an admitted scene."""
import base64
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import subprocess
import tempfile
import time

from deployment_compose_approval_v3_host import SCENE_RECOVERY_PROFILE
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_operation_witness_client_v3 import binding_value
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2
from deployment_gate_witness import key_material

NAMESPACE = 'dev-workflow-scene-recovery-handoff-v3'
PRINCIPAL = 'scene-recovery-handoff-v3'
FIELDS = {'sceneId', 'nonce', 'expiresAt', 'request', 'receiptDigest', 'firstBinding',
          'parentTail', 'firstWriteBindingDigest', 'writerStopObservationDigest'}


def reject():
    raise ValueError('compose-scene-recovery-handoff-v3-rejected') from None


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def issue(payload, signer, expected_public_hash, *, namespace=NAMESPACE):
    options = dict(capture_output=True, check=True, timeout=3, env={'PATH': '/usr/bin:/bin'})
    public = subprocess.run(['/usr/bin/ssh-keygen', '-y', '-f', str(signer)], **options).stdout
    if hashlib.sha256(key_material(public)).hexdigest() != expected_public_hash:
        reject()
    signature = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(signer), '-n', namespace],
                               input=canonical(payload), **options).stdout
    return dict(payload=payload, signature=base64.b64encode(signature).decode('ascii'))


def check_expiry(payload):
    expiry = payload['expiresAt']
    if type(expiry) is not int or not 0 < expiry - time.time() <= 60:
        reject()


def verify_signature(certificate, public_key, *, namespace=NAMESPACE, principal=PRINCIPAL):
    if type(certificate) is not dict or set(certificate) != {'payload', 'signature'}:
        reject()
    signature = certificate['signature']
    if type(signature) is not str or not 0 < len(signature) <= 4096:
        reject()
    with tempfile.TemporaryDirectory(prefix='scene-handoff-') as temporary:
        root = Path(temporary)
        signers, sig = root/'signers', root/'signature'
        signers.write_bytes(principal.encode() + b' ' + key_material(public_key) + b'\n')
        sig.write_bytes(base64.b64decode(signature, validate=True))
        result = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(signers),
            '-I', principal, '-n', namespace, '-s', str(sig)], input=canonical(certificate['payload']),
            capture_output=True, timeout=3, env={'PATH': '/usr/bin:/bin'})
        if result.returncode:
            reject()


def verify(certificate, *, public_key, scene_id, nonce, first_write, original, bundle, history):
    if type(certificate) is not dict or set(certificate) != {'payload', 'signature'}:
        reject()
    value = certificate['payload']
    signature = certificate['signature']
    if (type(value) is not dict or set(value) != FIELDS or type(signature) is not str
            or not 0 < len(signature) <= 4096 or value['sceneId'] != scene_id or value['nonce'] != nonce
            or not hex_value(nonce) or not hex_value(value['receiptDigest'])
            or not hex_value(value['writerStopObservationDigest'])
            or value['firstWriteBindingDigest'] != digest(first_write)
            or canonical(value['parentTail']) != canonical(history['closedTail'])):
        reject()
    check_expiry(value)
    request = RequestV2.from_json(canonical(value['request']).decode('ascii'))
    if request != replace(original, operation='recovery', profile_id=SCENE_RECOVERY_PROFILE,
                           history_hash=first_write['historyDigest'], observation_hash=request.observation_hash,
                           expires_at=request.expires_at):
        reject()
    request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=1800)
    receipts = history['receiptMap']
    operation = bundle.resolve_operations(receipts)[1]
    if operation['phase'] != 'stop' or operation['requestDigest'] != first_write['nextOperationDigest']:
        reject()
    scope = Profile3StepExecutor.scope_descriptor(bundle, request, value['receiptDigest'], operation, 1, receipts)
    expected = dict(history['closedTail']['binding'], generation=scope['generation'], scopeHash=scope['scopeHash'])
    if binding_value(value['firstBinding']) != expected:
        reject()
    verify_signature(certificate, public_key)
    return request
