"""Mac-authenticated closed first-create ownership, never execution permission."""
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

from deployment_compose_witness_store import canonical,hex_value
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_gate_witness import key_material

NAMESPACE='dev-workflow-scene-create-closure-v3'
PRINCIPAL='scene-create-closure-v3'
CHALLENGE={'sceneId','attemptId','attemptNonce','preparationId','capsuleDigest','slotGeneration','requestHash','bundleDigest'}
FIELDS=CHALLENGE|{'schemaVersion','purpose','historyDigest','receiptMap'}


def reject():raise ValueError('compose-scene-create-closure-v3-rejected') from None


def _payload(value):
    if (type(value) is not dict or set(value)!=FIELDS or type(value['schemaVersion']) is not int or value['schemaVersion']!=1
            or value['purpose']!='scene-create-closure-v3' or type(value['sceneId']) is not str
            or re.fullmatch('dw-scene-[0-9a-f]{16}',value['sceneId']) is None
            or type(value['slotGeneration']) is not int or not 0<value['slotGeneration']<2**53
            or any(not hex_value(value[k]) for k in ('attemptId','attemptNonce','preparationId','capsuleDigest','requestHash','bundleDigest','historyDigest'))
            or type(value['receiptMap']) is not dict or len(value['receiptMap'])!=1
            or any(type(k) is not str or not k or not hex_value(v) for k,v in value['receiptMap'].items())):reject()
    return value


def verify_create_closure(certificate,*,public_key,expected):
    try:
        if type(certificate) is bytes:
            if not 0<len(certificate)<=8192:reject()
            certificate=decode(certificate)
        if type(certificate) is not dict or set(certificate)!={'payload','signature'}:reject()
        value=_payload(certificate['payload']);_payload(expected)
        if (canonical(value)!=canonical(expected) or type(certificate['signature']) is not str
                or not 0<len(certificate['signature'])<=8192):reject()
        signature=base64.b64decode(certificate['signature'],validate=True)
        if not 0<len(signature)<=4096:reject()
        public=key_material(public_key)
        with tempfile.TemporaryDirectory(prefix='scene-closure-verify-') as temporary:
            root=Path(temporary);signers=root/'signers';sig=root/'signature'
            signers.write_bytes(PRINCIPAL.encode()+b' '+public+b'\n');signers.chmod(0o600)
            sig.write_bytes(signature);sig.chmod(0o600)
            result=subprocess.run(['/usr/bin/ssh-keygen','-Y','verify','-f',str(signers),'-I',PRINCIPAL,'-n',NAMESPACE,'-s',str(sig)],
                input=canonical(value),capture_output=True,timeout=10,env={'PATH':'/usr/bin:/bin'})
            if result.returncode:reject()
        return decode(canonical(value))
    except Exception:reject()


def issue_create_closure(admission,*,challenge,worker_terminal):
    from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
    from deployment_compose_restart_material_v3_host import _prefix
    try:
        if (type(admission) is not MacLiveAdmissionV3 or admission._owner_pid!=os.getpid() or admission._issuer is not admission
                or admission._root is None or admission._current is not admission._root or admission._pending is not None
                or type(challenge) is not dict or set(challenge)!=CHALLENGE or type(worker_terminal) is not dict):reject()
        challenge=decode(canonical(challenge));entry=admission._root
        admission._consent(entry)
        history=admission._history(entry);snapshot=history.capture();value=_prefix(history,snapshot)
        if (challenge['requestHash']!=entry['request'].digest() or challenge['bundleDigest']!=entry['bundle'].digest
                or worker_terminal.get('requestHash')!=challenge['requestHash']
                or worker_terminal.get('bundleDigest')!=challenge['bundleDigest']
                or worker_terminal.get('historyDigest')!=snapshot.digest
                or canonical(worker_terminal.get('receiptMap'))!=canonical(value['receiptMap'])):reject()
        payload=dict(challenge,schemaVersion=1,purpose='scene-create-closure-v3',historyDigest=snapshot.digest,receiptMap=value['receiptMap'])
        _payload(payload)
        signer=admission._signers[1]
        before=signer.stat()
        if signer.is_symlink() or before.st_uid!=os.getuid() or before.st_mode&0o777!=0o600 or before.st_nlink!=1:reject()
        actual=subprocess.run(['/usr/bin/ssh-keygen','-y','-f',str(signer)],capture_output=True,check=True,timeout=10,env={'PATH':'/usr/bin:/bin'}).stdout
        if key_material(actual)!=admission._public[1]:reject()
        signed=subprocess.run(['/usr/bin/ssh-keygen','-Y','sign','-f',str(signer),'-n',NAMESPACE],input=canonical(payload),
            capture_output=True,check=True,timeout=10,env={'PATH':'/usr/bin:/bin'})
        after=signer.stat()
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):reject()
        admission._consent(entry)
        if history.capture().canonical!=snapshot.canonical:reject()
        certificate=dict(payload=payload,signature=base64.b64encode(signed.stdout).decode('ascii'))
        verify_create_closure(certificate,public_key=admission._public[1],expected=payload)
        return certificate
    except Exception:reject()
