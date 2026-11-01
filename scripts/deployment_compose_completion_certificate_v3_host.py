"""Historical Mac history/terminal attestation, never execution authority.

An external trust decision must pin the verification key; an adjacent .pub file
or a certificate's own fingerprint cannot authenticate its issuer. Local witness
locks assume trusted exclusive storage; individual crypto commands are bounded,
not the whole operation. Later controller finalizers may still fail.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import weakref

from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_history_v3_host import AuthenticatedHistorySnapshotV3, pairs
from deployment_gate_witness import key_material

NAMESPACE='dev-workflow-compose-history-terminal-v3'
PURPOSE='compose-managed-recovery-history-terminal-v3'
PRINCIPAL='completion-host'
_RECORDS=weakref.WeakKeyDictionary()
_DIGESTS={'archiveDigest','historyDigest','bundleDigest','parentHistoryDigest','rootRequestHash',
 'recoveryRequestHash','managerBindingDigest','daemonBindingDigest','receiptMapDigest',
 'resourceInventoryDigest','hostProjectionDigest','hostEndpointDigest','witnessKeyHash'}
_PROOFS={'historyClosed','wrapperStopped','daemonStopped','inventoryRestored','hostProjectionUnchanged','transportExited'}
_FIELDS=_DIGESTS|{'schemaVersion','purpose','sourceSha','hostId','profile','hostProjectionProfile',
 'parentScopeCount','childScopeCount','totalWriteCount','closedSequence','proofs',
 'authorityGranted','runtimePermit','recoveryAuthorized','productionReady'}


def reject():raise ValueError('compose-completion-certificate-v3-rejected') from None

def digest(value):return hashlib.sha256(value if type(value) is bytes else encode(value)).hexdigest()

class _Candidate:
    @property
    def snapshot(self):
        record=_record(self)
        return AuthenticatedHistorySnapshotV3(record['snapshot'])


def _record(candidate):
    if type(candidate) is not _Candidate:reject()
    record=_RECORDS.get(candidate)
    if record is None or record['owner']!=(os.getpid(),threading.get_ident()):reject()
    return record


def discard_completion(candidate):
    if type(candidate) is not _Candidate:reject()
    if _RECORDS.get(candidate) is None:return
    _record(candidate);_RECORDS.pop(candidate)


def _issuer_seal(admission):
    return (admission._policy.identity_hash(),digest(admission._key),
        key_material(admission._public[0]),admission._signers[0],admission._store)


def _context(admission,session):
    from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
    from deployment_compose_owned_recovery_session_v3_host import OwnedRecoverySSHSessionV3, issued
    if type(admission) is not MacLiveAdmissionV3 or type(session) is not OwnedRecoverySSHSessionV3:reject()
    issued(session)
    if (admission._owner_pid!=os.getpid() or admission._issuer is not admission
            or session._closed or not session._started or session.diagnostic_profile is not None
            or not all(x is True for x in (session.verify_daemon_stop,session.verify_resource_inventory,session.verify_host_snapshot))):reject()
    raw=session._hello_canonical
    if type(raw) is not bytes:reject()
    hello=json.loads(raw,object_pairs_hook=pairs)
    if (set(hello)!={'root','daemonId','writerCertificateSha256','serverCertificateSha256','sourceSha','archiveDigest','hostId'}
            or hello['sourceSha']!=session.source_sha or hello['archiveDigest']!=session.archive_digest
            or hello['hostId']!=session.host_id or admission._policy.scope_hash!=digest(hello)
            or admission._policy.witness_key_sha256!=digest(key_material(admission._public[0]))):reject()
    root,current=admission._root,admission._current
    if root is None or current is None or current is root or admission._pending is not None:reject()
    for entry in (root,current):
        request=entry['request']
        if (request.host_id!=session.host_id or request.daemon_id!=hello['daemonId']
                or request.source.source_sha!=session.source_sha):reject()
    return root,current,raw


def prepare_completion(admission,session):
    """Capture authenticated closed history once; public snapshots are not issuers."""
    from deployment_compose_owned_recovery_controller_v3_host import _completed_history
    root,current,hello=_context(admission,session)
    issuer=_issuer_seal(admission)
    if session._completion_path_succeeded or session._finished:reject()
    snapshot=_completed_history(admission)
    if _context(admission,session)!=(root,current,hello) or _issuer_seal(admission)!=issuer:reject()
    value=json.loads(snapshot.canonical)
    candidate=_Candidate()
    _RECORDS[candidate]=dict(owner=(os.getpid(),threading.get_ident()),admission=admission,session=session,
        root=root,current=current,hello=hello,snapshot=snapshot.canonical,status=encode(value['chainStatus']),
        rootRequest=root['request'].digest(),request=current['request'].digest(),bundle=current['bundle'].digest,
        binding=session._binding,daemon=session._daemon_binding,resource=session._resource_baseline,host=session._host_baseline,
        issuer=issuer)
    return candidate


def _payload(value):
    if type(value) is not dict or set(value)!=_FIELDS:reject()
    if (type(value['schemaVersion']) is not int or value['schemaVersion']!=1 or value['purpose']!=PURPOSE
            or value['profile']!='managed-recovery-v3' or value['hostProjectionProfile']!='linux-docker-host-projection-v1'):reject()
    for field in _DIGESTS|{'sourceSha'}:
        size=40 if field=='sourceSha' else 64
        if type(value[field]) is not str or not re.fullmatch('[0-9a-f]{'+str(size)+'}',value[field]):reject()
    if type(value['hostId']) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',value['hostId']):reject()
    for key,count in (('parentScopeCount',1),('childScopeCount',4),('totalWriteCount',5),('closedSequence',6)):
        if type(value[key]) is not int or value[key]!=count:reject()
    if type(value['proofs']) is not dict or set(value['proofs'])!=_PROOFS or any(x is not True for x in value['proofs'].values()):reject()
    if any(value[key] is not False for key in ('authorityGranted','runtimePermit','recoveryAuthorized','productionReady')):reject()
    return value


def verify_completion(certificate,*,public_key,expected_binding):
    """Verify historical attestation with an externally trusted key/context pin."""
    try:
        if type(certificate) is not bytes or not 0<len(certificate)<=16384:reject()
        envelope=json.loads(certificate,object_pairs_hook=pairs,parse_constant=lambda _:reject())
        if type(envelope) is not dict or set(envelope)!={'payload','signature'} or encode(envelope)!=certificate:reject()
        payload=_payload(envelope['payload']);public=key_material(public_key)
        if payload['witnessKeyHash']!=digest(public):reject()
        if type(expected_binding) is not dict or set(expected_binding)!={'sourceSha','archiveDigest','hostId','historyDigest'}:reject()
        if any(type(v) is not str or payload[k]!=v for k,v in expected_binding.items()):reject()
        raw=envelope['signature']
        if type(raw) is not str or len(raw)>8192:reject()
        sig=base64.b64decode(raw,validate=True)
        if not 0<len(sig)<=4096 or base64.b64encode(sig).decode()!=raw:reject()
        with tempfile.TemporaryDirectory(prefix='dw-completion-verify-') as directory:
            path=Path(directory);signers=path/'signers';signature=path/'signature'
            signers.write_bytes(PRINCIPAL.encode()+b' '+public+b'\n');signers.chmod(0o600)
            signature.write_bytes(sig);signature.chmod(0o600)
            checked=subprocess.run(['/usr/bin/ssh-keygen','-Y','verify','-f',str(signers),'-I',PRINCIPAL,
                '-n',NAMESPACE,'-s',str(signature)],input=encode(payload),capture_output=True,timeout=10,env={'PATH':'/usr/bin:/bin'})
            if checked.returncode:reject()
        return json.loads(encode(payload))
    except Exception:reject()


def issue_completion(candidate):
    """Burn the live candidate before issuance; failures cannot be retried."""
    record=_record(candidate);_RECORDS.pop(candidate)
    admission,session=record['admission'],record['session']
    root,current,hello=_context(admission,session)
    if _issuer_seal(admission)!=record['issuer']:reject()
    if root is not record['root'] or current is not record['current'] or hello!=record['hello']:reject()
    if (not session._finished or not session._completion_path_succeeded
            or not all(x is True for x in (session.daemon_stopped_verified,session.resource_inventory_restored,session.host_snapshot_unchanged_verified))
            or session._process.poll()!=0 or session._reader.is_alive() or session._errors):reject()
    if (root['request'].digest()!=record['rootRequest'] or current['request'].digest()!=record['request']
            or current['bundle'].digest!=record['bundle'] or session._binding!=record['binding']
            or session._daemon_binding!=record['daemon'] or session._resource_baseline!=record['resource']
            or session._host_baseline!=record['host']):reject()
    status=admission._history(current)._client.chain_status()
    if encode(status)!=record['status']:reject()
    history=json.loads(record['snapshot']);host=json.loads(record['host'])
    payload=dict(schemaVersion=1,purpose=PURPOSE,sourceSha=session.source_sha,archiveDigest=session.archive_digest,
        hostId=session.host_id,profile='managed-recovery-v3',historyDigest=digest(record['snapshot']),
        bundleDigest=record['bundle'],parentHistoryDigest=history['parent']['historyDigest'],
        rootRequestHash=record['rootRequest'],recoveryRequestHash=record['request'],
        managerBindingDigest=digest(record['binding']),daemonBindingDigest=digest(record['daemon']),
        receiptMapDigest=digest(history['receiptMap']),resourceInventoryDigest=record['resource'],
        hostProjectionDigest=host['beforeDigest'],hostEndpointDigest=host['endpointDigest'],
        hostProjectionProfile=host['profile'],witnessKeyHash=digest(record['issuer'][2]),
        parentScopeCount=1,childScopeCount=4,totalWriteCount=5,closedSequence=6,
        proofs={key:True for key in _PROOFS},authorityGranted=False,runtimePermit=False,recoveryAuthorized=False,productionReady=False)
    _payload(payload)
    signer=record['issuer'][3]
    if signer.is_symlink() or signer.stat().st_uid!=os.getuid() or signer.stat().st_mode&0o777!=0o600:reject()
    signed=subprocess.run(['/usr/bin/ssh-keygen','-Y','sign','-f',str(signer),'-n',NAMESPACE],
        input=encode(payload),capture_output=True,check=True,timeout=10,env={'PATH':'/usr/bin:/bin'})
    certificate=encode(dict(payload=payload,signature=base64.b64encode(signed.stdout).decode()))
    verify_completion(certificate,public_key=record['issuer'][2],expected_binding={k:payload[k] for k in ('sourceSha','archiveDigest','hostId','historyDigest')})
    return certificate
