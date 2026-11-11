"""Journal reconciliation for an independently provisioned recovery signer.

The trusted host embedding pins the signer and supplies a fresh evidence
observer. This module provides neither a CLI nor an automatic recovery policy.
"""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import time

from deployment_compose_production_scope_v1_host import (
    MAX_BYTES, ScopeBlocked, ScopeRegistrationV1, _append, _history, _line,
    _locked_pending_scope, _read,
)
from deployment_compose_witness_store import canonical, hex_value
from deployment_gate_witness import key_material

NAMESPACE = 'dev-workflow-production-scope-reconciliation-v1'
PRINCIPAL = 'production-scope-recovery-operator'
MAX_APPROVAL_SECONDS = 900


def _reject():
    raise ScopeBlocked('Production scope reconciliation rejected') from None


def recovery_payload(registration, pending, evidence_digest, observation_digest, *, expires_at):
    """Build the exact message for an operator reviewing a legacy incident."""
    if (type(registration) is not ScopeRegistrationV1 or type(pending) is not dict
            or set(pending) != {'generation', 'requestHash', 'journalDigest'}
            or type(pending['generation']) is not int or pending['generation'] < 1
            or not all(hex_value(value) for value in (
                pending['requestHash'], pending['journalDigest'], evidence_digest, observation_digest))
            or type(expires_at) is not int):
        _reject()
    return dict(
        schemaVersion=1, operation='operator-reconcile-production-scope',
        hostId=registration.host_id, project=registration.project, daemonId=registration.daemon_id,
        scopeDirectory=str(registration.root), scopeIdentity=list(registration.root_identity),
        journalIdentity=list(registration.journal_identity), pending=dict(pending),
        evidenceDigest=evidence_digest, observationDigest=observation_digest,
        legacyMacAuthentication='unavailable',
        expiresAt=expires_at,
    )


def _verify_signature(material, signature, public_key):
    with tempfile.TemporaryDirectory(prefix='dw-scope-reconciliation-') as directory:
        allowed = Path(directory) / 'allowed-signers'
        signature_file = Path(directory) / 'approval.sig'
        allowed.write_bytes(PRINCIPAL.encode('ascii') + b' ' + public_key + b'\n')
        signature_file.write_bytes(signature)
        result = subprocess.run(
            ['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', PRINCIPAL,
             '-n', NAMESPACE, '-s', str(signature_file)],
            input=material, capture_output=True, timeout=10, check=False,
        )
        if result.returncode:
            _reject()


def reconcile_pending_scope(registration, request_digest, *, approval, signature,
                            public_key, trusted_signer_digest, observe_live_digest):
    """Append one signed operator disposition after a locked evidence recheck.

    The embedding retains the signed approval and independently supplies the
    trusted signer digest and the callback returning a fresh, stable live
    observation digest. The incident evidence digest binds the historical
    report separately. A successful return certifies journal closure only.
    A torn line remains blocked. If sync fails after a complete append, a
    later acquisition must sync the journal before issuing another lease.
    """
    if (type(approval) is not dict or type(signature) is not bytes
            or not 0 < len(signature) <= 4096 or not hex_value(trusted_signer_digest)
            or not callable(observe_live_digest)):
        _reject()
    key = key_material(public_key)
    if hashlib.sha256(key).hexdigest() != trusted_signer_digest:
        _reject()
    expiry = approval.get('expiresAt')
    evidence = approval.get('evidenceDigest')
    observation = approval.get('observationDigest')
    if type(expiry) is not int or not 0 < expiry - time.time() <= MAX_APPROVAL_SECONDS:
        _reject()

    with _locked_pending_scope(registration, request_digest, writable=True) as (fd, raw, pending):
        expected = recovery_payload(registration, pending, evidence, observation, expires_at=expiry)
        material = canonical(expected)
        if canonical(approval) != material:
            _reject()
        _verify_signature(material, signature, key)
        if (observe_live_digest() != observation or _read(registration, fd) != raw
                or time.time() >= expiry):
            _reject()
        proof = hashlib.sha256(
            b'dev-workflow:production-scope-reconciliation:v1\0' + material + b'\0' + signature,
        ).hexdigest()
        record = dict(state='operator-reconciled', generation=pending['generation'],
                      request=request_digest, proof=proof, evidence=evidence,
                      observation=observation, signer=trusted_signer_digest)
        line = _line(record)
        if len(raw) + len(line) > MAX_BYTES:
            _reject()
        _append(fd, line)
        persisted = _read(registration, fd)
        if persisted != raw + line:
            _reject()
        _history(persisted, registration)
        return record
