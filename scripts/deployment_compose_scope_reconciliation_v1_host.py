"""Journal reconciliation for an independently provisioned recovery signer.

The trusted host embedding pins the signer and supplies a fresh evidence
observer. This module provides neither a CLI nor an automatic recovery policy.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

from deployment_compose_production_scope_v1_host import (
    MAX_BYTES, ScopeBlocked, ScopeRegistrationV1, _append, _directory, _history, _line,
    _locked_pending_scope, _read,
)
from deployment_compose_witness_store import canonical, hex_value
from deployment_gate_witness import key_material

NAMESPACE = 'dev-workflow-production-scope-reconciliation-v1'
PRINCIPAL = 'production-scope-recovery-operator'
MAX_APPROVAL_SECONDS = 900
LEDGER_UNCONSUMED = 'ledger-unconsumed'
LEDGER_CONSUMED_BEFORE_GATE = 'ledger-consumed-before-gate'
FIRST_CREATE_OUTCOME_UNKNOWN = 'first-create-outcome-unknown'
ORIGINAL_RESTORED_AFTER_STOP = 'original-restored-after-confirmed-stop'
_CONSUMED_BASES = (LEDGER_CONSUMED_BEFORE_GATE, FIRST_CREATE_OUTCOME_UNKNOWN, ORIGINAL_RESTORED_AFTER_STOP)


def valid_ledger_sha(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{40}', value) is not None


def _reject():
    raise ScopeBlocked('Production scope reconciliation rejected') from None


def recovery_payload(registration, pending, evidence_digest, observation_digest, *, expires_at,
                     recovery_basis=None, ledger_target_sha=None):
    """Build the exact message for an operator reviewing a legacy incident."""
    if (type(registration) is not ScopeRegistrationV1 or type(pending) is not dict
            or set(pending) != {'generation', 'requestHash', 'journalDigest'}
            or type(pending['generation']) is not int or pending['generation'] < 1
            or not all(hex_value(value) for value in (
                pending['requestHash'], pending['journalDigest'], evidence_digest, observation_digest))
            or type(expires_at) is not int
            or recovery_basis not in (None, LEDGER_UNCONSUMED, *_CONSUMED_BASES)
            or (recovery_basis in _CONSUMED_BASES and not valid_ledger_sha(ledger_target_sha))
            or (recovery_basis not in _CONSUMED_BASES and ledger_target_sha is not None)):
        _reject()
    payload = dict(
        schemaVersion=1, operation='operator-reconcile-production-scope',
        hostId=registration.host_id, project=registration.project, daemonId=registration.daemon_id,
        scopeDirectory=str(registration.root), scopeIdentity=list(registration.root_identity),
        journalIdentity=list(registration.journal_identity), pending=dict(pending),
        evidenceDigest=evidence_digest, observationDigest=observation_digest,
        legacyMacAuthentication='unavailable',
        expiresAt=expires_at,
    )
    if recovery_basis == LEDGER_UNCONSUMED:
        payload.update(recoveryBasis=LEDGER_UNCONSUMED, legacyMacAuthentication='not-applicable')
    elif recovery_basis == LEDGER_CONSUMED_BEFORE_GATE:
        payload.update(recoveryBasis=LEDGER_CONSUMED_BEFORE_GATE,
                       legacyMacAuthentication='not-applicable', ledgerTargetSha=ledger_target_sha)
    elif recovery_basis in _CONSUMED_BASES:
        payload.update(recoveryBasis=recovery_basis, ledgerTargetSha=ledger_target_sha)
    return payload


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


def _retain_approval(registration, proof, expected, signature, public_key):
    raw = canonical(dict(approval=expected, signature=base64.b64encode(signature).decode('ascii'),
                         publicKey=public_key.decode('ascii')))
    root, identity = _directory(registration.root)
    try:
        if identity != registration.root_identity:
            _reject()
        name = 'reconciliation-' + proof + '.json'
        flags = os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            fd = os.open(name, flags | os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root)
        except FileExistsError:
            fd = os.open(name, flags | os.O_RDONLY, dir_fd=root)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                        or info.st_size != len(raw) or os.read(fd, len(raw) + 1) != raw):
                    _reject()
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            try:
                if os.write(fd, raw) != len(raw):
                    _reject()
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(root)
    finally:
        os.close(root)


def reconcile_pending_scope(registration, request_digest, *, approval, signature,
                            public_key, trusted_signer_digest, observe_live_digest,
                            recovery_basis=None, ledger_target_sha=None):
    """Append one signed operator disposition after a locked evidence recheck.

    The embedding independently supplies the trusted signer digest and a
    callback returning a fresh, stable live observation digest. The incident
    evidence digest binds the historical report separately. A successful
    return certifies journal closure only.
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
        expected = recovery_payload(registration, pending, evidence, observation, expires_at=expiry,
                                    recovery_basis=recovery_basis, ledger_target_sha=ledger_target_sha)
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
        _retain_approval(registration, proof, expected, signature, key)
        if _read(registration, fd) != raw or time.time() >= expiry:
            _reject()
        _append(fd, line)
        persisted = _read(registration, fd)
        if persisted != raw + line:
            _reject()
        _history(persisted, registration)
        return record
