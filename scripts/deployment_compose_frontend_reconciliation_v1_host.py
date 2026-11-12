"""Bind legacy journal reconciliation to the registered production frontend."""
import hashlib
import json
import os
import stat
import subprocess
import time

from deployment_compose_host_snapshot_v3_host import HostSnapshotV3, ProductionFrontendProtectionV1
from deployment_compose_production_caddy_probe_v1_host import ProductionCaddyProbeV1
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_compose_production_frontend_v3_host import prepare_frontend_plan
from deployment_compose_production_scope_v1_host import ScopeBlocked, _directory, _locked_pending_scope
from deployment_compose_retained_phase_v1_host import original_projection
from deployment_compose_retained_write_v1_host import _operation_tuple
from deployment_compose_scope_reconciliation_v1_host import reconcile_pending_scope, recovery_payload
from deployment_compose_witness_store import ZERO, canonical, hex_value, pairs


def _reject():
    raise ScopeBlocked('Production frontend recovery observation rejected') from None


def _directory_child(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        _reject()
    return fd


def _private_file(parent, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= maximum):
            _reject()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        if (len(raw) != info.st_size
                or (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
            _reject()
        return raw
    finally:
        os.close(fd)


def _same_entry(parent, name, fd):
    observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
    opened = os.fstat(fd)
    return (observed.st_dev, observed.st_ino) == (opened.st_dev, opened.st_ino)


def _prepared_gate(registration, request_digest, generation, expected, operation):
    root, identity = _directory(registration.root)
    try:
        if identity != registration.root_identity:
            _reject()
        gate = _directory_child(root, 'gate-' + request_digest)
        try:
            gate_entries = {'mutex', 'policy.json', generation}
            if set(os.listdir(gate)) != gate_entries:
                _reject()
            events = _directory_child(gate, generation)
            try:
                names = ('00000000.json', '00000001.json')
                if set(os.listdir(events)) != set(names):
                    _reject()
                raw = tuple(_private_file(events, name, 16384) for name in names)
                digests = tuple(hashlib.sha256(value).hexdigest() for value in raw)
                if (digests != expected or set(os.listdir(events)) != set(names)
                        or set(os.listdir(gate)) != gate_entries
                        or not _same_entry(gate, generation, events)
                        or not _same_entry(root, 'gate-' + request_digest, gate)):
                    _reject()
                opened, prepared = (json.loads(value, object_pairs_hook=pairs)['payload'] for value in raw)
                if (opened['kind'] != 'open' or opened['generation'] != generation
                        or opened['previous'] != ZERO or opened['data']['request_hash'] != request_digest
                        or opened['data']['operations'] != [operation]
                        or prepared['kind'] != 'prepare' or prepared['generation'] != generation
                        or prepared['directory'] != opened['directory']
                        or prepared['previous'] != hashlib.sha256(canonical(opened)).hexdigest()
                        or prepared['data']['operation'] != operation or not hex_value(prepared['data']['ref'])):
                    _reject()
                return digests
            finally:
                os.close(events)
        finally:
            os.close(gate)
    finally:
        os.close(root)


def _require_quiescent():
    result = subprocess.run(
        ['/usr/bin/systemctl', '--system', '--no-pager', '--plain', '--no-legend',
         'list-units', '--all', 'dw-writer-host-*.service'],
        capture_output=True, timeout=5, check=True,
    )
    if result.stdout.strip():
        _reject()


def _observe(registration, request_digest, *, private_plan, operation_nonce,
             gate_generation, gate_event_digests, caddy_id, network_id, endpoint_digest):
    if (registration.project != 'luohao-blog-prod'
            or type(gate_event_digests) is not tuple or len(gate_event_digests) != 2
            or not all(hex_value(value) for value in (
                request_digest, gate_generation, caddy_id, network_id, endpoint_digest, *gate_event_digests))):
        _reject()
    cutover = prepare_retained_frontend_cutover(private_plan, operation_nonce=operation_nonce)
    review = private_plan['publicReview']
    identity = review['identity']
    if ((identity['hostId'], identity['project'], identity['daemonId']) != (
            registration.host_id, registration.project, registration.daemon_id)
            or caddy_id not in cutover.protected_ids):
        _reject()

    _require_quiescent()
    operation = list(_operation_tuple(cutover.create()))
    events = _prepared_gate(registration, request_digest, gate_generation, gate_event_digests, operation)
    observer = HostSnapshotV3()
    try:
        if observer.descriptor()['endpointDigest'] != endpoint_digest:
            _reject()
        protection = ProductionFrontendProtectionV1(
            observer, daemon_id=registration.daemon_id, original_id=cutover.original_id,
            protected_ids=cutover.protected_ids,
        )
        original = original_projection(observer._get('/v1.45/containers/' + cutover.original_id + '/json',
                                                     time.monotonic() + 5, [2 * 1024 * 1024]))
        image_row = observer._get('/v1.45/images/' + identity['imageId'] + '/json',
                                  time.monotonic() + 5, [2 * 1024 * 1024])
        image = {key: image_row[key] for key in ('Id', 'Os', 'Architecture', 'Config')}
        networks = {name: value['NetworkID'] for name, value in original['NetworkSettings']['Networks'].items()}
        if networks != {'luohao-blog-prod_default': network_id}:
            _reject()
        rebuilt = prepare_frontend_plan(
            original, image, expected_identity=identity, expected_snapshot_digest=review['snapshotDigest'],
            network_ids=networks, protected_container_ids=review['protectedContainerIds'],
        )
        if canonical(rebuilt) != canonical(private_plan):
            _reject()
        ready = ProductionCaddyProbeV1(observer, caddy_id=caddy_id, network_id=network_id)
        if ready(cutover.original_id) is not True:
            _reject()
        protection_digest = protection.verify()
        observer.verify_unchanged()
        _require_quiescent()
        if _prepared_gate(registration, request_digest, gate_generation, gate_event_digests, operation) != events:
            _reject()
        return hashlib.sha256(canonical(dict(
            profile='production-frontend-legacy-reconciliation-v1', requestHash=request_digest,
            endpointDigest=endpoint_digest, protectionDigest=protection_digest,
            gateGeneration=gate_generation, gateEventDigests=list(events), planDigest=cutover.digest,
            frontendId=cutover.original_id, caddyId=caddy_id, networkId=network_id,
        ))).hexdigest()
    finally:
        observer.close()


def prepare_frontend_reconciliation(registration, request_digest, *, evidence_digest, expires_at, **observation):
    """Return an unsigned message after an exact read-only production check."""
    with _locked_pending_scope(registration, request_digest) as (_, _, pending):
        digest = _observe(registration, request_digest, **observation)
        return recovery_payload(registration, pending, evidence_digest, digest, expires_at=expires_at)


def reconcile_frontend_scope(registration, request_digest, *, approval, signature, public_key, **observation):
    """Use the independently installed signer pin and a fresh locked observation."""
    def signer_digest():
        parent, _ = _directory(registration.root.parent)
        try:
            pin = _private_file(parent, 'recovery-signer.sha256', 65).decode('ascii').removesuffix('\n')
            if not hex_value(pin):
                _reject()
            return pin
        finally:
            os.close(parent)

    trusted = signer_digest()

    def observe_live():
        digest = _observe(registration, request_digest, **observation)
        if signer_digest() != trusted:
            _reject()
        return digest

    return reconcile_pending_scope(
        registration, request_digest, approval=approval, signature=signature, public_key=public_key,
        trusted_signer_digest=trusted, observe_live_digest=observe_live,
    )
