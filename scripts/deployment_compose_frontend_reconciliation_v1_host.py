"""Bind journal reconciliation to the registered production frontend.

Unconsumed reconciliation requires a trusted controller adapter that reads
the exact request marker in the private authorization ledger. Preview and
apply both need that adapter.
"""
import base64
from contextlib import ExitStack
import hashlib
import json
import os
import stat
import subprocess
import time

from deployment_compose_host_snapshot_v3_host import (
    HostSnapshotV3, ProductionFrontendProtectionV1, _frontend_projection,
)
from deployment_compose_production_caddy_probe_v1_host import ProductionCaddyProbeV1
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_compose_production_frontend_approval_v1_host import GitHubProductionFrontendApprovalV2
from deployment_compose_production_frontend_v3_host import prepare_frontend_plan
from deployment_compose_production_scope_v1_host import ScopeBlocked, _directory, _locked_pending_scope
from deployment_compose_retained_phase_v1_host import original_projection, restored_phase, switched_phase, verify_phase
from deployment_compose_retained_write_v1_host import _operation_tuple
from deployment_compose_scope_reconciliation_v1_host import (
    FIRST_CREATE_OUTCOME_UNKNOWN, LEDGER_CONSUMED_BEFORE_GATE, LEDGER_UNCONSUMED,
    ORIGINAL_RESTORED_AFTER_RENAMES, ORIGINAL_RESTORED_AFTER_STOP, reconcile_pending_scope,
    recovery_payload, valid_ledger_sha,
)
from deployment_compose_witness_store import ZERO, canonical, hex_value, pairs
from deployment_gateway import FileWriterGate


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


def _unknown_create_marker(events, envelopes, generation, attempt, operation):
    """Validate the pinned unknown-response tail structurally, without the lost MAC key."""
    admitted, finished = (envelope['payload'] for envelope in envelopes[2:])
    prepared = envelopes[1]['payload']
    info = os.fstat(events)
    directory = [info.st_dev, info.st_ino]
    policy = envelopes[0]['policy']
    expected_response = dict(ref=attempt, definitive=False, response_hash=None,
                             response_binding_schema=1, status=0, bodyBase64='')
    marker_raw = _private_file(events, 'admitted-' + attempt, 16384)
    marker = json.loads(marker_raw, object_pairs_hook=pairs)
    for envelope, domain in (*((item, 'event') for item in envelopes), (marker, 'admission')):
        if (type(envelope) is not dict or set(envelope) != {'version', 'domain', 'policy', 'payload', 'mac'}
                or type(envelope['version']) is not int or envelope['version'] != 1
                or envelope['domain'] != 'dev-workflow.writer-gate.' + domain
                or envelope['policy'] != policy or not hex_value(envelope['mac'])):
            _reject()
    if (type(policy) is not dict or policy.get('operation_profile') != 'compose-v3'
            or policy.get('witness_required') is not True
            or operation[0] != 'POST' or not operation[1].startswith('/v1.45/containers/create?name=')
            or marker['payload'] != dict(generation=generation, ref=attempt)
            or any(set(item['payload']) != {'generation', 'directory', 'previous', 'kind', 'data'}
                   or item['payload']['directory'] != directory for item in envelopes)
            or admitted != dict(kind='admit', generation=generation, directory=directory,
                               previous=hashlib.sha256(canonical(prepared)).hexdigest(), data=attempt)
            or finished['kind'] != 'finish' or finished['generation'] != generation
            or finished['previous'] != hashlib.sha256(canonical(admitted)).hexdigest()
            or canonical(finished['data']) != canonical(expected_response)):
        _reject()
    return hashlib.sha256(marker_raw).hexdigest()


def _prepared_gate(registration, request_digest, generation, expected, operation, *, outcome_unknown=False):
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
                names = tuple(f'{index:08}.json' for index in range(4 if outcome_unknown else 2))
                entries = set(os.listdir(events))
                if not set(names) <= entries or len(entries) != len(names) + int(outcome_unknown):
                    _reject()
                raw = tuple(_private_file(events, name, 16384) for name in names)
                digests = tuple(hashlib.sha256(value).hexdigest() for value in raw)
                if (digests != expected
                        or set(os.listdir(gate)) != gate_entries
                        or not _same_entry(gate, generation, events)
                        or not _same_entry(root, 'gate-' + request_digest, gate)):
                    _reject()
                envelopes = tuple(json.loads(value, object_pairs_hook=pairs) for value in raw)
                opened, prepared = (envelope['payload'] for envelope in envelopes[:2])
                if (opened['kind'] != 'open' or opened['generation'] != generation
                        or opened['previous'] != ZERO or opened['data']['request_hash'] != request_digest
                        or opened['data']['operations'] != [operation]
                        or prepared['kind'] != 'prepare' or prepared['generation'] != generation
                        or prepared['directory'] != opened['directory']
                        or prepared['previous'] != hashlib.sha256(canonical(opened)).hexdigest()
                        or prepared['data']['operation'] != operation or not hex_value(prepared['data']['ref'])):
                    _reject()
                if outcome_unknown:
                    attempt = prepared['data']['ref']
                    if entries != {*names, 'admitted-' + attempt}:
                        _reject()
                    digests += (_unknown_create_marker(events, envelopes, generation, attempt, operation),)
                if (set(os.listdir(events)) != entries or set(os.listdir(gate)) != gate_entries
                        or not _same_entry(gate, generation, events)
                        or not _same_entry(root, 'gate-' + request_digest, gate)):
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


def _require_absent_gate(registration, request_digest):
    root, identity = _directory(registration.root)
    try:
        if identity != registration.root_identity:
            _reject()
        try:
            os.stat('gate-' + request_digest, dir_fd=root, follow_symlinks=False)
        except FileNotFoundError:
            return
        _reject()
    finally:
        os.close(root)


def _closed_create_and_stop(registration, request_digest, cutover, gate_evidence):
    return _closed_switch_prefix(registration, request_digest, cutover, gate_evidence, prefix=1)


def _closed_switch_prefix(registration, request_digest, cutover, gate_evidence, *, prefix):
    """Match each operation in the required prefix to its exact closed receipt."""
    if prefix not in (1, 3) or type(gate_evidence) is not dict or len(gate_evidence) != prefix + 1:
        _reject()
    if any(not hex_value(generation) or type(digests) is not tuple or len(digests) != 6
           or not all(hex_value(digest) for digest in digests)
           for generation, digests in gate_evidence.items()):
        _reject()
    gate_name = 'gate-' + request_digest
    evidence = {}
    with ExitStack() as stack:
        root, identity = _directory(registration.root)
        stack.callback(os.close, root)
        if identity != registration.root_identity:
            _reject()
        gate = _directory_child(root, gate_name)
        stack.callback(os.close, gate)
        entries = {'mutex', 'policy.json', *gate_evidence}
        if set(os.listdir(gate)) != entries:
            _reject()
        for generation, digests in gate_evidence.items():
            fd = _directory_child(gate, generation)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            names = tuple(f'{i:08}.json' for i in range(6))
            previous = ZERO
            events = []
            for name, digest, kind in zip(names, digests, ('open', 'prepare', 'admit', 'finish', 'close', 'proof')):
                raw = _private_file(fd, name, 16384)
                if hashlib.sha256(raw).hexdigest() != digest:
                    _reject()
                event = json.loads(raw, object_pairs_hook=pairs)['payload']
                if (event['kind'] != kind or event['generation'] != generation or event['previous'] != previous
                        or event['directory'] != [info.st_dev, info.st_ino]):
                    _reject()
                if kind == 'proof' and event['data']['payload'] != dict(generation=generation, head=previous):
                    _reject()
                previous = hashlib.sha256(canonical(event)).hexdigest()
                events.append(event['data'])
            opened, prepared, admitted, response, closed, _ = events
            attempt = prepared['ref']
            if (not hex_value(attempt) or admitted != attempt or response['ref'] != attempt
                    or opened['request_hash'] != request_digest or opened['operations'] != [prepared['operation']]
                    or closed is not None):
                _reject()
            marker_name = 'admitted-' + attempt
            marker_raw = _private_file(fd, marker_name, 16384)
            if (json.loads(marker_raw, object_pairs_hook=pairs)['payload'] != dict(generation=generation, ref=attempt)
                    or set(os.listdir(fd)) != {*names, marker_name} or not _same_entry(gate, generation, fd)):
                _reject()
            FileWriterGate._response_data(response)
            status = response['status']
            operation = tuple(prepared['operation'])
            if not response['definitive'] or operation in evidence:
                _reject()
            evidence[operation] = (status, base64.b64decode(response['bodyBase64'], validate=True),
                                   hashlib.sha256(marker_raw).hexdigest())
        if set(os.listdir(gate)) != entries or not _same_entry(root, gate_name, gate):
            _reject()
    create = _operation_tuple(cutover.create())
    if create not in evidence or evidence[create][0] != 201:
        _reject()
    _, body, create_marker = evidence.pop(create)
    candidate = json.loads(body, object_pairs_hook=pairs)['Id']
    expected = tuple(_operation_tuple(op) for op in cutover.switch(candidate)[:prefix])
    if set(evidence) != set(expected) or any(evidence[op][:2] != (204, b'') for op in expected):
        _reject()
    return candidate, (create_marker, *(evidence[op][2] for op in expected))


def _observe_restored(registration, request_digest, cutover, review, *, original_baseline, closed_gate_evidence,
                      caddy_id, network_id, endpoint_digest, verify_ledger_consumed, ledger_target_sha, recovery_basis):
    if not callable(verify_ledger_consumed) or not valid_ledger_sha(ledger_target_sha):
        _reject()
    _require_quiescent()
    prefix = 3 if recovery_basis == ORIGINAL_RESTORED_AFTER_RENAMES else 1
    candidate, markers = _closed_switch_prefix(registration, request_digest, cutover, closed_gate_evidence, prefix=prefix)
    phase = switched_phase(cutover, prefix)
    for operation in cutover.restore(candidate, switch_prefix=prefix, candidate_running=False):
        phase = restored_phase(cutover, phase, operation)
    observer = HostSnapshotV3()
    try:
        if observer.descriptor()['endpointDigest'] != endpoint_digest:
            _reject()
        identity = review['identity']
        image_row = observer._get('/v1.45/images/' + identity['imageId'] + '/json',
                                  time.monotonic() + 5, [2 * 1024 * 1024])
        image = {key: image_row[key] for key in ('Id', 'Os', 'Architecture', 'Config')}
        rebuilt = prepare_frontend_plan(
            original_baseline, image, expected_identity=identity, expected_snapshot_digest=review['snapshotDigest'],
            network_ids={'luohao-blog-prod_default': network_id}, protected_container_ids=review['protectedContainerIds'],
        )
        if canonical(rebuilt['publicReview']) != canonical(review):
            _reject()

        def sample():
            rows = [observer._get('/v1.45/containers/' + cid + '/json', time.monotonic() + 5, [2 * 1024 * 1024])
                    for cid in (cutover.original_id, candidate)]
            state = verify_phase(cutover, original_baseline, *rows, candidate_id=candidate, phase=phase, require_ready=True)
            snapshot = ProductionFrontendProtectionV1._observe(observer, 20)
            protection = _frontend_projection(snapshot, cutover.original_id, cutover.protected_ids, candidate)
            return hashlib.sha256(state).hexdigest(), hashlib.sha256(protection).hexdigest()

        before = sample()
        if ProductionCaddyProbeV1(observer, caddy_id=caddy_id, network_id=network_id)(cutover.original_id) is not True:
            _reject()
        expected = dict(ref='refs/tags/' + GitHubProductionFrontendApprovalV2.ledger_namespace + '/' + request_digest,
                        objectSha=ledger_target_sha)
        if verify_ledger_consumed(request_digest) != expected or sample() != before:
            _reject()
        _require_quiescent()
        if _closed_switch_prefix(registration, request_digest, cutover, closed_gate_evidence, prefix=prefix) != (candidate, markers):
            _reject()
        return hashlib.sha256(canonical(dict(
            recoveryBasis=recovery_basis, requestHash=request_digest, endpointDigest=endpoint_digest,
            planDigest=cutover.digest, candidateId=candidate, closedGateEvidence={
                key: list(value) for key, value in closed_gate_evidence.items()},
            admissionMarkers=list(markers), observationDigest=before[0], protectionDigest=before[1],
            ledgerMarker=expected, caddyId=caddy_id, networkId=network_id,
        ))).hexdigest()
    finally:
        observer.close()


def _observe(registration, request_digest, *, private_plan, operation_nonce,
             caddy_id, network_id, endpoint_digest, gate_generation=None, gate_event_digests=None,
             recovery_basis=None, verify_ledger_absent=None,
             verify_ledger_consumed=None, ledger_target_sha=None,
             original_baseline=None, closed_gate_evidence=None):
    if (registration.project != 'luohao-blog-prod'
            or not all(hex_value(value) for value in (request_digest, caddy_id, network_id, endpoint_digest))):
        _reject()
    if recovery_basis in (ORIGINAL_RESTORED_AFTER_STOP, ORIGINAL_RESTORED_AFTER_RENAMES):
        if (gate_generation is not None or gate_event_digests is not None or verify_ledger_absent is not None
                or type(original_baseline) is not dict):
            _reject()
        cutover = prepare_retained_frontend_cutover(private_plan, operation_nonce=operation_nonce)
        review = private_plan['publicReview']
        identity = review['identity']
        if ((identity['hostId'], identity['project'], identity['daemonId']) != (
                registration.host_id, registration.project, registration.daemon_id)
                or caddy_id not in cutover.protected_ids):
            _reject()
        return _observe_restored(
            registration, request_digest, cutover, review, original_baseline=original_baseline,
            closed_gate_evidence=closed_gate_evidence, caddy_id=caddy_id, network_id=network_id,
            endpoint_digest=endpoint_digest, verify_ledger_consumed=verify_ledger_consumed,
            ledger_target_sha=ledger_target_sha, recovery_basis=recovery_basis,
        )
    if original_baseline is not None or closed_gate_evidence is not None:
        _reject()
    before_gate = recovery_basis in (LEDGER_UNCONSUMED, LEDGER_CONSUMED_BEFORE_GATE)
    outcome_unknown = recovery_basis == FIRST_CREATE_OUTCOME_UNKNOWN
    consumed = recovery_basis == LEDGER_CONSUMED_BEFORE_GATE or outcome_unknown
    if before_gate and (gate_generation is not None or gate_event_digests is not None):
        _reject()
    if consumed:
        if (not callable(verify_ledger_consumed) or not valid_ledger_sha(ledger_target_sha)
                or verify_ledger_absent is not None):
            _reject()
    elif verify_ledger_consumed is not None or ledger_target_sha is not None:
        _reject()
    if recovery_basis == LEDGER_UNCONSUMED:
        if not callable(verify_ledger_absent):
            _reject()
    elif not before_gate and (recovery_basis not in (None, FIRST_CREATE_OUTCOME_UNKNOWN) or verify_ledger_absent is not None
          or type(gate_event_digests) is not tuple or len(gate_event_digests) != (4 if outcome_unknown else 2)
          or not all(hex_value(value) for value in (gate_generation, *gate_event_digests))):
        _reject()
    cutover = prepare_retained_frontend_cutover(private_plan, operation_nonce=operation_nonce)
    review = private_plan['publicReview']
    identity = review['identity']
    if ((identity['hostId'], identity['project'], identity['daemonId']) != (
            registration.host_id, registration.project, registration.daemon_id)
            or caddy_id not in cutover.protected_ids):
        _reject()

    _require_quiescent()
    if before_gate:
        _require_absent_gate(registration, request_digest)
        events = ()
    else:
        operation = list(_operation_tuple(cutover.create()))
        events = _prepared_gate(registration, request_digest, gate_generation, gate_event_digests, operation,
                                outcome_unknown=outcome_unknown)
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
        facts = dict(
            profile='production-frontend-legacy-reconciliation-v1', requestHash=request_digest,
            endpointDigest=endpoint_digest, protectionDigest=protection_digest,
            gateGeneration=gate_generation, gateEventDigests=list(events), planDigest=cutover.digest,
            frontendId=cutover.original_id, caddyId=caddy_id, networkId=network_id,
        )
        if consumed:
            # The trusted controller reads the exact ref afresh from its pinned
            # ledger. Bind both the ref and the reviewed target to this digest.
            marker = verify_ledger_consumed(request_digest)
            expected = dict(
                ref='refs/tags/' + GitHubProductionFrontendApprovalV2.ledger_namespace + '/' + request_digest,
                objectSha=ledger_target_sha,
            )
            if type(marker) is not dict or marker != expected:
                _reject()
            profile = ('production-frontend-first-create-outcome-unknown-reconciliation-v1' if outcome_unknown
                       else 'production-frontend-consumed-before-gate-reconciliation-v1')
            facts.update(profile=profile,
                         recoveryBasis=recovery_basis, ledgerMarker=expected)
            if outcome_unknown:
                facts.update(gateEventDigests=list(events[:4]), admissionMarkerDigest=events[4])
        elif recovery_basis == LEDGER_UNCONSUMED:
            # Supplied by the trusted private-ledger controller adapter. It must
            # perform a fresh exact-ref read and treat all other outcomes as denial.
            if verify_ledger_absent(request_digest) is not True:
                _reject()
            facts.update(profile='production-frontend-unconsumed-reconciliation-v1',
                         recoveryBasis=LEDGER_UNCONSUMED, ledgerMarkerAbsent=True)
        _require_quiescent()
        if before_gate:
            _require_absent_gate(registration, request_digest)
        else:
            if _prepared_gate(registration, request_digest, gate_generation, gate_event_digests, operation,
                              outcome_unknown=outcome_unknown) != events:
                _reject()
        return hashlib.sha256(canonical(facts)).hexdigest()
    finally:
        observer.close()


def prepare_frontend_reconciliation(registration, request_digest, *, evidence_digest, expires_at,
                                    recovery_basis=None, ledger_target_sha=None, **observation):
    """Return an unsigned message after an exact read-only production check."""
    with _locked_pending_scope(registration, request_digest) as (_, _, pending):
        digest = _observe(registration, request_digest, recovery_basis=recovery_basis,
                          ledger_target_sha=ledger_target_sha, **observation)
        return recovery_payload(registration, pending, evidence_digest, digest, expires_at=expires_at,
                                recovery_basis=recovery_basis, ledger_target_sha=ledger_target_sha)


def reconcile_frontend_scope(registration, request_digest, *, approval, signature, public_key,
                             recovery_basis=None, ledger_target_sha=None, **observation):
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
        digest = _observe(registration, request_digest, recovery_basis=recovery_basis,
                          ledger_target_sha=ledger_target_sha, **observation)
        if signer_digest() != trusted:
            _reject()
        return digest

    return reconcile_pending_scope(
        registration, request_digest, approval=approval, signature=signature, public_key=public_key,
        trusted_signer_digest=trusted, observe_live_digest=observe_live, recovery_basis=recovery_basis,
        ledger_target_sha=ledger_target_sha,
    )
