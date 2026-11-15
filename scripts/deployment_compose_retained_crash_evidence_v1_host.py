"""Read signed retained-frontend evidence after interruption. Grants no authority."""
import hashlib
import json
import os
from pathlib import Path
import re

from deployment_compose_operation_witness_client_v3 import binding_value
from deployment_compose_retained_witness_admission_v1_host import (
    _CHECKPOINT_NAMESPACE, _LINEAGE_NAMESPACE,
)
from deployment_compose_scene_recovery_handoff_v3_host import verify_signature
from deployment_compose_witness_store import ComposeWitnessStore, MAX_BYTES, canonical, hex_value, pairs
from deployment_gate_witness import key_material


_STAGES = ('create', 'switch', 'rollback')
_LINEAGE = re.compile(r'([0-9a-f]{64})\.retained-lineage\.json\Z')
_CHECKPOINT = re.compile(r'([0-9a-f]{64})\.retained-checkpoint-([0-4])\.json\Z')
_LINEAGE_FIELDS = {
    'schemaVersion', 'kind', 'stage', 'requestHash', 'receiptHash', 'reviewHash', 'scopeGeneration',
    'writerOrigin', 'cutover', 'firstBinding', 'parentBinding', 'parentLineageDigest',
}
_CHECKPOINT_FIELDS = {
    'schemaVersion', 'kind', 'stage', 'requestHash', 'lineageDigest', 'stateDigest', 'candidateId',
    'witnessDigests',
}


def _reject():
    raise ValueError('retained-staged-crash-evidence-rejected') from None


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _read(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, 'rb') as stream:
        identity = ComposeWitnessStore._file_id(fd)
        before = os.fstat(fd)
        raw = stream.read(limit + 1)
        after = os.fstat(fd)
        entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (not 0 < len(raw) <= limit or len(raw) != before.st_size
                or before.st_ctime_ns != after.st_ctime_ns
                or (entry.st_dev, entry.st_ino, entry.st_ctime_ns) != (*identity, after.st_ctime_ns)):
            _reject()
    return raw


def _signed(directory, name, fields, public_key, namespace):
    raw = _read(directory, name, 8192)
    value = json.loads(raw, object_pairs_hook=pairs)
    if type(value) is not dict or set(value) != {'payload', 'signature'} or raw != canonical(value):
        _reject()
    payload = value['payload']
    if type(payload) is not dict or set(payload) != fields or type(payload['schemaVersion']) is not int:
        _reject()
    if payload['schemaVersion'] != 1:
        _reject()
    verify_signature(value, public_key, namespace=namespace, principal='retained-crash-evidence')
    return payload, _digest(raw)


def _checkpoint(directory, entries, lineage, lineage_digest, public_key):
    request = lineage['requestHash']
    stages = sorted((int(match[2]), name) for name in entries if (match := _CHECKPOINT.fullmatch(name))
                    and match[1] == request)
    if not stages or [index for index, _ in stages] != list(range(len(stages))):
        _reject()
    index, filename = stages[-1]
    payload, _ = _signed(directory, filename, _CHECKPOINT_FIELDS, public_key, _CHECKPOINT_NAMESPACE)
    evidence = payload['witnessDigests']
    candidate = payload['candidateId']
    if (payload['kind'] != 'retained-stage-checkpoint' or payload['stage'] != lineage['stage']
            or payload['requestHash'] != request or payload['lineageDigest'] != lineage_digest
            or not hex_value(payload['stateDigest']) or type(evidence) is not list
            or len(evidence) != index or not all(hex_value(item) for item in evidence)
            or (not hex_value(candidate) if index else candidate is not None)
            or lineage['stage'] == 'create' and index > 1):
        _reject()
    state_dir = os.open(request, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        ComposeWitnessStore._directory_id(state_dir)
        actual = _digest(_read(state_dir, 'state.json', MAX_BYTES))
    finally:
        os.close(state_dir)
    return dict(stage=lineage['stage'], requestHash=request, candidateId=candidate,
                witnessDigests=evidence, stateDigest=actual, checkpointMatches=actual == payload['stateDigest'],
                cutover=lineage['cutover'], firstBinding=lineage['firstBinding'], lineageDigest=lineage_digest)


def inspect_retained_crash_evidence(root, pending, *, public_key, expected_key_hash):
    """Summarize a stopped session against an independently inspected scope journal."""
    if (not isinstance(root, Path) or not root.is_absolute() or root.resolve(strict=True) != root
            or type(pending) is not dict or set(pending) != {'generation', 'requestHash', 'journalDigest'}
            or type(pending['generation']) is not int or not 1 <= pending['generation'] < 2**53
            or not all(hex_value(pending[key]) for key in ('requestHash', 'journalDigest'))
            or _digest(key_material(public_key)) != expected_key_hash):
        _reject()
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        identity = ComposeWitnessStore._directory_id(directory)
        entries = set(os.listdir(directory))
        names = {match[1]: name for name in entries if (match := _LINEAGE.fullmatch(name))}
        if (not 1 <= len(names) <= 3 or set(names) != {name for name in entries if hex_value(name)}
                or any(match[1] not in names for name in entries if (match := _CHECKPOINT.fullmatch(name)))):
            _reject()
        lineages = {}
        for request, name in names.items():
            value, digest = _signed(directory, name, _LINEAGE_FIELDS, public_key, _LINEAGE_NAMESPACE)
            stage = value['stage']
            if (type(stage) is not str or stage not in _STAGES or stage in lineages
                    or value['kind'] != 'retained-stage-lineage' or value['requestHash'] != request
                    or type(value['scopeGeneration']) is not int or value['scopeGeneration'] != pending['generation']
                    or type(value['cutover']) is not dict or value['cutover'].get('stage') != stage
                    or not all(hex_value(value[key]) for key in ('receiptHash', 'reviewHash', 'writerOrigin'))):
                _reject()
            binding_value(value['firstBinding'])
            lineages[stage] = value, digest
        if set(lineages) != set(_STAGES[:len(names)]):
            _reject()
        previous = None
        evidence = []
        for stage in _STAGES[:len(names)]:
            value, digest = lineages[stage]
            cutover = value['cutover']
            if previous is None:
                if (value['requestHash'] != pending['requestHash'] or value['parentBinding'] is not None
                        or value['parentLineageDigest'] is not None):
                    _reject()
            else:
                parent, parent_digest = previous
                if (value['parentBinding'] != parent['firstBinding'] or value['parentLineageDigest'] != parent_digest
                        or value['writerOrigin'] != parent['writerOrigin'] or cutover.get('scopeGeneration') != pending['generation']
                        or any(cutover.get(key) != parent['cutover'].get(key)
                               for key in ('planDigest', 'operationNonce', 'runtimeArchiveDigest'))):
                    _reject()
                created = evidence[0]
                if (not evidence[-1]['checkpointMatches'] or cutover.get('candidateId') != created['candidateId']
                        or cutover.get('creationRequestHash') != created['requestHash']
                        or [cutover.get('creationWitnessDigest')] != created['witnessDigests']):
                    _reject()
                if stage == 'rollback' and (cutover.get('parentRequestHash') != evidence[-1]['requestHash']
                        or cutover.get('switchPrefix') != len(evidence[-1]['witnessDigests'])
                        or cutover.get('switchWitnessDigest') != _digest(canonical(evidence[-1]['witnessDigests']))):
                    _reject()
            observed = _checkpoint(directory, entries, value, digest, public_key)
            if stage != 'create' and observed['witnessDigests'] and observed['candidateId'] != cutover.get('candidateId'):
                _reject()
            evidence.append(observed)
            previous = value, digest
        if set(os.listdir(directory)) != entries or (root.stat().st_dev, root.stat().st_ino) != identity:
            _reject()
        return dict(pending=dict(pending), stages=evidence, uncertain=not evidence[-1]['checkpointMatches'],
                    authorityGranted=False, productionReady=False)
    finally:
        os.close(directory)
