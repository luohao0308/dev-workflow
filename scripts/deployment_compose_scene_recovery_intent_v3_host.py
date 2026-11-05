"""Prepare and recheck an exact scene recovery intent for future approval."""
from dataclasses import replace
from datetime import datetime, timezone
import secrets

from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_approval_v3_host import SCENE_RECOVERY_PROFILE as PROFILE
from deployment_compose_scene_phase_snapshot_v3_host import (
    digest, recheck_snapshot_recovery_draft, validate_scene_phase_snapshot)
from deployment_compose_witness_store import canonical, hex_value
from deployment_contract_v2 import RequestV2


KIND = 'compose-scene-recovery-intent-context-v3'
MAX_CONTEXT_BYTES = 4096
_BINDINGS = ('sceneId', 'snapshotId', 'sceneBindingDigest', 'checkpointMaterialDigest',
             'originalRequestHash', 'originalBundleDigest', 'historyDigest', 'draftDigest',
             'baselineStateDigest', 'phaseDigest', 'endpointBindingDigest', 'slotGeneration',
             'startWriteIndex', 'nextOperationDigest', 'firstWriteBindingDigest',
             'writerStopObservationDigest')


def reject():
    raise ValueError('compose-scene-recovery-intent-v3-rejected') from None


def scene_recovery_public_review(review):
    return dict(sceneId=review['sceneId'], historyDigest=review['historyDigest'],
                nextOperationDigest=review['nextOperationDigest'],
                firstWriteBindingDigest=review['firstWriteBindingDigest'],
                contextDigest=review['recoveryContextDigest'])


def _derive(reader, *, snapshot, expected_draft_digest, handle, intent_nonce, expires_at):
    from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3

    if type(reader) is not SceneCheckpointReaderV3 or not hex_value(intent_nonce):
        reject()
    validate_scene_phase_snapshot(snapshot, reader=reader)
    history = reader.context.history
    if intent_nonce == history._bundle.to_dict()['operationNonce']:
        reject()
    request = replace(history._request, operation='recovery', profile_id=PROFILE,
                      history_hash=snapshot.history_digest, observation_hash='0'*64,
                      expires_at=expires_at)
    request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=1800)
    observation = recheck_snapshot_recovery_draft(reader, snapshot=snapshot,
        expected_draft_digest=expected_draft_digest, handle=handle)
    # The comparison is repeated on verification with a fresh SSH challenge.
    # Bind stable evidence here. The challenge-specific transcript changes.
    context = canonical(dict(schemaVersion=1, kind=KIND, intentNonce=intent_nonce,
                             expiresAt=expires_at, **{key: observation[key] for key in _BINDINGS}))
    if len(context) > MAX_CONTEXT_BYTES:
        reject()
    request = replace(request, observation_hash=digest(context))
    request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=1800)
    review = dict(observation, kind=KIND, requestProfileId=PROFILE,
                  requestDigest=request.digest(), recoveryContextDigest=request.observation_hash,
                  expiresAt=expires_at)
    return request, context, review


def prepare_scene_recovery_intent(reader, *, snapshot, expected_draft_digest, handle, expires_at):
    """Return one private request and context after live recheck, without dispatching approval."""
    request, context, review = _derive(reader, snapshot=snapshot, expected_draft_digest=expected_draft_digest,
        handle=handle, intent_nonce=secrets.token_hex(32), expires_at=expires_at)
    return dict(request=request, context_bytes=context, review=review)


def verify_scene_recovery_intent(reader, *, snapshot, expected_draft_digest, handle,
                                 expected_request_digest, request, context_bytes):
    """Recompute the externally pinned candidate from a new live recheck."""
    if (type(request) is not RequestV2 or request.profile_id != PROFILE or request.operation != 'recovery'
            or not hex_value(expected_request_digest) or request.digest() != expected_request_digest
            or type(context_bytes) is not bytes or not 0 < len(context_bytes) <= MAX_CONTEXT_BYTES
            or digest(context_bytes) != request.observation_hash):
        reject()
    value = decode(context_bytes)
    if (type(value) is not dict or set(value) != {'schemaVersion', 'kind', 'intentNonce', 'expiresAt', *_BINDINGS}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1 or value['kind'] != KIND
            or value['expiresAt'] != request.expires_at or value['draftDigest'] != expected_draft_digest
            or canonical(value) != context_bytes):
        reject()
    current, context, review = _derive(reader, snapshot=snapshot, expected_draft_digest=expected_draft_digest,
        handle=handle, intent_nonce=value['intentNonce'], expires_at=request.expires_at)
    if current != request or context != context_bytes:
        reject()
    return review
