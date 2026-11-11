"""Private initial-state reconstruction, without writer or recovery authority.

The embedding independently supplies all pins, paths and keys. Serialized data
cannot authenticate that embedding. No session, grant or lifecycle proof is
created; the returned bytes are private and must not be published.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import time

from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_live_ssh_v3_host import verify_private_capsule
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, _plain

MAX_CAPSULE = 4 * 1024 * 1024
FIELDS = {'bundle', 'request', 'publicReview', 'sourceModel', 'rawRows',
          'sourceFacts', 'targetInputs', 'baselineArtifacts', 'scopePolicy',
          'imageCatalog', 'phaseSnapshot', 'observationMaterial'}
EXPECTED = {'hello', 'source_sha', 'ssh_alias', 'policy', 'trusted_boot_id', 'trusted_bind_digest'}


def reject():
    raise ValueError('compose-executor-capture-v3-rejected') from None


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            reject()
        result[key] = value
    return result


def nonfinite(value):
    reject()


@dataclass(frozen=True)
class InitialCaptureV3:
    bundle_bytes: bytes = field(repr=False)
    request_bytes: bytes = field(repr=False)
    baseline_digest: str
    phase_digest: str
    authorityGranted: bool = field(default=False, init=False)
    productionReady: bool = field(default=False, init=False)


def reconstruct_initial_capture(capsule_bytes, *, expected, integrity_keys,
                                cas_root, cas_key, docker_socket,
                                daemon_version, docker_root):
    """Reopen retained bytes and double-read initial state over GET-only Unix HTTP.

    All keyword arguments are trusted embedding inputs, never capsule fields.
    The finite operation budget and final wall-clock check do not extend expiry.
    """
    store = None
    deadline = time.monotonic() + 30
    try:
        if (type(capsule_bytes) is not bytes or not 0 < len(capsule_bytes) <= MAX_CAPSULE
                or type(expected) is not dict or set(expected) != EXPECTED
                or type(integrity_keys) is not dict
                or set(integrity_keys) != {'config', 'image', 'declaration', 'archive', 'target'}
                or any(type(k) is not bytes or len(k) != 32 for k in integrity_keys.values())
                or type(docker_root) is not str or not docker_root.startswith('/')
                or type(daemon_version) is not dict or set(daemon_version) != {'Version', 'GitCommit'}
                or any(type(v) is not str or not v for v in daemon_version.values())):
            reject()
        capsule = json.loads(capsule_bytes, object_pairs_hook=pairs, parse_constant=nonfinite)
        if type(capsule) is not dict or set(capsule) != FIELDS or encode(capsule) != capsule_bytes:
            reject()
        bundle, request = verify_private_capsule(capsule, keys=integrity_keys, **expected)
        if request.operation != 'deploy':
            reject()
        request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=900)
        producer = TrustedPhaseStateProducerV3(socket_path=docker_socket,
            project=bundle.to_dict()['identity']['project'], daemon_id=request.daemon_id,
            container_ids=tuple(sorted(row['Id'] for row in capsule['rawRows'].values())))
        store = ComposeRecoveryStore(cas_root, key=cas_key)
        with producer.operation_scope(deadline):
            rows = producer.reload(store, bundle, read_json=producer._get,
                daemon_version=daemon_version, expected_docker_root=docker_root)
            guard = PhaseGuardV3(bundle, rows, read_json=producer._get,
                daemon_version=daemon_version, expected_docker_root=docker_root)
            phase = guard.capture_phase(dict(phase_index=0,
                operation=bundle.creation_operations()[0], receipts={}, completed_operations=[]))
        request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=900)
        if time.monotonic() >= deadline:
            reject()
        return InitialCaptureV3(encode(bundle.to_dict()), request.canonical_json().encode('ascii'),
            bundle.to_dict()['baselineStateDigest'],
            hashlib.sha256(encode(_plain(phase))).hexdigest())
    except Exception:
        reject()
    finally:
        if store is not None:
            try:
                store.close()
            except Exception:
                reject()
