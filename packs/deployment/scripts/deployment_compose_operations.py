"""Pure, non-executable Compose batch operation description.

Inputs are evidence-shaped values, not trusted capabilities. In particular a
candidate reference is never a Docker container ID. A future writer must bind
it to a definitive create receipt before any subsequent operation.
The sequence does not prove that precreated candidates can coexist with old
containers without network-alias ambiguity; a real Engine test is required.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re

from deployment_compose_artifacts import ComposeArtifacts
from deployment_compose_target_artifacts import ComposeTargetArtifacts


DOMAIN = b'dev-workflow:compose-batch-operations:v1\0'
CANDIDATE_DOMAIN = b'dev-workflow:compose-batch-candidate-name:v1\0'
ID = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')


@dataclass(frozen=True)
class BaselineContainer:
    service: str
    container_id: str
    final_name: str
    image_id: str

    def __post_init__(self) -> None:
        if (not isinstance(self.service, str) or not NAME.fullmatch(self.service)
                or not isinstance(self.container_id, str) or not ID.fullmatch(self.container_id)
                or not isinstance(self.final_name, str) or not NAME.fullmatch(self.final_name)
                or not isinstance(self.image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.image_id)):
            raise ValueError('Invalid baseline container identity')


@dataclass(frozen=True)
class SymbolicOperation:
    phase: str
    service: str
    container_ref: str
    name: str | None = None
    image_id: str | None = None
    recipe_key_id: str | None = None
    recipe_hmac: str | None = None
    force: bool | None = None
    remove_volumes: bool | None = None


@dataclass(frozen=True)
class BatchOperations:
    schema_version: int
    operation_nonce: str
    baseline_observation_hash: str
    baseline_digest: str
    target_digest: str
    selected_services: tuple[str, ...]
    protected_services: tuple[str, ...]
    unverified_constraints: tuple[str, ...]
    dependencies: tuple[tuple[str, tuple[str, ...]], ...]
    operations: tuple[SymbolicOperation, ...]
    plan_hash: str
    structural_status: str = 'candidate-unverified'
    network_alias_safety: str = 'unverified-engine-test-required'
    execution_available: bool = False
    authority_granted: bool = False
    production_ready: bool = False


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _topological(selected: tuple[str, ...], dependencies: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    if type(dependencies) is not dict or set(dependencies) != set(selected):
        raise ValueError('Dependency scope differs from selected services')
    for service, deps in dependencies.items():
        if (type(deps) is not tuple or tuple(sorted(set(deps))) != deps
                or any(dep not in selected or dep == service for dep in deps)):
            raise ValueError('Invalid selected service dependencies')
    order, visiting, visited = [], set(), set()

    def visit(service: str) -> None:
        if service in visiting:
            raise ValueError('Selected service dependency cycle')
        if service in visited:
            return
        visiting.add(service)
        for dep in dependencies[service]:
            visit(dep)
        visiting.remove(service)
        visited.add(service)
        order.append(service)

    for service in selected:
        visit(service)
    return tuple(order)


def compile_operations(candidate: dict, baseline: tuple[BaselineContainer, ...],
                       old_artifacts: ComposeArtifacts, target_artifacts: ComposeTargetArtifacts,
                       operation_nonce: str, dependencies: dict[str, tuple[str, ...]],
                       baseline_observation_hash: str) -> BatchOperations:
    """Compile a finite symbolic sequence; does not construct Docker write bodies."""
    if type(operation_nonce) is not str or not ID.fullmatch(operation_nonce):
        raise ValueError('Invalid operation nonce')
    if type(baseline_observation_hash) is not str or not ID.fullmatch(baseline_observation_hash):
        raise ValueError('Invalid baseline observation hash')
    if (type(candidate) is not dict or candidate.get('schemaVersion') != 1
            or candidate.get('kind') != 'compose-batch-offline-plan'
            or candidate.get('structuralStatus') != 'candidate-unverified'
            or candidate.get('reasons') != [] or candidate.get('authorityGranted') is not False
            or candidate.get('executionAvailable') is not False
            or candidate.get('productionReady') is not False):
        raise ValueError('Expected non-executable candidate batch')
    selected, protected = candidate.get('selectedServices'), candidate.get('protectedServices')
    if (type(selected) is not list or not 1 <= len(selected) <= 32
            or type(protected) is not list
            or any(type(x) is not str or not NAME.fullmatch(x) for x in selected + protected)
            or selected != sorted(set(selected)) or protected != sorted(set(protected))
            or set(selected) & set(protected)):
        raise ValueError('Invalid selected/protected service scope')
    names = tuple(selected)
    unverified = candidate.get('unverifiedConstraints')
    if (type(unverified) is not list or unverified != sorted(set(unverified))
            or any(type(item) is not str or not NAME.fullmatch(item) for item in unverified)):
        raise ValueError('Invalid unverified constraint set')
    order = _topological(names, dependencies)
    normalized_dependencies = tuple((service, dependencies[service]) for service in names)
    if (candidate.get('startOrder') != list(order)
            or candidate.get('stopOrder') != list(reversed(order))):
        raise ValueError('Batch order differs from dependency graph')
    if (type(baseline) is not tuple or len(baseline) != len(names)
            or any(type(item) is not BaselineContainer for item in baseline)
            or tuple(item.service for item in baseline) != names
            or len({item.container_id for item in baseline}) != len(names)
            or len({item.final_name for item in baseline}) != len(names)):
        raise ValueError('Baseline identity differs from selected services')
    if (type(old_artifacts) is not ComposeArtifacts or type(target_artifacts) is not ComposeTargetArtifacts
            or tuple(item.service for item in old_artifacts.services) != names
            or tuple(item.service for item in target_artifacts.services) != names
            or len({item.source_sha for item in old_artifacts.services}) != 1):
        raise ValueError('Artifact scope or baseline source is not recoverable')
    if any(item.os != 'linux' or item.migration_mode != 'none' for item in old_artifacts.services):
        raise ValueError('Baseline platform or migration mode unsupported')
    if any(container.image_id != artifact.image_id
           for container, artifact in zip(baseline, old_artifacts.services)):
        raise ValueError('Baseline container image differs from artifact')
    by_old = {item.service: item for item in baseline}
    by_target = {item.service: item for item in target_artifacts.services}
    candidates = {service: 'dwc-' + hashlib.sha256(
        CANDIDATE_DOMAIN + operation_nonce.encode('ascii') + b'\0' + service.encode('ascii')
    ).hexdigest() for service in names}
    if set(candidates.values()) & {item.final_name for item in baseline}:
        raise ValueError('Candidate name conflicts with final name')
    ops = []
    for service in order:
        artifact = by_target[service]
        ops.append(SymbolicOperation('precreate-stopped', service, 'candidate:' + service,
                                     candidates[service], artifact.image_id,
                                     artifact.recipe_key_id, artifact.recipe_hmac))
    for service in reversed(order):
        ops.append(SymbolicOperation('stop-old', service, by_old[service].container_id))
    for service in reversed(order):
        ops.append(SymbolicOperation('remove-old', service, by_old[service].container_id,
                                     force=False, remove_volumes=False))
    for service in order:
        ops.append(SymbolicOperation('rename-candidate', service, 'candidate:' + service,
                                     by_old[service].final_name))
    for service in order:
        ops.append(SymbolicOperation('start-candidate', service, 'candidate:' + service))
        ops.append(SymbolicOperation('check-readiness', service, 'candidate:' + service))
    envelope = {'schemaVersion': 1, 'operationNonce': operation_nonce,
                'baselineObservationHash': baseline_observation_hash,
                'baselineDigest': old_artifacts.digest(), 'targetDigest': target_artifacts.digest(),
                'selectedServices': names, 'protectedServices': tuple(protected),
                'unverifiedConstraints': tuple(unverified),
                'dependencies': normalized_dependencies,
                'operations': [asdict(op) for op in ops]}
    digest = hashlib.sha256(DOMAIN + _canonical(envelope)).hexdigest()
    return BatchOperations(1, operation_nonce, baseline_observation_hash,
                           old_artifacts.digest(), target_artifacts.digest(), names,
                           tuple(protected), tuple(unverified), normalized_dependencies,
                           tuple(ops), digest)
