"""Explicit recipe-v3 target commitments; pure preparation, never authority.

This separate profile cannot upgrade a v1 approval. Fresh observation, HMAC
verification and authorization remain responsibilities of the trusted host.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from deployment_compose_target_artifacts import ARTIFACT_FIELDS, ServiceTargetArtifact
from deployment_contract_v2 import RequestV2

PROFILE = 'compose-application-batch-v2'
PROFILE_VERSION = '2'
DOMAIN = b'dev-workflow:compose-target-artifacts:v2\0'
MAX_JSON = 1024 * 1024
ERROR = 'invalid-compose-target-v2'
FIELDS = ARTIFACT_FIELDS | {'recipe_schema_version'}
MANIFEST_FIELDS = {'schema_version', 'profile_id', 'profile_version', 'services'}


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(ERROR)
        value[key] = item
    return value


@dataclass(frozen=True)
class ServiceTargetArtifactV2:
    service: str
    source_sha: str
    registry_digest: str
    image_id: str
    os: str
    architecture: str
    recipe_key_id: str
    recipe_hmac: str
    migration_digest: str
    migration_mode: str
    recipe_schema_version: int

    def __post_init__(self) -> None:
        try:
            common = {key: getattr(self, key) for key in ARTIFACT_FIELDS}
            if (any(type(value) is not str for value in common.values())
                    or type(self.recipe_schema_version) is not int
                    or self.recipe_schema_version != 3
                    or self.os != 'linux' or self.architecture not in ('amd64', 'arm64')):
                raise ValueError(ERROR)
            ServiceTargetArtifact(**common)
        except (TypeError, ValueError) as error:
            raise ValueError(ERROR) from error

    @classmethod
    def from_dict(cls, value: object) -> ServiceTargetArtifactV2:
        if type(value) is not dict or set(value) != FIELDS:
            raise ValueError(ERROR)
        return cls(**value)


@dataclass(frozen=True)
class ComposeTargetArtifactsV2:
    schema_version: int
    profile_id: str
    profile_version: str
    services: tuple[ServiceTargetArtifactV2, ...]

    def __post_init__(self) -> None:
        if (type(self.schema_version) is not int or self.schema_version != 2
                or type(self.profile_id) is not str or self.profile_id != PROFILE
                or type(self.profile_version) is not str or self.profile_version != PROFILE_VERSION
                or type(self.services) is not tuple or not 1 <= len(self.services) <= 32
                or any(type(item) is not ServiceTargetArtifactV2 for item in self.services)):
            raise ValueError(ERROR)
        if (tuple(sorted({item.service for item in self.services})) != tuple(item.service for item in self.services)
                or len({item.source_sha for item in self.services}) != 1
                or len(self.canonical_json()) > MAX_JSON):
            raise ValueError(ERROR)

    def canonical_json(self) -> str:
        return _canonical(asdict(self))

    def digest(self) -> str:
        return hashlib.sha256(DOMAIN + self.canonical_json().encode('ascii')).hexdigest()

    @classmethod
    def from_json(cls, raw: str) -> ComposeTargetArtifactsV2:
        try:
            if type(raw) is not str or len(raw) > MAX_JSON:
                raise ValueError(ERROR)
            value = json.loads(raw, object_pairs_hook=_object,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError(ERROR)))
            if (raw != _canonical(value) or type(value) is not dict
                    or set(value) != MANIFEST_FIELDS or type(value['services']) is not list):
                raise ValueError(ERROR)
            return cls(value['schema_version'], value['profile_id'], value['profile_version'],
                       tuple(ServiceTargetArtifactV2.from_dict(item) for item in value['services']))
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as error:
            raise ValueError(ERROR) from error


def verify_target_request_v2(request: RequestV2, manifest: ComposeTargetArtifactsV2) -> None:
    """Verify exact deploy scope only; no freshness or execution authorization."""
    if type(request) is not RequestV2 or type(manifest) is not ComposeTargetArtifactsV2:
        raise ValueError(ERROR)
    if (request.target.runtime != 'compose' or request.profile_id != PROFILE
            or request.profile_version != PROFILE_VERSION or request.operation != 'deploy'
            or request.history_hash is not None or type(request.max_uses) is not int or request.max_uses != 1
            or request.components != tuple(item.service for item in manifest.services)
            or any(item.source_sha != request.source.source_sha for item in manifest.services)
            or request.artifact_digest != manifest.digest() or request.after_hash != manifest.digest()):
        raise ValueError(ERROR)
