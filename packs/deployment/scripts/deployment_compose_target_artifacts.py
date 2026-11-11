"""Bounded target-image commitments for Compose batches; never execution authority.

Target recipes use a separate key space and digest domain from observed artifacts.
The host must independently verify their private HMACs before using a recipe.
RequestV2 binds one *target* source commit for the selected batch, including an
older target commit during rollback. Mixed-source historical targets require a
future request version and are rejected by this first profile.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re

from deployment_contract_v2 import RequestV2
from deployment_prepare import registry_reference


DOMAIN = b'dev-workflow:compose-target-artifacts:v1\0'
MAX_JSON = 1024 * 1024
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
ARTIFACT_FIELDS = {'service', 'source_sha', 'registry_digest', 'image_id',
                   'os', 'architecture', 'recipe_key_id', 'recipe_hmac',
                   'migration_digest', 'migration_mode'}
MANIFEST_FIELDS = {'schema_version', 'services'}


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate target artifact JSON field')
        value[key] = item
    return value


@dataclass(frozen=True)
class ServiceTargetArtifact:
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

    def __post_init__(self) -> None:
        if not isinstance(self.service, str) or not ID.fullmatch(self.service):
            raise ValueError('Invalid target service')
        if not isinstance(self.source_sha, str) or not SHA.fullmatch(self.source_sha):
            raise ValueError('Invalid target source SHA')
        if not isinstance(self.registry_digest, str) or not registry_reference(self.registry_digest):
            raise ValueError('Expected immutable target registry digest')
        if not isinstance(self.image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.image_id):
            raise ValueError('Invalid target image ID')
        if self.os != 'linux' or not isinstance(self.architecture, str) or not ID.fullmatch(self.architecture):
            raise ValueError('Target image must have a Linux platform')
        if not isinstance(self.recipe_key_id, str) or not ID.fullmatch(self.recipe_key_id):
            raise ValueError('Invalid private recipe key ID')
        if not isinstance(self.recipe_hmac, str) or not HASH.fullmatch(self.recipe_hmac):
            raise ValueError('Invalid private recipe HMAC')
        if not isinstance(self.migration_digest, str) or not HASH.fullmatch(self.migration_digest):
            raise ValueError('Invalid migration set digest')
        if self.migration_mode != 'none':
            raise ValueError('Compose batch v1 does not execute migrations')

    @classmethod
    def from_dict(cls, value: object) -> ServiceTargetArtifact:
        if type(value) is not dict or set(value) != ARTIFACT_FIELDS:
            raise ValueError('Invalid target service artifact fields')
        return cls(**value)


@dataclass(frozen=True)
class ComposeTargetArtifacts:
    schema_version: int
    services: tuple[ServiceTargetArtifact, ...]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError('Unsupported Compose target artifact version')
        if (type(self.services) is not tuple or not 1 <= len(self.services) <= 32
                or any(type(item) is not ServiceTargetArtifact for item in self.services)
                or tuple(sorted({item.service for item in self.services})) != tuple(item.service for item in self.services)):
            raise ValueError('Target services must be sorted, unique, and nonempty')
        if len(self.canonical_json()) > MAX_JSON:
            raise ValueError('Compose target artifact manifest exceeds size limit')

    def canonical_json(self) -> str:
        return _canonical(asdict(self))

    def digest(self) -> str:
        return hashlib.sha256(DOMAIN + self.canonical_json().encode('ascii')).hexdigest()

    @classmethod
    def from_json(cls, raw: str) -> ComposeTargetArtifacts:
        if type(raw) is not str or len(raw) > MAX_JSON:
            raise ValueError('Invalid bounded target artifact JSON')
        try:
            value = json.loads(raw, object_pairs_hook=_object,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
            if raw != _canonical(value):
                raise ValueError('Noncanonical target artifact JSON')
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as error:
            raise ValueError('Invalid canonical target artifact JSON') from error
        if type(value) is not dict or set(value) != MANIFEST_FIELDS or type(value['services']) is not list:
            raise ValueError('Invalid target artifact manifest fields')
        return cls(value['schema_version'], tuple(ServiceTargetArtifact.from_dict(item) for item in value['services']))


def verify_target_request(request: RequestV2, manifest: ComposeTargetArtifacts) -> None:
    """Bind a request to a target manifest; no trust or approval is conferred."""
    if type(request) is not RequestV2 or type(manifest) is not ComposeTargetArtifacts:
        raise ValueError('Invalid request or target artifact manifest')
    if (request.target.runtime != 'compose' or request.profile_id != 'compose-application-batch-v1'
            or request.profile_version != '1' or request.operation not in ('deploy', 'rollback')):
        raise ValueError('Unsupported Compose target request profile or operation')
    if request.components != tuple(item.service for item in manifest.services):
        raise ValueError('Target services differ from selected request components')
    if any(item.source_sha != request.source.source_sha for item in manifest.services):
        raise ValueError('Target source SHA differs from request source')
    if request.artifact_digest != manifest.digest():
        raise ValueError('Target artifact digest differs from request')
