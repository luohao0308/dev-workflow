"""Bounded Compose service artifacts. These values provide no execution authority."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re

from deployment_contract_v2 import RequestV2
from deployment_prepare import registry_reference


DOMAIN = b'dev-workflow:compose-artifacts:v1\0'
MAX_JSON = 1024 * 1024
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
ARTIFACT_FIELDS = {'service', 'source_sha', 'registry_digest', 'image_id',
                   'os', 'architecture', 'config_key_id', 'config_hmac',
                   'migration_digest', 'migration_mode'}
MANIFEST_FIELDS = {'schema_version', 'services'}


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate artifact JSON field')
        value[key] = item
    return value


@dataclass(frozen=True)
class ServiceArtifact:
    service: str
    source_sha: str
    registry_digest: str
    image_id: str
    os: str
    architecture: str
    config_key_id: str
    config_hmac: str
    migration_digest: str
    migration_mode: str

    def __post_init__(self) -> None:
        if not isinstance(self.service, str) or not ID.fullmatch(self.service):
            raise ValueError('Invalid service')
        if not isinstance(self.source_sha, str) or not SHA.fullmatch(self.source_sha):
            raise ValueError('Invalid source SHA')
        if not registry_reference(self.registry_digest):
            raise ValueError('Expected immutable registry digest')
        if not isinstance(self.image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.image_id):
            raise ValueError('Invalid observed image ID')
        if self.os not in ('linux', 'windows') or not isinstance(self.architecture, str) or not ID.fullmatch(self.architecture):
            raise ValueError('Invalid image platform')
        if not isinstance(self.config_key_id, str) or not ID.fullmatch(self.config_key_id):
            raise ValueError('Invalid host-private commitment key ID')
        if not isinstance(self.config_hmac, str) or not HASH.fullmatch(self.config_hmac):
            raise ValueError('Invalid host-private configuration HMAC')
        if not isinstance(self.migration_digest, str) or not HASH.fullmatch(self.migration_digest):
            raise ValueError('Invalid migration set digest')
        if self.migration_mode not in ('none', 'forward', 'reverse'):
            raise ValueError('Invalid migration mode')

    @classmethod
    def from_dict(cls, value: object) -> ServiceArtifact:
        if type(value) is not dict or set(value) != ARTIFACT_FIELDS:
            raise ValueError('Invalid service artifact fields')
        return cls(**value)


@dataclass(frozen=True)
class ComposeArtifacts:
    schema_version: int
    services: tuple[ServiceArtifact, ...]

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError('Unsupported Compose artifact version')
        if (type(self.services) is not tuple or not 1 <= len(self.services) <= 64
                or any(type(item) is not ServiceArtifact for item in self.services)
                or tuple(sorted({item.service for item in self.services})) != tuple(item.service for item in self.services)):
            raise ValueError('Services must be sorted, unique, and nonempty')
        if len(self.canonical_json()) > MAX_JSON:
            raise ValueError('Compose artifact manifest exceeds size limit')

    def canonical_json(self) -> str:
        return _canonical(asdict(self))

    def digest(self) -> str:
        return hashlib.sha256(DOMAIN + self.canonical_json().encode('ascii')).hexdigest()

    @classmethod
    def from_json(cls, raw: str) -> ComposeArtifacts:
        if type(raw) is not str or len(raw) > MAX_JSON:
            raise ValueError('Invalid bounded artifact JSON')
        try:
            value = json.loads(raw, object_pairs_hook=_object,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
            if raw != _canonical(value):
                raise ValueError('Noncanonical artifact JSON')
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as error:
            raise ValueError('Invalid canonical artifact JSON') from error
        if type(value) is not dict or set(value) != MANIFEST_FIELDS or type(value['services']) is not list:
            raise ValueError('Invalid artifact manifest fields')
        return cls(value['schema_version'], tuple(ServiceArtifact.from_dict(item) for item in value['services']))


def verify_request_artifacts(request: RequestV2, manifest: ComposeArtifacts) -> None:
    """Compare selected services and commitment; caller must separately trust both inputs."""
    if type(request) is not RequestV2 or type(manifest) is not ComposeArtifacts:
        raise ValueError('Invalid request or artifact manifest')
    if (request.target.runtime != 'compose' or request.profile_id != 'compose-application-batch-v1'
            or request.profile_version != '1' or request.operation != 'deploy'):
        raise ValueError('Unsupported Compose artifact request profile or operation')
    if request.components != tuple(item.service for item in manifest.services):
        raise ValueError('Artifact services differ from selected request components')
    if any(item.source_sha != request.source.source_sha for item in manifest.services):
        raise ValueError('Artifact source SHA differs from request source')
    if any(item.os != 'linux' or item.migration_mode != 'none' for item in manifest.services):
        raise ValueError('Compose application batch v1 requires Linux images and no migrations')
    if request.artifact_digest != manifest.digest():
        raise ValueError('Artifact digest differs from request')
