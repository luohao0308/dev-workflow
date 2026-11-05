"""Provider-neutral deployment intent values. Parsing never authorizes execution."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import urlsplit


DOMAIN = b'dev-workflow:deployment-request:v2\0'
MAX_JSON = 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
TARGET_FIELDS = {'runtime', 'namespace', 'target_id'}
SOURCE_FIELDS = {'provider_id', 'origin', 'project_id', 'project_path', 'source_sha'}
REQUEST_FIELDS = {'schema_version', 'operation', 'profile_id', 'profile_version',
                  'source', 'target', 'environment', 'production', 'daemon_id',
                  'components', 'protected_components', 'before_hash', 'after_hash',
                  'artifact_digest', 'observation_hash', 'history_hash', 'host_id', 'plan_hash', 'policy_hash',
                  'expires_at', 'max_uses'}


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def _parse(raw: str) -> object:
    if not isinstance(raw, str) or len(raw) > MAX_JSON:
        raise ValueError('Invalid canonical JSON')
    try:
        value = json.loads(raw, object_pairs_hook=_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
        if raw != _canonical(value):
            raise ValueError('Noncanonical JSON')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as error:
        raise ValueError('Invalid canonical JSON') from error
    return value


def _id(value: object) -> bool:
    return isinstance(value, str) and ID.fullmatch(value) is not None


def _hash(value: object) -> bool:
    return isinstance(value, str) and HASH.fullmatch(value) is not None


@dataclass(frozen=True)
class SourceIdentity:
    provider_id: str
    origin: str
    project_id: int
    project_path: str
    source_sha: str

    def __post_init__(self) -> None:
        if self.provider_id not in ('github.com', 'gitlab.com') or not isinstance(self.project_path, str):
            raise ValueError('Unsupported source provider or path')
        parts = self.project_path.split('/')
        if ((self.provider_id == 'github.com' and len(parts) != 2)
                or (self.provider_id == 'gitlab.com' and not 2 <= len(parts) <= 8)):
            raise ValueError('Invalid source path')
        if any(not _id(part) or part in ('.', '..') or part.endswith('.lock') for part in parts):
            raise ValueError('Invalid source path')
        if type(self.project_id) is not int or self.project_id <= 0:
            raise ValueError('Invalid immutable project ID')
        if not isinstance(self.source_sha, str) or not re.fullmatch(r'[0-9a-f]{40}', self.source_sha):
            raise ValueError('Invalid full source SHA')
        if not isinstance(self.origin, str):
            raise ValueError('Invalid canonical origin')
        parsed = urlsplit(self.origin)
        if (parsed.scheme != 'https' or parsed.netloc != self.provider_id or parsed.query or parsed.fragment
                or parsed.path != '/' + self.project_path + '.git'
                or self.origin != 'https://' + self.provider_id + parsed.path):
            raise ValueError('Invalid canonical origin')

    @classmethod
    def from_dict(cls, value: object) -> SourceIdentity:
        if not isinstance(value, dict) or set(value) != SOURCE_FIELDS:
            raise ValueError('Invalid source identity fields')
        return cls(**value)


@dataclass(frozen=True)
class TargetIdentity:
    runtime: str
    namespace: str
    target_id: str

    def __post_init__(self) -> None:
        if self.runtime not in ('docker', 'compose') or not all(_id(v) for v in (self.namespace, self.target_id)):
            raise ValueError('Invalid deployment target identity')

    @classmethod
    def from_dict(cls, value: object) -> TargetIdentity:
        if not isinstance(value, dict) or set(value) != TARGET_FIELDS:
            raise ValueError('Invalid deployment target fields')
        return cls(**value)


@dataclass(frozen=True)
class RequestV2:
    schema_version: int
    operation: str
    profile_id: str
    profile_version: str
    source: SourceIdentity
    target: TargetIdentity
    environment: str
    production: bool
    daemon_id: str
    components: tuple[str, ...]
    protected_components: tuple[str, ...]
    before_hash: str
    after_hash: str
    artifact_digest: str
    observation_hash: str
    history_hash: str | None
    host_id: str
    plan_hash: str
    policy_hash: str
    expires_at: str
    max_uses: int

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 2:
            raise ValueError('Unsupported deployment request version')
        if self.operation not in ('deploy', 'rollback', 'recovery'):
            raise ValueError('Unsupported deployment operation')
        if not isinstance(self.source, SourceIdentity) or not isinstance(self.target, TargetIdentity):
            raise ValueError('Invalid deployment target')
        if type(self.production) is not bool or not isinstance(self.daemon_id, str) or not 1 <= len(self.daemon_id) <= 256 or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]*', self.daemon_id) is None:
            raise ValueError('Invalid production marker or daemon identity')
        if not all(_id(v) for v in (self.profile_id, self.profile_version, self.environment, self.host_id)):
            raise ValueError('Invalid profile, environment, or host identifier')
        if (type(self.components) is not tuple or not 1 <= len(self.components) <= 64
                or any(not _id(v) for v in self.components)
                or tuple(sorted(set(self.components))) != self.components):
            raise ValueError('Components must be a sorted unique nonempty tuple')
        if (type(self.protected_components) is not tuple or len(self.protected_components) > 64
                or any(not _id(v) for v in self.protected_components)
                or tuple(sorted(set(self.protected_components))) != self.protected_components
                or set(self.components) & set(self.protected_components)):
            raise ValueError('Protected components must be sorted, unique and disjoint')
        if not all(_hash(v) for v in (self.before_hash, self.after_hash, self.artifact_digest,
                                      self.observation_hash,
                                      self.plan_hash, self.policy_hash)):
            raise ValueError('Invalid immutable digest')
        if ((self.operation == 'deploy' and self.history_hash is not None)
                or (self.operation != 'deploy' and not _hash(self.history_hash))):
            raise ValueError('History digest does not match deployment operation')
        if not isinstance(self.expires_at, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', self.expires_at):
            raise ValueError('Invalid UTC expiry')
        try:
            datetime.strptime(self.expires_at, '%Y-%m-%dT%H:%M:%SZ')
        except ValueError as error:
            raise ValueError('Invalid UTC expiry') from error
        if type(self.max_uses) is not int or self.max_uses != 1:
            raise ValueError('Deployment requests require one use')
        if len(self.canonical_json()) > MAX_JSON:
            raise ValueError('Deployment request exceeds bounded JSON size')

    def canonical_json(self) -> str:
        return _canonical(asdict(self))

    def digest(self) -> str:
        return hashlib.sha256(DOMAIN + self.canonical_json().encode('ascii')).hexdigest()

    def ensure_fresh(self, now: datetime, *, maximum_seconds: int = 3600) -> None:
        """Trusted host precondition; caller must separately authenticate and consume a grant."""
        if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None
                or type(maximum_seconds) is not int or not 0 < maximum_seconds <= 3600):
            raise ValueError('Invalid trusted time or expiry window')
        expiry = datetime.strptime(self.expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        if not 0 < (expiry - now.astimezone(timezone.utc)).total_seconds() <= maximum_seconds:
            raise ValueError('Deployment request expired or exceeds trusted expiry window')

    @classmethod
    def from_json(cls, raw: str) -> RequestV2:
        value = _parse(raw)
        if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
            raise ValueError('Invalid deployment request fields')
        components = value['components']
        if not isinstance(components, list):
            raise ValueError('Invalid deployment components')
        protected = value['protected_components']
        if not isinstance(protected, list):
            raise ValueError('Invalid protected components')
        return cls(**{**value, 'source': SourceIdentity.from_dict(value['source']),
                      'target': TargetIdentity.from_dict(value['target']),
                      'components': tuple(components), 'protected_components': tuple(protected)})
