"""Versioned release intent values; parsing an intent never grants authority."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import urlsplit


DOMAIN = b'dev-workflow:release-request:v2\0'
MAX_JSON = 1024 * 1024
SHA = re.compile(r'[0-9a-f]{40}')
HASH = re.compile(r'[0-9a-f]{64}')
SEGMENT = re.compile(r'[A-Za-z0-9_.-]+')
TAG = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]*')
IDENTITY_FIELDS = {'provider_id', 'origin', 'project_id', 'project_path', 'source_sha'}
REQUEST_FIELDS = {'schema_version', 'operation', 'identity', 'host_id', 'profile_id',
                  'target_sha', 'tag', 'remote', 'provider_payload_json', 'plan_hash',
                  'policy_hash', 'expires_at', 'max_uses'}


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


def _path(value: str, provider: str) -> bool:
    if not isinstance(value, str) or len(value) > 255:
        return False
    parts = value.split('/')
    return (len(parts) == 2 if provider == 'github.com' else 2 <= len(parts) <= 8) and all(
        SEGMENT.fullmatch(part) and part not in ('.', '..') and not part.endswith('.lock') for part in parts)


def valid_tag(value: object) -> bool:
    return (isinstance(value, str) and len(value) <= 255 and TAG.fullmatch(value) is not None
            and '..' not in value
            and all(part not in ('', '.', '..') and not part.startswith('.')
                    and not part.endswith(('.', '.lock')) for part in value.split('/')))


@dataclass(frozen=True)
class ProviderIdentity:
    provider_id: str
    origin: str
    project_id: int
    project_path: str
    source_sha: str

    def __post_init__(self) -> None:
        if self.provider_id not in ('github.com', 'gitlab.com') or not _path(self.project_path, self.provider_id):
            raise ValueError('Unsupported provider or project path')
        if type(self.project_id) is not int or self.project_id <= 0:
            raise ValueError('Invalid immutable project ID')
        if not isinstance(self.source_sha, str) or not SHA.fullmatch(self.source_sha):
            raise ValueError('Invalid full source SHA')
        if not isinstance(self.origin, str):
            raise ValueError('Invalid origin')
        parsed = urlsplit(self.origin)
        if (parsed.scheme != 'https' or parsed.netloc != self.provider_id or parsed.query or parsed.fragment
                or parsed.path != '/' + self.project_path + '.git'
                or self.origin != 'https://' + self.provider_id + parsed.path):
            raise ValueError('Origin must be the exact canonical HTTPS project remote')

    @classmethod
    def from_dict(cls, value: object) -> ProviderIdentity:
        if not isinstance(value, dict) or set(value) != IDENTITY_FIELDS:
            raise ValueError('Invalid provider identity fields')
        return cls(**value)


@dataclass(frozen=True)
class RequestV2:
    schema_version: int
    operation: str
    identity: ProviderIdentity
    host_id: str
    profile_id: str
    target_sha: str
    tag: str
    remote: str
    provider_payload_json: str
    plan_hash: str
    policy_hash: str
    expires_at: str
    max_uses: int

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 2:
            raise ValueError('Unsupported request version')
        if self.operation not in ('remote-tag-push', 'remote-release-create'):
            raise ValueError('Unsupported release operation')
        if not isinstance(self.identity, ProviderIdentity) or self.remote != self.identity.origin:
            raise ValueError('Remote and provider identity differ')
        for value in (self.host_id, self.profile_id):
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value):
                raise ValueError('Invalid trusted host or profile identifier')
        if not isinstance(self.target_sha, str) or not SHA.fullmatch(self.target_sha):
            raise ValueError('Invalid full target SHA')
        if not valid_tag(self.tag):
            raise ValueError('Invalid tag')
        if not isinstance(_parse(self.provider_payload_json), dict):
            raise ValueError('Provider payload must be a canonical JSON object')
        if any(not isinstance(value, str) or not HASH.fullmatch(value)
               for value in (self.plan_hash, self.policy_hash)):
            raise ValueError('Invalid plan or policy hash')
        if not isinstance(self.expires_at, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', self.expires_at):
            raise ValueError('Invalid UTC expiry')
        try:
            datetime.strptime(self.expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        except ValueError as error:
            raise ValueError('Invalid UTC expiry') from error
        if type(self.max_uses) is not int or self.max_uses != 1:
            raise ValueError('Release v2 requests require one use')
        if len(_canonical(asdict(self))) > MAX_JSON:
            raise ValueError('Release request exceeds the bounded JSON size')

    def canonical_json(self) -> str:
        return _canonical(asdict(self))

    def digest(self) -> str:
        return hashlib.sha256(DOMAIN + self.canonical_json().encode('ascii')).hexdigest()

    def ensure_fresh(self, now: datetime, *, maximum_seconds: int = 3600) -> None:
        """Host-side precondition; syntax validation alone never authorizes a request."""
        if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None
                or type(maximum_seconds) is not int or not 0 < maximum_seconds <= 3600):
            raise ValueError('Invalid trusted time or expiry window')
        expiry = datetime.strptime(self.expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        seconds = (expiry - now.astimezone(timezone.utc)).total_seconds()
        if not 0 < seconds <= maximum_seconds:
            raise ValueError('Release request is expired or exceeds the trusted expiry window')

    @classmethod
    def from_json(cls, raw: str) -> RequestV2:
        value = _parse(raw)
        if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
            raise ValueError('Invalid release request fields')
        return cls(**{**value, 'identity': ProviderIdentity.from_dict(value['identity'])})
