"""Host-local Compose read snapshot. This is not an execution authorization.

Only a separately provisioned host may construct this issuer. Its policy and TLS
paths must come from host configuration, never a repository or request payload.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import time
import weakref

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_collect import collect, image_catalog_digest
from deployment_compose_artifacts import ComposeArtifacts
from deployment_compose_image_catalog import verify_images
from deployment_compose_reader import ComposeDockerReader, ComposeReadPolicy
from deployment_prepare import registry_reference

_HEX = re.compile(r'[0-9a-f]{64}\Z')
_IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
_SHA = re.compile(r'[0-9a-f]{40}\Z')
_TEST_SEAM = object()


class ComposeObservation:
    """An opaque same-process snapshot, deliberately not JSON-serializable."""
    __slots__ = ('_issuer', '_boot', '_structure', '_private', '_instance', '_catalog', '_bind', '_expires', '_scope_kind', '_source_container_ids', '__weakref__')

    def __init__(self, issuer, boot, structure, private, instance, catalog, bind, expires, *, scope_kind='whole-project', source_container_ids=(), _token=None):
        if _token is not _TEST_SEAM:
            raise TypeError('host observation cannot be constructed externally')
        for key, value in (('_issuer', issuer), ('_boot', boot), ('_structure', structure),
                           ('_private', private), ('_instance', instance), ('_expires', expires)):
            object.__setattr__(self, key, value)
        object.__setattr__(self, '_catalog', catalog)
        object.__setattr__(self, '_bind', bind)
        object.__setattr__(self, '_scope_kind', scope_kind)
        object.__setattr__(self, '_source_container_ids', source_container_ids)

    def __setattr__(self, key, value):
        raise TypeError('host observation is immutable')

    def __reduce__(self):
        raise TypeError('host observation cannot be serialized')

    def __copy__(self):
        raise TypeError('host observation cannot be copied')

    def __deepcopy__(self, memo):
        raise TypeError('host observation cannot be copied')


def _protected_ids_valid(policy, live=None):
    """Optional host pins require complete, unique live scope IDs when enabled."""
    if 'protectedContainerIds' not in policy:
        return True
    pins = policy['protectedContainerIds']
    selected, protected = policy.get('selectedServices'), policy.get('protectedServices')
    if (type(selected) is not list or type(protected) is not list
            or any(type(name) is not str for name in selected + protected)
            or len(set(selected + protected)) != len(selected + protected)
            or type(pins) is not dict or set(pins) != set(protected)
            or any(type(cid) is not str or not _HEX.fullmatch(cid) for cid in pins.values())
            or len(set(pins.values())) != len(pins)):
        return False
    selected_pins = policy.get('selectedContainerIds', {})
    if (type(selected_pins) is not dict or not set(selected_pins).issubset(selected)
            or any(type(cid) is not str or not _HEX.fullmatch(cid) for cid in selected_pins.values())
            or len(set(selected_pins.values())) != len(selected_pins)
            or set(selected_pins.values()) & set(pins.values())):
        return False
    if live is None:
        return True
    ids = live.get('serviceContainerIds')
    return (type(ids) is dict and set(ids) == set(selected + protected)
            and all(type(cid) is str and _HEX.fullmatch(cid) for cid in ids.values())
            and len(set(ids.values())) == len(ids)
            and all(ids[name] == cid for name, cid in {**selected_pins, **pins}.items()))


class ComposeObservationHost:
    """Issue and recheck read snapshots from a pinned GET-only host gateway."""

    @property
    def scope_kind(self):
        return 'pinned-containers' if self.source_container_ids else 'whole-project'

    @property
    def source_container_ids(self):
        return self._source_container_ids

    @staticmethod
    def _validate_source_scope(scope_policy, ids):
        if (type(ids) is not tuple or len(ids) > 128
                or any(type(cid) is not str or not _HEX.fullmatch(cid) for cid in ids)
                or ids != tuple(sorted(set(ids)))):
            raise ValueError('reader-source-scope-mismatch')
        if not ids:
            return
        selected = scope_policy.get('selectedContainerIds')
        protected = scope_policy.get('protectedContainerIds')
        if (type(selected) is not dict or type(protected) is not dict
                or set(selected) != set(scope_policy.get('selectedServices', []))
                or set(protected) != set(scope_policy.get('protectedServices', []))
                or any(type(cid) is not str or not _HEX.fullmatch(cid)
                       for cid in list(selected.values()) + list(protected.values()))
                or tuple(sorted(list(selected.values()) + list(protected.values()))) != ids):
            raise ValueError('reader-source-scope-mismatch')

    def __init__(self, *, reader_policy: ComposeReadPolicy, scope_policy: dict,
                 baseline_artifacts: ComposeArtifacts, ca_file: Path, cert_file: Path, key_file: Path,
                 max_age_seconds: int = 30):
        if (type(reader_policy) is not ComposeReadPolicy or
                reader_policy.gateway_policy_hash is None or reader_policy.private_key_id is None or
                type(scope_policy) is not dict or type(baseline_artifacts) is not ComposeArtifacts or
                type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 300 or
                any(not isinstance(path, Path) or not path.is_absolute()
                    for path in (ca_file, cert_file, key_file))):
            raise ValueError('invalid-host-policy')
        if (scope_policy.get('project') != reader_policy.project or
                scope_policy.get('daemonId') != reader_policy.daemon_id or
                set(scope_policy.get('volumes', {})) != set(reader_policy.volume_names)):
            raise ValueError('reader-scope-mismatch')
        selected = scope_policy.get('selectedServices')
        protected = scope_policy.get('protectedServices')
        no_health = scope_policy.get('noHealthServices', [])
        image_ids = scope_policy.get('imageIds')
        if (type(selected) is not list or type(protected) is not list or
                type(no_health) is not list or any(type(item) is not str for item in no_health)
                or len(no_health) != len(set(no_health)) or
                not set(no_health).issubset(set(protected)) or
                type(image_ids) is not dict or set(image_ids) != set(selected + protected)
                or any(type(image) is not str or not _IMAGE.fullmatch(image)
                       for image in image_ids.values())):
            raise ValueError('invalid-host-health-policy')
        if not _protected_ids_valid(scope_policy):
            raise ValueError('invalid-host-protected-container-ids')
        baseline_sources = scope_policy.get('baselineSourceShas')
        if (type(baseline_sources) is not dict or set(baseline_sources) != set(selected) or
                any(type(source) is not str or not _SHA.fullmatch(source)
                    for source in baseline_sources.values()) or
                tuple(selected) != tuple(item.service for item in baseline_artifacts.services) or
                any(item.image_id != image_ids[item.service] or
                    item.source_sha != baseline_sources[item.service] or
                    item.os != 'linux' or item.migration_mode != 'none' or
                    item.config_key_id != reader_policy.private_key_id
                    for item in baseline_artifacts.services)):
            raise ValueError('host-artifact-scope-mismatch')
        protected_hmacs = scope_policy.get('protectedConfigHmacs')
        if (type(protected_hmacs) is not dict or set(protected_hmacs) != set(protected)
                or any(type(value) is not str or not _HEX.fullmatch(value)
                       for value in protected_hmacs.values())):
            raise ValueError('host-private-scope-mismatch')
        migrations = scope_policy.get('migrationDigests')
        if migrations is not None and (type(migrations) is not dict or
                migrations != {item.service: item.migration_digest for item in baseline_artifacts.services}):
            raise ValueError('host-migration-scope-mismatch')
        bind_paths = scope_policy.get('bindPaths', [])
        if (type(bind_paths) is not list or len(bind_paths) != reader_policy.bind_count
                or any(type(path) is not str for path in bind_paths)
                or bind_paths != sorted(set(bind_paths))):
            raise ValueError('host-bind-scope-mismatch')
        expected_bind = scope_policy.get('bindDigest')
        if ((reader_policy.bind_count and (type(expected_bind) is not str or
                                           not _HEX.fullmatch(expected_bind))) or
                (not reader_policy.bind_count and expected_bind is not None)):
            raise ValueError('host-bind-scope-mismatch')
        if bind_paths:
            mounts = scope_policy.get('mounts')
            if (type(mounts) is not dict or not set(selected).issubset(mounts)
                    or any(type(mounts[service]) is not list or
                           any(type(mount) is not dict for mount in mounts[service])
                           for service in selected)):
                raise ValueError('host-bind-scope-mismatch')
            sources = [mount.get('source') for service in selected for mount in mounts[service]
                       if mount.get('type') == 'bind']
            if (any(type(source) is not str for source in sources)
                    or sorted(set(sources)) != bind_paths
                    or any(mount.get('readOnly') is not True for service in selected
                           for mount in mounts[service] if mount.get('type') == 'bind')):
                raise ValueError('host-bind-scope-mismatch')
        self._validate_source_scope(scope_policy, reader_policy.source_container_ids)
        self._source_container_ids = reader_policy.source_container_ids
        self._policy = deepcopy(scope_policy)
        self._baseline_artifacts = baseline_artifacts
        self._reader = ComposeDockerReader(reader_policy, ca_file=ca_file,
                                            cert_file=cert_file, key_file=key_file,
                                            transport=None)
        self._max_age = max_age_seconds
        self._bind_count = reader_policy.bind_count
        self._collect = collect
        self._test_only = False
        self._issued = weakref.WeakKeyDictionary()

    @classmethod
    def _test_host(cls, reader, scope_policy, collector, baseline_artifacts, *, source_container_ids=(), _token=None):
        if _token is not _TEST_SEAM:
            raise TypeError('test seam is private')
        if not _protected_ids_valid(scope_policy):
            raise ValueError('invalid-host-protected-container-ids')
        cls._validate_source_scope(scope_policy, source_container_ids)
        host = object.__new__(cls)
        host._source_container_ids = source_container_ids
        host._reader, host._policy, host._collect, host._max_age = reader, deepcopy(scope_policy), collector, 30
        host._bind_count = 0
        host._baseline_artifacts = baseline_artifacts
        host._test_only = True
        host._issued = weakref.WeakKeyDictionary()
        return host

    def _read(self, deadline):
        if not self._test_only and (type(self._reader) is not ComposeDockerReader or
                                    self._reader._transport is not None or self._reader._context is None
                                    or type(self._reader.policy) is not ComposeReadPolicy
                                    or self._reader.policy.source_container_ids != self.source_container_ids):
            return None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            result = self._collect(self._reader, self._policy, max_seconds=remaining)
        except Exception:
            return None
        if type(result) is not dict or result.get('structuralStatus') != 'candidate-unverified':
            return None
        if any(type(result.get(key)) is not str or not _HEX.fullmatch(result[key])
               for key in ('privateDigest', 'instanceDigest', 'imageCatalogDigest')):
            return None
        bind_digest = result.get('bindDigest')
        if ((self._bind_count and (type(bind_digest) is not str or not _HEX.fullmatch(bind_digest)))
                or (not self._bind_count and bind_digest is not None)):
            return None
        if bind_digest != self._policy.get('bindDigest'):
            return None
        structure = result.get('structureDigest')
        if type(structure) is not str or not structure.startswith('sha256:') or not _HEX.fullmatch(structure[7:]):
            return None
        selected = self._policy.get('selectedServices')
        protected = self._policy.get('protectedServices')
        no_health = self._policy.get('noHealthServices', [])
        if (type(selected) is not list or not selected or type(protected) is not list or
                any(type(name) is not str for name in selected + protected) or
                len(set(selected + protected)) != len(selected + protected)):
            return None
        if not _protected_ids_valid(self._policy, result):
            return None
        states = result.get('serviceState')
        pinned_ids = self._policy.get('selectedContainerIds')
        if pinned_ids is not None and (type(result.get('serviceContainerIds')) is not dict
                or any(result['serviceContainerIds'].get(name) != cid
                       for name, cid in pinned_ids.items())):
            return None
        if result.get('serviceImages') != self._policy.get('imageIds'):
            return None
        expected_hmacs = {item.service: item.config_hmac for item in self._baseline_artifacts.services}
        expected_hmacs.update(self._policy.get('protectedConfigHmacs', {}))
        if result.get('serviceConfigHmacs') != expected_hmacs:
            return None
        if (type(states) is not dict or set(states) != set(selected + protected) or
                any(type(state) is not dict or state.get('running') is not True or
                    state.get('health') not in (('healthy', 'none') if service in no_health
                                                else ('healthy',))
                    for service, state in states.items())):
            return None
        try:
            images = {}
            projected = {}
            for service, image_id in sorted(self._policy['imageIds'].items()):
                if time.monotonic() >= deadline:
                    return None
                image = self._reader.get(f'/v1.45/images/{image_id}/json', deadline=deadline)
                if type(image) is not dict or set(image) != {'Id', 'Os', 'Architecture', 'RepoDigests'}:
                    return None
                digests = image['RepoDigests']
                architecture = image['Architecture']
                if (image['Id'] != image_id or image['Os'] != 'linux' or
                        type(architecture) is not str or
                        not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', architecture) or
                        type(digests) is not list or len(digests) > 128 or
                        len(set(digests)) != len(digests) or
                        any(type(ref) is not str or not registry_reference(ref) for ref in digests)):
                    return None
                normalized = {'os': 'linux', 'architecture': architecture,
                              'repoDigests': sorted(digests)}
                if image_id in images and images[image_id] != normalized:
                    return None
                images[image_id] = normalized
                if service in selected:
                    projected[service] = image
            verify_images(self._baseline_artifacts, projected)
            if image_catalog_digest(images) != result['imageCatalogDigest']:
                return None
        except Exception:
            return None
        if time.monotonic() >= deadline:
            return None
        boot = self._reader.gateway_boot_id
        if type(boot) is not str or not re.fullmatch(r'[0-9a-f]{32}', boot):
            return None
        try:
            if self._reader.gateway_info(deadline=deadline)['bootId'] != boot:
                return None
        except Exception:
            return None
        if time.monotonic() >= deadline:
            return None
        return (boot, structure, result['privateDigest'], result['instanceDigest'],
                result['imageCatalogDigest'], bind_digest)

    def issue(self):
        """Return opaque read evidence or None; no deploy/rollback permission."""
        start = time.monotonic()
        expires = start + self._max_age
        evidence = self._read(expires)
        if evidence is None:
            return None
        observation = ComposeObservation(self, *evidence, expires, scope_kind=self.scope_kind,
                                         source_container_ids=self.source_container_ids, _token=_TEST_SEAM)
        self._issued[observation] = (*evidence, expires)
        return observation

    def recheck(self, observation):
        """Fail closed on expiry, issuer mismatch, gateway restart or any drift."""
        if type(observation) is not ComposeObservation or observation._issuer is not self:
            return False
        if (observation._scope_kind != self.scope_kind or
                observation._source_container_ids != self.source_container_ids):
            return False
        issued = self._issued.get(observation)
        if (issued is None or issued != (observation._boot, observation._structure,
                                          observation._private, observation._instance, observation._catalog,
                                          observation._bind,
                                          observation._expires) or time.monotonic() >= issued[-1]):
            return False
        evidence = self._read(issued[-1])
        return evidence is not None and evidence == issued[:-1] and time.monotonic() < issued[-1]

    def commitment(self, observation):
        """Return a request binding only after rechecking a host-issued snapshot."""
        if self.scope_kind != 'whole-project':
            raise ValueError('whole-project-observation-required')
        if not self.recheck(observation):
            raise ValueError('fresh-issued-observation-required')
        evidence = self._issued[observation]
        value = {'boot': evidence[0], 'structure': evidence[1],
                 'private': evidence[2], 'instance': evidence[3],
                 'catalog': evidence[4], 'bind': evidence[5]}
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
        return hashlib.sha256(b'dev-workflow:compose-host-observation:v1\0' + raw).hexdigest()

    def retention_commitment(self, observation):
        """Bind pinned source evidence solely for retaining its existing resources."""
        if self.scope_kind == 'whole-project':
            return self.commitment(observation)
        if not self.recheck(observation):
            raise ValueError('fresh-issued-observation-required')
        evidence = self._issued[observation]
        value = {'boot': evidence[0], 'structure': evidence[1],
                 'private': evidence[2], 'instance': evidence[3],
                 'catalog': evidence[4], 'bind': evidence[5],
                 'scopeKind': self.scope_kind, 'containerIds': list(self.source_container_ids),
                 'projectCompletenessVerified': False}
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
        return hashlib.sha256(b'dev-workflow:compose-source-retention:v1\0' + raw).hexdigest()
