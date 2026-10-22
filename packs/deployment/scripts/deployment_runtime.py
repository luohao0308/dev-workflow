#!/usr/bin/env python3
"""Trusted, read-only Docker observations; exported JSON is never authority.

Configuration projection v2 hashes (without exporting) the inspected Config,
HostConfig, Path, Args, live networks, and Docker-managed file paths and bytes. Config includes environment and command values; these
values, raw API responses and transport exceptions never appear in exports.
Only an immutable-image/no-mount/read-only-root filesystem profile is complete.
The host supplies catalog and TLS trust directly, never through project/CLI data.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import http.client
from io import BytesIO
import json
from pathlib import Path
import re
import secrets
import ssl
import socket
import sys
import tarfile
import threading
import time
from urllib.parse import urlencode, urlsplit

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import deployment_spec
HEX = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'sha256:[0-9a-f]{64}\Z')
CONTAINER = re.compile(r'[0-9a-f]{64}\Z')
SHA = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
SEMVER = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
                    r'(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
                    r'(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?'
                    r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z')
MAX_RESPONSE = 8 * 1024 * 1024
MAX_MANAGED_FILE = 65536
MANAGED_FILES = {'hosts': 'HostsPath', 'hostname': 'HostnamePath', 'resolv.conf': 'ResolvConfPath'}


class RuntimeCollectionError(ValueError):
    """Sanitized failure suitable for a local diagnostic."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def utcnow():
    return datetime.now(timezone.utc)


def deadline_watchdog(peer, deadline):
    """Bound status/header reads as well as body inactivity on one connection."""
    def abort():
        try:
            peer.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    timer = threading.Timer(max(0, deadline - time.monotonic()), abort)
    timer.daemon = True
    timer.start()
    return timer


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeCollectionError('Duplicate JSON field')
        result[key] = value
    return result


def parse_json(value):
    return json.loads(value, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(RuntimeCollectionError('Invalid JSON number')))


@dataclass(frozen=True)
class RuntimePolicy:
    endpoint: str
    server_certificate_sha256: str
    daemon_id: str
    repository: str
    environment: str
    target: str
    production: bool
    project: str
    components: tuple[str, ...]
    catalog_json: str
    maximum_age: int = 3600
    capture_deadline: int = 30
    specifications_json: str | None = None

    def __post_init__(self):
        try:
            endpoint = urlsplit(self.endpoint)
            valid = (endpoint.scheme == 'https' and endpoint.hostname and not endpoint.username
                     and not endpoint.password and endpoint.path in ('', '/')
                     and not endpoint.query and not endpoint.fragment and endpoint.port != 0
                     and not any(c.isspace() or ord(c) < 32 for c in self.endpoint))
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise RuntimeCollectionError('Runtime endpoint must be an explicit HTTPS origin')
        if not isinstance(self.server_certificate_sha256, str) or not HEX.fullmatch(self.server_certificate_sha256):
            raise RuntimeCollectionError('A SHA256 peer certificate pin is required')
        if not isinstance(self.daemon_id, str) or not self.daemon_id or len(self.daemon_id) > 256:
            raise RuntimeCollectionError('An explicit daemon identity is required')
        if not isinstance(self.repository, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', self.repository):
            raise RuntimeCollectionError('An owner/name repository is required')
        if any(not isinstance(v, str) or not NAME.fullmatch(v) for v in (self.environment, self.target, self.project)):
            raise RuntimeCollectionError('Invalid runtime scope')
        if (type(self.production) is not bool or type(self.components) is not tuple or not self.components
                or any(not isinstance(v, str) or not NAME.fullmatch(v) for v in self.components)
                or len(set(self.components)) != len(self.components)):
            raise RuntimeCollectionError('Explicit unique components and production scope are required')
        if (type(self.maximum_age) is not int or not 1 <= self.maximum_age <= 86400
                or type(self.capture_deadline) is not int or not 1 <= self.capture_deadline <= 300):
            raise RuntimeCollectionError('Invalid runtime observation time limits')
        _catalog(self)
        if self.specifications_json is not None:
            try:
                specs = deployment_spec.parse_specifications(self.specifications_json)
                if any(component not in self.components for component, _ in specs):
                    raise ValueError
            except (ValueError, TypeError):
                raise RuntimeCollectionError('Invalid trusted specification catalog') from None

    def identity_hash(self):
        value = asdict(self)
        value['catalog_json'] = parse_json(self.catalog_json)
        if self.specifications_json is None:
            # Preserve the exact observed-v2 policy identity for existing hosts.
            del value['specifications_json']
        else:
            value['specifications_json'] = parse_json(self.specifications_json)
        return digest(value)


def _registry(value):
    if not isinstance(value, str) or value.count('@') != 1:
        return False
    name, pin = value.split('@')
    if not ID.fullmatch(pin) or '/' not in name or len(name) > 255:
        return False
    authority, path = name.split('/', 1)
    host, separator, port = authority.partition(':')
    label = r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?'
    if not re.fullmatch(label + r'(?:\.' + label + r')*', host):
        return False
    if separator and (not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535):
        return False
    segment = r'[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*'
    return all(re.fullmatch(segment, p) for p in path.split('/'))


def _catalog(policy):
    try:
        catalog = parse_json(policy.catalog_json)
        if (not isinstance(catalog, dict) or set(catalog) != {'schemaVersion', 'images'}
                or type(catalog['schemaVersion']) is not int or catalog['schemaVersion'] != 1
                or not isinstance(catalog['images'], list)):
            raise ValueError
        result = {}
        fields = {'component', 'imageId', 'repository', 'sourceSha', 'version', 'os', 'architecture', 'artifact', 'migration'}
        for entry in catalog['images']:
            if not isinstance(entry, dict) or set(entry) != fields:
                raise ValueError
            if (entry['component'] not in policy.components or entry['repository'] != policy.repository
                    or not isinstance(entry['imageId'], str) or not ID.fullmatch(entry['imageId'])
                    or not isinstance(entry['sourceSha'], str) or not SHA.fullmatch(entry['sourceSha'])
                    or not isinstance(entry['version'], str) or not SEMVER.fullmatch(entry['version'])
                    or any(not isinstance(entry[k], str) or not NAME.fullmatch(entry[k]) for k in ('os', 'architecture'))):
                raise ValueError
            migration = entry['migration']
            if (not isinstance(migration, dict) or set(migration) != {'mode', 'version'}
                    or migration['mode'] not in ('none', 'unknown') or migration['version'] is not None):
                raise ValueError
            artifact = entry['artifact']
            if not isinstance(artifact, dict):
                raise ValueError
            if artifact.get('kind') == 'local-build':
                if (set(artifact) != {'kind', 'imageId', 'buildSourceSha'}
                        or artifact['imageId'] != entry['imageId'] or artifact['buildSourceSha'] != entry['sourceSha']):
                    raise ValueError
            elif artifact.get('kind') == 'registry':
                if set(artifact) != {'kind', 'ref'} or not _registry(artifact['ref']):
                    raise ValueError
            else:
                raise ValueError
            key = (entry['component'], entry['imageId'])
            if key in result:
                raise ValueError
            result[key] = entry
        return result
    except (ValueError, TypeError, KeyError, RecursionError):
        raise RuntimeCollectionError('Invalid trusted runtime catalog') from None


class DockerTLSClient:
    """Explicit mTLS, verified hostname and peer pin before every GET request.

    The fixed endpoint must sit behind trusted GET-only enforcement.
    transport(path) is a trusted embedding/test hook, never a CLI facility;
    archive routes return bytes and JSON routes return JSON-compatible values.
    """
    def __init__(self, policy, *, ca_file: Path, cert_file: Path, key_file: Path, timeout=10, transport=None):
        if (not isinstance(policy, RuntimePolicy) or type(timeout) not in (int, float)
                or not 0 < timeout <= 300):
            raise RuntimeCollectionError('Invalid Docker client policy or timeout')
        self.policy, self.timeout, self._transport = policy, timeout, transport
        self._context = None
        if transport is None:
            try:
                context = ssl.create_default_context(cafile=str(ca_file))
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                context.keylog_filename = None
                context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
                self._context = context
            except (OSError, ValueError, ssl.SSLError):
                raise RuntimeCollectionError('Runtime TLS credentials could not be loaded') from None
        self.list_path = '/v1.45/containers/json?' + urlencode({'all': '1', 'filters': canonical({'label': ['com.docker.compose.project=' + policy.project]})})

    def get(self, path, *, deadline=None):
        if not (path in ('/v1.45/info', self.list_path)
                or re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/json', path)
                or re.fullmatch(r'/v1\.45/images/sha256:[0-9a-f]{64}/json', path)):
            raise RuntimeCollectionError('Docker read route refused')
        try:
            return parse_json(self._request(path, deadline=deadline).decode('utf-8'))
        except Exception:
            raise RuntimeCollectionError('Trusted Docker read failed') from None

    def managed_file(self, container_id, name, *, deadline=None) -> bytes:
        """Read only a fixed Docker-managed /etc file; never a host inspect path."""
        if (not isinstance(container_id, str) or not CONTAINER.fullmatch(container_id)
                or not isinstance(name, str) or name not in MANAGED_FILES):
            raise RuntimeCollectionError('Docker managed file route refused')
        path = '/v1.45/containers/' + container_id + '/archive?' + urlencode({'path': '/etc/' + name})
        try:
            raw = self._request(path, deadline=deadline, binary=True)
            with tarfile.open(fileobj=BytesIO(raw), mode='r:') as archive:
                member = archive.next()
                if (member is None or member.name != name or not member.isreg()
                        or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                        or member.linkname or member.sparse is not None or member.pax_headers
                        or not 0 <= member.size <= MAX_MANAGED_FILE):
                    raise ValueError
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError
                with stream:
                    content = stream.read(MAX_MANAGED_FILE + 1)
                if len(content) != member.size or archive.next() is not None:
                    raise ValueError
            if deadline is not None and time.monotonic() >= deadline:
                raise ValueError
            return content
        except Exception:
            raise RuntimeCollectionError('Trusted Docker managed file read failed') from None

    def _request(self, path, *, deadline=None, binary=False):
        """Shared pinned mTLS request for internally allowlisted JSON/binary GETs."""
        connection = None
        response = None
        watchdog = None
        try:
            remaining = self.timeout if deadline is None else min(self.timeout, deadline - time.monotonic())
            if remaining <= 0:
                raise RuntimeCollectionError('Runtime capture deadline exceeded')
            if self._transport is not None:
                # Round-trip to detach injected mutable objects and reject non-JSON values.
                value = self._transport(path)
                raw = value if binary else canonical(value).encode()
                if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE:
                    raise RuntimeCollectionError('Runtime response exceeds limit')
                return raw
            endpoint = urlsplit(self.policy.endpoint)
            connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443,
                                                     timeout=remaining, context=self._context)
            connection.connect()
            peer = connection.sock
            certificate = peer.getpeercert(binary_form=True)
            if hashlib.sha256(certificate).hexdigest() != self.policy.server_certificate_sha256:
                raise RuntimeCollectionError('Runtime peer certificate pin mismatch')
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeCollectionError('Runtime capture deadline exceeded')
                peer.settimeout(min(self.timeout, remaining))
            read_deadline = min(deadline if deadline is not None else float('inf'),
                                time.monotonic() + self.timeout)
            watchdog = deadline_watchdog(peer, read_deadline)
            connection.request('GET', path, headers={'Accept': 'application/x-tar' if binary else 'application/json'})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeCollectionError('Runtime read failed')
            raw = bytearray()
            while len(raw) <= MAX_RESPONSE:
                remaining = read_deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeCollectionError('Runtime read deadline exceeded')
                if connection.sock is not None:
                    connection.sock.settimeout(min(self.timeout, remaining))
                chunk = response.read1(min(65536, MAX_RESPONSE + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > MAX_RESPONSE:
                raise RuntimeCollectionError('Runtime response exceeds limit')
            return bytes(raw)
        except Exception:
            # Neither Docker error bodies nor paths/credentials from exceptions escape.
            raise RuntimeCollectionError('Trusted Docker read failed') from None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()


@dataclass(frozen=True)
class RuntimeObservation:
    payload_json: str
    evidence_hash: str
    state_hash: str
    policy_hash: str
    captured_at: str

    def to_dict(self):
        return parse_json(self.payload_json)

    def snapshot(self):
        payload = self.to_dict()
        if payload.get('complete') is not True or not isinstance(payload.get('snapshot'), dict):
            raise RuntimeCollectionError('Incomplete runtime evidence has no usable snapshot')
        return payload['snapshot']


class TrustedDockerCollector:
    def __init__(self, policy, client):
        if not isinstance(policy, RuntimePolicy) or not isinstance(client, DockerTLSClient) or client.policy != policy:
            raise RuntimeCollectionError('Runtime client policy mismatch')
        self.policy, self.client = policy, client
        self._policy_hash = policy.identity_hash()
        self._catalog = _catalog(policy)
        self._specifications = (None if policy.specifications_json is None else
                                deployment_spec.parse_specifications(policy.specifications_json))
        # Object identity and retained references prevent exported/reconstructed objects
        # (including dataclass copies) from acquiring in-process issuance authority.
        self._issued = {}
        self._issuance_lock = threading.Lock()
        self._sequence = 0

    def _read(self, path, deadline):
        if time.monotonic() >= deadline:
            raise RuntimeCollectionError('Runtime capture deadline exceeded')
        result = self.client.get(path, deadline=deadline)
        if time.monotonic() >= deadline:
            raise RuntimeCollectionError('Runtime capture deadline exceeded')
        return result

    def _round(self, deadline):
        info = self._read('/v1.45/info', deadline)
        if not isinstance(info, dict) or info.get('ID') != self.policy.daemon_id:
            raise RuntimeCollectionError('Runtime daemon identity mismatch')
        listed = self._read(self.client.list_path, deadline)
        if not isinstance(listed, list):
            raise RuntimeCollectionError('Invalid runtime container list')
        selected = {name: [] for name in self.policy.components}
        seen = set()
        for item in listed:
            if not isinstance(item, dict) or not isinstance(item.get('Id'), str) or not CONTAINER.fullmatch(item['Id']) or item['Id'] in seen:
                raise RuntimeCollectionError('Invalid or duplicate runtime container identity')
            seen.add(item['Id'])
            listed_labels = item.get('Labels')
            if (not isinstance(listed_labels, dict)
                    or listed_labels.get('com.docker.compose.project') != self.policy.project):
                raise RuntimeCollectionError('Listed container is outside trusted project scope')
            listed_service = listed_labels.get('com.docker.compose.service')
            if listed_service not in selected:
                continue
            container = self._read('/v1.45/containers/' + item['Id'] + '/json', deadline)
            if not isinstance(container, dict) or container.get('Id') != item['Id']:
                raise RuntimeCollectionError('Runtime container identity mismatch')
            config = container.get('Config')
            labels = config.get('Labels') if isinstance(config, dict) else None
            # Scope checked on every actual inspect, never trusted from list labels.
            if not isinstance(labels, dict) or labels.get('com.docker.compose.project') != self.policy.project:
                raise RuntimeCollectionError('Inspected container is outside trusted project scope')
            service = labels.get('com.docker.compose.service')
            if service not in selected or service != listed_service:
                raise RuntimeCollectionError('Inspected container is outside trusted component scope')
            selected[service].append(container)
        if any(len(items) != 1 for items in selected.values()):
            raise RuntimeCollectionError('Runtime requires exactly one container per component')
        mapping, instances, versions, incomplete = [], [], {}, []
        observed_configurations = {}
        for name in sorted(selected):
            container = selected[name][0]
            state = container.get('State')
            if (not isinstance(state, dict) or state.get('Running') is not True or state.get('Paused') is not False
                    or state.get('Restarting') is not False or state.get('Dead') is not False
                    or state.get('Status') != 'running' or type(state.get('Pid')) is not int or state['Pid'] <= 0
                    or not isinstance(state.get('StartedAt'), str)):
                raise RuntimeCollectionError('Runtime component is not stably running')
            try:
                # Docker uses RFC3339 nanoseconds; Python 3.10 only accepts
                # microseconds. Preserve the original identity string in evidence.
                match = re.fullmatch(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})'
                                     r'(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})', state['StartedAt'])
                if match is None:
                    raise ValueError
                normalized = (match[1] + ('.' + match[2][:6] if match[2] else '')
                              + ('+00:00' if match[3] == 'Z' else match[3]))
                started = datetime.fromisoformat(normalized)
                if started.tzinfo is None or started.year < 1970:
                    raise ValueError
            except ValueError:
                raise RuntimeCollectionError('Invalid runtime start timestamp') from None
            image_id = container.get('Image')
            if not isinstance(image_id, str) or not ID.fullmatch(image_id):
                raise RuntimeCollectionError('Runtime image must have an immutable identity')
            image = self._read('/v1.45/images/' + image_id + '/json', deadline)
            if not isinstance(image, dict) or image.get('Id') != image_id:
                raise RuntimeCollectionError('Inspected image identity mismatch')
            host, config = container.get('HostConfig'), container['Config']
            # Require explicit mount knowledge; absent fields cannot establish no mounts.
            if (not isinstance(host, dict) or host.get('ReadonlyRootfs') is not True
                    or container.get('Mounts') != [] or host.get('Binds') not in (None, [])
                    or host.get('VolumesFrom') not in (None, []) or host.get('Tmpfs') not in (None, {})
                    or host.get('Mounts') not in (None, [])
                    or config.get('Volumes') not in (None, {})):
                incomplete.append('unsupported-filesystem:' + name)
            entry = self._catalog.get((name, image_id))
            if entry is None:
                incomplete.append('catalog-missing:' + name)
            elif (image.get('Os') != entry['os'] or image.get('Architecture') != entry['architecture']
                  or (entry['artifact']['kind'] == 'registry'
                      and (not isinstance(image.get('RepoDigests'), list)
                           or entry['artifact']['ref'] not in image['RepoDigests']))):
                raise RuntimeCollectionError('Observed image does not match trusted catalog')
            if (not isinstance(host, dict) or host.get('Privileged') is not False
                    or host.get('Devices') not in (None, []) or host.get('DeviceRequests') not in (None, [])
                    or host.get('DeviceCgroupRules') not in (None, [])
                    or not isinstance(host.get('CapAdd'), (list, type(None)))
                    or any(not isinstance(cap, str) or cap.upper().removeprefix('CAP_') in ('SYS_ADMIN', 'ALL')
                           for cap in (host.get('CapAdd') or []))
                    or any(not isinstance(host.get(field), str)
                           or host[field] == 'host' or host[field].startswith('container:')
                           for field in ('PidMode', 'IpcMode', 'NetworkMode', 'UTSMode'))):
                incomplete.append('unsupported-isolation:' + name)
            managed = {}
            for filename, field in MANAGED_FILES.items():
                inspect_path = container.get(field)
                if (not isinstance(inspect_path, str) or not inspect_path.startswith('/')
                        or inspect_path.startswith('//') or any(part in ('.', '..', '') for part in inspect_path[1:].split('/'))
                        or any(ord(char) < 32 or ord(char) == 127 for char in inspect_path)):
                    incomplete.append('managed-file-unknown:' + name)
                    continue
                content = self.client.managed_file(container['Id'], filename, deadline=deadline)
                if time.monotonic() >= deadline:
                    raise RuntimeCollectionError('Runtime capture deadline exceeded')
                managed[filename] = {'inspectPath': inspect_path, 'sha256': hashlib.sha256(content).hexdigest()}
            settings = container.get('NetworkSettings')
            networks = settings.get('Networks') if isinstance(settings, dict) else None
            if not isinstance(networks, dict):
                incomplete.append('networks-unknown:' + name)
            projection = {'schemaVersion': 2, 'kind': 'docker-container-configuration',
                          'Config': config, 'HostConfig': host, 'Path': container.get('Path'), 'Args': container.get('Args'),
                          'managedFiles': managed, 'Networks': networks}
            configuration = 'sha256:' + digest(projection)
            if self._specifications is not None:
                # Retain all raw v2 inputs in private drift comparison even when
                # semantic identity deliberately omits generated Docker values.
                observed_configurations[name] = configuration
                if image.get('Os') != 'linux':
                    incomplete.append('unsupported-platform:' + name)
                spec = self._specifications.get((name, image_id))
                if spec is None:
                    incomplete.append('specification-missing:' + name)
                elif not spec.matches(container):
                    incomplete.append('specification-mismatch:' + name)
                else:
                    configuration = spec.configuration_digest()
            instances.append({'component': name, 'containerId': container['Id'], 'imageId': image_id,
                              'startedAt': state['StartedAt'], 'pid': state['Pid'], 'status': state['Status'],
                              'running': True, 'paused': False, 'restarting': False})
            if entry is not None:
                versions[name] = entry['version']
                if entry['migration']['mode'] != 'none':
                    incomplete.append('migration-unknown:' + name)
                mapping.append({'name': name, 'sourceSha': entry['sourceSha'], 'artifact': entry['artifact'],
                                'configurationDigest': configuration, 'migrationVersion': None})
            else:
                # Include configuration and image identities in drift comparison even
                # when no trusted source binding exists and no snapshot can be used.
                mapping.append({'name': name, 'imageId': image_id, 'configurationDigest': configuration})
        result = {'components': mapping, 'instances': instances, 'versions': versions, 'incomplete': incomplete}
        if self._specifications is not None:
            result['observedConfigurations'] = observed_configurations
        return result

    def collect(self):
        began = time.monotonic()
        try:
            deadline = began + self.policy.capture_deadline
            first, second = self._round(deadline), self._round(deadline)
            if time.monotonic() - began > self.policy.capture_deadline:
                raise RuntimeCollectionError('Runtime capture deadline exceeded')
            if canonical(first) != canonical(second):
                raise RuntimeCollectionError('Runtime changed during capture')
            captured_at = utcnow().isoformat()
            complete = not second['incomplete']
            snapshot = None
            if complete:
                snapshot = {'schemaVersion': 1, 'kind': 'deployment-snapshot',
                            'environment': self.policy.environment, 'target': self.policy.target,
                            'version': 'runtime-' + digest(second['components']),
                            'components': second['components'], 'capturedAt': captured_at,
                            'provenance': 'trusted-docker-runtime-v1:' + self._policy_hash}
            state_hash = digest({'policyHash': self._policy_hash, 'state': second})
            payload = {'schemaVersion': 1, 'kind': 'runtime-observation', 'complete': complete,
                       'snapshot': snapshot, 'instances': second['instances'], 'versions': second['versions'],
                       'scope': {'repository': self.policy.repository, 'environment': self.policy.environment,
                                 'target': self.policy.target, 'production': self.policy.production,
                                 'project': self.policy.project, 'components': list(self.policy.components)},
                       'policyHash': self._policy_hash, 'stateHash': state_hash, 'capturedAt': captured_at,
                       'nonce': secrets.token_hex(32), 'incomplete': second['incomplete'],
                       'verification': {'runtime': 'verified' if complete else 'incomplete',
                                        'health': 'unknown', 'smoke': 'unknown', 'backup': 'unknown',
                                        'migration': 'none' if complete else 'unknown'}}
            evidence_hash = digest(payload)
            payload['evidenceHash'] = evidence_hash
            observation = RuntimeObservation(canonical(payload), evidence_hash, state_hash, self._policy_hash, captured_at)
            with self._issuance_lock:
                self._sequence += 1
                self._issued[id(observation)] = (observation, time.monotonic(), self._sequence)
            return observation
        except RuntimeCollectionError:
            raise
        except Exception:
            raise RuntimeCollectionError('Runtime evidence could not be collected') from None

    def validate_history(self, observation, *, before=None):
        record = self._issued.get(id(observation))
        if (not isinstance(observation, RuntimeObservation) or record is None or record[0] is not observation
                or observation.policy_hash != self._policy_hash or self.policy.identity_hash() != self._policy_hash
                or self.client.policy != self.policy):
            raise RuntimeCollectionError('Runtime observation was not issued by this collector and scope')
        if observation.to_dict().get('complete') is not True:
            raise RuntimeCollectionError('Runtime observation is incomplete')
        if before is not None:
            self.validate_history(before)
            if observation is before or record[2] >= self._issued[id(before)][2]:
                raise RuntimeCollectionError('Runtime history must precede the baseline observation')
        return observation

    def validate(self, observation):
        self.validate_history(observation)
        issued = self._issued[id(observation)][1]
        age = (utcnow() - datetime.fromisoformat(observation.captured_at)).total_seconds()
        if not 0 <= age <= self.policy.maximum_age or not 0 <= time.monotonic() - issued <= self.policy.maximum_age:
            raise RuntimeCollectionError('Runtime observation is stale or future dated')
        return observation

    def recheck(self, observation):
        self.validate(observation)
        current = self.collect()
        self.validate(current)
        if current.state_hash != observation.state_hash:
            raise RuntimeCollectionError('Runtime state changed since approval baseline')
        return current


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'collect'))
    args = parser.parse_args(argv)
    result = {'executionAvailable': False, 'productionReady': False, 'runtimeVerification': 'unknown',
              'mode': 'trusted-host-injection-required'}
    if args.action == 'collect':
        result['error'] = 'Runtime collection requires a trusted embedding host'
    print(json.dumps(result, sort_keys=True))
    return int(args.action == 'collect')


if __name__ == '__main__':
    sys.exit(main())
