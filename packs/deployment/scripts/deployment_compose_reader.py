#!/usr/bin/env python3
"""Pinned, GET-only Docker API reader for a future Compose host collector.

This transport returns untrusted Docker JSON. It never signs observations or grants
execution authority. The trusted host supplies policy and TLS credentials directly.
The client allowlist cannot replace a server-side GET-only gateway: ordinary Docker
daemon TLS credentials can usually mutate state, so the host must independently
restrict routes and credentials before this client is used.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlencode, urlsplit

HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
DAEMON = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z')
MAX_RESPONSE = 8 * 1024 * 1024
GATEWAY_INFO_PATH = '/v1.45/workflow/reader-info'
BOOT_ID = re.compile(r'[0-9a-f]{32}\Z')


class ComposeReadError(ValueError):
    """Finite, secret-free read failure; raw exceptions never form diagnostics."""
    MESSAGES = {
        'pin-mismatch': 'Docker peer certificate pin mismatch',
        'deadline-exceeded': 'Docker read deadline exceeded',
        'invalid-json': 'Invalid Docker JSON response',
        'duplicate-json-field': 'Duplicate Docker JSON field',
        'response-too-large': 'Docker response too large',
        'http-status': 'Docker read returned non-success status',
        'transport-unavailable': 'Docker transport unavailable',
        'exact-not-found': 'Exact Docker inspect not found',
        'invalid-policy': 'Invalid Compose Docker reader policy',
        'route-refused': 'Compose Docker read route refused',
        'daemon-mismatch': 'Docker daemon identity mismatch',
        'inventory-shape': 'Invalid Compose inventory',
        'gateway-mismatch': 'Compose read gateway identity mismatch',
    }

    def __init__(self, code):
        self.code = code if code in self.MESSAGES else 'invalid-policy'
        super().__init__(self.MESSAGES[self.code])


class ComposeNotFound(ComposeReadError):
    """Authenticated exact inspect returned HTTP 404; not inventory evidence."""

    def __init__(self):
        super().__init__('exact-not-found')


@dataclass(frozen=True)
class ComposeReadPolicy:
    endpoint: str
    server_certificate_sha256: str
    daemon_id: str
    project: str
    volume_names: tuple[str, ...] = ()
    gateway_policy_hash: str | None = None
    private_key_id: str | None = None
    bind_count: int = 0
    image_defaults_enabled: bool = False
    source_container_ids: tuple[str, ...] = ()

    def __post_init__(self):
        try:
            endpoint = urlsplit(self.endpoint)
            valid = (endpoint.scheme == 'https' and endpoint.hostname and not endpoint.username
                     and not endpoint.password and endpoint.path in ('', '/')
                     and not endpoint.query and not endpoint.fragment and endpoint.port != 0
                     and not any(c.isspace() or ord(c) < 32 for c in self.endpoint))
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise ComposeReadError('invalid-policy')
        if type(self.server_certificate_sha256) is not str or not HEX.fullmatch(self.server_certificate_sha256):
            raise ComposeReadError('invalid-policy')
        if type(self.daemon_id) is not str or not DAEMON.fullmatch(self.daemon_id):
            raise ComposeReadError('invalid-policy')
        if type(self.project) is not str or not NAME.fullmatch(self.project):
            raise ComposeReadError('invalid-policy')
        if (type(self.volume_names) is not tuple or len(self.volume_names) > 128
                or any(type(name) is not str or not NAME.fullmatch(name) for name in self.volume_names)
                or len(self.volume_names) != len(set(self.volume_names))):
            raise ComposeReadError('invalid-policy')
        if (self.gateway_policy_hash is not None and
                (type(self.gateway_policy_hash) is not str or not HEX.fullmatch(self.gateway_policy_hash))):
            raise ComposeReadError('invalid-policy')
        if (self.private_key_id is not None and
                (type(self.private_key_id) is not str or not NAME.fullmatch(self.private_key_id)
                 or self.gateway_policy_hash is None)):
            raise ComposeReadError('invalid-policy')
        if (type(self.bind_count) is not int or not 0 <= self.bind_count <= 32
                or (self.bind_count and (self.private_key_id is None or self.gateway_policy_hash is None))):
            raise ComposeReadError('invalid-policy')

        if (type(self.image_defaults_enabled) is not bool
                or (self.image_defaults_enabled and
                    (self.private_key_id is None or self.gateway_policy_hash is None))):
            raise ComposeReadError('invalid-policy')

        if (type(self.source_container_ids) is not tuple or len(self.source_container_ids) > 128
                or any(type(cid) is not str or not HEX.fullmatch(cid) for cid in self.source_container_ids)
                or self.source_container_ids != tuple(sorted(set(self.source_container_ids)))
                or (self.source_container_ids and
                    (self.gateway_policy_hash is None or self.private_key_id is None))):
            raise ComposeReadError('invalid-policy')


class ComposeDockerReader:
    """Fixed-route API v1.45 GET reader; injected transport accepts path, returns bytes.

    A trusted host may inject a transport for tests. It must enforce equivalent peer
    authentication and server-side GET-only route isolation; raw Docker TLS credentials
    usually permit writes. Project JSON and environment variables cannot configure this reader.
    """

    def __init__(self, policy: ComposeReadPolicy, *, ca_file: Path, cert_file: Path,
                 key_file: Path, timeout=10, transport=None):
        if (not isinstance(policy, ComposeReadPolicy) or type(timeout) not in (int, float)
                or not 0 < timeout <= 300 or (transport is not None and not callable(transport))):
            raise ComposeReadError('invalid-policy')
        self.policy, self.timeout, self._transport = policy, timeout, transport
        self.gateway_boot_id = None
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
                raise ComposeReadError('transport-unavailable') from None
        filter_values = {'label': ['com.docker.compose.project=' + policy.project]}
        if policy.source_container_ids:
            filter_values['id'] = list(policy.source_container_ids)
        filters = json.dumps(filter_values,
                             sort_keys=True, separators=(',', ':'))
        self.list_path = '/v1.45/containers/json?' + urlencode({'all': '1', 'filters': filters})

    def get(self, path: str, *, deadline=None):
        if type(path) is not str or not self._allowed(path):
            raise ComposeReadError('route-refused')
        try:
            raw = self._request(path, deadline=deadline)
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=self._unique,
                               parse_constant=lambda _: self._invalid_number())
            if path == '/v1.45/info' and (type(value) is not dict or value.get('ID') != self.policy.daemon_id):
                raise ComposeReadError('daemon-mismatch')
            if path == self.list_path and type(value) is not list:
                raise ComposeReadError('inventory-shape')
            if path == self.list_path and self.policy.source_container_ids and (
                    len(value) != len(self.policy.source_container_ids)
                    or any(type(row) is not dict or type(row.get('Id')) is not str for row in value)
                    or sorted(row['Id'] for row in value) != list(self.policy.source_container_ids)):
                raise ComposeReadError('inventory-shape')
            if path.startswith('/v1.45/workflow/private/') and (
                    type(value) is not dict or set(value) != {'schemaVersion', 'keyId', 'configHmac', 'authorityGranted'}
                    or value['schemaVersion'] != 1 or value['keyId'] != self.policy.private_key_id
                    or type(value['configHmac']) is not str or not HEX.fullmatch(value['configHmac'])
                    or value['authorityGranted'] is not False):
                raise ComposeReadError('gateway-mismatch')
            if path.startswith('/v1.45/workflow/private-image/') and (
                    type(value) is not dict
                    or set(value) != {'schemaVersion', 'keyId', 'imageConfigHmac', 'authorityGranted'}
                    or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                    or type(value['keyId']) is not str or value['keyId'] != self.policy.private_key_id
                    or type(value['imageConfigHmac']) is not str or not HEX.fullmatch(value['imageConfigHmac'])
                    or value['authorityGranted'] is not False):
                raise ComposeReadError('gateway-mismatch')
            if path.startswith('/v1.45/workflow/binds/') and (
                    type(value) is not dict or set(value) != {'schemaVersion', 'bindDigest', 'authorityGranted'}
                    or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
                    or type(value['bindDigest']) is not str
                    or not HEX.fullmatch(value['bindDigest']) or value['authorityGranted'] is not False):
                raise ComposeReadError('gateway-mismatch')
            return value
        except ComposeReadError:
            raise
        except Exception:
            raise ComposeReadError('invalid-json') from None

    def gateway_info(self, *, deadline=None):
        """Validate a configured read gateway; no observation or execution authority."""
        self.gateway_boot_id = None
        if self.policy.gateway_policy_hash is None:
            raise ComposeReadError('invalid-policy')
        try:
            raw = self._request(GATEWAY_INFO_PATH, deadline=deadline)
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=self._unique,
                               parse_constant=lambda _: self._invalid_number())
            expected_fields = {'bootId', 'policyHash'}
            if self.policy.source_container_ids:
                expected_fields.update(('viewKind', 'containerIds'))
            if (type(value) is not dict or set(value) != expected_fields
                    or (self.policy.source_container_ids and
                        (value.get('viewKind') != 'pinned-containers' or
                         value.get('containerIds') != list(self.policy.source_container_ids)))
                    or type(value['bootId']) is not str or not BOOT_ID.fullmatch(value['bootId'])
                    or value['policyHash'] != self.policy.gateway_policy_hash):
                raise ComposeReadError('gateway-mismatch')
            self.gateway_boot_id = value['bootId']
            return value.copy()
        except ComposeReadError:
            raise
        except Exception:
            raise ComposeReadError('invalid-json') from None

    def _allowed(self, path):
        return (path in ('/v1.45/info', self.list_path)
                or bool(re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/json', path))
                or bool(re.fullmatch(r'/v1\.45/networks/[0-9a-f]{64}', path))
                or bool(re.fullmatch(r'/v1\.45/images/sha256:[0-9a-f]{64}/json', path))
                or (self.policy.image_defaults_enabled
                    and bool(re.fullmatch(r'/v1\.45/workflow/private-image/sha256:[0-9a-f]{64}', path)))
                or (self.policy.private_key_id is not None
                    and bool(re.fullmatch(r'/v1\.45/workflow/private/[0-9a-f]{64}', path)))
                or (self.policy.bind_count > 0 and bool(re.fullmatch(r'/v1\.45/workflow/binds/(0|[1-9]|[12][0-9]|3[01])', path))
                    and int(path.rsplit('/', 1)[1]) < self.policy.bind_count)
                or (path.startswith('/v1.45/volumes/') and path[len('/v1.45/volumes/'):] in self.policy.volume_names))

    @staticmethod
    def _unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ComposeReadError('duplicate-json-field')
            result[key] = value
        return result

    @staticmethod
    def _invalid_number():
        raise ComposeReadError('invalid-json')

    def _request(self, path, *, deadline):
        connection = response = watchdog = None
        watchdog_expired = threading.Event()
        try:
            remaining = self.timeout if deadline is None else min(self.timeout, deadline - time.monotonic())
            if remaining <= 0:
                raise ComposeReadError('deadline-exceeded')
            if self._transport is not None:
                raw = self._transport(path)
                if deadline is not None and time.monotonic() >= deadline:
                    raise ComposeReadError('deadline-exceeded')
                if type(raw) is not bytes:
                    raise ComposeReadError('invalid-json')
                if len(raw) > MAX_RESPONSE:
                    raise ComposeReadError('response-too-large')
                return raw
            endpoint = urlsplit(self.policy.endpoint)
            connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443,
                                                     timeout=remaining, context=self._context)
            connection.connect()
            peer = connection.sock
            if hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() != self.policy.server_certificate_sha256:
                raise ComposeReadError('pin-mismatch')
            read_deadline = min(deadline if deadline is not None else float('inf'), time.monotonic() + self.timeout)
            def abort():
                watchdog_expired.set()
                try:
                    peer.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            watchdog = threading.Timer(max(0, read_deadline - time.monotonic()), abort)
            watchdog.daemon = True
            watchdog.start()
            connection.request('GET', path, headers={'Accept': 'application/json'})
            response = connection.getresponse()
            if watchdog_expired.is_set() or time.monotonic() >= read_deadline:
                raise ComposeReadError('deadline-exceeded')
            if response.status == 404 and path not in ('/v1.45/info', self.list_path, GATEWAY_INFO_PATH):
                raise ComposeNotFound()
            if response.status != 200:
                raise ComposeReadError('http-status')
            raw = bytearray()
            while len(raw) <= MAX_RESPONSE:
                remaining = read_deadline - time.monotonic()
                if remaining <= 0:
                    raise ComposeReadError('deadline-exceeded')
                if connection.sock is not None:
                    connection.sock.settimeout(min(self.timeout, remaining))
                chunk = response.read1(min(65536, MAX_RESPONSE + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if watchdog_expired.is_set() or time.monotonic() >= read_deadline:
                raise ComposeReadError('deadline-exceeded')
            if len(raw) > MAX_RESPONSE:
                raise ComposeReadError('response-too-large')
            return bytes(raw)
        except ComposeNotFound:
            if path in ('/v1.45/info', self.list_path, GATEWAY_INFO_PATH):
                raise ComposeReadError('http-status') from None
            raise ComposeNotFound() from None
        except ComposeReadError:
            raise
        except (TimeoutError, socket.timeout):
            raise ComposeReadError('deadline-exceeded') from None
        except Exception:
            if watchdog_expired.is_set():
                raise ComposeReadError('deadline-exceeded') from None
            raise ComposeReadError('transport-unavailable') from None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()
