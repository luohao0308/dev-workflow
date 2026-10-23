"""Trusted, bounded read-only deployment probes. Candidate data is never routing authority.

Only the host constructs policies, supplies CA trust and optionally injects a test
transport. Bindings and results contain digests and fixed diagnostics, never URLs,
response data, predicates, credentials or exception text. No executable CLI exists.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import ssl
import sys
import time
from urllib.parse import unquote

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import deployment_runtime as runtime
import deployment_spec as specification

_ERRORS = frozenset(('probe-policy-rejected', 'probe-scope-rejected', 'probe-binding-rejected',
                     'probe-container-rejected', 'probe-deadline-exceeded', 'probe-network-failed',
                     'probe-peer-pin-rejected', 'probe-response-rejected', 'probe-status-failed',
                     'probe-json-rejected', 'probe-predicate-failed', 'probe-tls-rejected'))
_MAX_JSON = 262144


class VerificationError(ValueError):
    """Fixed, sanitized diagnostic; callers must never interpolate private data."""
    def __init__(self, code='probe-policy-rejected'):
        super().__init__(code if type(code) is str and code in _ERRORS else 'probe-policy-rejected')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _hash(value):
    return hashlib.sha256(_canonical(value).encode('ascii')).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _tree(value, depth=0):
    if depth > 24:
        raise ValueError
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError
    elif isinstance(value, dict):
        if len(value) > 256:
            raise ValueError
        for key, item in value.items():
            _tree(key, depth + 1)
            _tree(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 1024:
            raise ValueError
        for item in value:
            _tree(item, depth + 1)
    elif type(value) in (int, float):
        if not math.isfinite(value) or abs(value) > 1e100:
            raise ValueError


def _json(text, limit=_MAX_JSON):
    try:
        if type(text) is not str or len(text.encode('utf-8')) > limit:
            raise ValueError
        # Preflight depth before recursive decoding, respecting JSON strings.
        depth, quoted, escaped = 0, False, False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in '[{':
                depth += 1
                if depth > 24:
                    raise ValueError
            elif char in ']}':
                depth -= 1
        value = json.loads(text, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _tree(value)
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError, OverflowError):
        raise VerificationError('probe-json-rejected') from None


def _require(condition):
    if not condition:
        raise VerificationError()


def _string(value, limit, empty=False):
    _require(type(value) is str and (empty or bool(value)) and len(value) <= limit
             and all(ord(c) >= 32 and ord(c) != 127 for c in value))


def _number(value, lower, upper, integer=False):
    _require(type(value) in ((int,) if integer else (int, float))
             and math.isfinite(value) and lower <= value <= upper)


def _pointer(pointer):
    _string(pointer, 512, empty=True)
    _require(pointer == '' or pointer.startswith('/'))
    parts = pointer.split('/')[1:] if pointer else []
    _require(len(parts) <= 24 and not re.search(r'~(?![01])', pointer))
    return [p.replace('~1', '/').replace('~0', '~') for p in parts]


def _probe(value):
    fields = {'id', 'path', 'status', 'jsonExpectations', 'attempts', 'retryDelay', 'timeout', 'maxBodyBytes'}
    _require(type(value) is dict and set(value) == fields)
    _require(type(value['id']) is str and bool(runtime.NAME.fullmatch(value['id'])))
    path = value['path']
    _string(path, 2048)
    _require(path.startswith('/') and not path.startswith('//') and path.isascii())
    # Also reject encoded traversal, controls and route delimiters. No URL joining.
    decoded = path
    for _ in range(3):
        _require(not any(c in decoded for c in ('?', '#', '\\'))
                 and all(32 < ord(c) < 127 for c in decoded)
                 and not any(p in ('.', '..') for p in decoded.split('/')))
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    _require('%' not in decoded)
    _number(value['status'], 200, 299, True)
    _number(value['attempts'], 1, 5, True)
    _number(value['retryDelay'], 0, 2)
    _number(value['timeout'], .05, 10)
    _number(value['maxBodyBytes'], 1, 65536, True)
    expected = value['jsonExpectations']
    _require(type(expected) is dict and 1 <= len(expected) <= 32)
    for pointer, scalar in expected.items():
        _pointer(pointer)
        _require(scalar is None or type(scalar) in (str, bool, int, float))
        if type(scalar) is str:
            _string(scalar, 4096, empty=True)
    return value


def _profile(value):
    fields = {'component', 'imageId', 'specHash', 'containerPort', 'hostIp', 'hostPort',
              'address', 'scheme', 'tlsHostname', 'serverCertificateSha256', 'health', 'smoke'}
    _require(type(value) is dict and set(value) == fields)
    _require(type(value['component']) is str and bool(runtime.NAME.fullmatch(value['component'])))
    for key in ('imageId', 'specHash'):
        _require(type(value[key]) is str and bool(runtime.ID.fullmatch(value[key])))
    _require(type(value['containerPort']) is str
             and bool(re.fullmatch(r'[1-9][0-9]{0,4}/tcp', value['containerPort']))
             and int(value['containerPort'].split('/')[0]) <= 65535)
    _require(type(value['hostPort']) is str and bool(re.fullmatch(r'[1-9][0-9]{0,4}', value['hostPort']))
             and int(value['hostPort']) <= 65535)
    host = ipaddress.IPv4Address(value['hostIp'])
    address = ipaddress.IPv4Address(value['address'])
    _require(type(value['hostIp']) is str and type(value['address']) is str
             and str(host) == value['hostIp'] and str(address) == value['address']
             and not address.is_unspecified and not address.is_multicast
             and (host.is_unspecified or host == address))
    _require(value['scheme'] in ('http', 'https'))
    if value['scheme'] == 'http':
        _require(address.is_loopback and (host.is_loopback or host.is_unspecified)
                 and value['tlsHostname'] in ('', None) and value['serverCertificateSha256'] in ('', None))
    else:
        hostname = value['tlsHostname']
        _string(hostname, 253)
        _require(bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', hostname))
                 and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p)
                         for p in hostname.split('.')))
        _require(type(value['serverCertificateSha256']) is str
                 and bool(runtime.HEX.fullmatch(value['serverCertificateSha256'])))
    ids = set()
    for phase in ('health', 'smoke'):
        _require(type(value[phase]) is list and 1 <= len(value[phase]) <= 16)
        for probe in value[phase]:
            _probe(probe)
            _require(probe['id'] not in ids)
            ids.add(probe['id'])
    return value


@dataclass(frozen=True)
class ProbePolicy:
    runtime_policy_hash: str
    profiles_json: str
    total_timeout: int = 60

    def __post_init__(self):
        try:
            _require(type(self.runtime_policy_hash) is str and bool(runtime.HEX.fullmatch(self.runtime_policy_hash)))
            _number(self.total_timeout, 1, 120, True)
            value = _json(self.profiles_json)
            _require(type(value) is dict and set(value) == {'schemaVersion', 'kind', 'profiles'}
                     and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
                     and value['kind'] == 'deployment-probe-policy'
                     and type(value['profiles']) is list and 1 <= len(value['profiles']) <= 64)
            identities = set()
            for entry in value['profiles']:
                _profile(entry)
                key = (entry['component'], entry['imageId'])
                _require(key not in identities)
                identities.add(key)
            value['profiles'].sort(key=lambda p: (p['component'], p['imageId']))
            # Only canonical immutable strings are retained, never caller-owned trees.
            object.__setattr__(self, 'profiles_json', _canonical(value))
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise VerificationError() from None

    def identity_hash(self):
        return _hash({'schemaVersion': 1, 'kind': 'deployment-probe-policy-identity',
                      'runtimePolicyHash': self.runtime_policy_hash, 'profiles': _json(self.profiles_json),
                      'totalTimeout': self.total_timeout})


def _headers(headers, max_body):
    if type(headers) is not list or len(headers) > 64:
        raise VerificationError('probe-response-rejected')
    values, size = {}, 0
    for pair in headers:
        if type(pair) not in (tuple, list) or len(pair) != 2:
            raise VerificationError('probe-response-rejected')
        name, value = pair
        if (type(name) is not str or type(value) is not str
                or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or any(ord(c) < 32 or ord(c) > 126 for c in value)):
            raise VerificationError('probe-response-rejected')
        size += len(name) + len(value)
        if size > 16384:
            raise VerificationError('probe-response-rejected')
        values.setdefault(name.lower(), []).append(value.strip())
    length, transfer = values.get('content-length', []), values.get('transfer-encoding', [])
    if (len(length) > 1 or (length and transfer)
            or (length and (not re.fullmatch(r'[0-9]{1,10}', length[0]) or int(length[0]) > max_body))
            or bool(transfer)
            or values.get('content-encoding', ['identity']) != ['identity']):
        raise VerificationError('probe-response-rejected')
    return int(length[0]) if length else None


def _matches(document, expected):
    for pointer, scalar in expected.items():
        value = document
        for key in _pointer(pointer):
            if type(value) is dict and key in value:
                value = value[key]
            elif (type(value) is list and re.fullmatch(r'0|[1-9][0-9]{0,5}', key)
                  and int(key) < len(value)):
                value = value[int(key)]
            else:
                return False
        if type(value) is not type(scalar) or value != scalar:
            return False
    return True


class TrustedProbeVerifier:
    def __init__(self, policy: ProbePolicy, runtime_policy: runtime.RuntimePolicy, *,
                 ca_file: Path | None = None, transport=None):
        if (type(self) is not TrustedProbeVerifier or type(policy) is not ProbePolicy
                or type(runtime_policy) is not runtime.RuntimePolicy
                or policy.runtime_policy_hash != runtime_policy.identity_hash()
                or (transport is not None and not callable(transport))):
            raise VerificationError('probe-scope-rejected')
        self.policy, self.runtime_policy = policy, runtime_policy
        self._policy_hash = policy.identity_hash()
        self._transport = transport
        self._trusted_transport = transport
        self._profiles, self._specs, self._bindings, self._contexts = {}, {}, {}, {}
        try:
            specs = specification.parse_specifications(runtime_policy.specifications_json)
            catalog = runtime._catalog(runtime_policy)
            for profile in _json(policy.profiles_json)['profiles']:
                key = (profile['component'], profile['imageId'])
                spec = specs.get(key)
                if (key not in catalog or spec is None
                        or spec.configuration_digest() != profile['specHash']):
                    raise VerificationError('probe-scope-rejected')
                self._specs[key] = spec
                self._profiles[key] = _canonical(profile)
                if profile['scheme'] == 'https':
                    if not isinstance(ca_file, Path):
                        raise VerificationError('probe-tls-rejected')
                    # Do not use create_default_context: it can honor SSLKEYLOGFILE.
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.keylog_filename = None
                    context.load_verify_locations(cafile=str(ca_file))
                    self._contexts[key] = context
        except VerificationError:
            raise
        except (ValueError, TypeError, OSError):
            raise VerificationError('probe-scope-rejected') from None

    def _fixed(self):
        if (type(self) is not TrustedProbeVerifier or type(self.policy) is not ProbePolicy
                or self.policy.identity_hash() != self._policy_hash
                or self.runtime_policy.identity_hash() != self.policy.runtime_policy_hash
                or self._transport is not self._trusted_transport):
            raise VerificationError('probe-scope-rejected')
        expected = {(p['component'], p['imageId']): _canonical(p)
                    for p in _json(self.policy.profiles_json)['profiles']}
        if self._profiles != expected:
            raise VerificationError('probe-scope-rejected')
        recipes = specification.parse_specifications(self.runtime_policy.specifications_json)
        if (set(self._specs) != set(expected)
                or any(type(spec) is not specification.ContainerSpec
                       or spec != recipes.get(key) for key, spec in self._specs.items())):
            raise VerificationError('probe-scope-rejected')

    def bind(self, component: str, spec: specification.ContainerSpec) -> str:
        TrustedProbeVerifier._fixed(self)
        if (type(spec) is not specification.ContainerSpec or component != spec.component
                or (component, spec.image_id) not in self._profiles):
            raise VerificationError('probe-binding-rejected')
        key = (component, spec.image_id)
        profile = _json(self._profiles[key])
        expected = {'HostIp': profile['hostIp'], 'HostPort': profile['hostPort']}
        if (spec.configuration_digest() != profile['specHash']
                or expected not in _json(spec.host_config_json)['PortBindings'].get(profile['containerPort'], [])):
            raise VerificationError('probe-binding-rejected')
        binding = _canonical({'policyHash': self._policy_hash, 'component': component,
                              'imageId': spec.image_id, 'specHash': profile['specHash'],
                              'probeIds': [p['id'] for phase in ('health', 'smoke') for p in profile[phase]]})
        self._bindings[binding] = key
        return binding

    def _request(self, profile, probe, deadline):
        if self._transport is not None:
            return self._transport(_json(_canonical(profile)), _json(_canonical(probe)), deadline)
        peer = response = watchdog = None
        try:
            peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer.settimeout(max(.001, deadline - time.monotonic()))
            peer.connect((profile['address'], int(profile['hostPort'])))
            if profile['scheme'] == 'https':
                peer = self._contexts[(profile['component'], profile['imageId'])].wrap_socket(
                    peer, server_hostname=profile['tlsHostname'], do_handshake_on_connect=False)
            watchdog = runtime.deadline_watchdog(peer, deadline)
            if profile['scheme'] == 'https':
                peer.do_handshake()
                if hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() != profile['serverCertificateSha256']:
                    raise VerificationError('probe-peer-pin-rejected')
            if time.monotonic() >= deadline:
                raise VerificationError('probe-deadline-exceeded')
            host = profile['tlsHostname'] if profile['scheme'] == 'https' else profile['address']
            request = ('GET ' + probe['path'] + ' HTTP/1.1\r\nHost: ' + host + ':' + profile['hostPort']
                       + '\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n')
            peer.sendall(request.encode('ascii'))
            response = http.client.HTTPResponse(peer)
            response.begin()
            headers = response.getheaders()
            _headers(headers, probe['maxBodyBytes'])
            body = bytearray()
            while len(body) <= probe['maxBodyBytes']:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise VerificationError('probe-deadline-exceeded')
                peer.settimeout(remaining)
                part = response.read1(min(8192, probe['maxBodyBytes'] + 1 - len(body)))
                if not part:
                    break
                body.extend(part)
            return response.status, headers, bytes(body)
        finally:
            if watchdog is not None:
                watchdog.cancel()
            if response is not None:
                response.close()
            if peer is not None:
                peer.close()

    @staticmethod
    def _guard(guard, deadline):
        if time.monotonic() >= deadline:
            raise VerificationError('probe-deadline-exceeded')
        guard()  # Deliberately outside any network/validation exception handler.
        if time.monotonic() >= deadline:
            raise VerificationError('probe-deadline-exceeded')

    def check(self, binding_json: str, *, container: dict, guard, deadline: float) -> dict:
        TrustedProbeVerifier._fixed(self)
        if (type(binding_json) is not str or binding_json not in self._bindings
                or not callable(guard) or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or type(self.policy) is not ProbePolicy or self.policy.identity_hash() != self._policy_hash
                or self.runtime_policy.identity_hash() != self.policy.runtime_policy_hash):
            raise VerificationError('probe-binding-rejected')
        key = self._bindings[binding_json]
        profile = _json(self._profiles[key])
        spec = self._specs[key]
        if type(container) is not dict:
            raise VerificationError('probe-container-rejected')
        state = container.get('State')
        settings = container.get('NetworkSettings')
        if type(state) is not dict or type(settings) is not dict or type(settings.get('Ports')) is not dict:
            raise VerificationError('probe-container-rejected')
        if (type(container) is not dict or type(container.get('Id')) is not str
                or not runtime.CONTAINER.fullmatch(container['Id'])
                or container.get('Image') != profile['imageId'] or not spec.matches(container)
                or state.get('Running') is not True or state.get('Paused') is not False
                or state.get('Restarting') is not False or state.get('Dead') is not False
                or state.get('Status') != 'running'
                or {'HostIp': profile['hostIp'], 'HostPort': profile['hostPort']} not in
                container.get('NetworkSettings', {}).get('Ports', {}).get(profile['containerPort'], [])):
            raise VerificationError('probe-container-rejected')
        deadline = min(deadline, time.monotonic() + self.policy.total_timeout)
        result = {'passed': False, 'health': 'failed', 'smoke': 'not-run', 'policyHash': self._policy_hash,
                  'containerId': container['Id'], 'component': key[0], 'imageId': key[1],
                  'specHash': profile['specHash'], 'checks': []}
        for phase in ('health', 'smoke'):
            result[phase] = 'passed'
            for probe_index, configured_probe in enumerate(profile[phase]):
                started = time.monotonic()
                check = {'id': configured_probe['id'], 'phase': phase, 'status': 'failed', 'attempts': 0,
                         'durationMs': 0, 'responseHash': None, 'errorCode': None, 'httpStatus': None}
                for attempt in range(configured_probe['attempts']):
                    TrustedProbeVerifier._guard(guard, deadline)
                    # Fresh private trees keep even trusted hooks from mutating cached policy.
                    current = _json(self._profiles[key])
                    probe = current[phase][probe_index]
                    attempt_deadline = min(deadline, time.monotonic() + probe['timeout'])
                    check.update(attempts=attempt + 1, responseHash=None, httpStatus=None)
                    code, response = None, None
                    try:
                        response = TrustedProbeVerifier._request(self, current, probe, attempt_deadline)
                    except VerificationError as error:
                        code = str(error)
                    except (OSError, http.client.HTTPException):
                        code = 'probe-network-failed'
                    read_completed = time.monotonic()
                    TrustedProbeVerifier._guard(guard, deadline)
                    if read_completed >= attempt_deadline:
                        code = 'probe-deadline-exceeded'
                    if code is None:
                        try:
                            status, headers, body = response
                            if type(status) is not int or not 100 <= status <= 599 or type(body) is not bytes:
                                raise VerificationError('probe-response-rejected')
                            check['httpStatus'] = status
                            length = _headers(headers, probe['maxBodyBytes'])
                            if len(body) > probe['maxBodyBytes'] or (length is not None and length != len(body)):
                                raise VerificationError('probe-response-rejected')
                            check['responseHash'] = hashlib.sha256(body).hexdigest()
                            if status != probe['status']:
                                raise VerificationError('probe-status-failed')
                            document = _json(body.decode('utf-8'), probe['maxBodyBytes'])
                            if not _matches(document, probe['jsonExpectations']):
                                raise VerificationError('probe-predicate-failed')
                        except VerificationError as error:
                            code = str(error)
                        except (ValueError, TypeError, UnicodeError, RecursionError):
                            code = 'probe-response-rejected'
                    if time.monotonic() >= deadline:
                        raise VerificationError('probe-deadline-exceeded')
                    check['errorCode'] = code
                    if code is None:
                        check['status'] = 'passed'
                        break
                    if attempt + 1 < configured_probe['attempts']:
                        delay = configured_probe['retryDelay']
                        if time.monotonic() + delay >= deadline:
                            raise VerificationError('probe-deadline-exceeded')
                        time.sleep(delay)
                check['durationMs'] = max(0, int((time.monotonic() - started) * 1000))
                result['checks'].append(check)
                if check['status'] != 'passed':
                    result[phase] = 'failed'
                    return result
        result['passed'] = True
        return result
