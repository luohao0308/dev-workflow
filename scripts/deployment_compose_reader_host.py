"""Trusted, GET-only Compose Docker gateway. Embed with host-owned policy and TLS.

The Docker Unix socket is never exposed to the client. Project files and ambient
environment cannot supply policy, certificates, or the socket path.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlencode
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
import deployment_compose_private as private
import deployment_compose_bind_host as bind_host
import deployment_compose_image_defaults as image_defaults

MAX_RESPONSE = 8 * 1024 * 1024
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


class ReaderHostError(ValueError):
    pass


@dataclass(frozen=True)
class ComposeReaderHostPolicy:
    project: str
    daemon_id: str
    reader_certificate_sha256: str
    services: tuple[str, ...]
    container_ids: tuple[str, ...]
    image_ids: tuple[str, ...]
    network_ids: tuple[str, ...]
    volume_names: tuple[str, ...]
    private_key_id: str | None = None
    bind_paths: tuple[str, ...] = ()
    image_defaults_enabled: bool = False

    def __post_init__(self):
        groups = ((self.services, NAME), (self.container_ids, HEX),
                  (self.network_ids, HEX), (self.volume_names, NAME))
        if (type(self.project) is not str or not NAME.fullmatch(self.project)
                or type(self.daemon_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}', self.daemon_id)
                or type(self.reader_certificate_sha256) is not str
                or not HEX.fullmatch(self.reader_certificate_sha256)
                or any(type(group) is not tuple or len(group) > 128
                       or any(type(item) is not str or not pattern.fullmatch(item) for item in group)
                       or len(group) != len(set(group))
                       for group, pattern in groups)
                or type(self.image_ids) is not tuple or len(self.image_ids) > 128
                or any(type(item) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', item)
                       for item in self.image_ids)
                or len(self.image_ids) != len(set(self.image_ids))):
            raise ReaderHostError('reader-host-policy-rejected')
        if (type(self.bind_paths) is not tuple or len(self.bind_paths) > 32
                or len(self.bind_paths) != len(set(self.bind_paths))
                or any(not bind_host._valid_path(path) for path in self.bind_paths)
                or (self.bind_paths and self.private_key_id is None)):
            raise ReaderHostError('reader-host-policy-rejected')
        if self.private_key_id is not None and (type(self.private_key_id) is not str
                                                or not NAME.fullmatch(self.private_key_id)):
            raise ReaderHostError('reader-host-policy-rejected')

        if (type(self.image_defaults_enabled) is not bool
                or (self.image_defaults_enabled and self.private_key_id is None)):
            raise ReaderHostError('reader-host-policy-rejected')

    def digest(self):
        raw = json.dumps(self.__dict__, sort_keys=True, separators=(',', ':')).encode()
        return hashlib.sha256(raw).hexdigest()


class _UnixDocker(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self._path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _complete_json_response(response, *, allow_404=False):
    headers = response.getheaders()
    lengths = [v for k, v in headers if k.lower() == 'content-length']
    transfers = [v for k, v in headers if k.lower() == 'transfer-encoding']
    if (response.status not in ((200, 404) if allow_404 else (200,))
            or len(headers) > 64 or len(lengths) != 1
            and not (not lengths and len(transfers) == 1 and transfers[0].lower() == 'chunked')
            or (lengths and (transfers or not re.fullmatch(r'[0-9]{1,10}', lengths[0])
                             or int(lengths[0]) > MAX_RESPONSE))
            or (transfers and (len(transfers) != 1 or transfers[0].lower() != 'chunked'))
            or any(k.lower() in ('content-encoding', 'location') for k, _ in headers)):
        raise ReaderHostError('reader-upstream-unknown')
    raw = bytearray()
    while len(raw) <= MAX_RESPONSE:
        chunk = response.read1(min(65536, MAX_RESPONSE + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    if (len(raw) > MAX_RESPONSE or (lengths and len(raw) != int(lengths[0]))
            or response.length not in (None, 0) or not response.isclosed()):
        raise ReaderHostError('reader-upstream-unknown')
    if response.status == 404 and not raw:
        return b'', None
    try:
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError()
                value[key] = item
            return value
        return bytes(raw), json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError):
        raise ReaderHostError('reader-upstream-unknown') from None


def _labels(value):
    if type(value) is not dict:
        raise ReaderHostError('reader-upstream-unknown')
    return {key: value.get(key) for key in ('com.docker.compose.project', 'com.docker.compose.service')}


def _project(path, value, list_path):
    """Emit only collector-required fields, never raw daemon or container JSON."""
    if path == '/v1.45/info':
        return {'ID': value['ID']}
    if path == list_path:
        return [{'Id': x['Id'], 'ImageID': x['ImageID'], 'Labels': _labels(x['Labels'])} for x in value]
    if path.startswith('/v1.45/containers/'):
        config, settings, state = value['Config'], value['NetworkSettings'], value['State']
        networks = settings['Networks']
        return {'Id': value['Id'], 'Name': value['Name'], 'Image': value['Image'],
                'Config': {'Labels': _labels(config['Labels'])},
                'NetworkSettings': {'Networks': {
                    name: {'NetworkID': endpoint['NetworkID'], 'Aliases': endpoint['Aliases']}
                    for name, endpoint in networks.items()}},
                'Mounts': [{key: mount.get(key) for key in ('Type', 'Name', 'Source', 'Destination', 'RW')}
                           for mount in value['Mounts']],
                'RestartCount': value['RestartCount'],
                'State': {'Running': state['Running'], 'Pid': state['Pid'],
                          'StartedAt': state['StartedAt'],
                          'Health': None if state.get('Health') is None else {'Status': state['Health']['Status']}}}
    if path.startswith('/v1.45/images/'):
        return {key: value.get(key) for key in ('Id', 'Os', 'Architecture', 'RepoDigests')}
    if path.startswith('/v1.45/networks/'):
        return {'Id': value['Id'], 'Name': value['Name'], 'Labels': _labels(value['Labels'])}
    if value.get('Options') != {}:
        raise ReaderHostError('reader-upstream-unknown')
    return {'Name': value['Name'], 'Driver': value['Driver'], 'Options': {},
            'Labels': _labels(value['Labels'])}


def create_gateway(policy, *, tls_context, docker_socket, listen=('127.0.0.1', 0), timeout=10,
                   private_hmac_key=None):
    if (type(policy) is not ComposeReaderHostPolicy or not isinstance(tls_context, ssl.SSLContext)
            or tls_context.verify_mode != ssl.CERT_REQUIRED or not isinstance(docker_socket, Path)
            or not docker_socket.is_absolute() or type(timeout) not in (int, float)
            or not 1 <= timeout <= 180 or not hasattr(socket, 'AF_UNIX')
            or ((policy.private_key_id is None) != (private_hmac_key is None))
            or (private_hmac_key is not None and
                (type(private_hmac_key) is not bytes or len(private_hmac_key) < 32))):
        raise ReaderHostError('reader-host-policy-rejected')
    filters = json.dumps({'label': ['com.docker.compose.project=' + policy.project]},
                         sort_keys=True, separators=(',', ':'))
    list_path = '/v1.45/containers/json?' + urlencode({'all': '1', 'filters': filters})
    boot_id = uuid.uuid4().hex

    def private_path(path):
        match = re.fullmatch(r'/v1\.45/workflow/private/([0-9a-f]{64})', path)
        return match[1] if match and match[1] in policy.container_ids and private_hmac_key is not None else None

    def scoped(path, value):
        if path == '/v1.45/info':
            return type(value) is dict and value.get('ID') == policy.daemon_id
        if path == list_path:
            return type(value) is list and all(
                type(item) is dict and item.get('Id') in policy.container_ids
                and item.get('ImageID') in policy.image_ids
                and type(item.get('Labels')) is dict
                and item['Labels'].get('com.docker.compose.project') == policy.project
                and item['Labels'].get('com.docker.compose.service') in policy.services
                for item in value)
        container = re.fullmatch(r'/v1\.45/containers/([0-9a-f]{64})/json', path)
        if container:
            labels = value.get('Config', {}).get('Labels', {}) if type(value) is dict else {}
            return (type(value) is dict and value.get('Id') == container[1]
                    and value.get('Image') in policy.image_ids and type(labels) is dict
                    and labels.get('com.docker.compose.project') == policy.project
                    and labels.get('com.docker.compose.service') in policy.services)
        image = re.fullmatch(r'/v1\.45/images/(sha256:[0-9a-f]{64})/json', path)
        if image:
            return type(value) is dict and value.get('Id') == image[1]
        network = re.fullmatch(r'/v1\.45/networks/([0-9a-f]{64})', path)
        if network:
            return (type(value) is dict and value.get('Id') == network[1]
                    and type(value.get('Labels')) is dict
                    and value['Labels'].get('com.docker.compose.project') == policy.project)
        volume = path.removeprefix('/v1.45/volumes/')
        return (type(value) is dict and value.get('Name') == volume
                and type(value.get('Labels')) is dict
                and value['Labels'].get('com.docker.compose.project') == policy.project)

    def allowed(path):
        return (path in ('/v1.45/info', list_path)
                or bool(re.fullmatch(r'/v1\.45/containers/([0-9a-f]{64})/json', path)
                        and path.split('/')[3] in policy.container_ids)
                or bool(re.fullmatch(r'/v1\.45/images/(sha256:[0-9a-f]{64})/json', path)
                        and path.split('/')[3] in policy.image_ids)
                or bool(re.fullmatch(r'/v1\.45/networks/([0-9a-f]{64})', path)
                        and path.split('/')[3] in policy.network_ids)
                or bool(path.startswith('/v1.45/volumes/') and path[len('/v1.45/volumes/'):] in policy.volume_names))

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def reply(self, status, raw):
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

        def deny(self):
            self.reply(403, b'{"error":"reader-request-rejected"}')

        def do_GET(self):
            self.connection.settimeout(timeout)
            peer = self.connection.getpeercert(binary_form=True)
            if (not peer or hashlib.sha256(peer).hexdigest() != policy.reader_certificate_sha256
                    or self.headers.get_all('Content-Length') or self.headers.get_all('Transfer-Encoding')
                    or self.headers.get_all('Content-Encoding') or self.headers.get_all('Expect')):
                self.deny()
                return
            if self.path == '/v1.45/workflow/reader-info':
                self.reply(200, json.dumps({'bootId': boot_id, 'policyHash': policy.digest()},
                                           sort_keys=True, separators=(',', ':')).encode())
                return
            bind_match = re.fullmatch(r'/v1\.45/workflow/binds/(0|[1-9]|[12][0-9]|3[01])', self.path)
            if bind_match:
                index = int(bind_match[1])
                if private_hmac_key is None or index >= len(policy.bind_paths):
                    self.deny()
                    return
                try:
                    evidence = bind_host.snapshot(policy.bind_paths[index], allowed_paths=policy.bind_paths,
                                                  key=private_hmac_key, timeout_seconds=min(timeout, 2))
                    payload = {'schemaVersion': 1, 'bindDigest': evidence.digest,
                               'authorityGranted': False}
                    self.reply(200, json.dumps(payload, sort_keys=True, separators=(',', ':')).encode())
                except (ValueError, OSError):
                    self.reply(502, b'{"error":"reader-bind-unavailable"}')
                return
            image_match = re.fullmatch(r'/v1\.45/workflow/private-image/(sha256:[0-9a-f]{64})', self.path)
            private_image_id = (image_match[1] if image_match and policy.image_defaults_enabled
                                and image_match[1] in policy.image_ids else None)
            private_container_id = private_path(self.path)
            if private_container_id is None and private_image_id is None and not allowed(self.path):
                self.deny()
                return
            upstream_path = ('/v1.45/containers/' + private_container_id + '/json'
                             if private_container_id is not None else
                             '/v1.45/images/' + private_image_id + '/json'
                             if private_image_id is not None else self.path)
            connection = response = watchdog = None
            try:
                connection = _UnixDocker(docker_socket, timeout)
                connection.connect()
                upstream_socket = connection.sock
                deadline = time.monotonic() + timeout
                def abort():
                    try:
                        upstream_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                watchdog = threading.Timer(timeout, abort)
                watchdog.daemon = True
                watchdog.start()
                connection.request('GET', upstream_path, headers={'Connection': 'close'})
                response = connection.getresponse()
                exact = upstream_path not in ('/v1.45/info', list_path)
                raw, value = _complete_json_response(response, allow_404=exact)
                if time.monotonic() >= deadline:
                    raise ReaderHostError('reader-upstream-unknown')
                if response.status == 404:
                    self.reply(404, b'{"error":"reader-exact-not-found"}')
                    return
                if not scoped(upstream_path, value):
                    self.deny()
                    return
                if private_image_id is not None:
                    projection = image_defaults.commit_image_config(value, policy.private_key_id,
                                                                   private_hmac_key)
                elif private_container_id is not None:
                    secret_projection = {
                        'Config': value['Config'], 'HostConfig': value['HostConfig'],
                        'Mounts': [{**{key: None for key in private.MOUNT}, **mount}
                                   for mount in value['Mounts']],
                        'NetworkSettings': value['NetworkSettings'],
                    }
                    service = value['Config']['Labels']['com.docker.compose.service']
                    projection = private.commit(policy.project, service, secret_projection,
                                                policy.private_key_id, private_hmac_key)
                else:
                    projection = _project(upstream_path, value, list_path)
                if time.monotonic() >= deadline:
                    raise ReaderHostError('reader-upstream-unknown')
                self.reply(200, json.dumps(projection, sort_keys=True, separators=(',', ':')).encode())
            except Exception:
                self.reply(502, b'{"error":"reader-upstream-unknown"}')
            finally:
                if watchdog is not None:
                    watchdog.cancel()
                if response is not None:
                    response.close()
                if connection is not None:
                    connection.close()

        def do_POST(self): self.deny()
        do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_TRACE = do_CONNECT = do_POST

    class ReaderServer(ThreadingHTTPServer):
        def finish_request(self, request, client_address):
            # ThreadingHTTPServer dispatches finish_request in its connection worker.
            # A silent TLS peer must never stall the listener's accept loop.
            request.settimeout(min(timeout, 5))
            wrapped = None
            try:
                wrapped = tls_context.wrap_socket(request, server_side=True)
                wrapped.settimeout(timeout)
                self.RequestHandlerClass(wrapped, client_address, self)
            except (OSError, ssl.SSLError):
                pass
            finally:
                if wrapped is not None:
                    wrapped.close()
                else:
                    request.close()

    server = ReaderServer(listen, Handler)
    server.daemon_threads = True
    return server
