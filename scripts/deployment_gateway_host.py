"""Fixed trusted mTLS gateway for a local Unix Docker daemon.

Embed from a pinned distribution checkout. No CLI, ambient Docker discovery,
project plugins, shell commands or network backend are supported. The protected
FileWriterGate records admission before forwarding and definitive completion
before replying; upstream uncertainty remains blocked across process restarts.
"""
from __future__ import annotations

import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import ssl
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
import deployment_runtime as runtime
from deployment_gateway import FileWriterGate, GateError

MAX_BODY = 1024 * 1024


class GatewayHostError(ValueError):
    pass


class _UnixDocker(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self._socket_path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


def _complete_response(response, *, mutation):
    """A bounded read returning bytes is insufficient to prove HTTP completion."""
    headers = response.getheaders()
    if len(headers) > 64 or not 200 <= response.status <= 599:
        raise GatewayHostError('gateway-upstream-unknown')
    lengths = [value for key, value in headers if key.lower() == 'content-length']
    transfers = [value for key, value in headers if key.lower() == 'transfer-encoding']
    if (len(lengths) > 1 or (lengths and transfers) or (mutation and transfers)
            or (lengths and (not re.fullmatch(r'[0-9]{1,10}', lengths[0]) or int(lengths[0]) > MAX_BODY))
            or (response.status == 204 and lengths and int(lengths[0]) != 0)):
        raise GatewayHostError('gateway-upstream-unknown')
    raw = bytearray()
    while len(raw) <= MAX_BODY:
        chunk = response.read1(min(65536, MAX_BODY + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    if (len(raw) > MAX_BODY or (lengths and len(raw) != int(lengths[0]))
            or response.length not in (None, 0)):
        raise GatewayHostError('gateway-upstream-unknown')
    return bytes(raw)


def create_gateway(policy, gate, *, tls_context, reader_certificate_sha256,
                   docker_socket, listen=('127.0.0.1', 0), timeout=45):
    """Host supplies every trust input; returned server is not started implicitly."""
    if (type(policy) is not runtime.RuntimePolicy or type(gate) is not FileWriterGate
            or not isinstance(tls_context, ssl.SSLContext)
            or tls_context.verify_mode != ssl.CERT_REQUIRED
            or type(reader_certificate_sha256) is not str
            or not runtime.HEX.fullmatch(reader_certificate_sha256)
            or reader_certificate_sha256 == gate.policy.writer_certificate_sha256
            or not isinstance(docker_socket, Path) or not docker_socket.is_absolute()
            or type(timeout) not in (int, float) or not 1 <= timeout <= 180
            or not hasattr(socket, 'AF_UNIX')):
        raise GatewayHostError('gateway-host-policy-rejected')
    from urllib.parse import urlencode
    list_path = '/v1.45/containers/json?' + urlencode({'all': '1', 'filters': runtime.canonical(
        {'label': ['com.docker.compose.project=' + policy.project]})})
    images = {entry['imageId'] for entry in runtime._catalog(policy).values()}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def _reply(self, status, raw):
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

        def _deny(self):
            self._reply(403, b'{"error":"gateway-request-rejected"}')

        def _allowed_get(self):
            path = self.path
            image = re.fullmatch(r'/v1\.45/images/(sha256:[0-9a-f]{64})/json', path)
            return (path in ('/v1.45/info', list_path)
                or (image is not None and image[1] in images)
                or re.fullmatch(r'/v1\.45/containers/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/json', path)
                or re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/archive\?path=%2Fetc%2F(?:hosts|hostname|resolv\.conf)', path))

        def _handle(self):
            self.connection.settimeout(timeout)
            peer = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
            if peer not in (reader_certificate_sha256, gate.policy.writer_certificate_sha256):
                self._deny()
                return
            if self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Content-Encoding'):
                self._deny()
                return
            lengths = self.headers.get_all('Content-Length', [])
            if (len(lengths) > 1 or (lengths and not re.fullmatch(r'[0-9]{1,7}', lengths[0]))):
                self._deny()
                return
            size = int(lengths[0]) if lengths else 0
            if size > MAX_BODY or (self.command in ('GET', 'DELETE') and size):
                self._deny()
                return
            body = self.rfile.read(size)
            if len(body) != size:
                self._deny()
                return
            ticket = None
            if self.command == 'GET':
                if self.path == '/v1.45/workflow/gate-info':
                    self._reply(200, runtime.canonical(gate.info()).encode('ascii'))
                    return
                if not self._allowed_get():
                    self._deny()
                    return
            else:
                generations = self.headers.get_all('X-Dev-Workflow-Generation', [])
                attempts = self.headers.get_all('X-Dev-Workflow-Attempt', [])
                if peer != gate.policy.writer_certificate_sha256 or len(generations) != 1 or len(attempts) != 1:
                    self._deny()
                    return
                try:
                    ticket = FileWriterGate.admit(gate, generations[0], attempts[0], method=self.command,
                        path=self.path, body=body, writer_certificate_sha256=peer)
                except GateError:
                    self._deny()
                    return
            if self.command == 'GET' and '/archive?' in self.path:
                reference = self.path.split('/')[3]
                scope_connection = scope_response = scope_watchdog = None
                try:
                    scope_connection = _UnixDocker(docker_socket, timeout)
                    scope_connection.connect()
                    scope_watchdog = runtime.deadline_watchdog(scope_connection.sock, time.monotonic() + timeout)
                    scope_connection.request('GET', '/v1.45/containers/' + reference + '/json')
                    scope_response = scope_connection.getresponse()
                    scope_raw = _complete_response(scope_response, mutation=False)
                    scope_value = runtime.parse_json(scope_raw.decode('utf-8'))
                    if (scope_response.status != 200 or type(scope_value) is not dict
                            or scope_value.get('Id') != reference
                            or scope_value.get('Config', {}).get('Labels', {}).get('com.docker.compose.project') != policy.project):
                        self._deny()
                        return
                except Exception:
                    self._deny()
                    return
                finally:
                    if scope_watchdog is not None:
                        scope_watchdog.cancel()
                    if scope_response is not None:
                        scope_response.close()
                    if scope_connection is not None:
                        scope_connection.close()
            connection = response = watchdog = None
            definitive = False
            try:
                connection = _UnixDocker(docker_socket, timeout)
                connection.connect()
                watchdog = runtime.deadline_watchdog(connection.sock, time.monotonic() + timeout)
                connection.request(self.command, self.path, body=body or None,
                    headers={'Content-Type': 'application/json', 'Connection': 'close'})
                response = connection.getresponse()
                raw = _complete_response(response, mutation=ticket is not None)
                if (self.command == 'GET' and re.fullmatch(
                        r'/v1\.45/containers/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/json', self.path)
                        and response.status == 200):
                    inspected = runtime.parse_json(raw.decode('utf-8'))
                    if (type(inspected) is not dict or inspected.get('Config', {}).get('Labels', {}).get(
                            'com.docker.compose.project') != policy.project):
                        self._deny()
                        return
                # A complete HTTP error is also a definitive upstream outcome.
                if ticket is not None:
                    FileWriterGate.finish(gate, ticket, definitive=True, response_hash=hashlib.sha256(
                        str(response.status).encode('ascii') + b'\0' + raw).hexdigest())
                definitive = True
                self._reply(response.status, raw)
            except Exception:
                if ticket is not None and not definitive:
                    try:
                        FileWriterGate.finish(gate, ticket, definitive=False, response_hash=None)
                    except GateError:
                        pass  # The persisted admission already blocks quiescence.
                try:
                    self._reply(502, b'{"error":"gateway-upstream-unknown"}')
                except OSError:
                    pass
            finally:
                if watchdog is not None:
                    watchdog.cancel()
                if response is not None:
                    response.close()
                if connection is not None:
                    connection.close()

        def do_GET(self):
            self._handle()

        do_POST = do_DELETE = do_GET

    server = ThreadingHTTPServer(listen, Handler)
    server.daemon_threads = True
    try:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    except Exception:
        server.server_close()
        raise GatewayHostError('gateway-tls-rejected') from None
    return server
