"""Host-embedded write-only compose-v3 mTLS gateway; no authority endpoints."""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import re
import socket
import ssl
import time
import threading

from deployment_gateway_host import _UnixDocker, GatewayHostError
from deployment_gateway import FileWriterGate
import deployment_runtime as runtime

MAX_BODY = 1024 * 1024
MAX_RESPONSE = 4096
_HEX = re.compile(r'[0-9a-f]{64}')
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def _complete_response(response):
    headers = response.getheaders()
    lengths = [v for k, v in headers if k.lower() == 'content-length']
    if (response.headers.defects or len(headers) > 64
            or not 200 <= response.status <= 599
            or any(not _HEADER.fullmatch(k) or any(ord(c) < 32 and c != '\t' or ord(c) == 127 for c in v)
                   for k, v in headers)
            or any(k.lower() in ('transfer-encoding', 'content-encoding') for k, _ in headers)
            or len(lengths) > 1
            or lengths and (not re.fullmatch(r'[0-9]{1,6}', lengths[0]) or int(lengths[0]) > MAX_RESPONSE)
            or response.status in (204, 304) and lengths and int(lengths[0]) != 0):
        raise GatewayHostError('gateway-upstream-unknown')
    raw = bytearray()
    while len(raw) <= MAX_RESPONSE:
        chunk = response.read1(min(8192, MAX_RESPONSE + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    if (len(raw) > MAX_RESPONSE or lengths and len(raw) != int(lengths[0])
            or response.length not in (None, 0)):
        raise GatewayHostError('gateway-upstream-unknown')
    return bytes(raw)


def create_gateway_v3(gate, *, tls_context, docker_socket: Path, pre_dispatch,
                      listen=('127.0.0.1', 0), timeout=10, control_timeout=180, control_deadline=None):
    """Return an unstarted server. Only the trusted coordinator opens generations.

    pre_dispatch(method, path, body, generation, attempt_ref) must raise on a
    failed freshness, approval or protected-source guard. It grants no permit.
    """
    if (type(gate) is not FileWriterGate or gate.policy.operation_profile != 'compose-v3'
            or gate.policy.witness_required is not True
            or not isinstance(tls_context, ssl.SSLContext)
            or tls_context.verify_mode != ssl.CERT_REQUIRED
            or not isinstance(docker_socket, Path) or not docker_socket.is_absolute()
            or not callable(pre_dispatch) or type(timeout) not in (int, float)
            or not 1 <= timeout <= 180 or type(control_timeout) not in (int, float)
            or not 1 <= control_timeout <= 180
            or control_deadline is not None and (type(control_deadline) not in (int, float)
                or not time.monotonic() < control_deadline <= time.monotonic()+180)
            or not hasattr(socket, 'AF_UNIX')):
        raise GatewayHostError('gateway-host-policy-rejected')

    deadline = time.monotonic()+control_timeout if control_deadline is None else control_deadline

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass

        def _reply(self, status, body):
            self.close_connection = True
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def _deny(self):
            self._reply(403, b'{"error":"gateway-request-rejected"}')

        def handle_expect_100(self):
            self._deny()
            return False

        def _handle(self):
            ticket = None
            connection = response = watchdog = None
            try:
                peer = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
                generations = self.headers.get_all('X-Dev-Workflow-Generation', [])
                attempts = self.headers.get_all('X-Dev-Workflow-Attempt', [])
                lengths = self.headers.get_all('Content-Length', [])
                names = [key.lower() for key in self.headers.keys()]
                if (self.command not in ('POST', 'DELETE')
                        or peer != gate.policy.writer_certificate_sha256
                        or self.headers.defects or len(names) > 64 or len(set(names)) != len(names)
                        or any(not _HEADER.fullmatch(k) or any(ord(c) < 32 or ord(c) == 127 for c in v)
                               for k, v in self.headers.items())
                        or any(k in names for k in ('transfer-encoding', 'content-encoding', 'expect'))
                        or len(generations) != 1 or not _HEX.fullmatch(generations[0])
                        or len(attempts) != 1 or not _HEX.fullmatch(attempts[0])
                        or len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,7}', lengths[0])
                        or int(lengths[0]) > MAX_BODY):
                    self._deny()
                    return
                body = self.rfile.read(int(lengths[0]))
                if len(body) != int(lengths[0]):
                    self._deny()
                    return
                self.server.check_live()
                pre_dispatch(self.command, self.path, body, generations[0], attempts[0])
                self.server.check_live()
                ticket = FileWriterGate.admit(gate, generations[0], attempts[0],
                    method=self.command, path=self.path, body=body, writer_certificate_sha256=peer)
                # Cancellation and the final forwarding decision share one lock.
                # The serving thread remains owned until it is drained, even if
                # forwarding wins the race and its result becomes unknown.
                with self.server.dispatch_lock:
                    self.server.check_live()
                    connection = _UnixDocker(docker_socket, min(timeout, deadline-time.monotonic()))
                    connection.connect()
                    self.server.check_live()
                    watchdog = runtime.deadline_watchdog(connection.sock, min(deadline,time.monotonic()+timeout))
                    connection.request(self.command, self.path, body=body,
                        headers={'Content-Type': 'application/json', 'Connection': 'close'})
                response = connection.getresponse()
                raw = _complete_response(response)
                FileWriterGate.finish_response(gate, ticket, definitive=True, status=response.status, body=raw)
                # Clear only after durable witness and local acknowledgement. No retry.
                ticket = None
                self._reply(response.status, raw)
            except Exception:
                if ticket is not None:
                    try:
                        FileWriterGate.finish_response(gate, ticket, definitive=False, status=0, body=b'')
                    except Exception:
                        pass  # Remote-ahead or unresolved admission remains blocked.
                try:
                    if connection is None:
                        self._deny()
                    else:
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

        do_POST = do_DELETE = do_GET = do_PUT = do_PATCH = do_HEAD = do_OPTIONS = do_TRACE = do_CONNECT = _handle

    class WriterServer(HTTPServer):
        # A private per-step listener has exactly one serving owner. Shutdown
        # waits for that actual handler, not merely an accept-loop thread.
        def __init__(self, *args):
            self.dispatch_lock = threading.Lock()
            self.cancelled = threading.Event()
            self.lifecycle_lock = threading.Lock()
            self.serving = False
            self.closing = False
            self.owner = None
            self._owned_shutdown_waiter = None
            super().__init__(*args)

        def check_live(self):
            if self.closing or self.cancelled.is_set() or time.monotonic() >= deadline:
                raise GatewayHostError('gateway-control-expired-or-cancelled')

        def cancel(self):
            with self.dispatch_lock:
                self.cancelled.set()

        def serve_forever(self, *args, **kwargs):
            with self.lifecycle_lock:
                if self.closing: return
                self.serving = True
                self.owner = threading.get_ident()
            try:
                super().serve_forever(*args, **kwargs)
            finally:
                with self.lifecycle_lock:
                    self.serving = False

        def server_close(self):
            self.cancel()
            with self.lifecycle_lock:
                self.closing = True
                drain = self.serving and self.owner != threading.get_ident()
            if drain: self.shutdown()
            super().server_close()

        def drain_owned(self, thread, control_deadline):
            # Register before any operation that may time out. Closing rejects
            # new clients; without the dispatch barrier it is not a drain proof.
            with self.lifecycle_lock:
                self.closing = True
                self._blocked_drain = (thread, self._owned_shutdown_waiter)
            remaining = control_deadline-time.monotonic()
            if remaining <= 0 or not self.dispatch_lock.acquire(timeout=remaining):
                raise GatewayHostError('gateway-drain-deadline')
            try:
                self.cancelled.set()
            finally:
                self.dispatch_lock.release()
            with self.lifecycle_lock:
                needs_shutdown = self.serving and self.owner != threading.get_ident()
                if needs_shutdown and self._owned_shutdown_waiter is None:
                    self._owned_shutdown_waiter = threading.Thread(target=self.shutdown, daemon=True)
                    self._owned_shutdown_waiter.start()
                waiter = self._owned_shutdown_waiter
                self._blocked_drain = (thread, waiter)
            if waiter is not None:
                waiter.join(max(0,control_deadline-time.monotonic()))
            if thread.is_alive():
                thread.join(max(0,control_deadline-time.monotonic()))
            if (waiter is not None and waiter.is_alive()) or thread.is_alive():
                raise GatewayHostError('gateway-drain-deadline')
            HTTPServer.server_close(self)
            if time.monotonic() >= control_deadline:
                raise GatewayHostError('gateway-drain-deadline')
            del self._blocked_drain

        def finish_request(self, request, client_address):
            if self.closing:
                request.close()
                return
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
                    try:
                        wrapped.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    wrapped.close()
                else:
                    request.close()

    return WriterServer(listen, Handler)
