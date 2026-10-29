"""Absolute phase-read deadlines must defeat an active trickling Unix peer."""
import http.client
import os
from pathlib import Path
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'scripts'), str(ROOT/'packs/deployment/scripts')]
import deployment_compose_phase_state_v3_host as phase


@unittest.skipUnless(os.name == 'posix' and hasattr(socket, 'AF_UNIX'), 'Unix sockets required')
class PhaseDeadlineTests(unittest.TestCase):
    def producer(self, path):
        return phase.TrustedPhaseStateProducerV3(socket_path=str(path), project='dw-test',
            daemon_id='daemon', container_ids=('a'*64,), timeout=1)

    def test_trickling_response_cannot_extend_absolute_deadline(self):
        release, entered = threading.Event(), threading.Event()
        requests = []
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(1)
                data = bytearray()
                while b'\r\n\r\n' not in data:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    data.extend(chunk)
                requests.append(bytes(data).split(b'\r\n', 1)[0])
                entered.set()
                try:
                    self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n')
                    until = time.monotonic()+2
                    while time.monotonic() < until and not release.wait(.05):
                        self.request.sendall(b' ')
                except OSError:
                    pass  # The absolute watchdog must terminate this live stream.
        with tempfile.TemporaryDirectory(prefix='dw-phase-deadline-') as directory:
            path = Path(directory)/'docker.sock'
            server = socketserver.UnixStreamServer(str(path), Handler)
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            producer = self.producer(path)
            started = time.monotonic()
            try:
                with producer.operation_scope(started+.3):
                    with self.assertRaises((OSError, ValueError, http.client.HTTPException)):
                        producer._get('/v1.45/info')
                elapsed = time.monotonic()-started
                self.assertTrue(entered.is_set())
                self.assertEqual(requests, [b'GET /v1.45/info HTTP/1.1'])
                self.assertLess(elapsed, 1.5, 'body activity must not reset the absolute deadline')
            finally:
                release.set()
                server.shutdown()
                server.server_close()
                worker.join(3)
            self.assertFalse(worker.is_alive())

    def test_expired_scope_prevents_connection(self):
        producer = self.producer(Path('/tmp/dw-unused-deadline.sock'))
        with patch.object(phase, '_UnixDocker') as connection:
            with self.assertRaises((OSError, ValueError, TimeoutError)):
                with producer.operation_scope(time.monotonic()-1):
                    producer._get('/v1.45/info')
        connection.assert_not_called()
