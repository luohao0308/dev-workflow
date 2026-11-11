"""Fixed read-only readiness probe for the retained production frontend."""
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

from deployment_compose_host_snapshot_v3_host import HostSnapshotV3
from deployment_compose_phase_guard_v3_host import _lifecycle, protected_state_digest
from deployment_compose_recovery_daemon_v3_host import _ticks

_NETWORK = 'luohao-blog-prod_default'
_HEX = re.compile(r'[0-9a-f]{64}')
# The child enters the pinned network namespace only. Its host filesystem and
# system trust store stay intact. The only dynamic argument is an IPv4 address.
_PROBE_CODE = r'''
import http.client
import secrets
import socket
import ssl
import struct
import sys

NAME = b'\x08frontend\0'


def answers(kind):
    ident = secrets.randbits(16)
    question = NAME + struct.pack('!HH', kind, 1)
    packet = struct.pack('!HHHHHH', ident, 0x100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(2)
        connection.connect(('127.0.0.11', 53))
        connection.send(packet)
        data = connection.recv(4097)
    if not len(packet) <= len(data) <= 4096:
        raise ValueError()
    rid, flags, nq, count, authority, extra = struct.unpack_from('!HHHHHH', data)
    if (rid != ident or not flags & 0x8000 or flags & 0x7a0f or nq != 1
            or count > 16 or authority or extra or data[12:len(packet)] != question):
        raise ValueError()
    offset = len(packet)
    result = []
    for _ in range(count):
        if data[offset:offset+2] == b'\xc0\x0c':
            offset += 2
        elif data[offset:offset+len(NAME)].lower() == NAME:
            offset += len(NAME)
        else:
            raise ValueError()
        rrtype, rrclass, ttl, size = struct.unpack_from('!HHIH', data, offset)
        offset += 10
        if rrtype != kind or rrclass != 1 or size != (4 if kind == 1 else 16) or offset + size > len(data):
            raise ValueError()
        result.append(data[offset:offset+size])
        offset += size
    if offset != len(data):
        raise ValueError()
    return result


class CaddyConnection(http.client.HTTPSConnection):
    def connect(self):
        with socket.create_connection(('127.0.0.1', 443), self.timeout) as raw:
            # wrap_socket takes ownership of the descriptor. Connect, Host
            # header and certificate verification all remain fixed here.
            self.sock = self._context.wrap_socket(raw, server_hostname='makerhao.cn')


def ready(expected):
    if answers(1) != [socket.inet_aton(expected)] or answers(28):
        return False
    context = ssl.create_default_context()
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        return False
    for path, limit in (('/', 1048576), ('/health', 4096), ('/api/v1/articles/list?page_size=1', 262144)):
        connection = CaddyConnection('makerhao.cn', timeout=3, context=context)
        try:
            connection.request('GET', path, headers={'Connection': 'close', 'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            if (response.status != 200 or response.headers.defects
                    or response.getheader('Content-Encoding', 'identity').lower() != 'identity'
                    or not 0 < len(response.read(limit + 1)) <= limit
                    or response.length not in (0, None)):
                return False
        finally:
            connection.close()
    return answers(1) == [socket.inet_aton(expected)] and not answers(28)

if __name__ == '__main__':
    try:
        success = ready(sys.argv[1])
    except (OSError, ValueError, struct.error, http.client.HTTPException):
        success = False
    print('ready' if success else 'not-ready')
'''


def reject():
    raise ValueError('production-caddy-probe-identity-mismatch') from None


def _valid_id(value):
    return type(value) is str and _HEX.fullmatch(value) is not None


def _ns_identity(info):
    return info.st_dev, info.st_ino


def _namespace_identity(pid, fd):
    ticks = _ticks(pid)
    if type(ticks) is not int or ticks <= 0:
        reject()
    path = Path('/proc') / str(pid) / 'ns/net'
    identity = _ns_identity(os.fstat(fd))
    if (_ns_identity(path.stat()) != identity or _ticks(pid) != ticks
            or identity == _ns_identity(Path('/proc/self/ns/net').stat())):
        reject()
    return ticks, identity


def _probe(namespace_fd, address, timeout):
    try:
        process = subprocess.run(
            ['/usr/bin/nsenter', '--net=/proc/self/fd/' + str(namespace_fd), '--',
             '/usr/bin/python3', '-I', '-S', '-c', _PROBE_CODE, address],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            pass_fds=(namespace_fd,), env={}, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return process.returncode == 0 and process.stdout == b'ready\n'


class ProductionCaddyProbeV1:
    def __init__(self, observer, *, caddy_id, network_id):
        if type(observer) is not HostSnapshotV3 or not _valid_id(caddy_id) or not _valid_id(network_id):
            reject()
        self._observer = observer
        self._caddy_id, self._network_id = caddy_id, network_id
        self._owner = os.getpid(), threading.current_thread()

    def _row(self, cid, name, deadline):
        row = self._observer._get('/v1.45/containers/' + cid + '/json', deadline, [2*1024*1024])
        _lifecycle(row, 'running')
        if row['Id'] != cid or row['Name'] != name or row['State']['Pid'] <= 1:
            reject()
        endpoint = row['NetworkSettings']['Networks'][_NETWORK]
        if endpoint['NetworkID'] != self._network_id:
            reject()
        ip = ipaddress.IPv4Address(endpoint['IPAddress'])
        if str(ip) != endpoint['IPAddress'] or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            reject()
        return row, endpoint

    def __call__(self, candidate_id):
        if (self._owner != (os.getpid(), threading.current_thread()) or sys.platform != 'linux'
                or os.geteuid() != 0 or not _valid_id(candidate_id) or candidate_id == self._caddy_id):
            reject()
        deadline = time.monotonic() + 28
        pins = ((self._caddy_id, '/blog-caddy'), (candidate_id, '/blog-frontend'))
        handles = []
        try:
            self._observer._fresh(deadline)
            initial = []
            for cid, name in pins:
                row, endpoint = self._row(cid, name, deadline)
                pid = row['State']['Pid']
                fd = os.open(Path('/proc') / str(pid) / 'ns/net', os.O_RDONLY | os.O_CLOEXEC)
                handles.append(fd)
                initial.append((row, endpoint, _namespace_identity(pid, fd)))
            aliases = initial[1][1].get('Aliases')
            if (initial[0][2][1] == initial[1][2][1]
                    or initial[0][1]['IPAddress'] == initial[1][1]['IPAddress']
                    or initial[1][1].get('GlobalIPv6Address') not in (None, '')
                    or type(aliases) is not list or len(aliases) > 32
                    or any(type(alias) is not str for alias in aliases)
                    or aliases.count('frontend') != 1):
                reject()

            def recheck():
                self._observer._fresh(deadline)
                for (cid, name), fd, (original, _, identity) in zip(pins, handles, initial):
                    current, _ = self._row(cid, name, deadline)
                    if (protected_state_digest(current) != protected_state_digest(original)
                            or _namespace_identity(current['State']['Pid'], fd) != identity):
                        reject()

            recheck()
            remaining = min(18, deadline - time.monotonic() - 5)
            if remaining <= 0:
                reject()
            result = _probe(handles[0], initial[1][1]['IPAddress'], remaining)
            recheck()
            if time.monotonic() >= deadline:
                reject()
            return result
        except (KeyError, TypeError, AttributeError, OSError):
            reject()
        finally:
            for fd in handles:
                os.close(fd)
