"""Read-only Caddy probe tests. Docker, process and HTTP observations are fixtures."""
from copy import deepcopy
import ipaddress
import os
import socket
import ssl
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import test_deployment_compose_host_snapshot_v3_host as host_fixture
import deployment_compose_production_caddy_probe_v1_host as probe

CADDY, FRONTEND, NETWORK = 'a' * 64, 'b' * 64, 'c' * 64


class ProbeScopeTests(unittest.TestCase):
    def setUp(self):
        observer = object.__new__(host_fixture.host.HostSnapshotV3)
        observer._fresh = Mock()
        self.rows = {}
        for index, (cid, name) in enumerate(((CADDY, '/blog-caddy'), (FRONTEND, '/blog-frontend')), 2):
            self.rows[cid] = dict(Id=cid, Name=name, Image='sha256:'+'f'*64,
                Config={}, HostConfig={}, Mounts=[], RestartCount=0,
                NetworkSettings={'Networks': {probe._NETWORK: dict(NetworkID=NETWORK,
                    IPAddress=f'172.24.0.{index}', Aliases=['frontend'] if index == 3 else [])}},
                State=dict(Pid=index+100, StartedAt='now', Running=True, Paused=False,
                           Restarting=False, Dead=False, Status='running'))
        observer._get = Mock(side_effect=lambda path, *_: deepcopy(self.rows[path.split('/')[-2]]))
        self.probe = probe.ProductionCaddyProbeV1(observer, caddy_id=CADDY, network_id=NETWORK)
        self.observer = observer
        self.child = Mock(return_value=True)
        for change in (
                patch.object(probe, 'sys', SimpleNamespace(platform='linux')),
                patch.object(probe.os, 'geteuid', return_value=0),
                patch.object(probe.os, 'open', side_effect=[10, 11]),
                patch.object(probe.os, 'close'),
                patch.object(probe, '_namespace_identity', side_effect=lambda pid, fd: (pid, (1, fd))),
                patch.object(probe, '_probe', self.child)):
            change.start()
            self.addCleanup(change.stop)

    def test_uses_only_pinned_observations_and_closes_both_descriptors(self):
        self.observer._get.assert_not_called()
        self.assertIs(self.probe(FRONTEND), True)
        self.assertEqual(self.child.call_args.args[:2], (10, '172.24.0.3'))
        self.assertLessEqual(self.child.call_args.args[2], 18)
        self.assertEqual(len(self.observer._get.call_args_list), 6)
        self.assertEqual([call.args[0] for call in probe.os.close.call_args_list], [10, 11])

    def test_namespace_or_candidate_state_change_after_probe_fails_closed(self):
        def drift(*args):
            self.rows[FRONTEND]['State']['StartedAt'] = 'new-instance'
            return True
        self.child.side_effect = drift
        with self.assertRaises(ValueError):
            self.probe(FRONTEND)
        self.assertEqual(probe.os.close.call_count, 2)

    def test_wrong_pinned_network_never_launches_child(self):
        self.rows[FRONTEND]['NetworkSettings']['Networks'][probe._NETWORK]['NetworkID'] = CADDY
        with self.assertRaises(ValueError):
            self.probe(FRONTEND)
        self.child.assert_not_called()

    def test_invalid_candidate_id_never_reads_docker(self):
        for candidate in (CADDY, 'blog-frontend', FRONTEND + '/json'):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.probe(candidate)
        self.observer._get.assert_not_called()


class FixedChildTests(unittest.TestCase):
    def setUp(self):
        self.code = {'__name__': 'fixture'}
        exec(probe._PROBE_CODE, self.code)

    def test_dns_parser_rejects_wrong_query_and_preserves_duplicate_answers(self):
        def response(packet, *, bad=False):
            identity = struct.unpack_from('!H', packet)[0] ^ int(bad)
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + ipaddress.IPv4Address('172.24.0.3').packed
            return struct.pack('!HHHHHH', identity, 0x8180, 1, 2, 0, 0) + packet[12:] + answer * 2
        sock = Mock()
        connection = Mock()
        connection.__enter__ = Mock(return_value=sock)
        connection.__exit__ = Mock()
        sock.recv.side_effect = lambda _: response(sock.send.call_args.args[0])
        with patch.object(socket, 'socket', return_value=connection):
            self.assertEqual(self.code['answers'](1), [socket.inet_aton('172.24.0.3')] * 2)
            sock.recv.side_effect = lambda _: response(sock.send.call_args.args[0], bad=True)
            with self.assertRaises(ValueError):
                self.code['answers'](1)

    def test_https_fixed_routes_and_ready_requires_stable_dual_stack_dns(self):
        expected = '172.24.0.3'
        calls = []
        self.code['answers'] = lambda kind: [socket.inet_aton(expected)] if kind == 1 else []
        response = SimpleNamespace(status=200, headers=SimpleNamespace(defects=[]),
            getheader=lambda *_: 'identity', read=lambda _: b'ok', length=0)
        connection = Mock(getresponse=Mock(return_value=response))
        def build(host, *, timeout, context):
            self.assertEqual(host, 'makerhao.cn')
            self.assertEqual(timeout, 3)
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            return connection
        self.code['CaddyConnection'] = build
        connection.request.side_effect = lambda method, path, **kw: calls.append((method, path))
        self.assertTrue(self.code['ready'](expected))
        self.assertEqual(calls, [('GET','/'), ('GET','/health'), ('GET','/api/v1/articles/list?page_size=1')])
        response.status = 503
        self.assertFalse(self.code['ready'](expected))
        response.status = 200
        self.code['answers'] = Mock(side_effect=[[socket.inet_aton(expected)], [], [socket.inet_aton('172.24.0.4')]])
        self.assertFalse(self.code['ready'](expected))
