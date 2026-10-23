"""Independent synthetic contracts and loopback HTTP/TLS proof; no Docker writes."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
import deployment_verify as verify
import deployment_runtime as runtime
import deployment_spec as specification

IMAGE = 'sha256:' + 'a' * 64
CID = 'b' * 64
SECRET = 'PRIVATE-PROBE-VALUE-DO-NOT-EXPORT'


def fixture(port=18080, *, scheme='http', pin=None, hostname=None):
    spec = specification.ContainerSpec.from_image('web', {
        'Id': IMAGE, 'Os': 'linux', 'Config': {'User': '1000', 'Cmd': ['/app'],
        'Env': ['TOKEN=' + SECRET], 'ExposedPorts': {'8080/tcp': {}}}},
        port_bindings={'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(port)}]})
    catalog = {'schemaVersion': 1, 'images': [{'component': 'web', 'imageId': IMAGE,
        'repository': 'fixture/example', 'sourceSha': 'c' * 40, 'version': '1.0.0',
        'os': 'linux', 'architecture': 'amd64',
        'artifact': {'kind': 'local-build', 'imageId': IMAGE, 'buildSourceSha': 'c' * 40},
        'migration': {'mode': 'none', 'version': None}}]}
    policy = runtime.RuntimePolicy(endpoint='https://localhost:2376',
        server_certificate_sha256='d' * 64, daemon_id='fixture', repository='fixture/example',
        environment='staging', target='fixture', production=False, project='fixture',
        components=('web',), catalog_json=json.dumps(catalog),
        specifications_json=specification.specifications_json((spec,)))
    profile = {'component': 'web', 'imageId': IMAGE, 'specHash': spec.configuration_digest(),
        'containerPort': '8080/tcp', 'hostIp': '127.0.0.1', 'hostPort': str(port),
        'address': '127.0.0.1', 'scheme': scheme, 'tlsHostname': hostname,
        'serverCertificateSha256': pin, 'health': [probe('ready')], 'smoke': [probe('business')]}
    config = spec.to_dict()
    host = config['hostConfig']
    host.update(Privileged=False, PidMode='', IpcMode='private', UTSMode='')
    container = {'Id': CID, 'Image': IMAGE, 'Config': config['config'], 'HostConfig': host,
        'Mounts': [], 'NetworkSettings': {'Ports': deepcopy(host['PortBindings']),
                                       'Networks': {'bridge': {}}},
        'State': {'Running': True, 'Paused': False, 'Restarting': False, 'Dead': False, 'Status': 'running'}}
    assert spec.matches(container)
    return spec, policy, profile, container


def probe(name):
    return {'id': name, 'path': '/' + name, 'status': 200,
            'jsonExpectations': {'/ok': True}, 'attempts': 1, 'retryDelay': 0,
            'timeout': 1, 'maxBodyBytes': 1024}


def probe_policy(runtime_policy, profiles, **changes):
    return verify.ProbePolicy(runtime_policy.identity_hash(), json.dumps({
        'schemaVersion': 1, 'kind': 'deployment-probe-policy', 'profiles': profiles}), **changes)


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.runtime, self.profile, self.container = fixture()
        self.calls, self.guards = [], []

    def transport(self, profile, probe, deadline):
        self.calls.append((profile, probe, deadline))
        return 200, [('Content-Type', 'application/json')], b'{"ok":true}'

    def verifier(self, profile=None, transport=None, **kwargs):
        return verify.TrustedProbeVerifier(probe_policy(self.runtime, [profile or self.profile]),
            self.runtime, transport=transport or self.transport, **kwargs)

    def run_check(self, verifier=None, **kwargs):
        verifier = verifier or self.verifier()
        values = dict(container=self.container, guard=lambda: self.guards.append(True),
                      deadline=time.monotonic() + 5)
        values.update(kwargs)
        return verifier.check(verifier.bind('web', self.spec), **values)

    def test_api_pass_binding_and_redacted_report(self):
        self.profile['health'][0]['jsonExpectations'] = {'/private': SECRET}
        def response(*_):
            return 200, [('Secret', SECRET)], json.dumps({'private': SECRET, 'ok': True}).encode()
        verifier = self.verifier(transport=response)
        binding = verifier.bind('web', self.spec)
        self.assertEqual(set(json.loads(binding)), {'policyHash', 'component', 'imageId', 'specHash', 'probeIds'})
        result = self.run_check(verifier)
        self.assertTrue(result['passed'])
        self.assertEqual((result['health'], result['smoke']), ('passed', 'passed'))
        self.assertEqual(len(self.guards), 4)
        self.assertEqual(set(result['checks'][0]), {'id', 'phase', 'status', 'attempts', 'durationMs',
                                                'responseHash', 'errorCode', 'httpStatus'})
        self.assertNotIn(SECRET, json.dumps(result) + binding)
        self.assertNotIn('127.0.0.1', json.dumps(result) + binding)
        self.assertEqual(result['checks'][0]['responseHash'], hashlib.sha256(response()[2]).hexdigest())

    def test_policy_canonical_identity_and_frozen_storage(self):
        policy = probe_policy(self.runtime, [self.profile])
        changed = verify.ProbePolicy(self.runtime.identity_hash(), json.dumps(json.loads(policy.profiles_json), indent=4))
        self.assertEqual(policy.identity_hash(), changed.identity_hash())
        with self.assertRaises(FrozenInstanceError):
            policy.total_timeout = 2
        self.profile['health'][0]['path'] = '/changed'
        self.assertNotIn('/changed', policy.profiles_json)
        self.assertNotEqual(policy.identity_hash(), probe_policy(self.runtime, [self.profile]).identity_hash())

    def test_policy_rejects_unknown_missing_empty_duplicate_and_bad_types(self):
        mutations = [lambda p: p.update(extra=SECRET), lambda p: p.pop('address'),
            lambda p: p.update(health=[]), lambda p: p['smoke'][0].update(id='ready'),
            lambda p: p.update(containerPort='8080/udp'), lambda p: p.update(hostPort='0'),
            lambda p: p.update(hostPort='08080'), lambda p: p.update(hostPort='65536'),
            lambda p: p.update(address='localhost'), lambda p: p.update(address='192.0.2.1'),
            lambda p: p.update(hostIp='192.0.2.1', address='192.0.2.1'),
            lambda p: p['health'][0].update(attempts=True), lambda p: p['health'][0].update(timeout=.001),
            lambda p: p['health'][0].update(status=303), lambda p: p['health'][0].update(retryDelay=3),
            lambda p: p['health'][0].update(maxBodyBytes=65537),
            lambda p: p['health'][0].update(jsonExpectations={}),
            lambda p: p['health'][0].update(jsonExpectations={'bad': True}),
            lambda p: p['health'][0].update(jsonExpectations={'/~2': True}),
            lambda p: p['health'][0].update(jsonExpectations={'/ok': {}})]
        for mutation in mutations:
            value = deepcopy(self.profile)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(verify.VerificationError, '^probe-policy-rejected$'):
                probe_policy(self.runtime, [value])
        with self.assertRaises(verify.VerificationError):
            probe_policy(self.runtime, [self.profile, self.profile])
        for timeout in (False, 0, 121, 1.5):
            with self.subTest(timeout=timeout), self.assertRaises(verify.VerificationError):
                probe_policy(self.runtime, [self.profile], total_timeout=timeout)
        with self.assertRaises(verify.VerificationError):
            replace(probe_policy(self.runtime, [self.profile]), runtime_policy_hash='sha256:' + 'a' * 64)

    def test_fixed_paths_refuse_urls_traversal_and_encoded_controls(self):
        for path in ('https://private.invalid/x', '//private/x', '/a?token=x', '/a#x', '/a\\b',
                     '/a/../b', '/%2e%2e/x', '/%252e%252e/x', '/%0d%0aHost:x', '/%3fx', '/a b', '/é'):
            value = deepcopy(self.profile)
            value['health'][0]['path'] = path
            with self.subTest(path=path), self.assertRaises(verify.VerificationError):
                probe_policy(self.runtime, [value])

    def test_strict_json_policy_and_response(self):
        for body in ('{"ok":true,"ok":false}', '{"ok":NaN}', '{"ok":Infinity}', '{"ok":1e999}',
                     '{"ok":1e101}', '{"ok":"\\ud800"}', '[' * 30 + '0' + ']' * 30):
            with self.subTest(body=body):
                result = self.run_check(self.verifier(transport=lambda *_, body=body: (200, [], body.encode())))
                self.assertFalse(result['passed'])
                self.assertEqual(result['checks'][0]['errorCode'], 'probe-json-rejected')
        policy = probe_policy(self.runtime, [self.profile])
        with self.assertRaises(verify.VerificationError):
            replace(policy, profiles_json=policy.profiles_json.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'))
        with self.assertRaises(verify.VerificationError):
            replace(policy, profiles_json=' ' * 262145)

    def test_exact_predicates_pointer_null_missing_array_and_numeric_types(self):
        cases = [({'/ok': True}, {'ok': 1}, False), ({'/ok': None}, {}, False),
                 ({'/ok': None}, {'ok': None}, True), ({'/ok': 1}, {'ok': True}, False),
                 ({'/ok': 1}, {'ok': 1.0}, False), ({'': True}, True, True),
                 ({'/a~1b/~0/0': 'yes'}, {'a/b': {'~': ['yes']}}, True),
                 ({'/a/00': 1}, {'a': [1]}, False), ({'/a/999999': 1}, {'a': [1]}, False)]
        for expectations, body, passed in cases:
            with self.subTest(expectations=expectations, body=body):
                profile = deepcopy(self.profile)
                for phase in ('health', 'smoke'):
                    profile[phase][0]['jsonExpectations'] = expectations
                result = self.run_check(self.verifier(profile, lambda *_: (200, [], json.dumps(body).encode())))
                self.assertEqual(result['passed'], passed)

    def test_bad_headers_status_and_size_fail_closed(self):
        cases = [(302, [('Location', 'https://private.invalid')], b'{"ok":true}'),
                 (200, [('Content-Encoding', 'gzip')], b'{"ok":true}'),
                 (200, [('Content-Length', '11'), ('content-length', '11')], b'{"ok":true}'),
                 (200, [('Content-Length', '11'), ('Transfer-Encoding', 'chunked')], b'{"ok":true}'),
                 (200, [('Content-Length', '100')], b'{"ok":true}'),
                 (200, [('Content-Length', '-1')], b'{"ok":true}'),
                 (200, [('X', 'bad\r\nPrivate: secret')], b'{"ok":true}'),
                 (200, [('X', 'a' * 16385)], b'{"ok":true}'),
                 (200, [('X', 'a')] * 65, b'{"ok":true}'),
                 (200, [('Transfer-Encoding', 'gzip')], b'{"ok":true}'),
                 (200, [], b' ' * 1025), (True, [], b'{"ok":true}'),
                 (200, [], '{"ok":true}'), (200, [], b'\xff')]
        for response in cases:
            with self.subTest(index=cases.index(response)):
                result = self.run_check(self.verifier(transport=lambda *_: response))
                self.assertFalse(result['passed'])
                self.assertEqual(result['smoke'], 'not-run')
                self.assertEqual(len(result['checks']), 1)
                self.assertNotIn('private.invalid', json.dumps(result))

    def test_retry_and_failure_skip_remaining_checks(self):
        self.profile['health'][0]['attempts'] = 3
        def retry(*args):
            self.calls.append(args)
            return 503 if len(self.calls) < 3 else 200, [('Retry-After', '999999')], b'{"ok":true}'
        result = self.run_check(self.verifier(transport=retry))
        self.assertTrue(result['passed'])
        self.assertEqual(result['checks'][0]['attempts'], 3)
        self.assertEqual(len(self.calls), 4)
        self.profile['smoke'].append(probe('never'))
        result = self.run_check(self.verifier(transport=lambda _, p, d: (200, [],
            b'{"ok":true}' if p['id'] == 'ready' else b'{"ok":false}')))
        self.assertEqual((result['health'], result['smoke']), ('passed', 'failed'))
        self.assertEqual([c['id'] for c in result['checks']], ['ready', 'business'])

    def test_network_error_is_sanitized_and_guard_after_error_runs(self):
        def failing(*_):
            raise OSError(SECRET)
        result = self.run_check(self.verifier(transport=failing))
        self.assertEqual(result['checks'][0]['errorCode'], 'probe-network-failed')
        self.assertEqual(len(self.guards), 2)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_guard_failure_before_and_after_read_always_propagates(self):
        for fail_at in (1, 2):
            count = []
            def guard():
                count.append(True)
                if len(count) == fail_at:
                    raise OSError('authority-revoked')
            with self.subTest(fail_at=fail_at), self.assertRaisesRegex(OSError, 'authority-revoked'):
                self.run_check(guard=guard)
            self.assertEqual(len(count), fail_at)
        self.assertEqual(len(self.calls), 1)

    def test_guard_failure_after_network_error_propagates_and_total_budget_is_capped(self):
        guards = []
        def guard():
            guards.append(True)
            if len(guards) == 2:
                raise OSError('authority-revoked')
        def network_error(*_):
            raise OSError(SECRET)
        with self.assertRaisesRegex(OSError, '^authority-revoked$'):
            self.run_check(self.verifier(transport=network_error), guard=guard)
        self.assertEqual(len(guards), 2)
        profile = deepcopy(self.profile)
        profile['health'][0]['timeout'] = 10
        policy = probe_policy(self.runtime, [profile], total_timeout=1)
        verifier = verify.TrustedProbeVerifier(policy, self.runtime, transport=self.transport)
        started = time.monotonic()
        self.assertTrue(self.run_check(verifier, deadline=started + 100)['passed'])
        self.assertLessEqual(max(call[2] for call in self.calls), started + 1.05)

    def test_changed_runtime_scope_and_unissued_binding_rejected(self):
        verifier = self.verifier()
        binding = verifier.bind('web', self.spec)
        other = self.verifier()
        with self.assertRaisesRegex(verify.VerificationError, '^probe-binding-rejected$'):
            other.check(binding, container=self.container, guard=lambda: None, deadline=time.monotonic() + 1)
        verifier.runtime_policy = replace(self.runtime, production=True)
        with self.assertRaisesRegex(verify.VerificationError, '^probe-scope-rejected$'):
            self.run_check(verifier)
        self.assertEqual(self.calls, [])

    def test_post_read_authority_guard_does_not_spend_network_timeout(self):
        profile = deepcopy(self.profile)
        for phase in ('health', 'smoke'):
            profile[phase][0]['timeout'] = .05
        count = 0
        def guard():
            nonlocal count
            count += 1
            if count % 2 == 0:
                time.sleep(.07)
        result = self.run_check(self.verifier(profile), guard=guard)
        self.assertTrue(result['passed'])
        self.assertEqual(count, 4)

    def test_deadlines_before_after_guard_after_read_and_retry(self):
        with self.assertRaisesRegex(verify.VerificationError, 'probe-deadline-exceeded'):
            self.run_check(deadline=time.monotonic() - 1)
        self.assertEqual(self.calls, [])
        def guard():
            time.sleep(.03)
        with self.assertRaisesRegex(verify.VerificationError, 'probe-deadline-exceeded'):
            self.run_check(guard=guard, deadline=time.monotonic() + .01)
        self.assertEqual(self.calls, [])
        profile = deepcopy(self.profile)
        profile['health'][0]['timeout'] = .05
        def late(*_):
            time.sleep(.07)
            return 200, [], b'{"ok":true}'
        result = self.run_check(self.verifier(profile, late))
        self.assertEqual(result['checks'][0]['errorCode'], 'probe-deadline-exceeded')
        profile['health'][0].update(attempts=2, retryDelay=2)
        with self.assertRaisesRegex(verify.VerificationError, 'probe-deadline-exceeded'):
            self.run_check(self.verifier(profile, lambda *_: (503, [], b'{}')), deadline=time.monotonic() + .1)

    def test_scope_and_binding_refused_before_http(self):
        policy = probe_policy(self.runtime, [self.profile])
        with self.assertRaises(verify.VerificationError):
            verify.TrustedProbeVerifier(replace(policy, runtime_policy_hash='e' * 64), self.runtime, transport=self.transport)
        with self.assertRaises(verify.VerificationError):
            verify.TrustedProbeVerifier(policy, replace(self.runtime, specifications_json=None), transport=self.transport)
        profile = deepcopy(self.profile)
        profile['specHash'] = 'sha256:' + 'f' * 64
        with self.assertRaises(verify.VerificationError):
            self.verifier(profile)
        verifier = self.verifier()
        with self.assertRaises(verify.VerificationError):
            verifier.bind('other', self.spec)
        with self.assertRaises(verify.VerificationError):
            verifier.bind('web', specification.ContainerSpec.from_image('web', {
                'Id': IMAGE, 'Os': 'linux', 'Config': {'User': '1000', 'Cmd': ['/other']}}))
        binding = verifier.bind('web', self.spec)
        for changed in (binding + ' ', binding.replace('ready', 'untrusted'), '{}'):
            with self.assertRaises(verify.VerificationError):
                verifier.check(changed, container=self.container, guard=lambda: None, deadline=time.monotonic() + 1)
        # A profile with a matching spec digest but the wrong declared target is refused at bind.
        profile = deepcopy(self.profile)
        profile['hostPort'] = '18081'
        with self.assertRaises(verify.VerificationError):
            self.verifier(profile).bind('web', self.spec)
        self.assertEqual(self.calls, [])

    def test_actual_image_spec_running_and_published_port_required_before_calls(self):
        mutations = [lambda c: c.update(Id='bad'), lambda c: c.update(Image='sha256:' + 'e' * 64),
            lambda c: c['Config'].update(Env=['TOKEN=changed']),
            lambda c: c['State'].update(Running=False), lambda c: c['State'].update(Paused=True),
            lambda c: c['State'].update(Restarting=True), lambda c: c['State'].update(Dead=True),
            lambda c: c['NetworkSettings'].update(Ports={}),
            lambda c: c['NetworkSettings']['Ports']['8080/tcp'][0].update(HostPort='18081'),
            lambda c: c['NetworkSettings']['Ports']['8080/tcp'][0].update(HostIp='0.0.0.0')]
        for mutation in mutations:
            changed = deepcopy(self.container)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(verify.VerificationError, 'probe-container-rejected'):
                self.run_check(container=changed)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.guards, [])

    def test_trusted_transport_cannot_change_cached_profile_or_probe(self):
        def mutate(profile, probe, deadline):
            self.assertEqual(profile['address'], '127.0.0.1')
            self.assertEqual(probe['jsonExpectations'], {'/ok': True})
            profile['address'] = '192.0.2.1'
            probe['jsonExpectations'] = {'/ok': False}
            return 200, [], b'{"ok":true}'
        # Mutating a hook argument must not even change the active predicates.
        self.assertTrue(self.run_check(self.verifier(transport=mutate))['passed'])

    def test_chunked_wire_responses_are_refused_before_body_parsing(self):
        for wire in (b'b\r\n{"ok":true}XX0\r\n\r\n',
                     b'b\r\n{"ok":true}\r\n0\r\n',
                     b'b\r\n{"ok":true}\r\n0\r\n\r\n'):
            peer = mock.Mock()
            peer.makefile.side_effect = lambda *args: BytesIO(
                b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' + wire)
            with self.subTest(wire=wire), mock.patch.object(verify.socket, 'socket', return_value=peer), \
                    mock.patch.object(runtime, 'deadline_watchdog'):
                verifier = verify.TrustedProbeVerifier(probe_policy(self.runtime, [self.profile]), self.runtime)
                result = self.run_check(verifier)
                self.assertFalse(result['passed'])
                self.assertEqual(result['checks'][0]['errorCode'], 'probe-response-rejected')

    def test_in_memory_socket_http_parser_and_watchdog_without_dns(self):
        peer = mock.Mock()
        peer.makefile.side_effect = lambda *args: BytesIO(
            b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{"ok":true}')
        with mock.patch.object(verify.socket, 'socket', return_value=peer) as create_socket, \
                mock.patch.object(verify.socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
                mock.patch.object(runtime, 'deadline_watchdog') as watchdog:
            verifier = verify.TrustedProbeVerifier(probe_policy(self.runtime, [self.profile]), self.runtime)
            result = self.run_check(verifier)
        self.assertTrue(result['passed'])
        self.assertEqual(create_socket.call_args, mock.call(socket.AF_INET, socket.SOCK_STREAM))
        self.assertEqual(peer.connect.call_args_list, [mock.call(('127.0.0.1', 18080))] * 2)
        self.assertEqual(watchdog.call_count, 2)
        self.assertEqual(watchdog.return_value.cancel.call_count, 2)
        self.assertEqual(peer.sendall.call_args_list[0].args[0].split(b'\r\n')[0], b'GET /ready HTTP/1.1')

    def test_in_memory_tls_configuration_and_pin_before_get(self):
        certificate = b'fixture DER bytes, not a real TLS handshake'
        profile = deepcopy(self.profile)
        profile.update(scheme='https', tlsHostname='localhost',
                       serverCertificateSha256=hashlib.sha256(certificate).hexdigest())
        peer, wrapped, context = mock.Mock(), mock.Mock(), mock.Mock()
        context.wrap_socket.return_value = wrapped
        wrapped.getpeercert.return_value = certificate
        wrapped.makefile.side_effect = lambda *args: BytesIO(
            b'HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{"ok":true}')
        with mock.patch.object(verify.ssl, 'SSLContext', return_value=context), \
                mock.patch.object(verify.socket, 'socket', return_value=peer), \
                mock.patch.object(runtime, 'deadline_watchdog'):
            verifier = verify.TrustedProbeVerifier(probe_policy(self.runtime, [profile]), self.runtime,
                                                  ca_file=Path('/trusted/explicit-ca.pem'))
            context.load_verify_locations.assert_called_once_with(cafile=str(Path('/trusted/explicit-ca.pem')))
            context.load_verify_locations.reset_mock()
            self.assertTrue(self.run_check(verifier)['passed'])
            context.load_verify_locations.assert_not_called()
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertIs(context.check_hostname, True)
            self.assertIsNone(context.keylog_filename)
            context.wrap_socket.assert_called_with(peer, server_hostname='localhost', do_handshake_on_connect=False)
            wrapped.sendall.reset_mock()
            wrapped.getpeercert.return_value = b'wrong certificate'
            result = self.run_check(verifier)
            self.assertEqual(result['checks'][0]['errorCode'], 'probe-peer-pin-rejected')
            wrapped.sendall.assert_not_called()

    def test_malformed_container_shapes_are_sanitized(self):
        for field, value in (('State', []), ('NetworkSettings', []), ('NetworkSettings', {'Ports': []})):
            container = deepcopy(self.container)
            container[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(
                    verify.VerificationError, '^probe-container-rejected$'):
                self.run_check(container=container)
        self.assertEqual(self.calls, [])

    def test_no_subclass_or_candidate_configuration_transport(self):
        class Untrusted(verify.TrustedProbeVerifier):
            pass
        with self.assertRaises(verify.VerificationError):
            Untrusted(probe_policy(self.runtime, [self.profile]), self.runtime, transport=self.transport)
        with self.assertRaises(verify.VerificationError):
            verify.TrustedProbeVerifier(probe_policy(self.runtime, [self.profile]), self.runtime, transport='candidate')


class LocalServerMixin:
    def start_server(self, context=None):
        test = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                test.requests.append((self.path, self.headers.get('Host')))
                if self.path == '/slow':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                    for _ in range(25):
                        try:
                            self.connection.sendall(b'x')
                        except OSError:
                            return
                        time.sleep(.02)
                    return
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass
            def log_message(self, *_):
                pass
        self.requests = []
        try:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        except PermissionError:
            self.skipTest('Sandbox blocks loopback bind; this is not live HTTP/TLS proof')
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        if context is not None:
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        thread.start()
        return server.server_address[1]

    def exercise(self, port, *, ca_file=None, pin=None, hostname=None, path=None):
        spec, runtime_policy, profile, container = fixture(port, scheme='https' if ca_file else 'http',
                                                        pin=pin, hostname=hostname)
        if path:
            profile['health'][0].update(path=path, timeout=.12)
        verifier = verify.TrustedProbeVerifier(probe_policy(runtime_policy, [profile]), runtime_policy, ca_file=ca_file)
        return verifier.check(verifier.bind('web', spec), container=container, guard=lambda: None,
                              deadline=time.monotonic() + 3)

class LocalHTTPTests(LocalServerMixin, unittest.TestCase):
    def test_real_http_ignores_proxy_environment_and_uses_fixed_port(self):
        port = self.start_server()
        with mock.patch.dict(os.environ, {'HTTP_PROXY': 'http://192.0.2.1:1', 'ALL_PROXY': 'http://192.0.2.1:1'}):
            result = self.exercise(port)
        self.assertTrue(result['passed'])
        self.assertEqual(self.requests, [('/ready', '127.0.0.1:' + str(port)),
                                         ('/business', '127.0.0.1:' + str(port))])

    def test_real_slow_headers_bounded_by_shared_watchdog(self):
        port = self.start_server()
        started = time.monotonic()
        with mock.patch.object(runtime, 'deadline_watchdog', wraps=runtime.deadline_watchdog) as watchdog:
            result = self.exercise(port, path='/slow')
        self.assertFalse(result['passed'])
        self.assertLess(time.monotonic() - started, .8)
        self.assertEqual(watchdog.call_count, 1)
        self.assertEqual(result['smoke'], 'not-run')


@unittest.skipUnless(shutil.which('openssl'), 'openssl is required for synthetic TLS certificate generation')
class LocalTLSTests(LocalServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.ca = cls.directory / 'cert.pem'
        key = cls.directory / 'key.pem'
        completed = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(cls.ca), '-days', '1', '-subj', '/CN=localhost',
            '-addext', 'subjectAltName=DNS:localhost'], capture_output=True, timeout=20)
        if completed.returncode:
            cls.temp.cleanup()
            raise RuntimeError('Synthetic certificate generation failed')
        cls.pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cls.ca.read_text())).hexdigest()
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(cls.ca, key)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_tls_trust_hostname_pin_and_no_ambient_keylog(self):
        port = self.start_server(self.context)
        keylog = self.directory / 'ambient-keylog'
        with mock.patch.dict(os.environ, {'SSLKEYLOGFILE': str(keylog), 'HTTPS_PROXY': 'http://192.0.2.1:1'}):
            result = self.exercise(port, ca_file=self.ca, pin=self.pin, hostname='localhost')
        self.assertTrue(result['passed'])
        self.assertFalse(keylog.exists())
        self.assertEqual(len(self.requests), 2)

    def test_real_tls_pin_and_hostname_rejected_before_get(self):
        port = self.start_server(self.context)
        result = self.exercise(port, ca_file=self.ca, pin='0' * 64, hostname='localhost')
        self.assertEqual(result['checks'][0]['errorCode'], 'probe-peer-pin-rejected')
        self.assertEqual(self.requests, [])
        result = self.exercise(port, ca_file=self.ca, pin=self.pin, hostname='wrong.invalid')
        self.assertFalse(result['passed'])
        self.assertEqual(self.requests, [])

    def test_real_tls_slow_headers_watchdog(self):
        port = self.start_server(self.context)
        started = time.monotonic()
        result = self.exercise(port, ca_file=self.ca, pin=self.pin, hostname='localhost', path='/slow')
        self.assertFalse(result['passed'])
        self.assertLess(time.monotonic() - started, .8)

    def test_https_requires_explicit_ca_even_with_transport(self):
        spec, runtime_policy, profile, _ = fixture(scheme='https', pin=self.pin, hostname='localhost')
        with self.assertRaisesRegex(verify.VerificationError, 'probe-tls-rejected'):
            verify.TrustedProbeVerifier(probe_policy(runtime_policy, [profile]), runtime_policy,
                                       transport=lambda *_: (200, [], b'{}'))


if __name__ == '__main__':
    unittest.main()
