"""Controller and host boundaries for the read-only release probes."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / directory) for directory in ('scripts', 'packs/deployment/scripts', 'packs/release/scripts')]

from tests import test_deployment_compose_production_scope_v1_host as scope_fixture
import deployment_compose_retained_release_preflight_v1_host as probe


class ReleaseHostProbeTests(unittest.TestCase):
    def record(self):
        manifest = {'scope': {'hostId': 'xterminal-server'}}
        policy_hash = hashlib.sha256(probe._POLICY_DOMAIN + probe.canonical(manifest)).hexdigest()
        return dict(manifest=manifest, frontendPins={'containerId': 'a' * 64}, endpointDigest='c' * 64,
                    journalDigest='d' * 64, journalTail=dict(state='verified', generation=1),
                    caddyProbeReady=True, hostProjectionUnchanged=True, productionDockerWrites=0,
                    policyHash=policy_hash)

    def test_host_reply_checks_read_only_health_and_policy_binding(self):
        record = self.record()
        with patch.object(probe, '_probe', return_value=record) as inspect:
            self.assertEqual(probe.inspect_release_host(b'archive'), record)
            inspect.assert_called_once_with(b'archive', 'baseline', {})
        for change in (dict(caddyProbeReady=False), dict(productionDockerWrites=False),
                       dict(policyHash='e' * 64), dict(hostProjectionUnchanged=False)):
            with (self.subTest(change=change), patch.object(probe, '_probe', return_value=dict(record, **change)),
                  self.assertRaises(ValueError)):
                probe.inspect_release_host(b'archive')

    def test_active_probe_passes_only_pins_and_rejects_a_different_reply(self):
        record = self.record()
        request = 'a' * 64
        pending = dict(generation=2, requestHash=request, journalDigest='e' * 64)
        with patch.object(probe, '_probe', return_value=pending) as inspect:
            self.assertEqual(probe.inspect_active_release(b'archive', record, request_hash=request, generation=2),
                             pending)
            inspect.assert_called_once_with(b'archive', 'active', dict(
                policyHash=record['policyHash'], journalDigest=record['journalDigest'], requestHash=request,
                generation=2,
            ))
        with (patch.object(probe, '_probe', return_value=dict(pending, generation=3)),
              self.assertRaises(ValueError)):
            probe.inspect_active_release(b'archive', record, request_hash=request, generation=2)

    def test_transport_pins_ssh_host_and_limits_output(self):
        original = subprocess.Popen

        def local_shell(argv, **kwargs):
            self.assertEqual(argv[-2], 'xterminal-server')
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertIn('ForwardAgent=no', argv)
            self.assertIn('PermitLocalCommand=no', argv)
            self.assertTrue(argv[-1].startswith('exec /usr/bin/python3 -I -S -B -c '))
            script = ('import sys\nassert sys.stdin.buffer.read() == b"archive"\n'
                      f'sys.stdout.buffer.write({probe.canonical({"ok": True})!r})\n')
            return original([sys.executable, '-B', '-c', script], **kwargs)

        with (patch.object(probe, 'archive_files', return_value={probe._MEMBER: b''}),
              patch.object(probe.subprocess, 'Popen', side_effect=local_shell)):
            self.assertEqual(probe._probe(b'archive', 'baseline', {}), {'ok': True})

        def oversized(_, **kwargs):
            return original([sys.executable, '-B', '-c', f'print("a"*{probe._RESPONSE_LIMIT + 1})'], **kwargs)

        with (patch.object(probe, 'archive_files', return_value={probe._MEMBER: b''}),
              patch.object(probe.subprocess, 'Popen', side_effect=oversized), self.assertRaises(ValueError)):
            probe._probe(b'archive', 'baseline', {})

    def test_host_observation_pins_caddy_frontend_and_closed_tail(self):
        original, caddy, network = 'a' * 64, 'b' * 64, 'c' * 64
        registration = SimpleNamespace(host_id='xterminal-server', daemon_id='production-one', project='luohao-blog-prod')
        closed = dict(state='verified', generation=1, request='1' * 64, proof='2' * 64)
        journal = probe.canonical(closed) + b'\n'
        image_id = 'sha256:' + 'e' * 64
        frontend = dict(Name='/blog-frontend', Id=original, Image=image_id,
                        Config={'Labels': {'com.docker.compose.project': registration.project,
                                           'com.docker.compose.service': 'frontend'}},
                        State={'Running': True, 'Health': {'Status': 'healthy'}},
                        NetworkSettings={'Networks': {'luohao-blog-prod_default': {'NetworkID': network}}})
        responses = {
            '/v1.45/version': {'Version': '29.8.2', 'GitCommit': '8af9fe3'},
            '/v1.45/containers/' + original + '/json': frontend,
            '/v1.45/images/' + image_id + '/json': dict(Id=image_id, Config={
                'Labels': {'org.opencontainers.image.revision': 'f' * 40},
            }),
        }
        observer = Mock(_info_id=registration.daemon_id)
        observer._get.side_effect = lambda path, *_: responses[path]
        observer.descriptor.return_value = {'endpointDigest': 'd' * 64}
        manifest = dict(caddyId=caddy, networkId=network)
        with (patch.object(probe, 'HostSnapshotV3', return_value=observer),
              patch.object(probe, '_container_id', side_effect=[original, caddy]),
              patch.object(probe, '_inspect_registration', return_value=journal),
              patch.object(probe, 'ProductionCaddyProbeV1', return_value=Mock(return_value=True)) as readiness):
            result = probe._baseline(manifest, registration, '3' * 64)
        self.assertEqual(result['journalTail'], closed)
        self.assertEqual(result['journalDigest'], hashlib.sha256(journal).hexdigest())
        self.assertEqual(result['frontendPins']['containerId'], original)
        self.assertEqual(result['frontendPins']['imageId'], image_id)
        self.assertEqual(result['productionDockerWrites'], 0)
        readiness.assert_called_once_with(observer, caddy_id=caddy, network_id=network)
        readiness.return_value.assert_called_once_with(original)
        observer.verify_unchanged.assert_called_once_with()
        observer.close.assert_called_once_with()


@unittest.skipUnless(os.name == 'posix', 'POSIX production journal')
class ActiveScopeProbeTests(unittest.TestCase):
    def test_live_owner_keeps_its_lock_and_exact_started_generation(self):
        scope = scope_fixture.scope
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            registration = scope.provision_scope(root, host_id='host', project='blog-prod', daemon_id='docker-1')
            journal = root / scope._name(registration.project)
            base_digest = hashlib.sha256(journal.read_bytes()).hexdigest()
            request = 'a' * 64
            with scope.acquire_scope(registration, request) as lease:
                pending = probe._active(registration, base_digest, request, 1)
                self.assertEqual(pending, dict(generation=1, requestHash=request,
                                               journalDigest=hashlib.sha256(journal.read_bytes()).hexdigest()))
                for expected in ((base_digest, 'b'*64, 1), (base_digest, request, 2), ('c'*64, request, 1)):
                    with self.subTest(expected=expected), self.assertRaises(ValueError):
                        probe._active(registration, *expected)
                with self.assertRaisesRegex(scope.ScopeBlocked, 'live writer'):
                    scope.acquire_scope(registration, 'd' * 64)
                lease.check()
                lease.complete('e' * 64)
            with self.assertRaises(ValueError):
                probe._active(registration, base_digest, request, 1)
