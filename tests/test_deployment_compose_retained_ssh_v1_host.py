"""Retained SSH framing and original-unit lifecycle with explicit fixtures."""

from collections import deque
import hashlib
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / path) for path in ('scripts', 'packs/deployment/scripts', 'packs/release/scripts')]

import deployment_compose_retained_ssh_v1_host as ssh
from deployment_compose_production_scope_v1_host import ScopeRegistrationV1
from deployment_compose_retained_source_v1_host import CHANNEL_MEMBER
from tests.test_deployment_compose_retained_source_v1_host import fixture, zip_bytes

NONCE = 'a' * 64
ENDPOINT = 'b' * 64
SOURCE = 'c' * 40
ARCHIVE = zip_bytes(fixture() + [
    (CHANNEL_MEMBER, b'# fixture'),
    ('scripts/deployment_compose_retained_ssh_v1_host.py', b'# fixture'),
])
ARCHIVE_DIGEST = hashlib.sha256(ARCHIVE).hexdigest()
REG = ScopeRegistrationV1(Path('/var/lib/fixture'), (1, 2), (1, 3), 'fixture', 'luohao-blog-prod', 'docker-fixture')
SCOPE = ssh._scope(REG)


def frame(kind, **fields):
    return dict(kind=kind, channelNonce=NONCE, **fields)


def startup():
    return frame('production-startup', scope=SCOPE, endpointDigest=ENDPOINT,
                 source=dict(profile=ssh.PROFILE, sourceSha=SOURCE, archiveDigest=ARCHIVE_DIGEST,
                             originDigest='d'*64, channelNonce=NONCE))


class SSHTests(unittest.TestCase):
    def test_argv_is_fixed_and_strict(self):
        argv = ssh.ssh_argv('fixture', SOURCE, ARCHIVE_DIGEST)
        self.assertIn('ClearAllForwardings=yes', argv)
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('ForwardAgent=no', argv)
        self.assertEqual(argv[-2], 'fixture')
        code = ssh.manager_bootstrap(SOURCE, ARCHIVE_DIGEST)
        self.assertIn("ENTRYPOINT=" + repr(ssh.MANAGER), code)
        self.assertIn('run_manager(config,archive,r)', code)
        self.assertNotIn('run_production(config,archive,r)', code)
        compile(code, '<manager>', 'exec')
        for bad in ('-oProxyCommand=anything', 'root@fixture', 'fixture; sh', ''):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ssh.ssh_argv(bad, SOURCE, ARCHIVE_DIGEST)

    def test_ssh_startup_is_checked_against_independent_pins(self):
        for output in (startup(), dict(startup(), endpointDigest='0'*64)):
            process = Mock()
            process.poll.return_value = None
            with patch.object(ssh.subprocess, 'Popen', return_value=process) as spawn, \
                    patch.object(ssh, 'write_frame') as write, patch.object(ssh, 'read_frame', return_value=output):
                params = dict(source_sha=SOURCE, expected_archive_digest=ARCHIVE_DIGEST, registration=REG,
                              work_directory=Path('/var/lib/fixture-work'), expected_endpoint_digest=ENDPOINT)
                if output['endpointDigest'] != ENDPOINT:
                    with self.assertRaises(ValueError):
                        ssh.start_retained_ssh('fixture', ARCHIVE, **params)
                    process.stdin.close.assert_called_once()
                    process.wait.assert_called_once()
                    process.stdout.close.assert_called_once()
                else:
                    self.assertEqual(ssh.start_retained_ssh('fixture', ARCHIVE, **params), (process, output))
                    self.assertEqual(write.call_args.args[1]['scope'], SCOPE)
                    self.assertEqual(spawn.call_args.kwargs['stderr'], subprocess.DEVNULL)

    def test_owned_manager_stops_original_unit_after_clean_finish_or_failure(self):
        config = dict(entrypoint=ssh.MANAGER, sourceSha=SOURCE, archiveDigest=ARCHIVE_DIGEST,
                      channelNonce='e'*64, scope=SCOPE, mode='channel',
                      workDirectory='/var/lib/fixture-work', expectedEndpointDigest=ENDPOINT)
        for failure in (None, ValueError('fixture disconnected')):
            with patch.object(ssh, 'RetainedProductionUnitV1') as owner, \
                    patch.object(ssh, '_Relay') as relay, patch.object(ssh, 'write_frame'):
                unit = owner.return_value
                process = Mock()
                process.wait.return_value = 0
                unit.start_registered.return_value = (process, startup())
                relay.return_value.run.side_effect = failure
                root = Path('/var/lib/fixture-work/archive')
                if failure is None:
                    ssh.run_manager(config, ARCHIVE, root)
                    process.wait.assert_called_once()
                else:
                    with self.assertRaises(ValueError) as caught:
                        ssh.run_manager(config, ARCHIVE, root)
                    self.assertIs(caught.exception, failure)
                unit.stop.assert_called_once_with(timeout=30)
                unit.close.assert_called_once()


class RelayTests(unittest.TestCase):
    def exercise(self, controller, worker, *, error=False, deadline=None):
        controller_in, worker_out = deque(controller), deque(worker)
        controller_out, worker_in = [], []
        process = SimpleNamespace(stdout=worker_out, stdin=worker_in)

        def read(stream, *, timeout):
            self.assertGreater(timeout, 0)
            return stream.popleft()

        def write(stream, value, *, timeout):
            self.assertGreater(timeout, 0)
            stream.append(value)

        with patch.object(ssh, 'read_frame', side_effect=read), patch.object(ssh, 'write_frame', side_effect=write):
            relay = ssh._Relay(controller_in, controller_out, process, NONCE,
                               time.monotonic() + 30 if deadline is None else deadline)
            if error:
                with self.assertRaises((ValueError, TimeoutError)):
                    relay.run()
            else:
                relay.run()
                self.assertFalse(controller_in)
                self.assertFalse(worker_out)
        return controller_out, worker_in

    def test_deploy_and_restore_with_exact_consumption_challenge(self):
        configure = frame('configure', **{field: None for field in ssh.CONFIGURE})
        prepared = frame('prepared', review={}, writerCertificateSha256='d'*64)
        execute = frame('execute', request={})
        reply = frame('reply', response={})
        rpc = frame('rpc', service='intent', method='authorize',
                    request={'method': 'consume', 'requestHash': 'c'*64, 'generation': 1})
        challenge = frame('consume-check', nonce='f'*64, requestHash='c'*64, scopeGeneration=1)
        confirmed = dict(challenge, kind='consume-confirmed')
        executed = frame('executed', result={})
        restore = frame('restore-prepared', review={})
        write = frame('rpc', service='witness', method='append_event', request={})
        controller = [configure, execute, challenge, reply, execute, reply]
        worker = [prepared, rpc, confirmed, executed, restore, write, executed]
        controller_out, worker_in = self.exercise(controller, worker)
        self.assertEqual(controller_out, worker)
        self.assertEqual(worker_in, controller)

    def test_finish_after_prepared_without_execute(self):
        configure = frame('configure', **{field: None for field in ssh.CONFIGURE})
        prepared = frame('prepared', review={}, writerCertificateSha256='d'*64)
        finish = frame('finish')
        self.assertEqual(self.exercise([configure, finish], [prepared]), ([prepared], [configure, finish]))

    def test_blocked_stage_is_forwarded_only_for_known_values(self):
        configure = frame('configure', **{field: None for field in ssh.CONFIGURE})
        prepared = frame('prepared', review={}, writerCertificateSha256='d'*64)
        execute = frame('execute', request={})
        blocked = frame('blocked', knownPrefix=False, failureStage='validate-intent')
        controller = [configure, execute]
        self.assertEqual(self.exercise(controller, [prepared, blocked]), ([prepared, blocked], controller))
        for invalid in ('private failure detail', []):
            worker = [prepared, dict(blocked, failureStage=invalid)]
            self.assertEqual(self.exercise(controller, worker, error=True), ([prepared], controller))
        executed = frame('executed', result={})
        restore_blocked = dict(blocked, failureStage='prepare-restore')
        worker = [prepared, executed, restore_blocked]
        self.assertEqual(self.exercise(controller, worker), (worker, controller))
        self.assertEqual(self.exercise(controller, [prepared, restore_blocked], error=True), ([prepared], controller))

    def test_wrong_direction_and_nonce_do_not_forward(self):
        configure = frame('configure', **{field: None for field in ssh.CONFIGURE})
        prepared = frame('prepared', review={}, writerCertificateSha256='d'*64)
        for invalid in (frame('reply', response={}), dict(frame('finish'), channelNonce='0'*64)):
            controller_out, worker_in = self.exercise([configure, invalid], [prepared], error=True)
            self.assertEqual(controller_out, [prepared])
            self.assertEqual(worker_in, [configure])
        self.assertEqual(self.exercise([], [], error=True, deadline=time.monotonic()), ([], []))
