"""Framed controller/native integration with real cryptography and a Unix Engine double."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_retained_frontend_worker_v1_host as fixture
from deployment_compose_retained_controller_v1_host import RetainedControllerV1
from deployment_compose_retained_intent_relay_v1_host import IntentRelayRejected, RetainedIntentIssuerV1
from release_execute import AuthorizationUnavailable
import deployment_compose_retained_native_channel_v1_host as native
import deployment_compose_retained_source_v1_host as loader


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX, OpenSSL and OpenSSH required')
class NativeChannelTests(unittest.TestCase):
    fixed_production_network = True
    setUp = fixture.RetainedWorkerTests.setUp
    observe = fixture.RetainedWorkerTests.observe
    command = fixture.RetainedWorkerTests.command
    _transport = staticmethod(fixture.RetainedWorkerTests._transport)
    _write = fixture.RetainedWorkerTests._write
    _approval = fixture.RetainedWorkerTests._approval

    def test_framed_native_switch_and_restore_with_independent_witness_reconciliation(self):
        self._round_trip(deny_before_start=False)

    def test_relay_denial_at_closed_prefix_leaves_separately_approvable_restore(self):
        self._round_trip(deny_before_start=True)

    def test_initial_intent_failure_reports_stage_without_consumption_or_error_text(self):
        self._round_trip(deny_before_start=False, fail_validation=True)

    def test_restore_preparation_failure_keeps_verified_deploy_result(self):
        self._round_trip(deny_before_start=False, fail_restore_preparation=True)

    def test_ipv4_drift_after_stop_allows_only_a_fresh_approved_original_restart(self):
        self._round_trip(deny_before_start=False, ipv4_drift_after_stop=True)

    def test_ipv4_drift_after_restart_review_cannot_consume_recovery_approval(self):
        self._round_trip(deny_before_start=False, ipv4_drift_after_stop=True, late_ipv4_drift=True)

    def _round_trip(self, *, deny_before_start, fail_validation=False, fail_restore_preparation=False,
                    ipv4_drift_after_stop=False, late_ipv4_drift=False):
        self.write_patch.stop()
        if ipv4_drift_after_stop:
            self.network['firewall4WithoutTransientBans'] = 'a' * 64
        original = self.worker._plan
        prefix = 1 if ipv4_drift_after_stop else 3 if deny_before_start else 4
        expected = (original.create(), *original.switch(self.candidate)[:prefix],
                    *original.restore(self.candidate, switch_prefix=prefix, candidate_running=prefix == 4))
        by_path = {operation.path: operation for operation in expected}

        def engine_post(path, raw):
            operation = by_path[path]
            self.assertEqual(raw, operation.body)
            status, body, _ = self._write(operation, before_dispatch=lambda: None)
            if ipv4_drift_after_stop and operation.phase == 'stop-original':
                self.network['firewall4'] = '9' * 64
            return status, body

        self.engine_post = engine_post
        with ExitStack() as stack:
            if fail_validation:
                stack.enter_context(patch.object(native.RetainedIntentClientV1, 'validate',
                    side_effect=IntentRelayRejected('private failure detail')))
            if fail_restore_preparation:
                stack.enter_context(patch.object(native.RetainedFrontendWorkerV1, 'restore_review',
                    side_effect=ValueError('private restore preparation detail')))
            if deny_before_start:
                authorize = RetainedIntentIssuerV1.authorize_rpc

                def deny_at_closed_prefix(issuer, wire):
                    if (wire.get('method') == 'check' and issuer._request.operation == 'deploy'
                            and self.writes[-1:] == ['name-candidate']):
                        raise AuthorizationUnavailable('fixture revoked after closed write')
                    return authorize(issuer, wire)

                stack.enter_context(patch.object(RetainedIntentIssuerV1, 'authorize_rpc', deny_at_closed_prefix))
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory())).resolve()
            signers = [directory/'intent', directory/'witness']
            for signer in signers:
                subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(signer)],
                               capture_output=True, check=True, timeout=10)
            nonce = '9'*64
            source = dict(profile='production-retained-v2', channelNonce=nonce, sourceSha='b'*40,
                          archiveDigest='b'*64, originDigest=hashlib.sha256(b'native-origin').hexdigest())
            registration = self.registration
            scope = dict(root=str(registration.root), rootIdentity=list(registration.root_identity),
                         journalIdentity=list(registration.journal_identity), hostId=registration.host_id,
                         project=registration.project, daemonId=registration.daemon_id)
            observer = self.worker._observer
            startup = dict(kind='production-startup', channelNonce=nonce, source=source, scope=scope,
                           endpointDigest=observer.descriptor()['endpointDigest'])
            config = dict(channelNonce=nonce, workDirectory=str(directory))
            stack.enter_context(patch.object(native, 'check_loaded_source', return_value=source))
            stack.enter_context(patch.object(loader, 'check_loaded_source', return_value=source))
            stack.enter_context(patch('deployment_compose_host_snapshot_v3_host._frontend_endpoint_rules',
                                      return_value=()))
            stack.enter_context(patch('deployment_compose_host_snapshot_v3_host._frontend_host_veths',
                                      return_value=frozenset()))
            network_id = next(iter(self.private['privateBody']['NetworkingConfig']['EndpointsConfig'].values()))['NetworkID']
            self.values['/v1.45/networks/' + network_id] = {'Id': network_id}
            stack.enter_context(patch.object(native, 'ProductionCaddyProbeV1', return_value=lambda _: True))
            stack.enter_context(patch.object(sys, 'platform', 'linux'))
            native_read, controller_write = os.pipe()
            controller_read, native_write = os.pipe()
            worker_in = stack.enter_context(os.fdopen(native_read, 'rb', buffering=0))
            worker_out = stack.enter_context(os.fdopen(native_write, 'wb', buffering=0))
            parent_in = stack.enter_context(os.fdopen(controller_read, 'rb', buffering=0))
            parent_out = stack.enter_context(os.fdopen(controller_write, 'wb', buffering=0))
            errors = []

            def native_session():
                try:
                    native.run_channel(config, object(), observer, registration, stdin=worker_in, stdout=worker_out)
                except BaseException as error:
                    errors.append(error)
                finally:
                    worker_out.close()

            thread = threading.Thread(target=native_session, daemon=True)
            thread.start()
            try:
                network = self.private['privateBody']['NetworkingConfig']['EndpointsConfig']['luohao-blog-prod_default']
                controller = RetainedControllerV1(parent_out, parent_in, startup=startup, expected_startup=startup,
                    private_plan=self.private, operation_nonce='1'*64, policy_hash='f'*64,
                    intent_signer=signers[0], intent_public_key=signers[0].with_suffix('.pub').read_bytes(),
                    witness_signer=signers[1], witness_public_key=signers[1].with_suffix('.pub').read_bytes(),
                    witness_root=directory, witness_key=b'w'*32, gate_key=b'g'*32,
                    caddy_id=self.row['Id'], network_id=network['NetworkID'], timeout=120)
                stack.callback(controller.close)
                deploy_review = controller.review
                approval, grant, request, first_ledger = self._approval(deploy_review, 'deploy')
                result = controller.execute(approval, grant, request)
                if fail_validation:
                    self.assertEqual(result, dict(result=None, restoreReview=None, blocked=True,
                                                  failureStage='validate-intent'))
                    self.assertEqual(self.writes, [])
                    self.assertEqual(len(first_ledger.markers), 0)
                elif fail_restore_preparation:
                    self.assertEqual(result['failureStage'], 'prepare-restore')
                    self.assertTrue(result['blocked'])
                    self.assertIsNone(result['restoreReview'])
                    self.assertEqual(len(result['result']['witnessDigests']), 5)
                    self.assertEqual(self.writes, [operation.phase for operation in expected[:5]])
                    self.assertEqual(len(first_ledger.markers), 1)
                elif ipv4_drift_after_stop:
                    self.assertIsNone(result['result'])
                    restored = result['restoreReview']['retainedCutover']
                    self.assertEqual(restored['switchPrefix'], 1)
                    self.assertNotEqual(restored['protectionDigest'], deploy_review['retainedCutover']['protectionDigest'])
                    self.assertEqual(self.writes, ['create', 'stop-original'])
                elif deny_before_start:
                    self.assertIsNone(result['result'])
                    self.assertEqual(result['restoreReview']['retainedCutover']['switchPrefix'], 3)
                else:
                    self.assertEqual(len(result['result']['witnessDigests']), 5)
                if not (fail_validation or fail_restore_preparation):
                    approval, grant, request, second_ledger = self._approval(result['restoreReview'], 'rollback')
                    if late_ipv4_drift:
                        self.network['firewall4'] = '8' * 64
                    result = controller.execute(approval, grant, request)
                    if late_ipv4_drift:
                        self.assertTrue(result['blocked'])
                        self.assertEqual(self.writes, ['create', 'stop-original'])
                        self.assertFalse(second_ledger.markers)
                    else:
                        self.assertEqual(len(result['result']['witnessDigests']), prefix)
                        self.assertEqual(self.writes, [operation.phase for operation in expected])
                        self.assertEqual((len(first_ledger.markers), len(second_ledger.markers)), (1, 1))
            finally:
                parent_out.close()
                thread.join(8)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
