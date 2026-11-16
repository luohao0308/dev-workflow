"""Framed controller/native integration with real cryptography and a Unix Engine double."""
from contextlib import ExitStack
import hashlib
import json
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
from tests import test_deployment_compose_retained_release_review_v1_host as release_fixture
from deployment_compose_retained_controller_v1_host import RetainedControllerV1
from deployment_compose_retained_intent_relay_v1_host import IntentRelayRejected, RetainedIntentIssuerV1
from release_execute import AuthorizationUnavailable
import deployment_compose_retained_native_channel_v1_host as native
import deployment_compose_retained_source_v1_host as loader
from deployment_compose_production_scope_v1_host import _name
from deployment_gate_witness import key_material


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

    def test_staged_channel_creates_switches_and_rolls_back_with_separate_approvals(self):
        self._round_trip(deny_before_start=False, staged=True, short_switch=True)

    def test_staged_channel_relays_partial_switch_for_separately_approved_rollback(self):
        self._round_trip(deny_before_start=True, staged=True)

    def test_staged_channel_allows_only_projected_transient_firewall_changes(self):
        self._round_trip(deny_before_start=False, staged=True, transient_firewall_drift=True)

    def test_staged_channel_rejects_non_transient_firewall_change_before_consumption(self):
        self._round_trip(deny_before_start=False, staged=True, persistent_firewall_drift=True)

    def test_healthy_staged_deployment_closes_without_rollback_or_extra_docker_write(self):
        self._round_trip(deny_before_start=False, staged=True, keep_candidate=True)

    def test_one_review_keeps_healthy_candidate(self):
        self._round_trip(deny_before_start=False, staged=True, keep_candidate=True, single_review=True)

    def test_one_review_rolls_back_only_a_verified_readiness_failure(self):
        self._round_trip(deny_before_start=False, staged=True, single_review=True, readiness_failed=True)

    def test_acceptance_drift_leaves_independently_approved_rollback_available(self):
        self._round_trip(deny_before_start=False, staged=True, acceptance_drift=True)

    def test_initial_intent_failure_reports_stage_without_consumption_or_error_text(self):
        self._round_trip(deny_before_start=False, fail_validation=True)

    def test_restore_preparation_failure_keeps_verified_deploy_result(self):
        self._round_trip(deny_before_start=False, fail_restore_preparation=True)

    def test_ipv4_drift_after_stop_allows_only_a_fresh_approved_original_restart(self):
        self._round_trip(deny_before_start=False, ipv4_drift_after_stop=True)

    def test_ipv4_drift_after_restart_review_cannot_consume_recovery_approval(self):
        self._round_trip(deny_before_start=False, ipv4_drift_after_stop=True, late_ipv4_drift=True)

    def _round_trip(self, *, deny_before_start, fail_validation=False, fail_restore_preparation=False,
                    ipv4_drift_after_stop=False, late_ipv4_drift=False, staged=False, short_switch=False,
                    transient_firewall_drift=False, persistent_firewall_drift=False, keep_candidate=False,
                    acceptance_drift=False, single_review=False, readiness_failed=False):
        self.write_patch.stop()
        if ipv4_drift_after_stop or staged:
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
            if transient_firewall_drift and operation.phase in ('create', 'stop-original'):
                self.network['firewall4'] = 'b' * 64 if operation.phase == 'create' else 'c' * 64
            if ipv4_drift_after_stop and operation.phase == 'stop-original':
                self.network['firewall4'] = '9' * 64
            return status, body

        self.engine_post = engine_post
        with ExitStack() as stack:
            if readiness_failed:
                ready = native.RetainedFrontendWorkerV1._verify_readiness

                def check_readiness(worker, active_id):
                    if active_id == self.candidate:
                        raise native.RetainedReadinessFailed('fixture readiness check timed out')
                    return ready(worker, active_id)

                stack.enter_context(patch.object(native.RetainedFrontendWorkerV1, '_verify_readiness',
                                                 check_readiness))
            if transient_firewall_drift:
                capture = fixture.host_fixture.host.capture_network
                scans = 0

                def changing_bans(deadline, **kwargs):
                    nonlocal scans
                    network = capture(deadline, **kwargs)
                    if 'expected_endpoint_rules' in kwargs:
                        scans += 1
                        network['firewall4'] = ('e' if scans % 2 else 'f') * 64
                    return network

                stack.enter_context(patch.object(fixture.host_fixture.host, 'capture_network',
                                                 side_effect=changing_bans))
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
                    caddy_id=self.row['Id'], network_id=network['NetworkID'], timeout=120, staged=staged)
                stack.callback(controller.close)
                deploy_review = controller.review
                release = None
                if single_review:
                    release = release_fixture.ReleaseReviewTests()
                    release.configure(deploy_review)
                    approval = release.authority(1)
                    request = approval.request
                    grant = approval.validate(request)
                else:
                    approval, grant, request, first_ledger = self._approval(deploy_review, 'deploy')
                result = controller.execute(approval, grant, request)
                expected_deploy_witnesses = 4 if staged else 5
                if staged:
                    self.assertEqual(len(result['result']['witnessDigests']), 1)
                    self.assertEqual(self.writes, ['create'])
                    self.assertTrue(self.other_rows[self.original]['State']['Running'])
                    self.assertEqual(len(release.claims if release else first_ledger.markers), 1)
                    creation_hash = request.digest()
                    with self.assertRaises(ValueError):
                        controller.execute(approval, grant, request)
                    with self.assertRaises(ValueError):
                        controller.accept_deployment()
                    if short_switch:
                        approval, _, request, short_ledger = self._approval(result['switchReview'], 'deploy')
                        claims = approval.verifier('signed')
                        claims['exp'] = int(fixture.worker_module.time.time()) + 239
                        approval.verifier = lambda _: claims
                        result = controller.execute(approval, approval.validate(request), request)
                        self.assertEqual(result['failureStage'], 'cutover-window-too-short')
                        self.assertFalse(short_ledger.markers)
                        self.assertEqual(self.writes, ['create'])
                    if release:
                        ordinary, grant, request, _ = self._approval(result['switchReview'], 'deploy')
                        with self.assertRaises(ValueError):
                            controller.execute(ordinary, grant, request)
                        journal = (registration.root / _name(registration.project)).read_bytes()
                        started = json.loads(journal.splitlines()[-1])
                        self.assertEqual(started['request'], creation_hash)
                        public = signers[1].with_suffix('.pub').read_bytes()
                        evidence = dict(root=directory, public_key=public,
                                        expected_key_hash=hashlib.sha256(key_material(public)).hexdigest(),
                                        pending=dict(requestHash=creation_hash, generation=started['generation'],
                                                     journalDigest=hashlib.sha256(journal).hexdigest()))
                        approval = release.authority(2, stage='switch', review=result['switchReview'],
                                                     witness_source=evidence)
                        request = approval.request
                        grant = approval.validate(request)
                    else:
                        approval, grant, request, first_ledger = self._approval(result['switchReview'], 'deploy')
                    if persistent_firewall_drift:
                        self.network['firewall4'] = self.network['firewall4WithoutTransientBans'] = 'd' * 64
                    result = controller.execute(approval, grant, request, accept_success=keep_candidate and not release)
                if fail_validation:
                    self.assertEqual(result, dict(result=None, restoreReview=None, blocked=True,
                                                  failureStage='validate-intent'))
                    self.assertEqual(self.writes, [])
                    self.assertEqual(len(first_ledger.markers), 0)
                elif persistent_firewall_drift:
                    self.assertEqual(result['failureStage'], 'pre-write-protection-network')
                    self.assertFalse(first_ledger.markers)
                    self.assertEqual(self.writes, ['create'])
                    self.assertTrue(self.other_rows[self.original]['State']['Running'])
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
                    self.assertNotIn('readinessFailure', result)
                elif readiness_failed:
                    self.assertIsNone(result['result'])
                    self.assertEqual(result['readinessFailure'].request_hash, request.digest())
                    self.assertEqual(result['restoreReview']['retainedCutover']['switchPrefix'], 4)
                else:
                    self.assertEqual(len(result['result']['witnessDigests']), expected_deploy_witnesses)
                if keep_candidate:
                    from deployment_compose_retained_native_entry_v1_host import _inspect_registration

                    proof = result['terminalProof']
                    self.assertRegex(proof, r'^[0-9a-f]{64}$')
                    self.assertIsNone(result['restoreReview'])
                    terminal = json.loads(_inspect_registration(registration).splitlines()[-1])
                    self.assertEqual(terminal, dict(state='verified', generation=1,
                                                    request=creation_hash, proof=proof))
                    self.assertEqual(self.writes, [operation.phase for operation in expected[:5]])
                    self.assertTrue(self.other_rows[self.candidate]['State']['Running'])
                    self.assertFalse(self.other_rows[self.original]['State']['Running'])
                    if release:
                        self.assertEqual(len(release.claims), 2)
                if acceptance_drift:
                    old_firewall = self.network['firewall6']
                    self.network['firewall6'] = '0'*64
                    self.assertIsNone(controller.accept_deployment())
                    self.assertEqual(self.writes, [operation.phase for operation in expected[:5]])
                    self.network['firewall6'] = old_firewall
                if not (fail_validation or fail_restore_preparation or persistent_firewall_drift or keep_candidate):
                    if release:
                        approval = release.authority(3, stage='rollback', review=result['restoreReview'],
                                                     witness_source=evidence,
                                                     readiness_failure=result['readinessFailure'])
                        request = approval.request
                        grant = approval.validate(request)
                    else:
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
                        if release:
                            self.assertEqual(len(release.claims), 3)
                        else:
                            self.assertEqual((len(first_ledger.markers), len(second_ledger.markers)), (1, 1))
            finally:
                parent_out.close()
                thread.join(8)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
