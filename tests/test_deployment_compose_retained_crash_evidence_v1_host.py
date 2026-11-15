"""Process loss with real OpenSSH signatures and production-scope flock."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_retained_witness_admission_v1_host as witness_fixture
from tests import test_deployment_compose_host_snapshot_v3_host as host_fixture
from tests import test_deployment_compose_retained_frontend_worker_v1_host as worker_fixture
from tests.test_deployment_compose_production_frontend_approval_v1_host import approved, fixture, host
from deployment_compose_production_scope_v1_host import (
    ScopeBlocked, ScopeRegistrationV1, acquire_scope, inspect_pending_scope, provision_scope,
)
from deployment_compose_retained_crash_evidence_v1_host import inspect_retained_crash_evidence
from deployment_compose_retained_recovery_handoff_v1_host import (
    claim_crash_rollback, execute_crash_rollback, observe_confirmed_stop, prepare_crash_rollback_review,
)
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_compose_witness_store import canonical
from deployment_gate_witness import key_material


def _crash_fixture(parent, admit_only):
    tempfile.tempdir = str(parent)
    fixture = witness_fixture.RetainedWitnessAdmissionTests()
    fixture.staged_only = True
    fixture.setUp()
    override = parent/'fixture-plan.json'
    if override.exists():
        value = json.loads(override.read_bytes())
        fixture.private = value['plan']
        fixture.plan = prepare_retained_frontend_cutover(fixture.private, operation_nonce='1'*64)
        fixture.protection = value['protection']
        fixture.candidate = value['candidate']
    identity = fixture.private['publicReview']['identity']
    scope = parent/'scope'
    scope.mkdir(mode=0o700)
    registration = provision_scope(scope, host_id=identity['hostId'], project=identity['project'],
                                   daemon_id=identity['daemonId'])
    create = fixture._registration(stage='create')
    request = create['request'].digest()
    with acquire_scope(registration, request):
        creator = witness_fixture.RetainedWitnessAdmissionV1(**create)
        fixture._create(creator)
        _, witnesses = creator.closed_chain()
        switch = fixture._registration(stage='switch', creation=create['request'], creation_witness=witnesses[0])
        broker = witness_fixture.RetainedWitnessAdmissionV1(**switch, parent=creator)
        stop, rename, *_ = fixture.plan.switch(fixture.candidate)
        writer = fixture._complete(broker, broker.first_binding, stop, 0)
        if admit_only:
            binding = fixture._advance(broker, writer, rename, 1)
            fixture._complete(broker, binding, rename, 1, admit_only=True)
        print(json.dumps(dict(scope=str(scope), root=str(fixture.root), request=request,
                              scopeIdentity=registration.root_identity, journalIdentity=registration.journal_identity,
                              plan=fixture.private,
                              keyHash=hashlib.sha256(key_material(fixture.public)).hexdigest())), flush=True)
        sys.stdin.buffer.read(1)


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class RetainedCrashEvidenceTests(unittest.TestCase):
    def _interrupt(self, *, admit_only, prepared=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        if prepared is not None:
            (Path(temporary.name)/'fixture-plan.json').write_bytes(canonical(prepared))
        command = [sys.executable, '-B', '-c',
                   'import sys; from pathlib import Path; '
                   'from tests.test_deployment_compose_retained_crash_evidence_v1_host import _crash_fixture; '
                   '_crash_fixture(Path(sys.argv[1]).resolve(), sys.argv[2]=="True")',
                   temporary.name, str(admit_only)]
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, cwd=Path(__file__).resolve().parents[1]) as child:
            try:
                with selectors.DefaultSelector() as select:
                    select.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(select.select(20), 'writer did not reach crash point')
                line = child.stdout.readline()
                if not line:
                    self.fail(child.stderr.read().decode())
                result = json.loads(line)
                identity = result['plan']['publicReview']['identity']
                scope = ScopeRegistrationV1(Path(result['scope']), tuple(result['scopeIdentity']),
                                            tuple(result['journalIdentity']), identity['hostId'],
                                            identity['project'], identity['daemonId'])
                with self.assertRaisesRegex(ScopeBlocked, 'live writer'):
                    inspect_pending_scope(scope, result['request'])
            finally:
                child.kill()
                child.wait(timeout=5)
        pending = inspect_pending_scope(scope, result['request'])
        with self.assertRaisesRegex(ScopeBlocked, 'Unresolved'):
            acquire_scope(scope, 'f'*64)
        root = Path(result['root'])
        public = (root/'witness-key.pub').read_bytes()
        (root/'witness-key').unlink()
        report = inspect_retained_crash_evidence(root, pending, public_key=public,
                                                expected_key_hash=result['keyHash'])
        self.assertEqual(inspect_pending_scope(scope, result['request']), pending)
        return scope, root, pending, public, result['keyHash'], report, result['plan']

    def test_killed_after_closed_stop_recovers_verified_prefix_without_private_keys(self):
        _, root, pending, public, key_hash, report, _ = self._interrupt(admit_only=False)
        self.assertEqual([item['stage'] for item in report['stages']], ['create', 'switch'])
        self.assertEqual([len(item['witnessDigests']) for item in report['stages']], [1, 1])
        self.assertFalse(report['uncertain'])
        self.assertFalse(report['authorityGranted'])
        self.assertFalse(report['productionReady'])
        checkpoint, = (name for name in root.glob('*.retained-checkpoint-1.json')
                       if not name.name.startswith(pending['requestHash']))
        value = json.loads(checkpoint.read_bytes())
        value['payload']['candidateId'] = 'd'*64
        checkpoint.write_bytes(canonical(value))
        with self.assertRaises(ValueError):
            inspect_retained_crash_evidence(root, pending, public_key=public, expected_key_hash=key_hash)

    def test_killed_after_next_admission_keeps_prior_prefix_but_marks_tail_uncertain(self):
        _, _, _, _, _, report, plan = self._interrupt(admit_only=True)
        self.assertTrue(report['uncertain'])
        _, switch = report['stages']
        self.assertEqual(len(switch['witnessDigests']), 1)
        self.assertFalse(switch['checkpointMatches'])
        self.assertFalse(report['authorityGranted'])
        with self.assertRaises(ValueError):
            prepare_crash_rollback_review(report, plan, observation_digest='8'*64)

    def _recovery(self):
        scope, root, pending, public, key_hash, report, plan = self._interrupt(admit_only=False)
        current = {'digest': '8'*64}
        review = prepare_crash_rollback_review(report, plan, observation_digest=current['digest'])
        old, base, _ = fixture()
        request = host.prepare_production_frontend_request(
            review, policy_hash=old.policy_hash, expires_at=old.expires_at, operation='rollback')
        policy = host.ProductionFrontendApprovalPolicyV3(**dict(
            vars(base), stage='rollback', operation='rollback', host_id=request.host_id, daemon_id=request.daemon_id,
            snapshot_hash=request.before_hash, body_hash=request.after_hash, plan_hash=request.plan_hash,
            protected_inventory_hash=host._digest(list(request.protected_components)), request_hash=request.digest(),
            observation_hash=request.observation_hash, history_hash=request.history_hash))
        approval, ledger, _ = approved(policy, request)
        socket = host_fixture.HostTests()
        self.addCleanup(socket.doCleanups)
        socket.setUp()
        observer = socket.observe()
        patcher = patch('deployment_compose_retained_recovery_handoff_v1_host.observe_confirmed_stop',
                        side_effect=lambda *args, **kwargs: current['digest'])
        patcher.start()
        self.addCleanup(patcher.stop)
        return scope, pending, current, ledger, dict(
            registration=scope, root=root, pending=pending, public_key=public, expected_key_hash=key_hash,
            private_plan=plan, original_baseline={}, observer=observer, endpoint_digest='a'*64,
            review=review, approval=approval, grant=approval.validate(request), request=request,
            runtime_sha=base.workflow_sha)

    def test_fresh_recovery_claim_rechecks_observation_and_holds_original_generation(self):
        scope, pending, current, ledger, options = self._recovery()
        altered = deepcopy(options['review'])
        altered['retainedCutover']['recoveryJournalDigest'] = '0'*64
        with self.assertRaises(ValueError):
            claim_crash_rollback(**dict(options, review=altered))
        current['digest'] = '9'*64
        with self.assertRaises(ValueError):
            claim_crash_rollback(**options)
        self.assertFalse(ledger.markers)
        current['digest'] = '8'*64
        lease, receipt, operation, guard = claim_crash_rollback(**options)
        with lease:
            self.assertEqual(lease.generation, pending['generation'])
            self.assertEqual(receipt.request_hash, options['request'].digest())
            self.assertEqual(operation.phase, 'start-original')
            self.assertEqual(len(ledger.markers), 1)
            guard()
            with self.assertRaisesRegex(ScopeBlocked, 'live writer'):
                claim_crash_rollback(**options)
            current['digest'] = '9'*64
            with self.assertRaises(ValueError):
                guard()
            current['digest'] = '8'*64
            guard()
            lease.complete('e'*64)
        with acquire_scope(scope, 'f'*64) as following:
            self.assertEqual(following.generation, pending['generation'] + 1)

    def test_abandoned_claim_is_not_reused_even_when_the_old_journal_is_intact(self):
        scope, pending, _, ledger, options = self._recovery()
        lease, _, _, _ = claim_crash_rollback(**options)
        lease.close()
        self.assertEqual(inspect_pending_scope(scope, pending['requestHash']), pending)
        with self.assertRaisesRegex(ScopeBlocked, 'already claimed'):
            claim_crash_rollback(**options)
        self.assertEqual(len(ledger.markers), 1)

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required')
    def test_new_owner_restarts_original_and_closes_only_after_witness_and_readiness(self):
        self._witnessed_restart(ready=True)

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required')
    def test_restart_without_http_readiness_keeps_generation_pending(self):
        self._witnessed_restart(ready=False)

    def _witnessed_restart(self, *, ready):
        case = worker_fixture.RetainedWorkerTests()
        case.fixed_production_network = True
        self.addCleanup(case.doCleanups)
        case.setUp()
        worker = case.worker
        prepared = dict(plan=case.private, protection=worker._protection_digest, candidate=case.candidate)
        scope, root, pending, old_public, key_hash, report, _ = self._interrupt(admit_only=False, prepared=prepared)
        case.registration = scope
        case._write(worker._plan.create(), before_dispatch=lambda: None)
        case._write(worker._plan.switch(case.candidate)[0], before_dispatch=lambda: None)
        case.writes.clear()
        observer = case.observe()
        endpoint = observer.descriptor()['endpointDigest']
        source = dict(root=root, pending=pending, public_key=old_public, expected_key_hash=key_hash)
        provisional = prepare_crash_rollback_review(report, case.private, observation_digest='0'*64)
        protection = worker_fixture.worker_module.ProductionFrontendProtectionV1
        capture = protection._observe
        # Docker and endpoint firewall fixtures remain isolated from the OS.
        with (patch.object(protection, '_observe', side_effect=lambda obs, limit, _: capture(obs, limit)),
              patch('deployment_compose_retained_recovery_handoff_v1_host._capture_current_origin',
                    return_value=b'new-native-owner'),
              patch('deployment_compose_retained_recovery_handoff_v1_host.ProductionCaddyProbeV1',
                    return_value=lambda cid: ready and cid == case.original)):
            observation = observe_confirmed_stop(observer, case.private, worker._baseline,
                                                 provisional['retainedCutover'], endpoint_digest=endpoint)
            review = prepare_crash_rollback_review(report, case.private, observation_digest=observation)
            approval, grant, request, _ = case._approval(review, 'rollback')
            brokers = []

            def register(store, policy):
                broker = witness_fixture.RetainedWitnessAdmissionV1(
                    store=store, gate_policy=policy, gate_key=b'g'*32, witness_signer=case.key,
                    witness_public_key=case.public, private_plan=case.private, review=review,
                    request=request, approval=approval, consumption=registration['receipt'],
                    scope_generation=registration['generation'],
                    writer_origin_digest=hashlib.sha256(b'new-native-owner').hexdigest(), recovery_source=source,
                )
                brokers.append(broker)
                return broker.first_binding, broker.authorize_rpc

            registration = {}
            case._install_mtls_writer(register=register)

            def writer_factory(bound, operation, receipt, execution, generation):
                registration.update(receipt=receipt, generation=generation)
                return worker._factory(bound, operation, request.digest(),
                                       hashlib.sha256(canonical(asdict(receipt))).hexdigest(), execution)

            args = dict(private_plan=case.private, original_baseline=worker._baseline,
                        observer=observer, endpoint_digest=endpoint, review=review, approval=approval,
                        grant=grant, request=request, runtime_sha=approval.policy.workflow_sha,
                        witness_writer_factory=writer_factory, caddy_id=case.row['Id'], readiness_timeout=1)
            if ready:
                result = execute_crash_rollback(scope, **source, **args)
                self.assertEqual(result['scopeGeneration'], pending['generation'])
                self.assertEqual(brokers[0].closed_chain(), (case.candidate, [result['witnessDigest']]))
                with acquire_scope(scope, 'f'*64) as following:
                    self.assertEqual(following.generation, pending['generation'] + 1)
            else:
                with self.assertRaises(ValueError):
                    execute_crash_rollback(scope, **source, **args)
                self.assertEqual(inspect_pending_scope(scope, pending['requestHash']), pending)
                self.assertEqual(len(brokers[0].closed_chain()[1]), 1)
        self.assertEqual(case.writes, ['start-original'])
        self.assertTrue(case.other_rows[case.original]['State']['Running'])
        self.assertEqual(case.other_rows[case.candidate]['State']['Status'], 'created')
