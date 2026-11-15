"""Process loss with real OpenSSH signatures and production-scope flock."""
import hashlib
import json
from copy import deepcopy
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
from tests.test_deployment_compose_production_frontend_approval_v1_host import approved, fixture, host
from deployment_compose_production_scope_v1_host import (
    ScopeBlocked, ScopeRegistrationV1, acquire_scope, inspect_pending_scope, provision_scope,
)
from deployment_compose_retained_crash_evidence_v1_host import inspect_retained_crash_evidence
from deployment_compose_retained_recovery_handoff_v1_host import claim_crash_rollback, prepare_crash_rollback_review
from deployment_compose_witness_store import canonical
from deployment_gate_witness import key_material


def _crash_fixture(parent, admit_only):
    tempfile.tempdir = str(parent)
    fixture = witness_fixture.RetainedWitnessAdmissionTests()
    fixture.staged_only = True
    fixture.setUp()
    scope = parent/'scope'
    scope.mkdir(mode=0o700)
    registration = provision_scope(scope, host_id='host', project='luohao-blog-prod', daemon_id='daemon')
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
    def _interrupt(self, *, admit_only):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
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
                scope = ScopeRegistrationV1(Path(result['scope']), tuple(result['scopeIdentity']),
                                            tuple(result['journalIdentity']), 'host', 'luohao-blog-prod', 'daemon')
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
