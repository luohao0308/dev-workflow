"""Offline deployment capability contracts using real collector-issued baselines."""
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
sys.path.insert(1, str(ROOT / 'packs/release/scripts'))
import deployment_authorize as sdk
import release_execute as release
from tests import test_deployment_prepare as prepare_fixtures
from tests.test_deployment_runtime import DockerFixture, collector, policy, runtime

DATA = prepare_fixtures.DATA


def deadline(minutes=20):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


class Approval:
    """Trusted in-process host double; no network, commands or deployment writes."""
    def __init__(self):
        self.calls = []
        self.on_validate = self.on_consume = self.on_guard = None

    def validate(self, request):
        self.calls.append('validate')
        if self.on_validate:
            self.on_validate()
        return sdk.Grant('fixture:deployment', request.digest(), request.expires_at, 1)

    def consume(self, grant, request, *, before_consume=None):
        self.calls.append('consume')
        if self.on_consume:
            self.on_consume()
        if before_consume is not None:
            before_consume()
        return sdk.Receipt(grant.grant_id, request.digest(), 1, datetime.now(timezone.utc).isoformat())

    def guard(self, request):
        self.calls.append('guard')
        if self.on_guard:
            self.on_guard()


class DeploymentAuthorizeTests(unittest.TestCase):
    def setUp(self):
        # Composition deliberately avoids inheriting and rerunning planner tests.
        self.fixture = prepare_fixtures.DeploymentPrepareTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        deployment = self.fixture.config['extensions']['deployment']
        deployment['components'] = ['web']
        deployment['environments']['staging']['components'] = ['web']
        self.fixture.save_config()
        self.docker = DockerFixture()
        self.collector, _ = collector(policy(target='staging-cluster'), self.docker)
        self.observation = self.collector.collect()
        self.fixture.current = self.observation.snapshot()
        self.fixture.target['components'] = [self.fixture.component('web', '3')]
        self.plan = self.prepare()
        self.request = self.build()
        self.approval = Approval()

    def prepare(self):
        self.fixture.sync_inputs()
        plan = self.fixture.prepare()
        self.assertEqual(plan['result'], 'prepared', plan['blockers'])
        return plan

    def build(self, **changes):
        values = dict(collector=self.collector, observation=self.observation,
                      repository_slug='fixture/example', repository_id=123,
                      expires_at=deadline())
        values.update(changes)
        return sdk.build_request(self.root, self.plan, 'deployment-deploy', **values)

    def authorize(self, **changes):
        values = dict(collector=self.collector, observation=self.observation, approval=self.approval)
        values.update(changes)
        return sdk.authorize(self.root, self.plan, self.request, **values)

    def audits(self):
        return [json.loads(p.read_text()) for p in sorted((self.root / DATA).glob('authorization-*.json'))]

    def test_deploy_authorizes_exactly_one_dispatch_without_execution(self):
        permit = self.authorize()
        result = permit.to_dict()
        self.assertEqual(result['status'], 'consumed-verified')
        self.assertTrue(result['authorizationConsumed'])
        self.assertFalse(result['executionAvailable'])
        self.assertFalse(result['productionReady'])
        self.assertEqual(result['execution'], 'not-performed')
        self.assertEqual(result['requestHash'], self.request.digest())
        self.assertEqual(self.approval.calls, ['validate', 'consume', 'guard'])
        self.assertIs(permit.claim_for_dispatch(), permit.receipt)
        with self.assertRaisesRegex(sdk.AuthorizationError, 'already claimed'):
            permit.claim_for_dispatch()
        self.assertEqual(self.approval.calls.count('consume'), 1)
        self.assertEqual(self.audits(), [result])
        self.assertFalse((self.root / 'MUST_NOT_EXIST').exists())
        for path in (self.root / DATA).glob('authorization-*.json'):
            if os.name != 'nt':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        result['components'].clear()
        self.assertEqual(permit.to_dict()['components'], ['web'])

    def test_permit_identity_fields_are_read_only(self):
        permit = self.authorize()
        for field in ('request', 'grant', 'receipt'):
            with self.subTest(field=field), self.assertRaises(AttributeError):
                setattr(permit, field, object())

    def test_authorization_only_permit_cannot_guard_execution(self):
        permit = self.authorize()
        check = mock.Mock()
        with self.assertRaises(sdk.AuthorizationError):
            permit.guard_for_execution(check)
        permit.claim_for_dispatch()
        with self.assertRaises(sdk.AuthorizationError):
            permit.guard_for_execution(check)
        check.assert_not_called()

    def test_reconstructed_permit_cannot_recover_authority(self):
        issued = self.authorize()
        fake = sdk.DeploymentPermit(request=issued.request, grant=issued.grant, receipt=issued.receipt,
                                    check=lambda: None, result=issued.to_dict(), execution_guard=lambda check: check())
        with self.assertRaises(sdk.AuthorizationError):
            fake.claim_for_dispatch()

    def test_execution_binding_is_immutable_canonical_and_profile_specific(self):
        for value in ('{}', '[]', '{"profile":"other"}'):
            with self.subTest(binding=value), self.assertRaises(sdk.AuthorizationError):
                replace(self.request, execution_json=value)
    def test_request_and_host_types_are_frozen_and_domain_separated(self):
        grant = self.approval.validate(self.request)
        receipt = self.approval.consume(grant, self.request)
        for value, attribute in ((self.request, 'operation'), (grant, 'grant_id'), (receipt, 'use_number')):
            with self.subTest(value=type(value)), self.assertRaises(FrozenInstanceError):
                setattr(value, attribute, None)
        self.assertEqual(self.request.components, ('web',))
        self.assertEqual(self.request.repository, str(self.root))
        self.assertNotIn('release_json', asdict(self.request))
        self.assertNotEqual(self.request.digest(), sdk.fingerprint(asdict(self.request)))
        self.assertNotEqual(self.request.digest(), replace(self.request, operation='deployment-rollback').digest())

    def test_release_and_dictionary_requests_are_rejected_before_host(self):
        foreign = release.Request('release', str(self.root), 'a' * 40, 'main', 'a' * 40,
                                  'b' * 64, 'v1', 'a' * 40, None, None, None, 'c' * 64)
        for value in (foreign, asdict(self.request)):
            with self.subTest(value=type(value)), self.assertRaises(sdk.AuthorizationError):
                sdk.authorize(self.root, self.plan, value, collector=self.collector,
                              observation=self.observation, approval=self.approval)
        self.assertEqual(self.approval.calls, [])

    def test_release_and_dictionary_grants_are_rejected_without_consuming(self):
        grant = self.approval.validate(self.request)
        self.approval.calls.clear()
        for value in (release.Grant(**asdict(grant)), asdict(grant)):
            with self.subTest(value=type(value)), mock.patch.object(self.approval, 'validate', return_value=value):
                with self.assertRaises(sdk.AuthorizationError):
                    self.authorize()
        self.assertEqual(self.approval.calls, [])
        self.assertEqual(self.audits(), [])

    def test_release_and_dictionary_receipts_leave_uncertain_audit(self):
        grant = self.approval.validate(self.request)
        receipt = self.approval.consume(grant, self.request)
        for value in (release.Receipt(**asdict(receipt)), asdict(receipt)):
            with self.subTest(value=type(value)), mock.patch.object(self.approval, 'consume', return_value=value):
                with self.assertRaises(sdk.AuthorizationError):
                    self.authorize()
        self.assertEqual(len(self.audits()), 2)
        self.assertTrue(all(a['status'] == 'consumption-unverified' and not a['authorizationConsumed']
                            for a in self.audits()))

    def test_grant_scope_expiry_and_single_use_constraints(self):
        grant = self.approval.validate(self.request)
        for changes in ({'request_hash': '0' * 64}, {'max_uses': 2}, {'max_uses': True},
                        {'expires_at': deadline(-1)}, {'expires_at': deadline(21)}):
            with self.subTest(changes=changes), self.assertRaises(sdk.AuthorizationError):
                sdk.validate_grant(replace(grant, **changes), self.request)

    def test_receipt_binding_and_exact_use_are_required(self):
        grant = self.approval.validate(self.request)
        started = datetime.now(timezone.utc)
        receipt = self.approval.consume(grant, self.request)
        for changes in ({'grant_id': 'different'}, {'request_hash': '0' * 64},
                        {'use_number': 2}, {'use_number': True},
                        {'consumed_at': deadline(-2)}, {'consumed_at': deadline(2)}):
            with self.subTest(changes=changes), self.assertRaises(sdk.AuthorizationError):
                sdk.validate_receipt(replace(receipt, **changes), grant, self.request, started)

    def test_missing_authority_fails_closed(self):
        with self.assertRaisesRegex(sdk.AuthorizationError, 'authority unavailable'):
            self.authorize(approval=None)
        self.assertEqual(self.audits(), [])

    def test_cli_missing_authority_defaults_to_deny(self):
        for action in ('authorize', 'execute'):
            with self.subTest(action=action):
                result = subprocess.run([sys.executable, '-I', str(Path(sdk.__file__)), action],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('Trusted deployment host required', json.loads(result.stderr)['error'])
                self.assertEqual(result.stdout, '')

    def test_isolated_standalone_bootstrap_prefers_trusted_core_in_both_layouts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / 'candidate'
            candidate.mkdir()
            (candidate / 'workflow_config.py').write_text('raise RuntimeError("untrusted import")\n')
            installed = root / 'installed/scripts'
            installed.mkdir(parents=True)
            for source in (Path(sdk.__file__), Path(sdk.planner.__file__),
                           ROOT / 'core/scripts/workflow_config.py', ROOT / 'core/scripts/workflow_lock.py'):
                shutil.copyfile(source, installed / source.name)
            for script, core in ((Path(sdk.__file__), ROOT / 'core/scripts'),
                                 (installed / 'deployment_authorize.py', installed)):
                code = ('import importlib.util, sys; sys.path.insert(0, sys.argv[2]); '
                        'spec = importlib.util.spec_from_file_location("deployment_authorize", sys.argv[1]); '
                        'module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; '
                        'spec.loader.exec_module(module); import workflow_config; print(workflow_config.__file__)')
                with self.subTest(script=script):
                    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(script), str(candidate)],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(Path(result.stdout.strip()).resolve(), (core / 'workflow_config.py').resolve())

    def test_scope_mismatch_rejected(self):
        for changes in ({'repository_slug': 'other/repository'},):
            with self.subTest(changes=changes), self.assertRaises(sdk.AuthorizationError):
                self.build(**changes)
        for field, value in (('environment', 'production'), ('target', 'other'), ('production', True)):
            other, _ = collector(replace(self.collector.policy, **{field: value}), DockerFixture())
            observation = other.collect()
            with self.subTest(field=field), self.assertRaises(sdk.AuthorizationError):
                self.build(collector=other, observation=observation)

    def test_exported_or_copied_runtime_proof_is_rejected(self):
        for proof in (self.observation.to_dict(), self.observation.snapshot(),
                      runtime.RuntimeObservation(**asdict(self.observation)), replace(self.observation)):
            with self.subTest(proof=type(proof)), self.assertRaises(runtime.RuntimeCollectionError):
                self.build(observation=proof)

    def test_request_expiry_and_excess_lifetime_rejected(self):
        for expires in (deadline(-1), deadline(61)):
            with self.subTest(expires=expires), self.assertRaises(sdk.AuthorizationError):
                self.build(expires_at=expires)
        with mock.patch.object(sdk, 'clock', return_value=datetime.now(timezone.utc) + timedelta(minutes=21)):
            with self.assertRaises(sdk.AuthorizationError):
                self.authorize()
        self.assertEqual(self.approval.calls, [])

    def test_stale_baseline_cannot_authorize(self):
        future = datetime.now(timezone.utc) + timedelta(seconds=61)
        with mock.patch.object(runtime, 'utcnow', return_value=future):
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.authorize()
        self.assertEqual(self.approval.calls, [])

    def test_forged_plan_and_request_binding_rejected(self):
        for field, value in (('state_hash', '0' * 64), ('plan_hash', '0' * 64),
                             ('repository', '/untrusted'), ('configuration_hash', '0' * 64)):
            original = self.request
            self.request = replace(original, **{field: value})
            try:
                with self.subTest(field=field), self.assertRaises(sdk.AuthorizationError):
                    self.authorize()
            finally:
                self.request = original
        self.assertEqual(self.approval.calls, [])

    def test_input_and_configuration_drift_rejected_before_consumption(self):
        self.fixture.target['version'] = 'changed'
        self.fixture.sync_inputs()
        with self.assertRaises(ValueError):
            self.authorize()
        self.assertEqual(self.approval.calls, [])

    def test_configuration_bytes_drift_rejected_before_host(self):
        path = self.root / 'workflow.config.json'
        path.write_text(path.read_text() + '\n')
        with self.assertRaises(ValueError):
            self.authorize()
        self.assertEqual(self.approval.calls, [])
        self.assertEqual(self.audits(), [])

    def test_plan_content_drift_rejected_before_host(self):
        self.plan['version'] = 'unapproved-version'
        with self.assertRaises(ValueError):
            self.authorize()
        self.assertEqual(self.approval.calls, [])

    def test_live_drift_before_host_rejected(self):
        self.docker.container['State']['Pid'] += 1
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.authorize()
        self.assertEqual(self.approval.calls, [])

    def test_live_drift_during_approval_rejected_before_consumption(self):
        self.approval.on_validate = lambda: self.docker.container['State'].update(Pid=999)
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.authorize()
        self.assertEqual(self.approval.calls, ['validate'])
        self.assertEqual(self.audits(), [])

    def test_failed_consume_records_uncertain_outcome_without_retry(self):
        def fail():
            raise RuntimeError('host outcome unknown')
        self.approval.on_consume = fail
        with self.assertRaisesRegex(RuntimeError, 'outcome unknown'):
            self.authorize()
        audit, = self.audits()
        self.assertEqual(audit['status'], 'consumption-unverified')
        self.assertEqual(audit['failureCode'], 'consumption-rejected-or-unknown')
        self.assertFalse(audit['authorizationConsumed'])
        self.assertEqual(self.approval.calls, ['validate', 'consume'])

    def test_drift_inside_consumption_guard_records_unknown_outcome(self):
        self.approval.on_consume = lambda: self.docker.container['State'].update(Pid=999)
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.authorize()
        audit, = self.audits()
        self.assertEqual(audit['status'], 'consumption-unverified')
        self.assertFalse(audit['authorizationConsumed'])
        self.assertEqual(audit['failureCode'], 'consumption-rejected-or-unknown')
        self.assertEqual(self.approval.calls.count('consume'), 1)

    def test_runtime_drift_in_last_authority_reads_prevents_cas_and_retry(self):
        from tests import test_deployment_host as host_fixtures
        fixture = host_fixtures.DeploymentHostTests(methodName='runTest')
        fixture.setUp()
        fixture.req = self.request
        fixture.policy = replace(fixture.policy, target_repository=self.request.repository_slug,
                                 target_repository_id=self.request.repository_id,
                                 deployment_target=self.request.target,
                                 runtime_policy_hash=self.request.runtime_policy_hash)
        fixture.client = fixture.client_for([self.request])
        fixture.client.data.pop('/repos/sample/target')
        fixture.client.data['/repos/' + self.request.repository_slug] = dict(
            id=self.request.repository_id, full_name=self.request.repository_slug)
        approval = fixture.make_host()
        original = fixture.client.request
        at_cas = False
        def request(method, path, payload=None, **kwargs):
            nonlocal at_cas
            if method == 'POST':
                at_cas = True
            result = original(method, path, payload, **kwargs)
            if at_cas and method == 'GET' and path.endswith('/approvals'):
                self.docker.container['State']['Pid'] += 1
            return result
        with mock.patch.object(fixture.client, 'request', side_effect=request):
            with self.assertRaises(host_fixtures.AuthorizationUnavailable):
                self.authorize(approval=approval)
        self.assertTrue(at_cas)
        self.assertEqual(fixture.client.posts, 0)
        self.assertIn(self.request.digest(), approval._consumed)
        self.assertNotIn(self.request.digest(), approval._verified_consumptions)
        with self.assertRaises(host_fixtures.AuthorizationUnavailable):
            approval.consume(approval.validate(self.request), self.request)
        self.assertEqual(fixture.client.posts, 0)
        audit, = self.audits()
        self.assertEqual(audit['status'], 'consumption-unverified')
        self.assertFalse(audit['authorizationConsumed'])

    def test_postconsume_drift_leaves_verified_authority_spent(self):
        consume = self.approval.consume
        def drift_after_receipt(grant, request, *, before_consume=None):
            receipt = consume(grant, request, before_consume=before_consume)
            self.docker.container['State']['Pid'] += 1
            return receipt
        with mock.patch.object(self.approval, 'consume', side_effect=drift_after_receipt):
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.authorize()
        audit, = self.audits()
        self.assertEqual(audit['status'], 'consumed-invalidated')
        self.assertTrue(audit['authorizationConsumed'])
        self.assertEqual(self.approval.calls.count('consume'), 1)

    def test_guard_rejection_invalidates_consumed_authority(self):
        def revoked():
            raise sdk.AuthorizationError('host authority revoked')
        self.approval.on_guard = revoked
        with self.assertRaisesRegex(sdk.AuthorizationError, 'revoked'):
            self.authorize()
        audit, = self.audits()
        self.assertEqual(audit['status'], 'consumed-invalidated')
        self.assertTrue(audit['authorizationConsumed'])

    def test_guard_input_drift_rejected_after_callback(self):
        def change():
            self.fixture.target['version'] = 'changed-by-guard'
            self.fixture.sync_inputs()
        self.approval.on_guard = change
        with self.assertRaises(ValueError):
            self.authorize()
        self.assertEqual(self.audits()[0]['status'], 'consumed-invalidated')

    def test_guard_runtime_drift_cannot_return_dispatch_permit(self):
        self.approval.on_guard = lambda: self.docker.container['State'].update(Pid=999)
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.authorize()
        audit, = self.audits()
        self.assertEqual(audit['status'], 'consumed-invalidated')
        self.assertTrue(audit['authorizationConsumed'])

    def test_dispatch_rechecks_runtime_and_host_without_consuming_again(self):
        permit = self.authorize()
        self.docker.container['State']['Pid'] += 1
        with self.assertRaises(runtime.RuntimeCollectionError):
            permit.claim_for_dispatch()
        self.assertEqual(self.approval.calls.count('consume'), 1)

    def test_config_drift_during_last_collector_read_rejects_claim(self):
        permit = self.authorize()
        original = self.collector.recheck
        guarded = False
        def guard():
            nonlocal guarded
            guarded = True
        def recheck(observation):
            result = original(observation)
            if guarded:
                path = self.root / 'workflow.config.json'
                path.write_text(path.read_text() + '\n')
            return result
        self.approval.on_guard = guard
        with mock.patch.object(self.collector, 'recheck', side_effect=recheck):
            with self.assertRaises(ValueError):
                permit.claim_for_dispatch()
        self.assertFalse(permit._claimed)
        self.assertEqual(self.approval.calls.count('consume'), 1)
        self.assertTrue(self.audits()[0]['authorizationConsumed'])

    def test_concurrent_claim_is_atomic(self):
        permit = self.authorize()
        barrier = threading.Barrier(8)
        successes, failures = [], []
        lock = threading.Lock()
        def claim():
            barrier.wait(timeout=10)
            try:
                outcome = permit.claim_for_dispatch()
            except Exception as error:
                with lock:
                    failures.append(error)
            else:
                with lock:
                    successes.append(outcome)
        threads = [threading.Thread(target=claim) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(successes, [permit.receipt])
        self.assertEqual(len(failures), 7)
        self.assertTrue(all(isinstance(error, sdk.AuthorizationError) for error in failures))
        self.assertEqual(self.approval.calls, ['validate', 'consume', 'guard', 'guard'])

    def rollback_setup(self):
        history = self.observation
        # A restart changes actual current state without inventing historical JSON.
        self.docker.container['State']['Pid'] += 1
        self.docker.container['Config']['User'] = '2000'
        self.observation = self.collector.collect()
        self.fixture.current = self.observation.snapshot()
        self.fixture.target['components'] = history.snapshot()['components']
        self.plan = self.prepare()
        values = dict(collector=self.collector, observation=self.observation,
                      repository_slug='fixture/example', repository_id=123, expires_at=deadline())
        return history, values

    def test_rollback_requires_explicit_same_collector_history(self):
        history, values = self.rollback_setup()
        other, _ = collector(self.collector.policy, DockerFixture())
        for proof in (None, self.observation, history.to_dict(), history.snapshot(), replace(history), other.collect(),
                      self.collector.collect()):
            with self.subTest(proof=type(proof)), self.assertRaises(ValueError):
                sdk.build_request(self.root, self.plan, 'deployment-rollback', rollback_target=proof, **values)
        self.request = sdk.build_request(self.root, self.plan, 'deployment-rollback', rollback_target=history, **values)
        self.assertEqual(json.loads(self.request.conditions_json)['rollbackHistoryHash'], history.evidence_hash)
        self.assertNotEqual(self.request.state_hash, history.state_hash)
        self.assertIs(self.authorize(rollback_target=history).claim_for_dispatch().__class__, sdk.Receipt)

    def test_retained_history_can_be_old_but_current_baseline_must_be_fresh(self):
        history = self.observation
        future = datetime.now(timezone.utc) + timedelta(seconds=61)
        with mock.patch.object(runtime, 'utcnow', return_value=future), \
                mock.patch.object(prepare_fixtures.planner, 'now', return_value=future), \
                mock.patch.object(sdk.planner, 'now', return_value=future):
            self.docker.container['Config']['User'] = '2000'
            self.observation = self.collector.collect()
            self.fixture.current = self.observation.snapshot()
            self.fixture.target['components'] = history.snapshot()['components']
            self.plan = self.prepare()
            values = dict(collector=self.collector, observation=self.observation,
                          repository_slug='fixture/example', repository_id=123, expires_at=deadline())
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.collector.validate(history)
            self.request = sdk.build_request(self.root, self.plan, 'deployment-rollback', rollback_target=history, **values)
            self.authorize(rollback_target=history).claim_for_dispatch()
        stale_time = future + timedelta(seconds=61)
        with mock.patch.object(runtime, 'utcnow', return_value=stale_time), \
                mock.patch.object(sdk.planner, 'now', return_value=stale_time):
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.authorize(rollback_target=history)

    def test_rollback_target_and_live_baseline_cannot_be_substituted(self):
        history, values = self.rollback_setup()
        self.fixture.target['components'] = [self.fixture.component('web', '9')]
        self.plan = self.prepare()
        with self.assertRaisesRegex(sdk.AuthorizationError, 'differs from authenticated history'):
            sdk.build_request(self.root, self.plan, 'deployment-rollback', rollback_target=history, **values)
        with self.assertRaises(ValueError):
            self.build(rollback_target=history)


if __name__ == '__main__':
    unittest.main()
