"""Bounded recovery tests with real store/gate/SDK and synthetic Docker.

The narrow reader/writer shims model root-owned integration APIs that are being
added concurrently. No production adapter, authority or daemon is discovered.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
import deployment_recover as recover
from tests import test_deployment_execute as fixtures


class Approval:
    def __init__(self):
        self.used = False
        self.calls = []

    def validate(self, request):
        self.calls.append('validate')
        return recover.RecoveryGrant('recovery:fixture', request.digest(), request.expires_at, 1)

    def consume(self, grant, request, *, before_consume):
        if self.used:
            raise ValueError('already used')
        before_consume()
        self.used = True
        self.calls.append('consume')
        return recover.RecoveryReceipt(grant.grant_id, request.digest(), 1, recover.sdk.clock().isoformat())

    def guard(self, request):
        if not self.used:
            raise ValueError('not consumed')
        self.calls.append('guard')


class RecoveryStartIdentityTests(unittest.TestCase):
    def test_first_start_initializes_only_known_docker_defaults(self):
        docker = fixtures.MutableDocker()
        previous = deepcopy(docker.containers[fixtures.OLD])
        previous['State'].update(Running=False, Status='created')
        previous['HostConfig']['OomKillDisable'] = False
        for key in recover.runtime.MANAGED_FILES.values():
            previous[key] = ''
        current = deepcopy(previous)
        current['State'].update(Running=True, Status='running')
        current['HostConfig']['OomKillDisable'] = None
        for filename, key in recover.runtime.MANAGED_FILES.items():
            current[key] = '/var/lib/docker/containers/' + fixtures.OLD + '/' + filename
        fields = ('Id', 'Name', 'Image', 'Config', 'HostConfig', *recover.runtime.MANAGED_FILES.values())
        self.assertTrue(recover._start_identity_matches(previous, current, fields))
        for change in ('env', 'memory', 'path', 'already-started'):
            before, after = deepcopy(previous), deepcopy(current)
            if change == 'env':
                after['Config']['Env'].append('DRIFT=1')
            elif change == 'memory':
                after['HostConfig']['Memory'] = 128
            elif change == 'path':
                after['HostsPath'] = '/foreign/hosts'
            else:
                before['State']['Status'] = 'exited'
            with self.subTest(change=change):
                self.assertFalse(recover._start_identity_matches(before, after, fields))


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.DeploymentExecuteTests(methodName='runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        host = Path(self.temp.name).resolve()
        import deployment_store
        self.store = deployment_store.HostStore(deployment_store.StorePolicy(
            123, 'host', 'key', self.f.collector.policy), host / 'store', key=b'k' * 32)
        self.gate = recover.gateway.FileWriterGate(recover.gateway.GatePolicy('host', 'key',
            recover._hash(self.store.policy._scope()), 'a' * 64), host / 'gate', key=b'k' * 32)
        self.f.policy = replace(self.f.policy, history_policy_hash=self.store.policy.identity_hash(),
                                gateway_policy_hash=self.gate.policy.identity_hash())
        self.c = recover.HostCoordinator(self.store, self.gate, self.f.collector, self.f.policy)
        self.f.client = recover.engine.DockerMutationClient(self.f.policy, ca_file=Path('unused'),
            cert_file=Path('unused'), key_file=Path('unused'), transport=self.f.docker.write)
        self.f.engine = recover.engine.DockerExecutor(self.f.policy, self.f.client, self.f.collector, coordinator=self.c)
        self.c.executor = self.f.engine
        self.f.prepare()
        self.root, self.oid = self.f.root, json.loads(self.f.intent.binding_json)['intentId']
        original_get = recover.runtime.DockerTLSClient.get
        def get(client, path, **kwargs):
            if path == '/v1.45/workflow/gate-info':
                return self.gate.info()
            return original_get(client, path, **kwargs)
        def lookup(client, ref, *, deadline):
            return next((deepcopy(v) for v in self.f.docker.containers.values()
                         if ref in (v['Id'], v['Name'].lstrip('/'))), None)
        self.patch(mock.patch.object(recover.runtime.DockerTLSClient, 'get', get))
        self.patch(mock.patch.object(recover.runtime.DockerTLSClient, 'lookup_container', lookup, create=True))
        # Root will extend the gate's fixed allowlist to the existing SDK name.
        original_operation = recover.gateway._operation
        def operation(method, path, body_hash):
            original_operation(method, path.replace('name=dwf-', 'name=dev-workflow-'), body_hash)
            return method, path, body_hash
        self.patch(mock.patch.object(recover.gateway, '_operation', operation))
        self.dead = mock.patch.object(recover, 'process_alive', return_value=False)
        self.patch(self.dead)
        self.install_writer()

    def patch(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def install_writer(self):
        def write(method, path, body, before_send, operation):
            operation.validate_writer(self.f.policy)
            raw = b'' if body is None else fixtures.backend.canonical(body).encode()
            session = operation.before_write(method, path, raw)
            attempt = session.prepare_attempt(method, path, raw)
            before_send()
            session.headers(attempt)
            ticket = self.gate.admit(session.generation, attempt.ref, method=method, path=path, body=raw,
                                     writer_certificate_sha256='a' * 64)
            status, response = self.f.docker.write(method, path, body)
            self.gate.finish(ticket, definitive=True, response_hash=recover._hash(response))
            operation.after_write(session, recover._hash(response))
            return response
        def create(client, name, body, *, before_send, host_operation):
            return write('POST', '/v1.45/containers/create?name=' + name, body, before_send, host_operation)
        def remove(client, cid, *, before_send, host_operation):
            return write('DELETE', '/v1.45/containers/' + cid + '?force=false&v=false', None, before_send, host_operation)
        def start(client, cid, *, before_send, host_operation):
            return write('POST', '/v1.45/containers/' + cid + '/start', None, before_send, host_operation)
        self.patch(mock.patch.object(recover.engine.DockerMutationClient, 'create', create))
        self.patch(mock.patch.object(recover.engine.DockerMutationClient, 'remove', remove))
        def stop(client, cid, *, before_send, host_operation):
            return write('POST', '/v1.45/containers/' + cid + '/stop?t=10', None, before_send, host_operation)
        self.patch(mock.patch.object(recover.engine.DockerMutationClient, 'start', start))
        self.patch(mock.patch.object(recover.engine.DockerMutationClient, 'stop', stop))

    def authorize(self, op):
        self.f.request = recover.sdk.build_request(self.root, self.f.plan, self.f.operation,
            collector=self.f.collector, observation=self.f.observation, repository_slug='fixture/example',
            repository_id=123, expires_at=(recover.sdk.clock() + timedelta(minutes=20)).isoformat(),
            execution_intent=self.f.intent)
        permit = recover.sdk.authorize(self.root, self.f.plan, self.f.request,
            collector=self.f.collector, observation=self.f.observation, approval=self.f.approval,
            execution_intent=self.f.intent, host_operation=op)
        return permit

    def begin(self, phase='before', *, pending=False, stale=False):
        with self.c.operation(self.root, self.f.plan, self.f.intent) as op:
            # Exercise the actual SDK authorization lifecycle/attestation hooks.
            permit = self.authorize(op)
            with op.lifecycle('deployment-execution') as lock:
                op.record_owner(lock)
                if phase != 'before':
                    record = self.f.engine._issued[id(self.f.intent)]
                    name = json.loads(self.f.intent.binding_json)['resourceName']
                    payload = record['spec'].to_create('fixture', self.oid)
                    self.dispatch(op, 'POST', 'create?name=' + name, payload, pending=pending)
                    if phase in ('stopped', 'absent', 'after'):
                        self.dispatch(op, 'POST', fixtures.OLD + '/stop?t=10')
                    if phase in ('absent', 'after'):
                        self.dispatch(op, 'DELETE', fixtures.OLD + '?force=false&v=false')
                    if phase == 'after':
                        cid = next(k for k in self.f.docker.containers if k not in (fixtures.OLD, fixtures.API))
                        self.dispatch(op, 'POST', cid + '/start')
                if stale:
                    # Preserve an actual matching owner file, as process death
                    # would; the injected liveness oracle supplies dead evidence.
                    lock.owned = False
        return op

    def dispatch(self, op, method, suffix, body=None, *, pending=False):
        path = '/v1.45/containers/' + suffix
        raw = b'' if body is None else fixtures.backend.canonical(body).encode()
        session = op.before_write(method, path, raw)
        attempt = session.prepare_attempt(method, path, raw)
        ticket = self.gate.admit(session.generation, attempt.ref, method=method, path=path, body=raw,
                                 writer_certificate_sha256='a' * 64)
        status, response = self.f.docker.write(method, path, body)
        if not pending:
            self.gate.finish(ticket, definitive=True, response_hash=recover._hash(response))
            op.after_write(session, recover._hash(response))
        return session

    def request(self):
        return self.c.prepare_recovery(self.root, self.oid,
            expires_at=(recover.sdk.clock() + timedelta(minutes=10)).isoformat())

    def test_normal_sdk_executor_handoff_finishes_only_verified_journal(self):
        with self.c.operation(self.root, self.f.plan, self.f.intent) as op:
            permit = self.authorize(op)
            result = self.f.engine.execute(self.root, permit, self.f.intent, host_operation=op)
            self.assertEqual(result['status'], 'executed-verified', result)
        events = self.c._load(self.oid)
        self.assertEqual(events[-1]['kind'], 'terminal')
        self.assertEqual(len([e for e in events if e['kind'] == 'attempt']), 4)
        self.assertEqual(len([e for e in events if e['kind'] == 'response']), 4)
        self.assertEqual(len([e for e in events if e['kind'] == 'owner']), 2)

    def test_host_writer_refuses_foreign_id_and_wrong_body_before_generation(self):
        with self.c.operation(self.root, self.f.plan, self.f.intent) as op:
            self.authorize(op)
            with op.lifecycle('deployment-execution') as lock:
                op.record_owner(lock)
                for method, suffix, body in (
                    ('DELETE', fixtures.API + '?force=false&v=false', b''),
                    ('POST', 'create?name=dwf-' + self.oid, b'{}')):
                    with self.assertRaisesRegex(recover.RecoveryError, 'write-outside-exact-approved-action'):
                        op.before_write(method, '/v1.45/containers/' + suffix, body)
        self.assertFalse(any(e['kind'] == 'attempt' for e in self.c._load(self.oid)))
        self.assertEqual(self.f.docker.writes, [])

    def test_closed_table_and_actual_cleanup_before(self):
        self.begin('created')
        self.assertEqual(self.c.inspect(self.root, self.oid)['state'], 'candidate-stopped-old-running')
        req = self.request()
        count = len(self.f.docker.writes)
        approval = Approval()
        result = self.c.recover(req, approval)
        self.assertEqual(result['status'], 'recovered-runtime-verified')
        self.assertEqual(result['health'], 'unknown')
        self.assertFalse(result['productionReady'])
        self.assertEqual(len(self.f.docker.writes), count + 1)
        self.assertEqual(set(self.f.docker.containers), {fixtures.OLD, fixtures.API})
        self.assertEqual(approval.calls.count('consume'), 1)
        self.assertEqual(self.c._load(self.oid)[-1]['kind'], 'terminal')

    def test_cleanup_then_start_old_and_stale_owner_reclaim(self):
        self.begin('stopped', stale=True)
        req = self.request()
        self.assertEqual([x['action'] for x in json.loads(req.actions_json)], ['remove', 'start'])
        with mock.patch('workflow_lock.process_alive', return_value=False):
            self.c.recover(req, Approval())
        self.assertTrue(self.f.docker.containers[fixtures.OLD]['State']['Running'])
        self.assertFalse((self.root / '.dev-workflow/lifecycle.lock/owner.json').exists())

    def test_retained_before_recipe_restoration(self):
        self.begin('absent')
        req = self.request()
        self.assertEqual([x['action'] for x in json.loads(req.actions_json)], ['remove', 'create', 'start'])
        result = self.c.recover(req, Approval())
        self.assertEqual(result['observation'].snapshot()['components'], self.f.observation.snapshot()['components'])
        restored = next(v for k, v in self.f.docker.containers.items() if k != fixtures.API)
        self.assertEqual(restored['Name'], '/dev-workflow-recover-' + self.oid)
        self.assertTrue(restored['State']['Running'])

    def test_zero_action_before_and_after_need_fresh_authority(self):
        self.begin('after')
        req = self.request()
        self.assertEqual(json.loads(req.actions_json), [])
        count = len(self.f.docker.writes)
        result = self.c.recover(req, Approval())
        self.assertEqual(result['status'], 'recovered-runtime-verified')
        self.assertEqual(len(self.f.docker.writes), count)

    def test_before_complete_zero_action_resolution_still_consumes(self):
        self.begin()
        request = self.request()
        self.assertEqual(json.loads(request.actions_json), [])
        authority = Approval()
        self.c.recover(request, authority)
        self.assertTrue(authority.used)
        self.assertEqual(self.f.docker.writes, [])

    def test_interrupted_retained_create_is_found_by_name_then_started_with_new_grant(self):
        self.begin('absent')
        first = self.request()
        original = self.c._after_write
        count = []
        def lost_response(oid, session, digest):
            count.append(session)
            if len(count) == 2:
                raise recover.RecoveryError('synthetic-observer-crash-after-create')
            return original(oid, session, digest)
        with mock.patch.object(self.c, '_after_write', lost_response), self.assertRaisesRegex(
                recover.RecoveryError, 'synthetic-observer-crash'):
            self.c.recover(first, Approval())
        self.assertEqual(self.c.inspect(self.root, self.oid)['state'], 'retained-restoration-stopped')
        second = self.request()
        self.assertNotEqual(first.request_id, second.request_id)
        self.assertEqual([x['action'] for x in json.loads(second.actions_json)], ['start'])
        self.c.recover(second, Approval())
        creates = [x for x in self.f.docker.writes if '/create?' in x[1]]
        self.assertEqual(len(creates), 2)  # original candidate + one restoration

    def test_empty_selected_state_after_cleanup_crash_is_explicitly_blocked(self):
        self.begin('absent')
        request = self.request()
        original = self.c._after_write
        def stopped(oid, session, digest):
            original(oid, session, digest)
            raise recover.RecoveryError('synthetic-crash-after-cleanup')
        with mock.patch.object(self.c, '_after_write', stopped), self.assertRaises(recover.RecoveryError):
            self.c.recover(request, Approval())
        with self.assertRaisesRegex(recover.RecoveryError, 'unsupported-empty-selected-state'):
            self.request()

    def test_authority_revocation_stops_remaining_writes_and_preserves_pending_journal(self):
        self.begin('stopped')
        request = self.request()
        original = self.c._after_write
        authority = Approval()
        def revoke(oid, session, digest):
            original(oid, session, digest)
            authority.used = False
        count = len(self.f.docker.writes)
        with mock.patch.object(self.c, '_after_write', revoke), self.assertRaises(ValueError):
            self.c.recover(request, authority)
        self.assertEqual(len(self.f.docker.writes), count + 1)
        self.assertFalse(self.f.docker.containers[fixtures.OLD]['State']['Running'])
        self.assertNotEqual(self.c._load(self.oid)[-1]['kind'], 'terminal')
        self.assertEqual(self.c.inspect(self.root, self.oid)['state'], 'old-stopped-only')
        self.c.recover(self.request(), Approval())
        self.assertTrue(self.f.docker.containers[fixtures.OLD]['State']['Running'])

    def test_disagreement_between_list_and_authoritative_lookup_blocks(self):
        self.begin('created')
        with mock.patch.object(recover.runtime.DockerTLSClient, 'lookup_container', return_value=None), self.assertRaisesRegex(
                recover.RecoveryError, 'direct-lookup-presence-mismatch'):
            self.request()

    def test_quiescence_unknown_blocks_even_stable_inventory(self):
        self.begin('created', pending=True)
        count = len(self.f.docker.writes)
        with self.assertRaises(recover.gateway.GateError):
            self.request()
        self.assertEqual(len(self.f.docker.writes), count)

    def test_live_producer_and_unknown_owner_guard_block(self):
        self.begin()
        with mock.patch.object(recover, 'process_alive', return_value=True), self.assertRaisesRegex(
                recover.RecoveryError, 'producer-alive'):
            self.request()
        directory = self.root / '.dev-workflow/lifecycle.lock'
        directory.mkdir(exist_ok=True)
        (directory / 'recovery.lock').touch()
        with self.assertRaisesRegex(recover.RecoveryError, 'unknown-core-recovery-guard'):
            self.request()

    def test_unattested_owner_never_reclaimed(self):
        self.begin()
        directory = self.root / '.dev-workflow/lifecycle.lock'
        directory.mkdir(exist_ok=True)
        path = directory / 'owner.json'
        path.write_text(json.dumps(dict(pid=999999, token='0' * 32, operation='deployment-execution', transaction=self.oid)))
        with self.assertRaisesRegex(recover.RecoveryError, 'unattested'):
            self.request()
        self.assertTrue(path.exists())

    def test_inventory_foreign_relabelled_and_unselected_drift_block(self):
        self.begin('created')
        original = deepcopy(self.f.docker.containers)
        for kind in ('foreign', 'relabel', 'managed'):
            with self.subTest(kind=kind):
                self.f.docker.containers = deepcopy(original)
                self.f.docker.managed_files.clear()
                if kind == 'foreign':
                    value = deepcopy(original[fixtures.API])
                    value['Id'] = '9' * 64
                    self.f.docker.containers[value['Id']] = value
                elif kind == 'relabel':
                    cid = next(k for k in original if k not in (fixtures.API, fixtures.OLD))
                    self.f.docker.containers[cid]['Config']['Labels']['dev-workflow.execution-id'] = '8' * 64
                else:
                    self.f.docker.managed_files[(fixtures.API, 'hosts')] = b'drift'
                with self.assertRaises((recover.RecoveryError, recover.engine.ExecutionError)):
                    self.request()

    def test_fresh_state_guard_blocks_before_consumption_and_reconstructed_requests(self):
        self.begin('created')
        request = self.request()
        with self.assertRaisesRegex(recover.RecoveryError, 'held-recovery-session'):
            self.c.authorize_recovery(request, approval=Approval())
        with self.assertRaisesRegex(recover.RecoveryError, 'unissued-recovery-request'):
            self.c.recover(replace(request), Approval())
        self.f.docker.containers[fixtures.API]['RestartCount'] = 1
        authority = Approval()
        with self.assertRaises(recover.RecoveryError):
            self.c.recover(request, authority)
        self.assertFalse(authority.used)

    def test_normal_grants_and_forged_permits_are_rejected(self):
        self.begin()
        request = self.request()
        grant = recover.sdk.Grant('normal', request.digest(), request.expires_at, 1)
        with self.assertRaisesRegex(recover.RecoveryError, 'domain'):
            recover.validate_grant(grant, request)
        with self.assertRaisesRegex(recover.RecoveryError, 'held-issued'):
            self.c.execute_recovery(recover.RecoveryPermit(request, grant, None))

    def test_journal_tamper_restart_and_no_raw_secret(self):
        self.begin('created')
        c = recover.HostCoordinator(self.store, self.gate, self.f.collector, self.f.policy, executor=self.f.engine)
        self.assertEqual(c.inspect(self.root, self.oid)['state'], 'candidate-stopped-old-running')
        files = sorted(self.store.root.glob('journal-*'))
        self.assertNotIn(fixtures.SECRET, ''.join(p.read_text() for p in files))
        data = json.loads(files[0].read_text())
        data['payload']['data']['root'] = '/forged'
        files[0].write_text(json.dumps(data))
        with self.assertRaisesRegex(recover.RecoveryError, 'authentication'):
            c.inspect(self.root, self.oid)

    def test_unresolved_journal_blocks_normal_operation_and_expired_capability(self):
        op = self.begin()
        with self.assertRaisesRegex(recover.RecoveryError, 'host-operation-not-active'):
            op.validate(self.root, self.f.intent)
        with self.assertRaisesRegex(recover.RecoveryError, 'unresolved-host-operation'):
            with self.c.operation(self.root, self.f.plan, self.f.intent):
                self.fail('unresolved journal admitted')


if __name__ == '__main__':
    unittest.main()
