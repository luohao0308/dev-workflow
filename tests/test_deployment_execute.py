"""Independent synthetic Docker daemon; actual planner/collector/SDK issuance.

No Docker socket, image pull, external host, credentials, or product checkout.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import shutil
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
import deployment_execute as backend
import deployment_spec as recipes
from tests import test_deployment_prepare as planning
from tests.test_deployment_authorize import Approval
from tests.test_deployment_runtime import managed_archive

sdk, runtime = backend.sdk, backend.runtime
OLD, API = 'e' * 64, 'f' * 64
SECRET = 'EXECUTION-PRIVATE-ENV'


class MutableDocker:
    """Allowlisted fake Docker API server transport with mutable daemon state."""
    def __init__(self):
        self.containers, self.images, self.specs = {}, {}, {}
        self.writes, self.reads = [], []
        self.entries = []
        self.sequence = 0
        self.managed_files = {}
        self.on_write = self.on_read = None
        self.daemon_id = 'synthetic-daemon'
        for component, digit in (('web', 'a'), ('web', 'b'), ('api', 'c')):
            image_id = 'sha256:' + digit * 64
            image = dict(Id=image_id, Os='linux', Architecture='amd64', RepoDigests=[],
                         Config=dict(Cmd=['/service'], Entrypoint=None, Env=['TOKEN=' + SECRET],
                                     User='1000', WorkingDir='/app', Labels={}, ExposedPorts={}))
            spec = recipes.ContainerSpec.from_image(component, image)
            self.images[image_id] = image
            self.specs[(component, image_id)] = spec
            source = {'a': '1', 'b': '2', 'c': '3'}[digit] * 40
            self.entries.append(dict(component=component, imageId=image_id, repository='fixture/example',
                                     sourceSha=source, version='1.0.' + str(len(self.entries)), os='linux',
                                     architecture='amd64', artifact=dict(kind='local-build', imageId=image_id,
                                                                       buildSourceSha=source),
                                     migration=dict(mode='none', version=None)))
        for cid, component, digit in ((OLD, 'web', 'a'), (API, 'api', 'c')):
            spec = self.specs[(component, 'sha256:' + digit * 64)]
            self.containers[cid] = self.inspect(cid, 'initial-' + component,
                                                spec.to_create('fixture', 'initial'), running=True)

    def inspect(self, cid, name, body, *, running):
        config = deepcopy(body)
        host = config.pop('HostConfig')
        host.update(Privileged=False, PidMode='', IpcMode='private', UTSMode='')
        config.update(Hostname=cid[:12], Volumes=None)
        value = dict(Id=cid, Name='/' + name, Image=body['Image'], Config=config,
                     HostConfig=host, Mounts=[], Created='2026-01-01T00:00:00Z', RestartCount=0,
                     Path='/service', Args=[], NetworkSettings={'Networks': {'bridge': {'IPAddress': '172.17.0.2'}}},
                     State=dict(Running=running, Paused=False, Restarting=False, Dead=False,
                                Status='running' if running else 'created', Pid=123 if running else 0,
                                StartedAt='2026-01-01T00:00:00Z' if running else '0001-01-01T00:00:00Z'))
        for filename, key in runtime.MANAGED_FILES.items():
            value[key] = '/var/lib/docker/containers/' + cid + '/' + filename
        return value

    def read(self, path):
        self.reads.append(path)
        if self.on_read:
            self.on_read(path)
        route = urlsplit(path).path
        if route == '/v1.45/info':
            return dict(ID=self.daemon_id)
        if route == '/v1.45/containers/json':
            return [dict(Id=cid, Labels=deepcopy(value['Config']['Labels']))
                    for cid, value in sorted(self.containers.items())]
        if route.startswith('/v1.45/images/'):
            return deepcopy(self.images[route[len('/v1.45/images/'):-len('/json')]])
        cid = route.split('/')[3]
        if route.endswith('/json'):
            return deepcopy(self.containers[cid])
        if route.endswith('/archive'):
            filename = parse_qs(urlsplit(path).query)['path'][0].split('/')[-1]
            return managed_archive(filename, self.managed_files.get((cid, filename), b'fixed synthetic managed file'))
        raise AssertionError('Read route refused')

    def write(self, method, path, body):
        self.writes.append((method, path, deepcopy(body)))
        if self.on_write:
            outcome = self.on_write(method, path, body)
            if outcome is not None:
                return outcome
        route = urlsplit(path).path
        if method == 'POST' and route == '/v1.45/containers/create':
            self.sequence += 1
            cid = format(self.sequence, '064x')
            name = parse_qs(urlsplit(path).query)['name'][0]
            self.containers[cid] = self.inspect(cid, name, body, running=False)
            return 201, dict(Id=cid, Warnings=[])
        cid = route.split('/')[3]
        if method == 'POST' and route.endswith('/stop'):
            self.containers[cid]['State'].update(Running=False, Pid=0, Status='exited')
        elif method == 'DELETE' and route == '/v1.45/containers/' + cid:
            assert parse_qs(urlsplit(path).query) == dict(force=['false'], v=['false'])
            assert not self.containers[cid]['State']['Running']
            del self.containers[cid]
        elif method == 'POST' and route.endswith('/start'):
            self.containers[cid]['State'].update(Running=True, Pid=234, Status='running',
                                                 StartedAt='2026-02-01T00:00:00Z')
        else:
            raise AssertionError('Mutation route refused')
        return 204, None


class DeploymentExecuteTests(unittest.TestCase):
    def setUp(self):
        self.fixture = planning.DeploymentPrepareTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.docker = MutableDocker()
        p = runtime.RuntimePolicy(endpoint='https://localhost:2376', server_certificate_sha256='d' * 64,
                                  daemon_id=self.docker.daemon_id, repository='fixture/example',
                                  environment='staging', target='staging-cluster', production=False,
                                  project='fixture', components=('web', 'api'),
                                  catalog_json=runtime.canonical(dict(schemaVersion=1, images=self.docker.entries)),
                                  specifications_json=recipes.specifications_json(tuple(self.docker.specs.values())))
        reader = runtime.DockerTLSClient(p, ca_file=Path('unused'), cert_file=Path('unused'),
                                         key_file=Path('unused'), transport=self.docker.read)
        self.collector = runtime.TrustedDockerCollector(p, reader)
        self.policy = backend.ExecutionPolicy(p, 'a' * 64)
        self.client = backend.DockerMutationClient(self.policy, ca_file=Path('unused'), cert_file=Path('unused'),
                                                   key_file=Path('unused'), transport=self.docker.write)
        self.engine = backend.DockerExecutor(self.policy, self.client, self.collector)
        self.observation = self.collector.collect()
        self.approval = Approval()
        self.prepare()

    def desired(self, digit):
        entry = next(e for e in self.docker.entries if e['component'] == 'web' and e['imageId'].endswith(digit * 64))
        spec = self.docker.specs[('web', entry['imageId'])]
        return dict(name='web', sourceSha=entry['sourceSha'], artifact=deepcopy(entry['artifact']),
                    configurationDigest=spec.configuration_digest(), migrationVersion=None)

    def prepare(self, digit='b', *, operation='deployment-deploy', rollback_target=None):
        self.fixture.current = self.observation.snapshot()
        self.fixture.target['components'] = [self.desired(digit)]
        self.fixture.sync_inputs()
        self.plan = self.fixture.prepare()
        self.assertEqual(self.plan['result'], 'prepared', self.plan['blockers'])
        self.operation, self.history = operation, rollback_target
        self.intent = self.engine.prepare(self.root, self.plan, operation, observation=self.observation,
                                          rollback_target=rollback_target)

    def authorize(self, *, intent=True):
        kwargs = dict(collector=self.collector, observation=self.observation, rollback_target=self.history,
                      execution_intent=self.intent if intent else None)
        self.request = sdk.build_request(self.root, self.plan, self.operation, repository_slug='fixture/example',
                                         repository_id=123, expires_at=(sdk.clock() + timedelta(minutes=20)).isoformat(),
                                         **kwargs)
        return sdk.authorize(self.root, self.plan, self.request, approval=self.approval, **kwargs)

    def execute(self):
        return self.engine.execute(self.root, self.authorize(), self.intent)

    def audits(self):
        return [json.loads(path.read_text()) for path in (self.root / sdk.RECORDS).glob('execution-*.json')]

    def test_unselected_managed_file_drift_stops_before_next_write(self):
        permit = self.authorize()
        def change(method, path, body):
            if '/containers/create?' in path:
                self.docker.managed_files[(API, 'hosts')] = b'changed after authorization'
        self.docker.on_write = change
        result = self.engine.execute(self.root, permit, self.intent)
        self.assertEqual(len(self.docker.writes), 1)
        self.assertEqual(result['status'], 'executed-unverified')
        self.assertTrue(result['reconcileRequired'])
        self.assertTrue(self.docker.containers[OLD]['State']['Running'])

    def test_delayed_concurrent_replay_preserves_completed_journal(self):
        permit = self.authorize()
        ready, finished = threading.Event(), threading.Event()
        errors = []
        original = backend.DockerExecutor._validate_intent
        def delayed(engine, *args, **kwargs):
            original(engine, *args, **kwargs)
            if engine is self.engine and threading.current_thread().name == 'delayed-replay':
                ready.set()
                if not finished.wait(120):
                    raise AssertionError('Replay coordination timed out')
        def replay():
            try:
                self.engine.execute(self.root, permit, self.intent)
            except Exception as error:
                errors.append(error)
        with mock.patch.object(backend.DockerExecutor, '_validate_intent', new=delayed):
            thread = threading.Thread(target=replay, name='delayed-replay')
            thread.start()
            try:
                self.assertTrue(ready.wait(30))
                result = self.engine.execute(self.root, permit, self.intent)
                self.assertEqual(result['status'], 'executed-verified')
                path, = (self.root / sdk.RECORDS).glob('execution-*.json')
                evidence = path.read_bytes()
            finally:
                finished.set()
                thread.join(30)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertEqual(path.read_bytes(), evidence)
        self.assertEqual(len(self.docker.writes), 4)

    def test_expired_send_budget_refuses_before_dispatch(self):
        for deadline in (backend.time.monotonic() - 1, float('nan')):
            with self.subTest(deadline=deadline), self.assertRaises(backend.ExecutionError) as caught:
                self.client.start(OLD, before_send=lambda: deadline)
            self.assertFalse(caught.exception.may_have_mutated)
        self.assertEqual(self.docker.writes, [])

    def test_actual_issuance_deploy_then_fresh_rollback_preserves_api_instance(self):
        history = self.observation
        api = deepcopy(self.docker.containers[API])
        result = self.execute()
        self.assertEqual(result['status'], 'executed-verified', result)
        self.assertFalse(result['productionReady'])
        self.assertEqual(result['verification']['deployment'], 'verified')
        self.assertEqual(result['verification']['health'], 'unknown')
        self.assertNotEqual(result['runtimeVersion'], result['declaredVersion'])
        self.assertIs(self.collector.validate(result['observation']), result['observation'])
        self.assertEqual(self.docker.containers[API], api)
        self.assertNotIn(OLD, self.docker.containers)
        self.assertEqual([v[0] for v in self.docker.writes], ['POST', 'POST', 'DELETE', 'POST'])
        self.assertTrue(self.docker.writes[1][1].endswith('/' + OLD + '/stop?t=10'))
        self.assertTrue(self.docker.writes[2][1].endswith('/' + OLD + '?force=false&v=false'))
        self.assertNotIn(SECRET, json.dumps(self.audits()))
        self.observation = result['observation']
        self.prepare('a', operation='deployment-rollback', rollback_target=history)
        rollback = self.execute()
        self.assertEqual(rollback['status'], 'executed-verified', rollback)
        self.assertEqual(rollback['verification']['rollback'], 'verified')
        self.assertEqual(rollback['observation'].snapshot()['components'], history.snapshot()['components'])
        self.assertEqual(self.docker.containers[API], api)
        self.assertEqual(len(self.docker.writes), 8)
        self.assertEqual(self.approval.calls.count('consume'), 2)

    def test_authorization_only_permit_cannot_write(self):
        permit = self.authorize(intent=False)
        with self.assertRaisesRegex(backend.ExecutionError, 'binding-mismatch'):
            self.engine.execute(self.root, permit, self.intent)
        self.assertEqual(self.docker.writes, [])

    def test_intent_frozen_copied_exported_and_other_engine_rejected(self):
        with self.assertRaises(FrozenInstanceError):
            self.intent.binding_json = '{}'
        for forged in (replace(self.intent), json.loads(self.intent.binding_json)):
            with self.assertRaises((backend.ExecutionError, AttributeError)):
                if type(forged) is backend.ExecutionIntent:
                    forged.validate(self.root, self.plan, self.operation, self.collector, self.observation)
                else:
                    self.engine.execute(self.root, {}, forged)
        other = backend.DockerExecutor(self.policy, self.client, self.collector)
        with self.assertRaises(backend.ExecutionError):
            other.execute(self.root, self.authorize(), self.intent)
        self.assertEqual(self.docker.writes, [])

    def test_replay_and_regrant_same_intent_rejected(self):
        permit = self.authorize()
        self.assertEqual(self.engine.execute(self.root, permit, self.intent)['status'], 'executed-verified')
        with self.assertRaises(backend.ExecutionError):
            self.engine.execute(self.root, permit, self.intent)
        with self.assertRaises(ValueError):
            self.authorize()
        self.assertEqual(len(self.docker.writes), 4)

    def test_partial_mapping_cannot_select_two_components(self):
        self.fixture.target['components'].append(self.observation.snapshot()['components'][0])
        self.fixture.sync_inputs()
        plan = self.fixture.prepare()
        with self.assertRaisesRegex(backend.ExecutionError, 'exactly-one'):
            self.engine.prepare(self.root, plan, self.operation, observation=self.observation)

    def test_plan_configuration_digest_is_not_spec_authority(self):
        self.fixture.target['components'][0]['configurationDigest'] = 'sha256:' + '9' * 64
        self.fixture.sync_inputs()
        plan = self.fixture.prepare()
        with self.assertRaisesRegex(backend.ExecutionError, 'specification-unverified'):
            self.engine.prepare(self.root, plan, self.operation, observation=self.observation)

    def test_actual_image_platform_and_config_checked_in_prepare(self):
        image = self.docker.images['sha256:' + 'b' * 64]
        for key, value in (('Os', 'windows'), ('Architecture', 'arm64'), ('Id', 'sha256:' + '9' * 64)):
            before = image[key]
            image[key] = value
            with self.subTest(key=key), self.assertRaises(backend.ExecutionError):
                self.engine.prepare(self.root, self.plan, self.operation, observation=self.observation)
            image[key] = before
        image['Config']['Cmd'] = ['/different-program']
        with self.assertRaisesRegex(backend.ExecutionError, 'image-specification-mismatch'):
            self.engine.prepare(self.root, self.plan, self.operation, observation=self.observation)
        self.assertEqual(self.docker.writes, [])

    def test_changed_catalog_source_cannot_be_borrowed_for_desired_artifact(self):
        self.fixture.target['components'][0]['sourceSha'] = '9' * 40
        self.fixture.target['components'][0]['artifact']['buildSourceSha'] = '9' * 40
        self.fixture.sync_inputs()
        with self.assertRaisesRegex(backend.ExecutionError, 'image-catalog-unverified'):
            self.engine.prepare(self.root, self.fixture.prepare(), self.operation, observation=self.observation)

    def test_guard_after_create_rejects_unselected_drift_without_stop_or_cleanup(self):
        original = self.docker.write
        def drift(method, path, body):
            outcome = original(method, path, body)
            if '/create?' in path:
                self.docker.containers[API]['Config']['Env'].append('DRIFT=1')
            return outcome
        self.client._transport = drift
        result = self.execute()
        self.assertEqual(result['status'], 'executed-unverified')
        self.assertEqual(result['failureCode'], 'baseline-container-drift')
        self.assertTrue(result['reconcileRequired'])
        self.assertEqual(len(self.docker.writes), 1)
        self.assertTrue(self.docker.containers[OLD]['State']['Running'])
        self.assertEqual(len(self.docker.containers), 3)

    def test_create_response_lost_after_mutation_is_terminal_unknown(self):
        original = self.docker.write
        def lose(method, path, body):
            original(method, path, body)
            raise TimeoutError(SECRET)
        self.client._transport = lose
        result = self.execute()
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['execution'], 'unknown')
        self.assertTrue(result['reconcileRequired'])
        self.assertEqual(len(self.docker.writes), 1)
        self.assertTrue(self.docker.containers[OLD]['State']['Running'])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(result['resourceName'], json.loads(self.intent.binding_json)['resourceName'])

    def test_each_interrupted_action_never_retries_or_rolls_back(self):
        # Each subcase owns a separate synthetic repo/collector/permit.
        for fail_at in (1, 2, 3, 4):
            with self.subTest(fail_at=fail_at):
                fixture = type(self)(methodName='runTest')
                fixture.setUp()
                try:
                    original = fixture.docker.write
                    def interrupt(method, path, body):
                        outcome = original(method, path, body)
                        if len(fixture.docker.writes) == fail_at:
                            raise TimeoutError(SECRET)
                        return outcome
                    fixture.client._transport = interrupt
                    result = fixture.execute()
                    self.assertEqual(result['status'], 'unknown')
                    self.assertEqual(len(fixture.docker.writes), fail_at)
                    self.assertTrue(result['reconcileRequired'])
                finally:
                    fixture.doCleanups()

    def test_guard_failure_before_any_send_is_typed_and_permit_spent(self):
        permit = self.authorize()
        def deny(runtime_check):
            raise ValueError(SECRET)
        with mock.patch.object(permit, 'guard_for_execution', side_effect=deny):
            result = self.engine.execute(self.root, permit, self.intent)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['failureCode'], 'execution-guard-rejected')
        self.assertFalse(result['reconcileRequired'])
        self.assertEqual(self.docker.writes, [])
        self.assertTrue(permit._claimed)
        with self.assertRaises(ValueError):
            self.authorize()

    def test_old_remove_follows_created_verified_and_stopped_old(self):
        observed = []
        def check(method, path, body):
            if method == 'DELETE':
                candidates = [c for cid, c in self.docker.containers.items() if cid not in (OLD, API)]
                self.assertEqual(len(candidates), 1)
                self.assertEqual(candidates[0]['State']['Status'], 'created')
                self.assertEqual(self.docker.containers[OLD]['State']['Status'], 'exited')
                observed.append(True)
        self.docker.on_write = check
        self.assertEqual(self.execute()['status'], 'executed-verified')
        self.assertEqual(observed, [True])

    def test_changed_candidate_labels_or_spec_never_stop_old(self):
        original = self.docker.write
        def drift(method, path, body):
            outcome = original(method, path, body)
            if '/create?' in path:
                self.docker.containers[outcome[1]['Id']]['Config']['Labels'][backend.EXECUTION_LABEL] = 'foreign'
            return outcome
        self.client._transport = drift
        result = self.execute()
        self.assertEqual(result['failureCode'], 'candidate-container-unverified')
        self.assertEqual(len(self.docker.writes), 1)

    def test_daemon_identity_drift_blocks_followup(self):
        original = self.docker.write
        def drift(method, path, body):
            outcome = original(method, path, body)
            self.docker.daemon_id = 'different-daemon'
            return outcome
        self.client._transport = drift
        result = self.execute()
        self.assertEqual(result['failureCode'], 'daemon-identity-changed')
        self.assertEqual(len(self.docker.writes), 1)

    def test_foreign_extra_container_blocks_followup(self):
        original = self.docker.write
        def drift(method, path, body):
            outcome = original(method, path, body)
            extra = deepcopy(self.docker.containers[API])
            extra['Id'] = '9' * 64
            self.docker.containers[extra['Id']] = extra
            return outcome
        self.client._transport = drift
        result = self.execute()
        self.assertEqual(result['failureCode'], 'project-inventory-changed')
        self.assertEqual(len(self.docker.writes), 1)

    def test_old_restart_between_stop_and_remove_blocks_remove(self):
        original = self.docker.write
        def drift(method, path, body):
            outcome = original(method, path, body)
            if '/stop?' in path:
                self.docker.containers[OLD]['State']['StartedAt'] = '2026-03-01T00:00:00Z'
            return outcome
        self.client._transport = drift
        result = self.execute()
        self.assertEqual(result['failureCode'], 'old-container-changed')
        self.assertEqual(len(self.docker.writes), 2)
        self.assertIn(OLD, self.docker.containers)

    def test_root_change_during_last_runtime_read_blocks_next_write(self):
        permit = self.authorize()
        original = self.engine._stage
        candidate_checks = 0
        def drift(record, stage, new_id, deadline):
            nonlocal candidate_checks
            original(record, stage, new_id, deadline)
            if stage == 1:
                candidate_checks += 1
                if candidate_checks == 2:
                    path = self.root / 'workflow.config.json'
                    path.write_text(path.read_text() + '\n')
        with mock.patch.object(self.engine, '_stage', side_effect=drift):
            result = self.engine.execute(self.root, permit, self.intent)
        self.assertEqual(result['status'], 'executed-unverified')
        self.assertEqual(len(self.docker.writes), 1)
        self.assertEqual(candidate_checks, 2)
        self.assertTrue(self.docker.containers[OLD]['State']['Running'])

    def test_http_failure_is_ambiguous_even_if_fake_did_not_mutate(self):
        self.docker.on_write = lambda *_: (403, dict(message=SECRET))
        result = self.execute()
        self.assertEqual(result['status'], 'unknown')
        self.assertTrue(result['reconcileRequired'])
        self.assertEqual(len(self.docker.writes), 1)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_journal_exists_before_first_dispatch(self):
        def check(*_):
            audit, = self.audits()
            self.assertEqual(audit['actions'][-1]['status'], 'dispatch-attempted')
            self.assertTrue(audit['authorizationConsumed'])
        self.docker.on_write = check
        self.assertEqual(self.execute()['status'], 'executed-verified')

    def test_drift_during_final_authority_guard_leaves_executed_unverified(self):
        original = self.approval.guard
        def guard(request):
            original(request)
            if len(self.docker.writes) == 4:
                self.docker.containers[API]['State']['Pid'] += 1
        self.approval.guard = guard
        result = self.execute()
        self.assertEqual(result['status'], 'executed-unverified')
        self.assertEqual(result['execution'], 'performed')
        self.assertTrue(result['reconcileRequired'])
        self.assertNotIn('observation', result)

    def test_prepare_requires_full_spec_policy_and_exact_collector(self):
        with self.assertRaises(backend.ExecutionError):
            backend.ExecutionPolicy(replace(self.policy.runtime_policy, specifications_json=None), 'a' * 64)
        with self.assertRaises(backend.ExecutionError):
            backend.DockerExecutor(replace(self.policy, stop_timeout=11), self.client, self.collector)

    def test_client_allowlists_ids_and_exact_trusted_create_payload(self):
        for cid in ('short', OLD + '/../../images', None):
            for action in ('start', 'stop', 'remove'):
                with self.subTest(cid=cid, action=action), self.assertRaises(backend.ExecutionError) as caught:
                    getattr(self.client, action)(cid, before_send=lambda: self.fail('guard called'))
                self.assertFalse(caught.exception.may_have_mutated)
        body = self.docker.specs[('web', 'sha256:' + 'b' * 64)].to_create('fixture', '1' * 64)
        body['HostConfig']['Privileged'] = True
        with self.assertRaisesRegex(backend.ExecutionError, 'payload-rejected'):
            self.client.create('dwf-' + '1' * 64, body, before_send=lambda: self.fail('guard called'))
        self.assertEqual(self.docker.writes, [])

    def test_pin_is_verified_before_guard_and_request(self):
        cert = b'synthetic-server-DER'
        p = replace(self.policy, runtime_policy=replace(self.policy.runtime_policy,
                    server_certificate_sha256=hashlib.sha256(cert).hexdigest()))
        with mock.patch.object(Path, 'read_text', return_value='-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----'), \
                mock.patch.object(ssl, 'PEM_cert_to_DER_cert', return_value=b'client'), \
                mock.patch.object(ssl, 'create_default_context') as context, \
                mock.patch.object(backend.http.client, 'HTTPSConnection') as connection_type:
            p = replace(p, writer_certificate_sha256=hashlib.sha256(b'client').hexdigest())
            client = backend.DockerMutationClient(p, ca_file=Path('ca'), cert_file=Path('cert'), key_file=Path('key'))
            connection = connection_type.return_value
            connection.sock.getpeercert.return_value = cert
            response = connection.getresponse.return_value
            response.status = 204
            response.read1.return_value = b''
            order = []
            connection.connect.side_effect = lambda: order.append('connect')
            connection.sock.getpeercert.side_effect = lambda **_: order.append('pin') or cert
            connection.request.side_effect = lambda *_a, **_k: order.append('send')
            client.stop(OLD, before_send=lambda: order.append('guard'))
            self.assertEqual(order, ['connect', 'pin', 'guard', 'send'])
            self.assertTrue(context.return_value.check_hostname)
            self.assertEqual(context.return_value.verify_mode, ssl.CERT_REQUIRED)
            connection.request.reset_mock()
            connection.sock.getpeercert.side_effect = lambda **_: b'wrong'
            guard = mock.Mock()
            with self.assertRaises(backend.ExecutionError) as caught:
                client.stop(OLD, before_send=guard)
            self.assertFalse(caught.exception.may_have_mutated)
            guard.assert_not_called()
            connection.request.assert_not_called()

    def test_wrong_writer_principal_is_rejected_before_connect(self):
        with mock.patch.object(Path, 'read_text', return_value='-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----'), \
                mock.patch.object(ssl, 'PEM_cert_to_DER_cert', return_value=b'wrong'), \
                mock.patch.object(backend.http.client, 'HTTPSConnection') as connection:
            with self.assertRaisesRegex(backend.ExecutionError, 'credentials-rejected'):
                backend.DockerMutationClient(self.policy, ca_file=Path('ca'), cert_file=Path('cert'), key_file=Path('key'))
            connection.assert_not_called()

    def test_request_failure_timing_before_connect_and_after_send(self):
        guard = mock.Mock(side_effect=ValueError(SECRET))
        with self.assertRaises(backend.ExecutionError) as caught:
            self.client.stop(OLD, before_send=guard)
        self.assertFalse(caught.exception.may_have_mutated)
        self.assertEqual(caught.exception.code, 'execution-guard-rejected')
        self.assertEqual(self.docker.writes, [])
        self.client._transport = lambda *_: (_ for _ in ()).throw(TimeoutError(SECRET))
        with self.assertRaises(backend.ExecutionError) as caught:
            self.client.stop(OLD, before_send=lambda: None)
        self.assertTrue(caught.exception.may_have_mutated)
        self.assertNotIn(SECRET, str(caught.exception))
        self.client._transport = lambda *_: (_ for _ in ()).throw(backend.ExecutionError('transport-failure'))
        with self.assertRaises(backend.ExecutionError) as caught:
            self.client.stop(OLD, before_send=lambda: None)
        self.assertTrue(caught.exception.may_have_mutated)

    def test_internal_writer_route_allowlist_rejects_unsafe_operations(self):
        for method, path in (('POST', '/v1.45/images/create'), ('POST', '/v1.45/containers/' + OLD + '/exec'),
                             ('DELETE', '/v1.45/containers/' + OLD + '?force=true&v=true')):
            with self.assertRaisesRegex(backend.ExecutionError, 'route-rejected'):
                self.client._write(method, path, None, lambda: self.fail('guard called'), 204)
        self.assertEqual(self.docker.writes, [])

    def test_cli_has_no_local_execution_authority(self):
        for action, code in (('status', 0), ('execute', 1)):
            result = subprocess.run([sys.executable, '-I', '-B', str(Path(backend.__file__)), action],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertFalse(json.loads(result.stdout)['executionAvailable'])


@unittest.skipUnless(shutil.which('openssl'), 'openssl required for local mTLS fixture')
class LocalMutationTLSTests(unittest.TestCase):
    """Real sockets and certificates, with a purely synthetic server daemon."""
    @classmethod
    def setUpClass(cls):
        from tests.test_deployment_runtime import LocalTLSRuntimeTests
        LocalTLSRuntimeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.docker = MutableDocker()
        self.http_calls = []
        self.header_drip = False
        test = self
        daemon, calls = self.docker, self.http_calls
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                calls.append(self.path)
                length = int(self.headers.get('Content-Length', '0'))
                body = json.loads(self.rfile.read(length)) if length else None
                status, value = daemon.write('POST', self.path, body)
                if test.header_drip:
                    for byte in b'HTTP/1.1 204 No Content\r\nX-Drip: ' + b'x' * 1000 + b'\r\n\r\n':
                        try:
                            self.connection.sendall(bytes([byte]))
                        except OSError:
                            break
                        time.sleep(0.02)
                    self.close_connection = True
                    return
                raw = json.dumps(value).encode() if value is not None else b''
                self.send_response(status)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.directory / 'server.pem'), str(self.directory / 'server.key'))
        context.load_verify_locations(str(self.directory / 'ca.pem'))
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            server = ThreadingHTTPServer(('localhost', 0), Handler)
        except OSError as error:
            if error.errno in (errno.EPERM, errno.EACCES):
                self.skipTest('Sandbox denies local loopback listeners; real mTLS unverified here')
            raise
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.addCleanup(stop)
        def pin(name):
            return hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory / (name + '.pem')).read_text())).hexdigest()
        p = runtime.RuntimePolicy(endpoint='https://localhost:' + str(server.server_port),
                                  server_certificate_sha256=pin('server'), daemon_id=self.docker.daemon_id,
                                  repository='fixture/example', environment='staging', target='fixture',
                                  production=False, project='fixture', components=('web', 'api'),
                                  catalog_json=runtime.canonical(dict(schemaVersion=1, images=self.docker.entries)),
                                  specifications_json=recipes.specifications_json(tuple(self.docker.specs.values())))
        self.policy = backend.ExecutionPolicy(p, pin('client'))

    def client(self, policy=None):
        return backend.DockerMutationClient(policy or self.policy, ca_file=self.directory / 'ca.pem',
                                            cert_file=self.directory / 'client.pem', key_file=self.directory / 'client.key')

    def test_real_mtls_create_stop_and_start(self):
        client = self.client()
        guards = []
        body = self.docker.specs[('web', 'sha256:' + 'b' * 64)].to_create('fixture', '1' * 64)
        response = client.create('dwf-' + '1' * 64, body, before_send=lambda: guards.append('create'))
        self.assertIn(response['Id'], self.docker.containers)
        client.stop(OLD, before_send=lambda: guards.append('stop'))
        client.start(response['Id'], before_send=lambda: guards.append('start'))
        self.assertEqual(guards, ['create', 'stop', 'start'])
        self.assertEqual(len(self.http_calls), 3)
        self.assertTrue(self.docker.containers[response['Id']]['State']['Running'])

    def test_real_peer_pin_and_hostname_precede_guard_and_write(self):
        for p in (replace(self.policy, runtime_policy=replace(self.policy.runtime_policy,
                   server_certificate_sha256='0' * 64)),
                  replace(self.policy, runtime_policy=replace(self.policy.runtime_policy,
                   endpoint=self.policy.runtime_policy.endpoint.replace('localhost', '127.0.0.1')))):
            guard = mock.Mock()
            with self.assertRaises(backend.ExecutionError) as caught:
                self.client(p).stop(OLD, before_send=guard)
            self.assertFalse(caught.exception.may_have_mutated)
            guard.assert_not_called()
        self.assertEqual(self.http_calls, [])

    def test_real_guard_rejection_sends_no_http_request(self):
        with self.assertRaises(backend.ExecutionError) as caught:
            self.client().stop(OLD, before_send=lambda: (_ for _ in ()).throw(ValueError(SECRET)))
        self.assertFalse(caught.exception.may_have_mutated)
        self.assertEqual(self.http_calls, [])

    def test_trickled_headers_respect_total_budget_without_retry(self):
        self.header_drip = True
        # Loading Windows trust roots can take seconds. The budget begins at
        # the guarded send boundary, not during client/certificate setup.
        client = self.client()
        started = []
        def send_budget():
            started.append(time.monotonic())
            return started[0] + 0.15
        with self.assertRaises(backend.ExecutionError) as caught:
            client.start(OLD, before_send=send_budget)
        self.assertTrue(caught.exception.may_have_mutated)
        self.assertEqual(len(started), 1)
        self.assertLess(time.monotonic() - started[0], 2)
        self.assertEqual(len(self.http_calls), 1)


if __name__ == '__main__':
    unittest.main()
