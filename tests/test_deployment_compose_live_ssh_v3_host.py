"""Private synthetic captures; no SSH, Docker or GitHub operations."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import time
import hashlib
import json
import os
import socket
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.test_compose_profile3_prepare_fixture import CurrentPreparationUnixTests
import deployment_compose_live_ssh_v3_host as live
from deployment_compose_live_worker_v3_host import private_capsule, private_json


class LoaderTests(unittest.TestCase):
    def test_fixed_loader_has_only_live_entry(self):
        code=live.live_bootstrap('a'*64,'b'*40)
        compile(code,'<fixed-live-loader>','exec')
        self.assertIn('from deployment_compose_live_worker_v3_host import run',code)
        self.assertIn('run(config,sys.stdin.buffer,sys.stdout.buffer)',code)
        self.assertNotIn('_remote_main',code)
        self.assertIn('2097152',code)
        self.assertIn('16777216',code)
        self.assertIn('4*1024*1024',code)
        self.assertNotIn('result=result',code)

    def test_strict_transport_and_alias(self):
        argv=live.ssh_argv('linux-test','a'*64,'b'*40)
        for option in ('StrictHostKeyChecking=yes','ForwardAgent=no','ForwardX11=no',
                       'ClearAllForwardings=yes','PermitLocalCommand=no','BatchMode=yes',
                       'ServerAliveInterval=15','ServerAliveCountMax=3'):
            self.assertIn(option,argv)
        for alias in ('-oProxyCommand=x','host; echo secret','host x',''):
            with self.assertRaises(ValueError):live.ssh_argv(alias,'a'*64,'b'*40)


class RpcDiagnosticTests(unittest.TestCase):
    def test_review_close_preserves_active_failure_and_reports_own_failure(self):
        original = ValueError('original authorization rejection')
        cleanup = RuntimeError('cleanup failure')
        review = SimpleNamespace(close=unittest.mock.Mock(side_effect=cleanup))
        with self.assertRaises(ValueError) as caught:
            try:
                raise original
            finally:
                live._close_review(review)
        self.assertIs(caught.exception, original)
        with self.assertRaises(RuntimeError) as caught:
            live._close_review(review)
        self.assertIs(caught.exception, cleanup)
        self.assertEqual(review.close.call_count, 2)
        live._close_review(SimpleNamespace())

    def test_fixed_authorization_identifiers_survive_without_sensitive_messages(self):
        from release_execute import AuthorizationUnavailable
        try:
            try:
                error = AuthorizationUnavailable('TOKEN=secret-provider-body')
                error.failure_code = 'authorization-0123456789ab'
                error.mismatch_fields = ('aud', 'sub', 'TOKEN=secret', 'secret_identifier')
                raise error
            except AuthorizationUnavailable:
                raise ValueError('SECRET_ENV=private') from None
        except ValueError as wrapped:
            result = live._rpc_failure_diagnostic('witness', 'append_event', wrapped, 'open')
        self.assertEqual(result['eventKind'], 'open')
        self.assertEqual(result['causeTypes'], ['ValueError', 'AuthorizationUnavailable'])
        self.assertEqual(result['failureCodes'], ['authorization-0123456789ab'])
        self.assertEqual(result['mismatchFields'], ['aud', 'sub'])
        self.assertNotIn('secret', json.dumps(result).lower())

    def test_untrusted_identifiers_cycles_and_long_chains_are_bounded(self):
        error = type('SECRET_EXCEPTION_NAME', (ValueError,), {})('private payload')
        error.failure_code = 'authorization-secret-not-a-fixed-code'
        error.mismatch_fields = ['private_identifier']
        error.__context__ = error
        result = live._rpc_failure_diagnostic(['secret'], {'secret': True}, error, 'secret-kind')
        self.assertEqual(result, dict(stage='authorize-rpc', service='unknown', method='unknown',
                                     eventKind='unknown', causeTypes=['unknown'], failureCodes=[], mismatchFields=[]))
        for _ in range(10):
            outer = ValueError('secret'); outer.__context__ = error; error = outer
        self.assertEqual(len(live._rpc_failure_diagnostic('intent', 'wrong-secret', error)['causeTypes']), 5)

    @unittest.skipUnless(os.name == 'posix', 'private mode boundary is POSIX-only')
    def test_rpc_failure_is_exclusive_private_and_never_retried_or_replaced(self):
        error = ValueError('never serialize token or key')
        admission = SimpleNamespace(authorize_rpc=unittest.mock.Mock(side_effect=error))
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            first = None
            for index in range(2):
                error.failure_code = 'authorization-' + str(index)*12
                with self.assertRaises(ValueError) as caught:
                    live._authorize_rpc(admission, 'witness', 'append_event', {'token': 'private'}, case)
                self.assertIs(caught.exception, error)
                current = (case/'rpc-failure.private.json').read_bytes()
                if first is None: first = current
                else: self.assertEqual(current, first)
            self.assertEqual(admission.authorize_rpc.call_count, 2)
            path = case/'rpc-failure.private.json'
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text())['stage'], 'authorize-rpc')
            self.assertNotIn('private', path.read_text())


class CapsuleTests(CurrentPreparationUnixTests):
    # Reuse the real TLS reader + Unix Engine double preparation fixture.
    def prepare_initial(self,bodies):
        from deployment_compose_log_probe import IMAGE
        from deployment_compose_namespaced_transition_probe import V2
        self.images[0]['RepoDigests']=['public.ecr.aws/docker/library/'+IMAGE]
        self.images[1]['RepoDigests']=['public.ecr.aws/docker/library/'+V2]
        super().prepare_initial(bodies)

    def capsule(self):
        value=private_json(private_capsule(self.session,self.session.prepared))
        hello=dict(sourceSha='b'*40,hostId='host-one',daemonId='daemon-one')
        return value,dict(hello=hello,source_sha='b'*40,ssh_alias='host-one',
            policy=SimpleNamespace(identity_hash=lambda:'c'*64),keys=self.keys,
            trusted_boot_id=self.session.whole_observation._boot,trusted_bind_digest=None)

    def test_reconstructs_private_capture(self):
        capsule,kw=self.capsule()
        bundle,request=live.verify_private_capsule(capsule,**kw)
        self.assertEqual(bundle.digest,self.session.prepared['bundle'].digest)
        self.assertEqual(request,self.session.prepared['request'])

    def test_tamper_never_reaches_dispatch(self):
        capsule,kw=self.capsule()
        for field in ('policy_hash','before_hash','after_hash','artifact_digest','observation_hash','plan_hash'):
            changed=deepcopy(capsule);changed['request'][field]='d'*64
            with self.subTest(field=field),self.assertRaises(ValueError):
                live.verify_private_capsule(changed,**kw)
        changed=deepcopy(capsule)
        changed['sourceModel']['sourceSha']='e'*40
        with self.assertRaises(ValueError):live.verify_private_capsule(changed,**kw)
        changed=deepcopy(capsule)
        changed['rawRows']['backend']['Config']['Env'].append('SECRET=changed')
        with self.assertRaises(ValueError):live.verify_private_capsule(changed,**kw)

    def test_boot_from_capsule_cannot_override_owned_pin(self):
        capsule,kw=self.capsule();capsule['observationMaterial']['boot']='e'*32
        capsule['request']['observation_hash']=live._batch(b'dev-workflow:compose-host-observation:v1\0',capsule['observationMaterial'])
        with self.assertRaises(ValueError):live.verify_private_capsule(capsule,**kw)

    def test_self_rehashed_body_still_requires_source_authentication(self):
        from deployment_compose_bundle_v3 import ExecutionBundleV3, FIELDS
        from deployment_compose_image_defaults import derive_defaults, ZERO_DEFAULTS
        capsule,kw=self.capsule()
        changed=deepcopy(capsule);value=changed['bundle']
        for kind in ('baselineCreateBody','targetCreateBody'):
            value['services'][0][kind]['Env'].append('INJECTED=1')
        ti=changed['targetInputs']['backend']
        derived=derive_defaults(ti['image'],ti['commitment'],self.keys['target'],
            **{k:ti[k] for k in ('expected_image_id','expected_registry_digest','expected_architecture')})
        rebuilt=ExecutionBundleV3({k:value[k] for k in FIELDS},
            authenticated_image_defaults={'backend':{k:derived[k] for k in ZERO_DEFAULTS}})
        changed['bundle']=rebuilt.to_dict();changed['publicReview']=rebuilt.public_review()
        changed['request']['plan_hash']=rebuilt.digest
        changed['request']['after_hash']=live.digest({'backend':value['services'][0]['targetCreateBody']})
        with self.assertRaises(ValueError):live.verify_private_capsule(changed,**kw)



@unittest.skipUnless(os.name == 'posix', 'private recovery store requires POSIX semantics')
class BatchCapsuleTests(unittest.TestCase):
    def setUp(self):
        from tests.test_deployment_compose_prepare_v3_host import fixture
        from deployment_compose_prepare_v3_host import ComposePreparationHostV3
        from deployment_compose_phase_guard_v3_host import baseline_state_bytes
        from deployment_contract_v2 import SourceIdentity, TargetIdentity
        from deployment_compose_private import commit

        source_sha = 'b' * 40
        project = 'dw-restore-' + '3' * 24
        repo = live.REPOSITORY
        source = SourceIdentity('github.com', f'https://github.com/{repo}.git',
                                live.REPOSITORY_ID, repo, source_sha)
        source_model = {'sourceSha': source_sha}
        registries = {name: f'example.com/{name}@sha256:' + char * 64
                      for name, char in (('api', '3'), ('web', '4'))}
        kw, _ = fixture(batch=True, source=source, target=TargetIdentity('compose', project, 'staging'),
                        source_model_digest=live.digest(source_model), config_key_id='profile3-config',
                        target_registries=registries)
        store = kw['recovery']._store
        self.addCleanup(store.close)
        observer = kw['whole_observer']
        by_id = observer._unit_rows
        label = 'com.docker.compose.service'
        rows = {row['Config']['Labels'][label]: row for row in by_id.values()}
        keys = {name: kw['source_inputs']['web'][field]
                for name, field in (('config', 'private_key'), ('image', 'image_key'),
                                    ('declaration', 'declaration_key'))}
        keys['target'] = kw['target_inputs']['web']['key']
        scope = observer._policy
        scope['networks'] = kw['source_inputs']['web']['network_ids']
        scope['networkAttachments'] = {service: {name: endpoint['Aliases']
                for name, endpoint in row['NetworkSettings']['Networks'].items()}
            for service, row in rows.items()}
        scope['mounts'] = {service: [dict(type=mount['Type'],
                source=mount['Name'] if mount['Type'] == 'volume' else mount['Source'],
                target=mount['Destination'], readOnly=not mount['RW']) for mount in row['Mounts']]
            for service, row in rows.items()}
        scope['volumes'] = {mount['source']: {'driver': 'local', 'options': {}}
                            for mounts in scope['mounts'].values() for mount in mounts
                            if mount['type'] == 'volume'}
        labels = {'com.docker.compose.project': project}
        resources = {f'network:{name}': dict(Name=name, Id=ident, Labels=labels)
                     for name, ident in scope['networks'].items()}
        resources.update({f'volume:{name}': dict(Name=name, Driver='local', Options={}, Labels=labels)
                          for name in scope['volumes']})
        responses = {'/v1.45/info': {'ID': kw['daemon_id']}, '/inventory': [
            dict(Id=row['Id'], Labels=row['Config']['Labels']) for row in rows.values()]}
        for service, row in rows.items():
            cid = row['Id']
            responses[f'/v1.45/containers/{cid}/json'] = row
            responses[f'/v1.45/workflow/private/{cid}'] = commit(
                project, service, live._projection(row), 'profile3-config', keys['config'])
        for name, ident in scope['networks'].items():
            responses[f'/v1.45/networks/{ident}'] = resources[f'network:{name}']
        for name in scope['volumes']:
            responses[f'/v1.45/volumes/{name}'] = resources[f'volume:{name}']
        catalog = [observer._reader.get(f'/v1.45/images/{ident}/json', deadline=time.monotonic()+10)
                   for ident in sorted(set(scope['imageIds'].values()))]
        for image in catalog:
            image['Config'] = {'Env': ['IMAGE_DEFAULT=fixture']}
            responses[f"/v1.45/images/{image['Id']}/json"] = image
        reader = SimpleNamespace(list_path='/inventory', policy=SimpleNamespace(
            private_key_id='profile3-config', bind_count=0), get=lambda path, **kw: responses[path])
        assessment, private, instances, images, _ = live._snapshot(reader, scope, time.monotonic()+10)
        self.assertEqual(assessment['reasons'], [])
        collect = observer._collect
        observer._collect = lambda *args, **kw: dict(collect(*args, **kw),
            structureDigest=assessment['structureDigest'],
            privateDigest=live._batch(b'dev-workflow:compose-private-batch:v1\0', private),
            instanceDigest=live._batch(b'dev-workflow:compose-instance-batch:v1\0', instances),
            imageCatalogDigest=live.image_catalog_digest(images))
        observation = observer.issue()
        kw['archive_reference'] = kw['recovery'].retain(observation)
        preparer = ComposePreparationHostV3(**kw)
        expires = (datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.prepared = preparer.prepare_intent(observation, observation,
                                               operation_nonce='f'*64, expires_at=expires)
        phase = dict(rows=json.loads(baseline_state_bytes(by_id)), resources=resources)
        self.session = SimpleNamespace(preparer=preparer, whole_observation=observation,
            whole_observer=observer, raw_rows=rows, source_model=source_model,
            enrolled_images=catalog, guard=SimpleNamespace(capture_phase=lambda snapshot: phase))
        self.kwargs = dict(hello=dict(sourceSha=source_sha, hostId=kw['host_id'], daemonId=kw['daemon_id']),
            source_sha=source_sha, ssh_alias=kw['host_id'], policy=SimpleNamespace(identity_hash=lambda:kw['policy_hash']),
            keys=keys, trusted_boot_id=observation._boot, trusted_bind_digest=None)
        self.registries = registries

    def capsule(self):
        return private_json(private_capsule(self.session, self.prepared))

    def verify(self, capsule, *, registries=None):
        return live.verify_batch_private_capsule(capsule, **self.kwargs,
            expected_target_registries=self.registries if registries is None else registries)

    def test_batch_round_trip_is_explicit(self):
        sent = self.capsule()
        reader, writer = socket.socketpair()
        with reader, writer, ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(live.write_frame, writer, sent, timeout=5)
            capsule = live.read_frame(reader, timeout=5)
            pending.result()
        self.assertEqual(capsule, sent)
        self.assertIn('Config', capsule['imageCatalog'][0])
        self.assertEqual(capsule['kind'], 'compose-managed-batch-capsule')
        self.assertEqual(capsule['schemaVersion'], 1)
        self.assertEqual(set(capsule['sourceFacts']), {'api', 'web'})
        bundle, request = self.verify(capsule)
        self.assertEqual(bundle.digest, self.prepared['bundle'].digest)
        self.assertEqual(request, self.prepared['request'])
        with self.assertRaises(ValueError):
            live.verify_private_capsule(capsule, **self.kwargs)

    def test_batch_requires_exact_service_material_and_target_pins(self):
        for field in ('sourceFacts', 'rawRows', 'targetInputs'):
            for mutation in ('missing', 'extra', 'swapped'):
                with self.subTest(field=field, mutation=mutation):
                    capsule = self.capsule()
                    inputs = capsule[field]
                    if mutation == 'missing':
                        inputs.pop('api')
                    elif mutation == 'extra':
                        inputs['unexpected'] = inputs['api']
                    else:
                        inputs['api'], inputs['web'] = inputs['web'], inputs['api']
                    with self.assertRaises(ValueError):
                        self.verify(capsule)
        for registries in ({'web': self.registries['web']},
                           dict(self.registries, unexpected=self.registries['api']),
                           {'api': self.registries['web'], 'web': self.registries['api']}):
            with self.subTest(registries=registries), self.assertRaises(ValueError):
                self.verify(self.capsule(), registries=registries)

    def test_batch_rejects_detached_phase_scope_and_format(self):
        for path, changed in (
            (('schemaVersion',), True),
            (('kind',), 'compose-managed-batch-capsule-v2'),
            (('phaseSnapshot', 'rows', '7'*64, 'State', 'Pid'), 456),
            (('scopePolicy', 'baselineSourceShas', 'api'), 'c'*40),
            (('scopePolicy', 'protectedConfigHmacs', 'db'), 'e'*64),
        ):
            with self.subTest(path=path):
                capsule = self.capsule()
                obj = capsule
                for key in path[:-1]:
                    obj = obj[key]
                obj[path[-1]] = changed
                with self.assertRaises(ValueError):
                    self.verify(capsule)

    def rebind_bundle(self, capsule):
        from deployment_compose_bundle_v3 import ExecutionBundleV3, FIELDS
        from deployment_compose_image_defaults import ZERO_DEFAULTS
        value = capsule['bundle']
        bundle = ExecutionBundleV3({key: value[key] for key in FIELDS},
            authenticated_image_defaults={service: ZERO_DEFAULTS for service in self.registries})
        capsule['bundle'] = bundle.to_dict()
        capsule['publicReview'] = bundle.public_review()
        capsule['request']['plan_hash'] = bundle.digest

    def test_batch_recomputes_retention_binding_after_request_rehash(self):
        capsule = self.capsule()
        capsule['bundle']['retentionBindingDigest'] = 'd'*64
        self.rebind_bundle(capsule)
        with self.assertRaises(ValueError):
            self.verify(capsule)

    def test_batch_rejects_rehashed_unhealthy_baseline(self):
        from deployment_compose_phase_guard_v3_host import baseline_state_bytes
        capsule = self.capsule()
        capsule['rawRows']['api']['State']['Health']['Status'] = 'unhealthy'
        rows = {row['Id']: row for row in capsule['rawRows'].values()}
        baseline = baseline_state_bytes(rows)
        capsule['phaseSnapshot']['rows'] = json.loads(baseline)
        capsule['bundle']['baselineStateDigest'] = hashlib.sha256(baseline).hexdigest()
        self.rebind_bundle(capsule)
        with self.assertRaises(ValueError):
            self.verify(capsule)


def load_tests(loader, tests, pattern):
    # The inherited class supplies setup/cleanup and Engine responses, while its
    # own tests remain owned and run by their original module.
    return unittest.TestSuite(cls(name) for cls in (LoaderTests, RpcDiagnosticTests, CapsuleTests, BatchCapsuleTests)
        for name in cls.__dict__ if name.startswith('test_'))
