"""Private synthetic captures; no SSH, Docker or GitHub operations."""
from copy import deepcopy
import hashlib
import json
import os
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


def load_tests(loader, tests, pattern):
    # The inherited class supplies setup/cleanup and Engine responses, while its
    # own tests remain owned and run by their original module.
    return unittest.TestSuite(cls(name) for cls in (LoaderTests, RpcDiagnosticTests, CapsuleTests)
        for name in cls.__dict__ if name.startswith('test_'))
