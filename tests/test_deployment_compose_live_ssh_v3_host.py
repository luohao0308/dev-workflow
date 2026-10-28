"""Private synthetic captures; no SSH, Docker or GitHub operations."""
from copy import deepcopy
import hashlib
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
                       'ClearAllForwardings=yes','PermitLocalCommand=no','BatchMode=yes'):
            self.assertIn(option,argv)
        for alias in ('-oProxyCommand=x','host; echo secret','host x',''):
            with self.assertRaises(ValueError):live.ssh_argv(alias,'a'*64,'b'*40)


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
    return unittest.TestSuite(cls(name) for cls in (LoaderTests, CapsuleTests)
        for name in cls.__dict__ if name.startswith('test_'))
