"""Private registry namespace and exact content checks, no network calls."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
import hashlib
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
for directory in ('scripts','packs/deployment/scripts','core/scripts','tests/support'):
    sys.path.insert(0,str(ROOT/directory))
import deployment_compose_registry_enrollment_probe as registry


class RegistryEnrollmentTests(unittest.TestCase):
    def test_command_binds_only_owned_socket_namespace_and_fixed_tls_reference(self):
        root=Path('/var/tmp/dw-engine-'+'a'*16)
        cmd=registry.pull_command(root,root.name)
        self.assertEqual(cmd[1:5],['--address',str(root/'containerd.sock'),'--namespace',root.name])
        self.assertIn('--local',cmd);self.assertEqual(cmd[-1],registry.REFERENCE)
        for forbidden in ('--skip-verify','--plain-http','--user','--refresh','--http-dump','--http-trace'):
            self.assertNotIn(forbidden,cmd)
        for path,namespace in ((Path('/run'), 'moby'),(root,'moby'),(Path('/var/tmp/dw-engine-../bad'),'bad')):
            with self.assertRaises(ValueError):registry.pull_command(path,namespace)

    def test_enrollment_requires_live_full_reference_and_exact_content(self):
        before={'Id':'sha256:'+'b'*64,'Os':'linux','Architecture':'amd64','Config':{'Env':['A=fixed']},
                'RootFS':{'Type':'layers','Layers':['sha256:'+'c'*64]},'RepoDigests':[]}
        after=dict(before,RepoDigests=[registry.REFERENCE])
        result=registry.verify_enrollment(before,after)
        self.assertEqual(result,after);self.assertIsNot(result,after)
        for field,value in [('RepoDigests',[]),('RepoDigests',['python@sha256:'+'c'*64]),
                            ('Id','sha256:'+'d'*64),('Config',{'Env':['A=changed']}),
                            ('RootFS',{'Layers':[]}),('Architecture','arm64')]:
            changed=deepcopy(after);changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):registry.verify_enrollment(before,changed)


    def test_scope_cleanup_uses_scope_shape_without_service_main_pid(self):
        group='/system.slice/dw-engine-'+'a'*16+'-registry-pull.scope'
        # Actual absent-scope systemctl shape: no MainPID or Leader property.
        absent={'ControlGroup':'','LoadState':'not-found','ActiveState':'inactive'}
        self.assertTrue(registry.scope_stopped(absent,query_returncode=0,expected_group=group,cgroup_empty=True))
        inactive={'ControlGroup':group,'LoadState':'loaded','ActiveState':'inactive'}
        self.assertTrue(registry.scope_stopped(inactive,query_returncode=0,expected_group=group,cgroup_empty=True))
        for fields,code,empty in (({},1,True),(absent,2,True),(inactive,1,True),
                                  (inactive,0,False),(dict(inactive,ActiveState='active'),0,True),
                                  (dict(inactive,ControlGroup='/other.slice/foreign.scope'),0,True)):
            with self.subTest(fields=fields,code=code,empty=empty):
                self.assertFalse(registry.scope_stopped(fields,query_returncode=code,expected_group=group,cgroup_empty=empty))


    def test_origin_requires_real_manifest_bytes_hash_and_disables_proxy_redirects(self):
        manifest=b'{"schemaVersion":2}'
        digest='sha256:'+hashlib.sha256(manifest).hexdigest()
        def response(raw,url):
            result=Mock();result.status=200;result.geturl.return_value=url;result.read.return_value=raw
            result.__enter__=Mock(return_value=result);result.__exit__=Mock(return_value=False)
            return result
        opener=Mock()
        def open_response(request,**kwargs):
            if type(request) is str:return response(b'{"token":"public-unit-token"}',request)
            self.assertEqual(request.headers['Authorization'],'Bearer public-unit-token')
            return response(manifest,request.full_url)
        opener.open.side_effect=open_response
        with patch.object(registry,'IMAGE','python@'+digest),patch.object(registry.urllib.request,'build_opener',return_value=opener) as build:
            result=registry.verify_registry_manifest()
            self.assertEqual(result['registryManifestDigest'],digest)
            self.assertTrue(result['registryTLSOriginVerified'])
            self.assertEqual(build.call_args.args[0].proxies,{})
            self.assertIsInstance(build.call_args.args[1],registry.NoRedirect)
        with self.assertRaises(ValueError):registry.NoRedirect().redirect_request(None,None,302,'',{},'https://other.test')
        def tampered(request,**kwargs):
            if type(request) is str:return response(b'{"token":"public-unit-token"}',request)
            return response(b'wrong-manifest',request.full_url)
        opener.open.side_effect=tampered
        with patch.object(registry,'IMAGE','python@'+digest),patch.object(registry.urllib.request,'build_opener',return_value=opener),self.assertRaisesRegex(ValueError,'registry-origin-manifest-not-verified'):
            registry.verify_registry_manifest()


    def test_registry_selection_is_explicit_and_never_silent_fallback(self):
        root=Path('/var/tmp/dw-engine-'+'a'*16)
        ecr=registry.pull_command(root,root.name,registry='ecr-public')
        self.assertEqual(ecr[-1],'public.ecr.aws/docker/library/'+registry.IMAGE)
        self.assertEqual(registry.pull_command(root,root.name)[-1],registry.REFERENCE)
        for mode in ('other','http://untrusted',None,True):
            with self.assertRaisesRegex(ValueError,'registry-source-policy-rejected'):
                registry.pull_command(root,root.name,registry=mode)


    def test_admission_credits_only_smaller_already_resident_anon(self):
        mib=1024*1024
        self.assertEqual(registry.registry_capacity_required(768*mib,100*mib,120*mib),1116*mib)
        self.assertEqual(registry.registry_capacity_required(768*mib,0,0),1216*mib)
        self.assertEqual(registry.registry_capacity_required(768*mib,120*mib,100*mib),1116*mib)
        for values in ((512*mib,0,0),(768*mib,-1,0),(768*mib,769*mib,0),(768*mib,True,0)):
            with self.assertRaises(ValueError):registry.registry_capacity_required(*values)


if __name__=='__main__':unittest.main()
