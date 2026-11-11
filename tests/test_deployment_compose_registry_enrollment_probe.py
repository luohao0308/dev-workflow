"""Private registry namespace and exact content checks, no network calls."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
import hashlib
import json
import os
import shutil
import socket
import uuid
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
        before={'Id':registry.IMAGE.rsplit('@',1)[1],'Os':'linux','Architecture':'amd64','Config':{'Env':['A=fixed']},
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
            result=registry.verify_registry_manifest(image_reference=registry.IMAGE)
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
            registry.verify_registry_manifest(image_reference=registry.IMAGE)


    def test_registry_selection_is_explicit_and_never_silent_fallback(self):
        root=Path('/var/tmp/dw-engine-'+'a'*16)
        ecr=registry.pull_command(root,root.name,registry='ecr-public')
        self.assertEqual(ecr[-1],'public.ecr.aws/docker/library/'+registry.IMAGE)
        self.assertEqual(registry.pull_command(root,root.name)[-1],registry.REFERENCE)
        for mode in ('other','http://untrusted',None,True):
            with self.assertRaisesRegex(ValueError,'registry-source-policy-rejected'):
                registry.pull_command(root,root.name,registry=mode)


    def test_two_fixed_references_bind_origin_command_and_image_id(self):
        root=Path('/var/tmp/dw-engine-'+'a'*16)
        for image in (registry.IMAGE,registry.V2):
            reference,_,_=registry.registry_settings('ecr-public',image_reference=image)
            self.assertEqual(reference,'public.ecr.aws/docker/library/'+image)
            command=registry.pull_command(root,root.name,registry='ecr-public',image_reference=image)
            self.assertEqual(command[-1],reference)
            before=dict(Id=image.rsplit('@',1)[1],Os='linux',Architecture='amd64',Config={},RootFS={})
            after=dict(before,RepoDigests=[reference])
            self.assertEqual(registry.verify_enrollment(before,after,registry='ecr-public',image_reference=image),after)
            wrong=dict(before,Id='sha256:'+'0'*64)
            with self.assertRaises(ValueError):
                registry.verify_enrollment(wrong,dict(after,Id=wrong['Id']),registry='ecr-public',image_reference=image)
            wrong_ref=registry.V2 if image==registry.IMAGE else registry.IMAGE
            with self.assertRaises(ValueError):
                registry.verify_enrollment(before,after,registry='ecr-public',image_reference=wrong_ref)
        for image in ('python:latest','python@sha256:'+'0'*64,registry.REFERENCE,None,True):
            with self.subTest(image=image),self.assertRaises(ValueError):
                registry.registry_settings('ecr-public',image_reference=image)
        self.assertEqual(registry.pull_command(root,root.name),registry.pull_command(root,root.name,image_reference=registry.IMAGE))
        self.assertNotEqual(registry.pull_command(root,root.name)[-5],
                            registry.pull_command(root,root.name,image_reference=registry.V2)[-5])

    def test_both_selected_manifest_digests_are_verified_without_fallback(self):
        def response(raw,url):
            result=Mock(status=200);result.geturl.return_value=url;result.read.return_value=raw
            result.__enter__=Mock(return_value=result);result.__exit__=Mock(return_value=False)
            return result
        for image in (registry.IMAGE,registry.V2):
            digest=image.rsplit('@',1)[1];seen=[]
            def open_response(request,**kwargs):
                if type(request) is str:return response(b'{"token":"memory-only"}',request)
                seen.append(request.full_url)
                return response(b'unit-manifest-for-selected-fixed-reference',request.full_url)
            opener=Mock();opener.open.side_effect=open_response
            with patch.object(registry.urllib.request,'build_opener',return_value=opener),patch.object(
                registry.hashlib,'sha256',return_value=Mock(hexdigest=lambda:digest.split(':')[1])):
                result=registry.verify_registry_manifest(registry='ecr-public',image_reference=image)
            self.assertEqual(result['registryManifestDigest'],digest)
            self.assertEqual(seen,['https://public.ecr.aws/v2/docker/library/python/manifests/'+digest])
            self.assertNotIn('memory-only',str(result))

    @unittest.skipUnless(os.name=='posix','owned Unix socket fixture requires POSIX')
    def test_sequential_fixed_pulls_share_private_daemon_without_path_collisions(self):
        root=Path('/var/tmp/dw-engine-'+uuid.uuid4().hex[:16]);root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree,root)
        for name in ('containerd.sock','docker.sock'):
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.bind(str(root/name))
            self.addCleanup(sock.close)
        (root/'daemon.json').write_text(json.dumps({'containerd':str(root/'containerd.sock'),
            'containerd-namespace':root.name,'data-root':str(root/'data')}))
        target=registry.PrivateDaemon(root,{'ID':'private-daemon','DockerRootDir':str(root/'data')})
        images={image:dict(Id=image.rsplit('@',1)[1],Os='linux',Architecture='amd64',Config={},RootFS={})
                for image in (registry.IMAGE,registry.V2)}
        def inspect(*args):
            for image,cached in images.items():
                ref=registry.registry_settings('ecr-public',image_reference=image)[0]
                if args[-1]==cached['Id']:return json.dumps([cached])
                if args[-1]==ref:return json.dumps([dict(cached,RepoDigests=[ref])])
            raise AssertionError(args)
        target.run=inspect
        read_text=Path.read_text
        def read(path,*args,**kwargs):
            if str(path).startswith('/sys/fs/cgroup/system.slice/'):
                if path.name=='memory.max':return str(768*1024*1024)
                if path.name=='memory.swap.max':return '0'
                if path.name=='memory.stat':return 'anon 0\n'
                raise AssertionError(path)
            if path==Path('/proc/meminfo'):return 'MemAvailable: 4194304 kB\n'
            return read_text(path,*args,**kwargs)
        units=[];launchers=[]
        def run(command,**kwargs):
            if command[0]=='systemd-run':
                unit=next(arg.split('=',1)[1] for arg in command if arg.startswith('--unit='));units.append(unit)
                for expected in ('--property=MemoryMax=192M','--property=MemorySwapMax=0',
                    '--property=RuntimeMaxSec=180','--property=CPUQuota=25%','--property=TasksMax=128'):
                    self.assertIn(expected,command)
                launcher=Path(command[command.index('-B')+1]);launchers.append(launcher)
                text=launcher.read_text();self.assertIn(repr('-registry-pull'+('' if len(units)==1 else '-bf12ecc0bea3f171')+'.scope'),text)
                suffix='' if len(units)==1 else '-bf12ecc0bea3f171'
                (root/('registry-client-limits'+suffix+'.private.json')).write_text(json.dumps(
                    {'memoryMax':str(192*1024*1024),'swapMax':'0','cpuMax':'25000 100000','pidsMax':'128'}))
                return Mock(returncode=0)
            if command[:2]==['systemctl','show']:
                if '--value' in command:return Mock(stdout=b'not-found\n',returncode=0)
                return Mock(stdout='ControlGroup=\nLoadState=not-found\nActiveState=inactive\n',returncode=0)
            self.assertEqual(command[:2],['systemctl','stop']);return Mock(returncode=0)
        with patch.object(registry,'ensure_capacity'),patch.object(registry,'verify_registry_manifest',
            return_value={'registryTLSOriginVerified':True}),patch.object(Path,'read_text',read),patch.object(
            registry.subprocess,'run',side_effect=run):
            bad=dict(images[registry.V2],Id='sha256:'+'0'*64)
            with self.assertRaisesRegex(ValueError,'platform-or-manifest-identity'):
                registry.enroll_image(root,target,bad,registry='ecr-public',image_reference=registry.V2)
            receipts=[]
            for image in (registry.IMAGE,registry.V2):
                _,receipt=registry.enroll_image(root,target,images[image],registry='ecr-public',image_reference=image)
                receipts.append(receipt)
        self.assertEqual(units,[root.name+'-registry-pull.scope',root.name+'-registry-pull-bf12ecc0bea3f171.scope'])
        self.assertEqual(len(set(launchers)),2)
        for prefix in ('registry-hosts','registry-client'):
            self.assertTrue((root/prefix).is_dir());self.assertTrue((root/(prefix+'-bf12ecc0bea3f171')).is_dir())
        for stem,extension in (('registry-memory-admission','.private.json'),('registry-pull','.private.log'),
            ('registry-client-scope','.private.json'),('registry-image-evidence','.private.json'),
            ('registry-client-limits','.private.json')):
            self.assertTrue((root/(stem+extension)).is_file())
            self.assertTrue((root/(stem+'-bf12ecc0bea3f171'+extension)).is_file())
        self.assertNotIn('imageReference',receipts[0])
        self.assertEqual(receipts[1]['imageReference'],registry.V2)
        self.assertTrue(all(receipt['clientLimitsVerified'] and receipt['clientScopeStopped'] for receipt in receipts))

    def test_probe_forwards_selected_fixed_reference_through_source_and_enrollment(self):
        root=Path('/var/tmp/dw-engine-'+'a'*16)
        info={'ID':'owned-private','DockerRootDir':str(root/'data')}
        for image in (registry.IMAGE,registry.V2):
            cached=dict(Id=image.rsplit('@',1)[1])
            receipt={'clientLimitsVerified':True,'clientScopeStopped':True}
            def run(target,*args):
                return json.dumps(info) if args[0]=='info' else ''
            with patch.object(registry.PrivateDaemon,'run',run),patch.object(registry,'ensure_capacity'),patch(
                'deployment_compose_namespaced_transition_probe.source_image',return_value=cached) as source,patch(
                'deployment_compose_namespaced_runtime_probe.transfer_image') as transfer,patch.object(
                registry,'enroll_image',return_value=(cached,receipt)) as enroll:
                result=registry.probe_registry(root,info,registry='ecr-public',image_reference=image)
            self.assertTrue(result['success'])
            source.assert_called_once_with(image)
            self.assertEqual(enroll.call_args.kwargs,{'registry':'ecr-public','image_reference':image})
            self.assertEqual(transfer.call_args.args[0],cached['Id'])

    def test_admission_credits_only_smaller_already_resident_anon(self):
        mib=1024*1024
        self.assertEqual(registry.registry_capacity_required(768*mib,100*mib,120*mib),1116*mib)
        self.assertEqual(registry.registry_capacity_required(768*mib,0,0),1216*mib)
        self.assertEqual(registry.registry_capacity_required(768*mib,120*mib,100*mib),1116*mib)
        for values in ((512*mib,0,0),(768*mib,-1,0),(768*mib,769*mib,0),(768*mib,True,0)):
            with self.assertRaises(ValueError):registry.registry_capacity_required(*values)


if __name__=='__main__':unittest.main()
