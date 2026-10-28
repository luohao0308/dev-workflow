"""No real Docker calls; version/sentinel and irreversible ordering boundaries."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
for d in ('scripts','packs/deployment/scripts','tests/support'):sys.path.insert(0,str(ROOT/d))
import deployment_compose_namespaced_transition_probe as transition
import compose_transition_probe as app


@unittest.skipUnless(os.name=='posix','POSIX namespace transition diagnostic')
class TransitionTests(unittest.TestCase):
    def test_bootstrap_once_then_versions_retain_without_reseed(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'_deny_write',return_value=True):
            base=Path(directory);volume=base/'data';volume.mkdir();bind=base/'config';bind.write_text('nonce\n')
            args=dict(volume=volume,bind=bind,root=base/'root')
            app.startup('backend','nonce','v1',True,**args)
            before=(volume/'sentinel.txt').read_bytes()
            for version in ('v2','v1'):
                app.startup('backend','nonce',version,False,**args)
                self.assertEqual((volume/'sentinel.txt').read_bytes(),before)
            with self.assertRaises(RuntimeError):app.startup('backend','nonce','v1',True,**args)
            (volume/'sentinel.txt').unlink()
            with self.assertRaises(FileNotFoundError):app.startup('backend','nonce','v2',False,**args)
            self.assertFalse((volume/'sentinel.txt').exists())

    def test_explicit_workdir_handles_alpine_root_default_without_relaxing_compiler(self):
        from tests.test_deployment_compose_create import fixture
        recipe,inputs=fixture()
        image={'Id':inputs['baseline_image_id'],'Config':{'Env':inputs['image_defaults']['Env']}}
        project='dw-transition-'+'a'*24;network='c'*64
        value=transition.transition_recipe(image,project,network,project+'-data','/tmp/config.txt','backend',project)
        defaults=dict(inputs['image_defaults'],WorkingDir='/')
        candidate=transition.compile_create(value,baseline_image_id=image['Id'],image_defaults=defaults,
            identity={'hostId':'diagnostic','daemonId':'test','project':project,'service':'backend','containerName':value['containerName']},
            network_ids={project+'-net':network},allowed_mounts=value['mounts'],hostname='backend')
        self.assertEqual(candidate['body']['WorkingDir'],'/tmp')

    def test_generated_server_and_clients_are_compilable(self):
        for version in ('v1','v2'):
            for role in transition.ROLES:
                ast.parse(app.server_code(role,'nonce',version,False))
                ast.parse(app.client_code(role,role,'nonce',version,'172.20.0.2'))

    def test_client_rejects_wrong_version_and_dns_endpoint(self):
        code=app.client_code('frontend','frontend','token','v2','172.20.0.2')
        with patch('socket.getaddrinfo',return_value=[(None,None,None,None,('172.20.0.3',8080))]):
            with self.assertRaisesRegex(AssertionError,'DNS endpoint'):exec(code,{})
        response=Mock();response.status=200;response.geturl.return_value='http://frontend:8080/health'
        response.read.return_value=json.dumps({'role':'frontend','token':'token','version':'v1','checks':{}}).encode()
        opener=Mock();opener.open.return_value.__enter__=Mock(return_value=response);opener.open.return_value.__exit__=Mock(return_value=False)
        with patch('socket.getaddrinfo',return_value=[(None,None,None,None,('172.20.0.2',8080))]),patch('urllib.request.build_opener',return_value=opener):
            with self.assertRaises(AssertionError):exec(code,{})

    def test_switch_stops_reverse_then_removes_and_renames_known_ids(self):
        active={'backend':'a'*64,'frontend':'b'*64};pending={'backend':'c'*64,'frontend':'d'*64}
        known={i:{} for i in (*active.values(),*pending.values())};calls=[]
        target=Mock();target.stop.side_effect=lambda i:calls.append(('stop',i))
        def run(*args):
            calls.append(args)
            if args[:2]==('container','rename'):return ''
            receipt=args[2];role='backend' if receipt=='c'*64 else 'frontend'
            return json.dumps([{'Id':receipt,'Name':'/project-'+role}])
        target.run.side_effect=run
        with patch.object(transition,'delete',side_effect=lambda t,i:calls.append(('delete',i))):
            transition.switch(target,active,pending,known,lambda fn:fn(),'project')
        self.assertEqual(calls[:4],[('stop','b'*64),('stop','a'*64),('delete','b'*64),('delete','a'*64)])
        self.assertEqual(set(known),set(pending.values()))
        self.assertEqual([x for x in calls if x[:2]==('container','rename')],
                         [('container','rename','c'*64,'project-backend'),('container','rename','d'*64,'project-frontend')])

    def test_unknown_stop_prevents_delete_or_rename(self):
        target=Mock();target.stop.side_effect=subprocess.TimeoutExpired('stop',25)
        with patch.object(transition,'delete') as remove:
            with self.assertRaises(subprocess.TimeoutExpired):
                transition.switch(target,{'backend':'a'*64,'frontend':'b'*64},{'backend':'c'*64,'frontend':'d'*64},{},lambda fn:fn(),'project')
            remove.assert_not_called();target.run.assert_not_called()

    def test_second_stop_unknown_preserves_all_old_containers(self):
        target=Mock();target.stop.side_effect=['b'*64,subprocess.TimeoutExpired('backend-stop',25)]
        known={'a'*64:{'running':True},'b'*64:{'running':True}}
        with patch.object(transition,'delete') as remove:
            with self.assertRaises(subprocess.TimeoutExpired):
                transition.switch(target,{'backend':'a'*64,'frontend':'b'*64},
                    {'backend':'c'*64,'frontend':'d'*64},known,lambda fn:fn(),'project')
            remove.assert_not_called();target.run.assert_not_called()
        self.assertFalse(known['b'*64]['running'])
        self.assertTrue(known['a'*64]['running'])

    def test_delete_disables_force_and_volume_removal(self):
        target=Mock();response=target.connection.return_value.getresponse.return_value
        response.status=204;response.read.return_value=b''
        transition.delete(target,'a'*64)
        target.connection.return_value.request.assert_called_once_with('DELETE','/v1.45/containers/'+'a'*64+'?force=false&v=false')
        with self.assertRaises(ValueError):transition.delete(target,'container-name')

    def test_source_image_commands_are_read_only_and_closed(self):
        with patch.object(transition.subprocess,'run') as run:
            run.return_value.stdout=json.dumps([{'RepoDigests':[transition.V2]}]).encode()
            transition.source_image(transition.V2)
            self.assertEqual(run.call_args.args[0],['docker','--host',transition.PRODUCTION,'image','inspect',transition.V2])
            with self.assertRaises(ValueError):transition.source_image('python:latest')

    def test_preflight_mismatch_preserves_failure_and_skips_cleanup(self):
        root=Path('/var/tmp/dw-engine-'+'a'*16);info={'ID':'private','DockerRootDir':str(root/'data')}
        target=Mock();target.run.return_value=json.dumps(dict(info,ID='wrong',SwapLimit=True))
        with patch.object(transition,'PrivateDaemon',return_value=target),patch.object(transition,'transfer_image') as transfer:
            result=transition.run_transition(root,info)
        self.assertFalse(result['success']);self.assertFalse(result['inventoryBaselineCaptured'])
        self.assertEqual(result['privateFailure']['reason'],'private-daemon-mismatch')
        self.assertEqual(target.run.call_count,1);transfer.assert_not_called()

    def test_unknown_network_write_blocks_all_followup_and_cleanup(self):
        root=Path('/var/tmp/dw-engine-'+'a'*16)
        info={'ID':'private','DockerRootDir':str(root/'data'),'SwapLimit':True}
        images={ref:{'Id':'sha256:'+c*64,'Os':'linux','Architecture':'amd64','Config':{},'RootFS':{},'RepoDigests':[ref]}
                for ref,c in ((transition.IMAGE,'a'),(transition.V2,'b'))}
        target=Mock()
        def run(*args):
            if args[0]=='info':return json.dumps(info)
            if args[:2] in (('ps','-aq'),('images','-aq'),('network','ls'),('volume','ls')):return ''
            if args[:2]==('image','inspect'):
                return json.dumps([next(x for x in images.values() if x['Id']==args[2])])
            if args[:2]==('network','create'):raise subprocess.TimeoutExpired('private-network-create',30)
            raise AssertionError(args)
        target.run.side_effect=run
        with patch.object(transition,'PrivateDaemon',return_value=target), \
             patch.object(transition.subprocess,'run',return_value=Mock(stdout=b'{"ID":"production"}')), \
             patch.object(transition,'source_image',side_effect=lambda ref:images[ref]), \
             patch.object(transition,'ensure_capacity',return_value=1), \
             patch.object(transition.shutil,'disk_usage',return_value=Mock(free=100)), \
             patch.object(transition,'transfer_image'),patch.object(transition,'derive_defaults',return_value={}):
            result=transition.run_transition(root,info)
        self.assertFalse(result['success']);self.assertTrue(result['unknownWriteResult'])
        self.assertEqual(result['privateFailure']['phase'],'network-create')
        self.assertFalse(any(call.args[:2] in (('network','rm'),('image','rm'),('volume','create')) for call in target.run.call_args_list))


if __name__=='__main__':unittest.main()
