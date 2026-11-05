from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import subprocess
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from tests.test_deployment_compose_runtime_probe import Docker, probe as runtime
import deployment_compose_namespaced_runtime_probe as adapter

ROOT=Path('/var/tmp/dw-engine-'+'a'*16)
INFO={'ID':'private-daemon','DockerRootDir':str(ROOT/'data'),'SwapLimit':True}


@unittest.skipUnless(os.name=='posix','POSIX namespace/socket diagnostic')
class NamespacedRuntimeTests(unittest.TestCase):
    def test_scope_and_env_reject_default_socket_or_wrong_root(self):
        for root,info in [(Path('/var/run/docker'),INFO),(ROOT,dict(INFO,DockerRootDir='/var/lib/docker')),
                          (ROOT,dict(INFO,ID=True))]:
            with self.assertRaises(ValueError):adapter.PrivateDaemon(root,info)
        target=adapter.PrivateDaemon(ROOT,INFO)
        with patch.dict(adapter.os.environ,{'DOCKER_HOST':'tcp://wrong','DOCKER_CONTEXT':'wrong'}), \
             patch.object(adapter.subprocess,'run',return_value=Mock(stdout=b'ok')) as run:
            self.assertEqual(target.run('info'),'ok')
            args=run.call_args
            self.assertEqual(args.args[0][:3],['docker','--host','unix://'+str(ROOT/'docker.sock')])
            self.assertNotIn('DOCKER_HOST',args.kwargs['env'])
            self.assertNotIn('DOCKER_CONTEXT',args.kwargs['env'])
            self.assertEqual(args.kwargs['env']['DOCKER_API_VERSION'],'1.45')

    def test_http_socket_is_exact_private_path(self):
        target=adapter.PrivateDaemon(ROOT,INFO)
        with patch.object(adapter.socket,'socket') as factory:
            conn=target.connection()
            factory.return_value.connect.assert_called_once_with(str(ROOT/'docker.sock'))
            conn.close()
        with patch.object(target,'connection') as connection:
            response=connection.return_value.getresponse.return_value
            response.status=204;response.read.return_value=b''
            self.assertEqual(target.stop('b'*64),'b'*64)
            connection.return_value.request.assert_called_once_with('POST','/v1.45/containers/'+'b'*64+'/stop?t=10')
        with self.assertRaises(ValueError):target.stop('guessed-name')
        with self.assertRaises(ValueError):target.post({'method':'POST','path':'/v1.45/containers/prune'})

    def test_production_commands_are_inspect_info_only(self):
        with patch.object(adapter.subprocess,'run',return_value=Mock(stdout=b'{}')) as run:
            adapter.production_read('image','inspect',adapter.IMAGE)
            self.assertEqual(run.call_args.args[0][1:3],['--host',adapter.PRODUCTION])
            for command in [('image','pull',adapter.IMAGE),('container','rm','x'),('image','inspect','mutable:latest')]:
                with self.assertRaises(ValueError):adapter.production_read(*command)

    def test_transfer_uses_only_source_save_and_private_load(self):
        first=Mock(returncode=0);first.poll.return_value=0
        second=Mock(returncode=0);second.poll.return_value=0
        target=adapter.PrivateDaemon(ROOT,INFO)
        with patch.object(adapter.subprocess,'Popen',side_effect=[first,second]) as popen:
            adapter.transfer_image('sha256:'+'a'*64,target)
            calls=popen.call_args_list
            self.assertEqual(calls[0].args[0],['docker','--host',adapter.PRODUCTION,'image','save','sha256:'+'a'*64])
            self.assertEqual(calls[1].args[0],['docker','--host',target.host,'image','load'])
            first.stdout.close.assert_called_once()
        with self.assertRaises(ValueError):adapter.transfer_image('mutable:latest',target)

    def test_transfer_timeout_kills_only_its_two_cli_children(self):
        source=Mock();source.poll.return_value=None
        target=Mock();target.poll.return_value=None
        target.wait.side_effect=[subprocess.TimeoutExpired('private-load',180),None]
        with patch.object(adapter.subprocess,'Popen',side_effect=[source,target]):
            with self.assertRaises(subprocess.TimeoutExpired):
                adapter.transfer_image('sha256:'+'a'*64,adapter.PrivateDaemon(ROOT,INFO))
        source.kill.assert_called_once();target.kill.assert_called_once()

    @unittest.skipIf(sys.platform=='win32','POSIX runtime fixture')
    def test_import_without_repo_digests_uses_original_metadata_only_after_exact_match(self):
        docker=Docker();original=deepcopy(docker.image);docker.image['RepoDigests']=[]
        result=runtime.probe(docker,docker.post,docker.healthy,docker.stop,image_evidence=original)
        self.assertTrue(result['success'],result.get('privateFailure'))
        self.assertTrue(result['imageTransferIdentityMatched'])
        self.assertFalse(result['registryProvenanceVerified'])
        self.assertEqual(result['importedImageInspect']['RepoDigests'],[])
        self.assertEqual(original['RepoDigests'],[adapter.IMAGE])

    def test_imported_image_config_mismatch_blocks_before_any_resource_create(self):
        docker=Docker();original=deepcopy(docker.image);docker.image['Config']['Env'].append('FOREIGN=1')
        result=runtime.probe(docker,docker.post,docker.healthy,docker.stop,image_evidence=original)
        self.assertFalse(result['success'])
        self.assertEqual(result['privateFailure']['reason'],'imported-image-identity-mismatch')
        self.assertFalse(any(len(c)>1 and c[1]=='create' for c in docker.calls))

    def test_fresh_daemon_mismatch_blocks_image_export(self):
        with patch.object(adapter.PrivateDaemon,'run',return_value=json.dumps(dict(INFO,ID='changed'))), \
             patch.object(adapter,'production_read',return_value='{"ID":"production"}'), \
             patch.object(adapter,'transfer_image') as transfer:
            with self.assertRaises(ValueError):adapter.run_runtime(ROOT,INFO)
            transfer.assert_not_called()

    def test_swap_capability_missing_blocks_before_export(self):
        with patch.object(adapter.PrivateDaemon,'run',return_value=json.dumps(dict(INFO,SwapLimit=False))), \
             patch.object(adapter,'production_read',return_value='{\"ID\":\"production\"}'), \
             patch.object(adapter,'transfer_image') as transfer:
            with self.assertRaisesRegex(ValueError,'private-daemon-swap-limit-unavailable'):
                adapter.run_runtime(ROOT,INFO)
            transfer.assert_not_called()

    def test_vfs_worst_case_disk_bound_required_before_export(self):
        image={'Size':100,'RootFS':{'Layers':['one','two']}}
        required=500+1024**3
        with patch.object(adapter.shutil,'disk_usage',return_value=Mock(free=required)):
            self.assertEqual(adapter.ensure_capacity(ROOT,image),required)
        with patch.object(adapter.shutil,'disk_usage',return_value=Mock(free=required-1)):
            with self.assertRaises(ValueError):adapter.ensure_capacity(ROOT,image)
        with self.assertRaises(ValueError):adapter.ensure_capacity(ROOT,{'Size':True})

    def test_success_removes_imported_image_only_on_private_daemon(self):
        original=Docker().image
        for failure in (False,True):
            responses=[json.dumps(INFO),'','',
                       subprocess.CalledProcessError(1,['private-image-rm']) if failure else 'Deleted', '']
            with patch.object(adapter.PrivateDaemon,'run',side_effect=responses) as run, \
                 patch.object(adapter,'production_read',side_effect=['{"ID":"production"}',json.dumps([original])]), \
                 patch.object(adapter,'transfer_image'), patch.object(adapter,'ensure_capacity',return_value=1024**3), \
                 patch.object(adapter,'probe',return_value={'success':True,'unknownWriteResult':False}):
                result=adapter.run_runtime(ROOT,INFO)
            self.assertEqual(run.call_args_list[3].args,('image','rm',original['Id']))
            self.assertEqual(result['success'],not failure)
            self.assertEqual(result['importedImageRemoved'],not failure)
            self.assertEqual(result['unknownWriteResult'],failure)


if __name__=='__main__':unittest.main()
