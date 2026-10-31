"""Synthetic controller-boundary checks; these are NOT real Engine validation."""
from pathlib import Path
import sys
import tempfile
import shutil
import socket
import unittest
from dataclasses import dataclass
from copy import deepcopy
import json
import http.client
import io
import os
from unittest.mock import patch, Mock

ROOT=Path(__file__).resolve().parents[1]
for directory in ('scripts','packs/deployment/scripts','tests/support'):
    sys.path.insert(0,str(ROOT/directory))
import compose_profile3_prepare_fixture as fixture


@unittest.skipUnless(os.name == 'posix', 'private Linux preparation fixture')
class ControllerBoundaryTests(unittest.TestCase):
    def test_running_null_oom_observation_uses_exact_existing_policy(self):
        from copy import deepcopy
        from tests.test_deployment_compose_restore_body_host import fixture as source_fixture
        from deployment_compose_restore_host_config import compile_restore_host_config, OOM_ENABLED_POLICY
        args=source_fixture()
        common=[args[k] for k in ('raw','identity','artifact','private_key','network_ids','expected_mounts')]
        before=deepcopy(args['raw'])
        self.assertIsNone(args['raw']['HostConfig']['OomKillDisable'])
        result=compile_restore_host_config(*common,policy=fixture.SOURCE_HOST_POLICY)
        self.assertIsNone(result['hostConfigFragment']['OomKillDisable'])
        self.assertEqual(args['raw'],before)
        with self.assertRaises(ValueError):
            compile_restore_host_config(*common,policy=OOM_ENABLED_POLICY)

    def args(self):
        return dict(source_sha='b'*40,host_id='controller-host',expected_daemon_id='expected',
            keys={k:b'k'*32 for k in ('config','image','declaration','archive','target')},
            policy_hash='c'*64,expiry_seconds=600)

    def test_bad_source_and_daemon_rejected_before_engine_access(self):
        for change in ({'source_sha':'a'*40},{'source_sha':'not-a-sha'},{'expected_daemon_id':'other'}, {'expiry_seconds':901}):
            args=self.args();args.update(change)
            with patch.object(fixture,'PrivateDaemon') as daemon:
                with self.assertRaises(ValueError): fixture.validate_controller(Path('/unknown'),{'ID':'expected'},**args)
                daemon.assert_not_called()

    def test_unowned_root_rejected_without_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755)
            with patch.object(fixture,'PrivateDaemon') as daemon:
                with self.assertRaisesRegex(ValueError,'unowned-root'):
                    fixture.validate_controller(root,{'ID':'expected'},**self.args())
                daemon.return_value.run.assert_not_called()

    def test_unknown_write_blocks_cleanup_and_further_writes(self):
        session=fixture.PreparationSession(Mock(),'dw-owned')
        def fail(): raise OSError('unknown outcome')
        with self.assertRaises(OSError): session.write(fail)
        with self.assertRaisesRegex(ValueError,'blocked'): session.cleanup()
        callback=Mock()
        with self.assertRaisesRegex(ValueError,'blocked'): session.write(callback)
        callback.assert_not_called();session.target.assert_not_called()

    def test_unknown_write_closes_read_resources_without_engine_mutations(self):
        target=Mock()
        session=fixture.PreparationSession(target,'dw-owned')
        server,thread,store=Mock(),Mock(),Mock()
        thread.is_alive.return_value=False
        session.listeners=[(server,thread)]
        session.store=store
        session.created_ids=['1'*64]
        session.resources=[('network','2'*64)]
        session.unknown_write_result=True
        with patch.object(fixture,'delete') as delete:
            with self.assertRaisesRegex(ValueError,'blocked-after-unknown'):
                session.cleanup()
            delete.assert_not_called()
        server.shutdown.assert_called_once_with()
        server.server_close.assert_called_once_with()
        thread.join.assert_called_once_with(timeout=5)
        store.close.assert_called_once_with()
        self.assertEqual(target.mock_calls,[])
        self.assertIsNone(session.store)
        self.assertEqual(session.listeners,[])
        self.assertEqual(session.created_ids,['1'*64])
        self.assertTrue(session.unknown_write_result)

    def test_only_confirmed_ids_removed(self):
        session=fixture.PreparationSession(Mock(),'dw-owned')
        session.created_ids=['1'*64]
        with patch.object(fixture,'delete') as delete:
            session.cleanup()
            delete.assert_called_once_with(session.target,'1'*64)
        session.target.stop.assert_called_once_with('1'*64)

    def test_public_payload_excludes_private_prepared_material(self):
        @dataclass
        class Request:
            source: str
        bundle=Mock()
        bundle.public_review.return_value={'authorityGranted':False}
        bundle.to_dict.return_value={'Env':['SECRET=value']}
        prepared={'request':Request('trusted-revision'),'bundle':bundle,
                  'private_key':b'private-key','raw':{'Env':['SECRET=value']}}
        public=fixture.public_payload(prepared)
        self.assertEqual(set(public),{'request','review'})
        self.assertNotIn('SECRET',json.dumps(public))
        bundle.to_dict.assert_not_called()

    def test_strict_http_receipts_reject_ambiguous_ownership(self):
        # Parse real HTTP framing over synthetic bytes; no Engine is involved.
        class Socket:
            def __init__(self, raw): self.raw=raw
            def makefile(self, mode): return io.BytesIO(self.raw)
        for kind, field in (('container','Id'),('network','Id'),('volume','Name')):
            value='1'*64 if field=='Id' else 'dw-owned-data'
            valid=json.dumps({field:value}).encode()
            duplicate=('{"%s":"%s","%s":"%s"}'%(field,value,field,value)).encode()
            for body, length, status in ((valid,len(valid)+5,201),
                                         (duplicate,len(duplicate),201),
                                         (b'{"Id":NaN}',10,201),
                                         (valid,len(valid),200)):
                with self.subTest(kind=kind,body=body,status=status):
                    wire=('HTTP/1.1 %d Test\r\nContent-Length: %d\r\n\r\n'%(status,length)).encode()+body
                    response=http.client.HTTPResponse(Socket(wire));response.begin()
                    target=Mock();target.connection.return_value.getresponse.return_value=response
                    session=fixture.PreparationSession(target,'dw-owned')
                    server,thread,store=Mock(),Mock(),Mock()
                    thread.is_alive.return_value=False
                    session.listeners=[(server,thread)];session.store=store
                    with self.assertRaises(ValueError):
                        session.write(lambda: session.create('/synthetic-create',{},kind=kind,expected=value))
                    self.assertEqual(session.created_ids,[])
                    self.assertEqual(session.resources,[])
                    self.assertTrue(session.unknown_write_result)
                    target.reset_mock()
                    with patch.object(fixture,'delete') as delete:
                        with self.assertRaisesRegex(ValueError,'blocked-after-unknown'):session.cleanup()
                        delete.assert_not_called()
                    self.assertEqual(target.mock_calls,[])
                    server.shutdown.assert_called_once_with()
                    server.server_close.assert_called_once_with()
                    store.close.assert_called_once_with()

    def test_complete_created_http_receipt_registers_confirmed_id(self):
        class Socket:
            def makefile(self, mode):
                body=json.dumps({'Id':'1'*64}).encode()
                return io.BytesIO(('HTTP/1.1 201 Created\r\nContent-Length: %d\r\n\r\n'%len(body)).encode()+body)
        response=http.client.HTTPResponse(Socket());response.begin()
        target=Mock();target.connection.return_value.getresponse.return_value=response
        session=fixture.PreparationSession(target,'dw-owned')
        self.assertEqual(session.write(lambda: session.create('/synthetic-create',{})),'1'*64)
        self.assertEqual(session.created_ids,['1'*64])
        self.assertFalse(session.unknown_write_result)

    def test_observer_purpose_rejected_before_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for purpose in ('../escape', 'current', '', None):
                with self.subTest(purpose=purpose), self.assertRaisesRegex(ValueError,'observer-purpose'):
                    fixture._observers(root,Mock(),{},Mock(),b'k'*32,purpose=purpose)
                self.assertEqual(list(root.iterdir()),[])

    def test_current_requires_authenticated_history_before_engine_access(self):
        session=fixture.PreparationSession(Mock(),'dw-owned')
        with self.assertRaisesRegex(ValueError,'current-input'):
            fixture.prepare_current_profile3(session,original_bundle=Mock(),original_request=Mock(),
                authenticated_history=Mock(),keys=self.args()['keys'],source_sha='b'*40,
                host_id='controller-host',policy_hash='c'*64)
        self.assertEqual(session.target.mock_calls,[])
        self.assertIsNone(session.store)
        self.assertEqual(session.listeners,[])

    def test_shared_preparation_contains_no_engine_writers(self):
        # Structural regression check only, not an Engine integration test.
        import ast
        import inspect
        for helper in (fixture._prepare_observed,fixture.prepare_current_profile3):
            tree=ast.parse(inspect.getsource(helper))
            calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)]
            forbidden={'run','create','stop','transfer_image','enroll_image','delete'}
            for call in calls:
                name=call.func.attr if isinstance(call.func,ast.Attribute) else getattr(call.func,'id','')
                self.assertNotIn(name,forbidden)

    def test_command_reports_actual_python_version(self):
        command=fixture.fixture_command('dw-restore-'+'1'*24)
        compile(command,'fixture','exec')
        self.assertIn("'version': sys.version",command)
        self.assertNotIn("'version': 'same-image'",command)


@unittest.skipUnless(os.name == 'posix' and hasattr(socket,'AF_UNIX') and shutil.which('openssl') and shutil.which('ssh-keygen'), 'POSIX Unix sockets, OpenSSL and OpenSSH required')
class CurrentPreparationUnixTests(unittest.TestCase):
    """Fake Engine unit test: real Unix HTTP, reader mTLS, CAS and signed Store.

    The daemon responses are synthetic. No Docker process or external service is
    involved, and this does not prove actual Engine reconstruction equivalence.
    """
    def setUp(self):
        import socketserver
        import threading
        from copy import deepcopy
        from http.server import BaseHTTPRequestHandler
        from tests.test_deployment_compose_restore_body_host import fixture as source_fixture
        # Exercise POSIX CAS mechanics on macOS; production Linux admission is
        # tested independently by recovery-store tests. No storage seam is used.
        platform=patch('deployment_compose_recovery_store.sys.platform','linux')
        platform.start();self.addCleanup(platform.stop)
        self.deepcopy=deepcopy
        self.temp=tempfile.TemporaryDirectory(prefix='p3-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.project='dw-restore-'+'3'*24
        args=source_fixture()
        self.keys={k:b'k'*32 for k in ('config','image','declaration','archive','target')}
        self.images=[deepcopy(args['image']),deepcopy(args['image'])]
        self.images[1]['Id']='sha256:'+'9'*64
        self.images[1]['RepoDigests']=['example.com/app@sha256:'+'8'*64]
        self.network='c'*64
        self.network_name='sample_default'
        self.volume='sample-data'
        self.rows={}
        for service,cid in (('backend','1'*64),('peer','2'*64)):
            row=deepcopy(args['raw'])
            row.update(Id=cid,Name='/'+self.project+'-'+service,RestartCount=0,
                State=dict(Pid=123,StartedAt='initial',Running=True,Paused=False,
                    Restarting=False,Dead=False,Status='running',Health={'Status':'healthy','Log':[]}))
            row['Config']['Image']=row['Image']
            row['Config']['Labels'].update({'com.docker.compose.project':self.project,
                'com.docker.compose.service':service})
            row['NetworkSettings']['Networks'][self.network_name]['Aliases']=[service]
            self.rows[cid]=row
        self.calls=[]
        test=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                test.calls.append(('GET',self.path))
                path=self.path
                if path=='/v1.45/info':
                    value=dict(ID='daemon-one',DockerRootDir=str(test.root/'data'),ServerVersion='29.8.2')
                elif path=='/v1.45/version':value=dict(Version='29.8.2',GitCommit='8af9fe3')
                elif path.startswith('/v1.45/containers/json?'):
                    value=[dict(Id=r['Id'],ImageID=r['Image'],Labels=r['Config']['Labels']) for r in test.rows.values()]
                elif path.startswith('/v1.45/containers/'):
                    value=deepcopy(test.rows[path.split('/')[-2]])
                    value['State']['Health']['Log']=[dict(Start=str(len(test.calls)),
                        End=str(len(test.calls)),ExitCode=0,Output='healthy')]
                elif path.startswith('/v1.45/images/'):
                    iid=path[len('/v1.45/images/'):-len('/json')]
                    value=next(i for i in test.images if i['Id']==iid)
                elif path.startswith('/v1.45/networks/'):
                    value=dict(Id=test.network,Name=test.network_name,
                        Labels={'com.docker.compose.project':test.project},Containers={cid:{} for cid in test.rows})
                elif path.startswith('/v1.45/volumes/'):
                    value=dict(Name=test.volume,Driver='local',Options={},
                        Labels={'com.docker.compose.project':test.project},
                        Mountpoint=test.rows['2'*64]['Mounts'][0]['Source'])
                else:raise AssertionError(path)
                raw=json.dumps(value).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(raw)))
                self.end_headers();self.wfile.write(raw)
            def do_POST(self):
                test.calls.append(('POST',self.path));self.send_error(405)
            def do_DELETE(self):
                test.calls.append(('DELETE',self.path));self.send_error(405)
        class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
            daemon_threads=True
        server=Server(str(self.root/'docker.sock'),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        target=Mock(socket=str(self.root/'docker.sock'))
        target.run.side_effect=AssertionError('CLI forbidden in GET-only preparation')
        self.session=fixture.PreparationSession(target,self.project)
        self.addCleanup(self.session.cleanup)
        bodies={}
        for service,cid in (('backend','1'*64),('peer','2'*64)):
            row=self.rows[cid]
            bodies[service]=dict(deepcopy(row['Config']),HostConfig=deepcopy(row['HostConfig']),
                NetworkingConfig={'EndpointsConfig':{self.network_name:dict(NetworkID=self.network,Aliases=[service])}})
        before=deepcopy(self.rows)
        self.prepare_initial(bodies)
        self.assertEqual(self.rows,before)
        self.assertIsNone(self.session.raw_source['HostConfig']['OomKillDisable'])

    def prepare_initial(self,bodies):
        fixture._prepare_observed(self.session,root=self.root,
            rows={'backend':self.rows['1'*64],'peer':self.rows['2'*64]},images=self.images,
            references=[i['RepoDigests'][0] for i in self.images],bodies=bodies,
            network_name=self.network_name,network=self.network,volume=self.volume,
            bind=Path('/sample/config'),source_sha='b'*40,host_id='host-one',
            expected_daemon_id='daemon-one',fresh={'ServerVersion':'29.8.2'},keys=self.keys,
            policy_hash='c'*64,environment='staging',expiry_seconds=600,purpose='initial')
        session=self.session
        session.root=self.root
        session.enrolled_images=deepcopy(self.images)
        session.enrolled_references=tuple(i['RepoDigests'][0] for i in self.images)
        session.deployment_context=dict(preparer=session.preparer,prepared=session.prepared,
            bundle=session.prepared['bundle'],request=session.prepared['request'],
            whole_observer=session.whole_observer,retention_observer=session.retention_observer,
            guard=session.guard,producer=session.producer,
            raw_rows={'backend':deepcopy(self.rows['1'*64]),'peer':deepcopy(self.rows['2'*64])},
            source_model=deepcopy(session.source_model),source_inputs=session.source_inputs)

    def deploy(self, *, receipt_id=None, unknown=False):
        from tests import test_deployment_compose_history_v3_host as history_fixture
        h=history_fixture.HistoryTests('test_two_scopes_and_no_local_files')
        h.setup_gate_fixture();self.addCleanup(h.doCleanups)
        h.bundle=self.session.prepared['bundle'];h.req=self.session.prepared['request']
        h.receipts={};h.index=0;h.open_scope()
        if unknown:
            h.finish(status=0,body=b'',definitive=False)
            self.history=h.history()
            return h
        receipt_id=receipt_id or 'a'*64
        while True:
            h.finish(status=201 if h.op['phase']=='create' else 204,
                body=json.dumps({'Id':receipt_id}).encode() if h.op['phase']=='create' else b'')
            h.receipts={'backend':receipt_id}
            writes=[op for op in h.bundle.resolve_operations(h.receipts) if op['method']!='GET']
            if h.index==len(writes)-1:break
            h.index+=1;h.open_scope()
        old=self.rows.pop('1'*64)
        service=h.bundle.to_dict()['services'][0]
        row=self.deepcopy(old)
        row.update(Id='a'*64,Image=service['targetImageId'])
        body=self.deepcopy(service['targetCreateBody'])
        row['Config']={k:v for k,v in body.items() if k not in ('HostConfig','NetworkingConfig')}
        row['HostConfig']=body['HostConfig']
        self.rows['a'*64]=row
        self.history=h.history()
        return h

    def current(self,**changes):
        kw=dict(original_bundle=self.session.prepared['bundle'],original_request=self.session.prepared['request'],
            authenticated_history=self.history,keys=self.keys,source_sha='b'*40,host_id='host-one',policy_hash='c'*64)
        kw.update(changes)
        return fixture.prepare_current_profile3(self.session,**kw)

    def test_initial_and_current_real_unix_tls_cas_signed_history(self):
        self.deploy()
        session=self.session
        bundle=session.prepared['bundle'];original=bundle.to_dict()
        archive=session.store.get(original['archiveReference'])
        old=session.preparer
        with patch.object(session.whole_observer,'issue',side_effect=AssertionError('old observer forbidden')), \
             patch.object(session.retention_observer,'issue',side_effect=AssertionError('old observer forbidden')), \
             patch.object(session.whole_observer,'_read',side_effect=AssertionError('old observer forbidden')), \
             patch.object(session.retention_observer,'_read',side_effect=AssertionError('old observer forbidden')):
            result=self.current()
        current=result['prepared']['bundle'].to_dict()['services'][0]
        original_service=original['services'][0]
        self.assertEqual(current['baselineContainerId'],'a'*64)
        self.assertEqual(current['baselineCreateBody'],original_service['targetCreateBody'])
        self.assertEqual(current['targetImageId'],original_service['baselineImageId'])
        self.assertEqual(current['targetCreateBody'],original_service['baselineCreateBody'])
        self.assertIsNone(result['private_session'].raw_source['HostConfig']['OomKillDisable'])
        self.assertTrue(result['private_session'].raw_rows['backend']['State']['Health']['Log'])
        self.assertIs(session.preparer,old)
        self.assertIs(result['private_session'].store,session.store)
        self.assertEqual(session.store.get(original['archiveReference']),archive)
        for name in ('profile3-tls','profile3-rollback-tls','profile3-inputs.private.json','profile3-rollback-inputs.private.json'):
            path=self.root/name
            self.assertTrue(path.exists(),name)
            self.assertEqual(path.stat().st_mode & 0o777,0o700 if path.is_dir() else 0o600)
        self.assertTrue(self.calls)
        self.assertEqual({method for method,path in self.calls},{'GET'})

    def assert_denied_without_new_observers(self,**changes):
        with patch.object(fixture,'_observers') as observers:
            with self.assertRaises(ValueError):self.current(**changes)
            observers.assert_not_called()
        self.assertFalse((self.root/'profile3-rollback-tls').exists())
        self.assertFalse((self.root/'profile3-rollback-inputs.private.json').exists())
        self.assertEqual({method for method,path in self.calls},{'GET'})

    def test_wrong_signed_receipt_cannot_adopt_current_named_container(self):
        self.deploy(receipt_id='d'*64)
        self.assert_denied_without_new_observers()

    def test_unknown_signed_history_cannot_prepare(self):
        self.deploy(unknown=True)
        self.assert_denied_without_new_observers()

    def test_policy_peer_and_target_drift_denied_before_tls(self):
        self.deploy()
        self.assert_denied_without_new_observers(policy_hash='d'*64)
        self.rows['2'*64]['State']['Pid']+=1
        self.assert_denied_without_new_observers()
        self.rows['2'*64]['State']['Pid']-=1
        self.rows['a'*64]['Config']['Env'].append('UNAPPROVED=1')
        self.assert_denied_without_new_observers()

    def test_original_guard_phase_state_cannot_be_replayed_as_current(self):
        self.deploy()
        # A replay of the original selected CID is rejected even when names,
        # labels and current image are copied from the successfully deployed row.
        self.rows['1'*64]=self.rows.pop('a'*64)
        self.rows['1'*64]['Id']='1'*64
        self.assert_denied_without_new_observers()


if __name__=='__main__': unittest.main()
