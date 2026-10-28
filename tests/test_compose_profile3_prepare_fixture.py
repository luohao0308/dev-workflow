"""Synthetic controller-boundary checks; these are NOT real Engine validation."""
from pathlib import Path
import sys
import tempfile
import unittest
from dataclasses import dataclass
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

    def test_command_reports_actual_python_version(self):
        command=fixture.fixture_command('dw-restore-'+'1'*24)
        compile(command,'fixture','exec')
        self.assertIn("'version': sys.version",command)
        self.assertNotIn("'version': 'same-image'",command)


if __name__=='__main__': unittest.main()
