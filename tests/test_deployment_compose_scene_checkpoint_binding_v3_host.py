"""Native scene source/history binding; SSH/provider/Engine/kernel are doubles."""
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch
from tests import test_deployment_compose_checkpoint_source_v3_host as source_fixture
from tests.support.compose_scene_create_integration_fixture import run_case


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'POSIX/OpenSSL/OpenSSH required')
class SceneBindingTests(unittest.TestCase):
    def setUp(self):
        self.source=source_fixture.GitArchiveTests();self.source.setUp();self.addCleanup(self.source.doCleanups)

    def test_original_scene_origin_archive_and_native_git_match(self):
        from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3
        from deployment_compose_restart_checkpoint_v3_host import RestartCheckpointReaderV3
        notices=[]
        def receive(d):
            common=dict(expected_material_digest=d['materialDigest'],expected_custody_digest=d['custodyDigest'],expected_context=d['context'],expected_witness_key_hash=d['witnessKeyHash'])
            with SceneCheckpointReaderV3(Path(d['casePath']),**common,expected_scene_binding_digest=d['sceneBindingDigest'],expected_intent_key_hash=d['intentKeyHash']) as reader:
                self.assertIsNotNone(reader.writer_origin)
                self.assertEqual(reader.read_source_archive(),self.source.raw)
                proof=reader.verify_published_source(repository=self.source.repo)
                self.assertTrue(proof.publishedSourceArchiveVerified)
                self.assertFalse(proof.sourceRevalidated)
                self.assertFalse(reader.context.executionAvailable)
            with RestartCheckpointReaderV3(Path(d['casePath']),**common) as legacy:
                self.assertIsNone(legacy.writer_origin)
            notices.append(d)
        result=run_case(self,scene_controller=True,scene_callback=receive,published_source=(self.source.sha,self.source.raw,self.source.repo))
        self.assertEqual(result['postCount'],1);self.assertEqual(len(notices),1)

    def test_invalid_callback_or_source_rejects_without_business_dispatch(self):
        import deployment_compose_scene_create_broker_v3_host as broker
        native=broker.SceneCreateBrokerV3.start_first_create;calls=[]
        def start(subject,*args,**kwargs):
            calls.append(True);return native(subject,*args,**kwargs)
        with patch.object(broker.SceneCreateBrokerV3,'start_first_create',start):
            with self.assertRaises(ValueError):
                run_case(self,scene_controller=True,scene_callback=object(),published_source=(self.source.sha,self.source.raw,self.source.repo))
            with self.assertRaises(ValueError):
                run_case(self,scene_controller=True,scene_callback=lambda value:None,published_source=(self.source.sha,b'not a ZIP',self.source.repo))
        self.assertEqual(calls,[])

    def test_unissued_copy_and_instance_status_override_reject(self):
        import deployment_compose_scene_checkpoint_v3_host as checkpoint
        from deployment_compose_scene_create_controller_v3_host import SceneCreateControllerV3
        original=checkpoint.capture_scene_checkpoint
        def capture(controller,certificate,final):
            clone=object.__new__(SceneCreateControllerV3)
            clone.__dict__.update(controller.__dict__)
            with self.assertRaises(ValueError):SceneCreateControllerV3._owned(clone)
            controller._status=lambda:None
            try:
                with self.assertRaises(ValueError):SceneCreateControllerV3._owned(controller)
            finally:del controller._status
            return original(controller,certificate,final)
        with patch.object(checkpoint,'capture_scene_checkpoint',capture):
            result=run_case(self,scene_controller=True,scene_callback=lambda value:None,published_source=(self.source.sha,self.source.raw,self.source.repo))
        self.assertEqual(result['postCount'],1)

    def test_wrong_gateway_nonce_rejects_before_dispatch(self):
        import deployment_compose_scene_create_controller_v3_host as controller
        import deployment_compose_scene_create_broker_v3_host as broker
        original=controller.SceneCreateControllerV3.__init__
        def initialize(subject,**kwargs):
            kwargs['trusted_boot_id']='0'*32
            original(subject,**kwargs)
        with patch.object(controller.SceneCreateControllerV3,'__init__',initialize), patch.object(broker.SceneCreateBrokerV3,'start_first_create') as start:
            with self.assertRaises(ValueError):
                run_case(self,scene_controller=True,scene_callback=lambda value:None,published_source=(self.source.sha,self.source.raw,self.source.repo))
            start.assert_not_called()
