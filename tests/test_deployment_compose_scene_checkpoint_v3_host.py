"""Native history custody; provider, Engine, kernel and scene transport are doubles."""
import os
import shutil
import unittest
from unittest.mock import patch
from tests.support.compose_scene_create_integration_fixture import run_case
from deployment_compose_restart_checkpoint_v3_host import RestartCheckpointReaderV3


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'POSIX/OpenSSL/OpenSSH required')
class SceneCheckpointTests(unittest.TestCase):
    def run_rejected(self, callback, *, save_error=False, existing_material=False):
        import deployment_compose_scene_create_broker_v3_host as broker
        import deployment_compose_restart_checkpoint_v3_host as checkpoint
        from contextlib import ExitStack
        from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase
        calls=[]
        original=broker.SceneCreateBrokerV3.start_first_create
        def start(subject,*args,**kwargs):
            result=original(subject,*args,**kwargs)
            calls.append(True)
            return result
        original_init=LocalAcceptanceCase.__init__
        def initialize(subject,*args,**kwargs):
            original_init(subject,*args,**kwargs)
            (subject.root/'restart-material').mkdir(mode=0o700)
        with ExitStack() as stack:
            stack.enter_context(patch.object(broker.SceneCreateBrokerV3,'start_first_create',start))
            if save_error:
                stack.enter_context(patch.object(checkpoint,'save_checkpoint',side_effect=OSError('test storage failure')))
            if existing_material:
                stack.enter_context(patch.object(LocalAcceptanceCase,'__init__',initialize))
            with self.assertRaisesRegex(ValueError,'compose-scene-create-controller-v3-rejected'):
                run_case(self,scene_controller=True,checkpoint_callback=callback)
        return len(calls)

    def test_invalid_callback_and_existing_checkpoint_reject_before_dispatch(self):
        self.assertEqual(self.run_rejected(object()),0)
        self.assertEqual(self.run_rejected(lambda value:None,existing_material=True),0)

    def test_save_or_callback_failure_never_redispatches_create(self):
        notices=[]
        self.assertEqual(self.run_rejected(notices.append,save_error=True),1)
        self.assertEqual(notices,[])
        def refuse(descriptor):
            notices.append(descriptor)
            raise RuntimeError('test notification failure')
        self.assertEqual(self.run_rejected(refuse),1)
        self.assertEqual(len(notices),1)

    def test_callback_runs_detached_before_final_authenticated_reconnect(self):
        from deployment_compose_scene_create_controller_v3_host import SceneCreateControllerV3
        original=SceneCreateControllerV3._save_restart_checkpoint
        def save(subject,certificate,final,notify,left):
            def receive(descriptor):
                self.assertTrue(subject._client._closed)
                notify(descriptor)
            return original(subject,certificate,final,receive,left)
        with patch.object(SceneCreateControllerV3,'_save_restart_checkpoint',save):
            result=run_case(self,scene_controller=True,checkpoint_callback=lambda value:None)
        self.assertEqual(result['postCount'],1)

    def test_callback_changed_admission_binding_is_rejected(self):
        from deployment_compose_scene_create_controller_v3_host import SceneCreateControllerV3
        original=SceneCreateControllerV3._save_restart_checkpoint
        def save(subject,certificate,final,notify,left):
            def receive(descriptor):
                notify(descriptor)
                subject._admission._root['receiptHash']='0'*64
            return original(subject,certificate,final,receive,left)
        with patch.object(SceneCreateControllerV3,'_save_restart_checkpoint',save):
            self.assertEqual(self.run_rejected(lambda value:None),1)

    def test_native_checkpoint_callback_cold_reader_has_no_origin_or_execution(self):
        notices=[]
        def receive(descriptor):
            from pathlib import Path
            options=dict(expected_material_digest=descriptor['materialDigest'],
                expected_custody_digest=descriptor['custodyDigest'],expected_context=descriptor['context'],
                expected_witness_key_hash=descriptor['witnessKeyHash'])
            with RestartCheckpointReaderV3(Path(descriptor['casePath']),**options) as reader:
                self.assertIsNone(reader.writer_origin)
                self.assertFalse(reader.context.executionAvailable)
                self.assertFalse(reader.context.recoveryAuthorized)
                self.assertEqual(reader.context.snapshot.snapshot['chainStatus']['activeSeq'],6)
            with self.assertRaises(ValueError):
                RestartCheckpointReaderV3(Path(descriptor['casePath']),**dict(options,expected_material_digest='0'*64))
            notices.append(descriptor)
        result=run_case(self,scene_controller=True,checkpoint_callback=receive)
        self.assertEqual(result['postCount'],1)
        self.assertEqual(len(notices),1)

    def test_default_path_does_not_save(self):
        import deployment_compose_restart_checkpoint_v3_host as checkpoint
        with patch.object(checkpoint,'save_checkpoint',side_effect=AssertionError('not opted in')):
            self.assertEqual(run_case(self,scene_controller=True)['postCount'],1)
