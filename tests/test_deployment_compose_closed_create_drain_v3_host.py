"""Same-live closed-create facts; mock cleanup tests do not prove OS isolation."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests.test_deployment_compose_create_transport_v3_host import OwnedTransportIntegrationTests
import deployment_compose_create_transport_v3_host as transport
from deployment_compose_coordinator_v3_host import Profile3StepExecutor
from deployment_compose_history_v3_host import AuthenticatedHistoryV3


class CleanupStateTests(unittest.TestCase):
    def test_pending_hidden_until_each_cleanup_stage_finishes_without_reverify(self):
        for stage in ('group','stdin','stdout','tls'):
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as base:
                directory=Path(base)/'tls';directory.mkdir()
                value=object.__new__(transport.OwnedCreateTransportV3)
                value._owner=os.getpid();value._mutex=threading.RLock();value._closed=False
                value._go_sent=True;value._pending_terminal=None;value._terminal=None
                value._response_fact=(201,hashlib.sha256(b'body').hexdigest())
                value._process_proof=None;value._directory=directory
                st=directory.stat();value._directory_identity=(st.st_dev,st.st_ino)
                value._process=SimpleNamespace(returncode=-9,poll=lambda:-9,
                    stdin=SimpleNamespace(close=Mock()),stdout=SimpleNamespace(close=Mock()))
                facts=('a'*64,'b'*64,'c'*64,(1,2),123,-9)
                group=SimpleNamespace(kill_and_drain=Mock(return_value=object()),
                    capture_drain_facts=Mock(return_value=facts),close=Mock())
                value._group=group
                if stage=='group':group.close.side_effect=[ValueError('cleanup'),None]
                elif stage in ('stdin','stdout'):
                    getattr(value._process,stage).close.side_effect=[ValueError('cleanup'),None]
                real_remove=transport.shutil.rmtree
                count=[]
                def remove(path):
                    if stage=='tls' and not count:
                        count.append(True);raise ValueError('cleanup')
                    return real_remove(path)
                with patch.object(transport.shutil,'rmtree',remove):
                    with self.assertRaises(ValueError):value.close(time.monotonic()+2)
                    with self.assertRaises(ValueError):value.terminal_facts()
                    self.assertIsNotNone(value._pending_terminal)
                    value.close(time.monotonic()+2)
                self.assertEqual(value.terminal_facts(),(facts,value._response_fact))
                self.assertEqual(group.kill_and_drain.call_count,1)
                self.assertEqual(group.capture_drain_facts.call_count,1)
                self.assertFalse(directory.exists())


class ClosedCreateTests(OwnedTransportIntegrationTests):
    def test_same_live_record_and_identity_history_rejection(self):
        captured=[];initialize=Profile3StepExecutor.__init__
        def init(executor,*args,**kw):
            initialize(executor,*args,**kw);captured.append(executor)
        with patch.object(Profile3StepExecutor,'__init__',init):
            super().test_actual_owned_first_create_tls_and_closed_history()
        executor=captured[0]
        history=AuthenticatedHistoryV3(executor.bundle,executor.request,
            gate_policy=executor._policy,gate_key=executor._key,
            consumption_receipt_hash=executor._receipt,witness_client=executor._client,
            witness_client_factory=executor._factory)
        record=executor.capture_owned_closed_create(history)
        result=executor.verify_owned_closed_create(record,history)
        self.assertEqual(set(result),{'digest','authorityGranted','runtimePermit','recoveryAuthorized','productionReady'})
        self.assertTrue(all(result[k] is False for k in result if k!='digest'))
        copied_issuer=copy.copy(executor)
        with self.assertRaises(ValueError):copied_issuer.capture_owned_closed_create(history)
        with self.assertRaises(ValueError):copied_issuer.verify_owned_closed_create(record,history)
        for fake in (object(),copy.copy(record),{'digest':result['digest']}):
            with self.assertRaises(ValueError):executor.verify_owned_closed_create(fake,history)
        for field,value in (('_receipt','e'*64),('_binding',dict(executor._binding,epoch='e'*64))):
            original=getattr(executor,field);setattr(executor,field,value)
            try:
                with self.assertRaises(ValueError):executor.verify_owned_closed_create(record,history)
            finally:setattr(executor,field,original)
        with patch.object(history,'capture',side_effect=ValueError('signature')):
            with self.assertRaises(ValueError):executor.verify_owned_closed_create(record,history)
        self.assertEqual(executor.verify_owned_closed_create(record,history),result)
        epoch=executor._owned_transport._group.actor_epoch
        executor._owned_transport._group.actor_epoch='e'*64
        try:
            with self.assertRaises(ValueError):executor.verify_owned_closed_create(record,history)
        finally:executor._owned_transport._group.actor_epoch=epoch
        snapshot=history.capture()
        malformed=json.loads(snapshot.canonical)
        malformed['receiptMap']={executor.bundle.creation_operations()[0]['service']:'invalid'}
        from deployment_compose_history_v3_host import AuthenticatedHistorySnapshotV3
        from deployment_compose_coordinator_v3_host import canonical
        with patch.object(history,'capture',return_value=AuthenticatedHistorySnapshotV3(canonical(malformed))):
            with self.assertRaises(ValueError):executor.verify_owned_closed_create(record,history)
        # A genuine signed successor makes this historical one-scope record stale.
        operations=executor.bundle.resolve_operations(json.loads(snapshot.canonical)['receiptMap'])
        desc=executor.scope_descriptor(executor.bundle,executor.request,executor._receipt,
            operations[1],1,json.loads(snapshot.canonical)['receiptMap'])
        binding=dict(executor._binding,generation=desc['generation'],scopeHash=desc['scopeHash'])
        executor._client.transition_successor(expected_seq=6,expected_head=json.loads(snapshot.canonical)['closedTail']['head'],childBinding=binding)
        with self.assertRaises(ValueError):executor.verify_owned_closed_create(record,history)

    def _assert_no_record_after_negative(self, method):
        captured=[];initialize=Profile3StepExecutor.__init__
        def init(executor,*args,**kw):
            initialize(executor,*args,**kw);captured.append(executor)
        with patch.object(Profile3StepExecutor,'__init__',init):
            method()
        executor=captured[0]
        history=AuthenticatedHistoryV3(executor.bundle,executor.request,
            gate_policy=executor._policy,gate_key=executor._key,
            consumption_receipt_hash=executor._receipt,
            witness_client=executor._factory(executor._binding),witness_client_factory=executor._factory)
        with self.assertRaises(ValueError):executor.capture_owned_closed_create(history)
        self.assertIsNone(executor._owned_transport._terminal)

    def test_wrong_pin_cannot_create_closed_record(self):
        self._assert_no_record_after_negative(super().test_wrong_tls_pin_drains_process_but_never_closes_product_scope)

    def test_lost_response_cannot_create_closed_record(self):
        self._assert_no_record_after_negative(super().test_lost_actor_response_stays_nonclosed_after_process_and_gateway_drain)


def load_tests(loader,tests,pattern):
    return unittest.TestSuite(cls(name) for cls in (CleanupStateTests,ClosedCreateTests)
        for name in cls.__dict__ if name.startswith('test_'))
