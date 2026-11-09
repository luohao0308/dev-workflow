"""Native lifecycle binding with real SDK/Gate/CAS and synthetic kernel seams.

These tests validate registration association and fresh observer calls. They do
not claim native kernel acceptance, a global writer fence or source attestation.
"""
from copy import copy, deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import Mock, patch

from tests import test_deployment_compose_cold_recovery_v3_host as sdk
from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
from deployment_compose_image_defaults import ZERO_DEFAULTS
from deployment_compose_witness_store import canonical
from deployment_compose_cold_writer_v3_host import StoppedWriterObservationV3
import deployment_compose_native_writer_lifecycle_v3_host as native


SOURCE = 'c'*40
ARCHIVE = '7'*64


def origin():
    return canonical(dict(schemaVersion=1,kind='compose-owned-writer-origin-v3',sourceSha=SOURCE,archiveDigest=ARCHIVE,
        unit='dw-writer-host-'+'1'*16+'.service',kernelBoot='11111111-1111-1111-1111-111111111111',
        invocationId='2'*32,mainPid=os.getpid(),mainStartTicks=123,cgroupDevice=1,cgroupInode=2,
        parentDevice=1,parentInode=3,pidNamespaceDevice=1,pidNamespaceInode=4))


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),'POSIX/OpenSSH/TLS required')
class NativeLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sdk.ColdRecoveryTests.setUpClass()
        cls.capture_patch = patch.object(native,'_capture_current_origin',return_value=origin())
        cls.capture = cls.capture_patch.start()
        cls.fixture = cls.partial_host()
        helper, host, lifecycle, _ = cls.fixture
        cls.maps = cls.checkpoint_maps(host)
        cls.descriptor = host.capture_native_checkpoint(**cls.maps)

    @classmethod
    def tearDownClass(cls):
        cls.fixture[0].doCleanups()
        cls.capture_patch.stop()
        sdk.ColdRecoveryTests.tearDownClass()

    @staticmethod
    def partial_host(attack='readiness-failure', *, writer_source_sha=SOURCE, writer_archive_digest=ARCHIVE, allowed_engine_root=None):
        helper = sdk.ColdRecoveryTests('test_failed_readiness_retains_inspectable_closed_history')
        helper.setUp()
        saved = []
        original = ColdRecoveryHostV3
        def construct(*args,**kwargs):
            if allowed_engine_root is not None and not Path(kwargs['docker_socket']).resolve().is_relative_to(Path(allowed_engine_root).resolve()):
                raise ValueError('diagnostic Engine must be inside original private root')
            lifecycle = native.NativeWriterLifecycleV3(writer_source_sha=writer_source_sha,writer_archive_digest=writer_archive_digest,store=kwargs['store'])
            host = original(*args,**kwargs,native_lifecycle=lifecycle)
            saved.append((host,lifecycle,(args,kwargs)))
            return host
        try:
            if allowed_engine_root is not None and not helper.root.resolve().is_relative_to(Path(allowed_engine_root).resolve()):
                raise ValueError('diagnostic fixture root must be private')
            with patch.object(sdk,'ColdRecoveryHostV3',side_effect=construct):
                helper.run_case(attack)
        except BaseException:
            helper.doCleanups()
            raise
        host,lifecycle,args = saved[0]
        return helper,host,lifecycle,args

    @staticmethod
    def checkpoint_maps(host):
        history = host.inspect_history()
        baselines,defaults = {},{}
        current = history
        while current is not None:
            bundle = current._bundle
            baselines[bundle.digest] = host._store.get(bundle.to_dict()['baselineStateReference'])
            defaults[bundle.digest] = {service['name']:deepcopy(ZERO_DEFAULTS) for service in bundle.to_dict()['services']}
            current = current._parent
        return dict(baseline_bytes_by_bundle=baselines,authenticated_image_defaults_by_bundle=defaults,archive_digest='9'*64)

    def load(self,descriptor=None):
        _,host,_,_ = self.fixture
        return native.load_native_checkpoint(self.descriptor if descriptor is None else descriptor,
            store=host._store,gate_key=b'g'*32,pub=host._public,readonly_transport=host._reader.history._client._transport)

    def consumer(self,observer=None,descriptor=None):
        _,old,_,(_,kwargs) = self.fixture
        descriptor = self.descriptor if descriptor is None else descriptor
        options = dict(kwargs)
        options.pop('native_lifecycle',None)
        options['native_stop_observer'] = observer
        return ColdRecoveryHostV3(old._store.get(descriptor['materialReference']),
            **dict(options,expected_digest=descriptor['materialDigest'],expected_context=descriptor['context']))

    def test_native_preflight_failure_does_not_consume_approval(self):
        helper = sdk.ColdRecoveryTests('test_active_writer_rejects_before_cas')
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        original = ColdRecoveryHostV3
        seen = []
        def construct(*args,**kwargs):
            lifecycle = native.NativeWriterLifecycleV3(writer_source_sha=SOURCE,writer_archive_digest=ARCHIVE,store=kwargs['store'])
            host = original(*args,**kwargs,native_lifecycle=lifecycle)
            execute = host.execute
            def observe_execute(approval, **options):
                with patch.object(approval,'consume',wraps=approval.consume) as consume:
                    try:
                        return execute(approval,**options)
                    finally:
                        consume.assert_not_called()
                        seen.append(True)
            host.execute = observe_execute
            return host
        with patch.object(sdk,'ColdRecoveryHostV3',side_effect=construct),patch.object(
                native,'_capture_current_origin',side_effect=ValueError('not the current root managed writer')):
            helper.run_case('active-writer')
        self.assertEqual(seen,[True,True])

    def test_record_is_exact_registered_partial_child_with_separate_writer_source(self):
        _,host,_,_ = self.fixture
        record = json.loads(host._store.get(self.descriptor['recordReference']))
        child = host.inspect_history()
        self.assertEqual(record['requestHash'],child._request.digest())
        self.assertEqual(record['receiptHash'],child._receipt)
        self.assertEqual(record['firstBinding'],child._client.binding)
        self.assertEqual(record['writeIndex'],9)
        self.assertEqual(record['writerSourceSha'],SOURCE)
        self.assertNotEqual(record['writerSourceSha'],record['context']['sourceSha'])
        self.assertEqual(record['origin']['mainPid'],os.getpid())
        self.assertFalse(record['sourceRevalidated'])
        for key in native._FLAGS:
            self.assertIs(record[key],False)
        self.assertNotIn('gate_key',record)
        self.load()

    def test_unissued_host_flags_and_registration_cannot_mint_pair(self):
        _,host,lifecycle,_ = self.fixture
        forged = object.__new__(ColdRecoveryHostV3)
        forged._owner = (os.getpid(),__import__('threading').get_ident())
        forged._issuer = forged
        forged._native_lifecycle = lifecycle
        forged._native_executing = True
        forged._state = 'spent'
        with self.assertRaises(ValueError):
            lifecycle.begin(forged)
        with self.assertRaises(ValueError):
            lifecycle.begin(host)
        with self.assertRaises(ValueError):
            lifecycle.attach(native.NativeWriterRegistrationV3(),host)
        with self.assertRaises(ValueError):
            lifecycle.capture_checkpoint(native.NativeWriterRegistrationV3(),host,**self.maps)

    def test_observer_always_calls_fresh_native_checker_and_binds_subject(self):
        observer = self.load()
        host = self.consumer(observer)
        result = StoppedWriterObservationV3(self.descriptor['originDigest'],'e'*64,b'[]')
        with patch.object(native.cold,'observe_stopped_writer',side_effect=[result,ValueError('writer reappeared')]) as observe:
            self.assertIs(observer.observe_for(host),result)
            with self.assertRaises(ValueError):
                observer.observe_for(host)
            self.assertEqual(observe.call_count,2)
            self.assertEqual(observe.call_args.kwargs['expected_source_sha'],SOURCE)
        with self.assertRaises(ValueError):
            self.consumer(copy(observer))
        with self.assertRaises(ValueError):
            self.consumer(object.__new__(native.NativeCheckpointStopObserver))

    def test_unissued_and_method_shadow_native_objects_cannot_replace_checks(self):
        _,host,lifecycle,(_,kwargs) = self.fixture
        fake_lifecycle = object.__new__(native.NativeWriterLifecycleV3)
        fake_observer = object.__new__(native.NativeCheckpointStopObserver)
        for obj,method in ((fake_lifecycle,'_owned'),(fake_lifecycle,'begin'),
                           (fake_observer,'_owned'),(fake_observer,'observe_for'),
                           (lifecycle,'begin'),(self.load(),'observe_for')):
            with self.subTest(method=method),self.assertRaises(AttributeError):
                setattr(obj,method,lambda *args:True)
        with self.assertRaises(ValueError):
            native.NativeWriterLifecycleV3._owned(fake_lifecycle)
        with self.assertRaises(ValueError):
            self.consumer(fake_observer)
        options = dict(kwargs,native_lifecycle=fake_lifecycle)
        with self.assertRaises(ValueError):
            ColdRecoveryHostV3(b'{}',**options)

    def test_native_failure_blocks_preparation_and_engine_writes(self):
        observer = self.load()
        host = self.consumer(observer)
        helper,_,_,_ = self.fixture
        before = len(helper.engine_writes)
        with patch.object(native.cold,'observe_stopped_writer',side_effect=ValueError('active or reused PID')) as observe:
            for _ in range(2):
                with self.assertRaises(ValueError):
                    host.prepare_intent(operation_nonce='8'*64,expires_at=sdk.expiry())
            self.assertEqual(observe.call_count,1)
        self.assertEqual(len(helper.engine_writes),before)

    def test_rehashed_record_binding_forgery_is_rejected(self):
        _,host,_,_ = self.fixture
        original = json.loads(host._store.get(self.descriptor['recordReference']))
        for key,value in (('receiptHash','e'*64),('requestHash','e'*64),('bundleDigest','e'*64),
                          ('writeIndex',True),('writerSourceSha','b'*40),('sourceRevalidated',True)):
            record = dict(original,**{key:value})
            raw = canonical(record)
            descriptor = dict(self.descriptor,recordReference=host._store.put(raw),recordDigest=hashlib.sha256(raw).hexdigest())
            if key=='writerSourceSha':
                descriptor[key] = value
            with self.subTest(key=key),self.assertRaises(ValueError):
                self.load(descriptor)
        record = deepcopy(original)
        record['closedTail']['head'] = 'e'*64
        raw = canonical(record)
        with self.assertRaises(ValueError):
            self.load(dict(self.descriptor,recordReference=host._store.put(raw),recordDigest=hashlib.sha256(raw).hexdigest()))

    def test_checkpoint_cannot_republish_or_publish_during_execution(self):
        _,host,lifecycle,_ = self.fixture
        with patch.object(host._store,'put',side_effect=AssertionError('duplicate publish reached CAS')) as put:
            with self.assertRaises(ValueError):
                host.capture_native_checkpoint(**self.maps)
            put.assert_not_called()
        with patch.object(host,'_native_executing',True):
            with self.assertRaises(ValueError):
                host.capture_native_checkpoint(**self.maps)

    def test_native_finish_failure_preserves_primary_and_blocks_checkpoint(self):
        with patch.object(native.NativeWriterLifecycleV3,'finish',side_effect=OSError('native finish failed')):
            helper,host,_,_ = self.partial_host()
        self.addCleanup(helper.doCleanups)
        self.assertEqual(host._state,'spent')
        self.assertFalse(native._REGISTRATIONS[host._native_registration]['finished'])
        with self.assertRaises(ValueError):
            host.capture_native_checkpoint(**self.checkpoint_maps(host))

    def test_partial_publish_and_origin_drift_never_return_descriptor(self):
        for fail in ('write','origin'):
            with self.subTest(fail=fail):
                helper,host,_,_ = self.partial_host()
                self.addCleanup(helper.doCleanups)
                data = self.checkpoint_maps(host)
                if fail=='write':
                    original_put = host._store.put
                    calls = 0
                    def put(raw):
                        nonlocal calls
                        calls += 1
                        if calls==2:
                            raise OSError('publication interrupted')
                        return original_put(raw)
                    with patch.object(host._store,'put',side_effect=put),self.assertRaises(OSError):
                        host.capture_native_checkpoint(**data)
                    self.assertEqual(calls,2)
                else:
                    changed = dict(json.loads(origin()),invocationId='3'*32)
                    with patch.object(native,'_capture_current_origin',side_effect=[origin(),canonical(changed)]),self.assertRaises(ValueError):
                        host.capture_native_checkpoint(**data)
                with self.assertRaises(ValueError):
                    host.capture_native_checkpoint(**data)
