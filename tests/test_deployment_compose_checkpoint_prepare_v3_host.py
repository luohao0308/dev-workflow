"""Checkpoint-backed draft requests: real crypto/CAS/Unix HTTP, explicit host doubles."""
from copy import copy, deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import pickle
import shutil
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_live_phase_v3_host as live_fixture
from tests.support import compose_live_phase_fixture as process_fixture
from tests.support.compose_restart_material_fixture import GATE_KEY
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_witness_store import canonical
import deployment_compose_checkpoint_prepare_v3_host as checkpoint
from deployment_compose_recovery_capsule_v3_host import verify_recovery_capsule
from deployment_compose_approval_v3_host import GitHubFullBodyApprovalV3


def expiry():
    return (datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class CheckpointPreparationTests(unittest.TestCase):
    identity=live_fixture.LivePhaseTests.identity
    ticks=live_fixture.LivePhaseTests.ticks
    command=live_fixture.LivePhaseTests.command
    stopped=live_fixture.LivePhaseTests.stopped
    make_capture=live_fixture.LivePhaseTests.make_capture

    def setUp(self):
        live_fixture.LivePhaseTests.setUp(self)
        self.material=self.case.material()
        self.pins=self.case.expected_context()
        self.output_root=self.root/'fresh-cas';self.output_root.mkdir(mode=0o700)
        self.output=ComposeRecoveryStore(str(self.output_root.resolve()),key=b'n'*32)
        self.addCleanup(self.output.close)
        self.host=self.make_host()

    def make_host(self,**changes):
        args=dict(restart_material=self.material,expected_material_digest=hashlib.sha256(self.material).hexdigest(),
            expected_context=self.pins,gate_key=GATE_KEY,witness_public_key=self.case.public,
            witness_transport=self.case.transport,daemon=self.observer,expected_version=self.case.version,
            store=self.output)
        args.update(changes)
        return checkpoint.CheckpointRecoveryPreparationHostV3(**args)

    def prepare(self,**changes):
        args=dict(operation_nonce='b'*64,expires_at=expiry());args.update(changes)
        return self.host.prepare_intent(**args)

    def verify(self,prepared,**changes):
        args=dict(reference=prepared['recovery_context_reference'],request=prepared['request'],
            reviewed_history=prepared['reviewed_history']);args.update(changes)
        return self.host.verify_context(**args)

    def test_new_request_uses_authenticated_checkpoint_without_old_archive_cas(self):
        old=self.case.archive_store;old.close()
        before=(self.case.store.root/'state.json').read_bytes()
        with patch.object(old,'get',side_effect=AssertionError('old archive must not be read')):
            prepared=self.prepare();context=self.verify(prepared)
        request=prepared['request'];original=self.case.req
        self.assertEqual(context['kind'],'compose-checkpoint-recovery-context-v3')
        self.assertEqual(request.profile_id,'compose-checkpoint-recovery-intent-v3')
        self.assertEqual(request,replace(original,operation='recovery',profile_id=request.profile_id,
            history_hash=prepared['reviewed_history'].digest,observation_hash=hashlib.sha256(canonical(context)).hexdigest(),
            expires_at=request.expires_at))
        self.assertEqual(self.output.get(context['checkpointBaselineReference']),self.case.baseline_bytes)
        self.assertNotIn('baselineStateReference',context)
        self.assertEqual(context['checkpointMaterialDigest'],hashlib.sha256(self.material).hexdigest())
        self.assertEqual(context['receiptMap'],{'web':'a'*64})
        self.assertEqual(context['startWriteIndex'],1)
        self.assertEqual(context['nextOperation']['phase'],'stop')
        self.assertEqual(context['knownWritePrefix'],self.case.bundle.creation_operations())
        self.assertEqual(original.expires_at,'2020-01-01T00:00:00Z')
        self.assertEqual(before,(self.case.store.root/'state.json').read_bytes())
        for name in ('approvalReady','sourceRevalidated','writerQuiescenceVerified','daemonContinuityVerified',
                'authorityGranted','executionAvailable','runtimePermit','recoveryAuthorized','productionReady'):
            self.assertIs(prepared['review'][name],False)
        self.assertTrue(prepared['review']['blockers'])
        self.assertNotIn('Env',json.dumps(prepared['review']))
        self.assertNotIn(str(self.root),json.dumps(prepared['review']))

    def test_new_profile_and_context_are_rejected_by_legacy_approval_and_capsule(self):
        prepared=self.prepare();request=prepared['request']
        approval=object.__new__(GitHubFullBodyApprovalV3)
        approval._requests={request.digest():request}
        approval.policy=SimpleNamespace(operation='recovery',profile_version='3')
        with self.assertRaises(Exception):approval._match(request)
        original=self.case.req
        capsule=canonical(dict(request=asdict(request),context=json.loads(self.output.get(prepared['recovery_context_reference']))))
        with self.assertRaises(ValueError):
            verify_recovery_capsule(capsule,original_history=self.case.history(),expected_source=original.source,
                expected_host_id=original.host_id,expected_daemon_id=original.daemon_id,
                expected_target=original.target,expected_policy_hash=original.policy_hash)

    def test_all_external_material_context_and_key_pins_are_required(self):
        for changes in (dict(expected_material_digest='0'*64),dict(gate_key=b'z'*32),
                dict(witness_public_key=b'invalid'),dict(store=SimpleNamespace()),dict(daemon=SimpleNamespace()),
                dict(restart_material=SimpleNamespace())):
            with self.subTest(changes=tuple(changes)),self.assertRaises(ValueError):self.make_host(**changes)
        for key in self.pins:
            pins=dict(self.pins,**{key:'9'*(40 if key=='sourceSha' else 64)})
            with self.subTest(pin=key),self.assertRaises(ValueError):self.make_host(expected_context=pins)

    def test_rehashed_receipt_phase_endpoint_and_baseline_context_reject(self):
        prepared=self.prepare();original=json.loads(self.output.get(prepared['recovery_context_reference']))
        for field,value in (('receiptMap',{'web':'c'*64}),('startWriteIndex',True),('checkpointMaterialDigest','c'*64),
                ('checkpointBaselineReference','c'*64),('baselineStateDigest','c'*64),('currentPhaseSnapshot',{}),
                ('liveEndpointBinding',{}),('normalizationVersion',{'Version':'new','GitCommit':'other'}),
                ('nextOperation',{}),('kind','compose-recovery-context-v3'),('schemaVersion',True)):
            context=deepcopy(original);context[field]=value;raw=canonical(context)
            reference=self.output.put(raw);request=replace(prepared['request'],observation_hash=hashlib.sha256(raw).hexdigest())
            with self.subTest(field=field),self.assertRaises(ValueError):self.verify(prepared,reference=reference,request=request)

    def test_request_identity_and_history_snapshot_cannot_be_changed(self):
        prepared=self.prepare()
        for changes in (dict(after_hash='c'*64),dict(policy_hash='c'*64),dict(profile_id=self.case.req.profile_id),
                dict(source=replace(self.case.req.source,source_sha='c'*40)),dict(history_hash='c'*64)):
            with self.subTest(changes=tuple(changes)),self.assertRaises(ValueError):
                self.verify(prepared,request=replace(prepared['request'],**changes))
        from deployment_compose_history_v3_host import AuthenticatedHistorySnapshotV3
        forged=json.loads(prepared['reviewed_history'].canonical);forged['receiptMap']['web']='c'*64
        with self.assertRaises(ValueError):self.verify(prepared,reviewed_history=AuthenticatedHistorySnapshotV3(canonical(forged)))

    def test_baseline_and_context_cas_damage_fail_without_repair(self):
        prepared=self.prepare();reference=prepared['recovery_context_reference']
        context=json.loads(self.output.get(reference));baseline=context['checkpointBaselineReference']
        file=self.output_root/baseline;raw=file.read_bytes();file.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):self.verify(prepared)
        self.assertEqual(file.read_bytes(),b'corrupt')
        file.write_bytes(raw);context_file=self.output_root/reference;context_file.write_bytes(b'corrupt-context')
        with self.assertRaises(ValueError):self.verify(prepared)
        self.assertEqual(context_file.read_bytes(),b'corrupt-context')

    def test_current_engine_drift_or_history_advance_blocks_verified_intent(self):
        prepared=self.prepare();self.case.rows['a'*64]['Config']['Env'].append('CHANGED=secret')
        with self.assertRaises(ValueError):self.verify(prepared)
        self.case.rows['a'*64]['Config']['Env'].pop()
        self.case.index=1;self.case.open_scope()
        with self.assertRaises(ValueError):self.verify(prepared)
        with self.assertRaises(ValueError):self.prepare()

    def test_expired_excessive_or_original_nonce_and_invalid_deadline_reject(self):
        for changes in (dict(expires_at='2020-01-01T00:00:00Z'),dict(expires_at='2099-01-01T00:00:00Z'),
                dict(operation_nonce='bad'),dict(operation_nonce=self.case.bundle.to_dict()['operationNonce']),
                dict(timeout=True),dict(timeout=0),dict(timeout=float('nan')),dict(timeout=31)):
            with self.subTest(changes=changes),self.assertRaises(ValueError):self.prepare(**changes)

    def test_copy_pickle_fork_thread_and_store_replacement_reject(self):
        for clone in (copy,deepcopy,pickle.dumps):
            with self.subTest(clone=clone.__name__),self.assertRaises(ValueError):clone(self.host)
        import threading
        errors=[]
        def foreign():
            try:self.prepare()
            except Exception:errors.append(True)
        thread=threading.Thread(target=foreign);thread.start();thread.join(timeout=5)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[True])
        with patch.object(checkpoint.os,'getpid',return_value=os.getpid()+1):
            with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(self.verify(self.prepare())['startWriteIndex'],1)

    def test_failed_private_publication_never_returns_success_or_mutates_witness(self):
        before=(self.case.store.root/'state.json').read_bytes()
        with patch.object(self.output,'put',side_effect=OSError('fsync failed')):
            with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(before,(self.case.store.root/'state.json').read_bytes())

    def test_default_nonce_is_new_and_verify_writes_nothing(self):
        first=self.host.prepare_intent(expires_at=expiry())
        second=self.host.prepare_intent(expires_at=first['request'].expires_at)
        one=json.loads(self.output.get(first['recovery_context_reference']))
        two=json.loads(self.output.get(second['recovery_context_reference']))
        self.assertNotEqual(one['recoveryNonce'],two['recoveryNonce'])
        self.assertNotEqual(first['request'].digest(),second['request'].digest())
        self.assertNotEqual(one['recoveryNonce'],self.case.bundle.to_dict()['operationNonce'])
        with patch.object(self.output,'put',side_effect=AssertionError('verify may not write')):
            self.assertEqual(self.verify(first),one)
        self.assertEqual(first['review']['requestProfileId'],checkpoint.PROFILE)
        self.assertEqual(first['review']['originalBundleProfileId'],self.case.req.profile_id)

    def test_exited_producer_fresh_consumer_prepares_in_new_private_cas(self):
        directory=self.root/'handoff';directory.mkdir(mode=0o700)
        pins=dict(expectedDigest=hashlib.sha256(self.material).hexdigest(),expectedContext=self.pins)
        for name,raw in (('material.private.json',self.material),('pins.private.json',canonical(pins)),
                ('witness.pub',self.case.public)):
            process_fixture.record(directory/name,raw)
        socket_path=self.root/'witness.sock'
        server,thread,rpc=process_fixture.start_witness_server(self.case,socket_path)
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=3)))
        config=dict(daemonRoot=str(self.root),cgroupRoot=str(self.cg),unit=self.unit,pid=self.pid,
            main=self.main,invocation=self.invocation,witnessSocket=str(socket_path))
        process_fixture.record(directory/'config.private.json',canonical(config))
        before=(self.case.store.root/'state.json').read_bytes()
        script=Path(process_fixture.__file__)
        producer=subprocess.run([sys.executable,str(script),'produce',str(directory)],
            capture_output=True,text=True,timeout=30)
        self.assertEqual(producer.returncode,0,producer.stderr)
        first=json.loads(producer.stdout)
        # The original archive CAS is closed; only authenticated material crosses.
        self.case.archive_store.close()
        consumer=subprocess.run([sys.executable,str(script),'prepare',str(directory)],
            capture_output=True,text=True,timeout=30)
        self.assertEqual(consumer.returncode,0,consumer.stderr)
        second=json.loads(consumer.stdout)
        self.assertNotEqual(first['producerPid'],second['consumerPid'])
        self.assertTrue(second['summary']['verified'])
        self.assertEqual(second['summary']['requestProfileId'],checkpoint.PROFILE)
        self.assertEqual(second['summary']['contextKind'],checkpoint.KIND)
        self.assertFalse(second['summary']['approvalReady']);self.assertFalse(second['summary']['runtimePermit'])
        self.assertEqual(before,(self.case.store.root/'state.json').read_bytes())
        self.assertTrue(rpc);self.assertTrue(set(rpc)<=process_fixture.READS)
        self.assertFalse(second['signingPrivateKeyReceived'])
        self.assertFalse(second['witnessStoreKeyReceived'])
        self.assertTrue((directory/'draft-cas').is_dir())

    def test_instance_capture_callback_is_not_accepted_as_live_evidence(self):
        fake=unittest.mock.Mock(side_effect=AssertionError('instance callback must not run'))
        self.host._capture.capture=fake
        prepared=self.prepare()
        fake.assert_not_called()
        self.assertEqual(self.verify(prepared)['currentPhaseSnapshot']['rows'].keys(),self.case.rows.keys())
        self.assertGreaterEqual(self.http.count('/v1.45/version'),2)

    def test_original_store_context_and_capture_cannot_be_replaced(self):
        for name in ('_store','_context','_capture'):
            old=getattr(self.host,name);setattr(self.host,name,SimpleNamespace())
            with self.subTest(name=name),self.assertRaises(ValueError):self.prepare()
            setattr(self.host,name,old)
        old=self.output._key;self.output._key=b'z'*32
        with self.assertRaises(ValueError):self.prepare()
        self.output._key=old
        self.assertEqual(self.verify(self.prepare())['startWriteIndex'],1)

    def test_expiry_during_live_reads_and_shared_prepare_budget_reject(self):
        now=datetime.now(timezone.utc);advanced=[]
        def change(path):
            if path=='/v1.45/version':advanced.append(True)
        self.on_request=change
        clock=SimpleNamespace(now=lambda _:now+timedelta(hours=2) if advanced else now)
        with patch.object(checkpoint,'datetime',clock),self.assertRaises(ValueError):self.prepare()
        self.on_request=None
        calls=[];capture=checkpoint.LiveRecoveryPhaseCaptureV3.capture
        def record(instance,timeout=15):
            calls.append(timeout);return capture(instance,timeout=timeout)
        with patch.object(checkpoint.LiveRecoveryPhaseCaptureV3,'capture',record):self.prepare(timeout=15)
        self.assertEqual(len(calls),2)
        self.assertGreater(calls[0],calls[1]);self.assertLess(calls[0],15)
