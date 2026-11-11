"""Native slot state machine; unit start/stop and cold kernel observation are doubles."""
from copy import copy,deepcopy
import hashlib
import os
import pickle
import secrets
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_scene_writer_slot_v3_host as slot
from deployment_compose_witness_store import canonical


class FakeUnit:
    instances=[];fail_start=False;fail_stop=False
    def __init__(self,archive_digest,source_sha):
        self.source=source_sha;self.archive=archive_digest;self.calls=[];self.unit='dw-writer-host-'+secrets.token_hex(8)+'.service'
        self.instances.append(self)
    def start(self,**kwargs):
        self.calls.append('start')
        if self.fail_start:raise RuntimeError('uncertain-start')
    def capture_origin(self,**kwargs):
        self.calls.append('origin')
        return canonical(dict(schemaVersion=1,kind='compose-owned-writer-origin-v3',sourceSha=self.source,archiveDigest=self.archive,
            unit=self.unit,kernelBoot='11111111-1111-1111-1111-111111111111',invocationId='b'*32,mainPid=os.getpid(),
            mainStartTicks=1,cgroupDevice=1,cgroupInode=1,parentDevice=1,parentInode=1,pidNamespaceDevice=1,pidNamespaceInode=1))
    def stop(self,**kwargs):
        self.calls.append('stop')
        if self.fail_stop:raise RuntimeError('uncertain-stop')
    def close(self):self.calls.append('close')


class SlotTests(unittest.TestCase):
    def setUp(self):
        FakeUnit.instances=[];FakeUnit.fail_start=False;FakeUnit.fail_stop=False
        self.patch=patch.object(slot,'OwnedRecoveryUnitV3',FakeUnit);self.patch.start();self.addCleanup(self.patch.stop)
        def observed(raw,**kwargs):
            self.assertEqual(kwargs['expected_digest'],hashlib.sha256(raw).hexdigest())
            return SimpleNamespace(writerStoppedObserved=True,observation_digest='c'*64)
        self.observe=patch.object(slot,'observe_stopped_writer',side_effect=observed);self.observer=self.observe.start();self.addCleanup(self.observe.stop)
        self.subject=slot.SlotOwnerV3('a'*40,'b'*64)

    def test_service_owns_single_slot_and_requires_drain_before_next_generation(self):
        first=self.subject.reserve(0);self.assertEqual(first['slotGeneration'],1)
        original=FakeUnit.instances[0]
        with self.assertRaises(ValueError):self.subject.reserve(1)
        self.assertEqual(len(FakeUnit.instances),1)
        stopped=self.subject.drain(1);self.assertTrue(stopped['slotStoppedObserved'])
        self.assertEqual(self.subject.drain(1),stopped)
        self.assertEqual(original.calls,['start','origin','stop','close'])
        second=self.subject.reserve(1)
        self.assertEqual(second['slotGeneration'],2);self.assertNotEqual(first['writerOrigin']['unit'],second['writerOrigin']['unit'])
        self.assertFalse(second['runtimePermit']);self.assertFalse(second['writerQuiescenceVerified'])
        self.subject.drain(2)

    def test_unknown_creation_blocks_replacement_and_cannot_mint_drain_proof(self):
        FakeUnit.fail_start=True
        with self.assertRaises(RuntimeError):self.subject.reserve(0)
        self.assertTrue(self.subject.status()['creationOutcomeUnknown'])
        for generation in (0,1):
            with self.assertRaises(ValueError):self.subject.reserve(generation)
        with self.assertRaises(ValueError):self.subject.drain(1)
        self.assertNotIn('close',FakeUnit.instances[0].calls)
        self.assertEqual(len(FakeUnit.instances),1)

    def test_failed_cold_observation_never_allows_replacement(self):
        self.subject.reserve(0)
        with patch.object(slot,'observe_stopped_writer',side_effect=ValueError('still-live')):
            with self.assertRaises(ValueError):self.subject.drain(1)
        with self.assertRaises(ValueError):self.subject.reserve(1)
        self.assertNotIn('close',FakeUnit.instances[0].calls)
        self.assertEqual(self.subject.status()['slotState'],'failed')
        self.subject.drain(1);self.assertEqual(FakeUnit.instances[0].calls.count('close'),1)

    def test_stale_or_boolean_generation_copy_and_foreign_issuer_reject(self):
        for generation in (True,-1,1,1.0):
            with self.assertRaises(ValueError):self.subject.reserve(generation)
        for clone in (copy,deepcopy,pickle.dumps):
            with self.assertRaises(ValueError):clone(self.subject)
        with patch.object(slot.os,'getpid',return_value=os.getpid()+1):
            with self.assertRaises(ValueError):self.subject.status()
        self.assertEqual(self.subject.status()['slotGeneration'],0)
