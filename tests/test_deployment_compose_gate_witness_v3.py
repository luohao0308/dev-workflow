"""Real signed full-envelope integration; no Docker or production authority."""
import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_operation_witness_client_v3 as signed
from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
from deployment_gate_witness import opening_scope
import deployment_gateway as gateway

H = 'a' * 64
EMPTY = hashlib.sha256(b'').hexdigest()
RENAME = '/v1.45/containers/' + H + '/rename?name=project-web-1'


class GateFixture:
    sign = signed.SignedOperationWitnessTests.sign
    transport = signed.SignedOperationWitnessTests.transport

    def setup_gate_fixture(self, path=RENAME):
        signed.SignedOperationWitnessTests.setUp(self)
        self.gen='1'*64; self.request='2'*64; self.receipt='3'*64; self.cert='4'*64
        self.source='5'*64; self.body=b'{}' if '/create?' in path else b''
        self.ops=(('POST',path,hashlib.sha256(self.body).hexdigest()),)
        scope=opening_scope(self.gen,self.request,self.receipt,self.ops,self.source)
        self.policy=gateway.GatePolicy('v3-store','v3-key',H,self.cert,True,scope,
            self.client.key_hash,operation_profile='compose-v3')
        self.binding=dict(scopeHash=scope,epoch='6'*64,generation=self.gen,policyHash=self.policy.identity_hash())
        # A new independent scope is registered exactly once in this local fixture.
        (self.root/'gate-witness').mkdir(mode=0o700)
        self.store=signed.OperationWitnessStoreV3(self.root/'gate-witness',key=b'w'*32)
        self.addCleanup(self.store.close); self.store.register_once(self.binding)
        self.client=signed.OperationWitnessClientV3(self.binding,self.public,self.transport)
        self.adapter=GateOperationWitnessAdapterV3(self.client)
        patcher=patch.object(sys,'platform','linux');patcher.start();self.addCleanup(patcher.stop)

    def gate(self):
        return gateway.FileWriterGate(self.policy,self.root/'gate',key=b'g'*32,witness=self.adapter)

    def opening(self,gate,**kw):
        args=dict(generation=self.gen,request_hash=self.request,receipt_hash=self.receipt,
                  operations=self.ops,source_context_digest=self.source)
        args.update(kw)
        return gate.open_generation(**args)

    def admitted(self,gate):
        session=self.opening(gate)
        attempt=session.prepare_attempt(*self.ops[0][:2],self.body)
        ticket=gate.admit(self.gen,attempt.ref,method=attempt.method,path=attempt.path,
                          body=self.body,writer_certificate_sha256=self.cert)
        return ticket


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class GateWitnessV3Tests(GateFixture,unittest.TestCase):
    def setUp(self):self.setup_gate_fixture()

    def test_full_lifecycle_and_exact_material_reopen(self):
        gate=self.gate();ticket=self.admitted(gate)
        with self.assertRaises(ValueError):gate.finish(ticket,definitive=True,response_hash=H)
        gate.finish_response(ticket,definitive=True,status=201,body=b'{"Id":"test"}')
        proof=gate.close_generation(self.gen);self.assertTrue(gate.validate_proof(proof))
        records=self.adapter.authenticated_material_after()['records']
        self.assertEqual(len(records),6)
        for index,record in enumerate(records):
            envelope=base64.b64decode(record['externalMaterialBase64'])
            local=json.loads((self.root/'gate'/self.gen/f'{index:08d}.json').read_bytes())
            self.assertEqual(envelope,gateway._canonical(local))
        reopened=self.gate();self.assertTrue(reopened.validate_proof(reopened.load_proof(self.gen)))
        self.assertFalse(self.adapter.authenticated_material_after()['authorityGranted'])

    def test_create_lifecycle(self):
        # This fixture uses one pinned create with its exact body digest.
        self.setup_gate_fixture('/v1.45/containers/create?name=dwc-'+'a'*24+'-web')
        gate=self.gate();ticket=self.admitted(gate)
        gate.finish_response(ticket,definitive=True,status=201,body=b'{}')
        self.assertTrue(gate.validate_proof(gate.close_generation(self.gen)))

    def test_unknown_blocks_close_and_transition(self):
        gate=self.gate();ticket=self.admitted(gate)
        gate.finish_response(ticket,definitive=False,status=0,body=b'')
        with self.assertRaises(ValueError):gate.close_generation(self.gen)
        view=self.client.read()
        with self.assertRaises(ValueError):
            self.client.transition_successor(expected_seq=view['seq'],expected_head=view['head'],
                childBinding=dict(self.binding,generation='7'*64,scopeHash='8'*64))
        self.assertEqual(len(self.adapter.authenticated_material_after()['records']),4)

    def test_remote_response_persists_before_local_failure_and_blocks(self):
        gate=self.gate();ticket=self.admitted(gate)
        with patch.object(gate,'_write',side_effect=OSError('local failure')):
            with self.assertRaises(Exception):gate.finish_response(ticket,definitive=True,status=200,body=b'complete')
        material=self.adapter.authenticated_material_after()
        event=json.loads(base64.b64decode(material['records'][-1]['externalMaterialBase64']))['payload']
        self.assertEqual(event['data']['bodyBase64'],base64.b64encode(b'complete').decode())
        self.assertFalse(material['authorityGranted'])
        with self.assertRaises(ValueError):gate.generation_evidence(self.gen)
        with self.assertRaises(ValueError):gate.finish_response(ticket,definitive=True,status=200,body=b'complete')

    def test_local_rollback_and_missing_material_block(self):
        gate=self.gate();ticket=self.admitted(gate)
        gate.finish_response(ticket,definitive=True,status=200,body=b'')
        (self.root/'gate'/self.gen/'00000003.json').unlink()
        with self.assertRaises(ValueError):gate.generation_evidence(self.gen)
        original=self.client.events_after
        def missing(**kw):
            records=original(**kw);records[0]['externalMaterialBase64']=None;return records
        with patch.object(self.client,'events_after',side_effect=missing):
            with self.assertRaises(ValueError):self.adapter.authenticated_material_after()

    def test_stable_policy_and_signed_successor_generation(self):
        gate=self.gate();ticket=self.admitted(gate)
        gate.finish_response(ticket,definitive=True,status=200,body=b'')
        gate.close_generation(self.gen)
        old_policy=self.policy
        self.gen='7'*64
        scope=opening_scope(self.gen,self.request,self.receipt,self.ops,self.source)
        self.policy=replace(self.policy,witness_scope_hash=scope)
        self.assertEqual(old_policy.identity_hash(),self.policy.identity_hash())
        child=dict(self.binding,generation=self.gen,scopeHash=scope)
        view=self.client.read()
        self.client.transition_successor(expected_seq=view['seq'],expected_head=view['head'],childBinding=child)
        self.binding=child
        self.client=signed.OperationWitnessClientV3(child,self.public,self.transport)
        self.adapter=GateOperationWitnessAdapterV3(self.client)
        successor=self.gate()
        with self.assertRaisesRegex(gateway.GateError,'witness-opening-scope-mismatch'):
            self.opening(successor,request_hash='8'*64)
        with self.assertRaisesRegex(gateway.GateError,'online-witness-required'):
            gateway.FileWriterGate(old_policy,self.root/'gate',key=b'g'*32,witness=self.adapter)
        ticket=self.admitted(successor)
        successor.finish_response(ticket,definitive=True,status=204,body=b'')
        self.assertTrue(successor.validate_proof(successor.close_generation(self.gen)))
        self.assertEqual(len(self.client.read()['lineage']),1)

    def test_response_validation_and_legacy_rejection(self):
        gate=self.gate();ticket=self.admitted(gate)
        for kwargs in (dict(definitive=True,status=True,body=b''),dict(definitive=False,status=200,body=b''),
                       dict(definitive=False,status=0,body=b'x'),dict(definitive=True,status=99,body=b'')):
            with self.assertRaises(ValueError):gate.finish_response(ticket,**kwargs)
        with self.assertRaises(ValueError):GateOperationWitnessAdapterV3(object())
        from deployment_gate_witness import OnlineWitnessClient
        old = OnlineWitnessClient(self.binding, self.public, self.transport)
        with self.assertRaisesRegex(gateway.GateError, 'online-witness-required'):
            gateway.FileWriterGate(self.policy,self.root/'old',key=b'g'*32,witness=old)
        data = dict(ref=ticket.attempt_ref, definitive=True, status=200, bodyBase64='',
                    response_binding_schema=1, response_hash=H)
        with self.assertRaises(ValueError):gateway.FileWriterGate._response_data(data)
        legacy=gateway.FileWriterGate(gateway.GatePolicy('legacy','key',H,self.cert),self.root/'legacy',key=b'l'*32)
        with self.assertRaises(ValueError):legacy.finish_response(ticket,definitive=True,status=200,body=b'')
