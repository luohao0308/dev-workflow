"""Capacity model checked against real signed Gate/witness serialization."""
import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
import shutil
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_history_v3_host as history_fixture
from deployment_compose_history_v3_host import AuthenticatedHistorySnapshotV3
from deployment_compose_witness_store import canonical
from deployment_gateway import FileWriterGate
import deployment_compose_witness_budget_v3_host as budget


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.host=history_fixture.HistoryTests('test_two_scopes_and_no_local_files')
        self.host.setUp();self.addCleanup(self.host.doCleanups)

    def check(self, snapshot=None):
        h=self.host
        return budget.check_witness_byte_capacity(h.bundle,h.req,h.policy,h.receipt,h.binding,snapshot)

    def actual_size(self):
        h=self.host
        return len(h.store._seal(h.store._read()))

    def test_model_bounds_real_max_response_and_exact_current_state(self):
        h=self.host
        initial=self.check()
        self.assertEqual(initial['currentBytes'],self.actual_size())
        raw=b'{"Id":"'+b'a'*64+b'"}'
        raw+=b' '*(4096-len(raw))
        h.finish(body=raw)
        actual=h.store._read()['scopes'][0]
        desc=budget._scope_upper_bound(h.binding,h.policy,
            dict(operations=h.ops,source=h.source),h.req.digest(),h.receipt,None)
        self.assertLessEqual(len(canonical(actual)),len(canonical(desc)))
        self.assertLess(self.actual_size(),initial['requiredBytes'])
        snapshot=h.history().capture()
        value=self.check(snapshot)
        self.assertEqual(value['currentBytes'],self.actual_size())
        self.assertEqual(value['scopeCount'],5)
        self.assertEqual(value['eventCount'],30)
        self.assertEqual(value['maxResponseBytes'],4096)

    def test_capacity_rejects_before_any_gate_write(self):
        h=self.host;initial=self.check()
        self.assertEqual(h.client.read()['seq'],0)
        with patch.object(budget,'MAX_BYTES',initial['requiredBytes']-1):
            with self.assertRaises(ValueError):self.check()
        self.assertEqual(h.client.read()['seq'],0)
        self.assertFalse((h.root/'gate'/h.gen).exists())

    def test_gate_new_response_limit_keeps_historic_verifier(self):
        h=self.host;gate=h.current_gate;ticket=h.admitted(gate)
        body=b'x'*4097
        with self.assertRaises(ValueError):gate.finish_response(ticket,definitive=True,status=201,body=body)
        self.assertEqual(h.client.read()['seq'],3)
        historical=b'x'*65536
        data=dict(ref=ticket.attempt_ref,definitive=True,status=201,
            bodyBase64=base64.b64encode(historical).decode('ascii'),response_binding_schema=1,
            response_hash=hashlib.sha256(b'201\0'+historical).hexdigest())
        FileWriterGate._response_data(data)
        # An upstream overcap response is recorded as unknown; it cannot close.
        gate.finish_response(ticket,definitive=False,status=0,body=b'')
        with self.assertRaises(ValueError):gate.close_generation(h.gen)
        with self.assertRaises(ValueError):gate.finish_response(ticket,definitive=True,status=201,body=b'{}')

    def test_real_historical_large_response_is_counted_exactly(self):
        h=self.host;gate=h.current_gate;ticket=h.admitted(gate)
        raw=b'{"Id":"'+b'a'*64+b'"}'
        raw+=b' '*(65536-len(raw))
        data=dict(ref=ticket.attempt_ref,definitive=True,status=201,
            bodyBase64=base64.b64encode(raw).decode('ascii'),response_binding_schema=1,
            response_hash=hashlib.sha256(b'201\0'+raw).hexdigest())
        # Reconstruct an old persisted Gate event through the unchanged signed
        # storage grammar; new finish_response deliberately cannot emit it.
        with gate._locked():
            gate._append(h.gen,gate._state(h.gen),'finish',data)
        gate.close_generation(h.gen)
        snapshot=h.history().capture()
        request=replace(h.req,operation='rollback',history_hash=snapshot.digest)
        value=budget.check_witness_byte_capacity(h.bundle,request,h.policy,h.receipt,h.binding,snapshot)
        self.assertEqual(value['currentBytes'],self.actual_size())
        self.assertGreater(value['currentBytes'],200000)
        self.assertGreater(value['requiredBytes'],value['currentBytes'])
        with patch.object(budget,'MAX_BYTES',value['requiredBytes']-1):
            with self.assertRaises(ValueError):
                budget.check_witness_byte_capacity(h.bundle,request,h.policy,h.receipt,h.binding,snapshot)

    def test_gateway_response_cap_at_exact_boundary(self):
        import http.client
        from io import BytesIO
        from deployment_compose_write_gateway_v3_host import _complete_response
        class Peer:
            def __init__(self,raw):self.raw=raw
            def makefile(self,*args):return BytesIO(self.raw)
        for length in (4096,4097):
            for framed in (True,False):
                header=(b'Content-Length: '+str(length).encode()+b'\r\n') if framed else b''
                response=http.client.HTTPResponse(Peer(b'HTTP/1.1 200 OK\r\n'+header+b'\r\n'+b'x'*length))
                response.begin()
                if length==4096:self.assertEqual(len(_complete_response(response)),length)
                else:
                    with self.assertRaises(ValueError):_complete_response(response)

    def test_prior_requires_root_schema_and_bounded_directory_identity(self):
        h=self.host;h.finish()
        value=json.loads(h.history().capture().canonical)
        value['schemaVersion']=2
        with self.assertRaises(ValueError):self.check(AuthenticatedHistorySnapshotV3(canonical(value)))
        value['schemaVersion']=1
        record=value['scopes'][0]['records'][0]
        raw=json.loads(base64.b64decode(record['externalMaterialBase64']))
        raw['payload']['directory'][0]=2**64
        record['externalMaterialBase64']=base64.b64encode(canonical(raw)).decode('ascii')
        with self.assertRaises(ValueError):self.check(AuthenticatedHistorySnapshotV3(canonical(value)))

    def test_recovery_models_only_the_remaining_absolute_write_suffix(self):
        h=self.host;h.finish()
        snapshot=h.history().capture()
        request=replace(h.req,operation='recovery',history_hash=snapshot.digest)
        value=budget.check_witness_byte_capacity(h.bundle,request,h.policy,h.receipt,h.binding,snapshot)
        self.assertEqual(value['currentBytes'],self.actual_size())
        self.assertEqual(value['scopeCount'],5)
        self.assertEqual(value['eventCount'],30)
        with patch.object(budget,'MAX_SCOPES',5):
            budget.check_witness_byte_capacity(h.bundle,request,h.policy,h.receipt,h.binding,snapshot)
        raw=json.loads(snapshot.canonical);raw['blocker']='unknown-response'
        blocked=AuthenticatedHistorySnapshotV3(canonical(raw))
        request=replace(request,history_hash=blocked.digest)
        with self.assertRaises(ValueError):
            budget.check_witness_byte_capacity(h.bundle,request,h.policy,h.receipt,h.binding,blocked)

    def test_rollback_counts_all_original_bytes_and_future_scopes(self):
        h=self.host;h.finish()
        snapshot=h.history().capture()
        # Capacity helper relies on a freshly authenticated caller snapshot; this
        # alternate request models future rollback without granting that authority.
        request=replace(h.req,operation='rollback',history_hash=snapshot.digest)
        value=budget.check_witness_byte_capacity(h.bundle,request,h.policy,h.receipt,h.binding,snapshot)
        self.assertEqual(value['currentBytes'],self.actual_size())
        self.assertEqual(value['scopeCount'],6)
        self.assertEqual(value['eventCount'],36)
        with patch.object(budget,'MAX_SCOPES',5):
            with self.assertRaises(ValueError):
                budget.check_witness_byte_capacity(h.bundle,request,h.policy,h.receipt,h.binding,snapshot)


if __name__=='__main__':unittest.main()
