import base64
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3, ZERO
from deployment_compose_operation_witness_client_v3 import (
    OperationWitnessClientV3, dispatch_request, encode, NAMESPACE,
)

BINDING = dict(zip(('scopeHash', 'epoch', 'generation', 'policyHash'), (x * 64 for x in 'abcd')))
CHILD = dict(BINDING, scopeHash='f' * 64, generation='1' * 64)
ATTEMPT = 'e' * 64


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX and OpenSSH required')
class SignedOperationWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.key = self.root / 'signing'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)], check=True, capture_output=True)
        self.public = self.key.with_suffix('.pub').read_bytes()
        witness = self.root / 'witness'; witness.mkdir(mode=0o700)
        self.store = OperationWitnessStoreV3(witness, key=b'local-test-key-' + b'x' * 32)
        self.addCleanup(self.store.close); self.store.register_once(BINDING)
        self.calls = 0; self.last = None
        self.client = OperationWitnessClientV3(BINDING, self.public, self.transport)
        self.view = self.client.read()

    def sign(self, payload):
        signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(self.key), '-n', NAMESPACE],
                                input=encode(payload), capture_output=True, check=True)
        return dict(payload=deepcopy(payload), signature=base64.b64encode(signed.stdout).decode('ascii'))

    def transport(self, method, request):
        self.calls += 1
        self.last = self.sign(dispatch_request(self.store, method, request))
        return deepcopy(self.last)

    def append(self, kind, data=None, external=None, client=None):
        client = client or self.client
        event = dict(binding=client.binding, sequence=self.view['seq'] + 1,
                     previousHead=self.view['head'], kind=kind, data=data or {})
        if external is not None:
            event['materialDigest'] = hashlib.sha256(external).hexdigest()
        self.view = client.append_event(expected_seq=self.view['seq'], expected_head=self.view['head'], event=event, external_material=external)
        return event

    def complete(self):
        self.append('open', external=b'gate sealed opening\x00\n')
        self.append('prepared', {'attemptRef': ATTEMPT})
        self.append('admitted', {'attemptRef': ATTEMPT})
        self.append('response', dict(attemptRef=ATTEMPT, definitive=True, status=200, bodyBase64=''))
        self.append('completed', {'attemptRef': ATTEMPT}); self.append('closed')

    def rejected(self, client, method='read', **kwargs):
        with self.assertRaisesRegex(ValueError, '^operation-witness-v3-rejected$'):
            getattr(client, method)(**kwargs)

    def test_real_signature_full_material_and_successor(self):
        self.complete()
        records = self.client.events_after(seq=0, head=ZERO)
        self.assertEqual(base64.b64decode(records[0]['externalMaterialBase64']), b'gate sealed opening\x00\n')
        self.assertEqual(len(records), 6)
        self.assertEqual(self.client.check(expected_seq=6, expected_head=self.view['head']), self.view)
        child = self.client.transition_successor(expected_seq=6, expected_head=self.view['head'], childBinding=CHILD)
        self.assertEqual(child['lineage'][-1]['head'], self.view['head'])
        next_client = OperationWitnessClientV3(CHILD, self.public, self.transport)
        self.assertEqual(next_client.read(), child)
        self.assertFalse(self.client.read()['active'])
        event = dict(binding=BINDING, sequence=7, previousHead=self.view['head'], kind='open', data={})
        self.rejected(self.client, 'append_event', expected_seq=6, expected_head=self.view['head'], event=event)
        self.view = child
        self.append('open', client=next_client)

    def test_reply_replay_rejected_in_same_and_new_client(self):
        replay = deepcopy(self.last)
        self.client._transport = lambda method, request: replay
        self.rejected(self.client)
        self.rejected(OperationWitnessClientV3(BINDING, self.public, lambda m, r: replay))

    def test_signed_wrong_method_nonce_binding_digest_and_authority_rejected(self):
        for field, value in [('method', 'check'), ('bootNonce', '0' * 64), ('rpcNonce', '0' * 64),
                             ('binding', CHILD), ('requestDigest', '0' * 64), ('authorityGranted', True), ('schemaVersion', True)]:
            def transport(method, request):
                payload = dispatch_request(self.store, method, request)
                payload[field] = value
                return self.sign(payload)
            self.rejected(OperationWitnessClientV3(BINDING, self.public, transport))

    def test_modified_result_and_invalid_signature_rejected(self):
        def tamper(method, request):
            response = self.transport(method, request)
            response['payload']['result']['head'] = 'f' * 64
            return response
        self.rejected(OperationWitnessClientV3(BINDING, self.public, tamper))
        def signature(method, request):
            response = self.transport(method, request); response['signature'] = base64.b64encode(b'bad signature').decode()
            return response
        self.rejected(OperationWitnessClientV3(BINDING, self.public, signature))
        other = self.root / 'other'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)], check=True, capture_output=True)
        self.rejected(OperationWitnessClientV3(BINDING, other.with_suffix('.pub').read_bytes(), self.transport))

    def test_valid_signature_still_requires_content_constraints(self):
        mutations = [lambda result: result.update(seq=True), lambda result: result.update(phase='closed'),
                     lambda result: result.update(binding=CHILD), lambda result: result.update(authorityGranted=True)]
        for mutate in mutations:
            def transport(method, request):
                payload = dispatch_request(self.store, method, request); mutate(payload['result'])
                return self.sign(payload)
            self.rejected(OperationWitnessClientV3(BINDING, self.public, transport))
        self.append('open', external=b'original gate bytes')
        for field, value in [('canonicalEvent', '{}'), ('head', 'e' * 64), ('externalMaterialBase64', 'eA==')]:
            def transport(method, request):
                payload = dispatch_request(self.store, method, request); payload['result'][0][field] = value
                return self.sign(payload)
            self.rejected(OperationWitnessClientV3(BINDING, self.public, transport), 'events_after', seq=0, head=ZERO)
        self.rejected(self.client, 'events_after', seq=1, head='e' * 64)

    def test_offline_and_ack_lost_mutations_have_one_attempt(self):
        for committed in (False, True):
            calls = []
            def transport(method, request):
                calls.append(method)
                if committed:
                    dispatch_request(self.store, method, request)
                raise OSError('channel dropped')
            client = OperationWitnessClientV3(BINDING, self.public, transport)
            event = dict(binding=BINDING, sequence=1, previousHead=ZERO, kind='open', data={})
            self.rejected(client, 'append_event', expected_seq=0, expected_head=ZERO, event=event)
            self.assertEqual(calls, ['append_event'])
            self.assertEqual(self.store.read(BINDING)['seq'], int(committed))
        self.assertEqual(self.client.events_after(seq=0, head=ZERO)[0]['event'], event)

    def test_signed_chain_status_from_stale_client_preserves_binding(self):
        self.complete()
        closed_head = self.view['head']
        self.client.transition_successor(expected_seq=6, expected_head=closed_head, childBinding=CHILD)
        status = self.client.chain_status()
        self.assertEqual(status['activeBinding'], CHILD)
        self.assertEqual((status['activeSeq'], status['activeHead'], status['activePhase']), (0, ZERO, 'empty'))
        self.assertEqual(status['lineage'], [dict(binding=BINDING, seq=6, head=closed_head)])
        self.assertEqual(self.client.binding, BINDING)
        self.assertFalse(status['authorityGranted'] or status['productionReady'])
        stale_event = dict(binding=BINDING, sequence=7, previousHead=closed_head, kind='open', data={})
        self.rejected(self.client, 'append_event', expected_seq=6, expected_head=closed_head, event=stale_event)
        unknown = OperationWitnessClientV3(dict(CHILD, scopeHash='8' * 64), self.public, self.transport)
        self.rejected(unknown, 'chain_status')
        self.client.chain_status(); replay = deepcopy(self.last)
        self.rejected(OperationWitnessClientV3(BINDING, self.public, lambda m, r: replay), 'chain_status')

    def test_signed_chain_status_content_tampering_rejected(self):
        self.complete()
        self.client.transition_successor(expected_seq=6, expected_head=self.view['head'], childBinding=CHILD)
        changes = [dict(activeSeq=True), dict(activeHead='9' * 64), dict(activePhase='closed'),
                   dict(epoch='9' * 64), dict(policyHash='9' * 64), dict(authorityGranted=True),
                   dict(activeBinding=BINDING), dict(lineage=[]), dict(extra=True)]
        for change in changes:
            def transport(method, request):
                payload = dispatch_request(self.store, method, request)
                payload['result'].update(change)
                return self.sign(payload)
            self.rejected(OperationWitnessClientV3(BINDING, self.public, transport), 'chain_status')
        def duplicate(method, request):
            payload = dispatch_request(self.store, method, request)
            payload['result']['lineage'] *= 2
            return self.sign(payload)
        self.rejected(OperationWitnessClientV3(BINDING, self.public, duplicate), 'chain_status')

    def test_dispatch_cannot_register_reset_or_accept_extra_fields(self):
        request = dict(binding=BINDING, bootNonce='1' * 64, rpcNonce='2' * 64)
        for method in ('register_once', 'reserve', 'reset', 'sign'):
            with self.assertRaisesRegex(ValueError, '^operation-witness-v3-rejected$'):
                dispatch_request(self.store, method, request)
        with self.assertRaises(ValueError): dispatch_request(self.store, 'read', dict(request, extra=True))


if __name__ == '__main__':
    unittest.main()
