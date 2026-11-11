"""Opt-in grammar only; no Docker writes or new witness protocol."""
from dataclasses import replace
import hashlib
import json
import unittest

from tests.test_deployment_gateway import gateway, policy, H, CERT
from deployment_gate_witness import opening_scope

EMPTY = hashlib.sha256(b'').hexdigest()
CREATE = '/v1.45/containers/create?name=dwc-' + 'a' * 24 + '-web'
RENAME = '/v1.45/containers/' + H + '/rename?name=project-web-1'


def profile():
    return gateway.GatePolicy('host-store', 'host-key', H, CERT, True, H, H,
                              operation_profile='compose-v3')


class GrammarTests(unittest.TestCase):
    def test_legacy_binding_bytes_unchanged(self):
        binding = dict(store_id='host-store', key_id='host-key', scope_hash=H,
                       writer_certificate_sha256=CERT)
        self.assertEqual(policy()._binding(), binding)
        expected = hashlib.sha256(json.dumps(binding, sort_keys=True,
                                  separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(policy().identity_hash(), expected)
        for path in (CREATE, RENAME):
            with self.assertRaises(gateway.GateError):
                gateway._operation('POST', path, EMPTY)
        self.assertEqual(profile()._binding()['operation_profile'], 'compose-v3')

    def test_profile_policy_requires_witness(self):
        for value in ('unknown', '', None, 3):
            with self.assertRaises(gateway.GateError):
                replace(policy(), operation_profile=value)
        with self.assertRaises(gateway.GateError):
            replace(policy(), operation_profile='compose-v3')
        with self.assertRaisesRegex(gateway.GateError, 'online-witness-required'):
            gateway.FileWriterGate(profile(), None, key=b'k' * 32)

    def test_strict_grammar_and_empty_noncreate_body(self):
        for method, path in (('POST', CREATE), ('POST', RENAME),
                             ('POST', '/v1.45/containers/' + H + '/start'),
                             ('POST', '/v1.45/containers/' + H + '/stop?t=60'),
                             ('DELETE', '/v1.45/containers/' + H + '?force=false&v=false')):
            self.assertEqual(gateway._profile_operation('compose-v3', method, path, EMPTY),
                             (method, path, EMPTY))
        invalid = [CREATE.replace('dwc-', 'dwf-'), CREATE.replace('-web', '-'),
                   CREATE.replace('-web', '-' + 'x' * 65), CREATE + '&x=1',
                   RENAME.replace('project-web-1', '%77eb'), RENAME + '&x=1',
                   RENAME.replace(H, H[:12]), RENAME.replace('project-web-1', '/web'),
                   RENAME.replace('project-web-1', 'x' * 129),
                   '/v1.45/containers/' + H + '/stop?t=0',
                   '/v1.45/containers/' + H + '?force=true&v=false']
        for path in invalid:
            with self.subTest(path=path), self.assertRaises(gateway.GateError):
                gateway._profile_operation('compose-v3', 'POST', path, EMPTY)
        with self.assertRaises(gateway.GateError):
            gateway._profile_operation('compose-v3', 'POST', RENAME, H)


@unittest.skipUnless(__import__('os').name == 'posix' and __import__('shutil').which('ssh-keygen'),
                     'POSIX/OpenSSH witness fixture')
class ProfileWitnessTests(unittest.TestCase):
    def setUp(self):
        from tests.test_deployment_compose_gate_witness_v3 import GateFixture
        GateFixture.setup_gate_fixture(self)

    from tests.test_deployment_compose_gate_witness_v3 import GateFixture as _fixture
    sign = _fixture.sign
    transport = _fixture.transport
    gate = _fixture.gate
    opening = _fixture.opening

    def test_source_and_single_operation_required(self):
        gate = self.gate()
        with self.assertRaisesRegex(gateway.GateError, 'invalid-source-context'):
            self.opening(gate, source_context_digest=None)
        with self.assertRaisesRegex(gateway.GateError, 'single-approved-operation-required'):
            self.opening(gate, operations=self.ops + (('POST', CREATE, EMPTY),))

    def test_exact_pinned_operation_and_replay(self):
        gate = self.gate()
        session = self.opening(gate)
        with self.assertRaises(ValueError):
            session.prepare_attempt('POST', CREATE, b'')
        attempt = session.prepare_attempt('POST', RENAME, b'')
        with self.assertRaises(ValueError):
            gate.admit(self.gen, attempt.ref, method='POST', path=CREATE, body=b'',
                       writer_certificate_sha256=self.cert)
        ticket = gate.admit(self.gen, attempt.ref, method='POST', path=RENAME, body=b'',
                            writer_certificate_sha256=self.cert)
        gate.finish_response(ticket, definitive=True, status=200, body=b'')
        with gate._locked():
            self.assertEqual(gate._state(self.gen)['operations'], self.ops)
        with self.assertRaises(ValueError):
            gateway.FileWriterGate(replace(self.policy, operation_profile='legacy'),
                                   self.root / 'gate', key=b'g' * 32, witness=self.adapter)
