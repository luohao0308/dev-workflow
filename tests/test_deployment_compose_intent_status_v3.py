import base64
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
from deployment_compose_intent_status_v3 import IntentStatusClientV3, issue_intent_status, encode, NAMESPACE, ERROR
from tests.test_deployment_compose_approval_v3_host import ComposeApprovalTests, request


@unittest.skipUnless(shutil.which('ssh-keygen'), 'OpenSSH required')
class IntentStatusTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ComposeApprovalTests()
        self.fixture.setUp()
        self.req = self.fixture.req
        self.approval = self.fixture.approval()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = Path(self.temp.name) / 'key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)], check=True, capture_output=True)
        self.public = self.key.with_suffix('.pub').read_bytes()
        self.calls = 0
        self.last = None
        self.edit = lambda p: p
        self.client = IntentStatusClientV3(self.req, self.public, self.transport)

    def consume(self):
        self.approval.consume(self.approval.validate(self.req), self.req)

    def sign(self, payload):
        signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(self.key), '-n', NAMESPACE],
                                input=encode(payload), check=True, capture_output=True)
        return dict(payload=deepcopy(payload), signature=base64.b64encode(signed.stdout).decode('ascii'))

    def transport(self, rpc):
        self.calls += 1
        self.last = self.sign(self.edit(issue_intent_status(self.approval, self.req, rpc)))
        return deepcopy(self.last)

    def denied(self, client=None, req=None):
        with self.assertRaisesRegex(ValueError, '^' + ERROR + '$'):
            (client or self.client).check_consumed_intent(req or self.req)

    def test_real_status_no_secrets_or_permit(self):
        self.consume()
        self.assertIsNone(self.client.check_consumed_intent(self.req))
        payload = self.last['payload']
        self.assertIs(payload['runtimePermit'], False)
        self.assertIs(payload['authorityGranted'], False)
        self.assertNotIn('signed', encode(payload).decode())
        self.assertNotIn('token', encode(payload).decode())
        self.assertNotIn('PAT', encode(payload).decode())
        saved = deepcopy(self.last)
        replay = IntentStatusClientV3(self.req, self.public, lambda _: saved)
        self.denied(replay)
        self.client._transport = lambda _: saved
        self.denied()

    def test_signed_shape_hash_nonce_and_time_denials(self):
        self.consume()
        for changes in (dict(requestHash='0'*64), dict(bundleHash='0'*64), dict(bootNonce='0'*64),
                        dict(rpcNonce='0'*64), dict(issuedAt=int(time.time())+20),
                        dict(expiresAt=int(time.time())-1), dict(expiresAt=int(time.time())+60),
                        dict(runtimePermit=True), dict(consumed=1), dict(schemaVersion=True),
                        dict(productionReady=True), dict(extra=False)):
            self.edit = lambda p, changes=changes: dict(p, **changes)
            with self.subTest(changes=changes):
                self.denied()

    def test_small_receiver_clock_lag_waits_without_accepting_future(self):
        issued = int(time.time())
        def transport(rpc):
            return self.sign(dict(rpc, purpose='consumed-intent-status-v3',
                issuedAt=issued, expiresAt=issued+20, consumed=True,
                authorityGranted=False, runtimePermit=False, productionReady=False))
        self.client._transport = transport
        import deployment_compose_intent_status_v3 as module
        clock = SimpleNamespace(time=Mock(side_effect=[issued-.5, issued+.01]), sleep=Mock())
        with patch.object(module, 'time', clock):
            self.client.check_consumed_intent(self.req)
        clock.sleep.assert_called_once_with(.5)
        clock.time.side_effect = [issued-.5, issued-.1]
        with patch.object(module, 'time', clock): self.denied()
        clock.sleep.reset_mock()
        clock.time.side_effect = [issued-3]
        with patch.object(module, 'time', clock): self.denied()
        clock.sleep.assert_not_called()

    def test_exact_request_profiles_and_production(self):
        for req in (replace(self.req, plan_hash='0'*64), replace(self.req, host_id='other')):
            self.denied(req=req)
        self.assertEqual(self.calls, 0)
        for req in (replace(self.req, profile_version='1'), replace(self.req, profile_version='2'), replace(self.req, production=True)):
            with self.assertRaisesRegex(ValueError, ERROR):
                IntentStatusClientV3(req, self.public, self.transport)

    def test_no_ledger_or_expired_authority_refuses(self):
        self.denied()
        self.consume()
        self.approval._expires = time.time()-1
        # Real authority recheck refreshes token lifetime; an expired token is rejected.
        self.fixture.claims['exp'] = int(time.time())-1
        self.denied()

    def test_offline_wrong_key_and_bad_signature(self):
        self.consume()
        def offline(_):
            self.calls += 1
            raise OSError('offline secret')
        self.client._transport = offline
        self.denied()
        self.assertEqual(self.calls, 1)
        self.client._transport = self.transport
        self.client.check_consumed_intent(self.req)
        saved = deepcopy(self.last)
        saved['signature'] = base64.b64encode(b'bad').decode()
        self.client._transport = lambda _: saved
        self.denied()
        other = Path(self.temp.name) / 'other'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other)], check=True, capture_output=True)
        self.denied(IntentStatusClientV3(self.req, other.with_suffix('.pub').read_bytes(), self.transport))

    def test_helper_closed_request_and_registered_binding(self):
        self.consume()
        rpc = self.client._request()
        for altered in (dict(rpc, extra=True), dict(rpc, bundleHash='0'*64), dict(rpc, rpcNonce='bad')):
            with self.assertRaisesRegex(ValueError, ERROR):
                issue_intent_status(self.approval, self.req, altered)
        with self.assertRaisesRegex(ValueError, ERROR):
            issue_intent_status(object(), self.req, rpc)
        with self.assertRaisesRegex(ValueError, ERROR):
            issue_intent_status(self.approval, self.req, rpc, now=time.time()+7200)


if __name__ == '__main__':
    unittest.main()
