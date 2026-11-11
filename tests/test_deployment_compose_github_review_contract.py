from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import deployment_compose_github_review_contract as contract
from deployment_compose_approval_host import GitHubComposeApproval
from release_execute import AuthorizationUnavailable
from release_host import bundle_digest


def environment():
    return dict(GITHUB_REPOSITORY=contract.REPOSITORY, GITHUB_REPOSITORY_ID=str(contract.REPOSITORY_ID),
                GITHUB_REF=contract.REF, GITHUB_RUN_ATTEMPT='1', GITHUB_EVENT_NAME='workflow_dispatch',
                GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', DW_AUTH_REVIEWER_ID='84822776',
                DW_AUTH_LEDGER_REPOSITORY='sample/independent-ledger', DW_AUTH_LEDGER_ID='456',
                DW_AUTH_LEDGER_SHA='b' * 40)


class ReviewContractTests(unittest.TestCase):
    def setUp(self):
        self.env = environment()
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.bundle = contract.prepare(self.env, self.now)

    def verify(self, obj=None, **kwargs):
        return contract.verify(contract.canonical(self.bundle if obj is None else obj), self.env,
                               now=kwargs.get('now', self.now))

    def test_canonical_typed_bundle_and_real_sdk_digest(self):
        req, policy, digest = self.verify()
        self.assertEqual(req.digest(), self.bundle['requestHash'])
        self.assertEqual(digest, bundle_digest([req], policy.expires_at, policy.bundle_context()))
        self.assertEqual(asdict(policy), self.bundle['policy'])
        with self.assertRaises(ValueError):
            contract.verify(json.dumps(self.bundle), self.env, self.now)

    def test_rehashed_scope_tampering_rejected(self):
        for field, value in [('production', True), ('profile_version', '2'), ('daemon_id', 'real-daemon'),
                             ('max_uses', True), ('components', ['database'])]:
            with self.subTest(field=field):
                obj = json.loads(contract.canonical(self.bundle))
                obj['request'][field] = value
                obj['requestHash'] = contract.digest(obj['request'])
                obj['policyHash'] = contract.digest(obj['policy'])
                obj['bundleHash'] = contract.digest(obj)
                with self.assertRaises(ValueError):
                    self.verify(obj)

    def test_self_consistent_new_identity_cannot_replace_expected_context(self):
        other = dict(self.env, GITHUB_RUN_ID='789')
        with self.assertRaises(ValueError):
            self.verify(contract.prepare(other, self.now))

    def test_valid_typed_scope_with_all_hashes_recomputed_is_rejected(self):
        request, policy, _ = self.verify()
        for change in [dict(production=True), dict(daemon_id='real-daemon'),
                       dict(components=('database',))]:
            with self.subTest(change=change):
                changed_request = replace(request, **change)
                changed_policy = replace(policy, **change)
                obj = dict(self.bundle, request=asdict(changed_request), policy=asdict(changed_policy),
                           requestHash=changed_request.digest(), policyHash=contract.digest(asdict(changed_policy)),
                           bundleHash=bundle_digest([changed_request], changed_policy.expires_at,
                                                    changed_policy.bundle_context()))
                with self.assertRaisesRegex(ValueError, 'fixed workflow scope'):
                    self.verify(obj)

    def test_request_digest_tampering_rejected(self):
        for field in ['requestHash', 'policyHash', 'bundleHash']:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(dict(self.bundle, **{field: '0' * 64}))

    def test_expiry_and_rerun_guard(self):
        for now in [self.now - timedelta(seconds=1), self.now + timedelta(minutes=30)]:
            with self.assertRaises(ValueError):
                self.verify(now=now)
        for field, value in [('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_REPOSITORY_ID', '2'),
                             ('GITHUB_REF', 'refs/heads/main'), ('GITHUB_EVENT_NAME', 'push')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.prepare(dict(self.env, **{field: value}), self.now)

    def test_no_execution_permit(self):
        request, _, _ = self.verify()
        with self.assertRaises(AuthorizationUnavailable):
            GitHubComposeApproval.guard(object(), request)

    def test_duplicate_keys_and_unknown_fields_rejected(self):
        raw = contract.canonical(self.bundle)
        with self.assertRaises(ValueError):
            contract.verify('{"schema":1,' + raw[1:], self.env, self.now)
        with self.assertRaises(ValueError):
            self.verify(dict(self.bundle, executionAllowed=True))

    def test_no_redirect_or_untrusted_oidc_endpoint(self):
        with self.assertRaises(ValueError):
            contract.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.test')
        for url in ['http://foo.actions.githubusercontent.com/id', 'https://evil.test/id',
                    'https://foo.actions.githubusercontent.com.evil.test/id',
                    'https://u:p@foo.actions.githubusercontent.com/id',
                    'https://foo.actions.githubusercontent.com/id?audience=other']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                contract.fetch_token(dict(self.env, ACTIONS_ID_TOKEN_REQUEST_URL=url))

    def test_oidc_fetch_disables_proxy_and_sets_audience(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"value":"header.payload.signature"}'
        opener = mock.Mock()
        opener.open.return_value = response
        env = dict(self.env, ACTIONS_ID_TOKEN_REQUEST_URL='https://foo.actions.githubusercontent.com/id?x=1',
                   ACTIONS_ID_TOKEN_REQUEST_TOKEN='private-bearer')
        with mock.patch.object(contract.urllib.request, 'build_opener', return_value=opener) as build:
            self.assertEqual(contract.fetch_token(env), b'header.payload.signature')
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], contract.NoRedirect)
        request = opener.open.call_args.args[0]
        self.assertIn('audience=' + contract.AUDIENCE, request.full_url)

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required')
    def test_cms_roundtrip_never_writes_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key, output = root / 'cert.pem', root / 'key.pem', root / 'oidc.cms.der'
            subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(cert), '-subj', '/CN=test', '-days', '1'],
                           capture_output=True, check=True)
            token = b'private.header.payload'
            stdout = io.StringIO()
            with mock.patch.object(contract, 'fetch_token', return_value=token), mock.patch('sys.stdout', stdout):
                contract.seal(contract.canonical(self.bundle), self.env, cert, output)
            decrypted = subprocess.run(['/usr/bin/openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
                                        '-in', str(output), '-recip', str(cert), '-inkey', str(key)],
                                       capture_output=True, check=True).stdout
            self.assertEqual(decrypted, token)
            self.assertNotIn(token.decode(), stdout.getvalue())
            self.assertNotIn(token, output.read_bytes())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual({p.name for p in root.iterdir()}, {'cert.pem', 'key.pem', 'oidc.cms.der'})

    def test_cli_errors_do_not_echo_secret(self):
        with mock.patch.object(sys, 'argv', ['contract', 'seal', '--bundle', '/missing']), mock.patch('sys.stderr', new_callable=io.StringIO) as err:
            self.assertEqual(contract.main(), 1)
        self.assertEqual(err.getvalue(), 'Authorization-only contract failed closed\n')

    def test_workflow_contract(self):
        text = (ROOT / '.github/workflows/compose-protected-review.yml').read_text()
        self.assertNotIn('  push:',text)
        for expected in ['options: [launch, review]',
                         'environment: compose-review', 'id-token: write', 'artifact-ids:',
                         'ref: ${{ github.sha }}', 'run: sleep 300', 'retention-days: 1',
                         'dev-workflow approve %s', 'inputs: {mode: \'review\'}']:
            self.assertIn(expected, text)
        self.assertEqual(text.count('actions: write'), 1)
        self.assertNotIn('reviewPendingDeployments', text)
        self.assertNotIn('secrets.', text)
        self.assertNotIn('docker ', text)
        self.assertIn('path: sealed-evidence/oidc.cms.der', text)



class ActionPinTests(unittest.TestCase):
    def test_every_action_in_privileged_workflow_has_full_commit_pin(self):
        import re
        text=(Path(__file__).resolve().parents[1]/'.github/workflows/compose-protected-review.yml').read_text()
        uses=re.findall(r'(?m)^\s*(?:-\s+)?uses:\s+([^\s]+)',text)
        self.assertTrue(uses)
        self.assertTrue(all(re.fullmatch(r'actions/[a-z-]+@[0-9a-f]{40}',value) for value in uses))

if __name__ == '__main__':
    unittest.main()
