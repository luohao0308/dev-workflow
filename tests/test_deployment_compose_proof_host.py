"""Synthetic attestors test authentication and binding, not real backup success."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import unittest
from unittest import mock

from tests.test_deployment_compose_recovery_host import setup as recovery_setup
import os
from tests.test_deployment_compose_approval_host import deadline
import tests.test_deployment_compose_approval_host as approval_tests
from tests.test_release_host import claims
from deployment_compose_approval_host import AUDIENCE, GitHubComposeApproval
from release_execute import AuthorizationUnavailable
from deployment_compose_request_host import ComposeRequestHost
from deployment_compose_proof_host import DOMAIN, KINDS, canonical, ComposeProofHost


def stamp(value):
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')


def sign(body, key):
    return {'body': body, 'mac': hmac.new(key, DOMAIN + canonical(body), hashlib.sha256).hexdigest()}


def fixture():
    inputs, _, result, observation, _, _ = recovery_setup()
    issuer = ComposeRequestHost(**inputs)
    observation = inputs['observer'].issue()
    intent = issuer.prepare_intent(observation, operation_nonce='9' * 64, expires_at=deadline())
    old, new = inputs['observer']._baseline_artifacts, inputs['target']
    statements = {
        'provenance': {'targetDigest': new.digest(), 'source': {
            'provider': intent.source.provider_id, 'projectId': intent.source.project_id,
            'origin': intent.source.origin, 'sha': intent.source.source_sha}},
        'migration': {'schemaDigest': '4' * 64, 'services': [{
            'service': 'web', 'baselineMigration': old.services[0].migration_digest,
            'targetMigration': new.services[0].migration_digest, 'mode': 'none'}]},
        'backup': {'baselineDigest': old.digest(), 'backupDigest': '5' * 64,
                   'restoreTestDigest': '6' * 64},
    }
    now = datetime.now(timezone.utc)
    proofs = {k: sign(dict(version=1, kind=k, keyId=k, requestHash=intent.digest(),
              statement=statements[k], reportDigest='7' * 64,
              issuedAt=stamp(now - timedelta(seconds=5)),
              expiresAt=stamp(now + timedelta(minutes=30)), status='verified'), k.encode() * 32)
              for k in KINDS}
    return inputs, issuer, observation, intent, proofs, result


@unittest.skipIf(os.name == 'nt', 'final proof review requires private host recovery storage')
class ProofTests(unittest.TestCase):
    def test_authenticated_proofs_bind_final_request(self):
        inputs, issuer, observation, intent, proofs, _ = fixture()
        request = issuer.prepare(observation, operation_nonce='9' * 64,
                                 expires_at=intent.expires_at, proofs=proofs)
        self.assertNotEqual(request.plan_hash, intent.plan_hash)
        self.assertEqual(request.observation_hash, intent.observation_hash)
        issuer.verify(request, observation, operation_nonce='9' * 64, proofs=proofs)
        with self.assertRaises(ValueError):
            issuer.verify(intent, observation, operation_nonce='9' * 64, proofs=proofs)
        changed = deepcopy(proofs)
        changed['backup']['body']['reportDigest'] = '8' * 64
        changed['backup'] = sign(changed['backup']['body'], b'backup' * 32)
        with self.assertRaises(ValueError):
            issuer.verify(request, observation, operation_nonce='9' * 64, proofs=changed)

    def test_missing_forged_or_wrong_purpose_denied(self):
        inputs, issuer, observation, intent, proofs, _ = fixture()
        for kind in KINDS:
            missing = deepcopy(proofs)
            missing.pop(kind)
            changed = deepcopy(proofs)
            changed[kind]['body']['status'] = 'verified-by-project'
            wrong_key = deepcopy(proofs)
            wrong_key[kind] = sign(wrong_key[kind]['body'], b'unknown' * 32)
            for bundle in (missing, changed, wrong_key):
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    issuer.prepare(observation, operation_nonce='9' * 64,
                                   expires_at=intent.expires_at, proofs=bundle)

    def test_authenticated_wrong_claims_or_context_denied(self):
        inputs, issuer, observation, intent, proofs, _ = fixture()
        cases = [('provenance', 'requestHash', '0' * 64),
                 ('migration', 'statement', {'schemaDigest': '0' * 64, 'services': []}),
                 ('backup', 'statement', {'baselineDigest': intent.before_hash,
                    'backupDigest': '5' * 64, 'restoreTestDigest': '8' * 64}),
                 ('backup', 'reportDigest', '0' * 64),
                 ('provenance', 'version', True)]
        for kind, field, value in cases:
            changed = deepcopy(proofs)
            changed[kind]['body'][field] = value
            changed[kind] = sign(changed[kind]['body'], kind.encode() * 32)
            with self.subTest(field=field), self.assertRaises(ValueError):
                issuer.prepare(observation, operation_nonce='9' * 64,
                               expires_at=intent.expires_at, proofs=changed)
        with self.assertRaises(ValueError):
            issuer.prepare(observation, operation_nonce='8' * 64,
                           expires_at=intent.expires_at, proofs=proofs)

    def test_expiry_future_dates_and_short_lifetime_denied(self):
        inputs, issuer, observation, intent, proofs, _ = fixture()
        now = datetime.now(timezone.utc)
        for field, value in [('issuedAt', stamp(now + timedelta(minutes=1))),
                             ('issuedAt', stamp(now - timedelta(hours=2))),
                             ('expiresAt', stamp(now - timedelta(seconds=1))),
                             ('expiresAt', stamp(now + timedelta(minutes=1)))]:
            changed = deepcopy(proofs)
            changed['backup']['body'][field] = value
            changed['backup'] = sign(changed['backup']['body'], b'backup' * 32)
            with self.subTest(field=field), self.assertRaises(ValueError):
                issuer.prepare(observation, operation_nonce='9' * 64,
                               expires_at=intent.expires_at, proofs=changed)

    def test_drift_during_proof_validation_blocks_return(self):
        inputs, issuer, observation, intent, proofs, result = fixture()
        original = issuer._proof_host.verify
        def verify(*args):
            digest = original(*args)
            result['serviceContainerIds']['web'] = '3' * 64
            return digest
        with mock.patch.object(issuer._proof_host, 'verify', side_effect=verify):
            with self.assertRaises(ValueError):
                issuer.prepare(observation, operation_nonce='9' * 64,
                               expires_at=intent.expires_at, proofs=proofs)

    def test_exact_final_review_consumed_once_and_missing_proof_precedes_network(self):
        inputs, issuer, observation, intent, proofs, _ = fixture()
        request = issuer.prepare(observation, operation_nonce='9' * 64,
                                 expires_at=intent.expires_at, proofs=proofs)
        helper = approval_tests.ComposeApprovalTests()
        helper.policy = inputs['policy']
        client = helper.client_for([request])
        token_claims = dict(claims(inputs['policy']), aud=AUDIENCE)
        # One signed token has immutable times across every authority recheck.
        verifier = lambda _: deepcopy(token_claims)
        receipt = issuer.consume_approval(request, observation, operation_nonce='9' * 64,
                   proofs=proofs, client=client, oidc_token='signed', verifier=verifier)
        self.assertEqual(receipt.request_hash, request.digest())
        with self.assertRaises(AuthorizationUnavailable):
            issuer.consume_approval(request, observation, operation_nonce='9' * 64,
                   proofs=proofs, client=client, oidc_token='signed', verifier=verifier)
        client = mock.Mock()
        with self.assertRaises(ValueError):
            issuer.consume_approval(request, observation, operation_nonce='9' * 64,
                   proofs={}, client=client, oidc_token='signed', verifier=verifier)
        client.request.assert_not_called()

    def test_post_consumption_drift_burns_grant(self):
        inputs, issuer, observation, intent, proofs, result = fixture()
        request = issuer.prepare(observation, operation_nonce='9' * 64,
                                 expires_at=intent.expires_at, proofs=proofs)
        helper = approval_tests.ComposeApprovalTests()
        helper.policy = inputs['policy']
        client = helper.client_for([request])
        token_claims = dict(claims(inputs['policy']), aud=AUDIENCE)
        # One signed token has immutable times across every authority recheck.
        verifier = lambda _: deepcopy(token_claims)
        consume = GitHubComposeApproval.consume
        def consumed(approval, grant, reviewed):
            receipt = consume(approval, grant, reviewed)
            result['serviceContainerIds']['web'] = '3' * 64
            return receipt
        with mock.patch.object(GitHubComposeApproval, 'consume', consumed):
            with self.assertRaises(ValueError):
                issuer.consume_approval(request, observation, operation_nonce='9' * 64,
                   proofs=proofs, client=client, oidc_token='signed', verifier=verifier)
        result['serviceContainerIds']['web'] = '1' * 64
        with self.assertRaises(AuthorizationUnavailable):
            issuer.consume_approval(request, observation, operation_nonce='9' * 64,
                   proofs=proofs, client=client, oidc_token='signed', verifier=verifier)

    def test_malformed_large_or_recursive_records_fail_closed(self):
        inputs, issuer, observation, intent, proofs, _ = fixture()
        cyclic = deepcopy(proofs)
        cyclic['backup']['body']['statement'] = cyclic
        huge = deepcopy(proofs)
        huge['backup']['body']['reportDigest'] = 'x' * 65537
        exotic = deepcopy(proofs)
        exotic['backup']['body']['statement'] = object()
        for bundle in (cyclic, huge, exotic):
            with self.assertRaises(ValueError):
                issuer.prepare(observation, operation_nonce='9' * 64,
                               expires_at=intent.expires_at, proofs=bundle)

    def test_boolean_project_id_is_not_equal_to_numeric_identity(self):
        inputs, issuer, observation, intent, proofs, _ = fixture()
        # Python equality treats True as 1; canonical JSON comparison must not.
        source = replace(intent.source, project_id=1)
        changed_intent = replace(intent, source=source)
        changed = deepcopy(proofs)
        for kind in KINDS:
            changed[kind]['body']['requestHash'] = changed_intent.digest()
        changed['provenance']['body']['statement']['source']['projectId'] = True
        for kind in KINDS:
            changed[kind] = sign(changed[kind]['body'], kind.encode() * 32)
        with self.assertRaises(ValueError):
            inputs['proof_host'].verify(changed_intent, inputs['observer']._baseline_artifacts,
                                        inputs['target'], changed)

    def test_missing_or_tampered_archive_blocks_final_review_before_network(self):
        from pathlib import Path
        for change in ('delete', 'tamper'):
            inputs, issuer, observation, intent, proofs, _ = fixture()
            request = issuer.prepare(observation, operation_nonce='9' * 64,
                                     expires_at=intent.expires_at, proofs=proofs)
            store = inputs['recovery_host']._store
            path = Path(store._root) / inputs['recovery_reference']
            if change == 'delete':
                path.unlink()
            else:
                path.write_bytes(b'corrupt')
            client = mock.Mock()
            with self.subTest(change=change), self.assertRaises(ValueError):
                issuer.prepare(observation, operation_nonce='9' * 64,
                               expires_at=intent.expires_at, proofs=proofs)
            with self.assertRaises(ValueError):
                issuer.consume_approval(request, observation, operation_nonce='9' * 64,
                    proofs=proofs, client=client, oidc_token='signed')
            client.request.assert_not_called()
            if change == 'delete':
                self.assertFalse(path.exists())
            else:
                self.assertEqual(path.read_bytes(), b'corrupt')

    def test_valid_target_hmac_cannot_authorize_extra_configuration_change(self):
        from deployment_compose_recipe import commit_recipe
        from tests.test_deployment_compose_target_prepare import KEY
        inputs, _, observation, _, proofs, _ = fixture()
        inputs['recipes']['web']['process']['env'][0] = 'API_KEY=changed'
        recipe_hmac = commit_recipe(inputs['recipes']['web'], 'host-key-1', KEY)['hmac']
        inputs['target'] = replace(inputs['target'], services=(
            replace(inputs['target'].services[0], recipe_hmac=recipe_hmac),))
        issuer = ComposeRequestHost(**inputs)
        with self.assertRaisesRegex(ValueError, '^target-config-change-not-supported$'):
            issuer.prepare(observation, operation_nonce='9' * 64, expires_at=deadline(), proofs=proofs)

    def test_policy_rejects_shared_keys_and_empty_restore_proof(self):
        for keys, restore in [({k: (k, b'x' * 32) for k in KINDS}, '6' * 64),
                              ({k: (k, k.encode() * 32) for k in KINDS}, '0' * 64)]:
            with self.assertRaises(ValueError):
                ComposeProofHost(keys=keys, schema_digest='4' * 64,
                                 backup_digest='5' * 64, restore_test_digest=restore)


if __name__ == '__main__':
    unittest.main()
