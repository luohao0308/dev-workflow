"""Pinned GitLab preparation uses real preflight code and GET-only fake API."""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import release_gitlab_prepare_v2_host as prepare
import release_gitlab_preflight_host as preflight
from release_execute import Request as LegacyRequest


class GitLabPreparationTests(unittest.TestCase):
    def setUp(self):
        self.identity = prepare.ProviderIdentity('gitlab.com', 'https://gitlab.com/group/project.git',
                                                  42, 'group/project', 'a'*40)
        self.intent = {'preparation': {'targetSha': self.identity.source_sha},
                       'remote': {'url': self.identity.origin, 'project': self.identity.project_path},
                       'tag': {'name': 'v1.2.3', 'targetSha': self.identity.source_sha}}
        self.calls = []
        self.drift = False
        def transport(method, path, payload):
            self.calls.append((method, path, payload))
            self.assertEqual(method, 'GET')
            self.assertIsNone(payload)
            if path == '/projects/42':
                return 200, {}, {'id': 42, 'path_with_namespace': 'group/project'}
            if '/commits/' in path:
                return 200, {}, {'id': self.identity.source_sha}
            if self.drift and len(self.calls) > 6:
                return 200, {}, {'name': 'v1.2.3', 'message': None, 'target': self.identity.source_sha,
                                'commit': {'id': self.identity.source_sha}}
            return 404, {}, None
        self.client = preflight.GitLabClient('test-token', transport=transport)
        self.preflight = preflight.GitLabPreflightHost(client=self.client, expected_identity=self.identity,
                                                     repository=ROOT, remote='origin')
        self.rebuild = patch.object(preflight, 'build_intent', return_value=deepcopy(self.intent)).start()
        self.addCleanup(patch.stopall)
        self.subject = self.make()

    def make(self, **changes):
        settings = dict(preflight=self.preflight, expected_identity=self.identity,
                        host_id='host-one', policy_hash='f'*64)
        settings.update(changes)
        return prepare.GitLabRequestPreparationV2(**settings)

    def expiry(self, seconds=300):
        return (datetime.now(timezone.utc)+timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')

    def test_request_binds_preflight_host_policy_and_closed_payload(self):
        expiry = self.expiry()
        result = self.subject.prepare(self.intent, expires_at=expiry)
        request = result['request']
        self.assertIs(type(request), prepare.RequestV2)
        self.assertNotIsInstance(request, LegacyRequest)
        self.assertEqual(prepare.RequestV2.from_json(request.canonical_json()), request)
        self.assertEqual((request.operation, request.host_id, request.profile_id, request.max_uses),
                         ('remote-tag-push', 'host-one', prepare.PROFILE, 1))
        self.assertEqual(request.policy_hash, 'f'*64)
        self.assertEqual(request.identity, self.identity)
        self.assertEqual(request.target_sha, self.identity.source_sha)
        self.assertEqual(request.tag, 'v1.2.3')
        self.assertEqual(json.loads(request.provider_payload_json),
                         {'tag': request.tag, 'targetSha': request.target_sha,
                          'preflightDigest': result['preflight']['digest']})
        plan = dict(profile=prepare.PROFILE, hostId=request.host_id, identity=asdict(self.identity),
                    payload=json.loads(request.provider_payload_json))
        self.assertEqual(request.plan_hash, hashlib.sha256(prepare.PLAN_DOMAIN +
                         prepare.canonical(plan).encode('ascii')).hexdigest())
        self.assertEqual(len(self.calls), 12)
        for field in ('authorityGranted', 'executionAvailable', 'productionReady'):
            self.assertIs(result[field], False)
        with self.assertRaises(TypeError): LegacyRequest(**asdict(request))
        self.calls.clear()
        other = prepare.GitLabRequestPreparationV2(preflight=self.preflight,
            expected_identity=self.identity, host_id='host-two', policy_hash='e'*64)
        changed = other.prepare(self.intent, expires_at=expiry)['request']
        self.assertNotEqual(request.digest(), changed.digest())
        self.assertNotEqual(request.plan_hash, changed.plan_hash)

    def test_expiry_and_unsupported_operations_fail_before_network(self):
        for expiry in (self.expiry(-1), self.expiry(3700), True, 'bad'):
            with self.subTest(expiry=expiry), self.assertRaises(ValueError):
                self.subject.prepare(self.intent, expires_at=expiry)
        for operation in ('remote-release-create', True, 'deploy'):
            with self.assertRaises(ValueError):
                self.subject.prepare(self.intent, expires_at=self.expiry(), operation=operation)
        self.assertEqual(self.calls, [])

    def test_invalid_or_foreign_host_configuration_never_observes(self):
        for change in ({'host_id': True}, {'policy_hash': False}, {'preflight': {}},
                       {'expected_identity': replace(self.identity, project_id=43)},
                       {'expected_identity': replace(self.identity, source_sha='b'*40)}):
            with self.subTest(change=change), self.assertRaises(ValueError): self.make(**change)
        self.assertEqual(self.calls, [])

    def test_host_configuration_changes_are_strictly_rejected(self):
        for field, value in (('maximum_seconds', True), ('maximum_seconds', 60.0),
                             ('remote', 'other'), ('repository', str(ROOT)),
                             ('identity', replace(self.identity, project_id=43)),
                             ('client', preflight.GitLabClient('other-token', transport=lambda *args: None))):
            original = getattr(self.preflight, field)
            with self.subTest(field=field):
                setattr(self.preflight, field, value)
                with self.assertRaises(ValueError): self.subject.prepare(self.intent, expires_at=self.expiry())
                setattr(self.preflight, field, original)
        self.assertEqual(self.calls, [])

    def test_identity_boolean_mutation_is_not_hidden_by_dataclass_equality(self):
        object.__setattr__(self.identity, 'project_id', True)
        with self.assertRaises(ValueError): self.subject.prepare(self.intent, expires_at=self.expiry())
        self.assertEqual(self.calls, [])

    def test_configuration_changed_during_network_is_rejected(self):
        original = self.client.request
        def request(*args, **kwargs):
            result = original(*args, **kwargs)
            self.preflight.maximum_seconds = 60.0
            return result
        with patch.object(self.client, 'request', side_effect=request), self.assertRaises(ValueError):
            self.subject.prepare(self.intent, expires_at=self.expiry())
        self.assertEqual(len(self.calls), 6)

    def test_preflights_must_match_and_caller_context_cannot_replace_intent(self):
        self.drift = True
        with self.assertRaisesRegex(ValueError, 'observation-drift'):
            self.subject.prepare(self.intent, expires_at=self.expiry())
        self.calls.clear()
        for change in ({'authorityGranted': True}, {'preparation': {'verified': True}},
                       {'remote': {'url': 'https://gitlab.com/foreign/project.git'}}):
            with self.assertRaises(ValueError):
                self.subject.prepare({**self.intent, **change}, expires_at=self.expiry())
        self.assertEqual(self.calls, [])

    def test_real_local_preparation_is_rebuilt_without_api_writes(self):
        import tests.test_release_execute as release_tests
        patch.stopall()
        helper = release_tests.ReleaseExecuteTests(); helper.setUp()
        self.addCleanup(helper.doCleanups)
        helper.git('remote', 'set-url', 'origin', self.identity.origin)
        identity = replace(self.identity, source_sha=helper.sha)
        intent = preflight.build_intent(helper.root, helper.preparation, remote='origin', project_id=42)
        def transport(method, path, payload):
            self.assertEqual(method, 'GET'); self.assertIsNone(payload)
            if path == '/projects/42': return 200, {}, {'id': 42, 'path_with_namespace': 'group/project'}
            if '/commits/' in path: return 200, {}, {'id': helper.sha}
            return 404, {}, None
        host = preflight.GitLabPreflightHost(client=preflight.GitLabClient('test-token', transport=transport),
            expected_identity=identity, repository=helper.root, remote='origin')
        subject = prepare.GitLabRequestPreparationV2(preflight=host, expected_identity=identity,
                                                    host_id='host-one', policy_hash='f'*64)
        self.assertEqual(subject.prepare(intent, expires_at=self.expiry())['request'].target_sha, helper.sha)
        (helper.root/'dirty-untracked').write_text('changed')
        with self.assertRaises(ValueError): subject.prepare(intent, expires_at=self.expiry())
