from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/release_gitlab_preflight_host.py'
SPEC = importlib.util.spec_from_file_location('release_gitlab_preflight_host_under_test', SCRIPT)
host = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = host
SPEC.loader.exec_module(host)


class GitLabPreflightTests(unittest.TestCase):
    def setUp(self):
        self.sha = 'a' * 40
        self.identity = host.ProviderIdentity('gitlab.com', 'https://gitlab.com/group/project.git',
                                              42, 'group/project', self.sha)
        self.intent = {'preparation': {'targetSha': self.sha},
                       'remote': {'url': self.identity.origin, 'project': 'group/project'},
                       'tag': {'name': 'v1.2.3', 'targetSha': self.sha}}
        self.calls = []
        self.replies = [{'id': 42, 'path_with_namespace': 'group/project'}, {'id': self.sha}, None] * 2
        self.rebuild = mock.patch.object(host, 'build_intent', return_value=deepcopy(self.intent)).start()
        self.addCleanup(mock.patch.stopall)
        self.client = host.GitLabClient('host-test-token', transport=self.transport)
        self.subject = host.GitLabPreflightHost(client=self.client, expected_identity=self.identity,
                                               repository=SCRIPT.parent, remote='origin')

    def transport(self, method, path, payload):
        self.calls.append((method, path, payload))
        self.assertEqual(method, 'GET')
        self.assertIsNone(payload)
        reply = self.replies[len(self.calls) - 1]
        return (404 if reply is None else 200), {}, deepcopy(reply)

    def test_missing_tag_evidence_is_deterministic_and_get_only(self):
        first = self.subject.observe(self.intent)
        self.assertEqual(first['context']['observation']['tagStatus'], 'missing')
        self.assertFalse(first['context']['authorityGranted'])
        self.assertFalse(first['context']['executionAvailable'])
        self.assertEqual(len(self.calls), 6)
        self.assertEqual([p for _, p, _ in self.calls[:3]], [
            '/projects/42', '/projects/42/repository/commits/' + self.sha,
            '/projects/42/repository/tags/v1.2.3'])
        self.calls.clear()
        self.assertEqual(first, self.subject.observe(self.intent))

    def test_boolean_numeric_intent_substitution_rejected_before_network(self):
        self.intent['authorityGranted'] = False
        self.rebuild.return_value = deepcopy(self.intent)
        changed = deepcopy(self.intent)
        changed['authorityGranted'] = 0
        with self.assertRaises(host.IdentityConflict):
            self.subject.observe(changed)
        self.assertEqual(self.calls, [])

    def test_real_local_preparation_rebuild_with_mocked_gitlab_reads(self):
        import tests.test_release_execute as release_tests
        mock.patch.stopall()
        helper = release_tests.ReleaseExecuteTests()
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        helper.git('remote', 'set-url', 'origin', 'https://gitlab.com/group/project.git')
        identity = host.ProviderIdentity('gitlab.com', 'https://gitlab.com/group/project.git',
                                         42, 'group/project', helper.sha)
        intent = host.build_intent(helper.root, helper.preparation, remote='origin', project_id=42)
        def transport(method, path, payload):
            self.assertEqual(method, 'GET')
            if path == '/projects/42':
                return 200, {}, {'id': 42, 'path_with_namespace': 'group/project'}
            if '/commits/' in path:
                return 200, {}, {'id': helper.sha}
            return 404, {}, None
        client = host.GitLabClient('test-token', transport=transport)
        subject = host.GitLabPreflightHost(client=client, expected_identity=identity,
                                           repository=helper.root, remote='origin')
        self.assertEqual(subject.observe(intent)['context']['observation']['tagStatus'], 'missing')
        (helper.root / 'dirty-untracked').write_text('changed')
        with self.assertRaises((host.ExecutionError, release_tests.execution.preparation_tool.PreparationError)):
            subject.observe(intent)

    def matching_tag(self):
        return {'name': 'v1.2.3', 'message': None, 'target': self.sha, 'commit': {'id': self.sha}}

    def test_matching_tag(self):
        self.replies[2] = self.replies[5] = self.matching_tag()
        self.assertEqual(self.subject.observe(self.intent)['context']['observation']['tagStatus'], 'matching')

    def test_project_path_or_id_drift(self):
        for index in (0, 3):
            for field, value in (('path_with_namespace', 'foreign/project'), ('id', 43), ('id', True)):
                with self.subTest(index=index, field=field, value=value):
                    self.calls.clear()
                    self.replies = [{'id': 42, 'path_with_namespace': 'group/project'}, {'id': self.sha}, None] * 2
                    self.replies[index] = {**self.replies[index], field: value}
                    with self.assertRaises(host.IdentityConflict):
                        self.subject.observe(self.intent)

    def test_missing_source(self):
        self.replies[1] = None
        with self.assertRaises(host.IdentityConflict):
            self.subject.observe(self.intent)

    def test_conflicting_tag_and_annotation(self):
        for change in ({'target': 'b' * 40}, {'message': 'annotated'}, {'commit': {'id': 'b' * 40}}):
            self.calls.clear()
            self.replies[2] = {**self.matching_tag(), **change}
            with self.assertRaises(host.IdentityConflict):
                self.subject.observe(self.intent)

    def test_read_drift(self):
        self.replies[5] = self.matching_tag()
        with self.assertRaisesRegex(host.IdentityConflict, 'changed'):
            self.subject.observe(self.intent)

    def test_unknown_intent_and_foreign_identity_rejected_before_network(self):
        for change in ({'unknown': True}, {'remote': {'url': 'https://gitlab.com/foreign/project.git'}},
                       {'tag': {'name': 'v1.2.3', 'targetSha': 'b' * 40}}):
            with self.subTest(change=change), self.assertRaises(host.IdentityConflict):
                self.subject.observe({**self.intent, **change})
        self.assertEqual(self.calls, [])

    def test_host_identity_independent_of_rebuilt_intent(self):
        self.rebuild.return_value['tag']['targetSha'] = 'b' * 40
        with self.assertRaises(host.IdentityConflict):
            self.subject.observe(self.rebuild.return_value)
        self.assertEqual(self.calls, [])

    def test_unsupported_operation_and_expired_read_window(self):
        with self.assertRaises(host.ExecutionError):
            self.subject.observe(self.intent, operation='remote-release-create')
        self.assertEqual(self.calls, [])
        with mock.patch.object(host.time, 'monotonic', side_effect=[0, 0, 61]):
            with self.assertRaisesRegex(host.ExecutionError, 'time bound'):
                self.subject.observe(self.intent)
        self.assertEqual(len(self.calls), 1)

    def test_unavailable_response_blocks(self):
        with mock.patch.object(self.client, 'request', side_effect=host.ExecutionError('unavailable')):
            with self.assertRaises(host.ExecutionError):
                self.subject.observe(self.intent)


if __name__ == '__main__':
    unittest.main()
