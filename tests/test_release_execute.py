from __future__ import annotations

import copy
from dataclasses import replace
from datetime import timedelta
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'packs/release/scripts/release_execute.py'
SPEC = importlib.util.spec_from_file_location('release_execute_under_test', SCRIPT)
execution = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = execution
SPEC.loader.exec_module(execution)
URL = 'https://github.com/example/approved.git'


def write_utf8(path, value):
    path.write_bytes(value.encode('utf-8'))


def git_at(root, *arguments):
    return subprocess.run(['git', '-C', str(root), *arguments], check=True,
                          capture_output=True, encoding='utf-8').stdout.strip()


class TestApprovalHost:
    """Test-only host: authority and atomic counters live outside repository data."""
    def __init__(self, *, max_uses=1, expires=None):
        self.max_uses = max_uses
        self.expires = expires or execution.clock() + timedelta(minutes=5)
        self.lock = threading.Lock()
        self.requests = []
        self.grants = {}
        self.uses = {}
        self.consume_calls = 0
        self.on_validate = None
        self.on_consume = None
        self.transform_grant = lambda grant: grant
        self.transform_receipt = lambda receipt: receipt

    def validate(self, request):
        with self.lock:
            self.requests.append(request)
            digest = request.digest()
            if digest not in self.grants:
                self.grants[digest] = execution.Grant('test-grant-' + str(len(self.grants)), digest,
                                                     self.expires.isoformat(), self.max_uses)
            grant = self.transform_grant(self.grants[digest])
        if self.on_validate:
            self.on_validate(request)
        return grant

    def consume(self, grant, request):
        with self.lock:
            self.consume_calls += 1
            expected = self.grants.get(request.digest())
            if expected != grant or execution.timestamp(grant.expires_at) <= execution.clock():
                raise execution.ExecutionError('Host refused invalid, expired or mismatched grant')
            used = self.uses.get(grant.grant_id, 0)
            if used >= grant.max_uses:
                raise execution.ExecutionError('Host grant exhausted')
            self.uses[grant.grant_id] = used + 1
            receipt = execution.Receipt(grant.grant_id, request.digest(), used + 1,
                                         execution.clock().isoformat())
        if self.on_consume:
            self.on_consume(request)
        return self.transform_receipt(receipt)


class BareTagProvider:
    """Approved URL transport mapping stays in the host; pushes use real Git."""
    def __init__(self, root, bare):
        self.root, self.bare = root, bare
        self.pushes = 0
        self.reads = 0
        self.mode = None
        self.on_inspect = None

    def inspect(self, request):
        if request.remote_url != URL or request.remote_name != 'origin':
            raise AssertionError('Provider received an unapproved remote identity')
        self.reads += 1
        if self.on_inspect:
            self.on_inspect(request)
        if self.mode == 'read-failure' or (self.mode == 'read-failure-after-push' and self.pushes):
            raise OSError('Authoritative transport unavailable: Bearer TEST_PROVIDER_SECRET')
        ref = 'refs/tags/' + request.tag
        result = subprocess.run(['git', '-C', str(self.bare), 'show-ref', '--verify', '--quiet', ref],
                                capture_output=True, encoding='utf-8')
        if result.returncode == 1:
            return None
        if result.returncode:
            raise OSError('Bare tag inspection failed: ' + result.stderr)
        return {'objectSha': git_at(self.bare, 'rev-parse', ref),
                'targetSha': git_at(self.bare, 'rev-parse', ref + '^{commit}')}

    def push(self, request):
        if request.remote_url != URL:
            raise AssertionError('Unexpected push destination')
        self.pushes += 1
        if self.mode == 'reject':
            raise execution.ProviderRejected('Server rejected tag creation: Bearer TEST_PROVIDER_SECRET')
        execution.run_git(self.root, 'push', '--no-verify', str(self.bare),
                          request.tag_object_sha + ':refs/tags/' + request.tag)
        if self.mode == 'lost-response':
            raise OSError('Push response lost after server accepted it')


class TestReleaseProvider:
    """A test platform whose inspection returns the complete authoritative identity."""
    def __init__(self):
        self.record = None
        self.creates = 0
        self.mode = None

    @staticmethod
    def identity(request):
        payload = json.loads(request.release_json)
        assert payload['endpoint'] == 'https://api.github.com'
        assert payload['repository'] == 'example/approved'
        assert payload['repositoryId'] == 42
        return dict(payload, tag=request.tag, tagObjectSha=request.tag_object_sha,
                    targetSha=request.target_sha, releaseId=101)

    def inspect(self, request):
        self.identity(request)
        if self.mode == 'read-failure' or (self.mode == 'read-failure-after-create' and self.creates):
            raise OSError('Release read unavailable')
        return copy.deepcopy(self.record)

    def create(self, request):
        self.creates += 1
        if self.mode == 'reject':
            raise execution.ProviderRejected('Release rejected')
        self.record = self.identity(request)
        if self.mode == 'mutated-response':
            self.record['body'] = 'Unapproved server payload'
        if self.mode == 'lost-response':
            raise OSError('Release accepted but response lost')


class ReleaseExecuteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.root, self.bare = base / 'repository', base / 'remote.git'
        self.root.mkdir()
        git_at(self.root, 'init', '-q')
        git_at(self.root, 'config', 'user.name', 'Test')
        git_at(self.root, 'config', 'user.email', 'test@example.invalid')
        git_at(self.root, 'config', 'commit.gpgsign', 'false')
        git_at(self.root, 'config', 'tag.gpgsign', 'false')
        git_at(base, 'init', '--bare', '-q', str(self.bare))
        write_utf8(self.root / '.git/info/exclude', '.dev-workflow/\n')
        (self.root / '.dev-workflow').mkdir()
        write_utf8(self.root / '.dev-workflow/manifest.json', json.dumps({
            'managedBy': 'dev-workflow', 'schemaVersion': 5, 'enabledCapabilities': []}))
        self.config = {'schemaVersion': 1, 'enabledCapabilities': ['release'], 'commands': {},
                       'documents': {}, 'extensions': {'release': {'strategy': 'semver-tag',
                       'tagPrefix': 'v', 'components': ['web']}}}
        self.save_config()
        self.sha = self.git('rev-parse', 'HEAD')
        self.git('remote', 'add', 'origin', URL)
        self.spec = {'endpoint': 'https://api.github.com', 'repository': 'example/approved',
                     'repositoryId': 42, 'name': 'Release 1.2.3', 'body': 'Approved notes: 发布\n',
                     'draft': False, 'prerelease': False}
        self.preparation = execution.preparation_tool.prepare(self.root, 'HEAD', '1.2.3', [], [])
        self.plan = execution.build_plan(self.root, self.preparation, remote='origin', release=self.spec)
        self.host = TestApprovalHost()
        self.tags = BareTagProvider(self.root, self.bare)
        self.releases = TestReleaseProvider()

    def git(self, *arguments):
        return git_at(self.root, *arguments)

    def save_config(self):
        write_utf8(self.root / 'workflow.config.json', json.dumps(self.config))
        result = subprocess.run([sys.executable, str(SCRIPT.parents[3] / 'core/scripts/workflow_config.py'),
                                 'adopt', '--repo', str(self.root)], capture_output=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.git('add', '.')
        self.git('commit', '-qm', 'configuration', '--allow-empty')

    def execute(self, operation='local-tag-create', **overrides):
        arguments = dict(approval=self.host, tag_provider=self.tags, release_provider=self.releases)
        arguments.update(overrides)
        return execution.execute(self.root, self.plan, operation, **arguments)

    def seed_remote(self):
        self.git('tag', 'v1.2.3', self.sha)
        execution.run_git(self.root, 'push', '--no-verify', str(self.bare), self.sha + ':refs/tags/v1.2.3')

    def assert_no_mutation(self):
        self.assertEqual(self.git('tag'), '')
        self.assertEqual(self.tags.pushes, 0)
        self.assertEqual(self.releases.creates, 0)

    def assert_refused(self, **kwargs):
        with self.assertRaises((execution.ExecutionError, execution.preparation_tool.PreparationError, ValueError)):
            self.execute(**kwargs)

    def test_local_creation_is_lightweight_and_verified(self):
        result = self.execute()
        self.assertEqual(result['status'], 'created_verified')
        self.assertEqual(self.git('rev-parse', 'refs/tags/v1.2.3'), self.sha)
        self.assertEqual(self.git('cat-file', '-t', 'refs/tags/v1.2.3'), 'commit')
        self.assertTrue(result['authorizationConsumed'])
        self.assertEqual(self.host.consume_calls, 1)

    def test_duplicate_same_object_has_no_second_mutation_or_consumption(self):
        self.execute()
        result = self.execute()
        self.assertEqual(result['status'], 'already_present_verified')
        self.assertFalse(result['authorizationConsumed'])
        self.assertEqual(self.host.consume_calls, 1)

    def test_host_guard_revocation_prevents_local_tag_after_consumption(self):
        self.host.guard = mock.Mock(side_effect=execution.AuthorizationUnavailable('Host revoked approval'))
        result = self.execute()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['phase'], 'pre-dispatch')
        self.assertEqual(self.host.consume_calls, 1)
        self.host.guard.assert_called_once()
        self.assertEqual(self.git('tag'), '')

    def test_existing_annotated_tag_at_same_commit_is_refused(self):
        self.git('tag', '-a', 'v1.2.3', '-m', 'annotated', self.sha)
        self.assertNotEqual(self.git('rev-parse', 'v1.2.3'), self.sha)
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 0)

    def test_absent_only_local_creation_does_not_overwrite_racing_tag(self):
        self.host.on_consume = lambda request: self.git('tag', '-a', request.tag, '-m', 'race', self.sha)
        result = self.execute()
        self.assertEqual(result['status'], 'conflict')
        self.assertEqual(self.git('cat-file', '-t', 'v1.2.3'), 'tag')

    def test_remote_push_uses_real_bare_repository_and_duplicate_is_read_only(self):
        self.execute()
        result = self.execute('remote-tag-push')
        self.assertEqual(result['status'], 'created_verified')
        self.assertEqual(git_at(self.bare, 'rev-parse', 'refs/tags/v1.2.3'), self.sha)
        self.assertEqual(self.execute('remote-tag-push')['status'], 'already_present_verified')
        self.assertEqual(self.tags.pushes, 1)
        self.assertEqual(self.host.consume_calls, 2)

    def test_remote_rejection_keeps_successful_local_tag(self):
        self.execute()
        self.tags.mode = 'reject'
        result = self.execute('remote-tag-push')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.git('rev-parse', 'v1.2.3'), self.sha)
        self.assertEqual(self.releases.creates, 0)
        self.assertEqual(set(result['states'].values()), {'unknown'})

    def test_remote_push_lost_response_is_reconciled(self):
        self.execute()
        self.tags.mode = 'lost-response'
        self.assertEqual(self.execute('remote-tag-push')['status'], 'already_present_verified')
        self.assertEqual(self.tags.pushes, 1)

    def test_remote_requires_existing_approved_local_tag(self):
        self.assert_refused(operation='remote-tag-push')
        self.assertEqual(self.host.consume_calls, 0)
        self.assert_no_mutation()

    def test_remote_same_commit_different_raw_annotated_object_conflicts(self):
        self.git('tag', '-a', 'v1.2.3', '-m', 'remote annotated', self.sha)
        raw = self.git('rev-parse', 'v1.2.3')
        execution.run_git(self.root, 'push', '--no-verify', str(self.bare), raw + ':refs/tags/v1.2.3')
        self.git('tag', '-d', 'v1.2.3')
        self.git('tag', 'v1.2.3', self.sha)
        self.assert_refused(operation='remote-tag-push')
        self.assertEqual(self.tags.pushes, 0)
        self.assertEqual(git_at(self.bare, 'rev-parse', 'v1.2.3'), raw)

    def test_release_create_verifies_complete_payload_and_deduplicates(self):
        self.seed_remote()
        result = self.execute('remote-release-create')
        self.assertEqual(result['status'], 'created_verified')
        self.assertEqual(result['releaseId'], 101)
        self.assertEqual(self.releases.record['body'], self.spec['body'])
        self.assertEqual(self.execute('remote-release-create')['status'], 'already_present_verified')
        self.assertEqual(self.releases.creates, 1)
        self.assertEqual(self.host.consume_calls, 1)

    def test_release_rejection_is_failed(self):
        self.seed_remote()
        self.releases.mode = 'reject'
        self.assertEqual(self.execute('remote-release-create')['status'], 'failed')
        self.assertIsNone(self.releases.record)

    def test_release_mutated_response_conflicts(self):
        self.seed_remote()
        self.releases.mode = 'mutated-response'
        self.assertEqual(self.execute('remote-release-create')['status'], 'conflict')
        self.assert_refused(operation='remote-release-create')
        self.assertEqual(self.releases.creates, 1)

    def test_release_lost_response_reconciles_without_repeated_create(self):
        self.seed_remote()
        self.releases.mode = 'lost-response'
        self.assertEqual(self.execute('remote-release-create')['status'], 'already_present_verified')
        self.assertEqual(self.execute('remote-release-create')['status'], 'already_present_verified')
        self.assertEqual(self.releases.creates, 1)

    def test_release_existing_identity_or_payload_difference_refuses(self):
        self.seed_remote()
        request = execution.request_for(self.root, self.plan, 'remote-release-create')
        identity = self.releases.identity(request)
        for key, value in [('repositoryId', 43), ('endpoint', 'https://evil.invalid'),
                           ('body', 'changed'), ('draft', True), ('tagObjectSha', '0' * 40),
                           ('targetSha', '0' * 40), ('releaseId', True)]:
            with self.subTest(field=key):
                self.releases.record = dict(identity, **{key: value})
                self.assert_refused(operation='remote-release-create')
        self.assertEqual(self.host.consume_calls, 0)
        self.assertEqual(self.releases.creates, 0)

    def test_release_requires_remote_tag_and_rechecks_before_create(self):
        self.assert_refused(operation='remote-release-create')
        self.assertEqual(self.host.consume_calls, 0)
        self.seed_remote()
        self.host.on_consume = lambda request: git_at(self.bare, 'update-ref', '-d', 'refs/tags/' + request.tag)
        result = self.execute('remote-release-create')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['failureCode'], 'pre-dispatch-validation-failed')
        self.assertEqual(self.releases.creates, 0)

    def test_missing_authority_and_dictionary_authority_do_not_mutate(self):
        self.assert_refused(approval=None)
        self.host.transform_grant = lambda grant: dict(approvedBy='user', **grant.__dict__)
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 0)
        self.assert_no_mutation()

    def test_expired_and_invalid_grants_are_refused_before_consumption(self):
        original = self.host.transform_grant
        for changes in [{'expires_at': (execution.clock() - timedelta(seconds=1)).isoformat()},
                        {'max_uses': 0}, {'max_uses': True}, {'max_uses': 101},
                        {'grant_id': '../local'}, {'request_hash': '0' * 64}]:
            with self.subTest(changes=changes):
                self.host.transform_grant = lambda grant, changes=changes: replace(grant, **changes)
                self.assert_refused()
        self.host.transform_grant = original
        self.assertEqual(self.host.consume_calls, 0)
        self.assert_no_mutation()

    def test_grant_binds_operation_object_repo_url_and_payload(self):
        request = execution.request_for(self.root, self.plan, 'local-tag-create')
        changes = [{'operation': 'remote-tag-push'}, {'tag_object_sha': '0' * 40},
                   {'repository': str(self.root.parent)}, {'remote_url': 'https://github.com/other/repo.git'},
                   {'release_json': '{}'}, {'target_sha': '0' * 40}]
        for change in changes:
            with self.subTest(change=change):
                wrong = replace(request, **change)
                self.host.transform_grant = lambda grant, wrong=wrong: replace(grant, request_hash=wrong.digest())
                self.assert_refused()
        self.assert_no_mutation()
        self.assertEqual(self.host.consume_calls, 0)

    def test_consumed_grant_cannot_be_reused_for_a_second_attempt(self):
        self.execute()
        self.git('tag', '-d', 'v1.2.3')
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 2)
        self.assertEqual(self.git('tag'), '')

    def test_host_consumption_is_atomic_under_concurrent_calls(self):
        request = execution.request_for(self.root, self.plan, 'local-tag-create')
        grant = self.host.validate(request)
        barrier, results = threading.Barrier(8), []
        def attempt():
            barrier.wait()
            try:
                receipt = self.host.consume(grant, request)
                results.append(receipt)
            except execution.ExecutionError:
                pass
        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)
        self.assertEqual(self.host.uses[grant.grant_id], 1)

    def test_invalid_consumption_receipts_prevent_mutation(self):
        for changes in [{'request_hash': '0' * 64}, {'grant_id': 'different'},
                        {'use_number': 0}, {'use_number': True}, {'use_number': 2},
                        {'consumed_at': (execution.clock() - timedelta(minutes=1)).isoformat()}]:
            with self.subTest(changes=changes):
                self.host = TestApprovalHost()
                self.host.transform_receipt = lambda receipt, changes=changes: replace(receipt, **changes)
                self.assert_refused()
                self.assert_no_mutation()

    def test_plan_forgery_is_refused(self):
        original = self.plan
        for field, value in [('tagObjectSha', '0' * 40), ('repository', str(self.root.parent)),
                             ('requiresTrustedHost', False), ('schemaVersion', 2),
                             ('release', dict(self.spec, body='forged'))]:
            with self.subTest(field=field):
                self.plan = dict(original, **{field: value})
                # A changed valid payload needs fresh host consent, not the old request grant.
                if field == 'release':
                    request = execution.request_for(self.root, original, 'local-tag-create')
                    self.host.transform_grant = lambda grant: replace(grant, request_hash=request.digest())
                self.assert_refused()
        self.assert_no_mutation()

    def test_head_drift_before_validation_refuses(self):
        self.git('commit', '--allow-empty', '-qm', 'new head')
        self.assert_refused()
        self.assertEqual(self.host.requests, [])
        self.assert_no_mutation()

    def test_target_reference_drift_refuses_with_unchanged_head(self):
        self.git('branch', 'release-target')
        self.git('commit', '--allow-empty', '-qm', 'next')
        prepared = execution.preparation_tool.prepare(self.root, 'release-target', '1.2.3', [], [])
        self.plan = execution.build_plan(self.root, prepared, remote='origin', release=self.spec)
        self.git('branch', '-f', 'release-target', 'HEAD')
        self.assert_refused()
        self.assert_no_mutation()

    def test_configuration_drift_refuses(self):
        self.config['extensions']['release']['components'] = []
        self.save_config()
        self.assert_refused()
        self.assert_no_mutation()

    def test_remote_drift_before_and_after_consumption_refuses(self):
        for timing in ['before', 'after']:
            with self.subTest(timing=timing):
                self.git('remote', 'set-url', 'origin', URL)
                self.host = TestApprovalHost()
                callback = lambda request: self.git('remote', 'set-url', 'origin', 'https://github.com/other/repo.git')
                if timing == 'before':
                    self.host.on_validate = callback
                else:
                    self.host.on_consume = callback
                self.assert_refused()
                self.assertEqual(self.host.consume_calls, 0 if timing == 'before' else 1)
                self.assert_no_mutation()

    def test_head_drift_after_consumption_refuses(self):
        self.host.on_consume = lambda request: self.git('commit', '--allow-empty', '-qm', 'callback changed HEAD')
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 1)
        self.assert_no_mutation()

    def test_dirty_worktree_refuses(self):
        write_utf8(self.root / 'untracked.txt', 'User work\n')
        self.assert_refused()
        self.assert_no_mutation()

    def test_pending_upgrade_and_invalid_history_block_execution(self):
        history = self.root / '.dev-workflow/upgrades'
        journal_dir = history / ('a' * 32)
        journal_dir.mkdir(parents=True)
        write_utf8(journal_dir / 'journal.json', json.dumps({'schemaVersion': 1, 'target': str(self.root),
                   'transaction': journal_dir.name, 'status': 'pending'}))
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 0)
        (journal_dir / 'journal.json').unlink()
        self.assert_refused()
        self.assert_no_mutation()

    def test_audit_states_are_independently_unknown(self):
        result = self.execute()
        audit = self.root / '.dev-workflow/releases' / ('execution-' + result['attempt'] + '.json')
        self.assertEqual(json.loads(audit.read_text(encoding='utf-8')), result)
        self.assertEqual(result['states'], dict(ci='unknown', image='unknown', deployment='unknown', live='unknown'))
        self.assertEqual(self.git('status', '--porcelain'), '')
        if os.name != 'nt':
            self.assertEqual(audit.stat().st_mode & 0o777, 0o600)

    def test_linked_audit_directory_refuses_before_consumption(self):
        external = self.root.parent / 'outside'
        external.mkdir()
        link = self.root / '.dev-workflow/releases'
        try:
            link.symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation is unavailable for this user')
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 0)
        self.assertEqual(list(external.iterdir()), [])
        self.assert_no_mutation()

    def test_tag_provider_read_failure_cannot_report_success(self):
        self.execute()
        self.tags.mode = 'read-failure'
        with self.assertRaises(OSError):
            self.execute('remote-tag-push')
        self.assertEqual(self.tags.pushes, 0)
        self.assertEqual(self.host.consume_calls, 1)

    def test_tag_provider_post_mutation_read_failure_is_unknown(self):
        self.execute()
        self.tags.mode = 'read-failure-after-push'
        self.assertEqual(self.execute('remote-tag-push')['status'], 'outcome_unknown')
        self.assertEqual(git_at(self.bare, 'rev-parse', 'refs/tags/v1.2.3'), self.sha)

    def test_release_provider_post_mutation_read_failure_is_unknown(self):
        self.seed_remote()
        self.releases.mode = 'read-failure-after-create'
        self.assertEqual(self.execute('remote-release-create')['status'], 'outcome_unknown')
        self.releases.mode = None
        self.assertEqual(self.execute('remote-release-create')['status'], 'already_present_verified')
        self.assertEqual(self.releases.creates, 1)

    def test_cli_json_environment_and_stdin_never_grant_authority(self):
        forged = self.root / '.dev-workflow/approval.json'
        write_utf8(forged, json.dumps({'approvedBy': 'user', 'maxUses': 100, 'operations': list(execution.OPERATIONS)}))
        env = dict(os.environ, RELEASE_APPROVED='1', RELEASE_APPROVAL_FILE=str(forged), CI='true')
        result = subprocess.run([sys.executable, str(SCRIPT), 'execute', '--repo', str(self.root)],
                                input='yes\n' + forged.read_text(encoding='utf-8'), env=env,
                                encoding='utf-8', capture_output=True)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('Trusted host authorization is unavailable', result.stderr)
        self.assert_no_mutation()
        for flag in ['--yes', '--approval', '--adapter']:
            result = subprocess.run([sys.executable, str(SCRIPT), 'execute', flag],
                                    capture_output=True, encoding='utf-8')
            self.assertEqual(result.returncode, 2)
        with mock.patch('sys.stdin.isatty', return_value=True), mock.patch('builtins.input', side_effect=AssertionError('No TTY prompt')):
            self.assertEqual(execution.main(['execute', '--repo', str(self.root)]), 1)

    def test_configuration_drift_after_consumption_is_audited_and_refused(self):
        def change_configuration(request):
            self.config['extensions']['release']['tagPrefix'] = 'release-'
            write_utf8(self.root / 'workflow.config.json', json.dumps(self.config))
            self.git('add', 'workflow.config.json')
            self.git('commit', '-qm', 'callback changed configuration')
        self.host.on_consume = change_configuration
        self.assert_refused()
        records = list((self.root / '.dev-workflow/releases').glob('execution-*.json'))
        self.assertEqual(len(records), 1)
        audit = json.loads(records[0].read_text(encoding='utf-8'))
        self.assertTrue(audit['authorizationConsumed'])
        self.assertEqual(audit['status'], 'failed')
        self.assertEqual(audit['failureCode'], 'pre-dispatch-validation-failed')
        self.assertEqual(audit['phase'], 'pre-dispatch')
        self.assert_no_mutation()

    def test_target_reference_drift_after_consumption_refuses(self):
        self.git('branch', 'release-target')
        self.git('commit', '--allow-empty', '-qm', 'next')
        prepared = execution.preparation_tool.prepare(self.root, 'release-target', '1.2.3', [], [])
        self.plan = execution.build_plan(self.root, prepared, remote='origin', release=self.spec)
        self.host.on_consume = lambda request: self.git('branch', '-f', 'release-target', 'HEAD')
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 1)
        self.assert_no_mutation()

    def test_expiry_during_consumption_prevents_mutation(self):
        now = execution.clock()
        self.host = TestApprovalHost(expires=now + timedelta(seconds=10))
        def expire(request):
            patcher = mock.patch.object(execution, 'clock', return_value=now + timedelta(seconds=20))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.host.on_consume = expire
        self.assert_refused()
        self.assert_no_mutation()

    def test_local_tag_changed_during_consumption_cannot_be_pushed(self):
        self.execute()
        self.host.on_consume = lambda request: self.git('tag', '-f', '-a', request.tag, '-m', 'replacement', self.sha)
        self.assert_refused(operation='remote-tag-push')
        self.assertEqual(self.tags.pushes, 0)
        self.assertEqual(self.git('cat-file', '-t', 'v1.2.3'), 'tag')

    def test_remote_tag_changes_during_release_verification_conflict(self):
        self.seed_remote()
        self.git('tag', '-a', 'replacement', '-m', 'different raw identity', self.sha)
        other = self.git('rev-parse', 'replacement')
        execution.run_git(self.root, 'push', '--no-verify', str(self.bare), other + ':refs/tags/replacement')
        request = execution.request_for(self.root, self.plan, 'remote-release-create')
        self.releases.record = self.releases.identity(request)
        original = self.releases.inspect
        def inspect_and_change(request):
            observation = original(request)
            git_at(self.bare, 'update-ref', 'refs/tags/' + request.tag, other)
            return observation
        self.releases.inspect = inspect_and_change
        self.assert_refused(operation='remote-release-create')
        self.assertEqual(self.host.consume_calls, 0)
        self.assertEqual(self.releases.creates, 0)

    def test_remote_tag_changes_after_release_create_conflict(self):
        self.seed_remote()
        self.git('tag', '-a', 'replacement', '-m', 'different raw identity', self.sha)
        other = self.git('rev-parse', 'replacement')
        execution.run_git(self.root, 'push', '--no-verify', str(self.bare), other + ':refs/tags/replacement')
        original = self.releases.create
        def create_and_change(request):
            original(request)
            git_at(self.bare, 'update-ref', 'refs/tags/' + request.tag, other)
        self.releases.create = create_and_change
        self.assertEqual(self.execute('remote-release-create')['status'], 'conflict')
        self.assertEqual(self.releases.creates, 1)

    def test_release_provider_initial_read_failure_never_consumes_authority(self):
        self.seed_remote()
        self.releases.mode = 'read-failure'
        with self.assertRaises(OSError):
            self.execute('remote-release-create')
        self.assertEqual(self.host.consume_calls, 0)
        self.assertEqual(self.releases.creates, 0)

    def test_unignored_audit_records_refuse_before_consumption(self):
        write_utf8(self.root / '.git/info/exclude', '.dev-workflow/manifest.json\n')
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 0)
        self.assert_no_mutation()

    def test_tracked_workflow_records_refuse_before_consumption(self):
        self.git('add', '-f', '.dev-workflow/manifest.json')
        self.git('commit', '-qm', 'incorrectly tracked local metadata')
        self.preparation = execution.preparation_tool.prepare(self.root, 'HEAD', '1.2.3', [], [])
        self.plan = execution.build_plan(self.root, self.preparation, remote='origin', release=self.spec)
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 0)
        self.assert_no_mutation()

    def test_symbolic_local_tag_refuses(self):
        self.git('symbolic-ref', 'refs/tags/v1.2.3', 'refs/heads/' + self.git('branch', '--show-current'))
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 0)
        self.assertEqual(self.git('symbolic-ref', 'refs/tags/v1.2.3'), 'refs/heads/' + self.git('branch', '--show-current'))

    def test_final_remote_tag_read_head_drift_prevents_release_create(self):
        self.seed_remote()
        changed = []
        def change_head(request):
            if self.host.consume_calls and not changed:
                changed.append(True)
                self.git('commit', '--allow-empty', '-qm', 'provider callback changed HEAD')
        self.tags.on_inspect = change_head
        result = self.execute('remote-release-create')
        self.assertEqual(self.releases.creates, 0)
        self.assertTrue(result['authorizationConsumed'])
        self.assertEqual(self.host.consume_calls, 1)
        self.assertNotIn(result['status'], ('created_verified', 'already_present_verified'))

    def test_final_remote_tag_read_expiry_prevents_release_create(self):
        self.seed_remote()
        now = execution.clock()
        self.host = TestApprovalHost(expires=now + timedelta(minutes=5))
        changed = []
        def expire(request):
            if self.host.consume_calls and not changed:
                changed.append(True)
                patcher = mock.patch.object(execution, 'clock', return_value=now + timedelta(minutes=6))
                patcher.start()
                self.addCleanup(patcher.stop)
        self.tags.on_inspect = expire
        result = self.execute('remote-release-create')
        self.assertEqual(self.releases.creates, 0)
        self.assertTrue(result['authorizationConsumed'])
        self.assertEqual(self.host.consume_calls, 1)
        self.assertNotIn(result['status'], ('created_verified', 'already_present_verified'))

    def test_sentinel_only_ignore_does_not_authorize_actual_audit_filename(self):
        write_utf8(self.root / '.git/info/exclude', '.dev-workflow/*\n!.dev-workflow/releases/\n'
                   '.dev-workflow/releases/execution-local.json\n')
        self.assert_refused()
        self.assertEqual(self.host.consume_calls, 0)
        self.assert_no_mutation()

    def test_safe_diagnostics_distinguish_rejection_from_unavailable_verification(self):
        self.execute()
        for mode, status, reason in [('reject', 'failed', 'provider-rejected'),
                                     ('read-failure-after-push', 'outcome_unknown', 'verification-unavailable')]:
            with self.subTest(mode=mode):
                self.host = TestApprovalHost()
                self.tags = BareTagProvider(self.root, self.bare)
                self.tags.mode = mode
                result = self.execute('remote-tag-push')
                self.assertEqual(result['status'], status)
                self.assertEqual(result['failureCode'], reason)
                self.assertEqual(result['phase'], 'verification')
                audit_path = self.root / '.dev-workflow/releases' / ('execution-' + result['attempt'] + '.json')
                self.assertNotIn('TEST_PROVIDER_SECRET', execution.canonical(result))
                self.assertNotIn('TEST_PROVIDER_SECRET', audit_path.read_text(encoding='utf-8'))

    def test_cli_status_reports_preparation_only(self):
        result = subprocess.run([sys.executable, str(SCRIPT), 'status'], capture_output=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)
        status = json.loads(result.stdout)
        self.assertFalse(status['executionAvailable'])
        self.assertEqual(status['mode'], 'preparation-only')


if __name__ == '__main__':
    unittest.main()
