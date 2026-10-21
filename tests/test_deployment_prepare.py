"""Portable, offline deployment planning contracts; no declared command executes."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
import shlex
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'packs/deployment/scripts/deployment_prepare.py'
spec = importlib.util.spec_from_file_location('deployment_prepare_under_test', SCRIPT)
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)
DATA = '.dev-workflow/releases/deployments/'


class DeploymentPrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Deployment Test')
        self.git('config', 'user.email', 'deployment@example.invalid')
        (self.root / '.git/info/exclude').write_bytes(b'.dev-workflow/\n')
        self.write('.dev-workflow/manifest.json', {'schemaVersion': 5, 'managedBy': 'dev-workflow',
                   'installedPacks': ['deployment'], 'enabledCapabilities': []})
        phases = ('preflight', 'deploy', 'health', 'smoke', 'rollback', 'backup', 'restore', 'migrate')
        self.config = {'schemaVersion': 1, 'enabledCapabilities': ['deployment:compose'],
                       'commands': {phase: {'command': 'touch MUST_NOT_EXIST', 'cwd': '.'} for phase in phases},
                       'extensions': {'deployment': {'components': ['web', 'api'], 'environments': {
                           'staging': {'capability': 'deployment:compose', 'target': 'staging-cluster',
                                       'production': False, 'components': ['web', 'api'],
                                       'commands': {phase: phase for phase in phases}}}}}}
        self.save_config()
        self.current = self.manifest('deployment-snapshot', [self.component('web', '1'), self.component('api', '2')])
        self.target = self.manifest('deployment-target', [self.component('web', '3'), self.component('api', '4')])
        self.conditions = {'schemaVersion': 1, 'kind': 'deployment-conditions', 'environment': 'staging',
                           'target': 'staging-cluster', 'backup': {'required': False, 'reference': None,
                           'restoreEvidence': None}, 'migration': {'mode': 'none', 'evidence': None}}
        self.sync_inputs()

    def git(self, *args):
        return subprocess.run(['git', '--no-optional-locks', '-C', str(self.root), *args],
                              check=True, capture_output=True, encoding='utf-8').stdout.strip()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json.dumps(value, ensure_ascii=False).encode('utf-8'))

    def save_config(self):
        self.write('workflow.config.json', self.config)
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'core/scripts/workflow_config.py'),
                                 'adopt', '--repo', str(self.root)], capture_output=True, encoding='utf-8',
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.git('add', 'workflow.config.json')
        self.git('commit', '-qm', 'configuration', '--allow-empty')

    def component(self, name, digit):
        return {'name': name, 'sourceSha': digit * 40,
                'artifact': {'kind': 'registry', 'ref': 'registry.example/team/' + name + '@sha256:' + digit * 64},
                'configurationDigest': 'sha256:' + 'a' * 64, 'migrationVersion': None}

    def manifest(self, kind, components):
        value = {'schemaVersion': 1, 'kind': kind, 'environment': 'staging', 'target': 'staging-cluster',
                 'version': 'v2' if kind == 'deployment-target' else 'v1', 'components': components}
        if kind == 'deployment-snapshot':
            value.update(capturedAt=datetime.now(timezone.utc).isoformat(), provenance='supplied inventory')
        return value

    def sync_inputs(self):
        for name, value in [('target', self.target), ('current', self.current), ('conditions', self.conditions)]:
            self.write(DATA + name + '.json', value)

    def prepare(self, **overrides):
        arguments = dict(environment='staging', target_manifest=DATA + 'target.json',
                         current_snapshot=DATA + 'current.json', conditions_path=DATA + 'conditions.json')
        arguments.update(overrides)
        return planner.prepare(self.root, **arguments)

    def cli(self, *args, code=0):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), *args, '--repo', str(self.root)],
                                capture_output=True, encoding='utf-8',
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return json.loads(result.stdout if code == 0 else result.stderr)

    def plan_cli(self, *extra, code=0):
        return self.cli('plan', '--environment', 'staging', '--target-manifest', DATA + 'target.json',
                        '--current-snapshot', DATA + 'current.json', '--conditions', DATA + 'conditions.json',
                        *extra, code=code)

    def test_full_plan_keeps_independent_component_sources_and_complete_rollback(self):
        result = self.prepare()
        self.assertEqual(result['result'], 'prepared')
        self.assertEqual(result['desired'], self.target['components'])
        self.assertEqual(result['rollback']['components'], self.current['components'])
        self.assertEqual([c['sourceSha'] for c in result['desired']], ['3' * 40, '4' * 40])
        self.assertFalse(result['executionAvailable'])
        self.assertFalse(result['productionReady'])
        self.assertEqual(result['verification']['health'], 'unknown')

    def test_partial_target_carries_unchanged_components(self):
        self.target['components'] = self.target['components'][:1]
        self.sync_inputs()
        result = self.prepare()
        self.assertEqual(result['result'], 'prepared')
        self.assertEqual(result['desired'][1], self.current['components'][1])
        self.assertEqual(result['changes'][1]['action'], 'unchanged')
        self.assertFalse(result['changes'][1]['selected'])
        self.assertEqual(result['rollback']['components'], self.current['components'])

    def test_unchanged_selected_components_are_explicit(self):
        self.target['components'] = deepcopy(self.current['components'])
        self.sync_inputs()
        self.assertTrue(all(c['selected'] and c['action'] == 'unchanged' and not c['changedFields']
                            for c in self.prepare()['changes']))

    def test_missing_current_and_conditions_block_without_inventing_state(self):
        result = self.prepare(current_snapshot=None, conditions_path=None)
        self.assertIn('current-snapshot-missing', result['blockers'])
        self.assertIn('conditions-missing', result['blockers'])
        self.assertEqual(result['rollback']['components'], [])
        self.assertTrue(all(c['action'] == 'unknown' for c in result['changes']))

    def test_partial_baseline_blocks_full_rollback(self):
        self.current['components'].pop()
        self.target['components'] = self.target['components'][:1]
        self.sync_inputs()
        result = self.prepare()
        self.assertIn('rollback-state-incomplete', result['blockers'])
        self.assertIn('desired-state-incomplete', result['blockers'])

    def test_missing_phase_and_cwd_are_blockers(self):
        del self.config['extensions']['deployment']['environments']['staging']['commands']['smoke']
        self.config['commands']['deploy']['cwd'] = 'missing-directory'
        self.save_config()
        blockers = self.prepare()['blockers']
        self.assertIn('command-phase-missing:smoke', blockers)
        self.assertIn('command-cwd-missing:deploy', blockers)

    def test_mutable_or_confused_artifact_identities_fail(self):
        invalid = [{'kind': 'registry', 'ref': 'registry.example/team/web:latest'},
                   {'kind': 'registry', 'imageId': 'sha256:' + 'a' * 64},
                   {'kind': 'local-build', 'ref': 'registry.example/team/web@sha256:' + 'a' * 64},
                   {'kind': 'local-build', 'imageId': 'sha256:' + 'a' * 64, 'buildSourceSha': '1' * 40},
                   {'kind': 'bundle', 'ref': '../archive', 'sha256': 'a' * 64},
                   {'kind': 'bundle', 'ref': 'archive', 'sha256': 'sha256:' + 'a' * 64}]
        for artifact in invalid:
            with self.subTest(artifact=artifact):
                self.target['components'][0]['artifact'] = artifact
                self.sync_inputs()
                with self.assertRaises(planner.PlanningError):
                    self.prepare()

    def test_local_build_and_checksum_bundle_are_distinct_valid_identities(self):
        self.target['components'][0]['artifact'] = {'kind': 'local-build', 'imageId': 'sha256:' + 'b' * 64,
                                                   'buildSourceSha': '3' * 40}
        self.target['components'][1]['artifact'] = {'kind': 'bundle', 'ref': 'archives/api-v2.tgz', 'sha256': 'c' * 64}
        self.sync_inputs()
        self.assertEqual(self.prepare()['result'], 'prepared')

    def test_configuration_only_change_is_detected(self):
        self.target['components'] = deepcopy(self.current['components'])
        self.target['components'][0]['configurationDigest'] = 'sha256:' + 'b' * 64
        self.sync_inputs()
        self.assertEqual(self.prepare()['changes'][0]['changedFields'], ['configurationDigest'])

    def test_migration_change_requires_backup_restore_and_recovery(self):
        self.target['components'][0]['migrationVersion'] = 'migration2'
        self.sync_inputs()
        result = self.prepare()
        for blocker in ('backup-evidence-missing:backup', 'backup-evidence-missing:restore',
                        'migration-not-declared-reversible', 'migration-recovery-evidence-missing'):
            self.assertIn(blocker, result['blockers'])
        self.assertEqual(result['rollback']['status'], 'blocked')

    def evidence(self):
        for role in ('backup', 'restore', 'migration'):
            self.write(DATA + role + '.json', {'declared': role})
        self.conditions['backup'].update(required=True, reference=DATA + 'backup.json', restoreEvidence=DATA + 'restore.json')
        self.conditions['migration'].update(mode='reversible', evidence=DATA + 'migration.json')
        self.sync_inputs()

    def test_supplied_evidence_remains_unverified(self):
        self.target['components'][0]['migrationVersion'] = 'migration2'
        self.evidence()
        result = self.prepare()
        self.assertEqual(result['result'], 'prepared')
        self.assertTrue(all(e['verification'] == 'supplied_unverified' for e in result['inputs']['evidence']))
        self.assertEqual(result['verification']['backup'], 'unknown')
        self.assertEqual(result['verification']['authorization'], 'unknown')

    def test_declared_reversible_migration_requires_proof_even_with_unchanged_versions(self):
        self.conditions['migration']['mode'] = 'reversible'
        self.sync_inputs()
        result = self.prepare()
        for blocker in ('backup-evidence-missing:backup', 'backup-evidence-missing:restore',
                        'migration-recovery-evidence-missing'):
            self.assertIn(blocker, result['blockers'])
        self.evidence()
        result = self.prepare()
        self.assertEqual(result['result'], 'prepared')
        self.assertEqual(result['verification']['migration'], 'unknown')

    def test_missing_evidence_and_irreversible_migration_block(self):
        self.evidence()
        (self.root / (DATA + 'restore.json')).unlink()
        self.conditions['migration']['mode'] = 'irreversible'
        self.sync_inputs()
        result = self.prepare()
        self.assertIn('evidence-file-missing:restore', result['blockers'])
        self.assertIn('migration-recovery-unresolved', result['blockers'])

    def test_missing_backup_restore_and_migrate_commands_block(self):
        self.target['components'][0]['migrationVersion'] = 'migration2'
        self.evidence()
        commands = self.config['extensions']['deployment']['environments']['staging']['commands']
        for phase in ('backup', 'restore', 'migrate'):
            del commands[phase]
        self.save_config()
        self.assertTrue({'command-phase-missing:' + p for p in ('backup', 'restore', 'migrate')} <= set(self.prepare()['blockers']))

    def test_stale_and_future_current_snapshot_block(self):
        for offset in (-7200, 120):
            self.current['capturedAt'] = (datetime.now(timezone.utc) + timedelta(seconds=offset)).isoformat()
            self.sync_inputs()
            self.assertIn('current-snapshot-stale-or-future', self.prepare()['blockers'])

    def test_wrong_environment_target_and_naive_timestamp_fail(self):
        original = deepcopy(self.current)
        for field, value in [('environment', 'production'), ('target', 'another'), ('capturedAt', '2026-01-01T00:00:00')]:
            self.current = original | {field: value}
            self.sync_inputs()
            with self.subTest(field=field), self.assertRaises(planner.PlanningError):
                self.prepare()

    def test_unknown_fields_wrong_types_and_verified_claims_fail(self):
        original = deepcopy(self.target)
        for field, value in [('schemaVersion', True), ('components', {}), ('version', 'latest'),
                             ('verified', True), ('productionReady', True)]:
            self.target = original | {field: value}
            self.sync_inputs()
            with self.subTest(field=field), self.assertRaises(planner.PlanningError):
                self.prepare()

    def test_duplicate_json_keys_fail(self):
        (self.root / (DATA + 'target.json')).write_bytes(b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaisesRegex(planner.PlanningError, 'Duplicate'):
            self.prepare()

    def test_component_names_sources_and_digests_are_strict(self):
        original = deepcopy(self.target['components'][0])
        for field, value in [('name', 'other'), ('sourceSha', 'HEAD'), ('sourceSha', 123),
                             ('configurationDigest', 'a' * 64), ('migrationVersion', True), ('verified', True)]:
            self.target['components'][0] = original | {field: value}
            self.sync_inputs()
            with self.subTest(field=field, value=value), self.assertRaises(planner.PlanningError):
                self.prepare()

    def test_checked_rejects_new_head(self):
        saved = self.prepare()
        self.git('commit', '--allow-empty', '-qm', 'new head')
        with self.assertRaises(planner.PlanningError):
            planner.checked(self.root, saved)

    def test_checked_rejects_configuration_and_command_drift(self):
        saved = self.prepare()
        self.config['commands']['deploy']['command'] = 'changed command'
        self.save_config()
        with self.assertRaises(planner.PlanningError):
            planner.checked(self.root, saved)

    def test_checked_rejects_changed_inputs(self):
        saved = self.prepare()
        self.target['version'] = 'v3'
        self.sync_inputs()
        with self.assertRaises(planner.PlanningError):
            planner.checked(self.root, saved)

    def test_checked_rejects_changed_evidence(self):
        self.evidence()
        saved = self.prepare()
        self.write(DATA + 'backup.json', {'declared': 'different'})
        with self.assertRaises(planner.PlanningError):
            planner.checked(self.root, saved)

    def test_checked_rejects_cwd_existence_change(self):
        self.config['commands']['deploy']['cwd'] = 'runtime'
        self.save_config()
        saved = self.prepare()
        (self.root / 'runtime').mkdir()
        with self.assertRaises(planner.PlanningError):
            planner.checked(self.root, saved)

    def test_checked_rejects_forged_derived_states(self):
        saved = self.prepare()
        for field, value in [('productionReady', True), ('executionAvailable', True), ('desired', []),
                             ('rollback', {'status': 'verified'}), ('blockers', ['invented']),
                             ('verification', {'health': 'passed'}), ('commands', {}), ('result', 'deployed')]:
            with self.subTest(field=field), self.assertRaises(planner.PlanningError):
                planner.checked(self.root, saved | {field: value})

    def observation(self, components=None, **extra):
        value = self.manifest('deployment-snapshot', deepcopy(self.target['components'] if components is None else components))
        value['version'] = 'v2'
        value.update(extra)
        self.write(DATA + 'observation.json', value)
        return DATA + 'observation.json'

    def test_compare_deploy_and_rollback_matches_are_not_health_proof(self):
        saved = self.prepare()
        for direction, components in [('deploy', saved['desired']), ('rollback', saved['rollback']['components'])]:
            result = planner.compare(self.root, saved, self.observation(components, version=saved['version'] if direction == 'deploy' else saved['rollback']['version']), direction)
            self.assertEqual(result['result'], 'matches-supplied-snapshot')
            self.assertFalse(result['productionReady'])
            self.assertEqual(result['verification']['health'], 'unknown')
            self.assertEqual(result['verification']['runtime'], 'unknown')

    def test_compare_wrong_version_is_a_mismatch_even_when_components_match(self):
        result = planner.compare(self.root, self.prepare(), self.observation(version='wrong-version'))
        self.assertFalse(result['versionMatches'])
        self.assertEqual(result['result'], 'mismatches-supplied-snapshot')

    def test_compare_missing_component_and_stale_snapshot(self):
        saved = self.prepare()
        result = planner.compare(self.root, saved, self.observation(self.target['components'][:1]))
        self.assertEqual(result['result'], 'mismatches-supplied-snapshot')
        self.assertTrue(result['differences'][0]['missingObserved'])
        result = planner.compare(self.root, saved, self.observation(capturedAt='2000-01-01T00:00:00Z'))
        self.assertTrue(result['identitiesMatch'])
        self.assertEqual(result['result'], 'stale-supplied-snapshot')

    def test_compare_wrong_identity_and_direction_fail(self):
        saved = self.prepare()
        for field in ('environment', 'target'):
            with self.subTest(field=field), self.assertRaises(planner.PlanningError):
                planner.compare(self.root, saved, self.observation(**{field: 'wrong'}))
        with self.assertRaises(planner.PlanningError):
            planner.compare(self.root, saved, self.observation(), 'execute')

    def test_paths_outside_traversal_and_nonportable_paths_fail(self):
        for name in ('../outside.json', '/tmp/outside.json', 'x/../target.json', 'x\\target.json',
                     'C:/target.json', './target.json', 'x//target.json'):
            with self.subTest(name=name), self.assertRaises(planner.PlanningError):
                self.prepare(target_manifest=name)
        with self.assertRaises(planner.PlanningError):
            planner.prepare(self.root / '.dev-workflow', 'staging', 'target.json')

    def test_symlink_input_and_cwd_are_refused(self):
        link = self.root / (DATA + 'linked.json')
        try:
            link.symlink_to(self.root / (DATA + 'target.json'))
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation is unavailable for this account')
        with self.assertRaises(planner.PlanningError):
            self.prepare(target_manifest=DATA + 'linked.json')
        (self.root / 'linked-cwd').symlink_to(self.root, target_is_directory=True)
        self.config['commands']['deploy']['cwd'] = 'linked-cwd'
        self.write('workflow.config.json', self.config)
        # Adoption is metadata-only; track the link so clean-tree enforcement cannot mask path validation.
        self.git('add', '.')
        self.git('commit', '-qm', 'linked cwd')
        adopted = subprocess.run([sys.executable, '-B', str(ROOT / 'core/scripts/workflow_config.py'),
                                  'sync', '--repo', str(self.root)], capture_output=True, encoding='utf-8')
        self.assertEqual(adopted.returncode, 0, adopted.stderr)
        with self.assertRaises(planner.PlanningError):
            self.prepare()

    def test_explicit_private_output_and_no_overwrite(self):
        self.plan_cli()
        self.assertFalse((self.root / (DATA + 'saved.json')).exists())
        saved = self.plan_cli('--output', DATA + 'saved.json')
        self.assertEqual(saved, json.loads((self.root / (DATA + 'saved.json')).read_bytes()))
        self.assertTrue(self.cli('check-plan', '--plan', DATA + 'saved.json')['valid'])
        self.plan_cli('--output', DATA + 'saved.json', code=1)
        self.plan_cli('--output', 'public.json', code=1)
        self.assertFalse((self.root / 'public.json').exists())

    def test_output_cannot_escape_through_symlink(self):
        with tempfile.TemporaryDirectory() as outside:
            link = self.root / (DATA + 'escape')
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest('Symlink creation is unavailable for this account')
            self.plan_cli('--output', DATA + 'escape/plan.json', code=1)
            self.assertEqual(list(Path(outside).iterdir()), [])

    def test_planning_does_not_execute_commands_or_refresh_index(self):
        index = self.root / '.git/index'
        before = index.read_bytes()
        path = self.root / 'workflow.config.json'
        metadata = path.stat()
        os.utime(path, (metadata.st_atime, metadata.st_mtime + 5))
        self.plan_cli()
        self.assertEqual(index.read_bytes(), before)
        self.assertFalse((self.root / 'MUST_NOT_EXIST').exists())
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_partial_clone_configuration_is_rejected_before_object_inspection(self):
        cases = [('remote.offline.promisor', 'true'), ('remote.offline.promisor', 'false'),
                 ('remote.offline.partialclonefilter', 'blob:none'), ('extensions.partialclone', 'offline')]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                self.git('config', key, value)
                with mock.patch.object(planner, 'git', wraps=planner.git) as inspected:
                    with self.assertRaisesRegex(planner.PlanningError, 'Partial-clone or promisor'):
                        self.prepare()
                self.assertTrue(inspected.called)
                commands = [call.args[1:] for call in inspected.call_args_list]
                self.assertFalse(any(arguments[0] in ('ls-files', 'check-attr', 'status') for arguments in commands))
                self.assertFalse(any(arguments[0] == 'rev-parse' and 'HEAD^{commit}' in arguments for arguments in commands))
                self.git('config', '--unset', key)

    @unittest.skipIf(os.name == 'nt', 'Lazy-fetch transport execution control uses POSIX Git process behavior')
    def test_missing_partial_clone_blob_never_launches_local_transport(self):
        attributes = self.root / '.gitattributes'
        attributes.write_bytes(b'*.json text\n')
        self.git('add', '.gitattributes')
        self.git('commit', '-qm', 'attribute blob for lazy-fetch control')
        blob = self.git('rev-parse', 'HEAD:.gitattributes')
        attributes.unlink()
        (self.root / '.git/objects' / blob[:2] / blob[2:]).unlink()
        sentinel = self.root / '.git/lazy-fetch-ran'
        hook = self.root / '.git/lazy-fetch-probe.py'
        hook.write_bytes(("from pathlib import Path\nimport sys\n"
                          "Path(sys.argv[1]).write_bytes(b'called')\n"
                          "sys.exit(1)\n").encode('utf-8'))
        # remote-ext's percent-space escape preserves arguments without a shell.
        arguments = [Path(sys.executable).as_posix(), '-B', hook.as_posix(), sentinel.as_posix()]
        transport = 'ext::' + ' '.join(value.replace('%', '%%').replace(' ', '% ') for value in arguments)
        self.git('config', 'remote.offline.url', transport)
        self.git('config', 'remote.offline.promisor', 'true')
        self.git('config', 'remote.offline.partialclonefilter', 'blob:none')
        environment = dict(os.environ, GIT_TERMINAL_PROMPT='0', PYTHONDONTWRITEBYTECODE='1')
        environment.pop('GIT_NO_LAZY_FETCH', None)
        subprocess.run(['git', '-c', 'protocol.ext.allow=always', '-C', str(self.root),
                        'check-attr', 'filter', '--', 'workflow.config.json'],
                       capture_output=True, encoding='utf-8', env=environment, timeout=20)
        self.assertTrue(sentinel.is_file(), 'Control must prove missing attributes invoke the local promisor transport')
        sentinel.unlink()
        # Allow the same harmless local transport so denial cannot hide a callback.
        self.git('config', 'protocol.ext.allow', 'always')
        with self.assertRaisesRegex(planner.PlanningError, 'Partial-clone or promisor'):
            self.prepare()
        self.assertFalse(sentinel.exists())

    @unittest.skipIf(os.name == 'nt', 'Clean-filter execution control uses POSIX Git process behavior')
    def test_active_clean_filter_blocks_before_git_can_execute_it(self):
        sentinel = self.root / '.git/clean-filter-ran'
        hook = self.root / '.git/clean-filter-probe.py'
        hook.write_bytes(("from pathlib import Path\nimport sys\n"
                          "Path(sys.argv[1]).write_bytes(b'called')\n"
                          "sys.stdout.buffer.write(sys.stdin.buffer.read())\n").encode('utf-8'))
        command = ' '.join(shlex.quote(path.as_posix()) for path in (Path(sys.executable), hook, sentinel))
        self.git('config', 'filter.deployment-probe.clean', command)
        (self.root / '.gitattributes').write_bytes(b'filtered.txt filter=deployment-probe\n')
        filtered = self.root / 'filtered.txt'
        filtered.write_bytes(b'unchanged filtered content\n')
        self.git('add', '.gitattributes', 'filtered.txt')
        self.git('commit', '-qm', 'filtered content control')
        sentinel.unlink(missing_ok=True)
        metadata = filtered.stat()
        os.utime(filtered, (metadata.st_atime, metadata.st_mtime + 5))
        self.git('status', '--porcelain')
        self.assertTrue(sentinel.is_file(), 'Control must prove ordinary Git status executes the clean filter')
        sentinel.unlink()
        os.utime(filtered, (metadata.st_atime, metadata.st_mtime + 10))
        with self.assertRaisesRegex(planner.PlanningError, 'content filters'):
            self.prepare()
        self.assertFalse(sentinel.exists())

    def test_gitlink_is_rejected_before_submodule_worktree_inspection(self):
        commit = self.git('rev-parse', 'HEAD')
        self.git('update-index', '--add', '--cacheinfo', '160000', commit, 'uninitialized-module')
        with self.assertRaisesRegex(planner.PlanningError, 'Submodule worktree inspection'):
            self.prepare()

    def test_registry_authority_and_repository_segments_are_validated(self):
        digest = '@sha256:' + 'a' * 64
        invalid = ['registry.example//web', 'registry.example/team/../web', 'registry.example/.web',
                   'registry_example/team/web', 'registry..example/team/web', '-registry.example/team/web',
                   'registry-.example/team/web', 'registry.example:/team/web', 'registry.example:port/team/web',
                   'registry.example:0/team/web', 'registry.example:65536/team/web',
                   'registry.example/team/web/', 'registry.example/team/_web', 'registry.example/team/web_',
                   'registry.example/team/-web', 'registry.example/team/web-', 'registry.example/team/web.',
                   'registry.example/team/a___b', 'registry.example/team/a..b']
        for reference in invalid:
            with self.subTest(reference=reference):
                self.target['components'][0]['artifact']['ref'] = reference + digest
                self.sync_inputs()
                with self.assertRaisesRegex(planner.PlanningError, 'Registry artifacts'):
                    self.prepare()
        valid = ['registry.example/team/web', 'localhost:5000/team/web', 'registry.example:65535/team/web',
                 'registry.example/team/a__b/a--b', 'registry.example/team/a_b/a.b']
        for reference in valid:
            with self.subTest(reference=reference):
                self.target['components'][0]['artifact']['ref'] = reference + digest
                self.sync_inputs()
                self.assertEqual(self.prepare()['result'], 'prepared')

    def test_configured_fsmonitor_hook_never_runs_during_planning_checks_or_comparison(self):
        sentinel = self.root / '.git/fsmonitor-ran'
        hook = self.root / '.git/fsmonitor-probe.py'
        hook.write_bytes(("from pathlib import Path\nimport sys\n"
                          "Path(sys.argv[1]).write_bytes(b'called')\n"
                          "sys.stdout.buffer.write(b'probe\\0')\n").encode('utf-8'))
        command = ' '.join(shlex.quote(path.as_posix()) for path in (Path(sys.executable), hook, sentinel))
        self.git('config', 'core.fsmonitor', command)
        if os.name != 'nt':
            self.git('status', '--porcelain')
            self.assertTrue(sentinel.is_file(), 'Control must prove Git would execute the configured hook')
            sentinel.unlink()
        saved = self.prepare()
        planner.checked(self.root, saved)
        result = planner.compare(self.root, saved, self.observation())
        self.assertEqual(result['result'], 'matches-supplied-snapshot')
        self.assertFalse(sentinel.exists())

    def test_installed_deployment_pack_plans_and_full_uninstall_preserves_records(self):
        with tempfile.TemporaryDirectory() as directory:
            self.root = Path(directory).resolve()
            self.git('init', '-q')
            self.git('config', 'user.name', 'Installed Deployment Test')
            self.git('config', 'user.email', 'deployment@example.invalid')
            environment = dict(os.environ, DEV_WORKFLOW_NON_INTERACTIVE='1', PYTHONDONTWRITEBYTECODE='1')
            if os.name == 'nt':
                shell = shutil.which('pwsh') or shutil.which('powershell')
                if shell is None:
                    self.skipTest('PowerShell is unavailable for the Windows installer smoke test')
                install = [shell, '-NoProfile', '-File', str(ROOT / 'scripts/install.ps1'),
                           '-TargetPath', str(self.root), '-Packs', 'deployment', '-NonInteractiveInstall']
                uninstall = [shell, '-NoProfile', '-File', str(ROOT / 'scripts/uninstall.ps1'),
                             '-TargetPath', str(self.root)]
            else:
                install = ['bash', str(ROOT / 'scripts/install.sh'), '--target', str(self.root), '--packs', 'deployment']
                uninstall = ['bash', str(ROOT / 'scripts/uninstall.sh'), '--target', str(self.root)]
            def run(arguments):
                result = subprocess.run(arguments, capture_output=True, encoding='utf-8', env=environment)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result
            run(install)
            installed = self.root / 'scripts/deployment_prepare.py'
            self.assertTrue(installed.is_file())
            status = run([sys.executable, '-B', str(installed), 'status', '--repo', str(self.root)])
            self.assertEqual(json.loads(status.stdout)['mode'], 'offline-planning')
            self.write('workflow.config.json', self.config)
            run([sys.executable, '-B', str(self.root / 'scripts/workflow_config.py'),
                 'adopt', '--repo', str(self.root)])
            self.sync_inputs()
            self.git('add', '.')
            self.git('commit', '-qm', 'installed deployment configuration')
            output = DATA + 'installed-plan.json'
            result = run([sys.executable, '-B', str(installed), 'plan', '--repo', str(self.root),
                          '--environment', 'staging', '--target-manifest', DATA + 'target.json',
                          '--current-snapshot', DATA + 'current.json', '--conditions', DATA + 'conditions.json',
                          '--output', output])
            self.assertEqual(json.loads(result.stdout)['result'], 'prepared')
            project_before = (self.root / 'workflow.config.json').read_bytes()
            record_before = (self.root / output).read_bytes()
            self.assertFalse((self.root / '.agents').exists())
            run(uninstall)
            self.assertEqual((self.root / 'workflow.config.json').read_bytes(), project_before)
            self.assertEqual((self.root / output).read_bytes(), record_before)
            self.assertFalse(installed.exists())

    def test_status_and_compare_cli_emit_json(self):
        self.assertEqual(self.cli('status')['mode'], 'offline-planning')
        self.plan_cli('--output', DATA + 'saved.json')
        observation = self.observation()
        self.assertEqual(self.cli('compare', '--plan', DATA + 'saved.json', '--observed-snapshot', observation)['result'],
                         'matches-supplied-snapshot')

    def test_dirty_tree_unadopted_disabled_and_missing_pack_fail(self):
        (self.root / 'dirty.txt').write_bytes(b'untracked')
        with self.assertRaises(planner.PlanningError):
            self.prepare()
        (self.root / 'dirty.txt').unlink()
        manifest_path = self.root / '.dev-workflow/manifest.json'
        original = json.loads(manifest_path.read_bytes())
        for value in (original | {'installedPacks': []},
                      {key: value for key, value in original.items() if key != 'projectConfiguration'}):
            self.write('.dev-workflow/manifest.json', value)
            with self.assertRaises(planner.PlanningError):
                self.prepare()
        self.write('.dev-workflow/manifest.json', original)
        self.config['enabledCapabilities'] = []
        self.save_config()
        with self.assertRaises(planner.PlanningError):
            self.prepare()


    @unittest.skipIf(os.name == 'nt', 'POSIX control-character filename fixture')
    def test_carriage_return_filename_keeps_exact_filter_identity(self):
        name = 'danger\r.txt'
        (self.root / name).write_bytes(b'original\n')
        (self.root / '.gitattributes').write_bytes(b'"danger\\r.txt" filter=cr-probe\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'CR path identity')
        marker = self.root / '.git/cr-filter-ran'
        hook = self.root / '.git/cr-filter.py'
        hook.write_text('from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_bytes(b"called")\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n', encoding='utf-8')
        command = ' '.join(shlex.quote(part.as_posix()) for part in (Path(sys.executable), hook, marker))
        self.git('config', 'filter.cr-probe.clean', command)
        stat = (self.root / name).stat()
        os.utime(self.root / name, (stat.st_atime, stat.st_mtime + 5))
        self.git('status', '--porcelain')
        self.assertTrue(marker.exists(), 'Control must prove the exact CR path invokes its filter')
        marker.unlink()
        os.utime(self.root / name, (stat.st_atime, stat.st_mtime + 10))
        with self.assertRaisesRegex(planner.PlanningError, 'content filters'):
            self.prepare()
        self.assertFalse(marker.exists())

    def test_newline_subsection_promisor_is_rejected_before_object_inspection(self):
        config = self.root / '.git/config'
        original = config.read_bytes()
        for field in ('promisor', 'partialclonefilter'):
            with self.subTest(field=field):
                config.write_bytes(original + ('[remote "line\\nbreak"]\n\t' + field + ' = false\n').encode('utf-8'))
                actual_git = planner.git
                seen = []
                def inspect(root, *arguments, **kwargs):
                    seen.append(arguments)
                    return actual_git(root, *arguments, **kwargs)
                with mock.patch.object(planner, 'git', side_effect=inspect):
                    with self.assertRaises(planner.PlanningError):
                        self.prepare()
                self.assertTrue(seen)
                self.assertTrue(all(arguments[0] in ('config', 'rev-parse') for arguments in seen))
                self.assertFalse(any(arguments[0] == 'rev-parse' and 'HEAD^{commit}' in arguments for arguments in seen))
                config.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
