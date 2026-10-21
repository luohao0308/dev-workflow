"""Portable deployment declaration and read-only diagnostics contracts."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'core/scripts'
sys.path.insert(0, str(CORE))
import workflow_config as config
import workflow_check as doctor


class DeploymentConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / '.dev-workflow').mkdir()
        self.manifest = self.root / '.dev-workflow/manifest.json'
        self.project = self.root / 'workflow.config.json'
        self.policy = {'pushMode': 'manual', 'pushActor': 'user'}
        self.write(self.manifest, {'schemaVersion': 5, 'managedBy': 'dev-workflow',
                                  'installedPacks': ['deployment'], 'enabledCapabilities': [],
                                  'gitPolicy': self.policy})
        self.declaration = {
            'schemaVersion': 1, 'enabledCapabilities': ['deployment:compose'],
            'commands': {phase: {'command': 'never execute ' + phase, 'cwd': '.'}
                         for phase in config.DEPLOYMENT_PHASES},
            'extensions': {'deployment': {'components': ['web', 'worker'], 'environments': {
                'staging': {'capability': 'deployment:compose', 'target': 'staging-cluster',
                            'production': False, 'components': ['web'],
                            'commands': {phase: phase for phase in config.DEPLOYMENT_PHASES}}}}}}

    def write(self, path, value):
        path.write_text(json.dumps(value), encoding='utf-8')

    def cli(self, *arguments):
        process = subprocess.run([sys.executable, '-B', str(CORE / 'workflow_config.py'),
                                  *arguments, '--repo', str(self.root)], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        return json.loads(process.stdout)

    def test_adopt_sync_withdraw_preserve_declarations_and_permissions(self):
        self.write(self.project, self.declaration)
        before = self.manifest.read_bytes(), self.project.read_bytes()
        self.assertEqual(config.resolve_configuration(self.root)['source'], 'unadopted')
        self.assertEqual(config.resolve_configuration(self.root)['capabilities'], [])
        self.cli('adopt', '--dry-run')
        self.assertEqual(before, (self.manifest.read_bytes(), self.project.read_bytes()))
        self.cli('adopt')
        self.declaration['extensions']['deployment']['environments']['staging']['target'] = 'new-target'
        self.write(self.project, self.declaration)
        self.assertEqual(config.resolve_configuration(self.root)['warnings'][0]['code'], 'config.drift')
        self.cli('sync')
        self.assertEqual(json.loads(self.project.read_text()), self.declaration)
        self.assertFalse(config.resolve_configuration(self.root)['warnings'])
        self.cli('update', '--disable', 'deployment:compose')
        self.assertEqual(config.resolve_configuration(self.root)['capabilities'], [])
        self.assertEqual(json.loads(self.project.read_text())['extensions'], self.declaration['extensions'])
        retained = self.project.read_bytes()
        self.cli('withdraw')
        self.assertEqual(retained, self.project.read_bytes())
        self.assertEqual(json.loads(self.manifest.read_text())['gitPolicy'], self.policy)
        self.assertEqual(config.resolve_configuration(self.root)['source'], 'manifest')

    def test_disabled_registered_capabilities_and_shared_references_are_valid(self):
        self.declaration['enabledCapabilities'] = []
        environment = self.declaration['extensions']['deployment']['environments']['staging']
        environment['commands'] = dict.fromkeys(config.DEPLOYMENT_PHASES, 'preflight')
        for capability, pack in config.CAPABILITY_PACKS.items():
            if pack == 'deployment':
                environment['capability'] = capability
                self.assertEqual(config.validate_config(self.declaration), [])

    def test_missing_phases_and_declared_optional_phases_are_valid(self):
        environment = self.declaration['extensions']['deployment']['environments']['staging']
        for references in ({}, {'deploy': 'deploy'},
                           dict.fromkeys(config.DEPLOYMENT_OPTIONAL_PHASES, 'preflight')):
            environment['commands'] = references
            self.assertEqual(config.validate_config(self.declaration), [])

    def test_required_fields_types_unknown_fields_and_references_fail_closed(self):
        deployment = self.declaration['extensions']['deployment']
        cases = [None, [], {}, deployment | {'unexpected': True}, deployment | {'components': []},
                 deployment | {'components': ['web', 'web']}, deployment | {'components': [{}]},
                 deployment | {'environments': []}, deployment | {'environments': {}}]
        for field, values in {'capability': [None, [], {}, 'release', 'deployment:unknown'],
                              'target': [None, [], {}, '', '../target'],
                              'production': [None, 'false', 0, 1],
                              'components': [None, [], {}, ['missing'], ['web', 'web'], [{}]],
                              'commands': [None, [], dict.fromkeys(config.DEPLOYMENT_PHASES, 'missing'),
                                           dict.fromkeys(config.DEPLOYMENT_PHASES, 'echo deploy'),
                                           dict.fromkeys(config.DEPLOYMENT_PHASES, {}),
                                           dict.fromkeys(config.DEPLOYMENT_PHASES, ['deploy'])]}.items():
            for value in values:
                environment = deployment['environments']['staging'] | {field: value}
                cases.append(deployment | {'environments': {'staging': environment}})
        environment = deployment['environments']['staging']
        cases.extend([deployment | {'environments': {'staging': environment | {'authorization': True}}},
                      deployment | {'environments': {'staging': True}}])
        for field in environment:
            cases.append(deployment | {'environments': {'staging': {k: v for k, v in environment.items() if k != field}}})
        cases.append(deployment | {'environments': {'staging': environment | {
            'commands': environment['commands'] | {'extra': 'deploy'}}}})
        for invalid in cases:
            with self.subTest(invalid=invalid):
                value = deepcopy(self.declaration)
                value['extensions']['deployment'] = invalid
                self.assertTrue(config.validate_config(value))
        for commands in (None, [], {}):
            self.assertTrue(config.validate_config(self.declaration | {'commands': commands}))

    def test_all_deployment_identifiers_are_portable_and_bounded(self):
        for name in ('', '.', '..', '-first', '_first', 'two words', 'a/b', 'a\\b', 'é', 'a\n', 'a' * 129):
            for field in ('components', 'environment', 'target', 'reference'):
                with self.subTest(name=name, field=field):
                    value = deepcopy(self.declaration)
                    deployment = value['extensions']['deployment']
                    environment = deployment['environments']['staging']
                    if field == 'components':
                        deployment['components'] = [name]
                    elif field == 'environment':
                        deployment['environments'] = {name: environment}
                    elif field == 'target':
                        environment['target'] = name
                    else:
                        value['commands'][name] = {'command': 'never execute'}
                        environment['commands']['deploy'] = name
                    self.assertTrue(config.validate_config(value))
        self.assertTrue(config.portable_identifier('A0_.-' + 'x' * 123))

    def test_root_schema_and_release_contract_remain_unchanged(self):
        self.assertEqual(config.validate_config(self.declaration), [])
        for version in (True, 0, 2, '1'):
            self.assertTrue(config.validate_config(self.declaration | {'schemaVersion': version}))
        self.assertTrue(config.validate_config(self.declaration | {'authorizations': {}}))
        value = deepcopy(self.declaration)
        value['extensions']['release'] = {'strategy': 'commit-sha', 'components': ['web']}
        self.assertEqual(config.validate_config(value), [])
        schema = json.loads((ROOT / 'core/docs/workflow-config.schema.json').read_text())
        self.assertEqual(schema['properties']['schemaVersion']['const'], 1)
        extension = schema['properties']['extensions']['properties']['deployment']
        self.assertFalse(extension['additionalProperties'])
        self.assertEqual(extension['required'], ['components', 'environments'])
        self.assertEqual(schema['$defs']['deploymentIdentifier']['maxLength'], 128)
        environment = extension['properties']['environments']['additionalProperties']
        self.assertEqual(set(environment['properties']['capability']['enum']),
                         {key for key, pack in config.CAPABILITY_PACKS.items() if pack == 'deployment'})
        self.assertNotIn('required', environment['properties']['commands'])
        self.assertEqual(set(environment['properties']['commands']['properties']),
                         set(config.DEPLOYMENT_PHASES + config.DEPLOYMENT_OPTIONAL_PHASES))

    def test_doctor_reports_deployment_pack_and_tool_without_execution(self):
        self.declaration['enabledCapabilities'] = [key for key, pack in config.CAPABILITY_PACKS.items() if pack == 'deployment']
        self.write(self.project, self.declaration)
        self.cli('adopt')
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        report = doctor.check(self.root)
        self.assertFalse(report['commandsExecuted'])
        self.assertTrue(all(item['installed'] and not item['executable'] for item in report['capabilities']))
        self.assertEqual(sum(issue['code'] == 'capability.tool_missing' for issue in report['issues']), 5)
        self.assertEqual(before, {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()})
        (self.root / 'scripts').mkdir()
        (self.root / 'scripts/deployment_prepare.py').write_text('raise RuntimeError("must never run")')
        report = doctor.check(self.root)
        self.assertTrue(all(item['executable'] for item in report['capabilities']))
        self.assertNotIn('capability.tool_missing', {issue['code'] for issue in report['issues']})
        manifest = json.loads(self.manifest.read_text())
        manifest['installedPacks'] = []
        self.write(self.manifest, manifest)
        report = doctor.check(self.root)
        self.assertTrue(all(not item['installed'] for item in report['capabilities']))
        self.assertIn('capability.pack_missing', {issue['code'] for issue in report['issues']})


if __name__ == '__main__':
    unittest.main()
