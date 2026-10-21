"""Regression coverage for structurally valid historical migration inputs."""

import json
import unittest

if __package__:
    from .manifest_fixture import historical_manifest
else:
    from manifest_fixture import historical_manifest


class HistoricalManifestTests(unittest.TestCase):
    def setUp(self):
        self.current = {
            'schemaVersion': 5, 'workflowVersion': 'current',
            'gitPolicy': {'mergeActor': 'user', 'deleteAllowed': False},
            'files': [{'path': 'docs/TASKS.md', 'installedSha256': 'a' * 64}],
            'installedPacks': ['architecture'],
        }

    def test_schema_three_has_only_historical_policy(self):
        fixture = historical_manifest(self.current, 3)
        decoded = json.loads(json.dumps(fixture))
        self.assertEqual(decoded['gitPolicy'], {
            'pushMode': 'manual', 'pushActor': 'ai',
            'mergeMode': 'manual', 'mergeActor': 'ai',
        })
        self.assertEqual(self.current['gitPolicy']['mergeActor'], 'user')

    def test_schema_two_preserves_changed_ownership_case(self):
        fixture = historical_manifest(self.current, 2)
        self.assertEqual(fixture['workflowVersion'], '0.1.9')
        self.assertEqual(fixture['files'][0]['installedSha256'], '0' * 64)
        self.assertEqual(json.loads(json.dumps(fixture))['schemaVersion'], 2)

    def test_schema_one_omits_fields_not_supported_then(self):
        fixture = historical_manifest(self.current, 1)
        self.assertNotIn('gitPolicy', fixture)
        self.assertNotIn('files', fixture)
        self.assertEqual(json.loads(json.dumps(fixture))['installedPacks'], ['architecture'])
