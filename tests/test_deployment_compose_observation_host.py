import copy
import json
from pathlib import Path
import pickle
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
sys.path.insert(0, str(ROOT / 'scripts'))
from deployment_compose_reader import ComposeReadPolicy
from deployment_compose_artifacts import ComposeArtifacts, ServiceArtifact
from deployment_compose_collect import image_catalog_digest
from deployment_compose_observation_host import (ComposeObservation, ComposeObservationHost,
                                                  _TEST_SEAM)


class Reader:
    gateway_boot_id = 'a' * 32
    changed = None

    def gateway_info(self, *, deadline):
        return {'bootId': self.gateway_boot_id}

    def get(self, path, *, deadline):
        image_id = path.split('/')[3]
        value = {'Id': image_id, 'Os': 'linux', 'Architecture': 'amd64',
                 'RepoDigests': [REGISTRY] if image_id == WEB_IMAGE else []}
        if self.changed is not None:
            self.changed(value)
        return value


WEB_IMAGE = 'sha256:' + 'e' * 64
DB_IMAGE = 'sha256:' + 'f' * 64
REGISTRY = 'example.invalid/web@sha256:' + '1' * 64
API_IMAGE = 'sha256:' + '2' * 64
API_REGISTRY = 'example.invalid/api@sha256:' + '3' * 64


def artifacts():
    return ComposeArtifacts(1, (ServiceArtifact('web', '1' * 40, REGISTRY, WEB_IMAGE,
        'linux', 'amd64', 'host-key-1', 'a' * 64, 'b' * 64, 'none'),))


def scope():
    return {'selectedServices': ['web'], 'protectedServices': ['db'],
            'imageIds': {'web': WEB_IMAGE, 'db': DB_IMAGE},
            'baselineSourceShas': {'web': '1' * 40},
            'protectedConfigHmacs': {'db': 'd' * 64}}


def evidence():
    return {'structuralStatus': 'candidate-unverified', 'structureDigest': 'sha256:' + 'b' * 64,
            'privateDigest': 'c' * 64, 'instanceDigest': 'd' * 64,
            'imageCatalogDigest': image_catalog_digest({WEB_IMAGE: {'os': 'linux', 'architecture': 'amd64', 'repoDigests': [REGISTRY]},
                                                         DB_IMAGE: {'os': 'linux', 'architecture': 'amd64', 'repoDigests': []}}),
            'bindDigest': None,
            'serviceConfigHmacs': {'web': 'a' * 64, 'db': 'd' * 64},
            'serviceImages': {'web': 'sha256:' + 'e' * 64, 'db': 'sha256:' + 'f' * 64},
            'serviceState': {'web': {'running': True, 'health': 'healthy'},
                             'db': {'running': True, 'health': 'healthy'}},
            'authorityGranted': False, 'executionAvailable': False, 'runtimeVerification': 'unknown'}


def host(result=None):
    reader = Reader()
    result = result or evidence()
    issuer = ComposeObservationHost._test_host(reader, scope(),
        lambda reader, policy, max_seconds: copy.deepcopy(result), artifacts(), _token=_TEST_SEAM)
    return issuer, reader, result


class ObservationHostTests(unittest.TestCase):
    def test_issue_and_recheck_do_not_grant_authority(self):
        issuer, reader, result = host()
        observation = issuer.issue()
        self.assertIsInstance(observation, ComposeObservation)
        self.assertTrue(issuer.recheck(observation))
        self.assertFalse(hasattr(observation, 'authorityGranted'))
        with self.assertRaises(TypeError):
            json.dumps(observation)
        with self.assertRaises(TypeError):
            pickle.dumps(observation)
        with self.assertRaises(TypeError):
            copy.copy(observation)

    def test_recheck_rejects_expiry_issuer_and_all_drifts(self):
        issuer, reader, result = host()
        observation = issuer.issue()
        other, _, _ = host()
        self.assertFalse(other.recheck(observation))
        for key in ('structureDigest', 'privateDigest', 'instanceDigest', 'imageCatalogDigest'):
            old = result[key]
            result[key] = ('sha256:' if key == 'structureDigest' else '') + 'e' * 64
            self.assertFalse(issuer.recheck(observation), key)
            result[key] = old
        reader.gateway_boot_id = 'e' * 32
        self.assertFalse(issuer.recheck(observation))
        reader.gateway_boot_id = 'a' * 32
        with self.assertRaises(TypeError):
            observation._expires = time.monotonic() - 1
        object.__setattr__(observation, '_expires', time.monotonic() + 1000)
        self.assertFalse(issuer.recheck(observation))
        object.__setattr__(observation, '_expires', time.monotonic() - 1)
        self.assertFalse(issuer.recheck(observation))

    def test_importable_constructor_token_cannot_replay_unissued_observation(self):
        issuer, reader, _ = host()
        boot, structure, private, instance, catalog, bind = issuer._read(time.monotonic() + 30)
        forged = ComposeObservation(issuer, boot, structure, private, instance, catalog, bind,
                                    time.monotonic() + 30, _token=_TEST_SEAM)
        self.assertFalse(issuer.recheck(forged))

    def test_incomplete_unhealthy_or_missing_private_proof_denied(self):
        issuer, _, result = host()
        for change in (
            lambda r: r['serviceState'].pop('db'),
            lambda r: r['serviceState']['web'].update(health='none'),
            lambda r: r['serviceState']['db'].update(running=False),
            lambda r: r.update(privateDigest=None),
            lambda r: r.update(instanceDigest=None),
            lambda r: r.update(imageCatalogDigest=None),
            lambda r: r['serviceImages'].update(web='sha256:' + '0' * 64),
            lambda r: r.update(structuralStatus='blocked'),
        ):
            candidate = copy.deepcopy(result)
            change(candidate)
            issuer._collect = lambda reader, policy, max_seconds: candidate
            self.assertIsNone(issuer.issue())

    def test_protected_service_without_healthcheck_requires_host_declaration(self):
        issuer, _, result = host()
        result['serviceState']['db']['health'] = 'none'
        self.assertIsNone(issuer.issue())
        issuer._policy['noHealthServices'] = ['db']
        self.assertIsNotNone(issuer.issue())
        result['serviceState']['web']['health'] = 'none'
        self.assertIsNone(issuer.issue())

    def test_host_bind_commitment_is_required_and_rechecked(self):
        issuer, _, result = host()
        issuer._bind_count = 1
        self.assertIsNone(issuer.issue())
        result['bindDigest'] = '9' * 64
        issuer._policy['bindDigest'] = '9' * 64
        observation = issuer.issue()
        self.assertIsNotNone(observation)
        self.assertTrue(issuer.recheck(observation))
        result['bindDigest'] = '8' * 64
        self.assertFalse(issuer.recheck(observation))

    def test_stable_wrong_private_config_cannot_issue_observation(self):
        issuer, _, result = host()
        result['serviceConfigHmacs']['web'] = '0' * 64
        self.assertIsNone(issuer.issue())
        result['serviceConfigHmacs']['web'] = 'a' * 64
        result['serviceConfigHmacs']['db'] = '0' * 64
        self.assertIsNone(issuer.issue())

    def test_direct_image_inspect_drift_denied_after_collector(self):
        issuer, reader, _ = host()
        observed = issuer.issue()
        self.assertIsNotNone(observed)
        reader.changed = lambda value: value.update(RepoDigests=[])
        self.assertFalse(issuer.recheck(observed))
        self.assertIsNone(issuer.issue())
        reader.changed = lambda value: value.update(Architecture='arm64')
        self.assertFalse(issuer.recheck(observed))
        reader.changed = lambda value: value.update(Id=DB_IMAGE)
        self.assertFalse(issuer.recheck(observed))

    def test_total_age_includes_collect_and_direct_image_reads(self):
        issuer, reader, _ = host()
        issuer._max_age = 0.01
        reader.changed = lambda value: time.sleep(0.02)
        self.assertIsNone(issuer.issue())

    def test_public_constructor_rejects_source_or_image_scope_mismatch(self):
        policy = ComposeReadPolicy('https://docker.example', 'a' * 64, 'daemon', 'project',
                                   gateway_policy_hash='b' * 64, private_key_id='host-key-1')
        for change in (
            lambda value: value.update(baselineSourceShas={'web': '2' * 40}),
            lambda value: value.update(baselineSourceShas={}),
            lambda value: value.update(baselineSourceShas={'web': 'z' * 40}),
            lambda value: value['imageIds'].update(web=DB_IMAGE),
            lambda value: value.update(migrationDigests={'web': 'c' * 64}),
        ):
            host_scope = dict(scope(), project='project', daemonId='daemon', volumes={})
            change(host_scope)
            with self.assertRaises(ValueError):
                ComposeObservationHost(reader_policy=policy, scope_policy=host_scope,
                    baseline_artifacts=artifacts(), ca_file=ROOT / 'tests/ca',
                    cert_file=ROOT / 'tests/cert', key_file=ROOT / 'tests/key')

    def test_public_constructor_accepts_distinct_selected_baseline_sources(self):
        policy = ComposeReadPolicy('https://docker.example', 'a' * 64, 'daemon', 'project',
                                   gateway_policy_hash='b' * 64, private_key_id='host-key-1')
        mixed = ComposeArtifacts(1, (
            ServiceArtifact('api', '2' * 40, API_REGISTRY, API_IMAGE,
                            'linux', 'amd64', 'host-key-1', 'c' * 64, 'b' * 64, 'none'),
            ServiceArtifact('web', '1' * 40, REGISTRY, WEB_IMAGE,
                            'linux', 'amd64', 'host-key-1', 'a' * 64, 'b' * 64, 'none'),
        ))
        host_scope = dict(scope(), project='project', daemonId='daemon', volumes={},
                          selectedServices=['api', 'web'],
                          imageIds={'api': API_IMAGE, 'web': WEB_IMAGE, 'db': DB_IMAGE},
                          baselineSourceShas={'api': '2' * 40, 'web': '1' * 40})
        with mock.patch('deployment_compose_observation_host.ComposeDockerReader'):
            issuer = ComposeObservationHost(reader_policy=policy, scope_policy=host_scope,
                                            baseline_artifacts=mixed, ca_file=ROOT / 'tests/ca',
                                            cert_file=ROOT / 'tests/cert', key_file=ROOT / 'tests/key')
        self.assertEqual(issuer._policy['baselineSourceShas'], host_scope['baselineSourceShas'])
        self.assertIs(issuer._baseline_artifacts, mixed)
        for changed in ({'api': '1' * 40, 'web': '1' * 40},
                        {'api': '2' * 40},
                        {'api': '2' * 40, 'web': '1' * 40, 'db': '3' * 40}):
            with self.assertRaisesRegex(ValueError, '^host-artifact-scope-mismatch$'):
                ComposeObservationHost(reader_policy=policy,
                    scope_policy=dict(host_scope, baselineSourceShas=changed),
                    baseline_artifacts=mixed, ca_file=ROOT / 'tests/ca',
                    cert_file=ROOT / 'tests/cert', key_file=ROOT / 'tests/key')

    def test_public_constructor_rejects_unpinned_or_injected_transport(self):
        policy = ComposeReadPolicy('https://docker.example', 'a' * 64, 'daemon', 'project')
        with self.assertRaises(ValueError):
            ComposeObservationHost(reader_policy=policy, scope_policy={'project': 'project', 'daemonId': 'daemon', 'volumes': {}}, baseline_artifacts=artifacts(),
                                   ca_file=Path('/unused'), cert_file=Path('/unused'), key_file=Path('/unused'))
        with self.assertRaises(TypeError):
            ComposeObservation(None, 'a' * 32, 'sha256:' + 'b' * 64, 'c' * 64,
                               'd' * 64, 'e' * 64, None, 1)
        with self.assertRaises(TypeError):
            ComposeObservationHost._test_host(Reader(), {}, lambda *args: evidence(), artifacts())

    def test_valid_pinned_constructor_and_isolated_distribution_import(self):
        policy = ComposeReadPolicy('https://docker.example', 'a' * 64, 'daemon', 'project',
                                   gateway_policy_hash='b' * 64, private_key_id='host-key-1')
        host_scope = dict(scope(), project='project', daemonId='daemon', volumes={})
        with mock.patch('deployment_compose_observation_host.ComposeDockerReader') as reader:
            issuer = ComposeObservationHost(reader_policy=policy, scope_policy=host_scope, baseline_artifacts=artifacts(),
                                            ca_file=ROOT / 'tests/ca', cert_file=ROOT / 'tests/cert',
                                            key_file=ROOT / 'tests/key')
        self.assertIsNotNone(issuer)
        reader.assert_called_once()
        command = [sys.executable, '-I', '-B', '-c',
                   "import runpy; runpy.run_path(" + repr(str(ROOT / 'scripts/deployment_compose_observation_host.py')) + ")"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bind_count_must_match_selected_host_mount_sources(self):
        policy = ComposeReadPolicy('https://docker.example', 'a' * 64, 'daemon', 'project',
                                   gateway_policy_hash='b' * 64, private_key_id='host-key-1',
                                   bind_count=1)
        host_scope = dict(scope(), project='project', daemonId='daemon', volumes={},
                          bindPaths=['/host/config'], bindDigest='9' * 64,
                          mounts={'web': [{'type': 'bind', 'source': '/host/config',
                                           'target': '/etc/config', 'readOnly': True}], 'db': []})
        with mock.patch('deployment_compose_observation_host.ComposeDockerReader'):
            self.assertIsNotNone(ComposeObservationHost(
                reader_policy=policy, scope_policy=host_scope, baseline_artifacts=artifacts(),
                ca_file=ROOT / 'tests/ca', cert_file=ROOT / 'tests/cert',
                key_file=ROOT / 'tests/key'))
        without_expected = dict(host_scope)
        without_expected.pop('bindDigest')
        with self.assertRaisesRegex(ValueError, '^host-bind-scope-mismatch$'):
            ComposeObservationHost(reader_policy=policy, scope_policy=without_expected,
                                   baseline_artifacts=artifacts(), ca_file=ROOT / 'tests/ca',
                                   cert_file=ROOT / 'tests/cert', key_file=ROOT / 'tests/key')
        host_scope['bindPaths'] = ['/host/other']
        with self.assertRaisesRegex(ValueError, '^host-bind-scope-mismatch$'):
            ComposeObservationHost(reader_policy=policy, scope_policy=host_scope,
                                   baseline_artifacts=artifacts(), ca_file=ROOT / 'tests/ca',
                                   cert_file=ROOT / 'tests/cert', key_file=ROOT / 'tests/key')
        host_scope['bindPaths'] = ['/host/config']
        host_scope['mounts']['web'] = {'unexpected': 'mapping'}
        with self.assertRaisesRegex(ValueError, '^host-bind-scope-mismatch$'):
            ComposeObservationHost(reader_policy=policy, scope_policy=host_scope,
                                   baseline_artifacts=artifacts(), ca_file=ROOT / 'tests/ca',
                                   cert_file=ROOT / 'tests/cert', key_file=ROOT / 'tests/key')


if __name__ == '__main__':
    unittest.main()
