"""Fixed HostConfig profile rejects even authentically committed unsafe values."""
from copy import deepcopy
from unittest.mock import patch
import unittest

from tests.test_deployment_compose_snapshot import fixture as source_fixture, rebind, KEY
import deployment_compose_restore_host_config as restore


def fixture():
    raw, identity, artifact, networks, mounts = source_fixture()
    host = raw['HostConfig']
    host['MaskedPaths'] = list(restore.MASKED_PATHS)
    host['ReadonlyPaths'] = list(restore.READONLY_PATHS)
    for old, new in (('/data', '/sample-data'), ('/config', '/sample-config')):
        mounts[new] = mounts.pop(old)
        for m in raw['Mounts']:
            if m['Destination'] == old:
                m['Destination'] = new
        for m in host['Mounts']:
            if m['Target'] == old:
                m['Target'] = new
    return raw, identity, rebind(raw, identity, artifact), networks, mounts


def build(args, *, policy=restore.POLICY):
    raw, identity, artifact, networks, mounts = args
    return restore.compile_restore_host_config(raw, identity, artifact, KEY,
                                               networks, mounts, policy=policy)


class RestoreHostConfigTests(unittest.TestCase):
    def test_exact_private_fields_and_no_authority_or_request(self):
        args = fixture(); before = deepcopy(args)
        result = build(args)
        self.assertEqual(args, before)
        self.assertEqual(result['hostConfigFragment'], args[0]['HostConfig'])
        for k in ('daemonEffectiveDefaultsVerified', 'bindSourceTypesVerified',
                  'completeCreatePayloadAvailable', 'authorityGranted', 'executionAvailable',
                  'reconstructionValidated', 'productionReady'):
            self.assertIs(result[k], False)
        self.assertFalse({'method', 'path', 'Config', 'NetworkingConfig'} & result.keys())
        self.assertIn('daemon-effective-defaults-required', result['blockers'])
        args[0]['HostConfig']['LogConfig']['Config']['max-size'] = '20m'
        self.assertEqual(result['hostConfigFragment']['LogConfig']['Config']['max-size'], '10m')

    def test_each_policy_field_requires_exact_value_even_with_valid_source_hmac(self):
        fields = restore._fixed_policy()
        self.assertEqual(set(fields) | {'NetworkMode'}, restore.REQUIRED)
        for name, original in fields.items():
            args = fixture(); raw, identity, artifact, networks, mounts = args
            value = (not original if type(original) is bool else
                     original + 1 if type(original) is int else
                     original + 'changed' if type(original) is str else
                     [] if original is None else None)
            raw['HostConfig'][name] = value
            with self.subTest(field=name), self.assertRaisesRegex(ValueError, '^invalid-compose-restore-host-config-fragment$'):
                build((raw, identity, rebind(raw, identity, artifact), networks, mounts))

    def test_unsafe_structurally_valid_overrides_reject(self):
        changes = {'Privileged': True, 'ReadonlyRootfs': False, 'AutoRemove': True,
                   'CapAdd': ['SYS_ADMIN'], 'SecurityOpt': ['seccomp=unconfined'],
                   'Binds': ['/var/run/docker.sock:/socket:ro'], 'PidMode': 'host',
                   'IpcMode': 'host', 'UsernsMode': 'host', 'CgroupnsMode': 'host',
                   'Memory': 0, 'MemorySwap': -1, 'NanoCpus': 0, 'PidsLimit': -1,
                   'MaskedPaths': [], 'ReadonlyPaths': [], 'OomKillDisable': True,
                   'LogConfig': {'Type': 'json-file', 'Config': {}},
                   'RestartPolicy': {'Name': 'always', 'MaximumRetryCount': 0},
                   'Tmpfs': {'/': 'size=4m'}}
        for field, value in changes.items():
            raw, identity, artifact, networks, mounts = fixture()
            raw['HostConfig'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                build((raw, identity, rebind(raw, identity, artifact), networks, mounts))

    def test_complete_source_authentication_and_mount_coherence_still_required(self):
        args = fixture()
        args[0]['Config']['Env'].append('TAMPERED=secret')
        with self.assertRaises(ValueError):
            build(args)
        raw, identity, artifact, networks, mounts = fixture()
        raw['HostConfig']['Mounts'][0]['VolumeOptions']['NoCopy'] = False
        with self.assertRaises(ValueError):
            build((raw, identity, rebind(raw, identity, artifact), networks, mounts))

    def test_unsupported_mount_destinations_and_bind_write_reject(self):
        for target in ('/', '/proc', '/sys', '/dev', '/sample-config/nested', '/other'):
            raw, identity, artifact, networks, mounts = fixture()
            mounts[target] = mounts.pop('/sample-config')
            raw['Mounts'][1]['Destination'] = target
            raw['HostConfig']['Mounts'][1]['Target'] = target
            with self.subTest(target=target), self.assertRaises(ValueError):
                build((raw, identity, rebind(raw, identity, artifact), networks, mounts))
        raw, identity, artifact, networks, mounts = fixture()
        mounts['/sample-config']['readOnly'] = False
        raw['Mounts'][1]['RW'] = True
        raw['HostConfig']['Mounts'][1]['ReadOnly'] = False
        with self.assertRaises(ValueError):
            build((raw, identity, rebind(raw, identity, artifact), networks, mounts))

    def test_missing_null_and_empty_mounts_preserved_for_no_mount_service(self):
        digests = []
        for state in ('missing', None, []):
            raw, identity, artifact, networks, _ = fixture()
            raw['Mounts'] = []
            if state == 'missing':
                raw['HostConfig'].pop('Mounts')
            else:
                raw['HostConfig']['Mounts'] = state
            result = build((raw, identity, rebind(raw, identity, artifact), networks, {}))
            self.assertEqual(result['hostConfigFragment'], raw['HostConfig'])
            digests.append(result['fragmentDigest'])
        self.assertEqual(len(set(digests)), 3)

    def test_readonly_volume_and_network_id_form_preserved(self):
        raw, identity, artifact, networks, mounts = fixture()
        raw['Mounts'][0]['RW'] = False
        raw['HostConfig']['Mounts'][0]['ReadOnly'] = True
        mounts['/sample-data']['readOnly'] = True
        raw['HostConfig']['NetworkMode'] = networks['sample_default']
        result = build((raw, identity, rebind(raw, identity, artifact), networks, mounts))
        self.assertEqual(result['hostConfigFragment'], raw['HostConfig'])
        self.assertEqual(result['networkModeBinding']['observed'], networks['sample_default'])
        self.assertIs(result['networkModeBinding']['createSemanticsValidated'], False)

    def test_multiple_networks_and_policy_expansion_fail_closed(self):
        raw, identity, artifact, networks, mounts = fixture()
        endpoint = deepcopy(raw['NetworkSettings']['Networks']['sample_default'])
        endpoint['NetworkID'] = 'e'*64
        raw['NetworkSettings']['Networks']['second'] = endpoint
        networks['second'] = 'e'*64
        with self.assertRaises(ValueError):
            build((raw, identity, rebind(raw, identity, artifact), networks, mounts))
        for policy in ('other-profile', '', True, None):
            with self.assertRaises(ValueError):
                build(fixture(), policy=policy)
        with patch.object(restore, 'REQUIRED', restore.REQUIRED | {'FutureField'}):
            with self.assertRaises(ValueError):
                build(fixture())

    def test_source_host_identity_bound_without_claiming_effective_defaults(self):
        args = fixture(); first = build(args)
        changed = (args[0], dict(args[1], daemonId='another-daemon'), *args[2:])
        second = build(changed)
        self.assertEqual(first['hostConfigFragment'], second['hostConfigFragment'])
        self.assertNotEqual(first['fragmentDigest'], second['fragmentDigest'])
        self.assertEqual(first['policyDigest'], second['policyDigest'])


    def test_oom_enabled_policy_is_explicit_and_preserves_null_policy(self):
        original = fixture()
        with self.assertRaises(ValueError):
            build(original, policy=restore.OOM_ENABLED_POLICY)
        raw, identity, artifact, networks, mounts = fixture()
        raw['HostConfig']['OomKillDisable'] = False
        changed = (raw, identity, rebind(raw, identity, artifact), networks, mounts)
        with self.assertRaises(ValueError):
            build(changed)
        accepted = build(changed, policy=restore.OOM_ENABLED_POLICY)
        self.assertIs(accepted['hostConfigFragment']['OomKillDisable'], False)
        self.assertNotEqual(accepted['policyDigest'], build(original)['policyDigest'])
        self.assertIsNone(restore._fixed_policy()['OomKillDisable'])
        old = restore._fixed_policy(); new = restore._fixed_policy(policy=restore.OOM_ENABLED_POLICY)
        old.pop('OomKillDisable'); new.pop('OomKillDisable')
        self.assertEqual(old, new)
        for value in (True, 0, 1, None):
            raw['HostConfig']['OomKillDisable'] = value
            rejected = (raw, identity, rebind(raw, identity, artifact), networks, mounts)
            with self.subTest(value=value), self.assertRaises(ValueError):
                build(rejected, policy=restore.OOM_ENABLED_POLICY)


if __name__ == '__main__':
    unittest.main()
