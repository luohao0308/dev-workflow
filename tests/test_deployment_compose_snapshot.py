"""Cross-surface authenticated observation consistency, never authorization."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from tests.test_deployment_compose_config import config, context
from tests.test_deployment_compose_host_config import fixture as host_fixture
from tests.test_deployment_compose_network import fixture as network_fixture
from deployment_compose_artifacts import ServiceArtifact
from deployment_compose_private import MOUNT, commit
from deployment_compose_snapshot import prepare_snapshot, commit_snapshot

KEY = b'private-test-key-' + b'x' * 32


def fixture():
    ctx = dict(context(), hostId='host-one', daemonId='daemon-one', requestedApiVersion='1.45', engineVersion='29.8.2')
    raw = {'Id': ctx['containerId'], 'Name': '/' + ctx['containerName'], 'Image': ctx['imageId'],
           'Config': config(), 'HostConfig': host_fixture(), 'NetworkSettings': network_fixture(),
           'Mounts': [
               {'Type': 'volume', 'Name': 'sample-data', 'Driver': 'local', 'Source': '/var/lib/docker/volumes/sample-data/_data',
                'Destination': '/data', 'RW': True, 'Mode': '', 'Propagation': ''},
               {'Type': 'bind', 'Source': '/sample/config', 'Destination': '/config', 'RW': False, 'Mode': 'ro', 'Propagation': 'rprivate'}]}
    raw['NetworkSettings']['Ports'] = {}
    projection = {k: raw[k] for k in ('Config', 'HostConfig', 'NetworkSettings')}
    projection['Mounts'] = [{**m, **{k: m.get(k) for k in MOUNT}} for m in raw['Mounts']]
    digest = commit(ctx['project'], ctx['service'], projection, 'inspect-key', KEY)['configHmac']
    artifact = ServiceArtifact(ctx['service'], 'a' * 40, 'example.com/app@sha256:' + 'c' * 64,
        ctx['imageId'], 'linux', 'amd64', 'inspect-key', digest, 'd' * 64, 'none')
    networks = {'sample_default': 'c' * 64}
    mounts = {'/data': {'type': 'volume', 'source': 'sample-data', 'readOnly': False},
              '/config': {'type': 'bind', 'source': '/sample/config', 'readOnly': True}}
    return raw, ctx, artifact, networks, mounts


def rebind(raw, ctx, artifact):
    projection = {k: raw[k] for k in ('Config', 'HostConfig', 'NetworkSettings')}
    projection['Mounts'] = [{**m, **{k: m.get(k) for k in MOUNT}} for m in raw['Mounts']]
    digest = commit(ctx['project'], ctx['service'], projection, artifact.config_key_id, KEY)['configHmac']
    return replace(artifact, config_hmac=digest)


def build(raw, ctx, artifact, networks, mounts):
    return prepare_snapshot(raw, ctx, artifact, KEY, networks, mounts)


class SnapshotTests(unittest.TestCase):
    def test_all_surfaces_bound_without_reconstruction_claim(self):
        raw, ctx, artifact, networks, mounts = fixture()
        value = build(raw, ctx, artifact, networks, mounts)
        self.assertEqual(value['config']['rawConfig'], raw['Config'])
        self.assertEqual(value['hostConfig']['rawHostConfig'], raw['HostConfig'])
        self.assertEqual(value['networkSettings']['rawNetworkSettings'], raw['NetworkSettings'])
        self.assertEqual(value['mounts'], raw['Mounts'])
        self.assertFalse(value['authorityGranted'] or value['executionAvailable'] or value['reconstructionValidated'])
        first = commit_snapshot(raw, ctx, artifact, KEY, networks, mounts, key_id='snapshot-key', key=b'z' * 32)
        self.assertEqual(first, commit_snapshot(raw, ctx, artifact, KEY, networks, mounts, key_id='snapshot-key', key=b'z' * 32))
        changed = dict(ctx, daemonId='daemon-two')
        self.assertNotEqual(first, commit_snapshot(raw, changed, artifact, KEY, networks, mounts, key_id='snapshot-key', key=b'z' * 32))
        raw['Config']['Env'].append('CHANGED=secret')
        self.assertNotEqual(value['config']['rawConfig'], raw['Config'])

    def test_wrong_identity_artifact_or_private_proof_is_rejected(self):
        raw, ctx, artifact, networks, mounts = fixture()
        for field, value in [('Id', 'b' * 64), ('Name', '/other'), ('Image', 'sha256:' + 'f' * 64)]:
            changed = deepcopy(raw); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                build(changed, ctx, artifact, networks, mounts)
        for changed in (replace(artifact, config_hmac='0' * 64), replace(artifact, service='other'),
                        replace(artifact, image_id='sha256:' + 'f' * 64)):
            with self.assertRaises(ValueError):
                build(raw, ctx, changed, networks, mounts)
        changed = deepcopy(raw); changed['Config']['Env'][0] = 'Z=foreign-secret'
        with self.assertRaisesRegex(ValueError, '^invalid-compose-observed-snapshot$'):
            build(changed, ctx, artifact, networks, mounts)

    def test_network_and_mount_pins_and_order_coherence_reject_splices(self):
        raw, ctx, artifact, networks, mounts = fixture()
        for changed_networks, changed_mounts in [({'sample_default': 'f' * 64}, mounts),
                (networks, {**mounts, '/data': dict(mounts['/data'], source='other-volume')}),
                (networks, {'/data': mounts['/data']})]:
            with self.assertRaises(ValueError):
                build(raw, ctx, artifact, changed_networks, changed_mounts)
        for mutate in [lambda r: r['HostConfig']['Mounts'][0].update(Source='other'),
                       lambda r: r['Mounts'][1].update(RW=True),
                       lambda r: r['HostConfig'].update(NetworkMode='host'),
                       lambda r: r['HostConfig']['Mounts'][0]['VolumeOptions'].update(NoCopy=False),
                       lambda r: r['HostConfig']['Tmpfs'].update({'/data': ''}),
                       lambda r: r['Mounts'].append(deepcopy(r['Mounts'][0]))]:
            changed = deepcopy(raw); mutate(changed)
            # A genuine private HMAC cannot excuse inconsistent cross-surface topology.
            authenticated = rebind(changed, ctx, artifact)
            with self.assertRaises(ValueError):
                build(changed, ctx, authenticated, networks, mounts)

    def test_readonly_volume_requires_explicit_readonly_declaration(self):
        raw, ctx, artifact, networks, mounts = fixture()
        raw['Mounts'][0]['RW'] = False
        mounts['/data']['readOnly'] = True
        authenticated = rebind(raw, ctx, artifact)
        with self.assertRaises(ValueError):
            build(raw, ctx, authenticated, networks, mounts)
        raw['HostConfig']['Mounts'][0]['ReadOnly'] = True
        authenticated = rebind(raw, ctx, artifact)
        self.assertFalse(build(raw, ctx, authenticated, networks, mounts)['executionAvailable'])

    def test_no_mounts_preserves_missing_null_and_empty_declarations(self):
        values = []
        for mode in ('missing', 'null', 'empty'):
            raw, ctx, artifact, networks, _ = fixture()
            raw['Mounts'] = []
            if mode == 'missing':
                raw['HostConfig'].pop('Mounts')
            else:
                raw['HostConfig']['Mounts'] = None if mode == 'null' else []
            authenticated = rebind(raw, ctx, artifact)
            value = build(raw, ctx, authenticated, networks, {})
            self.assertEqual(value['hostConfig']['rawHostConfig'], raw['HostConfig'])
            values.append(commit_snapshot(raw, ctx, authenticated, KEY, networks, {}, key_id='key', key=b'z'*32)['hmac'])
        self.assertEqual(len(set(values)), 3)

    def test_multiple_pinned_networks_and_duplicate_network_ids(self):
        raw, ctx, artifact, networks, mounts = fixture()
        second = deepcopy(raw['NetworkSettings']['Networks']['sample_default'])
        second['NetworkID'] = 'e' * 64
        raw['NetworkSettings']['Networks']['sample_second'] = second
        networks['sample_second'] = 'e' * 64
        self.assertFalse(build(raw, ctx, rebind(raw, ctx, artifact), networks, mounts)['authorityGranted'])
        networks['sample_second'] = 'c' * 64
        raw['NetworkSettings']['Networks']['sample_second']['NetworkID'] = 'c' * 64
        with self.assertRaises(ValueError):
            build(raw, ctx, rebind(raw, ctx, artifact), networks, mounts)

    def test_authenticated_port_contradictions_are_rejected(self):
        for bindings in ([{'HostIp': '0.0.0.0', 'HostPort': '8080'}], None, []):
            raw, ctx, artifact, networks, mounts = fixture()
            raw['NetworkSettings']['Ports'] = {'8080/tcp': bindings}
            with self.assertRaises(ValueError):
                build(raw, ctx, rebind(raw, ctx, artifact), networks, mounts)
        raw, ctx, artifact, networks, mounts = fixture()
        raw['HostConfig']['PublishAllPorts'] = True
        with self.assertRaises(ValueError):
            build(raw, ctx, rebind(raw, ctx, artifact), networks, mounts)
        raw['HostConfig']['PublishAllPorts'] = False
        raw['Config']['ExposedPorts'] = {'8080/tcp': {}}
        raw['NetworkSettings']['Ports'] = {'8080/tcp': None}
        self.assertFalse(build(raw, ctx, rebind(raw, ctx, artifact), networks, mounts)['executionAvailable'])

    def test_metadata_and_unknown_fields_reject_without_secret_diagnostics(self):
        raw, ctx, artifact, networks, mounts = fixture()
        for change in ({'requestedApiVersion': '1.56'}, {'daemonId': 'private secret'}, {'hostId': True}):
            with self.assertRaisesRegex(ValueError, '^invalid-compose-observed-snapshot$'):
                build(raw, dict(ctx, **change), artifact, networks, mounts)
        raw['Mounts'][1]['extra'] = 'private-secret'
        with self.assertRaisesRegex(ValueError, '^invalid-compose-observed-snapshot$'):
            build(raw, ctx, artifact, networks, mounts)


if __name__ == '__main__':
    unittest.main()
