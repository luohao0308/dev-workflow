"""Stopped restore comparisons and private-daemon preflight, no Engine writes."""
from copy import deepcopy
import json
import subprocess
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
for directory in ('scripts', 'packs/deployment/scripts', 'tests/support'):
    sys.path.insert(0, str(ROOT / directory))
import deployment_compose_namespaced_restore_probe as probe
from tests.test_deployment_compose_restore_host_config import fixture


class RestoreProbeTests(unittest.TestCase):
    def test_complete_values_equal_and_dynamic_fields_classified(self):
        raw = fixture()[0]
        self.assertTrue(probe.compare_restored(raw, deepcopy(raw))['exactConfigHostMountAndDeclarationMatch'])
        changed = deepcopy(raw)
        changed['NetworkSettings']['Networks']['sample_default']['EndpointID'] = 'f'*64
        changed['NetworkSettings']['SandboxID'] = 'e'*64
        result = probe.compare_restored(raw, changed)
        self.assertTrue(result['exactConfigHostMountAndDeclarationMatch'])
        self.assertFalse(result['fullRuntimeNetworkIdentityEqual'])
        self.assertEqual(result['classifiedGeneratedNetworkDifferenceFields'], ['SandboxID', 'endpoint.EndpointID'])

    def test_changed_metadata_resources_mount_and_alias_are_unexplained(self):
        for field in ('Config', 'HostConfig', 'Mounts', 'aliases'):
            raw = fixture()[0]; changed = deepcopy(raw)
            if field == 'Config': changed['Config']['Hostname'] = 'changed'
            elif field == 'HostConfig': changed['HostConfig']['MemorySwap'] = -1
            elif field == 'Mounts': changed['Mounts'][0]['RW'] = False
            else: changed['NetworkSettings']['Networks']['sample_default']['Aliases'] = ['foreign']
            with self.subTest(field=field):
                self.assertFalse(probe.compare_restored(raw, changed)['exactConfigHostMountAndDeclarationMatch'])

    def test_unclassified_network_fields_and_membership_rejected(self):
        for part in ('settings', 'endpoint', 'members'):
            raw = fixture()[0]; changed = deepcopy(raw)
            if part == 'settings': changed['NetworkSettings']['Future'] = None
            elif part == 'endpoint': changed['NetworkSettings']['Networks']['sample_default']['Future'] = None
            else: changed['NetworkSettings']['Networks'] = {}
            with self.subTest(part=part), self.assertRaises(ValueError):
                probe.compare_restored(raw, changed)

    def test_type_substitution_is_not_equivalent(self):
        raw = fixture()[0]; changed = deepcopy(raw)
        changed['HostConfig']['ReadonlyRootfs'] = 1
        self.assertFalse(probe.compare_restored(raw, changed)['exactConfigHostMountAndDeclarationMatch'])

    def test_bad_private_identity_rejects_before_any_resource_write(self):
        target = Mock()
        target.run.return_value = json.dumps({'ID': 'wrong', 'DockerRootDir': '/bad', 'SwapLimit': True})
        with patch.object(probe, 'PrivateDaemon', return_value=target), patch.object(probe, 'source_image') as image:
            result = probe.run_restore(Path('/var/tmp/dw-engine-'+'a'*16), {'ID': 'expected'})
        self.assertFalse(result['success']); self.assertFalse(result['productionReady'])
        self.assertEqual(result['failurePhase'], 'preflight'); image.assert_not_called()
        self.assertEqual([call.args[:1] for call in target.run.call_args_list], [('info',), ('ps',)])
        self.assertEqual(result['createdIds'], [])


    def test_unknown_cleanup_response_blocks_remaining_writes(self):
        root = Path('/var/tmp/dw-engine-'+'a'*16); target = Mock(); calls = []
        def run(*args):
            calls.append(args)
            if args[0] == 'info':
                return json.dumps({'ID': 'expected', 'DockerRootDir': str(root/'data'), 'SwapLimit': True})
            if args[:2] == ('image', 'inspect'): return '[]'
            if args[:2] == ('image', 'rm'): raise subprocess.TimeoutExpired('private-image-rm', 30)
            return ''
        target.run.side_effect = run
        with patch.object(probe, 'PrivateDaemon', return_value=target), \
             patch.object(probe, 'source_image', return_value={'Id': 'sha256:'+'b'*64}), \
             patch.object(probe, 'ensure_capacity'), patch.object(probe, 'transfer_image'):
            result = probe.run_restore(root, {'ID': 'expected'})
        self.assertFalse(result['success']); self.assertTrue(result['unknownWriteResult'])
        self.assertEqual(result['cleanupFailureType'], 'TimeoutExpired')
        self.assertEqual(calls[-1], ('image', 'rm', 'sha256:'+'b'*64))


if __name__ == '__main__': unittest.main()
