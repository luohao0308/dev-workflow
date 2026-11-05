"""Stopped restore comparisons and private-daemon preflight, no Engine writes."""
from copy import deepcopy
import json
import subprocess
import tempfile
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


class RunningRestoreTests(unittest.TestCase):
    def baseline(self):
        raw = fixture()[0]
        raw['Id'] = 'old';raw['State'] = {'Running': True, 'StartedAt':'fixed'};raw['RestartCount'] = 0
        return raw

    def test_create_default_rule_is_exact_and_opt_in_only(self):
        raw = fixture()[0]; restored = deepcopy(raw)
        raw['HostConfig']['OomKillDisable'] = None
        server = {'Version': '29.8.2', 'GitCommit': '8af9fe3', 'RequestedApiVersion': '1.45'}
        body = {'HostConfig': deepcopy(raw['HostConfig'])}
        for value in (False, 0, True):
            restored['HostConfig']['OomKillDisable'] = value
            comparison = probe.compare_created(raw, restored, body, server)
            self.assertEqual(bool(comparison['acceptedCreateDefaultFields']), value is False)
            self.assertEqual(comparison['exactConfigHostMountAndDeclarationMatch'], value is False)
            self.assertFalse(probe.compare_restored(raw, restored)['exactConfigHostMountAndDeclarationMatch'])
        restored['HostConfig']['OomKillDisable'] = False
        for field, value in [('Version', '29.8.3'), ('GitCommit', 'other'), ('RequestedApiVersion', '1.46')]:
            self.assertFalse(probe.compare_created(raw, restored, body, dict(server, **{field:value}))['exactConfigHostMountAndDeclarationMatch'])
        body['HostConfig']['OomKillDisable'] = False
        self.assertFalse(probe.compare_created(raw, restored, body, server)['exactConfigHostMountAndDeclarationMatch'])

    def test_invalid_create_receipt_is_never_registered(self):
        known = ['a' * 64]
        for value in (None, [], {}, {'Id': True}, {'Id': 'b' * 63}, {'Id': 'a' * 64}):
            with self.assertRaises(ValueError):probe.created_id(value, known)
            self.assertEqual(known, ['a' * 64])
        self.assertEqual(probe.created_id({'Id': 'b' * 64}, known), 'b' * 64)

    def test_precheck_failure_has_no_old_stop(self):
        target, start = Mock(), Mock()
        with self.assertRaises(ValueError):
            probe.switch_stopped_restore(target, 'old', 'new', lambda fn:fn(), start,
                {'exactConfigHostMountAndDeclarationMatch':False}, baseline=self.baseline())
        target.stop.assert_not_called(); start.assert_not_called()

    def test_unknown_old_stop_never_starts_new(self):
        target, start = Mock(), Mock()
        target.stop.side_effect = subprocess.TimeoutExpired('stop', 10)
        with self.assertRaises(subprocess.TimeoutExpired):
            probe.switch_stopped_restore(target, 'old', 'new', lambda fn:fn(), start,
                {'exactConfigHostMountAndDeclarationMatch':True}, baseline=self.baseline())
        target.run.assert_not_called();start.assert_not_called()

    def test_stop_must_be_observed_and_new_health_failure_propagates(self):
        target, start = Mock(), Mock()
        target.run.return_value = json.dumps([{'Id':'old','State':{'Running':True}}])
        with self.assertRaises(ValueError):
            probe.switch_stopped_restore(target, 'old', 'new', lambda fn:fn(), start,
                {'exactConfigHostMountAndDeclarationMatch':True}, baseline=self.baseline())
        start.assert_not_called()
        stopped = self.baseline();stopped['State']['Running'] = False
        target.run.return_value = json.dumps([stopped])
        start.side_effect = ValueError('runtime-container-unhealthy')
        with self.assertRaisesRegex(ValueError,'runtime-container-unhealthy'):
            probe.switch_stopped_restore(target, 'old', 'new', lambda fn:fn(), start,
                {'exactConfigHostMountAndDeclarationMatch':True}, baseline=self.baseline())
        start.assert_called_once_with('new')

    def test_post_stop_restart_or_stable_configuration_drift_blocks_new_start(self):
        baseline = self.baseline()
        for mutate in (lambda c:c['State'].update(StartedAt='restarted'),
                       lambda c:c.update(RestartCount=1),
                       lambda c:c['Config'].update(Hostname='changed'),
                       lambda c:c['HostConfig'].update(Memory=0),
                       lambda c:c['Mounts'].clear()):
            target, start = Mock(), Mock();stopped = deepcopy(baseline)
            stopped['State']['Running'] = False;mutate(stopped)
            target.run.return_value = json.dumps([stopped])
            with self.assertRaisesRegex(ValueError, 'restore-old-lifecycle-or-configuration-drift-after-stop'):
                probe.switch_stopped_restore(target, 'old', 'new', lambda fn:fn(), start,
                    {'exactConfigHostMountAndDeclarationMatch':True}, baseline=baseline)
            start.assert_not_called()

    def test_host_sentinel_change_after_business_pass_never_reports_success(self):
        for mode in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                sentinel = Path(directory) / 'sentinel.txt'
                sentinel.write_text('expected\n')
                business_passed = sentinel.read_text() == 'expected\n'
                sentinel.write_text('host-modified-after-business\n')
                sentinel_preserved = sentinel.read_text() == 'expected\n'
            self.assertTrue(business_passed)
            result = {'restoredBusinessProbe': {'health':True,'business':True},
                      'comparison':{'exactConfigHostMountAndDeclarationMatch':True},
                      'sentinelPreserved':sentinel_preserved,'baselineUnchanged':True,
                      'cleanupComplete':True,'unknownWriteResult':False}
            with self.assertRaises(ValueError):probe.complete_restore_validation(result, restore_running=mode)
            self.assertFalse(probe.restore_succeeded(result, restore_running=mode))
            result['sentinelPreserved'] = True
            probe.complete_restore_validation(result, restore_running=mode)
            self.assertTrue(probe.restore_succeeded(result, restore_running=mode))
            result['sentinelPreserved'] = False
            self.assertFalse(probe.restore_succeeded(result, restore_running=mode))
            result['sentinelPreserved'] = True;result['failureType'] = 'ValueError'
            self.assertFalse(probe.restore_succeeded(result, restore_running=mode))

    def test_running_source_restart_identity_is_pinned_but_logs_can_change(self):
        raw = fixture()[0]
        raw.update(State={'Running': True, 'StartedAt': 'fixed', 'Health': {'Status':'healthy','Log':['old']}}, RestartCount=0)
        current = deepcopy(raw);current['State']['Health']['Log'] = ['new']
        probe.verify_running_source(raw, current)
        for mutate in (lambda c:c['State'].update(StartedAt='changed'),
                       lambda c:c.update(RestartCount=1),
                       lambda c:c['State'].update(Running=False),
                       lambda c:c['State']['Health'].update(Status='unhealthy')):
            changed = deepcopy(current); mutate(changed)
            with self.assertRaises(ValueError):probe.verify_running_source(raw, changed)

    def test_health_logs_do_not_change_stable_snapshot(self):
        raw = fixture()[0];raw['State'] = {'Health': {'Log': ['first']}}
        changed = deepcopy(raw);changed['State']['Health']['Log'] = ['later', 'timestamp']
        self.assertEqual(probe.stable_snapshot(raw), probe.stable_snapshot(changed))


if __name__ == '__main__': unittest.main()
