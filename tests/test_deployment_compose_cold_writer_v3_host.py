"""Cold writer observations; unit filesystem/systemd doubles except opt-in kernel test."""
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'packs/deployment/scripts', 'packs/release/scripts'))]
from tests import test_deployment_compose_owned_recovery_unit_v3_host as fixture
import deployment_compose_owned_recovery_unit_v3_host as units
import deployment_compose_cold_writer_v3_host as cold
from deployment_compose_witness_store import canonical

BOOT = '11111111-1111-1111-1111-111111111111'


@unittest.skipUnless(os.name == 'posix', 'POSIX cgroup directory descriptors')
class ColdWriterTests(unittest.TestCase):
    def setUp(self):
        self.h = fixture.UnitTests('test_start_handoff_fixed_command_and_stop_are_distinct_from_workload_success')
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        units._boot.return_value = BOOT
        self.h.owner._boot_id = BOOT
        self.proc = self.h.root / 'proc'
        (self.proc / 'self/ns').mkdir(parents=True)
        self.self_stat = self.proc / 'self/stat'
        self.self_stat.write_text(self.stat_line(os.getpid()))
        (self.proc / 'self/ns/pid').write_text('namespace identity fixture')
        (self.proc / '1/ns').mkdir(parents=True)
        (self.proc / '1/ns/pid').symlink_to(self.proc / 'self/ns/pid')
        patcher = patch.object(cold, 'PROC', self.proc)
        patcher.start()
        self.addCleanup(patcher.stop)
        def command(argv, **kwargs):
            result = self.h.command(argv, **kwargs)
            result.stderr = b''
            return result
        units.subprocess.run.side_effect = command

    @staticmethod
    def stat_line(pid, ticks=123):
        return str(pid) + ' (fixture) ' + ' '.join(['S'] + ['0'] * 18 + [str(ticks)]) + '\n'

    def origin(self):
        self.h.owner.start()
        self.pid_dir = self.proc / str(self.h.process.pid)
        self.pid_dir.mkdir()
        (self.pid_dir / 'stat').write_text(self.stat_line(self.h.process.pid))
        (self.pid_dir / 'ns').mkdir()
        (self.pid_dir / 'ns/pid').symlink_to(self.proc / 'self/ns/pid')
        return self.h.owner.capture_origin()

    def stop(self):
        self.h.owner.stop()
        (self.h.group / 'cgroup.procs').write_text('')
        shutil.rmtree(self.pid_dir)

    def observe(self, raw, **changes):
        options = dict(expected_digest=hashlib.sha256(raw).hexdigest(),
            expected_source_sha='c' * 40, expected_archive_digest='b' * 64)
        options.update(changes)
        return cold.observe_stopped_writer(raw, **options)

    def empty_group(self, path, *, populated=0, procs=''):
        path.mkdir()
        (path / 'cgroup.type').write_text('domain\n')
        (path / 'cgroup.events').write_text('populated ' + str(populated) + '\nfrozen 0\n')
        (path / 'cgroup.procs').write_text(procs)

    def test_capture_requires_live_certain_original_identity(self):
        with self.assertRaises(ValueError):
            self.h.owner.capture_origin()
        raw = self.origin()
        value = json.loads(raw)
        self.assertEqual(value['mainPid'], self.h.process.pid)
        self.assertEqual(value['mainStartTicks'], 123)
        self.assertEqual(value['parentInode'], (self.h.root / 'system.slice').stat().st_ino)
        self.assertEqual(value['pidNamespaceInode'], (self.proc / 'self/ns/pid').stat().st_ino)
        self.h.owner.creation_outcome_unknown = True
        with self.assertRaises(ValueError):
            self.h.owner.capture_origin()
        self.h.owner.creation_outcome_unknown = False
        self.stop()
        with self.assertRaises(ValueError):
            self.h.owner.capture_origin()

    def test_empty_bound_group_or_collected_group_proves_only_original_writer_stop(self):
        raw = self.origin()
        with self.assertRaises(ValueError):
            self.observe(raw)
        self.stop()
        before = len(self.h.stops())
        result = self.observe(raw)
        self.assertTrue(result.writerStoppedObserved)
        for name in ('daemonStoppedVerified', 'historyFreshnessVerified', 'linuxQuiescenceVerified',
                     'authorityGranted', 'runtimePermit', 'recoveryAuthorized', 'productionReady'):
            self.assertIs(getattr(result, name), False)
            self.assertIs(result.public_summary()[name], False)
        with self.assertRaises(FrozenInstanceError):
            result.runtimePermit = True
        self.assertNotIn('observations', repr(result))
        self.assertEqual(len(self.h.stops()), before)
        self.empty_group(self.h.group / 'empty-child')
        self.assertTrue(self.observe(raw).writerStoppedObserved)
        shutil.rmtree(self.h.group)
        self.h.phase = 'absent'
        self.assertTrue(self.observe(raw).writerStoppedObserved)

    def test_hash_context_and_closed_origin_schema_rejected_before_manager_read(self):
        raw = self.origin()
        self.stop()
        for options in (dict(expected_digest='0' * 64), dict(expected_source_sha='0' * 40),
                        dict(expected_archive_digest='0' * 64), dict(expected_source_sha=True)):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.observe(raw, **options)
        value = json.loads(raw)
        variants = [b'', raw + b' ', b'{"x":1,"x":2}', b'NaN', b'x' * (cold.MAX_ORIGIN + 1),
                    canonical(dict(value, mainPid=True)), canonical(dict(value, extra=True)),
                    canonical(dict(value, unit='sshd.service')), canonical(dict(value, schemaVersion=True))]
        before = len(self.h.calls)
        for candidate in variants:
            with self.subTest(size=len(candidate)), self.assertRaises(ValueError):
                self.observe(candidate)  # Rehash the outer pin to reach inner checks.
        self.assertEqual(len(self.h.calls), before)

    def test_pid_reuse_zombie_or_any_original_pid_presence_never_counts_as_gone(self):
        raw = self.origin()
        self.stop()
        self.pid_dir.mkdir()
        for ticks, state in ((123, 'S'), (999, 'S'), (123, 'Z')):
            (self.pid_dir / 'stat').write_text(self.stat_line(self.h.process.pid, ticks).replace(' S ', ' ' + state + ' '))
            with self.subTest(ticks=ticks, state=state), self.assertRaises(ValueError):
                self.observe(raw)

    def test_namespace_and_proc_self_view_mismatch_rejected(self):
        raw = self.origin()
        self.stop()
        value = json.loads(raw)
        with self.assertRaises(ValueError):
            self.observe(canonical(dict(value, pidNamespaceInode=value['pidNamespaceInode'] + 1)))
        self.self_stat.write_text(self.stat_line(os.getpid() + 1))
        with self.assertRaises(ValueError):
            self.observe(raw)

    def test_equal_numeric_self_pid_does_not_accept_other_proc_mount_namespace(self):
        raw = self.origin()
        self.stop()
        namespace = self.proc / '1/ns/pid'
        namespace.unlink()
        namespace.write_text('different procfs PID namespace')
        self.assertEqual(self.self_stat.read_text().split()[0], str(os.getpid()))
        with self.assertRaises(ValueError):
            self.observe(raw)

    def test_original_writer_namespace_must_match_observer(self):
        self.origin()
        namespace = self.pid_dir / 'ns/pid'
        namespace.unlink()
        namespace.write_text('different writer namespace')
        with self.assertRaises(ValueError):
            self.h.owner.capture_origin()

    def test_boot_invocation_and_inconsistent_substate_rejected(self):
        raw = self.origin()
        self.stop()
        units._boot.return_value = '22222222-2222-2222-2222-222222222222'
        with self.assertRaises(ValueError):
            self.observe(raw)
        units._boot.return_value = BOOT
        self.h.invocation = 'd' * 32
        with self.assertRaises(ValueError):
            self.observe(raw)
        self.h.invocation = 'a' * 32
        original = self.h.state
        def running_substate():
            return dict(original(), SubState='running')
        with patch.object(self.h, 'state', side_effect=running_substate), self.assertRaises(ValueError):
            self.observe(raw)

    def test_parent_or_group_replacement_cannot_be_treated_as_absence(self):
        raw = self.origin()
        self.stop()
        self.h.group.rename(self.h.group.with_suffix('.old'))
        self.empty_group(self.h.group)
        with self.assertRaises(ValueError):
            self.observe(raw)
        shutil.rmtree(self.h.group)
        parent = self.h.root / 'system.slice'
        parent.rename(self.h.root / 'old-system.slice')
        parent.mkdir()
        with self.assertRaises(ValueError):
            self.observe(raw)

    def test_remaining_descendants_and_symlinks_rejected(self):
        raw = self.origin()
        self.stop()
        child = self.h.group / 'remaining'
        self.empty_group(child, populated=1, procs='123\n')
        with self.assertRaises(ValueError):
            self.observe(raw)
        shutil.rmtree(child)
        child.symlink_to(self.h.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.observe(raw)

    def test_observations_must_be_stable_and_late_pid_or_namespace_change_rejects(self):
        raw = self.origin()
        self.stop()
        original = cold._tree
        calls = []
        def change_pid(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(True)
            if len(calls) == 2:
                self.pid_dir.mkdir()
            return result
        with patch.object(cold, '_tree', side_effect=change_pid), self.assertRaises(ValueError):
            self.observe(raw)
        self.assertEqual(len(calls), 2)
        self.pid_dir.rmdir()
        calls.clear()
        def change_namespace(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(True)
            if len(calls) == 2:
                path = self.proc / 'self/ns/pid'
                path.rename(path.with_name('old-pid-namespace'))
                path.write_text('new namespace inode')
            return result
        with patch.object(cold, '_tree', side_effect=change_namespace), self.assertRaises(ValueError):
            self.observe(raw)

    def test_permission_and_parser_errors_are_not_absence(self):
        raw = self.origin()
        self.stop()
        original = cold.os.stat
        def denied(path, *args, **kwargs):
            if Path(path) == self.pid_dir:
                raise PermissionError('fixture process view denied')
            return original(path, *args, **kwargs)
        with patch.object(cold.os, 'stat', side_effect=denied), self.assertRaises(ValueError):
            self.observe(raw)
        self.h.duplicate = True
        with self.assertRaises(ValueError):
            self.observe(raw)

    def test_deadline_and_invalid_timeouts_do_not_become_stop_success(self):
        raw = self.origin()
        self.stop()
        for timeout in (True, 0, -1, float('inf'), float('nan'), 31):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.observe(raw, timeout=timeout)
        clock = SimpleNamespace(monotonic=Mock(side_effect=[100, 100, 111]))
        with patch.object(cold, 'time', clock), self.assertRaises(ValueError):
            self.observe(raw, timeout=1)

    def test_capture_revalidates_invocation_pid_and_namespace(self):
        self.origin()
        self.h.reuse_pid = True
        with self.assertRaises(ValueError):
            self.h.owner.capture_origin()
        self.h.reuse_pid = False
        self.h.invocation = 'd' * 32
        with self.assertRaises(ValueError):
            self.h.owner.capture_origin()
        self.h.invocation = 'a' * 32
        self.self_stat.write_text(self.stat_line(os.getpid() + 1))
        with self.assertRaises(ValueError):
            self.h.owner.capture_origin()


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0
    and os.environ.get('DEV_WORKFLOW_TEST_COLD_WRITER_STOP') == '1',
    'explicit dedicated Linux/root systemd/cgroup test host required')
class KernelColdWriterTests(unittest.TestCase):
    def test_original_loader_stops_before_new_process_observes(self):
        with tempfile.TemporaryDirectory(prefix='dw-cold-writer-kernel-') as directory:
            root = Path(directory).resolve()
            script = ROOT / 'tests/support/compose_cold_writer_fixture.py'
            producer = subprocess.run([sys.executable, str(script), 'produce', str(root)],
                capture_output=True, text=True, timeout=80)
            self.assertEqual(producer.returncode, 0, producer.stderr)
            pins = json.loads(producer.stdout)
            self.assertFalse(pins['archiveOrConfigSent'])
            consumer = subprocess.run([sys.executable, str(script), 'consume'],
                input=json.dumps(pins), capture_output=True, text=True, timeout=40)
            self.assertEqual(consumer.returncode, 0, consumer.stderr)
            result = json.loads(consumer.stdout)
            self.assertNotEqual(pins['producerPid'], result['consumerPid'])
            self.assertTrue(result['summary']['writerStoppedObserved'])
            self.assertFalse(result['summary']['authorityGranted'])
            self.assertFalse(result['engineStarted'])
            self.assertFalse(result['executionRecovered'])


if __name__ == '__main__':
    unittest.main()
