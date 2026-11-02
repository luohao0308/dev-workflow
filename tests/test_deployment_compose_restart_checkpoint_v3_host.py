"""Private checkpoint custody and original-controller cold-read integration."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import pickle
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'packs/deployment/scripts', 'packs/release/scripts'))]
from tests.support.compose_restart_material_fixture import RestartFixture, ARCHIVE_DIGEST, STORE_KEY
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_witness_store import canonical
import deployment_compose_restart_checkpoint_v3_host as checkpoint


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.f = RestartFixture()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.close_create()
        self.case = self.f.root / 'cold-case'
        self.case.mkdir(mode=0o700)
        shutil.copytree(self.f.store.root, self.case / 'witness')
        self.signer = self.case / 'witness-signing'
        shutil.copy2(self.f.key, self.signer)
        self.store = OperationWitnessStoreV3(self.case / 'witness', key=STORE_KEY)
        self.addCleanup(self.store.close)
        self.f.store = self.store
        self.material = self.case / 'restart-material/material.private.json'
        self.custody = self.case / 'restart-custody/keys.private.json'

    def save(self, **changes):
        args = dict(original_history=self.f.history(), baseline_bytes=self.f.baseline_bytes,
            authenticated_image_defaults=self.f.defaults, archive_digest=ARCHIVE_DIGEST,
            witness_store=self.store, witness_signer=self.signer)
        args.update(changes)
        return checkpoint.save_checkpoint(self.case, **args)

    def reader(self, descriptor, case=None, **changes):
        args = dict(expected_material_digest=descriptor['materialDigest'],
            expected_custody_digest=descriptor['custodyDigest'],
            expected_context=descriptor['context'], expected_witness_key_hash=descriptor['witnessKeyHash'])
        args.update(changes)
        return checkpoint.RestartCheckpointReaderV3(self.case if case is None else case, **args)

    def test_pair_round_trip_separates_secrets_and_preserves_witness(self):
        before = (self.case / 'witness/state.json').read_bytes()
        descriptor = self.save()
        self.assertEqual(descriptor['casePath'], str(self.case))
        self.assertEqual(hashlib.sha256(self.material.read_bytes()).hexdigest(), descriptor['materialDigest'])
        self.assertEqual(hashlib.sha256(self.custody.read_bytes()).hexdigest(), descriptor['custodyDigest'])
        for path in (self.material, self.custody):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        keys = json.loads(self.custody.read_bytes())
        self.assertEqual(set(keys), {'schemaVersion', 'kind', 'gateKeyBase64', 'storeKeyBase64'})
        self.assertNotIn(b'gateKeyBase64', self.material.read_bytes())
        self.assertNotIn(b'OPENSSH PRIVATE KEY', self.custody.read_bytes())
        with self.reader(descriptor) as reader:
            result = reader.context
            self.assertEqual(result.snapshot.digest, descriptor['context']['historyDigest'])
            for name in ('authorityGranted', 'runtimePermit', 'recoveryAuthorized', 'productionReady'):
                self.assertIs(getattr(result, name), False)
        with self.assertRaises(ValueError):
            result.history.capture()
        self.assertEqual(before, (self.case / 'witness/state.json').read_bytes())

    def test_duplicate_save_does_not_replace_existing_pair(self):
        descriptor = self.save()
        before = (self.material.read_bytes(), self.custody.read_bytes())
        with self.assertRaises(ValueError):
            self.save()
        self.assertEqual(before, (self.material.read_bytes(), self.custody.read_bytes()))
        with self.reader(descriptor) as reader:
            self.assertTrue(reader.context.historyAuthenticated)

    def test_external_pins_required_and_wrong_pair_keys_rejected_even_when_rehashed(self):
        descriptor = self.save()
        for field in ('expected_material_digest', 'expected_custody_digest', 'expected_witness_key_hash'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.reader(descriptor, **{field: '0' * 64})
        with self.assertRaises(ValueError):
            self.reader(descriptor, expected_context={})
        value = json.loads(self.custody.read_bytes())
        value['gateKeyBase64'] = base64.b64encode(b'wrong-key' * 4).decode('ascii')
        raw = canonical(value)
        self.custody.write_bytes(raw)
        with self.assertRaises(ValueError):
            self.reader(descriptor, expected_custody_digest=hashlib.sha256(raw).hexdigest())

    def test_context_pin_is_frozen_before_file_callbacks(self):
        descriptor = self.save()
        pins = dict(descriptor['context'], sourceSha='0' * 40)
        original = checkpoint.read_file
        calls = []
        def mutate(*args, **kwargs):
            pins.update(descriptor['context'])
            calls.append(True)
            return original(*args, **kwargs)
        with patch.object(checkpoint, 'read_file', side_effect=mutate), self.assertRaises(ValueError):
            self.reader(descriptor, expected_context=pins)
        self.assertTrue(calls)

    def test_save_rejects_wrong_signer_or_store_before_publication(self):
        replacement = self.case / 'other-signing'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(replacement)],
                       check=True, capture_output=True, timeout=10)
        self.signer.write_bytes(replacement.read_bytes())
        with self.assertRaises(ValueError):
            self.save()
        self.assertFalse(self.material.exists())
        self.assertFalse(self.custody.exists())

    def test_partial_publication_and_directory_fsync_failure_return_no_descriptor(self):
        original = checkpoint.os.link
        def fail_second(source, destination, *args, **kwargs):
            if str(destination) == 'keys.private.json':
                raise OSError('simulated custody publication failure')
            return original(source, destination, *args, **kwargs)
        with patch.object(checkpoint.os, 'link', side_effect=fail_second), self.assertRaises(ValueError):
            self.save()
        self.assertTrue(self.material.exists())
        self.assertFalse(self.custody.exists())
        descriptor = dict(materialDigest=hashlib.sha256(self.material.read_bytes()).hexdigest(),
            custodyDigest='0' * 64, context=self.f.expected_context(),
            witnessKeyHash=self.f.client.key_hash)
        with self.assertRaises(ValueError):
            self.reader(descriptor)
        with self.assertRaises(ValueError):
            self.save()

    def test_directory_fsync_failure_is_not_success(self):
        original = checkpoint.os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('simulated directory sync failure')
            return original(fd)
        with patch.object(checkpoint.os, 'fsync', side_effect=fail_directory), self.assertRaises(ValueError):
            self.save()

    def test_modes_hardlinks_and_symlinks_are_rejected(self):
        descriptor = self.save()
        for directory in (self.case, self.material.parent, self.custody.parent):
            directory.chmod(0o755)
            try:
                with self.assertRaises(ValueError):
                    self.reader(descriptor)
            finally:
                directory.chmod(0o700)
        for path in (self.material, self.custody, self.signer):
            with self.subTest(mode=path.name):
                path.chmod(0o644)
                with self.assertRaises(ValueError):
                    self.reader(descriptor)
                path.chmod(0o600)
            alias = self.case / ('alias-' + path.name)
            os.link(path, alias)
            try:
                with self.assertRaises(ValueError):
                    self.reader(descriptor)
            finally:
                alias.unlink()
        alias = self.f.root / 'case-alias'
        alias.symlink_to(self.case, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.reader(descriptor, case=alias)
        original = self.material.read_bytes()
        self.material.unlink()
        destination = self.case / 'material-copy'
        destination.write_bytes(original)
        destination.chmod(0o600)
        self.material.symlink_to(destination)
        with self.assertRaises(ValueError):
            self.reader(descriptor)

    def test_replacement_or_state_advance_invalidates_live_reader(self):
        descriptor = self.save()
        with self.reader(descriptor) as reader:
            context = reader.context
            parent = self.material.parent
            parent.rename(parent.with_name('old-material'))
            parent.mkdir(mode=0o700)
            shutil.copy2(parent.with_name('old-material') / self.material.name, self.material)
            with self.assertRaises(ValueError):
                context.history.capture()

    def test_advanced_original_witness_rejects_old_checkpoint(self):
        descriptor = self.save()
        self.f.receipts = {'web': 'a' * 64}
        self.f.index = 1
        self.f.open_scope()
        before = (self.case / 'witness/state.json').read_bytes()
        with self.assertRaises(ValueError):
            self.reader(descriptor)
        self.assertEqual(before, (self.case / 'witness/state.json').read_bytes())

    def test_missing_lock_is_not_created_or_repaired(self):
        descriptor = self.save()
        lock = self.case / 'witness/witness.lock'
        lock.unlink()
        with self.assertRaises(ValueError):
            OperationWitnessStoreV3(self.case / 'witness', key=STORE_KEY, create_lock=False)
        with self.assertRaises(ValueError):
            self.reader(descriptor)
        self.assertFalse(lock.exists())

    def test_copy_foreign_thread_and_fork_cannot_close_original_reader(self):
        descriptor = self.save()
        reader = self.reader(descriptor)
        self.addCleanup(reader.close)
        try:
            duplicate = copy.copy(reader)
        except (TypeError, ValueError):
            duplicate = None
        if duplicate is not None:
            with self.assertRaises(ValueError):
                duplicate.close()
        with self.assertRaises(ValueError):
            copy.deepcopy(reader)
        with self.assertRaises(ValueError):
            pickle.dumps(reader)
        rejected = []
        def foreign():
            try:
                reader.close()
            except ValueError:
                rejected.append(True)
        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(rejected, [True])
        if hasattr(os, 'fork'):
            pid = os.fork()
            if pid == 0:
                try:
                    reader.close()
                except ValueError:
                    os._exit(0)
                except BaseException:
                    os._exit(2)
                os._exit(1)
            waited, status = os.waitpid(pid, 0)
            self.assertEqual(waited, pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
        self.assertTrue(reader.context.historyAuthenticated)

    def test_caller_primary_survives_reader_close_failure(self):
        reader = self.reader(self.save())
        self.addCleanup(reader.close)
        with patch.object(reader, 'close', side_effect=ValueError('secondary-close')):
            with self.assertRaisesRegex(RuntimeError, 'primary-caller'):
                with reader:
                    raise RuntimeError('primary-caller')


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX/OpenSSL/OpenSSH required')
class ControllerCheckpointTests(unittest.TestCase):
    def test_raw_popen_rejects_checkpoint_callback_before_any_case_creation(self):
        import deployment_compose_owned_recovery_controller_v3_host as controller
        with tempfile.TemporaryDirectory(prefix='dw-raw-checkpoint-reject-') as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with self.assertRaises(ValueError):
                controller._drive_recovery_protocol(root, process=process, channel_nonce='1' * 64,
                    source_sha='b' * 40, archive_digest='2' * 64, host_id='host-one',
                    normalization_version={'Version': '29.8.2', 'GitCommit': '8af9fe3'},
                    review=object(), on_review=lambda value: None, trusted_boot_id='4' * 32,
                    trusted_bind_digest=None, expected_root='/var/tmp/dw-engine-' + '1' * 16,
                    expected_daemon_id='daemon-one', expected_project='dw-restore-' + '3' * 24,
                    _restart_checkpoint=lambda value: None, timeout=20)
            self.assertIsNotNone(process.poll())
            self.assertFalse(list(root.iterdir()))

    def test_original_controller_delivers_pins_before_refused_second_review_then_process_exits(self):
        with tempfile.TemporaryDirectory(prefix='dw-controller-checkpoint-') as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            script = ROOT / 'tests/support/compose_restart_checkpoint_fixture.py'
            producer = subprocess.run([sys.executable, str(script), 'produce', str(root)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(producer.returncode, 0, producer.stderr)
            result = json.loads(producer.stdout)
            self.assertEqual(result['reviewedOperations'], ['deploy'])
            self.assertEqual(result['secondConsumptionCount'], 0)
            self.assertTrue(result['controllerCleanupVerified'])
            consumer = subprocess.run([sys.executable, str(script), 'consume'],
                input=json.dumps(result['descriptor']), capture_output=True, text=True, timeout=60)
            self.assertEqual(consumer.returncode, 0, consumer.stderr)
            cold = json.loads(consumer.stdout)
            self.assertNotEqual(result['producerPid'], cold['consumerPid'])
            self.assertTrue(cold['witnessUnchanged'])
            self.assertTrue(cold['historicalTransportClosed'])
            self.assertFalse(cold['executionRecovered'])
            self.assertEqual(cold['newApprovalConsumptions'], 0)

    def test_callback_failure_prevents_even_second_review(self):
        from tests.support.compose_restart_checkpoint_fixture import produce
        with tempfile.TemporaryDirectory(prefix='dw-checkpoint-callback-') as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            result = produce(root, fail_callback=True)
            self.assertEqual(result['secondReviewCalls'], 0)
            self.assertEqual(result['secondConsumptionCount'], 0)
            self.assertTrue(result['controllerCleanupVerified'])

    def test_save_failure_prevents_second_review_and_preserves_cleanup(self):
        from tests.test_deployment_compose_owned_recovery_session_v3_host import SessionTests
        from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase
        from types import SimpleNamespace
        import deployment_compose_owned_recovery_controller_v3_host as controller
        harness = SessionTests('test_full_managed_flow_checks_independent_history_and_manager_completion')
        session = harness.open()
        self.addCleanup(harness.doCleanups)
        owner = SimpleNamespace(reviewed=[])
        base = LocalAcceptanceCase.review_adapter(owner)
        class Review:
            def consume_prepared(self, *args):
                return base.consume_prepared(*args)
            def close(self):
                pass
        notices = []
        with patch.object(checkpoint, 'save_checkpoint', side_effect=OSError('checkpoint-write-failed')):
            with self.assertRaisesRegex(OSError, 'checkpoint-write-failed'):
                controller._drive_managed_recovery_protocol(harness.root, session=session,
                    review=Review(), on_review=lambda value: None,
                    on_restart_checkpoint=notices.append, timeout=100)
        self.assertEqual([request.operation for request in owner.reviewed], ['deploy'])
        self.assertEqual(notices, [])
        self.assertTrue(session.cleanup_report()['localProcessReaped'])

    def test_default_path_does_not_save_keys_and_diagnostic_rejects_callback(self):
        from tests.test_deployment_compose_owned_recovery_session_v3_host import SessionTests
        import deployment_compose_owned_recovery_controller_v3_host as controller
        normal = SessionTests('test_full_managed_flow_checks_independent_history_and_manager_completion')
        self.addCleanup(normal.doCleanups)
        with patch.object(checkpoint, 'save_checkpoint', side_effect=AssertionError('not opted in')):
            result = normal.drive()
        self.assertNotIn('restartCheckpoint', result)
        self.assertFalse(list(normal.root.rglob('keys.private.json')))
        diagnostic = SessionTests('test_diagnostic_business_and_second_consumption_are_blocked')
        session = diagnostic.open(diagnostic=True)
        self.addCleanup(diagnostic.doCleanups)
        with patch.object(session, 'begin', side_effect=AssertionError('started diagnostic')):
            with self.assertRaises(ValueError):
                controller._drive_managed_recovery_protocol(diagnostic.root, session=session,
                    review=object(), on_review=lambda value: None,
                    on_restart_checkpoint=lambda value: None)
        self.assertFalse(list(diagnostic.root.rglob('keys.private.json')))

    def test_opted_full_flow_keeps_callback_copy_separate_and_old_checkpoint_becomes_stale(self):
        from tests.test_deployment_compose_owned_recovery_session_v3_host import SessionTests
        from tests.test_deployment_compose_live_controller_flow_v3_host import LocalAcceptanceCase
        from types import SimpleNamespace
        import deployment_compose_owned_recovery_controller_v3_host as controller
        harness = SessionTests('test_full_managed_flow_checks_independent_history_and_manager_completion')
        session = harness.open(verify_daemon=True, verify_resources=True, verify_host=True)
        self.addCleanup(harness.doCleanups)
        owner = SimpleNamespace(reviewed=[])
        base = LocalAcceptanceCase.review_adapter(owner)
        delivered = []
        def notice(descriptor):
            delivered.append(copy.deepcopy(descriptor))
            descriptor['materialDigest'] = '0' * 64
        result = controller._drive_managed_recovery_protocol(harness.root, session=session,
            review=base, on_review=lambda value: None, on_restart_checkpoint=notice, timeout=100)
        self.assertEqual([request.operation for request in owner.reviewed], ['deploy', 'recovery'])
        self.assertEqual(result['restartCheckpoint'], delivered[0])
        self.assertTrue(result['historyCompleted'])
        self.assertIn('completionCertificateDigest', result)
        descriptor = delivered[0]
        with self.assertRaises(ValueError):
            checkpoint.RestartCheckpointReaderV3(Path(descriptor['casePath']),
                expected_material_digest=descriptor['materialDigest'],
                expected_custody_digest=descriptor['custodyDigest'],
                expected_context=descriptor['context'], expected_witness_key_hash=descriptor['witnessKeyHash'])


if __name__ == '__main__':
    unittest.main()
