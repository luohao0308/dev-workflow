"""Scene-bound native checkpoint cold reads, tamper rejection and resource ownership."""
import base64
from copy import copy, deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_checkpoint_source_v3_host as source_fixture
from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3, _arguments
from deployment_compose_witness_store import canonical

FIXTURE = Path(__file__).resolve().parent / 'support/compose_scene_binding_exit_fixture.py'


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX/OpenSSL/OpenSSH required')
class SceneSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = source_fixture.GitArchiveTests()
        cls.source.setUp()
        cls.temporary = tempfile.TemporaryDirectory(prefix='scene-binding-security-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.addClassCleanup(cls.source.doCleanups)
        parent = Path(cls.temporary.name).resolve()
        archive = parent / 'input.private.zip'
        archive.write_bytes(cls.source.raw); archive.chmod(0o600)
        produced = subprocess.run([sys.executable, str(FIXTURE), 'produce', str(parent),
            str(cls.source.repo), cls.source.sha, str(archive)], capture_output=True, text=True, timeout=180)
        if produced.returncode:
            raise AssertionError(produced.stderr)
        cls.produced = json.loads(produced.stdout)
        cls.descriptor = cls.produced['descriptor']
        cls.case = Path(cls.descriptor['casePath'])
        cls.binding = cls.case / 'scene-checkpoint/binding.private.json'
        cls.archive = cls.case / 'scene-checkpoint/archive.private.zip'

    def reader(self, **changes):
        options = _arguments(self.descriptor); options.update(changes)
        return SceneCheckpointReaderV3(self.case, **options)

    def sign(self, artifact, namespace='dev-workflow-scene-checkpoint-v3'):
        signed = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f',
            str(self.case / 'intent-signing'), '-n', namespace], input=canonical(artifact['payload']),
            capture_output=True, check=True, timeout=10)
        artifact['signature'] = base64.b64encode(signed.stdout).decode('ascii')
        return canonical(artifact)

    def test_original_producer_exits_before_new_consumer_and_native_git_recheck(self):
        self.assertEqual(self.produced['postCount'], 1)
        self.assertLessEqual(self.produced['unixFrameBytes'], 8192)
        self.assertLessEqual(self.produced['sshFrameBytes'], 8192)
        consumer = subprocess.run([sys.executable, str(FIXTURE), 'consume'],
            input=json.dumps(self.produced), capture_output=True, text=True, timeout=120)
        self.assertEqual(consumer.returncode, 0, consumer.stderr)
        result = json.loads(consumer.stdout)
        self.assertNotEqual(result['consumerPid'], self.produced['producerPid'])
        self.assertTrue(result['writerOriginBound'])
        self.assertTrue(result['sourceArchiveBound'])
        self.assertTrue(result['gitObjectContentsVerified'])
        self.assertFalse(result['executionRecovered'])

    def test_wrong_external_pins_and_rehashed_forged_origin_reject(self):
        for field in ('expected_scene_binding_digest', 'expected_intent_key_hash', 'expected_material_digest'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.reader(**{field: '0' * 64})
        original = self.binding.read_bytes()
        try:
            forged = json.loads(original)
            forged['payload']['evidence']['writerOrigin']['mainStartTicks'] += 1
            raw = canonical(forged); self.binding.write_bytes(raw)
            with self.assertRaises(ValueError):
                self.reader(expected_scene_binding_digest=hashlib.sha256(raw).hexdigest())
        finally:
            self.binding.write_bytes(original)

    def test_resigned_cross_context_and_wrong_namespace_reject(self):
        original = self.binding.read_bytes()
        try:
            for mutation in ('material', 'hello', 'origin', 'namespace'):
                with self.subTest(mutation=mutation):
                    artifact = json.loads(original)
                    if mutation == 'material': artifact['payload']['materialDigest'] = '0' * 64
                    if mutation == 'hello': artifact['payload']['hello']['hostId'] = 'other-host'
                    if mutation == 'origin': artifact['payload']['evidence']['writerOrigin']['sourceSha'] = '0' * 40
                    raw = self.sign(artifact, 'other-namespace' if mutation == 'namespace'
                                    else 'dev-workflow-scene-checkpoint-v3')
                    self.binding.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        self.reader(expected_scene_binding_digest=hashlib.sha256(raw).hexdigest())
        finally:
            self.binding.write_bytes(original)

    def test_archive_permissions_content_and_extra_members_reject(self):
        original = self.archive.read_bytes()
        try:
            self.archive.chmod(0o644)
            with self.assertRaises(ValueError): self.reader()
            self.archive.chmod(0o600); self.archive.write_bytes(b'changed ZIP')
            with self.assertRaises(ValueError): self.reader()
            self.archive.write_bytes(original)
            extra = self.archive.parent / 'unexpected'
            extra.write_bytes(b'extra'); extra.chmod(0o600)
            try:
                with self.assertRaises(ValueError): self.reader()
            finally:
                extra.unlink()
        finally:
            self.archive.chmod(0o600); self.archive.write_bytes(original)

    def test_copy_thread_and_fork_cannot_read_or_close_original(self):
        with self.reader() as reader:
            with self.assertRaises(ValueError): copy(reader)
            forged = object.__new__(SceneCheckpointReaderV3)
            forged.__dict__.update(reader.__dict__)
            with self.assertRaises(ValueError): forged.read_source_archive()
            with self.assertRaises(ValueError): forged.close()
            failures = []
            def foreign():
                for action in (reader.read_source_archive, reader.close):
                    try: action()
                    except ValueError: failures.append(True)
            thread = threading.Thread(target=foreign); thread.start(); thread.join(timeout=10)
            self.assertFalse(thread.is_alive()); self.assertEqual(failures, [True, True])
            pid = os.fork()
            if pid == 0:
                try:
                    reader.read_source_archive()
                except ValueError:
                    os._exit(0)
                os._exit(1)
            self.assertEqual(os.waitpid(pid, 0)[1], 0)
            self.assertEqual(reader.read_source_archive(), self.source.raw)
        with self.assertRaises(ValueError): reader.read_source_archive()

    def test_enter_failure_closes_original_descriptors(self):
        reader = self.reader()
        original = self.archive.read_bytes()
        guard = reader._reader._guard
        fds = [value[0] for value in guard.dirs.values()]
        fds.extend((reader._reader._store._dir, reader._reader._store._lock))
        try:
            self.archive.write_bytes(b'tampered after construction')
            with self.assertRaises(ValueError):
                with reader:
                    self.fail('tampered enter accepted')
            self.assertTrue(reader._closed)
            for fd in fds:
                with self.assertRaises(OSError): os.fstat(fd)
        finally:
            self.archive.write_bytes(original)

    def test_partial_publication_cannot_notify_or_redispatch(self):
        from tests.support.compose_scene_create_integration_fixture import run_case
        import deployment_compose_scene_checkpoint_v3_host as custody
        import deployment_compose_scene_create_broker_v3_host as broker
        original_publish = custody.publish
        original_start = broker.SceneCreateBrokerV3.start_first_create
        notifications, dispatches, partial = [], [], []
        def publish(fd, name, raw):
            if name == 'archive.private.zip':
                partial.append(set(os.listdir(fd)))
                raise OSError('test partial publication')
            return original_publish(fd, name, raw)
        def start(subject, *args, **kwargs):
            result = original_start(subject, *args, **kwargs)
            dispatches.append(True)
            return result
        with patch.object(custody, 'publish', publish), \
                patch.object(broker.SceneCreateBrokerV3, 'start_first_create', start):
            with self.assertRaises(ValueError):
                run_case(self, scene_controller=True, scene_callback=notifications.append,
                    published_source=(self.source.sha, self.source.raw, self.source.repo))
        self.assertEqual(notifications, [])
        self.assertEqual(dispatches, [True])
        self.assertEqual(partial, [{'binding.private.json'}])
