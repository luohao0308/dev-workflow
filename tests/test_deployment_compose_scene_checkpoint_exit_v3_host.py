"""Original scene producer exits before a separate signed-history reader starts."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/support/compose_scene_checkpoint_exit_fixture.py'


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX/OpenSSL/OpenSSH required')
class SceneCheckpointExitTests(unittest.TestCase):
    def test_exited_producer_then_new_consumer_reauthenticates_original_checkpoint(self):
        with tempfile.TemporaryDirectory(prefix='scene-checkpoint-exit-') as directory:
            producer = subprocess.run([sys.executable, str(FIXTURE), 'produce', directory],
                                      capture_output=True, text=True, timeout=120)
            self.assertEqual(producer.returncode, 0, producer.stderr)
            original = json.loads(producer.stdout)
            self.assertEqual(original['postCount'], 1)
            # subprocess.run has reaped the original producer before this spawn.
            consumer = subprocess.run([sys.executable, str(FIXTURE), 'consume'],
                                      input=json.dumps(original['descriptor']),
                                      capture_output=True, text=True, timeout=60)
            self.assertEqual(consumer.returncode, 0, consumer.stderr)
            result = json.loads(consumer.stdout)
            self.assertNotEqual(result['consumerPid'], original['producerPid'])
            self.assertTrue(result['historyAuthenticated'])
            self.assertTrue(result['witnessUnchanged'])
            self.assertFalse(result['executionRecovered'])
            self.assertFalse(result['writerOriginBound'])
            self.assertFalse(result['sourceArchiveBound'])
