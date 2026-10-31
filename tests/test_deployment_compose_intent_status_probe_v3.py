import os
from pathlib import Path
import shutil
import sys
import subprocess
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import deployment_compose_intent_status_probe as probe


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'), 'POSIX OpenSSH required')
class ProbeTests(unittest.TestCase):
    def test_actual_client_and_signatures_over_owned_process(self):
        result=probe._run([sys.executable,'-I','-u','-c',probe.REMOTE])
        self.assertTrue(result['success'])
        self.assertTrue(result['diagnosticOnly'])
        self.assertFalse(result['authorityGranted'])
        self.assertEqual(result['dockerWrites'],0)
        self.assertEqual(len(result['cases']),7)
        self.assertTrue(result['workerStopped'])
        lag=result['cases'][1]
        self.assertEqual(lag['outcome'],'accepted')
        self.assertGreaterEqual(lag['receiverAfter'],lag['signedIssued'])

    def test_remote_silent_host_has_own_deadline(self):
        code=probe.REMOTE.replace('REMOTE_TIMEOUT=90','REMOTE_TIMEOUT=.2')
        process=subprocess.Popen([sys.executable,'-I','-u','-c',code],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        started=time.monotonic()
        try:
            process.wait(timeout=3)
            self.assertNotEqual(process.returncode,0)
            self.assertIn(b'read-timeout',process.stderr.read())
            self.assertLess(time.monotonic()-started,3)
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=3)
            process.stdin.close();process.stdout.close();process.stderr.close()

    def test_clock_lag_beyond_budget_reports_fixed_case_and_remains_rejected(self):
        code = probe.REMOTE.replace("1 if case=='lag-one-second'", "3 if case=='lag-one-second'")
        self.assertNotEqual(code, probe.REMOTE)
        with self.assertRaisesRegex(ValueError, '^matrix-failed:lag-one-second$'):
            probe._run([sys.executable, '-I', '-u', '-c', code])

    def test_transport_pins_and_alias_rejection(self):
        with patch.object(probe,'_run',return_value={}) as run:
            probe.run_probe('xterminal-server')
        argv=run.call_args.args[0]
        for value in ('StrictHostKeyChecking=yes','ForwardAgent=no','ClearAllForwardings=yes','ServerAliveInterval=15'):
            self.assertIn(value,argv)
        for value in ('-oHost=x','a;b','a b',''):
            with self.assertRaises(ValueError):probe.run_probe(value)
