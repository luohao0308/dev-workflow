"""Execute only a toy archive loader; never run the real recovery worker."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_owned_recovery_ssh_v3_host as recovery


class LoaderTests(unittest.TestCase):
    def archive(self, extra=None):
        output = io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:
            archive.writestr(recovery.WORKER,
                "def run(config, stdin, stdout):\n"
                " import json\n"
                " stdout.write(json.dumps({'entrypoint':config['entrypoint']}).encode()); stdout.flush()\n")
            archive.writestr('scripts/deployment_compose_v3_channel_worker.py',
                "def write_frame(*args,**kwargs):raise AssertionError('unused result frame')\n")
            if extra:archive.writestr(*extra)
        return output.getvalue()

    def test_fixed_entry_and_strict_argv(self):
        argv = recovery.ssh_argv('linux-test','a'*64,'b'*40)
        self.assertEqual(argv[:-1],recovery.live.ssh_argv('linux-test','a'*64,'b'*40)[:-1])
        command = shlex.split(argv[-1])
        self.assertEqual(command[:5],['exec','python3','-I','-u','-c'])
        code = command[5]
        compile(code,'<recovery-loader>','exec')
        self.assertIn(recovery.ENTRYPOINT,code)
        self.assertNotIn('deployment_compose_live_worker_v3_host',code)
        for alias in ('-oProxyCommand=x','host; echo secret','host x',''):
            with self.assertRaises(ValueError):recovery.ssh_argv(alias,'a'*64,'b'*40)

    def test_malformed_pins_reject_before_command_construction(self):
        for value in (None,True,1,'','A'*64,'a'*63,'a'*65,'a'*64+';id'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):recovery.ssh_argv('host',value,'b'*40)
        for value in (None,True,'','B'*40,'b'*39,'b'*41):
            with self.assertRaises(ValueError):recovery.recovery_bootstrap('a'*64,value)

    def test_archive_retains_original_source_check_and_requires_worker(self):
        raw = self.archive()
        with patch.object(recovery.live,'published_live_archive',return_value=raw) as fetch:
            self.assertEqual(recovery.published_recovery_archive('b'*40),raw)
            fetch.assert_called_once_with('b'*40)
        output = io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:archive.writestr('scripts/other.py','')
        with patch.object(recovery.live,'published_live_archive',return_value=output.getvalue()):
            with self.assertRaises(ValueError):recovery.published_recovery_archive('b'*40)
        with patch.object(recovery.live,'published_live_archive',side_effect=ValueError('source-rejected')):
            with self.assertRaisesRegex(ValueError,'source-rejected'):recovery.published_recovery_archive('b'*40)

    def test_manager_loader_has_fixed_entry_and_rejects_template_drift(self):
        argv=recovery.manager_ssh_argv('linux-test','a'*64,'b'*40)
        self.assertEqual(argv[:-1],recovery.ssh_argv('linux-test','a'*64,'b'*40)[:-1])
        code=shlex.split(argv[-1])[-1]
        compile(code,'<manager-loader>','exec')
        self.assertIn(recovery.MANAGER_ENTRYPOINT,code)
        self.assertIn('run(config,sys.stdin.buffer,sys.stdout.buffer,archive)',code)
        self.assertNotIn('deployment_compose_owned_recovery_worker_v3_host',code)
        with patch.object(recovery.live,'live_bootstrap',return_value='changed-template'):
            with self.assertRaises(ValueError):recovery.manager_bootstrap('a'*64,'b'*40)

    def test_manager_archive_requires_manager_unit_and_daemon_observer(self):
        for names in ([],['scripts/deployment_compose_owned_recovery_manager_v3_host.py'],
                ['scripts/deployment_compose_owned_recovery_manager_v3_host.py',
                 'scripts/deployment_compose_owned_recovery_unit_v3_host.py'],
                ['scripts/deployment_compose_owned_recovery_manager_v3_host.py',
                 'scripts/deployment_compose_owned_recovery_unit_v3_host.py',
                 'scripts/deployment_compose_recovery_daemon_v3_host.py'],
                ['scripts/deployment_compose_owned_recovery_manager_v3_host.py',
                 'scripts/deployment_compose_owned_recovery_unit_v3_host.py',
                 'scripts/deployment_compose_recovery_daemon_v3_host.py',
                 'scripts/deployment_compose_resource_inventory_v3_host.py'],
                ['scripts/deployment_compose_owned_recovery_manager_v3_host.py',
                 'scripts/deployment_compose_owned_recovery_unit_v3_host.py',
                 'scripts/deployment_compose_recovery_daemon_v3_host.py',
                 'scripts/deployment_compose_resource_inventory_v3_host.py',
                 'scripts/deployment_compose_host_snapshot_v3_host.py',
                 'scripts/deployment_compose_host_commands_v3_host.py']):
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w') as archive:
                for name in names:archive.writestr(name,'')
            raw=output.getvalue()
            with patch.object(recovery,'published_recovery_archive',return_value=raw) as fetch:
                if len(names)==6:self.assertEqual(recovery.published_manager_archive('b'*40),raw)
                else:
                    with self.assertRaises(ValueError):recovery.published_manager_archive('b'*40)
                fetch.assert_called_once_with('b'*40)

    @unittest.skipUnless(os.name=='posix','bootstrap uses POSIX pipe selectors')
    def test_actual_manager_loader_passes_only_same_validated_archive(self):
        code=("def run(config,stdin,stdout,archive):\n"
              " import hashlib,json\n"
              " stdout.write(json.dumps({'entrypoint':config['entrypoint'],"
              "'digest':hashlib.sha256(archive).hexdigest()}).encode()); stdout.flush()\n")
        raw=self.archive(('scripts/deployment_compose_owned_recovery_manager_v3_host.py',code))
        digest=hashlib.sha256(raw).hexdigest()
        config=dict(archiveBase64=base64.b64encode(raw).decode(),archiveDigest=digest,
            sourceSha='b'*40,entrypoint=recovery.MANAGER_ENTRYPOINT)
        payload=json.dumps(config).encode()
        result=subprocess.run([sys.executable,'-I','-u','-c',recovery.manager_bootstrap(digest,'b'*40)],
            input=struct.pack('!I',len(payload))+payload,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),dict(entrypoint=recovery.MANAGER_ENTRYPOINT,digest=digest))

    @unittest.skipUnless(os.name=='posix','bootstrap uses POSIX pipe selectors')
    def test_actual_loader_pins_entry_source_digest_and_archive_paths(self):
        for attack in ('valid','entrypoint','source','digest','path'):
            with self.subTest(attack=attack):
                raw = self.archive(('../escape.py','') if attack=='path' else None)
                digest = hashlib.sha256(raw).hexdigest()
                config = dict(archiveBase64=base64.b64encode(raw).decode(),archiveDigest=digest,
                    sourceSha='b'*40,entrypoint=recovery.ENTRYPOINT)
                if attack=='entrypoint':config['entrypoint']=recovery.live.ENTRYPOINT
                if attack=='source':config['sourceSha']='c'*40
                if attack=='digest':config['archiveDigest']='0'*64
                payload=json.dumps(config).encode()
                result=subprocess.run([sys.executable,'-I','-u','-c',recovery.recovery_bootstrap(digest,'b'*40)],
                    input=struct.pack('!I',len(payload))+payload,capture_output=True,timeout=10)
                if attack=='valid':
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(json.loads(result.stdout),{'entrypoint':recovery.ENTRYPOINT})
                else:
                    self.assertNotEqual(result.returncode,0)
                    self.assertEqual(result.stdout,b'')


if __name__=='__main__':unittest.main()
