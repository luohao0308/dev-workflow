from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import deployment_host_doctor as doctor

class DoctorTests(unittest.TestCase):
    def test_offline_missing_inputs_no_network_or_output(self):
        with tempfile.TemporaryDirectory() as root:
            sentinel = Path(root)/'keylog'
            cfg = SimpleNamespace(store_key_file=Path(root)/'missing')
            with patch.dict('os.environ', {'SSLKEYLOGFILE': str(sentinel)}), patch.object(doctor, '_get', side_effect=AssertionError('network')):
                report = doctor.diagnose(cfg)
            self.assertFalse(sentinel.exists())
            self.assertEqual(list(Path(root).iterdir()), [])
            self.assertEqual(report['status'], 'fail')
            self.assertFalse(report['productionReady'])
            self.assertNotIn(str(root), str(report))
    def test_online_keylog_blocks_network(self):
        with tempfile.TemporaryDirectory() as root:
            sentinel = Path(root)/'keylog'
            with patch.dict('os.environ', {'SSLKEYLOGFILE': str(sentinel)}), patch.object(doctor, '_get', side_effect=AssertionError('network')):
                report = doctor.diagnose(SimpleNamespace(), online=True)
            self.assertFalse(sentinel.exists())
            self.assertIn('ambient-tls-output-refused', str(report))

import shutil
import subprocess
import os
@unittest.skipUnless(shutil.which('openssl') and os.name != 'nt', 'OpenSSL and POSIX private-file verification required')
class RealTLSDoctorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_deployment_runtime import LocalTLSRuntimeTests
        LocalTLSRuntimeTests.setUpClass.__func__(cls)
        cls.directory = cls.directory.resolve()
        for name in ('ca.pem', 'client.pem', 'client.key', 'server.pem', 'server.key'):
            (cls.directory/name).chmod(0o600)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def config(self):
        return SimpleNamespace(distribution_commit='0'*40, store_key_file=self.directory/'client.key', gate_key_file=self.directory/'client.key',
                               ca_file=self.directory/'ca.pem', reader_cert_file=self.directory/'client.pem', reader_key_file=self.directory/'client.key',
                               writer_cert_file=self.directory/'server.pem', writer_key_file=self.directory/'server.key', execution_policy=SimpleNamespace(writer_certificate_sha256=doctor.hashlib.sha256(doctor.ssl.PEM_cert_to_DER_cert((self.directory/'server.pem').read_text())).hexdigest()))
    def test_real_matching_tls_offline_has_no_writes(self):
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.directory.iterdir() if p.is_file()}
        with patch.object(doctor, '_get', side_effect=AssertionError('network')), patch.dict('os.environ', {'SSLKEYLOGFILE': str(self.directory/'sentinel')}):
            report = doctor.diagnose(self.config())
        self.assertIn('tls-loadable-only', str(report))
        after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.directory.iterdir() if p.is_file()}
        self.assertEqual(before, after)
    def test_encrypted_key_noninteractive(self):
        encrypted = self.directory/'encrypted.key'
        subprocess.run(['openssl', 'pkey', '-in', str(self.directory/'client.key'), '-aes256', '-passout', 'pass:fixture-only', '-out', str(encrypted)], check=True, capture_output=True, timeout=10)
        encrypted.chmod(0o600)
        cfg = self.config(); cfg.reader_key_file = encrypted
        report = doctor.diagnose(cfg)
        self.assertIn('private-input-or-tls-invalid', str(report))
        self.assertNotIn('fixture-only', str(report))
        encrypted.unlink()
    def test_fixed_online_get_policy(self):
        cfg = self.config()
        cfg.runtime_policy = SimpleNamespace(endpoint='https://localhost:12345', server_certificate_sha256='a'*64, daemon_id='daemon', repository='owner/target')
        cfg.store_policy = SimpleNamespace(repository_id=1)
        cfg.github = dict(host_repository='owner/host', host_repository_id=2, ledger_repository='owner/ledger', ledger_repository_id=3,
                          reviewer_ids=(7,), prevent_self_review=True, workflow_sha='b'*40, ledger_sha='c'*40, deploy_approval_environment='deploy', rollback_approval_environment='rollback', recovery_approval_environment='recovery', credential_file=self.directory/'token')
        cfg.github['credential_file'].write_text('fixture-token'); cfg.github['credential_file'].chmod(0o600)
        calls = []
        def get(host, port, path, context, headers=None, pin=None):
            calls.append((host, path))
            if path == '/v1.45/info':
                return {'ID': 'daemon'}
            if '/git/commits/' in path:
                return {'sha': path.split('/')[-1]}
            if '/environments/' in path:
                return dict(name=path.split('/')[-1], can_admins_bypass=False, protection_rules=[dict(type='required_reviewers', prevent_self_review=True, reviewers=[dict(type='User', reviewer={'id': 7})])])
            name = path.removeprefix('/repos/')
            return dict(full_name=name, id={'owner/target':1, 'owner/host':2, 'owner/ledger':3}[name])
        try:
            with patch.object(doctor, '_get', side_effect=get), patch.dict('os.environ', {'SSLKEYLOGFILE': ''}):
                report = doctor.diagnose(cfg, online=True)
            self.assertIn('github-identities-and-review-policy-observed', str(report))
            self.assertEqual(len(calls), 8)
            self.assertTrue(all(host == 'api.github.com' for host, _ in calls))
            self.assertTrue(all('/owner/host/environments/' in path for _, path in calls[-3:]))
        finally:
            cfg.github['credential_file'].unlink()

    def test_tls_uses_bytes_when_original_paths_change(self):
        cfg = self.config()
        original = cfg.reader_key_file.read_bytes()
        original_factory = doctor._tls_context
        def replace_then_load(ca, cert, key):
            cfg.reader_key_file.write_bytes(b'not-a-key')
            try:
                return original_factory(ca, cert, key)
            finally:
                cfg.reader_key_file.write_bytes(original)
        with patch.object(doctor, '_tls_context', side_effect=replace_then_load):
            report = doctor.diagnose(cfg)
        self.assertIn('tls-loadable-only', str(report))

class DiagnosticContractTests(unittest.TestCase):
    def test_windows_unknown_exit_two(self):
        from deployment_host_config import ConfigurationError
        import io
        with patch.object(doctor, 'load_host_config', side_effect=ConfigurationError('private-acl-unverified')), patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(doctor.main(['--config', 'unused', '--json']), 2)
        report = doctor.json.loads(output.getvalue())
        self.assertEqual(report['status'], 'unknown')
        self.assertIn('private-acl-unverified', output.getvalue())
    def test_real_git_filters_never_execute_and_dirty_is_rejected(self):
        import shlex
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            def git(*args):
                return subprocess.run(['git','-C',str(root),*args],check=True,capture_output=True).stdout.decode().strip()
            git('init'); git('config','user.name','Fixture'); git('config','user.email','fixture@example.invalid')
            git('config','core.autocrlf','false')
            (root/'scripts').mkdir()
            source = root/'scripts'/'fixture.py'
            source.write_text('print("trusted")\n')
            (root/'.gitattributes').write_text('scripts/*.py filter=tripwire\n')
            git('add','.'); git('commit','-m','fixture')
            head=git('rev-parse','HEAD')
            sentinel=root/'sentinel'
            helper=root/'filter.py'
            helper.write_text('from pathlib import Path\nPath('+repr(str(sentinel))+').write_text("executed")\n')
            command=shlex.quote(sys.executable)+' '+shlex.quote(str(helper))
            git('config','filter.tripwire.clean',command)
            git('config','filter.tripwire.process',command)
            git('config','filter.tripwire.required','true')
            with patch.object(doctor,'DISTRIBUTION',root):
                self.assertTrue(doctor._distribution_verified(head))
                source.write_text('print("changed")\n')
                with self.assertRaises(ValueError):
                    doctor._distribution_verified(head)
                source.write_text('print("trusted")\n')
                git('config','remote.origin.promisor','true')
                with self.assertRaises(ValueError):
                    doctor._distribution_verified(head)
            self.assertFalse(sentinel.exists())

    def test_get_refuses_redirect_and_ambiguous_framing(self):
        connection = unittest.mock.MagicMock()
        response = connection.getresponse.return_value
        response.getheaders.return_value = [('Content-Length', '2'), ('Content-Length', '2')]
        with patch.object(doctor.http.client, 'HTTPSConnection', return_value=connection), patch.object(doctor.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 443))]), patch.object(doctor.socket, 'socket'), patch.object(doctor.ssl, 'SSLContext') as context:
            with self.assertRaises(ValueError):
                doctor._get('api.github.com', 443, '/repos/example/host', context)
        connection.close.assert_called_once()
        response.read.assert_not_called()

    def test_dns_timeout_never_sends_late(self):
        import threading
        release = threading.Event()
        finished = threading.Event()
        def resolve(*args, **kwargs):
            release.wait(2)
            finished.set()
            return [(2, 1, 6, '', ('127.0.0.1', 443))]
        with patch.object(doctor.socket, 'getaddrinfo', side_effect=resolve), patch.object(doctor.socket, 'socket') as connect:
            try:
                with self.assertRaises(TimeoutError):
                    doctor._get_raw('example.invalid', 443, '/', None, timeout=0.01)
                release.set()
                self.assertTrue(finished.wait(1))
                connect.assert_not_called()
            finally:
                release.set()

    @unittest.skipIf(os.name == 'nt', 'POSIX private-file length check after permissions')
    def test_short_hmac_key_rejected_without_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve()/'key'
            path.write_bytes(b'short-secret-marker'); path.chmod(0o600)
            report = doctor.diagnose(SimpleNamespace(store_key_file=path, gate_key_file=path))
            self.assertEqual(report['status'], 'fail')
            self.assertIn('hmac-key-invalid-or-short', str(report))
            self.assertNotIn('short-secret-marker', str(report))

    @unittest.skipUnless(os.name == 'nt', 'Native Windows ACL-unknown contract')
    def test_windows_real_config_file_reports_unknown(self):
        import io
        from deployment_host_config import read_private_bytes, ConfigurationError
        with tempfile.TemporaryDirectory() as root:
            path = Path(root).resolve()/'config.json'
            path.write_text('{}')
            with self.assertRaisesRegex(ConfigurationError, '^private-acl-unverified$'):
                read_private_bytes(path, maximum=100)
            with patch('sys.stdout', new_callable=io.StringIO) as output:
                code = doctor.main(['--config', str(path), '--json'])
            self.assertEqual(code, 2)
            report = doctor.json.loads(output.getvalue())
            self.assertEqual(report['status'], 'unknown')
            self.assertEqual(report['checks'][0]['code'], 'private-acl-unverified')
