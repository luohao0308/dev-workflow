"""Production bootstrap tests, including real Linux cmdline and fixture origin."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / path) for path in ('scripts', 'packs/deployment/scripts', 'packs/release/scripts')]

import deployment_compose_retained_native_entry_v1_host as entry
import deployment_compose_retained_source_v1_host as source
from deployment_compose_checkpoint_source_v3_host import REQUIRED as LEGACY_REQUIRED
from deployment_compose_production_scope_v1_host import provision_scope
from deployment_compose_profile3_prepare_ssh_probe import ORIGIN


def zip_bytes(items):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, data in items:
            zipped.writestr(name, data)
    return output.getvalue()


def fixture():
    return [(name, b'# fixture\n') for name in sorted(source.REQUIRED)]


class ArchiveTests(unittest.TestCase):
    def test_production_archive_rejects_test_modules_unsafe_metadata_and_duplicates(self):
        self.assertEqual(set(source.archive_files(zip_bytes(fixture()))), source.REQUIRED)
        symlink = zipfile.ZipInfo('scripts/deployment_compose_extra.py')
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for name in ('tests/support/fixture.py', 'tests/test_any.py', '../escape.py', symlink):
            with self.subTest(name=name), self.assertRaises(ValueError):
                source.archive_files(zip_bytes(fixture() + [(name, b'bad')]))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            duplicate = zip_bytes(fixture() + fixture()[:1])
        with self.assertRaises(ValueError):
            source.archive_files(duplicate)

    def test_unissued_source_receipt_is_rejected(self):
        with self.assertRaises(ValueError):
            source.check_loaded_source(object.__new__(source.ProductionLoadedSourceV1))

    @unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'POSIX Git required')
    def test_local_git_archive_pins_blob_contents_and_excludes_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()

            def git(*args):
                return subprocess.run(['/usr/bin/git', '-C', str(root), *args], capture_output=True,
                                      check=True, timeout=15).stdout.decode().strip()

            git('init', '-q')
            git('remote', 'add', 'origin', ORIGIN)
            for name in source.REQUIRED | LEGACY_REQUIRED:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'# tracked\n')
            git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
            sha = git('rev-parse', 'HEAD')
            raw = source.production_archive(root, sha)
            (root / sorted(source.REQUIRED)[0]).write_bytes(b'# modified worktree\n')
            self.assertEqual(raw, source.production_archive(root, sha))
            files = source.archive_files(raw)
            self.assertFalse(any(name.startswith('tests/') for name in files))
            self.assertEqual(set(files.values()), {b'# tracked\n'})


@unittest.skipUnless(os.name == 'posix', 'POSIX registered scope required')
class StartupTests(unittest.TestCase):
    def test_startup_observer_rechecks_daemon_and_journal_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            reg = provision_scope(root, host_id='fixture', project='luohao-blog-prod', daemon_id='fixture-daemon')
            encoded = dict(root=str(root), rootIdentity=list(reg.root_identity), journalIdentity=list(reg.journal_identity),
                           hostId=reg.host_id, project=reg.project, daemonId=reg.daemon_id)
            self.assertEqual(entry.scope_registration(encoded), reg)
            with patch.object(entry, 'check_loaded_source'), patch.object(entry, 'HostSnapshotV3') as native:
                native.return_value._info_id = 'fixture-daemon'
                self.assertIs(entry.prepare(object(), reg), native.return_value)
                native.return_value._info_id = 'wrong-daemon'
                with self.assertRaises(ValueError):
                    entry.prepare(object(), reg)
                native.return_value.close.assert_called_once()
                bad_pin = entry.scope_registration(dict(encoded, journalIdentity=[0, 0]))
                native.reset_mock()
                with self.assertRaises(ValueError):
                    entry.prepare(object(), bad_pin)
                native.assert_not_called()

    def test_fixed_entry_dispatches_only_explicit_channel_mode(self):
        prepared = Mock()
        prepared.descriptor.return_value = {'endpointDigest': 'a' * 64}
        receipt = object()
        registration = object()
        facts = dict(profile=source.PROFILE, sourceSha='b'*40, archiveDigest='c'*64,
                     channelNonce='d'*64, originDigest='e'*64)
        fake_channel = Mock()
        with patch.object(entry, 'issue_loaded_source', return_value=receipt), \
                patch.object(entry, 'scope_registration', return_value=registration), \
                patch.object(entry, 'prepare', return_value=prepared), \
                patch.object(entry, 'check_loaded_source', return_value=facts), \
                patch.object(entry, 'write_frame') as write, \
                patch.dict(sys.modules, {'deployment_compose_retained_native_channel_v1_host': fake_channel}):
            config = dict(scope={}, mode='startup-check')
            entry.run_production(config, b'archive', ROOT)
            fake_channel.run_channel.assert_not_called()
            config = dict(scope={}, mode='channel')
            entry.run_production(config, b'archive', ROOT)
            fake_channel.run_channel.assert_called_once_with(config, receipt, prepared, registration)
            self.assertEqual(write.call_args.args[1]['source'], facts)
            self.assertEqual(prepared.close.call_count, 2)


@unittest.skipUnless(sys.platform == 'linux', 'Linux /proc command identity required')
class ActualBootstrapTests(unittest.TestCase):
    def _run(self, raw, work, *, mode='startup-check'):
        sha = 'b'*40
        digest = hashlib.sha256(raw).hexdigest()
        config = dict(entrypoint=source.ENTRYPOINT, sourceSha=sha, archiveDigest=digest,
                      channelNonce='c'*64, scope={}, mode=mode, workDirectory=str(work),
                      archiveBase64=base64.b64encode(raw).decode('ascii'))
        payload = json.dumps(config).encode('ascii')
        return subprocess.run([sys.executable, '-I', '-S', '-u', '-c', source.production_bootstrap(sha, digest)],
                              input=struct.pack('!I', len(payload)) + payload, capture_output=True, timeout=20)

    def test_production_bootstrap_issues_only_from_real_loaded_files_and_detects_drift(self):
        files = [(p.relative_to(ROOT).as_posix(), p.read_bytes()) for p in ROOT.rglob('*.py')
                 if source.re.fullmatch(source.NAME, p.relative_to(ROOT).as_posix())]
        entry_name = 'scripts/deployment_compose_retained_native_entry_v1_host.py'
        files = [(name, raw) for name, raw in files if name != entry_name]
        files.append((entry_name, b'''
from deployment_compose_retained_source_v1_host import issue_loaded_source, check_loaded_source
import deployment_compose_retained_source_v1_host as source
import json
def run_production(config, archive, root):
    # A container lacks the dedicated systemd unit. Only this kernel origin
    # query is a fixture. Command identity and loaded archive remain native.
    source._capture_current_origin = lambda *_: b'fixture-origin'
    receipt = issue_loaded_source(config, archive, root)
    print(json.dumps(check_loaded_source(receipt)))
    try:
        check_loaded_source(receipt, scope={'unexpected': 'different'})
    except ValueError:
        pass
    else:
        raise RuntimeError('scope drift accepted')
    path = root / 'scripts/deployment_compose_retained_native_entry_v1_host.py'
    path.write_bytes(b'# changed')
    try:
        check_loaded_source(receipt)
    except ValueError:
        print('drift-rejected')
    else:
        raise RuntimeError('source drift accepted')
'''))
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            result = self._run(zip_bytes(files), work)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            facts, drift = result.stdout.splitlines()
            self.assertEqual(json.loads(facts)['profile'], source.PROFILE)
            self.assertEqual(drift, b'drift-rejected')
            self.assertEqual(list(work.iterdir()), [])

    def test_bootstrap_rejects_test_file_before_importing_entry(self):
        entries = [(name, b'raise RuntimeError("import-ran")\n') for name, _ in fixture()]
        raw = zip_bytes(entries + [('tests/support/foreign.py', b'bad')])
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            result = self._run(raw, work)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'production-package-member', result.stderr)
            self.assertNotIn(b'import-ran', result.stderr)
            self.assertEqual(list(work.iterdir()), [])

    def test_channel_mode_requires_fixed_channel_module_before_import(self):
        entries = [(name, b'raise RuntimeError("import-ran")\n') for name, _ in fixture()]
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(zip_bytes(entries), Path(directory).resolve(), mode='channel')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'production-package-incomplete', result.stderr)
            self.assertNotIn(b'import-ran', result.stderr)
