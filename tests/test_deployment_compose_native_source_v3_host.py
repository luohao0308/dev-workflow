"""Closed archive profile and non-forgeable process-local receipt admission."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
import tempfile
import os
import threading
from types import MappingProxyType
from unittest.mock import patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import deployment_compose_native_source_v3_host as source


class NativeSourceTests(unittest.TestCase):
    def archive(self, extra=()):
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as zipped:
            for name in ('scripts/deployment_compose_native_source_v3_host.py',
                'tests/support/compose_native_writer_lifecycle_fixture.py','tests/__init__.py',
                'tests/test_deployment_compose_native_writer_lifecycle_v3_host.py'):
                zipped.writestr(name,b'# fixture\n')
            for name,value in extra:
                # Preserve intentionally invalid raw names on Windows too;
                # ZipInfo(name) normalizes backslashes before writing there.
                info=zipfile.ZipInfo('placeholder.py')
                info.filename=info.orig_filename=name
                zipped.writestr(info,value)
        return output.getvalue()

    def test_closed_archive_members_and_modes(self):
        self.assertEqual(len(source.archive_files(self.archive())),4)
        for name in ('../outside.py','/outside.py','tests/../outside.py','scripts/random.py','tests/test_x.py/evil.py','tests\\test_x.py'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                source.archive_files(self.archive(((name,b''),)))
        with self.assertRaises(ValueError):source.archive_files(self.archive((('tests/__init__.py',b'collision'),)))
        with self.assertRaises(ValueError):source.archive_files(b'')
        with self.assertRaises(zipfile.BadZipFile):source.archive_files(self.archive()[:50])
        with patch.object(zipfile.os,'sep','\\'),self.assertRaises(ValueError):
            source.archive_files(self.archive((('tests\\test_x.py',b''),)))

    def test_source_receipts_cannot_be_constructed_or_copied(self):
        with self.assertRaises(ValueError):source.LoadedNativeSourceV3()
        forged=object.__new__(source.LoadedNativeSourceV3)
        for value in (forged,copy.copy(forged),None,{}):
            with self.assertRaises((ValueError,TypeError)):source.check_loaded_source(value)

    def test_retained_archive_uses_independent_digest(self):
        raw=self.archive()
        class Store:
            def get(self,reference):return raw
        facts=dict(profile=source.PROFILE,sourceSha='a'*40,archiveDigest=hashlib.sha256(raw).hexdigest(),
            archiveReference='cas-ref',channelNonce='b'*64,entrypoint=source.ENTRYPOINT,loaderArchiveVerified=True)
        self.assertEqual(source.verify_retained_source(facts,Store()),raw)
        for key,value in (('archiveDigest','c'*64),('sourceSha','invalid'),('entrypoint','caller.run'),('loaderArchiveVerified',1),('profile','caller')):
            with self.subTest(key=key),self.assertRaises(ValueError):source.verify_retained_source(dict(facts,**{key:value}),Store())

    @unittest.skipUnless(os.name=='posix','nofollow paths required')
    def test_receipt_seals_owner_and_files_without_exposing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            path=root/'unique_native_source_probe.py';path.write_bytes(b'# original');path.chmod(0o600)
            receipt=object.__new__(source.LoadedNativeSourceV3)
            state=dict(owner=(os.getpid(),threading.get_ident()),start_ticks=123,command=['fixed'],
                root=root,root_seal=source._root_seal(root),files=MappingProxyType({path.name:b'# original'}),
                source='a'*40,archive_digest='b'*64)
            source._ISSUED[receipt]=MappingProxyType(state)
            # Retain stdlib modules: pathlib on Python 3.12 imports ntpath lazily.
            modules={name:module for name,module in sys.modules.items() if name!='tests' and not name.startswith('tests.')}
            with patch.object(source,'_actual_command',return_value=['fixed']),patch.object(source,'_start_ticks',return_value=123),patch.dict(sys.modules,modules,clear=True):
                public=source.check_loaded_source(receipt);public['source']='forged'
                self.assertEqual(source.check_loaded_source(receipt)['source'],'a'*40)
                with self.assertRaises(ValueError):source.check_loaded_source(copy.copy(receipt))
                path.write_bytes(b'# changed')
                with self.assertRaises(ValueError):source.check_loaded_source(receipt)
                path.unlink();other=root/'other.py';other.write_bytes(b'# original');other.chmod(0o600)
                path.symlink_to(other)
                with self.assertRaises(OSError):source.check_loaded_source(receipt)
                path.unlink();path.write_bytes(b'# original');path.chmod(0o600)
                root.chmod(0o755)
                with self.assertRaises(ValueError):source.check_loaded_source(receipt)
                root.chmod(0o700)
                state['owner']=(os.getpid()+1,threading.get_ident())
                with self.assertRaises(ValueError):source.check_loaded_source(receipt)

    @unittest.skipUnless(sys.platform=='linux','actual Linux proc command line required')
    def test_forged_python_loader_namespace_rejected_by_kernel_command(self):
        code = r"""import sys,pathlib
sys.path.insert(0,SCRIPTS)
import deployment_compose_native_source_v3_host as source
config=dict(sourceSha='a'*40,archiveDigest='b'*64)
archive=b'fake';r=pathlib.Path('/tmp')
sys.orig_argv=[sys.executable,'-I','-S','-u','-c',source.diagnostic_bootstrap('a'*40,'b'*64)]
try:source._issue(config,archive,r)
except ValueError:print('kernel-command-rejected')
else:raise AssertionError('forged issuer accepted')
""".replace('SCRIPTS',repr(str(Path(source.__file__).parent)))
        result=subprocess.run([sys.executable,'-I','-S','-u','-c',code],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'kernel-command-rejected')

    @unittest.skipUnless(os.name=='posix','POSIX framed bootstrap required')
    def test_fixed_bootstrap_rejects_wrong_pins_before_import(self):
        code=source.diagnostic_bootstrap('a'*40,'b'*64)
        compile(code,'<bootstrap>','exec')
        value=dict(sourceSha='a'*40,archiveDigest='b'*64,entrypoint=source.ENTRYPOINT,archiveBase64='eA==')
        raw=json.dumps(value).encode();data=len(raw).to_bytes(4,'big')+raw
        result=subprocess.run([sys.executable,'-I','-S','-u','-c',code],input=data,capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'published-package-rejected',result.stderr)
        self.assertEqual(result.stdout,b'')
        for sha,digest in (('bad','b'*64),('a'*40,'bad')):
            with self.assertRaises(ValueError):source.diagnostic_bootstrap(sha,digest)


if __name__=='__main__':unittest.main()
