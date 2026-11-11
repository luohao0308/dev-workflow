"""A normal producer exit must retain parent-owned diagnostic recovery bytes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name=='posix','POSIX fixture imports required')
class SourceFixtureRetentionTests(unittest.TestCase):
    def test_normal_exit_retains_only_explicit_parent_owned_temporaries(self):
        with tempfile.TemporaryDirectory() as directory:
            code='''import sys,tempfile
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+'/tests/support']
from compose_native_writer_lifecycle_fixture import retain_parent_owned_temporaries
owned=Path(sys.argv[2])
retained=tempfile.TemporaryDirectory(dir=owned)
ordinary=tempfile.TemporaryDirectory(dir=owned)
Path(retained.name,'material').write_bytes(b'original')
try:
 retain_parent_owned_temporaries(owned/'different',(retained,))
except ValueError:pass
else:raise AssertionError('outside parent accepted')
retain_parent_owned_temporaries(owned,(retained,))
print(Path(retained.name).name,Path(ordinary.name).name)
'''
            reply=subprocess.run([sys.executable,'-I','-S','-c',code,str(ROOT),directory],capture_output=True,text=True,check=True,timeout=10)
            retained,ordinary=reply.stdout.split()
            self.assertEqual((Path(directory)/retained/'material').read_bytes(),b'original')
            self.assertFalse((Path(directory)/ordinary).exists())
