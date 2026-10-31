from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from tests.test_deployment_compose_snapshot import fixture
from deployment_compose_network_source_host import issue_network_from_git


class NetworkSourceHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        self.args = fixture()
        self.model = {'services': {'app': {'networks': {'main': {'aliases': ['app', 'custom']}}}},
                      'networks': {'main': {'name': 'sample_default', 'external': True}}}

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True).stdout.decode().strip()

    def commit(self, content=None, symlink=False):
        p = self.root/'compose.json'
        if symlink:
            p.symlink_to('elsewhere')
        else:
            p.write_bytes(content if content is not None else json.dumps(self.model).encode())
        self.git('add', 'compose.json')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', '-c', 'core.hooksPath=/dev/null',
                 'commit', '-qm', 'fixture')
        self.sha = self.git('rev-parse', 'HEAD')
        self.digest = hashlib.sha256(p.read_bytes()).hexdigest() if not symlink else 'e'*64

    def issue(self, **options):
        raw, identity, artifact, networks, mounts = self.args
        pins = dict(expected_blob_digest=self.digest, declaration_key_id='source-key', declaration_key=b'z'*32)
        pins.update(options)
        return issue_network_from_git(self.root, 'compose.json', raw, identity,
            replace(artifact, source_sha=self.sha), b'private-test-key-'+b'x'*32, networks, mounts, **pins)

    def test_committed_blob_used_despite_dirty_worktree(self):
        self.commit()
        (self.root/'compose.json').write_text('dirty secret')
        result = self.issue()
        self.assertTrue(result['sourceEvidence']['gitBlobMembershipVerified'])
        self.assertEqual(result['sourceEvidence']['sha256'], self.digest)
        self.assertEqual(result['declaration']['sourceSha'], self.sha)
        self.assertFalse(result['repositoryOwnershipVerified'] or result['deploymentSourceMatchVerified']
                         or result['authorityGranted'] or result['executionAvailable'] or result['productionReady'])

    def test_wrong_content_digest_and_source_commit_reject(self):
        self.commit()
        with self.assertRaises(ValueError):
            self.issue(expected_blob_digest='f'*64)
        self.sha = 'a'*40
        with self.assertRaisesRegex(ValueError, '^invalid-compose-network-source$'):
            self.issue()

    def test_static_address_or_unreviewed_merge_fields_reject(self):
        self.model['services']['app']['networks']['main']['ipv4_address'] = '172.20.0.3'
        self.commit()
        with self.assertRaises(ValueError):
            self.issue()

    def test_duplicate_keys_and_escaped_interpolation_reject(self):
        self.commit(b'{"services":{},"services":{},"networks":{}}')
        with self.assertRaises(ValueError):
            self.issue()
        (self.root/'compose.json').write_bytes(b'{}')
        self.model['services']['app']['image'] = '${IMAGE}'
        content = json.dumps(self.model).replace('$', r'\u0024').encode()
        (self.root/'compose.json').write_bytes(content)
        self.git('add', 'compose.json')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'second')
        self.sha = self.git('rev-parse', 'HEAD'); self.digest = hashlib.sha256(content).hexdigest()
        with self.assertRaises(ValueError):
            self.issue()

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink fixture')
    def test_symlink_source_reject(self):
        self.commit(symlink=True)
        with self.assertRaises(ValueError):
            self.issue()

    def test_oversized_source_rejected_before_blob_read(self):
        self.commit(b' ' * (128 * 1024 + 1))
        with self.assertRaises(ValueError):
            self.issue()

    def test_promisor_config_rejects_before_any_missing_object_lookup(self):
        self.commit()
        self.git('config', 'remote.origin.promisor', 'true')
        self.git('config', 'extensions.partialClone', 'origin')
        self.git('config', 'remote.origin.url', '/nonexistent-test-promisor-no-network')
        self.sha = 'a'*40
        from unittest.mock import patch
        import deployment_compose_network_source_host as host
        original = host._git
        calls = []
        def record(root, *args):
            calls.append(args)
            return original(root, *args)
        with patch.object(host, '_git', side_effect=record), self.assertRaises(ValueError):
            self.issue()
        self.assertEqual(calls, [('config', '--includes', '--null', '--list')])

    def test_authenticated_observation_must_match_source_aliases(self):
        self.model['services']['app']['networks']['main']['aliases'] = ['other']
        self.commit()
        with self.assertRaises(ValueError):
            self.issue()


if __name__ == '__main__':
    unittest.main()
