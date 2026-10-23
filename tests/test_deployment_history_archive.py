"""Pure archive authentication, manifest and bounded-parser regressions."""
from dataclasses import replace
from pathlib import Path
import hashlib
import hmac
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
from tests.test_deployment_store import fixture, store, KEY
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import deployment_history_archive as archive

class ArchiveTests(unittest.TestCase):
    def setUp(self):
        collector, _, _, _ = fixture()
        self.policy = store.StorePolicy(42, 'host', 'key-v1', collector.policy)
        with tempfile.TemporaryDirectory() as temp:
            backend = store.HostStore(self.policy, Path(temp).resolve() / 'host', key=KEY)
            ref = backend.capture_history(collector, collector.collect())
            self.histories = {ref: (backend.root / ref).read_bytes()}
        self.raw = archive.build_archive(self.policy, self.histories, KEY, created_at='2099-01-01T00:00:00+00:00')

    def signed(self, mutate):
        value = json.loads(self.raw)
        mutate(value['archive'])
        value['signature'] = hmac.new(KEY, archive._DOMAIN + archive._bytes(value['archive']), hashlib.sha256).hexdigest()
        return archive._bytes(value)

    def test_roundtrip_immutable_without_filesystem_or_store(self):
        with patch('builtins.open', side_effect=AssertionError('IO')), patch.object(store, 'HostStore', side_effect=AssertionError('constructor')):
            verified = archive.verify_archive(self.raw, self.policy, KEY)
            self.assertEqual(archive.build_archive(self.policy, self.histories, KEY, created_at=verified.created_at), self.raw)
        self.assertEqual(verified.records[0].raw, next(iter(self.histories.values())))
        with self.assertRaises(TypeError):
            verified.records[0].record['kind'] = 'changed'

    def test_wrong_key_scope_and_noncanonical(self):
        for raw, policy, key in ((self.raw, self.policy, b'x' * 32),
                                 (self.raw, replace(self.policy, repository_id=99), KEY),
                                 (self.raw + b'\n', self.policy, KEY),
                                 (b'{"archive":{},"archive":{}}', self.policy, KEY),
                                 (b'{"archive":NaN}', self.policy, KEY)):
            with self.subTest(raw=raw[:15]), self.assertRaises(archive.ArchiveError):
                archive.verify_archive(raw, policy, key)

    def test_authenticated_manifest_tampering(self):
        mutations = [lambda b: b['manifest'].clear(),
                     lambda b: b['records'].append(b['records'][0]),
                     lambda b: (b['records'].append(b['records'][0]), b['manifest'].append(b['manifest'][0])),
                     lambda b: b['manifest'][0].update(reference='../escape'),
                     lambda b: b['manifest'][0].update(size=True),
                     lambda b: b['manifest'][0].update(sha256='0' * 64),
                     lambda b: b.update(key='secret'),
                     lambda b: b.update(createdAt='2000-01-01T00:00:00+00:00'),
                     lambda b: b['records'][0]['envelope'].update(signature='0' * 64)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(archive.ArchiveError):
                archive.verify_archive(self.signed(mutation), self.policy, KEY)

    def test_size_and_count_limits(self):
        for constant, limit in [('MAX_ARCHIVE', len(self.raw) - 1), ('MAX_RECORD', 1), ('MAX_ENTRIES', 0)]:
            with self.subTest(constant=constant), patch.object(archive, constant, limit), self.assertRaises(archive.ArchiveError):
                archive.verify_archive(self.raw, self.policy, KEY)
        with self.assertRaises(archive.ArchiveError):
            archive.build_archive(self.policy, {'../escape': b'{}'}, KEY, created_at='2099-01-01T00:00:00+00:00')

if __name__ == '__main__':
    unittest.main()
