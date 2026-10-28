"""Fixed GET-only Compose Docker reader security boundaries."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve().parents[1] / 'packs/deployment/scripts/deployment_compose_reader.py'
spec = importlib.util.spec_from_file_location('deployment_compose_reader_under_test', SCRIPT)
reader = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = reader
spec.loader.exec_module(reader)


class ComposeReaderTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.policy = reader.ComposeReadPolicy('https://localhost:2376', 'a' * 64, 'daemon-1', 'blog', ('blog_uploads',))
        def transport(path):
            self.calls.append(path)
            return b'{"ID":"daemon-1"}' if path.endswith('/info') else b'[]'
        self.client = reader.ComposeDockerReader(self.policy, ca_file=Path('unused'), cert_file=Path('unused'),
                                                  key_file=Path('unused'), transport=transport)

    def test_image_defaults_optin_and_exact_response(self):
        path = '/v1.45/workflow/private-image/sha256:' + 'c' * 64
        with self.assertRaises(reader.ComposeReadError):
            self.client.get(path)
        for options in ({'image_defaults_enabled': 1}, {'image_defaults_enabled': True},
                        {'image_defaults_enabled': True, 'private_key_id': 'key'}):
            with self.assertRaises(reader.ComposeReadError):
                reader.ComposeReadPolicy('https://localhost', 'a'*64, 'daemon', 'blog', **options)
        policy = reader.ComposeReadPolicy('https://localhost', 'a'*64, 'daemon', 'blog',
                                         gateway_policy_hash='b'*64, private_key_id='key',
                                         image_defaults_enabled=True)
        good = {'schemaVersion': 1, 'keyId': 'key', 'imageConfigHmac': 'd'*64,
                'authorityGranted': False}
        payload = good.copy()
        client = reader.ComposeDockerReader(policy, ca_file=Path('unused'), cert_file=Path('unused'),
                                             key_file=Path('unused'),
                                             transport=lambda _: json.dumps(payload).encode())
        self.assertEqual(client.get(path), good)
        for key, bad in [('schemaVersion', True), ('schemaVersion', '1'), ('keyId', 'foreign'),
                         ('imageConfigHmac', 1), ('imageConfigHmac', 'z'*64),
                         ('authorityGranted', 0), ('Config', {'Env': ['secret']})]:
            payload = {**good, key: bad}
            with self.subTest(key=key, bad=bad), self.assertRaises(reader.ComposeReadError):
                client.get(path)
        for bad_path in (path + '/json', path + '?x=1', path.replace('sha256:', ''),
                         path.replace('sha256:', 'tag:')):
            with self.assertRaises(reader.ComposeReadError):
                client.get(bad_path)

    def test_exact_routes_only_and_no_write(self):
        allowed = ['/v1.45/info', self.client.list_path, '/v1.45/containers/' + 'b'*64 + '/json',
                   '/v1.45/images/sha256:' + 'c'*64 + '/json',
                   '/v1.45/networks/' + 'd'*64, '/v1.45/volumes/blog_uploads']
        for path in allowed:
            self.client.get(path)
        self.assertEqual(self.calls, allowed)
        for path in ('/v1.45/containers/json?all=1', '/v1.45/containers/create',
                     '/v1.45/containers/' + 'b'*64 + '/start', '/v1.45/build', '/v1.45/images/create',
                     '/v1.45/containers/' + 'b'*64 + '/exec', '/v1.45/volumes/other',
                     '/v1.45/networks/' + 'd'*64 + '/json', '/v1.45/networks/' + 'd'*64 + '/connect', '/v1.45/info?x=1',
                     '/v1.45/containers/' + 'B'*64 + '/json'):
            with self.assertRaises(reader.ComposeReadError, msg=path):
                self.client.get(path)
        self.assertEqual(self.calls, allowed)

    def test_reject_bad_policy(self):
        for endpoint in ('http://localhost', 'https://user:password@localhost', 'https://localhost/foo',
                         'https://localhost?x=1'):
            with self.assertRaises(reader.ComposeReadError):
                reader.ComposeReadPolicy(endpoint, 'a'*64, 'daemon-1', 'blog')
        with self.assertRaises(reader.ComposeReadError):
            reader.ComposeReadPolicy('https://localhost', 'a'*64, 'daemon-1', 'blog', ('../secret',))
        with self.assertRaises(reader.ComposeReadError):
            reader.ComposeReadPolicy('https://localhost', 'a'*64, 'daemon-1', 'blog', (['unhashable'],))
        with self.assertRaises(reader.ComposeReadError):
            reader.ComposeReadPolicy('https://localhost', 'a'*64, 'daemon-1', 'blog', tuple('v%d' % i for i in range(129)))

    def test_reject_duplicate_nonfinite_oversize_and_exception_leak(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'x' * (reader.MAX_RESPONSE+1)):
            self.client._transport = lambda path, raw=raw: raw
            with self.assertRaises(reader.ComposeReadError):
                self.client.get('/v1.45/containers/' + 'b'*64 + '/json')
        def leak(path):
            raise RuntimeError('secret-key and Docker response body')
        self.client._transport = leak
        with self.assertRaises(reader.ComposeReadError) as caught:
            self.client.get('/v1.45/info')
        self.assertNotIn('secret-key', str(caught.exception))
        self.assertEqual(caught.exception.code, 'transport-unavailable')
        self.assertIsNone(caught.exception.__cause__)

    def test_not_found_is_exact_inspect_only(self):
        def missing(path):
            raise reader.ComposeNotFound()
        self.client._transport = missing
        with self.assertRaises(reader.ComposeReadError) as caught:
            self.client.get(self.client.list_path)
        self.assertNotIsInstance(caught.exception, reader.ComposeNotFound)
        self.assertEqual(caught.exception.code, 'http-status')
        with self.assertRaises(reader.ComposeNotFound) as exact:
            self.client.get('/v1.45/containers/' + 'b'*64 + '/json')
        self.assertEqual(exact.exception.code, 'exact-not-found')

    def test_info_identity_inventory_shape_and_deadline(self):
        self.client._transport = lambda path: b'{"ID":"wrong"}'
        with self.assertRaises(reader.ComposeReadError):
            self.client.get('/v1.45/info')
        self.client._transport = lambda path: b'{}'
        with self.assertRaises(reader.ComposeReadError):
            self.client.get(self.client.list_path)
        self.calls.clear()
        self.client._transport = lambda path: self.calls.append(path) or b'[]'
        with self.assertRaises(reader.ComposeReadError):
            self.client.get('/v1.45/info', deadline=0)
        self.assertEqual(self.calls, [])

    def test_gateway_info_requires_configured_hash_and_exact_schema(self):
        with self.assertRaises(reader.ComposeReadError):
            self.client.gateway_info()
        self.assertEqual(self.calls, [])
        with self.assertRaises(reader.ComposeReadError):
            self.client.get(reader.GATEWAY_INFO_PATH)
        expected = 'e' * 64
        policy = reader.ComposeReadPolicy('https://localhost:2376', 'a'*64, 'daemon-1', 'blog',
                                          gateway_policy_hash=expected)
        responses = [b'{"bootId":"' + b'f'*32 + b'","policyHash":"' + expected.encode() + b'"}',
                     b'{"bootId":"bad","policyHash":"' + expected.encode() + b'"}',
                     b'{"bootId":"' + b'f'*32 + b'","policyHash":"' + b'0'*64 + b'"}',
                     b'{"bootId":"' + b'f'*32 + b'"}',
                     b'{"bootId":"' + b'f'*32 + b'","policyHash":"' + expected.encode() + b'","extra":1}']
        calls = []
        def transport(path):
            calls.append(path)
            return responses.pop(0)
        client = reader.ComposeDockerReader(policy, ca_file=Path('unused'), cert_file=Path('unused'),
                                            key_file=Path('unused'), transport=transport)
        self.assertEqual(client.gateway_info()['bootId'], 'f'*32)
        self.assertEqual(client.gateway_boot_id, 'f'*32)
        for _ in range(4):
            with self.assertRaises(reader.ComposeReadError) as caught:
                client.gateway_info()
            self.assertEqual(caught.exception.code, 'gateway-mismatch')
            self.assertIsNone(client.gateway_boot_id)
        self.assertEqual(calls, [reader.GATEWAY_INFO_PATH]*5)
        with self.assertRaises(reader.ComposeReadError):
            reader.ComposeReadPolicy('https://localhost', 'a'*64, 'daemon-1', 'blog', gateway_policy_hash='wrong')

    def test_pinned_peer_mismatch_stays_distinct(self):
        class Peer:
            def getpeercert(self, *, binary_form):
                return b'wrong-certificate-secret'
        class Connection:
            sock = Peer()
            def __init__(self, *args, **kwargs):
                pass
            def connect(self):
                pass
            def close(self):
                pass
        self.client._transport = None
        self.client._context = object()
        with mock.patch.object(reader.http.client, 'HTTPSConnection', Connection):
            with self.assertRaises(reader.ComposeReadError) as caught:
                self.client.get('/v1.45/info')
        self.assertEqual(caught.exception.code, 'pin-mismatch')
        self.assertNotIn('wrong-certificate-secret', str(caught.exception))

    def test_failure_codes_remain_distinct_and_secret_free(self):
        cases = [(b'{\"a\":1,\"a\":2}', 'duplicate-json-field'),
                 (b'{\"a\":NaN}', 'invalid-json'),
                 (b'x' * (reader.MAX_RESPONSE + 1), 'response-too-large')]
        for raw, code in cases:
            self.client._transport = lambda path, raw=raw: raw
            with self.assertRaises(reader.ComposeReadError) as caught:
                self.client.get('/v1.45/containers/' + 'b'*64 + '/json')
            self.assertEqual(caught.exception.code, code)
        def timeout(path):
            raise TimeoutError('secret token')
        self.client._transport = timeout
        with self.assertRaises(reader.ComposeReadError) as caught:
            self.client.get('/v1.45/info')
        self.assertEqual(caught.exception.code, 'deadline-exceeded')
        self.assertNotIn('secret', str(caught.exception))

    def test_bind_routes_require_pinned_gateway_and_exact_projection(self):
        for count in (-1, 33, True, 1.0):
            with self.assertRaises(reader.ComposeReadError):
                reader.ComposeReadPolicy('https://localhost', 'a'*64, 'daemon-1', 'blog',
                                         bind_count=count, private_key_id='key', gateway_policy_hash='b'*64)
        with self.assertRaises(reader.ComposeReadError):
            reader.ComposeReadPolicy('https://localhost', 'a'*64, 'daemon-1', 'blog', bind_count=1)
        policy = reader.ComposeReadPolicy('https://localhost', 'a'*64, 'daemon-1', 'blog',
                                          bind_count=1, private_key_id='key', gateway_policy_hash='b'*64)
        payload = {'schemaVersion': 1, 'bindDigest': 'c'*64, 'authorityGranted': False}
        client = reader.ComposeDockerReader(policy, ca_file=Path('unused'), cert_file=Path('unused'),
                                             key_file=Path('unused'),
                                             transport=lambda path: json.dumps(payload).encode())
        self.assertEqual(client.get('/v1.45/workflow/binds/0'), payload)
        for path in ('/v1.45/workflow/binds/1', '/v1.45/workflow/binds/00',
                     '/v1.45/workflow/binds/0/extra'):
            with self.assertRaises(reader.ComposeReadError) as caught:
                client.get(path)
            self.assertEqual(caught.exception.code, 'route-refused')
        for bad in ({**payload, 'authorityGranted': True}, {**payload, 'extra': 'secret'},
                    {**payload, 'bindDigest': 'bad'}, {**payload, 'schemaVersion': True}):
            client._transport = lambda path, bad=bad: json.dumps(bad).encode()
            with self.assertRaises(reader.ComposeReadError) as caught:
                client.get('/v1.45/workflow/binds/0')
            self.assertEqual(caught.exception.code, 'gateway-mismatch')


if __name__ == '__main__':
    unittest.main()
