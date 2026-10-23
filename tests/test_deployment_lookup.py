"""Only authenticated Docker 404 establishes absence for recovery."""
from copy import deepcopy
from pathlib import Path
import shutil
import unittest
from tests import test_deployment_runtime as fixture

runtime = fixture.runtime
CID = 'a' * 64
NAME = 'dwf-' + 'b' * 64


class LookupTests(unittest.TestCase):
    def client(self, transport):
        return runtime.DockerTLSClient(fixture.policy(), ca_file=Path('unused'), cert_file=Path('unused'),
                                       key_file=Path('unused'), transport=transport)

    def test_exact_id_and_name_matching(self):
        value = dict(Id=CID, Name='/' + NAME)
        calls = []
        client = self.client(lambda path: calls.append(path) or deepcopy(value))
        self.assertEqual(client.lookup_container(CID), value)
        self.assertEqual(client.lookup_container(NAME), value)
        self.assertEqual(calls, ['/v1.45/containers/' + ref + '/json' for ref in (CID, NAME)])
        for ref in ('', '/other', '../x', NAME + '?all=1', CID + '/archive', 'x' * 129):
            with self.assertRaises(runtime.RuntimeCollectionError):
                client.lookup_container(ref)
        self.assertEqual(len(calls), 2)
        value['Id'] = 'c' * 64
        with self.assertRaises(runtime.RuntimeCollectionError):
            client.lookup_container(CID)

    def test_errors_and_empty_json_never_become_absence(self):
        def transport(path):
            raise runtime.DockerNotFound('trusted synthetic HTTP 404')
        self.assertIsNone(self.client(transport).lookup_container(CID))
        for value in (None, {}, [], {'message': 'not found'}):
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.client(lambda path: value).lookup_container(CID)
        for error in (KeyError('missing'), TimeoutError('unknown'), ValueError('bad JSON')):
            def failed(path):
                raise error
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.client(failed).lookup_container(CID)


@unittest.skipUnless(shutil.which('openssl'), 'openssl required')
class LocalLookupTests(unittest.TestCase):
    setUpClass = classmethod(fixture.LocalTLSRuntimeTests.setUpClass.__func__)
    tearDownClass = classmethod(fixture.LocalTLSRuntimeTests.tearDownClass.__func__)
    start_server = fixture.LocalTLSRuntimeTests.start_server
    client = fixture.LocalTLSRuntimeTests.client

    def test_real_mtls_404_only_and_pin_precedes_absence(self):
        policy, calls = self.start_server(response_status=404, response_body={'message': 'missing'})
        self.assertIsNone(self.client(policy).lookup_container(CID))
        self.assertEqual(len(calls), 1)
        from dataclasses import replace
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.client(replace(policy, server_certificate_sha256='0' * 64)).lookup_container(CID)
        self.assertEqual(len(calls), 1)
        for status in (403, 500):
            policy, _ = self.start_server(response_status=status, response_body={'message': 'private failure'})
            with self.assertRaises(runtime.RuntimeCollectionError):
                self.client(policy).lookup_container(CID)


if __name__ == '__main__':
    unittest.main()
