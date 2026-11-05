"""Fixture invariants and generated client rejection before endpoint contact."""
import ast
import errno
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent/'support'))
import compose_restore_probe as app

TOKEN = 'dw-restore-'+'a'*24


class RestoreApplicationTests(unittest.TestCase):
    def test_generated_programs_fit_observation_contract_and_compile(self):
        for code in (app.server_code(TOKEN), app.health_code(TOKEN), app.client_code('backend', TOKEN, '172.20.0.3')):
            ast.parse(code)
        self.assertLess(len(app.server_code(TOKEN)), 8192)
        self.assertLess(len(app.health_code(TOKEN)), 1024)

    def test_only_exact_readonly_failure_is_accepted(self):
        for error, accepted in [(errno.EROFS, True), (errno.EACCES, False), (errno.ENOENT, False)]:
            with self.subTest(errno=error), patch('builtins.open', side_effect=OSError(error, 'fixture')):
                if accepted: self.assertTrue(app._denied('/fixture'))
                else:
                    with self.assertRaises(OSError): app._denied('/fixture')
        with patch('builtins.open', return_value=io.BytesIO()), self.assertRaises(RuntimeError):
            app._denied('/fixture')

    def test_sentinel_and_bind_require_exact_token(self):
        with patch.object(app.Path, 'read_text', return_value=TOKEN+'\n'), patch.object(app, '_denied', return_value=True):
            self.assertTrue(all(app._checks(TOKEN).values()))
        with patch.object(app.Path, 'read_text', return_value='foreign\n'), patch.object(app, '_denied', return_value=True):
            with self.assertRaises(RuntimeError): app._checks(TOKEN)
        with patch.object(app.Path, 'read_text', side_effect=[TOKEN+'\n','foreign\n']), patch.object(app, '_denied', return_value=True):
            with self.assertRaises(RuntimeError): app._checks(TOKEN)

    def test_wrong_dns_identity_rejects_before_http(self):
        with patch('socket.getaddrinfo', return_value=[(None,None,None,None,('172.20.0.9',8080))]), \
             patch('urllib.request.build_opener') as opener:
            with self.assertRaisesRegex(AssertionError, 'DNS identity'): exec(app.client_code('backend', TOKEN, '172.20.0.3'), {})
            opener.assert_not_called()

    def test_wrong_health_token_rejected(self):
        response=Mock();response.status=200;response.geturl.return_value='http://127.0.0.1:8080/health'
        response.read.return_value=json.dumps({'token':'foreign','path':'/health','version':'same-image',
                                              'checks':dict.fromkeys(app.CHECKS,True)}).encode()
        opener=Mock();opener.open.return_value.__enter__=Mock(return_value=response);opener.open.return_value.__exit__=Mock(return_value=False)
        with patch('urllib.request.build_opener',return_value=opener), self.assertRaises(AssertionError):
            exec(app.health_code(TOKEN),{})

    def test_invalid_program_identity_rejected(self):
        for token in ('', 'x'*24, None, TOKEN+'\n'):
            with self.assertRaises(ValueError): app.server_code(token)
        with self.assertRaises(ValueError): app.client_code('external.example', TOKEN)
        with self.assertRaises(ValueError): app.client_code('backend', TOKEN, 'not-an-ip')


if __name__ == '__main__': unittest.main()
