"""Stdlib-only one-service fixture for isolated full-configuration restoration."""
import errno
import inspect
import json
from pathlib import Path
import re

CHECKS = ('sentinelPreserved', 'bindReadonly', 'rootReadonly')


def _identity(token):
    if type(token) is not str or not re.fullmatch(r'dw-restore-[0-9a-f]{24}', token):
        raise ValueError('invalid-restore-fixture-token')


def _denied(path):
    try:
        with open(path, 'ab') as stream:
            stream.write(b'forbidden')
    except OSError as error:
        if error.errno == errno.EROFS:
            return True
        raise
    raise RuntimeError('restore fixture write unexpectedly succeeded')


def _checks(token):
    result = {'sentinelPreserved': Path('/sample-data/sentinel.txt').read_text() == token + '\n',
              'bindReadonly': _denied('/sample-config/config.txt'),
              'rootReadonly': _denied('/restore-probe-root')}
    if not all(value is True for value in result.values()):
        raise RuntimeError('restore fixture invariant failed')
    if Path('/sample-config/config.txt').read_text() != token + '\n':
        raise RuntimeError('restore fixture bind changed')
    return result


def _serve(token):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    _checks(token)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ('/health', '/business/probe'):
                self.send_error(404)
                return
            try:
                value = {'token': token, 'version': 'same-image', 'path': self.path,
                         'checks': _checks(token)}
                body = json.dumps(value, sort_keys=True).encode('ascii')
            except (OSError, RuntimeError):
                self.send_error(503)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()


def server_code(token):
    _identity(token)
    return ('import errno,json\nfrom pathlib import Path\n' + inspect.getsource(_denied)
            + inspect.getsource(_checks) + inspect.getsource(_serve) + '\n_serve(' + repr(token) + ')\n')


def health_code(token):
    _identity(token)
    return ("import json,urllib.request\nu='http://127.0.0.1:8080/health'\n"
            "o=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
            "with o.open(u,timeout=5) as r:\n"
            " assert r.status==200 and r.geturl()==u\n raw=r.read(4097)\n assert len(raw)<=4096\n d=json.loads(raw)\n"
            "assert d['token']==" + repr(token) + " and d['path']=='/health' and d['version']=='same-image'\n"
            "assert set(d['checks'])==set(" + repr(CHECKS) + ") and all(v is True for v in d['checks'].values())\n")


def client_code(host, token, expected_ip=None):
    _identity(token)
    if host not in ('backend', '127.0.0.1'):
        raise ValueError('invalid-restore-fixture-host')
    if expected_ip is not None:
        import ipaddress
        if type(expected_ip) is not str:
            raise ValueError('invalid-restore-fixture-address')
        ipaddress.IPv4Address(expected_ip)
    return ("import json,socket,urllib.request\n"
            "host=" + repr(host) + '\ntoken=' + repr(token) + '\nexpected=' + repr(expected_ip) + '\n'
            "addresses={row[4][0] for row in socket.getaddrinfo(host,8080,type=socket.SOCK_STREAM)}\n"
            "assert expected is None or addresses=={expected},'DNS identity mismatch'\n"
            "opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
            "for path in ('/health','/business/probe'):\n"
            " url='http://'+host+':8080'+path\n"
            " with opener.open(url,timeout=5) as response:\n"
            "  assert response.status==200 and response.geturl()==url\n"
            "  raw=response.read(4097)\n  assert len(raw)<=4096\n  value=json.loads(raw)\n"
            " assert set(value)=={'token','version','path','checks'}\n"
            " assert value['token']==token and value['version']=='same-image' and value['path']==path\n"
            " assert set(value['checks'])==set(" + repr(CHECKS) + ") and all(v is True for v in value['checks'].values())\n"
            "print(json.dumps({'token':token,'dnsMatchesExpectedIP':True,'health':True,'business':True,'checks':value['checks']},sort_keys=True))\n")
