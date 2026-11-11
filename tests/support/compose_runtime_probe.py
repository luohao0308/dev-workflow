"""Fixed-path, stdlib-only application for isolated Compose runtime experiments."""
import errno
import json
import pathlib

CHECKS = {
    'backend': ('bind_read', 'bind_readonly', 'root_readonly',
                'sentinel_preserved', 'volume_initial_empty'),
    'frontend': ('bind_read', 'bind_readonly', 'root_readonly',
                 'sentinel_preserved', 'volume_readonly', 'image_include_present'),
}


def _validate_identity(role, token):
    if (role not in CHECKS or not isinstance(token, str) or not token
            or len(token) > 256 or '\x00' in token):
        raise ValueError('invalid fixture identity')


def _deny_write(path):
    try:
        with open(path, 'ab') as stream:
            stream.write(b'forbidden')
    except OSError as error:
        if error.errno == errno.EROFS:
            return True
        raise
    raise RuntimeError('write unexpectedly succeeded')


def startup_check(role, token, *, volume=None, bind=None, root=None, image_include=None):
    _validate_identity(role, token)
    volume = pathlib.Path(volume or ('/usr/local/include' if role == 'backend' else '/data'))
    bind = pathlib.Path(bind or '/probe/config.txt')
    root = pathlib.Path(root or '/runtime-probe-root')
    image_include = pathlib.Path(image_include or '/usr/local/include')
    checks = dict.fromkeys(CHECKS[role], True)
    checks['bind_read'] = bind.read_text() == token + '\n'
    checks['bind_readonly'] = _deny_write(bind)
    checks['root_readonly'] = _deny_write(root)
    sentinel = volume / 'sentinel.txt'
    if role == 'backend':
        checks['volume_initial_empty'] = not any(volume.iterdir())
        if not checks['volume_initial_empty']:
            raise RuntimeError('volume was populated before seeding')
        with sentinel.open('x') as stream:
            stream.write(token + '\n')
    else:
        checks['image_include_present'] = any(image_include.rglob('Python.h'))
        checks['volume_readonly'] = _deny_write(sentinel)
    checks['sentinel_preserved'] = sentinel.read_text() == token + '\n'
    if not all(checks.values()):
        raise RuntimeError('runtime fixture check failed')
    return checks


def _response(role, token, checks):
    volume = pathlib.Path('/usr/local/include' if role == 'backend' else '/data')
    result = dict(checks)
    result['sentinel_preserved'] = (volume / 'sentinel.txt').read_text() == token + '\n'
    if set(result) != set(CHECKS[role]) or not all(value is True for value in result.values()):
        raise RuntimeError('runtime preservation failed')
    return {'role': role, 'token': token, 'checks': result}


def _serve(role, token):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    checks = startup_check(role, token)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/health':
                self.send_error(404)
                return
            try:
                body = json.dumps(_response(role, token, checks), sort_keys=True).encode()
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

    import signal

    def terminate(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()


def make_server_code(role, token):
    _validate_identity(role, token)
    source = pathlib.Path(__file__).read_text()
    return source + '\n_serve(' + repr(role) + ', ' + repr(token) + ')\n'


def _client_code(host, role, token, dns):
    _validate_identity(role, token)
    return '''import json,socket,urllib.request
host,role,token,keys,dns = %r
if dns:
    answers=socket.getaddrinfo(host,8080,type=socket.SOCK_STREAM)
    assert answers, 'DNS returned no endpoints'
url='http://'+host+':8080/health'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise RuntimeError('redirect forbidden')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
with opener.open(url,timeout=5) as response:
    assert response.status==200 and response.geturl()==url
    raw=response.read(4097)
    assert len(raw)<=4096
result=json.loads(raw)
assert set(result)=={'role','token','checks'}
assert result['role']==role and result['token']==token
assert set(result['checks'])==set(keys)
assert all(value is True for value in result['checks'].values())
print(json.dumps(result,sort_keys=True))
''' % ((host, role, token, CHECKS[role], dns),)


def make_health_code(role, token):
    return _client_code('127.0.0.1', role, token, False)


def make_peer_code(peer, token):
    if peer not in ('backend', 'frontend'):
        raise ValueError('invalid fixture peer')
    return _client_code(peer, peer, token, True)
