"""Versioned, idempotent sentinel fixture for namespace-only transitions."""
import json
import pathlib
from compose_runtime_probe import _deny_write


def startup(role, token, version, bootstrap, *, volume=None, bind=None, root=None, include=None):
    if role not in ('backend','frontend') or version not in ('v1','v2') or type(bootstrap) is not bool:
        raise ValueError('invalid-transition-fixture')
    data=pathlib.Path(volume or ('/usr/local/include' if role=='backend' else '/data'))
    config=pathlib.Path(bind or '/probe/config.txt')
    sentinel=data/'sentinel.txt'
    if bootstrap and role=='backend':
        if any(data.iterdir()):raise RuntimeError('NoCopy-volume-not-empty')
        with sentinel.open('x') as stream:stream.write(token+'\n')
    # Retain mode must never create or overwrite a missing/bad sentinel.
    if sentinel.read_text()!=token+'\n':raise RuntimeError('sentinel-changed')
    checks={'sentinel_preserved':True,'bind_read':config.read_text()==token+'\n',
            'bind_readonly':_deny_write(config),'root_readonly':_deny_write(pathlib.Path(root or '/transition-root'))}
    if role=='frontend':
        checks['volume_readonly']=_deny_write(sentinel)
        checks['image_include_present']=any(pathlib.Path(include or '/usr/local/include').rglob('Python.h'))
    if not all(checks.values()):raise RuntimeError('transition-check-failed')
    return checks


def server_code(role,token,version,bootstrap):
    # Include only the shared EROFS helper, not an import requiring a second bind.
    import inspect
    helper='import errno\n'+inspect.getsource(_deny_write)
    source=pathlib.Path(__file__).read_text().replace('from compose_runtime_probe import _deny_write',helper,1)
    return source+"\nserve(%r,%r,%r,%r)\n"%(role,token,version,bootstrap)


def serve(role,token,version,bootstrap):
    import signal
    from http.server import BaseHTTPRequestHandler,HTTPServer
    checks=startup(role,token,version,bootstrap)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            data=pathlib.Path('/usr/local/include' if role=='backend' else '/data')
            if self.path!='/health' or (data/'sentinel.txt').read_text()!=token+'\n':
                self.send_error(503);return
            body=json.dumps({'role':role,'token':token,'version':version,'checks':checks}).encode()
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    def stop(*args):raise SystemExit(0)
    signal.signal(signal.SIGTERM,stop)
    HTTPServer(('0.0.0.0',8080),Handler).serve_forever()


def client_code(host,role,token,version,expected_ip=None):
    return '''import json,socket,urllib.request
host,role,token,version,expected=%r
if expected is not None:
 addresses={x[4][0] for x in socket.getaddrinfo(host,8080,socket.AF_INET,socket.SOCK_STREAM)}
 assert addresses=={expected}, 'unexpected DNS endpoint'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise RuntimeError('redirect-forbidden')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
with opener.open('http://'+host+':8080/health',timeout=5) as response:
 assert response.status==200 and response.geturl()=='http://'+host+':8080/health'
 raw=response.read(4097)
 assert len(raw)<=4096
 value=json.loads(raw)
assert set(value)=={'role','token','version','checks'}
assert (value['role'],value['token'],value['version'])==(role,token,version)
keys={'sentinel_preserved','bind_read','bind_readonly','root_readonly'}
if role=='frontend':keys|={'volume_readonly','image_include_present'}
assert set(value['checks'])==keys and all(x is True for x in value['checks'].values())
print(json.dumps(value))
'''%((host,role,token,version,expected_ip),)
