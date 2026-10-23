"""Real loopback mTLS runtime evidence; GitHub facts are synthetic."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import threading
from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import deployment_host_doctor as doctor
import deployment_host_config as config
from tests import test_deployment_runtime as fixtures

@unittest.skipUnless(shutil.which('openssl') and os.name != 'nt', 'POSIX anonymous TLS pipes and OpenSSL required')
class DoctorRuntimeTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.LocalTLSRuntimeTests.setUpClass.__func__(cls)
        cls.directory = cls.directory.resolve()
        for args in [('req','-newkey','rsa:2048','-nodes','-keyout','writer.key','-out','writer.csr','-subj','/CN=writer'),
                     ('x509','-req','-in','writer.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','writer.pem','-days','1','-extfile','client.ext')]:
            subprocess.run(['openssl',*args], cwd=cls.directory, capture_output=True, check=True, timeout=20)
        for p in cls.directory.iterdir():
            if p.is_file(): p.chmod(0o600)
        for name in ('store-key','gate-key','token'):
            p=cls.directory/name; p.write_bytes(b'fixture-private-material-32-bytes-only'); p.chmod(0o600)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def fixture(self, certificate='server'):
        collector, _, _, _ = fixtures.SpecificationRuntimeTests().fixture()
        transport=collector.client._transport
        calls=[]
        class Handler(BaseHTTPRequestHandler):
            def handle(self):
                try:
                    super().handle()
                except ConnectionResetError:
                    pass  # A pin rejection closes TLS before sending HTTP.
            def do_GET(self):
                calls.append(('GET',self.path,bool(self.connection.getpeercert())))
                value=transport(self.path)
                raw=value if isinstance(value,bytes) else json.dumps(value).encode()
                self.send_response(200); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def do_POST(self):
                calls.append(('POST',self.path,False)); self.send_error(405)
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.directory/(certificate+'.pem')),str(self.directory/(certificate+'.key')))
        ctx.load_verify_locations(str(self.directory/'ca.pem')); ctx.verify_mode=ssl.CERT_REQUIRED
        server.socket=ctx.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        self.addCleanup(server.server_close); self.addCleanup(thread.join,3); self.addCleanup(server.shutdown)
        pin=lambda name:hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.directory/(name+'.pem')).read_text())).hexdigest()
        runtime=replace(config.RuntimePolicy(**asdict(collector.policy)), endpoint='https://localhost:'+str(server.server_port),server_certificate_sha256=pin(certificate))
        store=config.StorePolicy(42,'store','key',runtime)
        gate=config.GatePolicy('store','key',config.digest(store._scope()),pin('writer'))
        execution=config.ExecutionPolicy(runtime,pin('writer'),history_policy_hash=store.identity_hash(),gateway_policy_hash=gate.identity_hash())
        template=json.loads((Path(__file__).resolve().parents[1]/'examples/deployment-host/host.example.json').read_text())
        document=dict(template,runtime=asdict(runtime),store={k:v for k,v in asdict(store).items() if k!='runtime_policy'},gate=asdict(gate),execution={k:v for k,v in asdict(execution).items() if k!='runtime_policy'})
        for field,name in dict(store_key_file='store-key',gate_key_file='gate-key',ca_file='ca.pem',reader_cert_file='client.pem',reader_key_file='client.key',writer_cert_file='writer.pem',writer_key_file='writer.key').items(): document[field]=str(self.directory/name)
        document['github']['credential_file']=str(self.directory/'token')
        path=self.directory/'config.json'; path.write_text(json.dumps(document)); path.chmod(0o600)
        return config.load_host_config(path),calls
    def diagnose(self,bundle):
        def github(host,port,path,*args,**kwargs):
            self.assertEqual(host,'api.github.com')
            if '/git/commits/' in path: return {'sha':path.split('/')[-1]}
            if '/environments/' in path:
                return dict(name=path.split('/')[-1],can_admins_bypass=False,protection_rules=[dict(type='required_reviewers',prevent_self_review=True,reviewers=[dict(type='User',reviewer={'id':1})])])
            slug=path.removeprefix('/repos/')
            ids={bundle.runtime_policy.repository:42,bundle.github['host_repository']:43,bundle.github['ledger_repository']:44}
            return {'id':ids[slug],'full_name':slug}
        with patch.object(doctor,'_get',side_effect=github),patch.dict(os.environ,{'SSLKEYLOGFILE':''}):
            report=doctor.diagnose(bundle,online=True)
        return next(c for c in report['checks'] if c['id']=='runtime'),report
    def test_complete_real_mtls_two_rounds(self):
        bundle,calls=self.fixture()
        check,report=self.diagnose(bundle)
        self.assertEqual(check['status'],'pass',report)
        self.assertTrue(all(m=='GET' and authenticated for m,_,authenticated in calls))
        for fragment in ('/info','/containers/json?','/images/','/archive?'):
            self.assertGreaterEqual(sum(fragment in p for _,p,_ in calls),2)
        self.assertNotIn(fixtures.SECRET,str(report))
    def test_bad_peer_pin_sends_no_get(self):
        bundle,calls=self.fixture()
        bundle=replace(bundle,runtime_policy=replace(bundle.runtime_policy,server_certificate_sha256='0'*64))
        check,_=self.diagnose(bundle)
        self.assertNotEqual(check['status'],'pass'); self.assertEqual(calls,[])
    def test_bad_hostname_sends_no_get(self):
        bundle,calls=self.fixture('wronghost')
        check,_=self.diagnose(bundle)
        self.assertNotEqual(check['status'],'pass'); self.assertEqual(calls,[])
    def test_untrusted_ca_sends_no_get(self):
        bundle,calls=self.fixture()
        bundle=replace(bundle,ca_file=self.directory/'client.pem')
        check,_=self.diagnose(bundle)
        self.assertNotEqual(check['status'],'pass'); self.assertEqual(calls,[])
    def test_wrong_client_usage_sends_no_get(self):
        bundle,calls=self.fixture()
        bundle=replace(bundle,reader_cert_file=self.directory/'server.pem',reader_key_file=self.directory/'server.key')
        check,_=self.diagnose(bundle)
        self.assertNotEqual(check['status'],'pass'); self.assertEqual(calls,[])
