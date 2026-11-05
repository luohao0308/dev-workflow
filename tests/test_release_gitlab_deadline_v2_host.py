"""Real cold TLS connection boundary; local server is not GitLab acceptance."""
import http.server
import os
from pathlib import Path
import shutil
import ssl
import socket
import threading
import time
import unittest
from unittest.mock import patch

from tests import test_release_gitlab_execute_v2_host as fixture
import release_gitlab as gitlab
from tests import test_deployment_compose_write_gateway_v3_host as tls_fixture


@unittest.skipUnless(os.name=='posix' and shutil.which('openssl'),'POSIX local TLS fixture')
class DeadlineTLSBoundaryTests(unittest.TestCase):
    setUpClass=classmethod(tls_fixture.WriteGatewayTests.setUpClass.__func__)
    tearDownClass=classmethod(tls_fixture.WriteGatewayTests.tearDownClass.__func__)

    def setUp(self):
        self.requests=[];owner=self
        server_tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(self.directory/'server.pem',self.directory/'server.key')
        class Handler(http.server.BaseHTTPRequestHandler):
            def handle(self):
                try:super().handle()
                except ConnectionResetError:pass  # Expected peer close on expired handshake.
            def do_POST(self):
                owner.requests.append(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(201);self.send_header('Content-Length','0');self.end_headers()
            def log_message(self,*args):pass
        class Server(http.server.HTTPServer):
            def get_request(self):
                connection,address=super().get_request()
                return server_tls.wrap_socket(connection,server_side=True),address
        self.server=Server(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        def cleanup():self.server.shutdown();self.server.server_close();self.thread.join(3)
        self.addCleanup(cleanup)
        self.context=ssl.create_default_context(cafile=self.directory/'ca.pem')

    def connection(self,deadline):
        connection=gitlab._DeadlineHTTPSConnection('localhost',port=self.server.server_port,deadline=deadline,timeout=2,context=self.context)
        self.addCleanup(connection.close);return connection

    def test_cold_tls_completion_after_deadline_sends_zero_http_requests(self):
        deadline=time.monotonic()+.15;connect=gitlab.HTTPSConnection.connect;handshake=[]
        def delayed(connection):
            connect(connection);handshake.append(True)
            time.sleep(max(0,deadline-time.monotonic())+.03)
        with patch.object(gitlab.HTTPSConnection,'connect',delayed),self.assertRaises(gitlab.GitLabUnavailable):
            self.connection(deadline).request('POST','/mock-tag',body=b'{}')
        self.assertEqual(handshake,[True])
        self.assertEqual(self.requests,[])

    def test_unexpired_cold_tls_sends_exactly_one_request(self):
        connection=self.connection(time.monotonic()+2)
        connection.request('POST','/mock-tag',body=b'{}')
        self.assertEqual(connection.getresponse().status,201)
        self.assertEqual(self.requests,[b'{}'])

    def test_callback_deadline_values_rejected_before_mock_transport(self):
        calls=[]
        client=gitlab.GitLabClient('test',transport=lambda *args:(calls.append(args) or (201,{},{})))
        for value in (True,False,float('nan'),float('inf'),'deadline',time.monotonic()-1):
            with self.subTest(value=value),self.assertRaises(gitlab.GitLabUnavailable):
                client.request('POST','/projects/42/repository/tags',{},before_send=lambda:value)
        self.assertEqual(calls,[])
        client.request('POST','/projects/42/repository/tags',{},before_send=lambda:None)
        self.assertEqual(len(calls),1)

    def test_client_deadline_handler_blocks_real_cold_tls_before_http(self):
        client=gitlab.GitLabClient('test-only',timeout=2)
        deadline=time.monotonic()+.15;callbacks=[]
        initialize=gitlab.HTTPSConnection.__init__;connect=gitlab.HTTPSConnection.connect
        create=socket.create_connection
        context=ssl.create_default_context(cafile=self.directory/'ca.pem')
        context.check_hostname=False  # Local CA test endpoint; production context is unchanged.
        def init(connection,*args,**kwargs):
            kwargs['context']=context
            return initialize(connection,*args,**kwargs)
        def local(address,*args,**kwargs):
            self.assertEqual(address[0],'gitlab.com')
            return create(('127.0.0.1',self.server.server_port),*args,**kwargs)
        def delayed(connection):
            connect(connection)
            time.sleep(max(0,deadline-time.monotonic())+.03)
        sends=[];sendall=ssl.SSLSocket.sendall
        def tracked_send(sock,data,*args,**kwargs):
            sends.append(len(data));return sendall(sock,data,*args,**kwargs)
        def before():callbacks.append(True);return deadline
        with patch.object(gitlab.HTTPSConnection,'__init__',init),patch.object(gitlab.HTTPSConnection,'connect',delayed),patch.object(socket,'create_connection',local),patch.object(ssl.SSLSocket,'sendall',tracked_send):
            with self.assertRaises(gitlab.GitLabUnavailable):
                client.request('POST','/projects/42/repository/tags',dict(tag_name='v1.2.3',ref='a'*40),before_send=before)
        self.assertEqual(callbacks,[True])
        self.assertEqual(sends,[])
        self.assertEqual(self.requests,[])
