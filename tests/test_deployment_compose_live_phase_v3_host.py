"""Real Unix HTTP/signatures; Engine, systemd, proc and peer credentials doubled."""
from copy import copy, deepcopy
import hashlib
import json
import os
from pathlib import Path
import pickle
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_recovery_daemon_v3_host as daemon_fixture
BOOT=daemon_fixture.BOOT
from tests.support import compose_restart_material_fixture as restart_fixture
import deployment_compose_recovery_daemon_v3_host as daemon
import deployment_compose_cold_writer_v3_host as cold
from deployment_compose_live_phase_v3_host import LiveRecoveryPhaseCaptureV3
from deployment_compose_witness_store import canonical


@unittest.skipUnless(os.name=='posix' and shutil.which('ssh-keygen'),'POSIX/OpenSSH required')
class LivePhaseTests(unittest.TestCase):
    # Reuse the actual Unix server and its test-only systemd/proc identities,
    # without inheriting unrelated test methods.
    identity=daemon_fixture.DaemonTests.identity
    ticks=daemon_fixture.DaemonTests.ticks
    command=daemon_fixture.DaemonTests.command
    stopped=daemon_fixture.DaemonTests.stopped

    def setUp(self):
        self.case=restart_fixture.RestartFixture();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.case.close_create()
        daemon_fixture.DaemonTests.setUp(self)
        # Keep ssh-keygen and process creation real: isolate only this module's
        # systemctl subprocess dependency, not the shared stdlib module.
        self.patches[-1].stop()
        scoped=patch.object(daemon,'subprocess',SimpleNamespace(run=self.command))
        scoped.start();self.addCleanup(scoped.stop)
        self.info['ID']=self.case.req.daemon_id
        owner=self
        class Inventory:
            def __getitem__(self,path):return owner.case.read(path)
        self.inventory=Inventory()
        self.proc=self.root/'proc-double'
        (self.proc/'self/ns').mkdir(parents=True)
        (self.proc/'self/stat').write_text(str(os.getpid())+' (fixture) S\n')
        (self.proc/'self/ns/pid').touch()
        for pid in (1,self.pid):
            ns=self.proc/str(pid)/'ns';ns.mkdir(parents=True)
            (ns/'pid').symlink_to(self.proc/'self/ns/pid')
        for name in ('net','mnt'):(self.proc/str(self.pid)/'ns'/name).touch()
        patcher=patch.object(cold,'PROC',self.proc);patcher.start();self.addCleanup(patcher.stop)
        self.observer=daemon.ObservedRecoveryDaemonV3(str(self.root),self.case.req.daemon_id,kernel_boot=BOOT)
        self.addCleanup(self.observer.close)
        self.capture=self.make_capture()

    def make_capture(self,**changes):
        args=dict(original_history=self.case.history(),baseline_bytes=self.case.baseline_bytes,
            daemon=self.observer,expected_version=self.case.version)
        args.update(changes)
        return LiveRecoveryPhaseCaptureV3(**args)

    def test_real_unix_capture_two_scans_without_authority_or_mutation(self):
        before=(self.case.store.root/'state.json').read_bytes()
        result=self.capture.capture()
        summary=result.public_summary()
        self.assertTrue(summary['phaseApplicabilityVerified'])
        self.assertTrue(summary['currentDaemonIdentityVerified'])
        for key in ('daemonContinuityVerified','phaseFreshnessVerified','writerQuiescenceVerified',
                'authorityGranted','executionAvailable','runtimePermit','recoveryAuthorized','productionReady'):
            self.assertIs(summary[key],False)
        self.assertEqual(self.http.count('/v1.45/version'),2)
        self.assertEqual(before,(self.case.store.root/'state.json').read_bytes())
        self.assertEqual(self.case.req.expires_at,'2020-01-01T00:00:00Z')
        self.assertEqual(summary['phase_digest'],hashlib.sha256(result.phase_bytes).hexdigest())
        self.assertEqual(json.loads(result.phase_bytes)['rows'].keys(),self.case.rows.keys())
        self.assertNotIn('Env',repr(result));self.assertNotIn('phase_bytes',summary)
        self.assertTrue(all(cmd[:3]==['/usr/bin/systemctl','--system','show'] for cmd in self.calls))

    def test_cleaned_candidate_or_protected_configuration_rejects(self):
        original=deepcopy(self.case.rows)
        del self.case.rows['a'*64]
        with self.assertRaises(ValueError):self.capture.capture()
        self.case.rows=deepcopy(original)
        protected=self.case.bundle.to_dict()['protectedContainers'][0]['containerId']
        self.case.rows[protected]['Config']['Env'].append('DRIFT=private')
        with self.assertRaises(ValueError):self.capture.capture()

    def test_socket_replacement_boot_and_starttime_drift_reject(self):
        original=self.root/'docker.sock';retained=self.root/'retained.sock'
        original.rename(retained)
        import socket
        replacement=socket.socket(socket.AF_UNIX)
        try:
            replacement.bind(str(original))
            with self.assertRaises(ValueError):self.capture.capture()
        finally:
            replacement.close();original.unlink();retained.rename(original)
        with patch.object(daemon.units,'_boot',return_value='22222222-2222-2222-2222-222222222222'):
            with self.assertRaises(ValueError):self.capture.capture()
        with patch.object(daemon.units,'_pid_identity',return_value=(self.pid,999)):
            with self.assertRaises(ValueError):self.capture.capture()

    def test_network_and_volume_changes_reject(self):
        read=self.case.read
        for kind in ('networks','volumes'):
            def drift(path):
                value=read(path)
                if '/'+kind+'/' in path:
                    if kind=='networks':value['Id']='f'*64
                    else:value['Mountpoint']='/wrong'
                return value
            with self.subTest(kind=kind),patch.object(self.case,'read',side_effect=drift):
                with self.assertRaises(ValueError):self.capture.capture()

    def test_version_or_daemon_info_cannot_self_authenticate(self):
        self.case.version={'Version':'future','GitCommit':'other'}
        with self.assertRaises(ValueError):self.capture.capture()
        self.case.version={'Version':'29.8.2','GitCommit':'8af9fe3'}
        for field,value in (('ID','wrong'),('DockerRootDir','/wrong')):
            old=self.info[field];self.info[field]=value
            with self.assertRaises(ValueError):self.capture.capture()
            self.info[field]=old

    def test_second_scan_or_namespace_drift_rejects(self):
        count=[]
        def drift(path):
            if path=='/v1.45/version':
                count.append(path)
                if len(count)==2:self.case.rows['a'*64]['State']['StartedAt']='changed'
        self.on_request=drift
        with self.assertRaises(ValueError):self.capture.capture()
        self.case.rows['a'*64]['State']['StartedAt']='';self.on_request=None
        def namespace(path):
            if path=='/v1.45/version':
                file=self.proc/str(self.pid)/'ns/net'
                file.rename(file.with_suffix('.old')) if file.exists() and not file.with_suffix('.old').exists() else None
                file.touch()
        self.on_request=namespace
        with self.assertRaises(ValueError):self.capture.capture()

    def test_pid_namespace_proc_view_and_root_permissions_reject(self):
        (self.proc/'self/stat').write_text(str(os.getpid()+1)+' (wrong) S\n')
        with self.assertRaises(ValueError):self.capture.capture()
        (self.proc/'self/stat').write_text(str(os.getpid())+' (fixture) S\n')
        ns=self.proc/str(self.pid)/'ns/pid';ns.unlink();ns.touch()
        with self.assertRaises(ValueError):self.capture.capture()
        ns.unlink();ns.symlink_to(self.proc/'self/ns/pid')
        self.root.chmod(0o755)
        try:
            with self.assertRaises(ValueError):self.capture.capture()
        finally:self.root.chmod(0o700)

    def test_stopped_unit_new_invocation_peer_or_pidfile_rejects(self):
        for attack in ('stopped','invocation','peer','pidfile'):
            old=(self.active,self.invocation,self.peer)
            if attack=='stopped':self.active=False
            if attack=='invocation':self.invocation='b'*32
            if attack=='peer':self.peer=(self.pid+1,os.getuid(),42)
            if attack=='pidfile':(self.root/'daemon.pid').write_text(str(self.main))
            with self.subTest(attack=attack),self.assertRaises(ValueError):self.capture.capture()
            self.active,self.invocation,self.peer=old
            (self.root/'daemon.pid').write_text(str(self.pid))

    def test_history_advance_during_get_and_pending_unknown_reject(self):
        advanced=[]
        def advance(path):
            if path=='/v1.45/version' and not advanced:
                advanced.append(True);self.case.index=1;self.case.open_scope()
        self.on_request=advance
        with self.assertRaises(ValueError):self.capture.capture()
        self.on_request=None
        with self.assertRaises(ValueError):self.make_capture().capture()
        self.case.finish(status=0,body=b'',definitive=False)
        with self.assertRaises(ValueError):self.make_capture().capture()

    def test_foreign_objects_baseline_or_cached_identity_reject(self):
        for changes in (dict(daemon=SimpleNamespace()),dict(baseline_bytes=b'{}')):
            with self.subTest(changes=tuple(changes)),self.assertRaises(ValueError):self.make_capture(**changes)
        self.capture._baseline=b'{}'
        with self.assertRaises(ValueError):self.capture.capture()

    def test_copy_pickle_reject_without_closing_original_resources(self):
        for clone in (copy,deepcopy,pickle.dumps):
            with self.subTest(clone=clone.__name__),self.assertRaises(ValueError):clone(self.capture)
        self.assertTrue(self.capture.capture().phaseApplicabilityVerified)

    def test_phase_whitelist_rejects_before_http_and_shared_budget_limits_reads(self):
        before=list(self.http);deadline=time.monotonic()+5
        paths=frozenset({'/v1.45/info'})
        with self.assertRaises(ValueError):
            self.observer._request('/v1.45/containers/foreign/json',deadline,[10000],phase_paths=paths)
        self.assertEqual(before,self.http)
        raw=json.dumps(self.info).encode();budget=[len(raw)+5]
        self.assertEqual(self.observer._request('/v1.45/info',deadline,budget,phase_paths=paths),self.info)
        self.assertEqual(budget,[5])
        with self.assertRaises(ValueError):self.observer._request('/v1.45/info',deadline,budget,phase_paths=paths)
        self.assertEqual(budget,[-1])

    def test_all_capture_gets_share_deadline_and_budget(self):
        requests=[];request=self.observer._request
        def read(path,deadline,budget=None,**kwargs):
            requests.append((deadline,id(budget),budget[0]))
            return request(path,deadline,budget,**kwargs)
        with patch.object(self.observer,'_request',side_effect=read):self.capture.capture()
        self.assertGreater(len(requests),5)
        self.assertEqual(len({r[0] for r in requests}),1)
        self.assertEqual(len({r[1] for r in requests}),1)
        self.assertEqual(requests[0][2],16*1024*1024)
        self.assertTrue(all(a[2]>b[2] for a,b in zip(requests,requests[1:])))

    def test_expired_absolute_deadline_and_invalid_timeout_reject(self):
        for timeout in (True,0,31,float('nan'),float('inf')):
            with self.subTest(timeout=timeout),self.assertRaises(ValueError):self.capture.capture(timeout)
        def delayed(path):
            if path=='/v1.45/version':time.sleep(.12)
        self.on_request=delayed
        with self.assertRaises(ValueError):self.capture.capture(.06)

    def test_exited_producer_new_consumer_independent_owner_keeps_services(self):
        from tests.support import compose_live_phase_fixture as process_fixture
        directory=self.root/'handoff';directory.mkdir(mode=0o700)
        material=self.case.material()
        pins=dict(expectedDigest=hashlib.sha256(material).hexdigest(),expectedContext=self.case.expected_context())
        for name,raw in (('material.private.json',material),('pins.private.json',canonical(pins)),
                ('witness.pub',self.case.public)):
            process_fixture.record(directory/name,raw)
        socket_path=self.root/'witness.sock'
        server,thread,rpc=process_fixture.start_witness_server(self.case,socket_path)
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=3)))
        config=dict(daemonRoot=str(self.root),cgroupRoot=str(self.cg),unit=self.unit,
            pid=self.pid,main=self.main,invocation=self.invocation,witnessSocket=str(socket_path))
        process_fixture.record(directory/'config.private.json',canonical(config))
        script=Path(process_fixture.__file__)
        before=(self.case.store.root/'state.json').read_bytes()
        producer=subprocess.run([sys.executable,str(script),'produce',str(directory)],
            capture_output=True,text=True,timeout=30)
        self.assertEqual(producer.returncode,0,producer.stderr)
        first=json.loads(producer.stdout)
        # subprocess.run has reaped producer before any new consumer is started.
        consumer=subprocess.run([sys.executable,str(script),'consume',str(directory)],
            capture_output=True,text=True,timeout=30)
        self.assertEqual(consumer.returncode,0,consumer.stderr)
        second=json.loads(consumer.stdout)
        self.assertNotEqual(first['producerPid'],second['consumerPid'])
        self.assertTrue(second['summary']['phaseApplicabilityVerified'])
        self.assertFalse(second['summary']['daemonContinuityVerified'])
        self.assertFalse(second['summary']['runtimePermit'])
        for result in (first,second):
            self.assertFalse(result['signingPrivateKeyReceived'])
            self.assertFalse(result['witnessStoreKeyReceived'])
            self.assertTrue(set(result['readonlyRPC'])<=process_fixture.READS)
        self.assertTrue(rpc);self.assertTrue(set(rpc)<=process_fixture.READS)
        self.assertEqual(before,(self.case.store.root/'state.json').read_bytes())
        self.assertTrue(server.fileno()>=0);self.assertTrue(self.active)
        self.assertEqual(self.http.count('/v1.45/version'),2)
        self.assertEqual(set(p.name for p in directory.iterdir()),
            {'material.private.json','pins.private.json','witness.pub','config.private.json',
             'validated-material.private.json','validated-pins.private.json'})

    def test_rejected_http10_responses_close_immediately_without_gc(self):
        import socketserver
        import threading
        from http.server import BaseHTTPRequestHandler
        mode=['budget']
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(503 if mode[0]=='status' else 200)
                self.send_header('Content-Length','invalid' if mode[0]=='headers' else '2')
                self.end_headers();self.wfile.write(b'{}');self.wfile.flush()
        path=self.root/'rejected.sock'
        server=socketserver.UnixStreamServer(str(path),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=3)))
        from deployment_compose_reader_host import _UnixDocker
        complete=daemon._complete_json_response
        for reason in ('budget','status','headers'):
            mode[0]=reason;responses=[];sockets=[]
            def record_response(response):
                responses.append(response);sockets.append(response.fp.raw._sock)
                return complete(response)
            with self.subTest(reason=reason),\
                    patch.object(daemon,'_UnixDocker',side_effect=lambda _,timeout:_UnixDocker(str(path),timeout)),\
                    patch.object(daemon,'_complete_json_response',side_effect=record_response):
                with self.assertRaises(Exception):
                    self.observer._request('/v1.45/info',time.monotonic()+5,[0 if reason=='budget' else 100],
                        phase_paths=frozenset({'/v1.45/info'}))
                self.assertEqual(len(responses),1)
                self.assertTrue(responses[0].isclosed())
                self.assertEqual(sockets[0].fileno(),-1)
