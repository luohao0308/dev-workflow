"""Real Unix HTTP; explicit systemd/process/credentials/network-command doubles."""
from copy import deepcopy
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import socket
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','packs/deployment/scripts','packs/release/scripts')]
import deployment_compose_host_snapshot_v3_host as host
from deployment_compose_host_commands_v3_host import _left as systemd_time_left
from deployment_compose_resource_inventory_v3_host import CONTAINERS,IMAGES,NETWORKS,VOLUMES


@unittest.skipUnless(os.name=='posix','POSIX Unix sockets required')
class HostTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.run=Path(temp.name);self.main=1234;self.peer=1;self.http=[];self.actions=[]
        self.context=dict(kernelBoot='boot',initStartTicks=99,net='net:[1]',mnt='mnt:[2]',pid='pid:[3]')
        self.service=dict(Id='docker.service',LoadState='loaded',ActiveState='active',SubState='running',
            MainPID=str(self.main),ControlGroup='/system.slice/docker.service',InvocationID='a'*32)
        self.socket=dict(Id='docker.socket',LoadState='loaded',ActiveState='active',SubState='running',
            InvocationID='b'*32,Listen='/run/docker.sock (Stream)')
        self.network=dict(profile='host-network-firewall-v1',netns='net:[1]',mountns='mnt:[2]',
            routes4=[{'dst':'default','gateway':'192.0.2.1'}],routes6=[],ipForward4=1,ipForward6=0,
            firewall4='4'*64,firewall6='6'*64,tools={})
        self.row=dict(Id='a'*64,Name='/protected',Image='sha256:'+'b'*64,RestartCount=0,
            State=dict(StartedAt='2026-01-01T00:00:00Z',Status='running'),Config={'Env':['private-fixture']},
            HostConfig={'Memory':1024},Mounts=[],NetworkSettings={'Networks':{},'Ports':{}})
        self.other_rows={}
        self.engine_post=None
        self.values={'/v1.45/info':{'ID':'production-one','DockerRootDir':'/var/lib/docker'},
            CONTAINERS:[{'Id':'a'*64}],IMAGES:[{'Id':'sha256:'+'b'*64}],NETWORKS:[{'Id':'c'*64}],
            VOLUMES:{'Volumes':[{'Name':'protected-data'}],'Warnings':None}}
        test=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                test.http.append(self.path)
                if self.path.endswith('/json') and '/containers/' in self.path:
                    cid=self.path.split('/')[-2]
                    value=deepcopy(test.other_rows.get(cid,test.row))
                else:
                    value=test.values[self.path]
                if value is not test.values.get(self.path) and type(value.get('State')) is dict:
                    value['State'].setdefault('Health', {})['Log']=[{'End':str(len(test.http))}]
                raw=json.dumps(value).encode();self.send_response(200)
                self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def do_POST(self):
                if test.engine_post is None:
                    self.send_error(405)
                    return
                raw=self.rfile.read(int(self.headers['Content-Length']))
                status,body=test.engine_post(self.path,raw)
                self.send_response(status)
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server=socketserver.UnixStreamServer(str(self.run/'docker.sock'),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=3)))
        original=host._UnixDocker
        def connection(path,timeout):
            self.assertRegex(path,r'^/proc/self/fd/[0-9]+/docker.sock$')
            return original(str(self.run/'docker.sock'),timeout)
        self.patches=[patch.object(host,'_RUN',self.run),patch.object(host,'_UID',os.getuid()),
            patch.object(host.units,'_environment'),patch.object(host,'_context',side_effect=lambda:dict(self.context)),
            patch.object(host,'_root_process'),patch.object(host.units,'_pid_identity',return_value=(self.main,555)),
            patch.object(host,'_peer',side_effect=lambda _:(self.peer,os.getuid(),42)),
            patch.object(host,'_UnixDocker',side_effect=connection),
            patch.object(host,'capture_network',side_effect=lambda _, **kwargs:deepcopy(self.network)),
            patch.object(host,'read_systemd',side_effect=self.command)]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def command(self,name,deadline):
        self.actions.append(name)
        self.assertIn(name,('docker.service','docker.socket'))
        data=self.service if name=='docker.service' else self.socket
        names=host._SERVICE if name=='docker.service' else host._SOCKET
        return ''.join(k+'='+data[k]+'\n' for k in names).encode()
    def observe(self):
        value=host.HostSnapshotV3();self.addCleanup(value.close);return value
    def test_socket_activation_profile_ignores_health_logs_and_exposes_only_digests(self):
        value=self.observe();descriptor=value.descriptor()
        self.assertEqual(descriptor['profile'],host.PROFILE)
        self.assertEqual(value.verify_unchanged(),descriptor['beforeDigest'])
        self.assertNotIn('private-fixture',json.dumps(descriptor))
        self.assertIn('docker.socket',self.actions)
    def test_direct_daemon_peer_needs_no_socket_activation_identity(self):
        self.peer=self.main;value=self.observe();value.verify_unchanged()
        self.assertNotIn('docker.socket',self.actions)
    def test_service_restart_namespace_or_peer_change_rejects(self):
        value=self.observe()
        self.service['InvocationID']='9'*32
        with self.assertRaises(ValueError):value.verify_unchanged()
        self.service['InvocationID']='a'*32;self.context['net']='net:[9]'
        with self.assertRaises(ValueError):value.verify_unchanged()
        self.context['net']='net:[1]';self.peer=999
        with self.assertRaises(ValueError):value.verify_unchanged()
    def test_protected_container_config_restart_or_membership_drift_rejects(self):
        value=self.observe();old=deepcopy(self.row)
        for mutate in (lambda:self.row['HostConfig'].update(Memory=2048),
                lambda:self.row.update(RestartCount=1),lambda:self.row.update(Name='/changed')):
            mutate()
            with self.assertRaises(ValueError):value.verify_unchanged()
            self.row=deepcopy(old)
        self.values[VOLUMES]['Volumes'].append({'Name':'unrelated-new-volume'})
        with self.assertRaises(ValueError):value.verify_unchanged()
    def test_firewall_route_and_forwarding_changes_reject(self):
        value=self.observe();original=deepcopy(self.network)
        for key,bad in (('firewall4','9'*64),('routes6',[{'dst':'::/0'}]),('ipForward4',0)):
            self.network[key]=bad
            with self.assertRaises(ValueError):value.verify_unchanged()
            self.network=deepcopy(original)
    def test_null_container_state_and_incomplete_volume_coverage_reject(self):
        self.row['State']=None
        with self.assertRaises(ValueError):self.observe()
        self.row['State']={'StartedAt':'x','Status':'running'}
        self.values[VOLUMES]['Warnings']=['unavailable']
        with self.assertRaises(ValueError):self.observe()
    def test_wrong_socket_activation_listen_path_or_stopped_service_rejects(self):
        self.socket['Listen']='/run/other.sock (Stream)'
        with self.assertRaises(ValueError):self.observe()
        self.socket['Listen']='/run/docker.sock (Stream)';self.service['ActiveState']='inactive'
        with self.assertRaises(ValueError):self.observe()
    def test_mount_membership_order_is_canonical_but_properties_are_protected(self):
        self.row['Mounts']=[{'Destination':'/z','RW':False},{'Destination':'/a','RW':True}]
        value=self.observe();self.row['Mounts'].reverse();value.verify_unchanged()
        self.row['Mounts'][0]['RW']=False
        with self.assertRaises(ValueError):value.verify_unchanged()
    def test_socket_replacement_and_missing_network_coverage_reject(self):
        value=self.observe();(self.run/'docker.sock').rename(self.run/'old.sock')
        other=socket.socket(socket.AF_UNIX);self.addCleanup(other.close);other.bind(str(self.run/'docker.sock'))
        with self.assertRaises(ValueError):value.verify_unchanged()

    def test_native_write_connection_rejects_different_peer_before_request(self):
        observer = self.observe()
        connection = observer._bound_write_connection(3)
        connection.connect()
        self.addCleanup(connection.close)
        before = list(self.http)
        self.peer = 999
        with self.assertRaises(ValueError):
            connection.request('POST', '/v1.45/containers/' + 'a' * 64 + '/start')
        self.assertEqual(self.http, before)

    def test_native_write_connection_uses_bounded_systemd_deadline_with_long_write_budget(self):
        observer = self.observe()

        def command_with_production_deadline(name, deadline):
            systemd_time_left(deadline)
            return self.command(name, deadline)

        connection = observer._bound_write_connection(120)
        self.addCleanup(connection.close)
        with patch.object(host, 'read_systemd', side_effect=command_with_production_deadline):
            connection.connect()
        connection.request('GET', '/v1.45/info')
        with connection.getresponse() as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.load(response)['ID'], 'production-one')

    def test_frontend_protection_tracks_all_other_containers_and_resource_definitions(self):
        original,candidate='e'*64,'f'*64
        for cid in (original,candidate):
            self.other_rows[cid]=dict(deepcopy(self.row),Id=cid,Name='/'+cid[0])
        self.values[CONTAINERS].append({'Id':original})
        network=self.values[NETWORKS][0]
        network.update(Driver='bridge',Containers={original:{'Name':'old'},self.row['Id']:{'Name':'other'}})
        volume=self.values[VOLUMES]['Volumes'][0]
        volume.update(Driver='local',Options={'device':'protected'})
        observer=self.observe()
        protection=host.ProductionFrontendProtectionV1(
            observer,daemon_id='production-one',original_id=original,protected_ids=(self.row['Id'],))
        baseline=protection.verify()
        self.values[CONTAINERS].append({'Id':candidate})
        self.other_rows[original]['State']['Status']='exited'
        network['Containers'][candidate]={'Name':'new'}
        self.assertEqual(protection.verify(candidate_id=candidate),baseline)
        with self.assertRaises(ValueError):
            protection.verify()
        for target,key,bad in ((self.row,'RestartCount',1),
                (network,'Driver','host'),(volume,'Options',{'device':'different'}),
                (network['Containers'][self.row['Id']],'Name','changed')):
            before=target[key]
            target[key]=bad
            with self.assertRaises(ValueError):
                protection.verify(candidate_id=candidate)
            target[key]=before
        self.values[CONTAINERS].remove({'Id':original})
        with self.assertRaises(ValueError):
            protection.verify(candidate_id=candidate)

    def test_frontend_protection_rejects_incomplete_or_wrong_daemon_scope(self):
        original='e'*64
        self.other_rows[original]=dict(deepcopy(self.row),Id=original)
        self.values[CONTAINERS].append({'Id':original})
        observer=self.observe()
        for daemon,protected in (('different',(self.row['Id'],)),('production-one',('d'*64,))):
            with self.assertRaises(ValueError):
                host.ProductionFrontendProtectionV1(
                    observer,daemon_id=daemon,original_id=original,protected_ids=protected)

    def test_frontend_firewall_rule_is_bound_to_bridge_membership(self):
        network_id = 'a' * 64
        name = 'luohao-blog-prod_default'
        cid = 'b' * 64
        endpoint = dict(NetworkID=network_id, IPAddress='172.19.0.2', EndpointID='endpoint')
        row = dict(Id=cid, State={'Status': 'running'}, HostConfig={'PortBindings': {}},
                   NetworkSettings={'Networks': {name: endpoint}})
        members = {cid: dict(IPv4Address='172.19.0.2/16', EndpointID='endpoint')}
        definitions = {network_id: dict(Name=name, Driver='bridge', Options={}, Containers=members)}
        self.assertEqual(host._frontend_endpoint_rules(definitions, [row]),
                         (b'-A PREROUTING -d 172.19.0.2/32 ! -i br-aaaaaaaaaaaa -j DROP',))
        members['c' * 64] = dict(members[cid])
        with self.assertRaises(ValueError):
            host._frontend_endpoint_rules(definitions, [row])
        members.clear()
        row['State']['Status'] = 'exited'
        endpoint.update(IPAddress='', EndpointID='')
        self.assertEqual(host._frontend_endpoint_rules(definitions, [row]), ())


class ContextTests(unittest.TestCase):
    def test_only_exact_kernel_routes_on_verified_frontend_peers_are_projected(self):
        peer = 'vethabc'
        common = dict(dev=peer, protocol='kernel', flags=[], pref='medium')
        link = dict(common, dst='fe80::/64', metric=256)
        local = dict(common, type='local', dst='fe80::2', table='local', metric=0)
        multicast = dict(common, type='multicast', dst='ff00::/8', table='local', metric=256)
        other = [dict(link, dev='vethdef'), dict(link, dst='::/0'), dict(local, dst='2001:db8::1'),
                 dict(multicast, protocol='static'), dict(link, metric=300)]
        self.assertEqual(host._without_frontend_link_routes([link, local, multicast, *other], {peer}), other)
        self.assertEqual(host._without_frontend_link_routes(other, set()), other)
        with self.assertRaises(ValueError):
            host._without_frontend_link_routes([local, dict(local, dst='fe80::3')], {peer})

    def test_private_namespace_is_not_host_coverage(self):
        links={f'/proc/{pid}/ns/{name}':f'{name}:[1]' for pid in ('self','1') for name in ('net','mnt','pid')}
        links['/proc/self/ns/mnt']='mnt:[2]'
        with patch.object(host.units,'_boot',return_value='boot'),patch.object(host,'_root_process'),\
                patch('deployment_compose_recovery_daemon_v3_host._ticks',return_value=99),\
                patch.object(host.os,'readlink',side_effect=links.__getitem__):
            with self.assertRaises(ValueError):host._context()


if __name__=='__main__':unittest.main()
