"""Trusted runtime collection, issuance and real local TLS transport contracts."""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import timedelta
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import tarfile
import threading
import unittest
from unittest import mock
from urllib.parse import urlencode

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'packs/deployment/scripts/deployment_runtime.py'
spec = importlib.util.spec_from_file_location('deployment_runtime_under_test', SCRIPT)
runtime = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runtime
spec.loader.exec_module(runtime)
IMAGE = 'sha256:' + 'a' * 64
CID = 'b' * 64
SECRET = 'SECRET-DO-NOT-EXPORT'


def catalog():
    return {'schemaVersion': 1, 'images': [{'component': 'web', 'imageId': IMAGE,
            'repository': 'fixture/example', 'sourceSha': 'c' * 40, 'version': '1.2.3',
            'os': 'linux', 'architecture': 'amd64',
            'artifact': {'kind': 'local-build', 'imageId': IMAGE, 'buildSourceSha': 'c' * 40},
            'migration': {'mode': 'none', 'version': None}}]}


def policy(**changes):
    values = dict(endpoint='https://localhost:2376', server_certificate_sha256='d' * 64,
                  daemon_id='fixture-daemon', repository='fixture/example', environment='staging',
                  target='fixture', production=False, project='fixture', components=('web',),
                  catalog_json=json.dumps(catalog()), maximum_age=60, capture_deadline=30)
    values.update(changes)
    return runtime.RuntimePolicy(**values)


def managed_archive(name, content=b'fixture', *, kind=tarfile.REGTYPE):
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.size = len(content) if kind == tarfile.REGTYPE else 0
        archive.addfile(member, BytesIO(content) if member.size else None)
    return buffer.getvalue()


class DockerFixture:
    def __init__(self):
        self.calls = []
        self.info = {'ID': 'fixture-daemon'}
        self.files = {'hosts': b'127.0.0.1 localhost\n', 'hostname': b'fixture-web\n',
                      'resolv.conf': b'nameserver 127.0.0.11\n'}
        self.container = {'HostsPath': '/var/lib/docker/containers/' + CID + '/hosts',
                          'HostnamePath': '/var/lib/docker/containers/' + CID + '/hostname',
                          'ResolvConfPath': '/var/lib/docker/containers/' + CID + '/resolv.conf',
                          'NetworkSettings': {'Networks': {'fixture_default': {'IPAddress': '172.18.0.2'}}}, 'Id': CID, 'Image': IMAGE, 'Path': '/web', 'Args': [],
                          'Config': {'Labels': {'com.docker.compose.project': 'fixture',
                                                'com.docker.compose.service': 'web'},
                                     'Env': ['TOKEN=' + SECRET], 'Volumes': None,
                                     'Cmd': ['/web'], 'User': '1000'},
                          'HostConfig': {'ReadonlyRootfs': True, 'Binds': None,
                                         'VolumesFrom': None, 'Tmpfs': None, 'Privileged': False,
                                         'Devices': [], 'DeviceRequests': None, 'CapAdd': None,
                                         'PidMode': '', 'IpcMode': 'private', 'NetworkMode': 'fixture_default',
                                         'UTSMode': '', 'DeviceCgroupRules': None}, 'Mounts': [],
                          'State': {'Running': True, 'Paused': False, 'Restarting': False,
                                    'Dead': False, 'Status': 'running', 'Pid': 123,
                                    'StartedAt': '2026-01-01T00:00:00.000000000Z'}}
        self.listed = [{'Id': CID, 'Labels': deepcopy(self.container['Config']['Labels'])}]
        self.image = {'Id': IMAGE, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': []}
        self.on_call = None

    def __call__(self, path):
        self.calls.append(path)
        if self.on_call:
            self.on_call(path)
        if path == '/v1.45/info':
            return deepcopy(self.info)
        if path.startswith('/v1.45/containers/json?'):
            return deepcopy(self.listed)
        if path == '/v1.45/containers/' + CID + '/json':
            return deepcopy(self.container)
        if path == '/v1.45/images/' + IMAGE + '/json':
            return deepcopy(self.image)
        for name, content in self.files.items():
            # A second fixture container uses the same fixed managed files.
            if (runtime.re.fullmatch(r'/v1\.45/containers/[0-9a-f]{64}/archive', path.split('?')[0])
                    and path.endswith('/archive?' + urlencode({'path': '/etc/' + name}))):
                return managed_archive(name, content)
        raise AssertionError('Unexpected route')


def collector(p=None, fixture=None):
    p, fixture = p or policy(), fixture or DockerFixture()
    client = runtime.DockerTLSClient(p, ca_file=Path('unused'), cert_file=Path('unused'),
                                     key_file=Path('unused'), transport=fixture)
    return runtime.TrustedDockerCollector(p, client), fixture


class RuntimeTests(unittest.TestCase):
    def test_complete_snapshot_exact_planner_shape_and_private_export(self):
        c, fixture = collector()
        observation = c.collect()
        self.assertIs(c.validate(observation), observation)
        snapshot = observation.snapshot()
        self.assertEqual(set(snapshot), {'schemaVersion', 'kind', 'environment', 'target', 'version',
                                         'components', 'capturedAt', 'provenance'})
        self.assertEqual(set(snapshot['components'][0]), {'name', 'sourceSha', 'artifact',
                                                        'configurationDigest', 'migrationVersion'})
        self.assertRegex(snapshot['version'], r'^runtime-[0-9a-f]{64}$')
        self.assertIsNone(snapshot['components'][0]['migrationVersion'])
        self.assertEqual(observation.to_dict()['versions'], {'web': '1.2.3'})
        for text in (SECRET, 'HostConfig', 'TOKEN=', 'Env', 'ReadonlyRootfs'):
            self.assertNotIn(text, observation.payload_json)
        self.assertEqual(fixture.calls.count('/v1.45/info'), 2)
        self.assertEqual(len(fixture.calls), 14)
        from tests.test_deployment_prepare import planner
        self.assertEqual(planner.manifest(snapshot, 'deployment-snapshot', 'staging', 'fixture', ['web']), snapshot)

    def test_managed_file_contents_and_inspect_paths_are_bound_without_export(self):
        for filename, field in runtime.MANAGED_FILES.items():
            for change_path in (False, True):
                c, fixture = collector()
                previous = c.collect()
                if change_path:
                    fixture.container[field] += '-changed'
                else:
                    fixture.files[filename] = SECRET.encode()
                with self.subTest(filename=filename, path=change_path):
                    with self.assertRaisesRegex(runtime.RuntimeCollectionError, 'changed'):
                        c.recheck(previous)
                    self.assertNotIn(SECRET, c.collect().payload_json)
        self.assertIn('/v1.45/containers/' + CID + '/archive?path=%2Fetc%2Fhosts', fixture.calls)

    def test_unknown_managed_files_and_networks_are_incomplete(self):
        for field in runtime.MANAGED_FILES:
            for value in (None, '', 123, '/tmp/../hosts', '/tmp/hosts\x00'):
                c, fixture = collector()
                fixture.container[runtime.MANAGED_FILES[field]] = value
                observation = c.collect()
                self.assertFalse(observation.to_dict()['complete'])
                with self.assertRaises(runtime.RuntimeCollectionError):
                    c.validate(observation)
        c, fixture = collector()
        fixture.container.pop('NetworkSettings')
        self.assertFalse(c.collect().to_dict()['complete'])

    def test_unsafe_profiles_are_incomplete(self):
        for changes in ({'Privileged': True}, {'Devices': [{'PathOnHost': SECRET}]},
                        {'DeviceRequests': [{'Count': -1}]}, {'CapAdd': ['SYS_ADMIN']},
                        {'CapAdd': ['CAP_SYS_ADMIN']}, {'CapAdd': ['ALL']},
                        {'PidMode': 'host'}, {'IpcMode': 'host'}, {'NetworkMode': 'host'},
                        {'NetworkMode': 'container:external'}, {'Privileged': None},
                        {'DeviceCgroupRules': ['b *:* rwm']}, {'UTSMode': 'host'},
                        {'UTSMode': 'container:external'}):
            c, fixture = collector()
            fixture.container['HostConfig'].update(changes)
            with self.subTest(changes=changes):
                observation = c.collect()
                self.assertFalse(observation.to_dict()['complete'])
                self.assertNotIn(SECRET, observation.payload_json)
                with self.assertRaises(runtime.RuntimeCollectionError):
                    observation.snapshot()
                with self.assertRaises(runtime.RuntimeCollectionError):
                    c.validate(observation)

    def test_live_network_connect_drift_rejects_recheck(self):
        c, fixture = collector()
        previous = c.collect()
        fixture.container['NetworkSettings']['Networks']['external'] = {'IPAddress': SECRET}
        with self.assertRaisesRegex(runtime.RuntimeCollectionError, 'changed'):
            c.recheck(previous)
        self.assertNotIn(SECRET, c.collect().payload_json)

    def test_managed_archive_is_strict_bounded_and_fixed_route(self):
        c, fixture = collector()
        for name in ('/etc/hosts', '../hosts', 'passwd', '/etc/passwd', ''):
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.client.managed_file(CID, name)
        self.assertEqual(fixture.calls, [])
        for identity in ('short', CID + '/..', None):
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.client.managed_file(identity, 'hosts')
        bad = [b'not tar', {}, b'x' * (runtime.MAX_RESPONSE + 1),
               managed_archive('hosts', b'x' * (runtime.MAX_MANAGED_FILE + 1)),
               managed_archive('../hosts'), managed_archive('/etc/hosts'), managed_archive('hostname')]
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.CHRTYPE, tarfile.GNUTYPE_SPARSE):
            bad.append(managed_archive('hosts', kind=kind))
        buffer = BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            for _ in range(2):
                archive.addfile(tarfile.TarInfo('hosts'))
        bad.append(buffer.getvalue())
        buffer = BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo('hosts')
            member.pax_headers = {'comment': SECRET}
            archive.addfile(member)
        bad.append(buffer.getvalue())
        for raw in bad:
            c.client._transport = lambda path: raw
            with self.subTest(type=type(raw)), self.assertRaises(runtime.RuntimeCollectionError) as caught:
                c.client.managed_file(CID, 'hosts')
            self.assertNotIn(SECRET, str(caught.exception))
        for content in (b'', b'x' * runtime.MAX_MANAGED_FILE):
            c.client._transport = lambda path: managed_archive('hosts', content)
            self.assertEqual(c.client.managed_file(CID, 'hosts'), content)

    def test_history_requires_separate_earlier_collector_issuance(self):
        c, _ = collector()
        earlier = c.collect()
        baseline = c.collect()
        later = c.collect()
        self.assertIs(c.validate_history(earlier, before=baseline), earlier)
        for history in (baseline, later, replace(earlier)):
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.validate_history(history, before=baseline)
        with self.assertRaises(runtime.RuntimeCollectionError):
            c.validate_history(earlier, before=replace(baseline))
        with mock.patch.object(runtime.time, 'monotonic', return_value=c._issued[id(earlier)][1]):
            same_time = c.collect()
        # Windows Python 3.10 monotonic ticks can coincide for distinct captures.
        # Collector-owned sequence establishes issuance order independently.
        self.assertIs(c.validate_history(earlier, before=same_time), earlier)
        with self.assertRaises(runtime.RuntimeCollectionError):
            c.validate_history(same_time, before=earlier)

    def test_independent_exports(self):
        c, _ = collector()
        observation = c.collect()
        observation.to_dict()['snapshot']['components'][0]['artifact']['imageId'] = 'tampered'
        observation.snapshot()['components'].clear()
        self.assertEqual(observation.snapshot()['components'][0]['artifact']['imageId'], IMAGE)
        c.validate(observation)

    def test_json_and_dataclass_copy_cannot_recreate_issuance(self):
        c, _ = collector()
        observation = c.collect()
        for forged in (replace(observation), runtime.RuntimeObservation(**asdict(observation)),
                       observation.to_dict(), observation.snapshot(), None):
            with self.subTest(type=type(forged)), self.assertRaises(runtime.RuntimeCollectionError):
                c.validate(forged)
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.validate_history(forged)
        other, _ = collector()
        with self.assertRaises(runtime.RuntimeCollectionError):
            other.validate(observation)

    def test_history_is_authentic_but_does_not_satisfy_current_freshness(self):
        c, _ = collector()
        observation = c.collect()
        with mock.patch.object(runtime, 'utcnow', return_value=runtime.utcnow() + timedelta(seconds=61)):
            c.validate_history(observation)
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.validate(observation)
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.recheck(observation)
        with mock.patch.object(runtime.time, 'monotonic', return_value=c._issued[id(observation)][1] + 61):
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.validate(observation)
        with mock.patch.object(runtime, 'utcnow', return_value=runtime.utcnow() - timedelta(seconds=1)):
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.validate(observation)

    def test_recheck_fresh_evidence_stable_state(self):
        c, _ = collector()
        previous = c.collect()
        current = c.recheck(previous)
        self.assertEqual(previous.state_hash, current.state_hash)
        self.assertEqual(previous.snapshot()['version'], current.snapshot()['version'])
        self.assertNotEqual(previous.evidence_hash, current.evidence_hash)
        self.assertIsNot(previous, current)

    def test_restart_changes_instance_hash_without_changing_runtime_release(self):
        c, fixture = collector()
        previous = c.collect()
        fixture.container['State']['Pid'] = 456
        fixture.container['State']['StartedAt'] = '2026-01-02T00:00:00Z'
        current = c.collect()
        self.assertNotEqual(previous.state_hash, current.state_hash)
        self.assertEqual(previous.snapshot()['version'], current.snapshot()['version'])
        with self.assertRaises(runtime.RuntimeCollectionError):
            c.recheck(previous)
        c.validate_history(previous)

    def test_configuration_changes_are_digest_bound_without_export(self):
        c, fixture = collector()
        previous = c.collect()
        fixture.container['Config']['Env'] = ['TOKEN=new-' + SECRET]
        current = c.collect()
        self.assertNotEqual(previous.state_hash, current.state_hash)
        self.assertNotEqual(previous.snapshot()['version'], current.snapshot()['version'])
        self.assertNotIn(SECRET, current.payload_json)

    def test_missing_catalog_and_unknown_migration_are_incomplete(self):
        for data in ({'schemaVersion': 1, 'images': []}, catalog()):
            if data['images']:
                data['images'][0]['migration']['mode'] = 'unknown'
            c, _ = collector(policy(catalog_json=json.dumps(data)))
            observation = c.collect()
            self.assertFalse(observation.to_dict()['complete'])
            self.assertIsNone(observation.to_dict()['snapshot'])
            for action in (observation.snapshot, lambda: c.validate(observation), lambda: c.validate_history(observation)):
                with self.assertRaises(runtime.RuntimeCollectionError):
                    action()

    def test_unsupported_filesystems_never_claim_verified(self):
        mutations = [lambda x: x['HostConfig'].update(ReadonlyRootfs=False),
                     lambda x: x['HostConfig'].pop('ReadonlyRootfs'),
                     lambda x: x.update(Mounts=[{'Type': 'bind', 'Source': SECRET}]),
                     lambda x: x.pop('Mounts'),
                     lambda x: x['HostConfig'].update(Binds=[SECRET + ':/config']),
                     lambda x: x['HostConfig'].update(VolumesFrom=['other']),
                     lambda x: x['HostConfig'].update(Tmpfs={'/tmp': ''}),
                     lambda x: x['Config'].update(Volumes={'/data': {}})]
        for change in mutations:
            c, fixture = collector()
            change(fixture.container)
            observation = c.collect()
            self.assertFalse(observation.to_dict()['complete'])
            self.assertEqual(observation.to_dict()['verification']['runtime'], 'incomplete')
            self.assertNotIn(SECRET, observation.payload_json)

    def test_actual_inspected_scope_is_checked(self):
        for field in ('com.docker.compose.project', 'com.docker.compose.service'):
            c, fixture = collector()
            fixture.container['Config']['Labels'][field] = 'impostor'
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.collect()
            self.assertFalse(any('/images/' in path for path in fixture.calls))

    def test_daemon_rechecked_in_second_round(self):
        c, fixture = collector()
        def change(path):
            if path == '/v1.45/info' and fixture.calls.count(path) == 2:
                fixture.info['ID'] = 'wrong-daemon'
        fixture.on_call = change
        with self.assertRaises(runtime.RuntimeCollectionError):
            c.collect()

    def test_two_rounds_reject_drift(self):
        for kind in ('pid', 'config', 'image'):
            c, fixture = collector()
            def change(path):
                if path == '/v1.45/info' and fixture.calls.count(path) == 2:
                    if kind == 'pid':
                        fixture.container['State']['Pid'] += 1
                    elif kind == 'config':
                        fixture.container['Config']['User'] = '999'
                    else:
                        fixture.image['Architecture'] = 'arm64'
            fixture.on_call = change
            with self.subTest(kind=kind), self.assertRaises(runtime.RuntimeCollectionError):
                c.collect()

    def test_deadline_fails_closed(self):
        c, _ = collector()
        with mock.patch.object(runtime.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaisesRegex(runtime.RuntimeCollectionError, 'deadline'):
                c.collect()

    def test_invalid_container_and_image_states(self):
        mutations = [lambda x: x.listed.clear(), lambda x: x.listed.append(deepcopy(x.listed[0])),
                     lambda x: x.container.update(Id='e' * 64),
                     lambda x: x.container['State'].update(Running=False),
                     lambda x: x.container['State'].update(Paused=True),
                     lambda x: x.container['State'].update(Restarting=True),
                     lambda x: x.container['State'].update(Dead=True),
                     lambda x: x.container['State'].update(Pid=True),
                     lambda x: x.container['State'].update(StartedAt=SECRET),
                     lambda x: x.container.update(Image='web:latest'),
                     lambda x: x.image.update(Id='sha256:' + 'e' * 64),
                     lambda x: x.image.update(Os='windows'),
                     lambda x: x.image.update(Architecture='arm64')]
        for change in mutations:
            c, fixture = collector()
            change(fixture)
            with self.subTest(change=change), self.assertRaises(runtime.RuntimeCollectionError) as caught:
                c.collect()
            self.assertNotIn(SECRET, str(caught.exception))

    def test_registry_exact_observed_digest_required(self):
        data = catalog()
        ref = 'registry.example/fixture/web@sha256:' + 'e' * 64
        data['images'][0]['artifact'] = {'kind': 'registry', 'ref': ref}
        c, fixture = collector(policy(catalog_json=json.dumps(data)))
        fixture.image['RepoDigests'] = [ref]
        self.assertEqual(c.collect().snapshot()['components'][0]['artifact']['ref'], ref)
        fixture.image['RepoDigests'] = ['registry.example/other/web@sha256:' + 'e' * 64]
        with self.assertRaises(runtime.RuntimeCollectionError):
            c.collect()

    def test_policy_identity_binds_all_scope_and_catalog_fields(self):
        p = policy()
        reordered = json.dumps(json.loads(p.catalog_json), sort_keys=True, indent=2)
        self.assertEqual(p.identity_hash(), replace(p, catalog_json=reordered).identity_hash())
        for changes in ({'production': True}, {'project': 'different'}, {'target': 'other'},
                        {'environment': 'production'}, {'maximum_age': 120}, {'daemon_id': 'other'},
                        {'server_certificate_sha256': 'e' * 64}, {'endpoint': 'https://other:2376'}):
            self.assertNotEqual(p.identity_hash(), replace(p, **changes).identity_hash())
        c, _ = collector(p)
        observation = c.collect()
        c.policy = replace(p, production=True)
        with self.assertRaises(runtime.RuntimeCollectionError):
            c.validate_history(observation)

    def test_strict_catalog_allowlist_and_source_binding(self):
        mutations = [lambda x: x.update(extra=True), lambda x: x.update(schemaVersion=True),
                     lambda x: x['images'][0].update(verified=True),
                     lambda x: x['images'][0].update(repository='wrong/repository'),
                     lambda x: x['images'][0].update(sourceSha='short'),
                     lambda x: x['images'][0].update(version='latest'),
                     lambda x: x['images'][0].update(component='other'),
                     lambda x: x['images'][0]['artifact'].update(imageId='sha256:' + 'f' * 64),
                     lambda x: x['images'][0]['artifact'].update(buildSourceSha='f' * 40),
                     lambda x: x['images'][0]['artifact'].update(extra=True),
                     lambda x: x['images'][0]['migration'].update(version='1'),
                     lambda x: x['images'][0]['migration'].update(mode='reversible'),
                     lambda x: x['images'].append(deepcopy(x['images'][0]))]
        for change in mutations:
            data = catalog()
            change(data)
            with self.subTest(change=change), self.assertRaises(runtime.RuntimeCollectionError):
                policy(catalog_json=json.dumps(data))
        for raw in ('{}', 'null', '{"schemaVersion":1,"schemaVersion":1,"images":[]}', '{invalid'):
            with self.assertRaises(runtime.RuntimeCollectionError):
                policy(catalog_json=raw)

    def test_policy_refuses_discovery_and_ambiguous_scope(self):
        for endpoint in ('unix:///var/run/docker.sock', 'http://localhost:2375', 'https://u:p@localhost',
                         'https://localhost/api', 'https://localhost?token=x', 'https://localhost#x',
                         'https://localhost:0', 'https://localhost:bad', 'https://local host'):
            with self.subTest(endpoint=endpoint), self.assertRaises(runtime.RuntimeCollectionError):
                policy(endpoint=endpoint)
        for changes in ({'components': ['web']}, {'components': ('web', 'web')}, {'components': ()},
                        {'production': 1}, {'maximum_age': True}, {'capture_deadline': 0},
                        {'server_certificate_sha256': 'F' * 64}, {'repository': 'local/path/extra'}):
            with self.assertRaises(runtime.RuntimeCollectionError):
                policy(**changes)

    def test_transport_route_allowlist_and_sanitized_errors(self):
        c, fixture = collector()
        for path in ('/info', '/v1.44/info', '/v1.45/containers/create', '/v1.45/containers/json',
                     '/v1.45/images/web:latest/json', '/v1.45/containers/' + CID + '/archive?path=/'):
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.client.get(path)
        self.assertEqual(fixture.calls, [])
        fixture.on_call = lambda path: (_ for _ in ()).throw(ValueError(SECRET))
        with self.assertRaises(runtime.RuntimeCollectionError) as caught:
            c.collect()
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_multicomponent_mapping_is_complete_and_unselected_services_not_inspected(self):
        data = catalog()
        api = deepcopy(data['images'][0])
        api['component'] = 'api'
        api['sourceSha'] = 'e' * 40
        api['artifact']['buildSourceSha'] = api['sourceSha']
        data['images'].append(api)
        p = policy(components=('web', 'api'), catalog_json=json.dumps(data))
        fixture = DockerFixture()
        second = deepcopy(fixture.container)
        second['Id'] = 'e' * 64
        second['Config']['Labels']['com.docker.compose.service'] = 'api'
        fixture.listed.append({'Id': second['Id'], 'Labels': second['Config']['Labels']})
        fixture.listed.append({'Id': 'f' * 64, 'Labels': {'com.docker.compose.project': 'fixture',
                                                       'com.docker.compose.service': 'unselected'}})
        def transport(path):
            if path == '/v1.45/containers/' + second['Id'] + '/json':
                return deepcopy(second)
            return fixture(path)
        c, _ = collector(p, transport)
        observation = c.collect()
        self.assertEqual([v['name'] for v in observation.snapshot()['components']], ['api', 'web'])
        self.assertEqual(observation.snapshot()['components'][0]['sourceSha'], 'e' * 40)
        self.assertEqual(len(observation.to_dict()['instances']), 2)
        self.assertFalse(any('f' * 64 in path for path in fixture.calls))
        second['State']['Pid'] += 1
        with self.assertRaises(runtime.RuntimeCollectionError):
            c.recheck(observation)

    def test_distinct_duplicate_component_instances_are_refused(self):
        c, fixture = collector()
        fixture.listed.append({'Id': 'e' * 64, 'Labels': deepcopy(fixture.listed[0]['Labels'])})
        original = c.client._transport
        def transport(path):
            if path == '/v1.45/containers/' + 'e' * 64 + '/json':
                value = deepcopy(fixture.container)
                value['Id'] = 'e' * 64
                return value
            return original(path)
        c.client._transport = transport
        with self.assertRaisesRegex(runtime.RuntimeCollectionError, 'exactly one'):
            c.collect()

    def test_list_scope_mismatch_refused_before_any_inspect(self):
        c, fixture = collector()
        fixture.listed[0]['Labels']['com.docker.compose.project'] = 'foreign'
        with self.assertRaises(runtime.RuntimeCollectionError):
            c.collect()
        self.assertEqual(len(fixture.calls), 2)

    def test_semantic_versions_strict_prerelease_and_build_metadata(self):
        for version in ('1.2.3', '0.0.0', '1.2.3-alpha.1+linux.amd64', '1.2.3-0'):
            data = catalog()
            data['images'][0]['version'] = version
            policy(catalog_json=json.dumps(data))
        for version in ('01.2.3', '1.2', '1.2.3-01', '1.2.3-alpha..x', '1.2.3+', 'v1.2.3'):
            data = catalog()
            data['images'][0]['version'] = version
            with self.subTest(version=version), self.assertRaises(runtime.RuntimeCollectionError):
                policy(catalog_json=json.dumps(data))

    def test_production_client_verifies_pin_before_request_and_uses_secure_context(self):
        p = policy(production=True)
        context = mock.Mock()
        certificate = b'fixture-DER'
        matching = replace(p, server_certificate_sha256=hashlib.sha256(certificate).hexdigest())
        with mock.patch.object(runtime.ssl, 'create_default_context', return_value=context), \
                mock.patch.object(runtime.http.client, 'HTTPSConnection') as connection_type:
            connection = connection_type.return_value
            connection.sock.getpeercert.return_value = certificate
            response = connection.getresponse.return_value
            response.status = 200
            response.read1.side_effect = [b'{"ID":"fixture-daemon"}', b'']
            client = runtime.DockerTLSClient(matching, ca_file=Path('ca'), cert_file=Path('cert'), key_file=Path('key'))
            self.assertEqual(client.get('/v1.45/info'), {'ID': 'fixture-daemon'})
            runtime.ssl.create_default_context.assert_called_once_with(cafile='ca')
            context.load_cert_chain.assert_called_once_with(certfile='cert', keyfile='key')
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
            self.assertIs(context.check_hostname, True)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertIsNone(context.keylog_filename)
            self.assertEqual(connection.mock_calls[0], mock.call.connect())
            self.assertEqual(connection.mock_calls[1], mock.call.sock.getpeercert(binary_form=True))
            connection.request.assert_called_once_with('GET', '/v1.45/info', headers={'Accept': 'application/json'})
            connection.close.assert_called_once()
            connection.reset_mock()
            connection.sock.getpeercert.return_value = b'wrong-certificate'
            with self.assertRaises(runtime.RuntimeCollectionError):
                client.get('/v1.45/info')
            connection.request.assert_not_called()
            connection.close.assert_called_once()

    def test_production_managed_archive_uses_pinned_bounded_binary_get(self):
        certificate = b'fixture-DER'
        p = policy(server_certificate_sha256=hashlib.sha256(certificate).hexdigest())
        route = '/v1.45/containers/' + CID + '/archive?path=%2Fetc%2Fhosts'
        with mock.patch.object(runtime.ssl, 'create_default_context'), \
                mock.patch.object(runtime.http.client, 'HTTPSConnection') as connection_type:
            connection = connection_type.return_value
            connection.sock.getpeercert.return_value = certificate
            response = connection.getresponse.return_value
            response.status = 200
            response.read1.side_effect = [managed_archive('hosts', SECRET.encode()), b'']
            client = runtime.DockerTLSClient(p, ca_file=Path('ca'), cert_file=Path('cert'), key_file=Path('key'))
            self.assertEqual(client.managed_file(CID, 'hosts'), SECRET.encode())
            connection.request.assert_called_once_with('GET', route, headers={'Accept': 'application/x-tar'})
            self.assertEqual(response.read1.call_args_list[0], mock.call(65536))
            connection.close.assert_called_once()
            connection.reset_mock()
            connection.sock.getpeercert.return_value = b'wrong'
            with self.assertRaises(runtime.RuntimeCollectionError):
                client.managed_file(CID, 'hosts')
            connection.request.assert_not_called()
            connection.close.assert_called_once()
            connection.sock.getpeercert.return_value = certificate
            response.read1.side_effect = [b'x' * (runtime.MAX_RESPONSE + 1)]
            with self.assertRaises(runtime.RuntimeCollectionError):
                client.managed_file(CID, 'hosts')

    def test_cli_status_and_collect_fail_closed(self):
        for action, status in (('status', 0), ('collect', 1)):
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), action], capture_output=True,
                                    text=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(result.returncode, status, result.stderr)
            data = json.loads(result.stdout)
            self.assertFalse(data['executionAvailable'])
            self.assertFalse(data['productionReady'])
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), 'collect', '--policy', 'x'],
                                capture_output=True, text=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(result.returncode, 2)


class SpecificationRuntimeTests(unittest.TestCase):
    def fixture(self, *, components=('web',)):
        from tests.test_deployment_spec import image_fixture, inspect_fixture
        spec_api = runtime.deployment_spec
        fixture = DockerFixture()
        fixture.image = image_fixture()
        specs = tuple(spec_api.ContainerSpec.from_image(name, fixture.image) for name in components)
        containers = {('b' if index == 0 else 'e') * 64: inspect_fixture(spec, ('b' if index == 0 else 'e') * 64)
                      for index, spec in enumerate(specs)}
        data = catalog()
        data['images'] = [dict(deepcopy(data['images'][0]), component=name) for name in components]
        p = policy(components=components, catalog_json=json.dumps(data),
                   specifications_json=spec_api.specifications_json(specs))
        def transport(path):
            if path.startswith('/v1.45/containers/json?'):
                return [{'Id': cid, 'Labels': value['Config']['Labels']} for cid, value in containers.items()]
            if path.startswith('/v1.45/containers/') and path.endswith('/json'):
                return deepcopy(containers[path.split('/')[3]])
            return fixture(path)
        c, _ = collector(p, transport)
        return c, fixture, containers, specs

    def test_recreation_stable_spec_digest_but_new_state_and_instance(self):
        from tests.test_deployment_spec import inspect_fixture, SECRET as SPEC_SECRET
        c, fixture, containers, specs = self.fixture()
        before = c.collect()
        self.assertEqual(before.snapshot()['components'][0]['configurationDigest'], specs[0].configuration_digest())
        containers.clear()
        replacement = inspect_fixture(specs[0], 'f' * 64)
        replacement['State'].update(Pid=456, StartedAt='2026-02-01T00:00:00.000000000Z')
        replacement['NetworkSettings']['Networks']['bridge'].update(IPAddress='172.17.0.3', EndpointID='d' * 64)
        replacement['Config']['Labels']['dev-workflow.execution-id'] = 'replacement'
        containers[replacement['Id']] = replacement
        fixture.files['hostname'] = b'new-generated-hostname'
        after = c.collect()
        self.assertEqual(before.snapshot()['components'], after.snapshot()['components'])
        self.assertEqual(before.snapshot()['version'], after.snapshot()['version'])
        self.assertNotEqual(before.state_hash, after.state_hash)
        self.assertNotEqual(before.to_dict()['instances'], after.to_dict()['instances'])
        with self.assertRaisesRegex(runtime.RuntimeCollectionError, 'changed'):
            c.recheck(before)
        for private in (SPEC_SECRET, 'HostConfig', 'Env', 'TOKEN=', 'observedConfigurations'):
            self.assertNotIn(private, after.payload_json)

    def test_config_mismatch_and_missing_spec_have_no_snapshot_authority(self):
        changes = [lambda x: x['Config']['Env'].append('DRIFT=1'),
                   lambda x: x['Config']['Labels'].update(custom='changed'),
                   lambda x: x['HostConfig'].update(Memory=128)]
        for change in changes:
            c, _, containers, _ = self.fixture()
            change(containers[CID])
            observation = c.collect()
            self.assertFalse(observation.to_dict()['complete'])
            self.assertIn('specification-mismatch:web', observation.to_dict()['incomplete'])
            with self.assertRaises(runtime.RuntimeCollectionError):
                c.validate(observation)
            with self.assertRaises(runtime.RuntimeCollectionError):
                observation.snapshot()
        c, fixture, containers, _ = self.fixture()
        missing = replace(c.policy, specifications_json=runtime.deployment_spec.specifications_json(()))
        c, _ = collector(missing, c.client._transport)
        observation = c.collect()
        self.assertIn('specification-missing:web', observation.to_dict()['incomplete'])
        with self.assertRaises(runtime.RuntimeCollectionError):
            observation.snapshot()

    def test_raw_generated_drift_retained_for_every_component(self):
        for component in ('web', 'api'):
            for field in ('hostname', 'network', 'path', 'managed', 'label'):
                c, fixture, containers, _ = self.fixture(components=('web', 'api'))
                before = c.collect()
                selected = next(x for x in containers.values() if x['Config']['Labels']['com.docker.compose.service'] == component)
                if field == 'hostname':
                    selected['Config']['Hostname'] = 'generated-drift'
                elif field == 'network':
                    selected['NetworkSettings']['Networks']['bridge']['IPAddress'] = '172.17.0.99'
                elif field == 'path':
                    selected['Path'] = '/different-effective-path'
                elif field == 'managed':
                    fixture.files['hosts'] += b'127.0.0.2 changed'
                else:
                    selected['Config']['Labels']['dev-workflow.execution-id'] = 'changed'
                after = c.collect()
                if field == 'hostname':
                    self.assertFalse(after.to_dict()['complete'])
                else:
                    self.assertEqual(before.snapshot()['components'], after.snapshot()['components'])
                self.assertNotEqual(before.state_hash, after.state_hash)
                with self.subTest(component=component, field=field), self.assertRaises(runtime.RuntimeCollectionError):
                    c.recheck(before)

    def test_profile_policy_binding_canonical_json_and_legacy_hash(self):
        c, _, _, _ = self.fixture()
        p = c.policy
        self.assertEqual(p.identity_hash(), replace(p, specifications_json=json.dumps(json.loads(p.specifications_json), indent=2)).identity_hash())
        self.assertNotEqual(p.identity_hash(), replace(p, specifications_json=None).identity_hash())
        legacy = policy()
        original = asdict(legacy)
        del original['specifications_json']
        original['catalog_json'] = json.loads(legacy.catalog_json)
        self.assertEqual(legacy.identity_hash(), runtime.digest(original))
        for raw in ('{}', 'null', '{invalid', '{"schemaVersion":true,"kind":"docker-spec-catalog","specifications":[]}'):
            with self.assertRaises(runtime.RuntimeCollectionError):
                replace(p, specifications_json=raw)
        from tests.test_deployment_spec import image_fixture
        foreign = runtime.deployment_spec.ContainerSpec.from_image('foreign', image_fixture())
        with self.assertRaises(runtime.RuntimeCollectionError):
            replace(p, specifications_json=runtime.deployment_spec.specifications_json((foreign,)))

    def test_spec_profile_requires_linux_even_if_catalog_allows_other_platform(self):
        c, fixture, _, _ = self.fixture()
        fixture.image['Os'] = 'windows'
        data = json.loads(c.policy.catalog_json)
        data['images'][0]['os'] = 'windows'
        p = replace(c.policy, catalog_json=json.dumps(data))
        c, _ = collector(p, c.client._transport)
        observation = c.collect()
        self.assertIn('unsupported-platform:web', observation.to_dict()['incomplete'])
        with self.assertRaises(runtime.RuntimeCollectionError):
            observation.snapshot()

    def test_wrong_image_spec_not_selected_by_labels(self):
        c, fixture, containers, _ = self.fixture()
        wrong = 'sha256:' + 'f' * 64
        containers[CID]['Image'] = wrong
        fixture.image['Id'] = wrong
        original = c.client._transport
        c.client._transport = lambda path: deepcopy(fixture.image) if path == '/v1.45/images/' + wrong + '/json' else original(path)
        observation = c.collect()
        self.assertFalse(observation.to_dict()['complete'])
        self.assertIn('specification-missing:web', observation.to_dict()['incomplete'])


@unittest.skipUnless(shutil.which('openssl'), 'openssl required for local mTLS fixture')
class LocalTLSRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        def openssl(*args):
            result = subprocess.run(['openssl', *args], cwd=cls.directory, capture_output=True,
                                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            if result.returncode:
                raise AssertionError('Local TLS fixture certificate generation failed')
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem',
                '-days', '1', '-subj', '/CN=Runtime Test CA',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        for name in ('server', 'client', 'wronghost'):
            openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name + '.key', '-out', name + '.csr',
                    '-subj', '/CN=' + ('wrong.invalid' if name == 'wronghost' else 'localhost'))
            ext = cls.directory / (name + '.ext')
            ext.write_text(('subjectAltName=DNS:wrong.invalid\n' if name == 'wronghost' else 'subjectAltName=DNS:localhost\n')
                           + 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                           + 'extendedKeyUsage=' + ('clientAuth' if name == 'client' else 'serverAuth') + '\n')
            openssl('x509', '-req', '-in', name + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
                    '-out', name + '.pem', '-days', '1', '-extfile', name + '.ext')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def start_server(self, certificate='server', response_status=200, response_body=None):
        fixture, calls = DockerFixture(), []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(('GET', self.path, bool(self.connection.getpeercert())))
                value = response_body if response_body is not None else fixture(self.path)
                body = value if isinstance(value, bytes) else json.dumps(value).encode()
                self.send_response(response_status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        try:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        except PermissionError:
            self.skipTest('Sandbox denies loopback socket binding; run this fixture on an unrestricted test host')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.directory / (certificate + '.pem')), str(self.directory / (certificate + '.key')))
        context.load_verify_locations(str(self.directory / 'ca.pem'))
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 3)
        self.addCleanup(server.shutdown)
        der = ssl.PEM_cert_to_DER_cert((self.directory / (certificate + '.pem')).read_text())
        p = policy(endpoint='https://localhost:' + str(server.server_port),
                   server_certificate_sha256=hashlib.sha256(der).hexdigest())
        return p, calls

    def client(self, p):
        return runtime.DockerTLSClient(p, ca_file=self.directory / 'ca.pem',
                                       cert_file=self.directory / 'client.pem', key_file=self.directory / 'client.key')

    def test_real_mtls_collection_is_get_only_and_scoped(self):
        p, calls = self.start_server()
        with mock.patch.dict(os.environ, {'HTTPS_PROXY': 'http://invalid:1', 'DOCKER_HOST': 'unix:///invalid'}):
            c = runtime.TrustedDockerCollector(p, self.client(p))
            observation = c.collect()
            c.validate(observation)
        self.assertTrue(observation.to_dict()['complete'])
        self.assertEqual(len(calls), 14)
        self.assertTrue(all(method == 'GET' and authenticated for method, _, authenticated in calls))
        listed = [path for _, path, _ in calls if '/containers/json?' in path]
        from urllib.parse import parse_qs, urlsplit
        filters = json.loads(parse_qs(urlsplit(listed[0]).query)['filters'][0])
        self.assertEqual(filters, {'label': ['com.docker.compose.project=fixture']})
        self.assertTrue(all(path.startswith('/v1.45/') for _, path, _ in calls))
        self.assertNotIn(SECRET, observation.payload_json)

    def test_pin_mismatch_sends_no_http_request(self):
        p, calls = self.start_server()
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.client(replace(p, server_certificate_sha256='0' * 64)).get('/v1.45/info')
        self.assertEqual(calls, [])

    def test_hostname_verification_sends_no_http_request(self):
        p, calls = self.start_server(certificate='wronghost')
        with self.assertRaises(runtime.RuntimeCollectionError):
            self.client(p).get('/v1.45/info')
        self.assertEqual(calls, [])

    def test_server_requires_client_certificate(self):
        p, calls = self.start_server()
        import http.client
        context = ssl.create_default_context(cafile=str(self.directory / 'ca.pem'))
        from urllib.parse import urlsplit
        connection = http.client.HTTPSConnection('localhost', urlsplit(p.endpoint).port, context=context, timeout=2)
        self.addCleanup(connection.close)
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError, http.client.HTTPException)):
            connection.request('GET', '/v1.45/info')
            connection.getresponse()
        self.assertEqual(calls, [])

    def test_redirect_and_private_error_body_are_never_exposed(self):
        for status in (302, 401, 500):
            p, calls = self.start_server(response_status=status, response_body=SECRET.encode())
            with self.assertRaises(runtime.RuntimeCollectionError) as caught:
                self.client(p).get('/v1.45/info')
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertEqual(len(calls), 1)

    def test_invalid_json_and_oversized_response_fail_closed(self):
        for body in (SECRET.encode(), b'{"ID":"a","ID":"b"}', b'x' * (runtime.MAX_RESPONSE + 1)):
            p, _ = self.start_server(response_body=body)
            with self.assertRaises(runtime.RuntimeCollectionError) as caught:
                self.client(p).get('/v1.45/info')
            self.assertNotIn(SECRET, str(caught.exception))


if __name__ == '__main__':
    unittest.main()
