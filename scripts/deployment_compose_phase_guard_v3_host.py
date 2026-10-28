"""Trusted GET freshness checks. This object grants no write authority.

The embedding authenticates the bundle, baseline and transport. Volume contents,
application readiness and bind source file types require separate host checks.
"""
from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from urllib.parse import quote
from types import MappingProxyType

from deployment_compose_bundle_v3 import ExecutionBundleV3


def _plain(v):
    if isinstance(v, Mapping):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, (tuple, list)):
        return [_plain(x) for x in v]
    return v


def _immutable(value):
    if type(value) is dict:
        return MappingProxyType({k: _immutable(v) for k, v in value.items()})
    if type(value) is list:
        return tuple(_immutable(v) for v in value)
    return value


def _encode(v):
    return json.dumps(_plain(v), sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def _same(a, b):
    return _encode(a) == _encode(b)


def _fail():
    raise ValueError('compose-phase-guard-v3-blocked') from None


def _lifecycle(row, status=None):
    state = row['State']
    for key in ('Running', 'Paused', 'Restarting', 'Dead'):
        if type(state[key]) is not bool:
            _fail()
    if any(state[key] is not False for key in ('Paused', 'Restarting', 'Dead')):
        _fail()
    if (type(state['Pid']) is not int or state['Pid'] < 0
            or type(row['RestartCount']) is not int or row['RestartCount'] < 0
            or type(state['StartedAt']) is not str or type(state['Status']) is not str):
        _fail()
    actual = state['Status']
    if status is not None and actual != status:
        _fail()
    if actual == 'running':
        if state['Running'] is not True or state['Pid'] <= 0:
            _fail()
    elif actual in ('created', 'exited'):
        if state['Running'] is not False or state['Pid'] != 0:
            _fail()
    else:
        _fail()


def _stable(row):
    _lifecycle(row)
    value = {k: row[k] for k in ('Id', 'Name', 'Image', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings', 'RestartCount')}
    value['State'] = {k: row['State'][k] for k in ('Pid', 'StartedAt', 'Running', 'Paused', 'Restarting', 'Dead', 'Status')}
    value['Health'] = row['State'].get('Health', {}).get('Status')
    return value


def protected_state_digest(row):
    """Hash private stable data; never return inspect material."""
    try:
        return hashlib.sha256(_encode(_stable(row))).hexdigest()
    except Exception:
        _fail()


def baseline_state_bytes(rows):
    """Canonical private original state, excluding health logs and exit details."""
    try:
        if type(rows) is not dict or not rows:
            _fail()
        return _encode({cid: _stable(row) for cid, row in rows.items()})
    except Exception:
        _fail()


def baseline_state_digest(rows):
    return hashlib.sha256(baseline_state_bytes(rows)).hexdigest()


class PhaseGuardV3:
    def __init__(self, bundle, baseline_rows, *, read_json, daemon_version,
                 expected_docker_root=None):
        try:
            if type(bundle) is not ExecutionBundleV3 or type(baseline_rows) is not dict or not callable(read_json):
                _fail()
            if (type(daemon_version) is not dict or set(daemon_version) != {'Version', 'GitCommit'}
                    or any(type(x) is not str or not x for x in daemon_version.values())):
                _fail()
            self._bundle = bundle
            self._v = bundle.to_dict()
            if baseline_state_digest(baseline_rows) != self._v['baselineStateDigest']:
                _fail()
            self._base = deepcopy(baseline_rows)
            self._read = read_json
            self._version = deepcopy(daemon_version)
            self._root = expected_docker_root
            self._services = {s['name']: s for s in self._v['services']}
            self._protected = {p['containerId']: p['staticConfigDigest'] for p in self._v['protectedContainers']}
            ids = set(self._protected) | {s['baselineContainerId'] for s in self._services.values()}
            if set(self._base) != ids:
                _fail()
            for cid, row in self._base.items():
                if row['Id'] != cid or len(cid) != 64 or any(c not in '0123456789abcdef' for c in cid):
                    _fail()
                if row['Config']['Labels']['com.docker.compose.project'] != self._v['identity']['project']:
                    _fail()
                self._healthy(row)
                _stable(row)
            for cid, pin in self._protected.items():
                if protected_state_digest(self._base[cid]) != pin:
                    _fail()
            for s in self._services.values():
                row = self._base[s['baselineContainerId']]
                if row['Name'] != '/' + s['finalName'] or row['Image'] != s['baselineImageId']:
                    _fail()
                self._body(row, s, s['baselineCreateBody'], pending=False)
        except Exception:
            _fail()

    @staticmethod
    def _healthy(row):
        _lifecycle(row, 'running')
        if row['State']['Running'] is not True or row['State']['Health']['Status'] != 'healthy':
            _fail()

    def _body(self, row, s, body, *, pending):
        config = {k: v for k, v in body.items() if k not in ('HostConfig', 'NetworkingConfig')}
        if not _same(row['Config'], config) or row['Image'] != body['Image']:
            _fail()
        host = deepcopy(body['HostConfig'])
        if (pending and self._version == {'Version': '29.8.2', 'GitCommit': '8af9fe3'}
                and host.get('OomKillDisable') is None
                and row['HostConfig'].get('OomKillDisable') is False):
            host['OomKillDisable'] = False
        if not _same(row['HostConfig'], host):
            _fail()
        declarations = body['HostConfig']['Mounts']
        if len(row['Mounts']) != len(declarations):
            _fail()
        by_target = {m['Destination']: m for m in row['Mounts']}
        if len(by_target) != len(declarations):
            _fail()
        for mount in declarations:
            actual = by_target[mount['Target']]
            if actual['Type'] != mount['Type'] or actual['RW'] is not (not mount.get('ReadOnly', False)):
                _fail()
            if mount['Type'] == 'volume':
                if actual['Name'] != mount['Source'] or actual['Driver'] != 'local':
                    _fail()
            elif mount['Type'] == 'bind':
                if actual['Source'] != mount['Source']:
                    _fail()
            else:
                _fail()
        baseline = self._base[s['baselineContainerId']]
        if not _same(row['Mounts'], baseline['Mounts']):
            _fail()
        endpoints = row['NetworkSettings']['Networks']
        if set(endpoints) != set(body['NetworkingConfig']['EndpointsConfig']):
            _fail()
        for name, declared in body['NetworkingConfig']['EndpointsConfig'].items():
            actual = endpoints[name]
            if not _same({k: actual[k] for k in ('NetworkID', 'Aliases')}, declared):
                _fail()
            for key in ('IPAMConfig', 'Links', 'DriverOpts'):
                if actual.get(key) is not None:
                    _fail()
        if row['Config']['Labels']['com.docker.compose.service'] != s['name']:
            _fail()

    def _context(self, snapshot):
        snapshot = _plain(snapshot)
        if set(snapshot) != {'phase_index', 'operation', 'receipts', 'completed_operations'}:
            _fail()
        done, receipts = snapshot['completed_operations'], snapshot['receipts']
        if type(done) is not list or type(receipts) is not dict:
            _fail()
        creates = self._bundle.creation_operations()
        created = [op['service'] for op in done if op.get('phase') == 'create']
        if len(created) != len(set(created)) or set(receipts) != set(created):
            _fail()
        forbidden = set(self._base)
        ids = list(receipts.values())
        if any(type(cid) is not str or len(cid) != 64 or any(c not in '0123456789abcdef' for c in cid) for cid in ids):
            _fail()
        if len(set(ids)) != len(ids) or set(ids) & forbidden:
            _fail()
        ops = self._bundle.resolve_operations(receipts) if len(receipts) == len(creates) else creates
        if len(done) >= len(ops) or not _same(done, ops[:len(done)]):
            _fail()
        op = ops[len(done)]
        if op['method'] == 'GET' or not _same(snapshot['operation'], op):
            _fail()
        if type(snapshot['phase_index']) is not int or snapshot['phase_index'] != sum(o['method'] != 'GET' for o in done):
            _fail()
        return done, receipts

    def capture_phase(self, snapshot):
        """Return private immutable phase facts after two fresh matching reads."""
        try:
            done, receipts = self._context(snapshot)
            first = deepcopy(self._capture(done, receipts))
            second = deepcopy(self._capture(done, receipts))
            if not _same(first, second):
                _fail()
            return _immutable(first)
        except Exception:
            _fail()

    def __call__(self, snapshot):
        self.capture_phase(snapshot)
        return True

    def _capture(self, done, receipts):
        get = self._read
        version = get('/v1.45/version')
        if not _same({k: version[k] for k in self._version}, self._version):
            _fail()
        info = get('/v1.45/info')
        if info['ID'] != self._v['identity']['daemonId'] or (self._root is not None and info['DockerRootDir'] != self._root):
            _fail()
        phases = {(o['phase'], o['service']) for o in done}
        remaining = {s['baselineContainerId'] for s in self._services.values() if ('delete', s['name']) not in phases}
        expected = remaining | set(self._protected) | set(receipts.values())
        filters = json.dumps({'label': ['com.docker.compose.project=' + self._v['identity']['project']]}, sort_keys=True, separators=(',', ':'))
        inventory = get('/v1.45/containers/json?all=1&filters=' + quote(filters, safe=''))
        if type(inventory) is not list or len(inventory) != len(expected) or {r['Id'] for r in inventory} != expected:
            _fail()
        rows = {}
        for cid in sorted(expected):
            row = get('/v1.45/containers/' + cid + '/json')
            if row['Id'] != cid or row['Config']['Labels']['com.docker.compose.project'] != self._v['identity']['project']:
                _fail()
            rows[cid] = row
            if cid in self._protected and protected_state_digest(row) != self._protected[cid]:
                _fail()
        for name, s in self._services.items():
            cid = s['baselineContainerId']
            if cid in remaining:
                row, base = rows[cid], self._base[cid]
                if ('stop', name) not in phases:
                    if not _same(_stable(row), _stable(base)):
                        _fail()
                else:
                    _lifecycle(row, 'exited')
                    for key in ('Id', 'Name', 'Image', 'Config', 'HostConfig', 'Mounts', 'RestartCount'):
                        if not _same(row[key], base[key]):
                            _fail()
                    if not _same(row['State']['StartedAt'], base['State']['StartedAt']) or not _same(row['State']['Pid'], 0):
                        _fail()
                    self._body(row, s, s['baselineCreateBody'], pending=False)
            if name in receipts:
                row = rows[receipts[name]]
                started = ('start', name) in phases
                _lifecycle(row, 'running' if started else 'created')
                self._body(row, s, s['targetCreateBody'], pending=not started)
                expected_name = s['finalName'] if ('rename', name) in phases else 'dwc-' + self._v['operationNonce'][:24] + '-' + name
                if row['Name'] != '/' + expected_name or (not started and row['State']['Running'] is not False):
                    _fail()
                if ('readiness', name) in phases:
                    self._healthy(row)
        resources = {}
        for name, pin in self._v['networks'].items():
            net = get('/v1.45/networks/' + pin['id'])
            if net['Id'] != pin['id'] or net['Name'] != name or net['Labels']['com.docker.compose.project'] != self._v['identity']['project']:
                _fail()
            if not set(net['Containers']).issubset(expected):
                _fail()
            for cid, row in rows.items():
                attached = row['NetworkSettings']['Networks']
                if cid in net['Containers'] and name not in attached:
                    _fail()
                if name in attached and row['State']['Running'] is True and cid not in net['Containers']:
                    _fail()
            resources['network:' + name] = net
        volumes = {m['Name'] for row in self._base.values() for m in row['Mounts'] if m['Type'] == 'volume'}
        for name in sorted(volumes):
            volume = get('/v1.45/volumes/' + quote(name, safe=''))
            if volume['Name'] != name or volume['Driver'] != 'local' or volume.get('Options') not in (None, {}):
                _fail()
            sources = {m['Source'] for r in self._base.values() for m in r['Mounts'] if m['Type'] == 'volume' and m['Name'] == name}
            if sources != {volume['Mountpoint']}:
                _fail()
            resources['volume:' + name] = volume
        return dict(rows={cid: _stable(row) for cid, row in rows.items()}, resources=resources)
