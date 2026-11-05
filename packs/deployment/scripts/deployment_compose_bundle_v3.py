"""Private profile3 value contract for the host coordinator.

The caller must authenticate source, defaults, topology and retention independently.
Content checks and hashes here do not authenticate inputs or admit Engine writes.
Never log canonical bytes or body getters: they can contain credentials.
"""
from copy import deepcopy
import hashlib
import json
import re
from urllib.parse import quote

from deployment_compose_config import map_config
from deployment_compose_host_config import map_host_config
from deployment_compose_image_defaults import ZERO_DEFAULTS, _plain
from deployment_compose_recipe import ENV_NAME

PROFILE = 'compose-application-batch-v1'
PROFILE_VERSION = '3'
DOMAIN = b'dev-workflow:compose-full-body-bundle:v1\0'
RESOLVER = 'compose-full-body-receipt-resolution-v1'
MAX_BYTES = 4 * 1024 * 1024
MAX_SERVICES = 16
MAX_OPERATIONS = 96
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z')
FIELDS = {'schemaVersion', 'profile', 'profileVersion', 'identity', 'services',
          'protectedContainers', 'networks', 'mounts', 'archiveReference',
          'sourceSnapshotDigest', 'retentionBindingDigest', 'baselineStateReference', 'baselineStateDigest', 'operationNonce', 'expiresAt'}
SERVICE = {'name', 'finalName', 'baselineContainerId', 'baselineImageId', 'targetImageId',
           'baselineCreateBody', 'targetCreateBody', 'dependsOn'}


def _fail():
    raise ValueError('invalid-compose-full-body-bundle')


def _closed(v, fields):
    if type(v) is not dict or set(v) != fields:
        _fail()


def _text(v):
    if type(v) is not str or not v or len(v) > 4096 or '\0' in v:
        _fail()


def _hex(v):
    if type(v) is not str or not HEX.fullmatch(v):
        _fail()


def _name(v):
    if type(v) is not str or not NAME.fullmatch(v):
        _fail()


def _encode(v):
    raw = json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False).encode('ascii')
    if len(raw) > MAX_BYTES:
        _fail()
    return raw


def _digest(v):
    return hashlib.sha256(_encode(v)).hexdigest()


def _env(values):
    if type(values) is not list or len(values) > 128:
        _fail()
    keys = []
    for item in values:
        _text(item)
        key, sep, _ = item.partition('=')
        if not sep or not ENV_NAME.fullmatch(key):
            _fail()
        keys.append(key)
    if len(set(keys)) != len(keys):
        _fail()
    return set(keys)


def _inheritance(body, defaults):
    _closed(defaults, set(ZERO_DEFAULTS))
    if defaults['Env'] is not None and type(defaults['Env']) is not list:
        _fail()
    for key in ('Cmd', 'Entrypoint'):
        if defaults[key] is not None and (type(defaults[key]) is not list or any(type(x) is not str for x in defaults[key])):
            _fail()
    if not _env(defaults['Env'] if defaults['Env'] is not None else []) <= _env(body['Env']):
        _fail()
    for key in ('Labels', 'Volumes', 'ExposedPorts', 'Healthcheck'):
        if defaults[key] is not None and defaults[key] != {}:
            _fail()
    if defaults['StopSignal'] != '':
        _fail()
    for key in ('User', 'WorkingDir'):
        if type(defaults[key]) is not str or (body[key] == '' and defaults[key] != ''):
            _fail()
    for key in ('Cmd', 'Entrypoint'):
        vector = body[key]
        if key == 'Entrypoint' and vector is None and defaults[key] is None:
            continue
        if type(vector) is not list or not vector or any(type(x) is not str or not x for x in vector):
            _fail()


class ExecutionBundleV3:
    """Immutable canonical content only; trusted host builder supplies authenticated inputs."""
    __slots__ = ('_canonical', '_digest')

    def __setattr__(self, key, value):
        raise AttributeError('immutable bundle')

    def __delattr__(self, key):
        raise AttributeError('immutable bundle')

    def __init__(self, value, *, authenticated_image_defaults):
        try:
            v = deepcopy(value)
            authenticated_image_defaults = deepcopy(authenticated_image_defaults)
            _plain(authenticated_image_defaults)
            _plain(v)
            _closed(v, FIELDS)
            if type(v['schemaVersion']) is not int or v['schemaVersion'] != 1 or v['profile'] != PROFILE or v['profileVersion'] != PROFILE_VERSION:
                _fail()
            _closed(v['identity'], {'hostId', 'daemonId', 'project', 'sourceIdentity'})
            for item in v['identity'].values():
                _text(item)
            for key in ('sourceSnapshotDigest', 'retentionBindingDigest', 'baselineStateReference', 'baselineStateDigest', 'operationNonce'):
                _hex(v[key])
            _text(v['archiveReference'])
            if type(v['expiresAt']) is not int or not 0 < v['expiresAt'] < 2**53:
                _fail()
            services = v['services']
            if type(services) is not list or not 1 <= len(services) <= MAX_SERVICES:
                _fail()
            if type(authenticated_image_defaults) is not dict:
                _fail()
            names, old_ids, finals = set(), set(), set()
            for s in services:
                _closed(s, SERVICE)
                _name(s['name']); _name(s['finalName']); _hex(s['baselineContainerId'])
                if s['name'] in names or s['baselineContainerId'] in old_ids or s['finalName'] in finals:
                    _fail()
                names.add(s['name']); old_ids.add(s['baselineContainerId']); finals.add(s['finalName'])
                for key in ('baselineImageId', 'targetImageId'):
                    if type(s[key]) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', s[key]):
                        _fail()
                b, t = s['baselineCreateBody'], s['targetCreateBody']
                if type(b) is not dict or type(t) is not dict or not {'HostConfig', 'NetworkingConfig'} <= set(b):
                    _fail()
                config = {k: x for k, x in b.items() if k not in ('HostConfig', 'NetworkingConfig')}
                context = dict(project=v['identity']['project'], service=s['name'], containerId=s['baselineContainerId'], containerName=s['finalName'], imageId=s['baselineImageId'])
                map_config(config, context); map_host_config(b['HostConfig'], context)
                expected = deepcopy(b); expected['Image'] = s['targetImageId']
                if b['Image'] != s['baselineImageId'] or _encode(t) != _encode(expected):
                    _fail()
                target_config = {k: x for k, x in t.items() if k not in ('HostConfig', 'NetworkingConfig')}
                map_config(target_config, {**context, 'imageId': s['targetImageId']})
                map_host_config(t['HostConfig'], {**context, 'imageId': s['targetImageId']})
                _inheritance(t, authenticated_image_defaults[s['name']])
                deps = s['dependsOn']
                if type(deps) is not list or any(type(d) is not str for d in deps) or len(set(deps)) != len(deps):
                    _fail()
                s['dependsOn'] = sorted(deps)
            if set(authenticated_image_defaults) != names:
                _fail()
            protected = v['protectedContainers']
            if type(protected) is not list or len(protected) > 32:
                _fail()
            pins = set()
            for pin in protected:
                _closed(pin, {'containerId', 'staticConfigDigest'})
                _hex(pin['containerId']); _hex(pin['staticConfigDigest'])
                if pin['containerId'] in pins | old_ids:
                    _fail()
                pins.add(pin['containerId'])
            if type(v['networks']) is not dict or not 1 <= len(v['networks']) <= 16:
                _fail()
            for name, net in v['networks'].items():
                _name(name); _closed(net, {'id', 'aliases'}) ; _hex(net['id'])
                if type(net['aliases']) is not dict or set(net['aliases']) != names:
                    _fail()
                for aliases in net['aliases'].values():
                    if type(aliases) is not list or len(aliases) > 32 or len(set(aliases)) != len(aliases):
                        _fail()
                    for alias in aliases:
                        _name(alias)
            if len({n['id'] for n in v['networks'].values()}) != len(v['networks']):
                _fail()
            if type(v['mounts']) is not dict or set(v['mounts']) != names:
                _fail()
            for s in services:
                _validate_resources(s, v)
            order = []
            pending = {s['name']: set(s['dependsOn']) for s in services}
            if any(not deps <= names for deps in pending.values()):
                _fail()
            while pending:
                ready = sorted(n for n, deps in pending.items() if deps <= set(order))
                if not ready:
                    _fail()
                order.extend(ready)
                for n in ready:
                    del pending[n]
            v['services'] = sorted(services, key=lambda s: s['name'])
            v['protectedContainers'] = sorted(protected, key=lambda p: p['containerId'])
            v['resolverContract'] = RESOLVER
            v['resolverRules'] = {'maxResponseBytes': 4096, 'receiptKeys': 'exact-selected-services', 'candidateIds': 'unique-full64-disjoint-baseline-and-protected', 'lookup': 'definitive-create-receipt-only', 'readiness': 'running-and-healthy', 'bodyDigestEncoding': 'sha256-wire-body-empty-bytes-if-absent-otherwise-canonical-json', 'requestDigestEncoding': 'canonical-json-method-path-bodyDigest', 'stopTimeoutSeconds': 10}
            v['resolverRules']['successStatusByPhase'] = dict(create=201, stop=204, delete=204, rename=204, start=204, readiness=200)
            v['imageDefaultsDigests'] = {n: _digest(authenticated_image_defaults[n]) for n in sorted(names)}
            v['operations'] = _symbolic(order)
            if len(v['operations']) > MAX_OPERATIONS:
                _fail()
            raw = _encode(v)
            object.__setattr__(self, '_canonical', raw)
            object.__setattr__(self, '_digest', hashlib.sha256(DOMAIN + raw).hexdigest())
        except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
            _fail()

    @property
    def canonical_bytes(self):
        return self._canonical

    @property
    def digest(self):
        return self._digest

    def to_dict(self):
        return json.loads(self._canonical)

    def public_review(self):
        v = self.to_dict()
        return {'bundleDigest': self.digest, 'profile': PROFILE, 'profileVersion': PROFILE_VERSION,
                'identity': v['identity'], 'expiresAt': v['expiresAt'],
                'protectedContainers': deepcopy(v['protectedContainers']),
                'services': [{k: s[k] for k in ('name', 'finalName', 'baselineContainerId', 'baselineImageId', 'targetImageId', 'dependsOn')} |
                             {'baselineBodyDigest': _digest(s['baselineCreateBody']), 'targetBodyDigest': _digest(s['targetCreateBody'])} for s in v['services']],
                'operations': v['operations'], 'blockers': ['trusted-host-authentication-required', 'coordinator-admission-and-recovery-required']}

    def creation_operations(self):
        """Exact create prefix before candidate IDs exist; no write authority."""
        v = self.to_dict()
        services = {s['name']: s for s in v['services']}
        return [_operation(v, op, services[op['service']], None)
                for op in v['operations'] if op['phase'] == 'create']

    def resolve_operations(self, receipts):
        """Resolve definitive IDs only. Caller must authenticate each create receipt."""
        v = self.to_dict(); services = {s['name']: s for s in v['services']}
        if type(receipts) is not dict or set(receipts) != set(services):
            _fail()
        forbidden = {s['baselineContainerId'] for s in services.values()} | {p['containerId'] for p in v['protectedContainers']}
        for cid in receipts.values():
            _hex(cid)
        if len(set(receipts.values())) != len(receipts) or set(receipts.values()) & forbidden:
            _fail()
        return [_operation(v, op, services[op['service']], receipts[op['service']])
                for op in v['operations']]


def _operation(v, op, service, candidate_id):
    phase = op['phase']
    body = None
    method = 'POST'
    if phase == 'create':
        path = '/v1.45/containers/create?name=' + quote(
            'dwc-' + v['operationNonce'][:24] + '-' + service['name'], safe='')
        body = service['targetCreateBody']
    else:
        cid = service['baselineContainerId'] if phase in ('stop', 'delete') else candidate_id
        path = '/v1.45/containers/' + cid
        if phase == 'delete':
            method = 'DELETE'
            path += '?force=false&v=false'
        elif phase == 'rename':
            path += '/rename?name=' + quote(service['finalName'], safe='')
        elif phase == 'stop':
            path += '/stop?t=10'
        elif phase == 'readiness':
            method = 'GET'
            path += '/json'
        else:
            path += '/' + phase
    body_digest = hashlib.sha256(b'' if body is None else _encode(body)).hexdigest()
    return {**op, 'method': method, 'path': path, 'body': deepcopy(body),
            'bodyDigest': body_digest,
            'expectedStatus': v['resolverRules']['successStatusByPhase'][phase],
            'requestDigest': _digest({'method': method, 'path': path, 'bodyDigest': body_digest}),
            'readinessCondition': 'running-and-healthy' if phase == 'readiness' else None,
            'prerequisitesHealthy': service['dependsOn'] if phase in ('start', 'readiness') else []}


def _symbolic(order):
    return ([{'phase': 'create', 'service': n} for n in order] +
            [{'phase': phase, 'service': n} for phase in ('stop', 'delete') for n in reversed(order)] +
            [{'phase': 'rename', 'service': n} for n in order] +
            [{'phase': phase, 'service': n} for n in order for phase in ('start', 'readiness')])


def _validate_resources(s, v):
    body = s['baselineCreateBody']
    _closed(body['NetworkingConfig'], {'EndpointsConfig'})
    endpoints = body['NetworkingConfig']['EndpointsConfig']
    if type(endpoints) is not dict or set(endpoints) != set(v['networks']):
        _fail()
    for name, endpoint in endpoints.items():
        _closed(endpoint, {'NetworkID', 'Aliases'})
        if endpoint != {'NetworkID': v['networks'][name]['id'], 'Aliases': v['networks'][name]['aliases'][s['name']]}:
            _fail()
    mounts = v['mounts'][s['name']]
    if type(mounts) is not list or len(mounts) > 32 or mounts != body['HostConfig']['Mounts']:
        _fail()
