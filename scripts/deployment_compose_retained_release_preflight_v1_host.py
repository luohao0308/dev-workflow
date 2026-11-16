"""Read the registered production frontend and its scope journal over pinned SSH."""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import stat
import subprocess
import sys
import tempfile
import time

from deployment_compose_host_snapshot_v3_host import HostSnapshotV3
from deployment_compose_production_caddy_probe_v1_host import ProductionCaddyProbeV1
from deployment_compose_production_scope_v1_host import _directory, _history, _name, _read
from deployment_compose_retained_native_entry_v1_host import _inspect_registration, scope_registration
from deployment_compose_retained_source_v1_host import MAX_ARCHIVE, MAX_SOURCE, NAME, archive_files
from deployment_compose_witness_store import canonical, hex_value, pairs

_HOST = 'xterminal-server'
_ROOT = Path('/var/lib/dev-workflow/production-frontend')
_MEMBER = 'scripts/deployment_compose_retained_release_preflight_v1_host.py'
_MANIFEST_LIMIT = 16384
_RESPONSE_LIMIT = 32768
_TIMEOUT = 120
_POLICY_DOMAIN = b'dev-workflow:retained-production-frontend-registration:v1\0'
_BASELINE_FIELDS = {
    'manifest', 'frontendPins', 'endpointDigest', 'journalDigest', 'journalTail',
    'caddyProbeReady', 'hostProjectionUnchanged', 'productionDockerWrites', 'policyHash',
}
_PENDING_FIELDS = {'generation', 'requestHash', 'journalDigest'}
_BOOTSTRAP = r'''
import hashlib, io, json, os, re, stat, sys, tempfile, zipfile
from pathlib import Path
if os.geteuid() != 0:
    raise ValueError('registered production inspection requires root')
archive_limit, source_limit = MAX_ARCHIVE_VALUE, MAX_SOURCE_VALUE
mode, digest, arguments = sys.argv[1:]
raw = sys.stdin.buffer.read(archive_limit + 1)
if not 0 < len(raw) <= archive_limit or hashlib.sha256(raw).hexdigest() != digest:
    raise ValueError('inspection archive mismatch')
with tempfile.TemporaryDirectory(prefix='dw-release-inspection-', dir='/var/tmp') as directory:
    root = Path(directory)
    with zipfile.ZipFile(io.BytesIO(raw)) as package:
        files = package.infolist()
        if (not 0 < len(files) <= 1024 or len({item.filename for item in files}) != len(files)
                or sum(item.file_size for item in files) > source_limit):
            raise ValueError('inspection source exceeds bounds')
        for item in files:
            if (not re.fullmatch(NAME_PATTERN, item.filename) or item.filename != item.orig_filename
                    or item.is_dir() or item.flag_bits & 65 or item.file_size < 0
                    or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG)):
                raise ValueError('unsafe inspection source member')
        package.extractall(root)
    sys.path[:0] = [str(root / p) for p in ('scripts', 'core/scripts', 'packs/deployment/scripts', 'packs/release/scripts')]
    from deployment_compose_retained_release_preflight_v1_host import _remote
    _remote(mode, arguments)
'''.replace('MAX_ARCHIVE_VALUE', str(MAX_ARCHIVE)).replace('MAX_SOURCE_VALUE', str(MAX_SOURCE)).replace(
    'NAME_PATTERN', repr(NAME)
)


def _reject():
    raise ValueError('retained-release-host-inspection-rejected') from None


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _manifest():
    for path in (_ROOT, _ROOT / 'work'):
        fd, _ = _directory(path)
        os.close(fd)
    fd = os.open(_ROOT / 'registration.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            _reject()
        raw = stream.read(_MANIFEST_LIMIT + 1)
    if not 0 < len(raw) <= _MANIFEST_LIMIT:
        _reject()
    manifest = json.loads(raw, object_pairs_hook=pairs)
    registration = scope_registration(manifest['scope'])
    if (canonical(manifest) != raw or registration.root != _ROOT / 'scope' or registration.host_id != _HOST
            or manifest['workDirectory'] != str(_ROOT / 'work') or manifest['hostname'] != 'makerhao.cn'
            or manifest['runtimeRepository'] != 'luohao0308/dev-workflow'
            or manifest['runtimeRef'] != 'refs/heads/main' or manifest['reviewEnvironment'] != 'compose-review'):
        _reject()
    return manifest, registration, _digest(_POLICY_DOMAIN + raw)


def _container_id(name):
    inspected = subprocess.run(
        ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', 'inspect', '--format={{.Id}}', name],
        capture_output=True, check=True, timeout=8,
    ).stdout.decode('ascii').strip()
    if not hex_value(inspected):
        _reject()
    return inspected


def _baseline(manifest, registration, policy_hash):
    frontend_id = _container_id('blog-frontend')
    caddy_id = _container_id('blog-caddy')
    if caddy_id != manifest['caddyId']:
        _reject()
    journal = _inspect_registration(registration)
    observer = HostSnapshotV3()
    try:
        def read(path):
            return observer._get(path, time.monotonic() + 5, [2 * 1024 * 1024])

        if observer._info_id != registration.daemon_id:
            _reject()
        version = read('/v1.45/version')
        if (version['Version'], version['GitCommit']) != ('29.8.2', '8af9fe3'):
            _reject()
        frontend = read('/v1.45/containers/' + frontend_id + '/json')
        labels = frontend['Config']['Labels']
        network = frontend['NetworkSettings']['Networks']['luohao-blog-prod_default']['NetworkID']
        if (frontend['Name'] != '/blog-frontend' or frontend['Id'] != frontend_id
                or frontend['State']['Running'] is not True or frontend['State']['Health']['Status'] != 'healthy'
                or network != manifest['networkId'] or labels['com.docker.compose.project'] != registration.project
                or labels['com.docker.compose.service'] != 'frontend'):
            _reject()
        image = read('/v1.45/images/' + frontend['Image'] + '/json')
        source_sha = image['Config']['Labels']['org.opencontainers.image.revision']
        if image['Id'] != frontend['Image'] or re.fullmatch('[0-9a-f]{40}', source_sha) is None:
            _reject()
        if ProductionCaddyProbeV1(observer, caddy_id=caddy_id, network_id=network)(frontend_id) is not True:
            _reject()
        observer.verify_unchanged()
        if _inspect_registration(registration) != journal:
            _reject()
        pins = dict(hostId=registration.host_id, daemonId=registration.daemon_id, project=registration.project,
                    service='frontend', containerId=frontend_id, containerName='blog-frontend',
                    imageId=frontend['Image'], sourceSha=source_sha)
        return dict(manifest=manifest, frontendPins=pins, endpointDigest=observer.descriptor()['endpointDigest'],
                    journalDigest=_digest(journal), journalTail=json.loads(journal.splitlines()[-1]),
                    caddyProbeReady=True, hostProjectionUnchanged=True, policyHash=policy_hash,
                    productionDockerWrites=0)
    finally:
        observer.close()


def _active(registration, baseline_digest, request_hash, generation):
    """Read through the pinned inode while the live worker holds its own lock."""
    root, identity = _directory(registration.root)
    try:
        if identity != registration.root_identity:
            _reject()
        fd = os.open(_name(registration.project), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        try:
            journal = _read(registration, fd)
            if not journal.endswith(b'\n'):
                _reject()
            prefix, _, tail = journal[:-1].rpartition(b'\n')
            closed = prefix + b'\n'
            next_generation, seen = _history(closed, registration)
            if (_digest(closed) != baseline_digest or next_generation != generation or request_hash in seen
                    or tail != canonical(dict(state='started', generation=generation, request=request_hash))
                    or _read(registration, fd) != journal):
                _reject()
        finally:
            os.close(fd)
    finally:
        os.close(root)
    return dict(generation=generation, requestHash=request_hash, journalDigest=_digest(journal))


def _remote(mode, encoded):
    arguments = json.loads(encoded, object_pairs_hook=pairs)
    manifest, registration, policy_hash = _manifest()
    if mode == 'baseline' and arguments == {}:
        result = _baseline(manifest, registration, policy_hash)
    elif (mode == 'active' and type(arguments) is dict
          and set(arguments) == {'policyHash', 'journalDigest', 'requestHash', 'generation'}
          and arguments['policyHash'] == policy_hash and hex_value(arguments['journalDigest'])
          and hex_value(arguments['requestHash'])
          and type(arguments['generation']) is int and 1 <= arguments['generation'] < 2**53):
        result = _active(registration, arguments['journalDigest'], arguments['requestHash'],
                         arguments['generation'])
    else:
        _reject()
    sys.stdout.buffer.write(canonical(result))
    sys.stdout.buffer.flush()


def _probe(archive, mode, arguments):
    if _MEMBER not in archive_files(archive):
        _reject()
    command = 'exec /usr/bin/python3 -I -S -B -c ' + ' '.join(
        shlex.quote(value) for value in (_BOOTSTRAP, mode, _digest(archive), canonical(arguments).decode('ascii'))
    )
    argv = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
            '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
            '-o', 'PermitLocalCommand=no', _HOST, command]
    deadline = time.monotonic() + _TIMEOUT
    received = bytearray()
    with tempfile.TemporaryFile() as stdin:
        stdin.write(archive)
        stdin.seek(0)
        with subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            _reject()
                        chunk = os.read(process.stdout.fileno(), _RESPONSE_LIMIT + 1 - len(received))
                        if not chunk:
                            break
                        received.extend(chunk)
                        if len(received) > _RESPONSE_LIMIT:
                            _reject()
                if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                    _reject()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
    response = json.loads(received, object_pairs_hook=pairs)
    if type(response) is not dict or canonical(response) != received:
        _reject()
    return response


def _validate_baseline(record):
    if type(record) is not dict or set(record) != _BASELINE_FIELDS:
        _reject()
    manifest = record['manifest']
    if (type(manifest) is not dict or record['policyHash'] != _digest(_POLICY_DOMAIN + canonical(manifest))
            or not hex_value(record['journalDigest']) or not hex_value(record['endpointDigest'])
            or type(record['journalTail']) is not dict or type(record['frontendPins']) is not dict
            or record['caddyProbeReady'] is not True or record['hostProjectionUnchanged'] is not True
            or type(record['productionDockerWrites']) is not int or record['productionDockerWrites'] != 0):
        _reject()


def inspect_release_host(archive: bytes) -> dict:
    """Verify the registered host, current healthy frontend and settled journal."""
    record = _probe(archive, 'baseline', {})
    _validate_baseline(record)
    return record


def inspect_active_release(archive: bytes, baseline: dict, *, request_hash: str, generation: int) -> dict:
    """Bind a live started record to the previously verified closed journal."""
    _validate_baseline(baseline)
    if not hex_value(request_hash) or type(generation) is not int or not 1 <= generation < 2**53:
        _reject()
    reply = _probe(archive, 'active', dict(policyHash=baseline['policyHash'],
                                          journalDigest=baseline['journalDigest'],
                                          requestHash=request_hash, generation=generation))
    if (type(reply) is not dict or set(reply) != _PENDING_FIELDS or reply['requestHash'] != request_hash
            or type(reply['generation']) is not int or reply['generation'] != generation
            or not hex_value(reply['journalDigest'])):
        _reject()
    return reply
