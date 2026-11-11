"""Fixed SSH manager for one owned retained-production worker session."""

import base64
import hashlib
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import time

from deployment_compose_retained_native_channel_v1_host import (
    BLOCKED_FIELDS, CONFIGURE, FAILURE_STAGES, REVIEW_COMMAND_TIMEOUT,
)
from deployment_compose_retained_native_entry_v1_host import scope_registration
from deployment_compose_retained_production_unit_v1_host import RetainedProductionUnitV1
from deployment_compose_production_scope_v1_host import ScopeRegistrationV1
from deployment_compose_retained_source_v1_host import (
    CHANNEL_MEMBER, CONFIG_FIELDS, ENTRYPOINT, PROFILE, archive_files, production_bootstrap,
)
from deployment_compose_v3_channel_worker import read_frame, write_frame
from deployment_compose_witness_store import hex_value

MANAGER = 'deployment_compose_retained_ssh_v1_host.run_manager'
MANAGER_FIELDS = CONFIG_FIELDS | {'expectedEndpointDigest'}
SESSION_SECONDS = 3600
WITNESS_METHODS = {
    'register', 'read', 'check', 'append_event', 'chain_status', 'events_after', 'transition_successor',
}


def reject():
    raise ValueError('retained-production-ssh-rejected') from None


def manager_bootstrap(source_sha, archive_digest):
    code = production_bootstrap(source_sha, archive_digest)
    substitutions = (
        (f'ENTRYPOINT={ENTRYPOINT!r}\n', f'ENTRYPOINT={MANAGER!r}\n'),
        (f'CONFIG_FIELDS=set({sorted(CONFIG_FIELDS)!r})', f'CONFIG_FIELDS=set({sorted(MANAGER_FIELDS)!r})'),
        ('from deployment_compose_retained_native_entry_v1_host import run_production',
         'from deployment_compose_retained_ssh_v1_host import run_manager'),
        ('run_production(config,archive,r)', 'run_manager(config,archive,r)'),
    )
    for old, new in substitutions:
        if code.count(old) != 1:
            reject()
        code = code.replace(old, new)
    return code


def ssh_argv(alias, source_sha, archive_digest):
    if type(alias) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', alias):
        reject()
    command = 'exec /usr/bin/python3 -I -S -u -c ' + shlex.quote(manager_bootstrap(source_sha, archive_digest))
    return [
        'ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
        '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', '-o', 'ClearAllForwardings=yes',
        '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'PermitLocalCommand=no', alias, command,
    ]


def _scope(registration):
    if type(registration) is not ScopeRegistrationV1:
        reject()
    value = dict(root=str(registration.root), rootIdentity=list(registration.root_identity),
                 journalIdentity=list(registration.journal_identity), hostId=registration.host_id,
                 project=registration.project, daemonId=registration.daemon_id)
    if scope_registration(value) != registration:
        reject()
    return value


def _path(value):
    if type(value) is not str or len(value) > 4096 or '\0' in value:
        reject()
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or str(path) != value:
        reject()
    return path


def _remaining(deadline, limit):
    left = min(deadline - time.monotonic(), limit)
    if left <= 0:
        raise TimeoutError('retained-production-ssh-deadline')
    return left


def _startup(value, *, scope, source_sha, archive_digest, endpoint_digest):
    if type(value) is not dict or not hex_value(value.get('channelNonce')):
        reject()
    source = value.get('source')
    if type(source) is not dict or not hex_value(source.get('originDigest')):
        reject()
    expected = dict(kind='production-startup', channelNonce=value['channelNonce'], scope=scope,
                    endpointDigest=endpoint_digest, source=dict(profile=PROFILE, sourceSha=source_sha,
                    archiveDigest=archive_digest, channelNonce=value['channelNonce'],
                    originDigest=source['originDigest']))
    if value != expected:
        reject()
    return expected


def start_retained_ssh(alias, archive, *, source_sha, expected_archive_digest, registration,
                       work_directory, expected_endpoint_digest):
    """Start the fixed manager once and return its validated native startup frame."""
    files = archive_files(archive)
    if (hashlib.sha256(archive).hexdigest() != expected_archive_digest
            or not hex_value(expected_endpoint_digest) or CHANNEL_MEMBER not in files
            or 'scripts/deployment_compose_retained_ssh_v1_host.py' not in files):
        reject()
    _path(str(work_directory))
    argv = ssh_argv(alias, source_sha, expected_archive_digest)
    scope = _scope(registration)
    config = dict(entrypoint=MANAGER, sourceSha=source_sha, archiveDigest=expected_archive_digest,
                  channelNonce=secrets.token_hex(32), scope=scope, mode='channel',
                  workDirectory=str(work_directory), expectedEndpointDigest=expected_endpoint_digest,
                  archiveBase64=base64.b64encode(archive).decode('ascii'))
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, bufsize=0)
    try:
        write_frame(process.stdin, config, timeout=20)
        startup = _startup(read_frame(process.stdout, timeout=90), scope=scope, source_sha=source_sha,
                           archive_digest=expected_archive_digest, endpoint_digest=expected_endpoint_digest)
        if process.poll() is not None:
            reject()
        return process, startup
    except BaseException:
        # EOF allows the original remote manager to run its finally block.
        process.stdin.close()
        try:
            process.wait(timeout=35)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        finally:
            process.stdout.close()
        raise


class _Relay:
    """Bounded, directional relay. The native unit and controller verify content."""

    def __init__(self, stdin, stdout, process, nonce, deadline):
        self.stdin, self.stdout = stdin, stdout
        self.process, self.nonce, self.deadline = process, nonce, deadline

    def _read(self, stream, shapes, limit):
        frame = read_frame(stream, timeout=_remaining(self.deadline, limit))
        if type(frame) is not dict or frame.get('channelNonce') != self.nonce:
            reject()
        kind = frame.get('kind')
        if type(kind) is not str or kind not in shapes or set(frame) != {'kind', 'channelNonce'} | shapes[kind]:
            reject()
        return frame

    def _write(self, stream, frame):
        write_frame(stream, frame, timeout=_remaining(self.deadline, 30))

    def _controller(self, shapes, limit=900):
        return self._read(self.stdin, shapes, limit)

    def _worker(self, shapes, limit=120):
        return self._read(self.process.stdout, shapes, limit)

    def _rpc(self, rpc):
        service, method, request = rpc['service'], rpc['method'], rpc['request']
        if type(method) is not str or type(request) is not dict:
            reject()
        if service == 'intent':
            verb = request.get('method')
            if method != 'authorize' or verb not in ('validate', 'consume', 'check'):
                reject()
        elif service == 'witness' and method in WITNESS_METHODS:
            verb = None
        else:
            reject()
        self._write(self.stdout, rpc)
        if verb == 'consume':
            fields = {'nonce', 'requestHash', 'scopeGeneration'}
            challenge = self._controller({'consume-check': fields}, limit=90)
            if (not hex_value(challenge['nonce']) or not hex_value(challenge['requestHash'])
                    or challenge['requestHash'] != request.get('requestHash')
                    or type(challenge['scopeGeneration']) is not int
                    or challenge['scopeGeneration'] <= 0
                    or challenge['scopeGeneration'] != request.get('generation')):
                reject()
            self._write(self.process.stdin, challenge)
            confirmed = self._worker({'consume-confirmed': fields}, limit=90)
            if confirmed != dict(challenge, kind='consume-confirmed'):
                reject()
            self._write(self.stdout, confirmed)
        reply = self._controller({'reply': {'response'}}, limit=90)
        self._write(self.process.stdin, reply)

    def _execute(self, *, rollback):
        command = self._controller({'execute': {'request'}, 'finish': set()}, limit=REVIEW_COMMAND_TIMEOUT)
        self._write(self.process.stdin, command)
        if command['kind'] == 'finish':
            return False
        executed = False
        for _ in range(4096):
            shapes = {'blocked': BLOCKED_FIELDS}
            if not executed:
                shapes.update(rpc={'service', 'method', 'request'}, executed={'result'})
            if not rollback:
                shapes['restore-prepared'] = {'review'}
            frame = self._worker(shapes, limit=180)
            kind = frame['kind']
            if kind == 'rpc':
                self._rpc(frame)
            elif kind == 'executed':
                self._write(self.stdout, frame)
                if rollback:
                    return False
                executed = True
            elif kind == 'blocked':
                stage = frame['failureStage']
                if (frame['knownPrefix'] is not False or type(stage) is not str or stage not in FAILURE_STAGES
                        or executed != (stage == 'prepare-restore')):
                    reject()
                self._write(self.stdout, frame)
                return False
            else:
                self._write(self.stdout, frame)
                return True
        reject()

    def run(self):
        self._write(self.process.stdin, self._controller({'configure': CONFIGURE}))
        prepared = self._worker({'prepared': {'review', 'writerCertificateSha256'}})
        self._write(self.stdout, prepared)
        if self._execute(rollback=False):
            self._execute(rollback=True)


def run_manager(config, archive, root):
    """Start and stop only the native unit owned by this exact manager."""
    if (type(config) is not dict or set(config) != MANAGER_FIELDS or config['entrypoint'] != MANAGER
            or config['mode'] != 'channel' or not hex_value(config['expectedEndpointDigest'])):
        reject()
    work = _path(config['workDirectory'])
    if not isinstance(root, Path) or root.parent != work:
        reject()
    deadline = time.monotonic() + SESSION_SECONDS
    registration = scope_registration(config['scope'])
    unit = RetainedProductionUnitV1(archive, source_sha=config['sourceSha'],
                                    expected_archive_digest=config['archiveDigest'])
    process, startup = unit.start_registered(
        registration, work_directory=work, mode='channel', expected_endpoint_digest=config['expectedEndpointDigest'],
    )
    primary = None
    try:
        startup = _startup(startup, scope=config['scope'], source_sha=config['sourceSha'],
                           archive_digest=config['archiveDigest'], endpoint_digest=config['expectedEndpointDigest'])
        write_frame(sys.stdout.buffer, startup, timeout=_remaining(deadline, 30))
        _Relay(sys.stdin.buffer, sys.stdout.buffer, process, startup['channelNonce'], deadline).run()
        if process.wait(timeout=_remaining(deadline, 15)) != 0:
            reject()
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            unit.stop(timeout=30)
            unit.close()
        except Exception:
            if primary is None:
                raise
            if hasattr(primary, 'add_note'):
                primary.add_note('owned production unit cleanup could not be verified')
