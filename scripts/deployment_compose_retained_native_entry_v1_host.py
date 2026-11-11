"""Fixed startup for a source-verified production frontend unit."""

import os
from pathlib import Path
import sys

from deployment_compose_host_snapshot_v3_host import HostSnapshotV3
from deployment_compose_production_scope_v1_host import (
    ScopeRegistrationV1, _directory, _header, _history, _name, _read,
)
from deployment_compose_retained_source_v1_host import (
    check_loaded_source, issue_loaded_source, reject,
)
from deployment_compose_v3_channel_worker import write_frame

_SCOPE_FIELDS = {'root', 'rootIdentity', 'journalIdentity', 'hostId', 'project', 'daemonId'}


def _identity(value):
    if type(value) is not list or len(value) != 2 or any(type(item) is not int or item < 0 for item in value):
        reject()
    return tuple(value)


def scope_registration(value):
    if (type(value) is not dict or set(value) != _SCOPE_FIELDS or type(value['root']) is not str
            or len(value['root']) > 4096 or value['project'] != 'luohao-blog-prod'):
        reject()
    _header(value['hostId'], value['project'], value['daemonId'])
    return ScopeRegistrationV1(
        Path(value['root']), _identity(value['rootIdentity']), _identity(value['journalIdentity']),
        value['hostId'], value['project'], value['daemonId'],
    )


def _inspect_registration(registration):
    root_fd, identity = _directory(registration.root)
    try:
        if identity != registration.root_identity:
            reject()
        fd = os.open(_name(registration.project), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
        try:
            raw = _read(registration, fd)
            _history(raw, registration)
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def prepare(receipt, registration):
    """Open the production observer and recheck the independently registered scope."""
    if type(registration) is not ScopeRegistrationV1 or registration.project != 'luohao-blog-prod':
        reject()
    scope = dict(root=str(registration.root), rootIdentity=list(registration.root_identity),
                 journalIdentity=list(registration.journal_identity), hostId=registration.host_id,
                 project=registration.project, daemonId=registration.daemon_id)
    check_loaded_source(receipt, scope=scope)
    before = _inspect_registration(registration)
    observer = HostSnapshotV3()
    try:
        if observer._info_id != registration.daemon_id or _inspect_registration(registration) != before:
            reject()
        check_loaded_source(receipt, scope=scope)
        return observer
    except BaseException:
        observer.close()
        raise


def run_production(config, archive, root):
    receipt = issue_loaded_source(config, archive, root)
    registration = scope_registration(config['scope'])
    observer = prepare(receipt, registration)
    try:
        source = check_loaded_source(receipt)
        hello = {
            'kind': 'production-startup', 'channelNonce': source['channelNonce'], 'source': source,
            'endpointDigest': observer.descriptor()['endpointDigest'], 'scope': config['scope'],
        }
        write_frame(sys.stdout.buffer, hello, timeout=15)
        if config['mode'] == 'channel':
            from deployment_compose_retained_native_channel_v1_host import run_channel

            run_channel(config, receipt, observer, registration)
    finally:
        observer.close()
