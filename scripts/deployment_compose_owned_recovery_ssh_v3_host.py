"""Fixed recovery loader construction only; no launcher or remote stop proof.

The embedding still owns authenticated source/observer pins and the Delegate
unit lifecycle. Constructing argv never authenticates those prerequisites.
"""
import io
import re
import shlex
import zipfile

import deployment_compose_live_ssh_v3_host as live

ENTRYPOINT = 'deployment_compose_owned_recovery_worker_v3_host.run'
WORKER = 'scripts/deployment_compose_owned_recovery_worker_v3_host.py'
MANAGER_ENTRYPOINT = 'deployment_compose_owned_recovery_manager_v3_host.run'
RESPONSE_LOSS_ENTRYPOINT = 'deployment_compose_response_loss_worker_v3_host.run'
RESPONSE_LOSS_MANAGER_ENTRYPOINT = 'deployment_compose_response_loss_manager_v3_host.run'
RESPONSE_LOSS_WORKER = 'scripts/deployment_compose_response_loss_worker_v3_host.py'


def reject():
    raise ValueError('compose-owned-recovery-ssh-v3-rejected') from None


def recovery_bootstrap(archive_digest, source_sha):
    if (type(archive_digest) is not str or not re.fullmatch('[0-9a-f]{64}',archive_digest)
            or type(source_sha) is not str or not re.fullmatch('[0-9a-f]{40}',source_sha)):
        reject()
    # Reuse the bounded, hash-pinned loader, replacing only its fixed worker.
    code = live.live_bootstrap(archive_digest,source_sha)
    return code.replace('deployment_compose_live_worker_v3_host',
                        'deployment_compose_owned_recovery_worker_v3_host')


def ssh_argv(alias, archive_digest, source_sha):
    code = recovery_bootstrap(archive_digest,source_sha)
    argv = live.ssh_argv(alias,archive_digest,source_sha)
    argv[-1] = 'exec python3 -I -u -c ' + shlex.quote(code)
    return argv


def published_recovery_archive(source_sha):
    # Preserve the existing exact clean HEAD/origin/published-ref source checks.
    raw = live.published_live_archive(source_sha)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if WORKER not in archive.namelist():
            reject()
    return raw


def manager_bootstrap(archive_digest, source_sha):
    """Fixed manager receives the loader-validated archive, never source text."""
    code = recovery_bootstrap(archive_digest,source_sha)
    worker = 'deployment_compose_owned_recovery_worker_v3_host'
    call = ' run(config,sys.stdin.buffer,sys.stdout.buffer)'
    if code.count(worker)!=2 or code.count(call)!=1:reject()
    return code.replace(worker,'deployment_compose_owned_recovery_manager_v3_host').replace(
        call,' run(config,sys.stdin.buffer,sys.stdout.buffer,archive)')


def manager_ssh_argv(alias, archive_digest, source_sha):
    code = manager_bootstrap(archive_digest,source_sha)
    argv = live.ssh_argv(alias,archive_digest,source_sha)
    argv[-1] = 'exec python3 -I -u -c '+shlex.quote(code)
    return argv


def published_manager_archive(source_sha):
    raw = published_recovery_archive(source_sha)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        required = {'scripts/deployment_compose_owned_recovery_manager_v3_host.py',
            'scripts/deployment_compose_owned_recovery_unit_v3_host.py',
            'scripts/deployment_compose_recovery_daemon_v3_host.py',
            'scripts/deployment_compose_resource_inventory_v3_host.py',
            'scripts/deployment_compose_host_snapshot_v3_host.py',
            'scripts/deployment_compose_host_commands_v3_host.py',
            'scripts/deployment_compose_recovery_profiles_v3_host.py',
            'scripts/deployment_compose_response_loss_observation_v3_host.py'}
        if not required.issubset(archive.namelist()):reject()
    return raw


def response_loss_bootstrap(archive_digest,source_sha):
    """Fixed worker code for the distinct profile-bound diagnostic manager."""
    code=recovery_bootstrap(archive_digest,source_sha)
    module='deployment_compose_owned_recovery_worker_v3_host'
    if code.count(module)!=2:reject()
    return code.replace(module,'deployment_compose_response_loss_worker_v3_host')


def published_response_loss_archive(source_sha):
    raw=published_manager_archive(source_sha)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if RESPONSE_LOSS_WORKER not in archive.namelist():reject()
    return raw


def response_loss_manager_bootstrap(archive_digest,source_sha):
    code=response_loss_bootstrap(archive_digest,source_sha)
    module='deployment_compose_response_loss_worker_v3_host'
    call=' run(config,sys.stdin.buffer,sys.stdout.buffer)'
    if code.count(module)!=2 or code.count(call)!=1:reject()
    return code.replace(module,'deployment_compose_response_loss_manager_v3_host').replace(
        call,' run(config,sys.stdin.buffer,sys.stdout.buffer,archive)')


def response_loss_manager_ssh_argv(alias,archive_digest,source_sha):
    code=response_loss_manager_bootstrap(archive_digest,source_sha)
    argv=live.ssh_argv(alias,archive_digest,source_sha)
    argv[-1]='exec python3 -I -u -c '+shlex.quote(code)
    return argv


def published_response_loss_manager_archive(source_sha):
    raw=published_response_loss_archive(source_sha)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        required={'scripts/deployment_compose_response_loss_manager_v3_host.py',
            'scripts/deployment_compose_recovery_profiles_v3_host.py'}
        if not required.issubset(archive.namelist()):reject()
    return raw
