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
