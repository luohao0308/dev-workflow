"""Preflight and publish the registered same-image luohao-blog frontend."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile


_RUNTIME_DIRS = ('scripts', 'core/scripts', 'packs/deployment/scripts', 'packs/release/scripts')
_CERTIFICATE = '.github/compose-approval-recipient.pem'
_BASELINE = 'baseline.json'


class ReleaseCommandBlocked(ValueError):
    pass


def _reject(message):
    raise ReleaseCommandBlocked(message) from None


def _emit(kind, **data):
    print(json.dumps(dict(kind=kind, **data), ensure_ascii=True), flush=True)


def _run(*args, data=None, timeout=25):
    return subprocess.run(args, input=data, capture_output=True, check=True, timeout=timeout).stdout


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _private_directory(path, repo):
    if not path.is_absolute() or path.resolve(strict=True) != path or path.is_relative_to(repo):
        _reject('Release workspace must be an absolute private directory outside the checkout')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            _reject('Release workspace must be owned and mode 0700')
        return info.st_dev, info.st_ino
    finally:
        os.close(fd)


def _private_file(path, *, limit=1048576):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        _reject('Expected a private absolute file path')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= limit):
            _reject('Invalid private file owner, mode, or size')
        raw = stream.read(limit + 1)
        if len(raw) != info.st_size or os.fstat(stream.fileno()).st_ctime_ns != info.st_ctime_ns:
            _reject('Private release file changed during read')
        return raw


def _save_baseline(root, identity, raw):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) != identity:
            _reject('Release workspace changed')
        marker = os.open(_BASELINE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(marker, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)


def _published(runtime):
    current = _run('gh', 'api', 'repos/luohao0308/dev-workflow/branches/main', '--jq', '.commit.sha')
    if current.decode('ascii').strip() != runtime:
        _reject('Release runtime must match published main')


def _runtime(repo, runtime, directory):
    expected = _run('git', '-C', str(repo), 'show',
                    runtime+':scripts/deployment_compose_retained_release_v1_host.py')
    if Path(__file__).read_bytes() != expected:
        _reject('Release command differs from the pinned runtime')
    raw = _run('git', '-C', str(repo), 'archive', runtime, _CERTIFICATE, *_RUNTIME_DIRS)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        archive.extractall(directory, filter='data')
    sys.path[:0] = [str(directory/folder) for folder in _RUNTIME_DIRS]


def _prepare(archive, runtime):
    from deployment_compose_blog_frontend_preflight_v1_host import capture, prepare_capture
    from deployment_compose_retained_release_preflight_v1_host import inspect_release_host
    from deployment_compose_witness_store import canonical

    baseline = inspect_release_host(archive)
    if (baseline['caddyProbeReady'] is not True or baseline['hostProjectionUnchanged'] is not True
            or baseline['productionDockerWrites'] != 0):
        _reject('Registered frontend failed read-only preflight')
    pins = baseline['frontendPins']
    plan = prepare_capture(capture(pins['hostId']), pins)
    evidence = dict(runtimeSha=runtime, baseline=baseline, privatePlanDigest=_hash(canonical(plan)))
    return baseline, plan, evidence


def _execute_release(controller, reviewer, archive, baseline, plan, witness_root, witness_public, emit):
    from deployment_compose_retained_release_preflight_v1_host import inspect_active_release
    from deployment_compose_witness_store import canonical
    from deployment_gate_witness import key_material

    expiry = (datetime.now(timezone.utc)+timedelta(minutes=28)).strftime('%Y-%m-%dT%H:%M:%SZ')
    reviewer.request_release_review(plan, controller.review, expires_at=expiry,
                                    on_review=lambda value: emit('human-review', **value))
    slot, approval, grant = reviewer.release_stage_grant('create', controller.review, after_slot=0)
    creation = controller.execute(approval, grant, approval.request)
    if creation['blocked'] or creation.get('switchReview') is None:
        _reject('Creation has no verified switch review')
    created = creation['result']
    emit('created', result=created)

    def evidence():
        pins = controller.review['retainedCutover']
        if pins['creationRequestHash'] != created['requestHash']:
            _reject('Release review differs from closed creation')
        pending = inspect_active_release(archive, baseline, request_hash=created['requestHash'],
                                         generation=pins['scopeGeneration'])
        return dict(root=witness_root, pending=pending, public_key=witness_public,
                    expected_key_hash=_hash(key_material(witness_public)))

    for _ in range(2):
        witness = evidence()
        slot, approval, grant = reviewer.release_stage_grant('switch', controller.review, after_slot=slot,
                                                            witness_source=witness)
        switched = controller.execute(approval, grant, approval.request)
        if switched.get('switchReview') is None:
            break
        emit('switch-slot-rejected-before-consumption', slot=slot)
    else:
        controller.finish()
        _reject('Insufficient cutover window before switch consumption')
    if switched.get('terminalProof') is not None:
        return dict(disposition='retained-candidate', result=switched['result'], proof=switched['terminalProof'],
                    generation=witness['pending']['generation'], creationRequest=created['requestHash'])
    failure = switched.get('readinessFailure')
    if failure is None or switched.get('restoreReview') is None:
        _reject('Release has no verified automatic restoration request')
    witness = evidence()
    slot, approval, grant = reviewer.release_stage_grant(
        'rollback', controller.review, after_slot=slot, witness_source=witness, readiness_failure=failure,
    )
    restored = controller.execute(approval, grant, approval.request)
    if restored['blocked'] or restored['result'] is None:
        _reject('Automatic restoration has no terminal result')
    return dict(disposition='restored-original', result=restored['result'], proof=_hash(canonical(restored['result'])),
                generation=witness['pending']['generation'], creationRequest=created['requestHash'])


def _verify_recipient(key, certificate):
    _private_file(key, limit=65536)
    challenge = os.urandom(32)
    cipher = _run('/usr/bin/openssl', 'cms', '-encrypt', '-binary', '-aes256', '-outform', 'DER',
                  str(certificate), data=challenge)
    if _run('/usr/bin/openssl', 'cms', '-decrypt', '-inform', 'DER', '-inkey', str(key),
            '-passin', 'pass:', data=cipher) != challenge:
        _reject('Recipient private key does not match the pinned certificate')


def _worker_exit(process, verified):
    process.stdin.close()
    try:
        code = process.wait(timeout=45)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        if verified:
            _reject('Native worker exit could not be verified')
    else:
        if code != 0 and verified:
            _reject('Native worker did not exit cleanly')
    finally:
        process.stdout.close()


def _publish(args, archive, baseline, plan, certificate):
    from deployment_compose_retained_controller_v1_host import RetainedControllerV1
    from deployment_compose_retained_native_entry_v1_host import scope_registration
    from deployment_compose_retained_release_preflight_v1_host import inspect_release_host
    from deployment_compose_retained_ssh_v1_host import start_retained_ssh
    from deployment_compose_production_frontend_review_v1_host import GitHubProductionFrontendReviewV1

    _verify_recipient(args.recipient_private_key, certificate)
    session = Path(tempfile.mkdtemp(prefix='release-', dir=args.workspace))
    roots = [session/'reviews', session/'witnesses']
    for path in roots:
        path.mkdir(mode=0o700)
    review_root, witness_root = roots
    intent, witness = (witness_root/'intent', witness_root/'witness')
    for signer in (intent, witness):
        _run('/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(signer))
    manifest = baseline['manifest']
    registration = scope_registration(manifest['scope'])
    reviewer = GitHubProductionFrontendReviewV1(review_root, runtime_sha=args.runtime_sha,
        recipient_private_key=args.recipient_private_key, registered_policy_hash=baseline['policyHash'])
    process = controller = None
    terminal = None
    try:
        process, startup = start_retained_ssh(registration.host_id, archive, source_sha=args.runtime_sha,
            expected_archive_digest=_hash(archive), registration=registration,
            work_directory=Path(manifest['workDirectory']), expected_endpoint_digest=baseline['endpointDigest'])
        controller = RetainedControllerV1(process.stdin, process.stdout, startup=startup, expected_startup=startup,
            private_plan=plan, operation_nonce=os.urandom(32).hex(), policy_hash=baseline['policyHash'],
            intent_signer=intent, intent_public_key=intent.with_suffix('.pub').read_bytes(),
            witness_signer=witness, witness_public_key=witness.with_suffix('.pub').read_bytes(),
            witness_root=witness_root, witness_key=os.urandom(32), gate_key=os.urandom(32),
            caddy_id=manifest['caddyId'], network_id=manifest['networkId'], staged=True)
        terminal = _execute_release(controller, reviewer, archive, baseline, plan, witness_root,
                                    witness.with_suffix('.pub').read_bytes(), _emit)
    finally:
        try:
            try:
                if controller is not None:
                    controller.close()
            finally:
                if process is not None:
                    _worker_exit(process, terminal is not None)
        finally:
            reviewer.close()
    final = inspect_release_host(archive)
    expected = dict(state='verified', generation=terminal['generation'], request=terminal['creationRequest'],
                    proof=terminal['proof'])
    active = ('candidateId' if terminal['disposition'] == 'retained-candidate' else 'originalId')
    if (final['journalTail'] != expected or final['frontendPins']['containerId'] != terminal['result'][active]
            or final['manifest'] != baseline['manifest'] or final['endpointDigest'] != baseline['endpointDigest']
            or final['caddyProbeReady'] is not True):
        _reject('Post-release journal, active container, or Caddy readiness differs')
    _emit('completed', **terminal)
    return 0 if terminal['disposition'] == 'retained-candidate' else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('preflight', 'release'))
    parser.add_argument('--runtime-sha', required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--recipient-private-key', type=Path)
    args = parser.parse_args(argv)
    if (re.fullmatch('[0-9a-f]{40}', args.runtime_sha) is None
            or (args.mode == 'release') != (args.recipient_private_key is not None)):
        parser.error('Choose an exact runtime and supply the private recipient key only for release.')
    repo = Path.cwd().resolve()
    try:
        identity = _private_directory(args.workspace, repo)
        _published(args.runtime_sha)
        with tempfile.TemporaryDirectory(prefix='dw-release-runtime-') as directory:
            _runtime(repo, args.runtime_sha, Path(directory))
            from deployment_compose_retained_source_v1_host import production_archive
            from deployment_compose_witness_store import canonical

            archive = production_archive(repo, args.runtime_sha)
            baseline, plan, evidence = _prepare(archive, args.runtime_sha)
            raw = canonical(evidence)
            if args.mode == 'preflight':
                _save_baseline(args.workspace, identity, raw)
                _emit('preflight', runtime=args.runtime_sha, record=str(args.workspace/_BASELINE), productionWrites=0)
                return 0
            if _private_directory(args.workspace, repo) != identity or _private_file(args.workspace/_BASELINE) != raw:
                _reject('Fresh production baseline differs from preflight')
            return _publish(args, archive, baseline, plan, Path(directory)/_CERTIFICATE)
    except ReleaseCommandBlocked as error:
        _emit('blocked', reason=str(error))
        return 2
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Do not print subprocess arguments, server responses, or private data.
        _emit('blocked', category=type(error).__name__)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
