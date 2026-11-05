"""Dedicated Linux/root fixed-loader producer and read-only cold consumer.

No archive/config is sent to the wrapper; no business worker or Engine starts.
The producer alone starts/stops its randomly named owned unit.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'packs/deployment/scripts', 'packs/release/scripts'))]
import deployment_compose_owned_recovery_unit_v3_host as units
import deployment_compose_cold_writer_v3_host as cold


def produce(directory, *, source_sha='0' * 40, archive_digest='0' * 64):
    owner = units.OwnedRecoveryUnitV3(archive_digest, source_sha)
    try:
        process = owner.start()
        if process.poll() is not None or owner.creation_outcome_unknown:
            raise AssertionError('loader ownership was not established')
        raw = owner.capture_origin()
        try:
            cold.observe_stopped_writer(raw, expected_digest=hashlib.sha256(raw).hexdigest(),
                expected_source_sha=source_sha, expected_archive_digest=archive_digest)
        except ValueError:
            pass
        else:
            raise AssertionError('running original writer accepted as stopped')
        origin = directory / 'writer-origin.private.json'
        fd = os.open(origin, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
        owner.stop()
        if not owner._stopped or process.poll() is None:
            raise AssertionError('original owner did not complete stop')
        return dict(originPath=str(origin), expectedDigest=hashlib.sha256(raw).hexdigest(),
            sourceSha=source_sha, archiveDigest=archive_digest, producerPid=os.getpid(),
            unit=owner.unit, archiveOrConfigSent=False, engineStarted=False)
    finally:
        if owner._invocation is not None and not owner._stopped:
            owner.stop()
        if owner._stopped:
            owner.close()


def consume(pins):
    commands = []
    real = subprocess.run
    def read_only(argv, **kwargs):
        if argv[:3] != ['/usr/bin/systemctl', '--system', 'show']:
            raise AssertionError('cold consumer attempted a non-show command')
        commands.append(list(argv))
        return real(argv, **kwargs)
    with patch.object(units.OwnedRecoveryUnitV3, '__init__', side_effect=AssertionError('new owner')), \
         patch.object(units.OwnedRecoveryUnitV3, 'stop', side_effect=AssertionError('stop')), \
         patch.object(cold.subprocess, 'run', side_effect=read_only):
        result = cold.observe_stopped_writer(Path(pins['originPath']).read_bytes(),
            expected_digest=pins['expectedDigest'], expected_source_sha=pins['sourceSha'],
            expected_archive_digest=pins['archiveDigest'])
    if len(commands) < 2:
        raise AssertionError('two complete manager observations required')
    return dict(consumerPid=os.getpid(), producerPid=pins['producerPid'],
        summary=result.public_summary(), readOnlyCommandCount=len(commands),
        archiveOrConfigSent=False, engineStarted=False, executionRecovered=False)


if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'produce':
        if len(sys.argv) == 5:
            result = produce(Path(sys.argv[2]).resolve(strict=True),
                source_sha=sys.argv[3], archive_digest=sys.argv[4])
        elif len(sys.argv) == 3:
            result = produce(Path(sys.argv[2]).resolve(strict=True))
        else:
            raise ValueError('fixture source context rejected')
    elif mode == 'consume':
        result = consume(json.load(sys.stdin))
    else:
        raise ValueError('fixture action rejected')
    print(json.dumps(result), flush=True)
