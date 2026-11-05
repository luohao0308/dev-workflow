#!/usr/bin/env python3
"""Offline, untrusted Compose model screening; never executes Docker or grants deployment.

The input may contain expanded environment values. Results intentionally include
only fixed reason codes, never service configuration, hashes, or input paths.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
import deployment_prepare as planner

MAX_MODEL = 1024 * 1024
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
SUPPORTED_KEYS = frozenset({
    'image', 'read_only', 'user', 'cap_drop', 'security_opt', 'restart',
    'environment', 'networks', 'depends_on', 'healthcheck', 'labels',
    'ports', 'expose', 'logging', 'stop_grace_period', 'init',
    'command', 'entrypoint',
})


class PreflightError(ValueError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError('duplicate-json-field')
        result[key] = value
    return result


def parse_model(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_MODEL:
        raise PreflightError('invalid-model-size')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except PreflightError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise PreflightError('invalid-model-json') from None
    if not isinstance(value, dict) or not isinstance(value.get('services'), dict):
        raise PreflightError('invalid-compose-model')
    return value


def assess(model: dict, service: str) -> dict:
    if (not isinstance(model, dict) or not isinstance(model.get('services'), dict)
            or not isinstance(service, str) or not NAME.fullmatch(service)):
        raise PreflightError('invalid-compose-scope')
    selected = model['services'].get(service)
    if not isinstance(selected, dict):
        raise PreflightError('missing-compose-service')
    reasons = set()
    if set(selected) - SUPPORTED_KEYS:
        reasons.add('unsupported-service-fields')
    image = selected.get('image')
    if not planner.registry_reference(image):
        reasons.add('immutable-image-required')
    if selected.get('read_only') is not True:
        reasons.add('read-only-root-required')
    user = selected.get('user')
    if not isinstance(user, str) or not re.fullmatch(r'[1-9][0-9]*(?::[0-9]+)?', user):
        reasons.add('numeric-nonroot-user-required')
    caps = selected.get('cap_drop')
    if caps != ['ALL']:
        reasons.add('drop-all-capabilities-required')
    security = selected.get('security_opt')
    if security not in (['no-new-privileges:true'], ['no-new-privileges']):
        reasons.add('no-new-privileges-required')
    if selected.get('restart', 'no') != 'no':
        reasons.add('restart-policy-unsupported')
    if selected.get('command') is not None or selected.get('entrypoint') is not None:
        reasons.add('command-override-unsupported')
    return dict(schemaVersion=1, kind='compose-offline-preflight',
                service=service, structuralStatus='blocked' if reasons else 'candidate-unverified',
                reasons=sorted(reasons), runtimeVerification='unknown',
                authorityGranted=False, executionAvailable=False, productionReady=False)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--service', required=True)
    args = parser.parse_args(argv)
    try:
        path = args.model
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_MODEL:
            raise PreflightError('invalid-model-file')
        result = assess(parse_model(path.read_bytes()), args.service)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, PreflightError) as error:
        code = str(error) if isinstance(error, PreflightError) else 'model-unavailable'
        print(json.dumps({'error': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
