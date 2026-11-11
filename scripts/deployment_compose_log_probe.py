#!/usr/bin/env python3
"""Bounded stopped-container logging experiment, never a deployment writer.

Creates three never-started containers on the local Linux daemon, then deletes
only IDs from successful create receipts. stdout is private evidence, including
failure/unknown results. Unknown creates are never retried or deleted by name.
The official fixture image must already exist. No pull or daemon changes.
"""
import json
import os
import re
import subprocess
import sys
import uuid

IMAGE = 'python@sha256:56a11364ffe0fee3bd60af6d6d5209eba8a99c2c16dc4c7c5861dc06261503cc'
ID = re.compile(r'[0-9a-f]{64}\Z')


def docker(*args):
    env = dict(os.environ, DOCKER_API_VERSION='1.45')
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        env.pop(key, None)
    return subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', *args],
        env=env, capture_output=True, timeout=20, check=True).stdout.decode('utf-8')


def inventory(run):
    ids = sorted(run('container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}').splitlines())
    if len(set(ids)) != len(ids) or any(not ID.fullmatch(value) for value in ids):
        raise ValueError('invalid-inventory')
    if not ids:
        return []
    values = json.loads(run('container', 'inspect', *ids))
    if sorted(item['Id'] for item in values) != ids:
        raise ValueError('invalid-inventory')
    return sorted([{'id': item['Id'], 'startedAt': item['State']['StartedAt'],
        'status': item['State']['Status'], 'restartCount': item['RestartCount']}
        for item in values], key=lambda item: item['id'])


def diagnostic(error, phase):
    result = {'phase': phase, 'type': type(error).__name__}
    if isinstance(error, subprocess.CalledProcessError):
        result['exitCode'] = error.returncode
    for key in ('stdout', 'stderr'):
        value = getattr(error, key, None)
        if value:
            result[key] = (value.decode('utf-8', errors='replace') if isinstance(value, bytes)
                           else str(value))[:4096]
    if isinstance(error, ValueError):
        result['reason'] = str(error)[:512]
    return result


def probe(run=docker):
    project = 'dw-compose-sample-' + uuid.uuid4().hex[:24]
    result = {'schemaVersion': 1, 'kind': 'compose-stopped-log-probe',
        'project': project, 'observations': [], 'cleanup': [], 'unknownCreateResult': False,
        'authorityGranted': False, 'productionReady': False, 'executionAvailable': False,
        'effectiveDefaultsVerified': False, 'completed': False}
    receipts = []
    phase = 'info'
    try:
        info = json.loads(run('info', '--format', '{{json .}}'))
        if info.get('OSType') != 'linux' or not info.get('ID'):
            raise ValueError('unsupported-daemon')
        result['daemonId'] = info['ID']
        phase = 'image-inspect'
        images = json.loads(run('image', 'inspect', IMAGE))
        if len(images) != 1:
            raise ValueError('unexpected-image')
        image = images[0]
        config = image['Config']
        if (image['Os'] != 'linux' or IMAGE not in image['RepoDigests']
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', image['Id'])
                or any(config.get(key) for key in ('Volumes', 'ExposedPorts', 'Healthcheck'))):
            raise ValueError('unsupported-image-defaults')
        phase = 'before-inventory'
        result['before'] = inventory(run)
        for role, flags in (('default', []), ('none', ['--log-driver=none']),
                ('json', ['--log-driver=json-file', '--log-opt=max-size=1m', '--log-opt=max-file=1'])):
            name = project + '-' + role
            args = ['container', 'create', '--pull=never', '--name=' + name,
                '--label=com.docker.compose.project=' + project, '--label=dev-workflow.probe=stopped-log',
                '--network=none', '--read-only', '--memory=64m', '--memory-swap=64m',
                '--cpus=0.1', '--pids-limit=32', '--restart=no',
                '--entrypoint=/usr/local/bin/python3', *flags, image['Id'], '-c', 'pass']
            # From immediately before submission until exact receipt parsing,
            # any error means unknown outcome; never issue a replacement create.
            phase = role + '-create'
            result['unknownCreateResult'] = True
            receipt = run(*args).strip()
            if (not ID.fullmatch(receipt) or receipt in receipts
                    or receipt in {item['id'] for item in result['before']}):
                raise ValueError('unknown-create-receipt')
            receipts.append(receipt)
            result['unknownCreateResult'] = False
            phase = role + '-inspect'
            values = json.loads(run('container', 'inspect', receipt))
            if len(values) != 1:
                raise ValueError('unexpected-created-container')
            item = values[0]
            if (item['Id'] != receipt or item['Image'] != image['Id'] or item['Name'] != '/' + name
                    or item['Config']['Labels'].get('com.docker.compose.project') != project
                    or item['State']['Running'] is not False or item['State']['Status'] != 'created'
                    or item['HostConfig']['NetworkMode'] != 'none' or item.get('Mounts') != []):
                raise ValueError('unexpected-created-container')
            result['observations'].append({'role': role, 'id': receipt,
                'state': item['State']['Status'], 'logConfig': item['HostConfig']['LogConfig']})
        result['completed'] = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result['failure'] = 'log-probe-incomplete'
        result['privateFailure'] = diagnostic(error, phase)
    finally:
        for receipt in reversed(receipts):
            try:
                # No force flag: an unexpectedly started container must block.
                if run('container', 'rm', receipt).strip() != receipt:
                    raise ValueError('unknown-removal')
                result['cleanup'].append({'id': receipt, 'removed': True})
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                result['cleanup'].append({'id': receipt, 'removed': False,
                    'privateFailure': diagnostic(error, 'cleanup')})
        try:
            result['after'] = inventory(run)
            result['existingContainersUnchanged'] = result.get('before') == result['after']
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            result['existingContainersUnchanged'] = False
            result['privateAfterFailure'] = diagnostic(error, 'after-inventory')
    result['success'] = (result['completed'] and not result['unknownCreateResult']
        and len(result['cleanup']) == 3 and all(item['removed'] for item in result['cleanup'])
        and result['existingContainersUnchanged'])
    return result


if __name__ == '__main__':
    if sys.platform != 'linux':
        sys.exit('linux-required')
    evidence = probe()
    print(json.dumps(evidence, sort_keys=True, allow_nan=False))
    sys.exit(0 if evidence['success'] else 1)
