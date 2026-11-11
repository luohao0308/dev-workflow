#!/usr/bin/env python3
"""Read-only sampling for a disposable Linux Compose fixture; no authorization.

Raw inspect data stays in a preprovisioned private directory. The public report
contains field names and fixed blocker codes only. No Docker mutation is issued.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_private import REQUIRED_CONFIG, REQUIRED_HOST, KNOWN_OPTIONAL_CONFIG, KNOWN_OPTIONAL_HOST
from deployment_compose_baseline_recipe import ENDPOINT_CONFIG, ENDPOINT_RUNTIME

PROJECT = re.compile(r'dw-compose-sample-[0-9a-f]{24}\Z')
IMAGE = re.compile(r'(?:docker\.io/library/)?python(?::[A-Za-z0-9_.-]+)?@sha256:[0-9a-f]{64}\Z')
ID = re.compile(r'[0-9a-f]{64}\Z')
SERVICES = ('backend', 'frontend', 'guard')
MAX_BYTES = 4 * 1024 * 1024


def fail():
    raise ValueError('compose-engine-sample-rejected')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def version(value):
    if type(value) is not str or not re.fullmatch(r'[0-9]+\.[0-9]+', value):
        fail()
    return tuple(int(x) for x in value.split('.'))


def validate_image(image):
    if type(image) is not str or not IMAGE.fullmatch(image):
        fail()
    return image.rsplit('@', 1)[1]


class DockerReader:
    def __init__(self):
        self.deadline = time.monotonic() + 90

    def read(self, *args, fixed_api=True):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            fail()
        env = dict(os.environ)
        env.pop('DOCKER_API_VERSION', None)
        if fixed_api:
            env['DOCKER_API_VERSION'] = '1.45'
        try:
            # Spool privately, then bound the in-memory read. Docker has a
            # command deadline; this is not a hard disk-quota guarantee.
            with tempfile.TemporaryFile() as output:
                result = subprocess.run(['docker', *args], env=env, stdout=output,
                                        stderr=subprocess.DEVNULL,
                                        timeout=min(15, remaining), check=False)
                if result.returncode != 0 or os.fstat(output.fileno()).st_size > MAX_BYTES:
                    fail()
                output.seek(0)
                raw = output.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    fail()
                return raw.decode('utf-8')
        except (OSError, subprocess.SubprocessError, UnicodeError):
            fail()

    def object(self, *args, fixed_api=True):
        try:
            return json.loads(self.read(*args, fixed_api=fixed_api))
        except (ValueError, TypeError):
            fail()


def preflight(reader):
    if sys.platform != 'linux':
        fail()
    server = reader.object('version', '--format', '{{json .Server}}', fixed_api=False)
    info = reader.object('info', '--format', '{{json .}}')
    if (type(server) is not dict or type(info) is not dict or info.get('OSType') != 'linux'
            or version(server.get('ApiVersion')) < (1, 45)
            or version(server.get('MinAPIVersion')) > (1, 45)
            or type(info.get('ID')) is not str or not info['ID']):
        fail()
    return {'daemonId': info['ID'], 'serverVersion': server.get('Version'),
            'apiVersion': server['ApiVersion'], 'minimumApiVersion': server['MinAPIVersion'],
            'osType': 'linux', 'architecture': info.get('Architecture'),
            'loggingDriver': info.get('LoggingDriver')}


def inventory(reader, project):
    lines = reader.read('container', 'ls', '--all', '--no-trunc', '--filter',
                        'label=com.docker.compose.project=' + project, '--format', '{{.ID}}').splitlines()
    if len(lines) != 3 or len(set(lines)) != 3 or any(not ID.fullmatch(x) for x in lines):
        fail()
    return tuple(sorted(lines))


def inspect(reader, project, image, ids):
    values = reader.object('container', 'inspect', *ids)
    if type(values) is not list or len(values) != 3:
        fail()
    result = {}
    for item in values:
        if type(item) is not dict or item.get('Id') not in ids:
            fail()
        config = item.get('Config')
        if type(config) is not dict or type(config.get('Labels')) is not dict:
            fail()
        labels = config['Labels']
        service = labels.get('com.docker.compose.service')
        state = item.get('State')
        if (service not in SERVICES or service in result
                or labels.get('com.docker.compose.project') != project
                or str(labels.get('com.docker.compose.oneoff', '')).lower() != 'false'
                or config.get('Image') != image
                or type(state) is not dict or state.get('Running') is not True
                or type(state.get('Health')) is not dict or state['Health'].get('Status') != 'healthy'
                or type(item.get('Image')) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', item['Image'])
                or any(type(item.get(k)) is not dict for k in ('HostConfig', 'NetworkSettings'))
                or type(item.get('Mounts')) is not list):
            fail()
        # Deliberately exclude changing health logs; preserve original config,
        # complete network endpoints and mounts for private shape investigation.
        result[service] = {k: item.get(k) for k in (
            'Id', 'Name', 'Image', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings')}
        result[service]['instance'] = {k: state.get(k) for k in ('Pid', 'StartedAt')}
        result[service]['instance']['restartCount'] = item.get('RestartCount')
    if tuple(sorted(result)) != SERVICES or len({x['Id'] for x in result.values()}) != 3:
        fail()
    return result


def summarize(samples):
    result = {}
    for service, sample in sorted(samples.items()):
        config, host, network = (sample[k] for k in ('Config', 'HostConfig', 'NetworkSettings'))
        endpoints = network.get('Networks')
        if type(endpoints) is not dict or not endpoints or any(type(x) is not dict for x in endpoints.values()):
            fail()
        extra_config = sorted(set(config) - (REQUIRED_CONFIG | KNOWN_OPTIONAL_CONFIG))
        extra_host = sorted(set(host) - (REQUIRED_HOST | KNOWN_OPTIONAL_HOST | {'PidMode', 'IpcMode', 'LogConfig'}))
        extra_network = sorted(set(network) - {'Networks'})
        reasons = []
        for fields, reason in ((extra_config, 'unrepresented-config-fields'),
                               (extra_host, 'unrepresented-host-fields'),
                               (extra_network, 'unrepresented-networksettings-fields')):
            if fields:
                reasons.append(reason)
        if host.get('RestartPolicy') != {'Name': 'no', 'MaximumRetryCount': 0}:
            reasons.append('unsupported-restart-policy')
        if host.get('LogConfig') != {'Type': 'none', 'Config': {}}:
            reasons.append('unsupported-effective-log-config')
        endpoint_fields = sorted(set().union(*(set(x) for x in endpoints.values())))
        for endpoint in endpoints.values():
            if set(endpoint) != ENDPOINT_CONFIG | set(ENDPOINT_RUNTIME):
                reasons.append('incomplete-or-unrepresented-endpoint-fields')
            if endpoint.get('MacAddress') != '':
                reasons.append('unrepresented-endpoint-mac')
            if endpoint.get('IPAMConfig') is not None or endpoint.get('Links') not in (None, []) or endpoint.get('DriverOpts') not in (None, {}):
                reasons.append('unsupported-endpoint-options')
        # Never expose attacker-controlled label/env values or host paths.
        all_fields = extra_config + extra_host + extra_network + endpoint_fields
        if any(type(x) is not str or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}', x) for x in all_fields):
            fail()
        result[service] = {'extraConfigFields': extra_config, 'extraHostFields': extra_host,
            'extraNetworkSettingsFields': extra_network, 'endpointFields': endpoint_fields,
            'knownBlockers': sorted(set(reasons)), 'recipeEquivalence': 'not-assessed'}
    return {'schemaVersion': 1, 'kind': 'compose-engine-shape-report', 'services': result,
            'authorityGranted': False, 'executionAvailable': False, 'productionReady': False}


def capture(reader, project, image):
    if type(project) is not str or not PROJECT.fullmatch(project):
        fail()
    digest = validate_image(image)
    engine = preflight(reader)
    ids = inventory(reader, project)
    samples = inspect(reader, project, image, ids)
    for image_id in sorted({x['Image'] for x in samples.values()}):
        images = reader.object('image', 'inspect', image_id)
        if (type(images) is not list or len(images) != 1 or images[0].get('Id') != image_id
                or images[0].get('Os') != 'linux' or type(images[0].get('RepoDigests')) is not list
                or not any(type(ref) is str and ref in ('python@' + digest,
                           'docker.io/library/python@' + digest) for ref in images[0]['RepoDigests'])):
            fail()
    if inventory(reader, project) != ids or inspect(reader, project, image, ids) != samples:
        fail()
    if preflight(reader) != engine:
        fail()
    report = summarize(samples)
    report['engine'] = {k: v for k, v in engine.items() if k != 'daemonId'}
    report['image'] = image
    report['requestedApiVersion'] = '1.45'
    return {'schemaVersion': 1, 'kind': 'compose-private-engine-sample',
            'engine': engine, 'project': project, 'containers': samples,
            'runtimeVerification': 'diagnostic-only', 'productionReady': False}, report


def save_private(root, sample, report):
    if sys.platform != 'linux' or not isinstance(root, Path) or not root.is_absolute():
        fail()
    # Open every ancestor without following symlinks and pin the private root.
    import stat
    if '..' in root.parts or '.' in root.parts:
        fail()
    def open_root():
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in root.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            mode = os.fstat(fd)
            if stat.S_IMODE(mode.st_mode) != 0o700 or mode.st_uid != os.getuid():
                fail()
            return fd
        except BaseException:
            os.close(fd)
            raise
    directory = open_root()
    identity = os.fstat(directory)
    try:
        for name, value in (('sample.private.json', sample), ('report.json', report)):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                raw = canonical(value)
                if len(raw) > MAX_BYTES:
                    fail()
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        fail()
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(directory)
        current = open_root()
        try:
            after = os.fstat(current)
            if (after.st_dev, after.st_ino) != (identity.st_dev, identity.st_ino):
                fail()
        finally:
            os.close(current)
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('preflight', 'capture'))
    parser.add_argument('--image', required=True)
    parser.add_argument('--project')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        validate_image(args.image)
        reader = DockerReader()
        if args.mode == 'preflight':
            preflight(reader)
            print('Supported Linux Engine API 1.45 available; no authorization granted.')
        else:
            sample, report = capture(reader, args.project, args.image)
            save_private(args.output, sample, report)
            print('Private sample and diagnostic field report saved; productionReady=false.')
    except Exception:
        raise SystemExit('compose-engine-sample-rejected') from None


if __name__ == '__main__':
    main()
