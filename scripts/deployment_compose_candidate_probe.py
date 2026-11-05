#!/usr/bin/env python3
"""Single stopped create-candidate experiment, isolated from deployment authority.

Creates one internal network, one empty volume, one private bind fixture and one
never-started container. Unknown write outcomes stop progress, with no retry or
cleanup by guessed identity. stdout is PRIVATE evidence. No pulls or global edits.
"""
from copy import deepcopy
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_create import compile_create
from deployment_compose_image_defaults import commit_image_config, derive_defaults
from deployment_compose_create_inspect import compare_create_inspect
from deployment_compose_log_probe import docker, inventory, diagnostic, IMAGE, ID


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/var/run/docker.sock')


def post_candidate(candidate):
    connection = UnixConnection('localhost', timeout=20)
    try:
        connection.request('POST', candidate['path'], json.dumps(candidate['body']),
                           {'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024 or response.status != 201:
            raise ValueError('candidate-create-response-rejected')
        return json.loads(raw)
    finally:
        connection.close()


def recipe_for(image, project, network_id, volume, bind):
    return {'schemaVersion': 3, 'project': project, 'service': 'candidate',
        'containerName': project + '-candidate', 'imageId': image['Id'],
        'process': {'user': '', 'workingDir': '', 'entrypoint': ['/usr/local/bin/python3'],
            'cmd': ['-c', 'pass'], 'env': sorted(image['Config'].get('Env') or [])},
        'hostConfig': {'privileged': False, 'readOnlyRootfs': True, 'capAdd': [],
            'devices': [], 'pidMode': 'private', 'ipcMode': 'private',
            'logConfig': {'type': 'none', 'config': {}},
            'restartPolicy': {'name': 'no', 'maximumRetryCount': 0},
            'resources': {'memoryBytes': 67108864, 'memorySwapBytes': 67108864,
                          'nanoCpus': 100000000, 'pidsLimit': 32}},
        'mounts': [{'type': 'bind', 'source': bind, 'target': '/probe/config.txt',
                   'readOnly': True, 'noCopy': False, 'createHostPath': False},
                  {'type': 'volume', 'source': volume, 'target': '/usr/local/bin',
                   'readOnly': False, 'noCopy': True, 'createHostPath': False}],
        'networks': [{'id': network_id, 'aliases': ['candidate']}], 'ports': [],
        'health': {'test': ['CMD', '/usr/local/bin/python3', '-c', 'pass'],
                   'intervalNs': 10000000000, 'timeoutNs': 20000000000, 'retries': 3}}


def resources(run):
    networks = [json.loads(line) for line in
        run('network', 'ls', '--no-trunc', '--format', '{{json .}}').splitlines()]
    volumes = run('volume', 'ls', '--format', '{{.Name}}').splitlines()
    ids = [item['ID'] for item in networks]
    if (any(type(value) is not str or not ID.fullmatch(value) for value in ids)
            or len(set(ids)) != len(ids) or len(set(volumes)) != len(volumes)):
        raise ValueError('invalid-resource-inventory')
    return {'networkIds': sorted(item['ID'] for item in networks),
            'networkNames': sorted(item['Name'] for item in networks), 'volumeNames': sorted(volumes)}


def probe(run=docker, post=post_candidate):
    project = 'dw-compose-sample-' + uuid.uuid4().hex[:24]
    network_name, volume_name = project + '-net', project + '-data'
    result = {'schemaVersion': 1, 'kind': 'compose-stopped-candidate-probe',
        'project': project, 'authorityGranted': False, 'executionAvailable': False,
        'reconstructionValidated': False, 'productionReady': False,
        'startRequestsIssued': 0, 'unknownWriteResult': False, 'cleanup': []}
    network_id = container_id = bind_root = None
    volume_created = False
    phase = 'preflight'
    try:
        info = json.loads(run('info', '--format', '{{json .}}'))
        if info.get('OSType') != 'linux' or not info.get('ID'):
            raise ValueError('unsupported-daemon')
        result['beforeContainers'] = inventory(run)
        result['beforeResources'] = resources(run)
        if network_name in result['beforeResources']['networkNames'] or volume_name in result['beforeResources']['volumeNames']:
            raise ValueError('existing-probe-name')
        images = json.loads(run('image', 'inspect', IMAGE))
        if len(images) != 1 or IMAGE not in images[0]['RepoDigests']:
            raise ValueError('unexpected-image')
        image = images[0]
        # A test key only authenticates locally supplied input, never authority.
        key = os.urandom(32)
        defaults = derive_defaults(image, commit_image_config(image, 'probe-test-key', key), key,
            expected_image_id=image['Id'], expected_registry_digest=IMAGE,
            expected_architecture=image['Architecture'])
        if any(defaults[key] for key in ('Volumes', 'ExposedPorts', 'Healthcheck', 'Labels')):
            raise ValueError('unsupported-image-defaults')
        phase = 'network-create'
        result['unknownWriteResult'] = True
        receipt = run('network', 'create', '--internal', '--driver=bridge',
            '--label=com.docker.compose.project=' + project, network_name).strip()
        if not ID.fullmatch(receipt) or receipt in result['beforeResources']['networkIds']:
            raise ValueError('unknown-network-receipt')
        network_id = receipt
        result['unknownWriteResult'] = False
        phase = 'network-inspect'
        net = json.loads(run('network', 'inspect', network_id))[0]
        if (net['Id'] != network_id or net['Name'] != network_name or net['Driver'] != 'bridge'
                or net['Internal'] is not True or net['Labels'].get('com.docker.compose.project') != project):
            raise ValueError('unexpected-network')
        phase = 'volume-create'
        result['unknownWriteResult'] = True
        receipt = run('volume', 'create', '--driver=local',
            '--label=com.docker.compose.project=' + project, volume_name).strip()
        if receipt != volume_name:
            raise ValueError('unknown-volume-receipt')
        phase = 'volume-inspect'
        vol = json.loads(run('volume', 'inspect', volume_name))[0]
        if (vol['Name'] != volume_name or vol['Driver'] != 'local'
                or vol['Labels'].get('com.docker.compose.project') != project):
            raise ValueError('unexpected-volume')
        volume_created = True
        result['unknownWriteResult'] = False
        bind_root = tempfile.mkdtemp(prefix=project + '-')
        bind = Path(bind_root) / 'config.txt'
        bind.write_text('isolated-candidate-bind-sentinel\n')
        bind.chmod(0o600)
        phase = 'compile'
        recipe = recipe_for(image, project, network_id, volume_name, str(bind))
        candidate = compile_create(recipe, baseline_image_id=image['Id'], image_defaults=defaults,
            identity={'hostId': 'diagnostic-host', 'daemonId': info['ID'], 'project': project,
                      'service': 'candidate', 'containerName': recipe['containerName']},
            network_ids={network_name: network_id}, allowed_mounts=deepcopy(recipe['mounts']), hostname='candidate-host')
        result['candidate'] = candidate
        phase = 'container-create'
        result['unknownWriteResult'] = True
        response = post(candidate)
        receipt = response.get('Id') if type(response) is dict else None
        if (type(receipt) is not str or not ID.fullmatch(receipt)
                or receipt in {item['id'] for item in result['beforeContainers']}):
            raise ValueError('unknown-container-receipt')
        container_id = receipt
        result['createReceipt'] = response
        result['unknownWriteResult'] = False
        phase = 'container-inspect'
        values = json.loads(run('container', 'inspect', container_id))
        if (len(values) != 1 or values[0]['Id'] != container_id
                or values[0]['State']['Status'] != 'created' or values[0]['State']['Running'] is not False):
            raise ValueError('unexpected-created-container')
        result['inspect'] = values[0]
        result['comparison'] = compare_create_inspect(candidate, values[0], expected_receipt_id=container_id)
        result['bindSentinelUnchanged'] = bind.read_text() == 'isolated-candidate-bind-sentinel\n'
        result['completed'] = True
    except (OSError, ValueError, KeyError, TypeError, IndexError, http.client.HTTPException,
            subprocess.SubprocessError) as error:
        result['privateFailure'] = diagnostic(error, phase)
    finally:
        # If any write outcome is unknown, preserve all dependencies for review.
        clean = not result['unknownWriteResult']
        for kind, receipt in [('container', container_id), ('volume', volume_name if volume_created else None), ('network', network_id)]:
            if receipt is None or not clean:
                continue
            try:
                output = run(kind, 'rm', receipt).strip()
                if output != receipt:
                    raise ValueError('unknown-cleanup-result')
                result['cleanup'].append({'kind': kind, 'removed': True})
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                clean = False
                result['cleanup'].append({'kind': kind, 'removed': False,
                    'privateFailure': diagnostic(error, kind + '-cleanup')})
        result['bindDirectoryRemoved'] = False
        if bind_root and clean:
            try:
                shutil.rmtree(bind_root)
                result['bindDirectoryRemoved'] = True
            except OSError as error:
                result['privateBindCleanupFailure'] = diagnostic(error, 'bind-cleanup')
                result['retainedBindDirectory'] = bind_root
        elif bind_root:
            result['retainedBindDirectory'] = bind_root
        try:
            result['afterContainers'] = inventory(run)
            result['afterResources'] = resources(run)
            result['existingContainersUnchanged'] = result.get('beforeContainers') == result['afterContainers']
            result['resourceInventoryUnchanged'] = result.get('beforeResources') == result['afterResources']
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            result['privateAfterFailure'] = diagnostic(error, 'after-inventory')
    result['experimentCompleted'] = bool(result.get('completed') and not result['unknownWriteResult']
        and len(result['cleanup']) == 3 and all(item['removed'] for item in result['cleanup'])
        and result['bindDirectoryRemoved']
        and result.get('existingContainersUnchanged') and result.get('resourceInventoryUnchanged'))
    result['validationPassed'] = bool(result['experimentCompleted'] and result.get('bindSentinelUnchanged')
        and result.get('comparison', {}).get('explicitRequestedFieldsMatch'))
    result['success'] = result['validationPassed']
    return result


if __name__ == '__main__':
    if sys.platform != 'linux':
        sys.exit('linux-required')
    evidence = probe()
    print(json.dumps(evidence, sort_keys=True, allow_nan=False))
    sys.exit(0 if evidence['success'] else 1)
