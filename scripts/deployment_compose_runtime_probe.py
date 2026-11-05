#!/usr/bin/env python3
"""Two-service runtime experiment only; no deployment/recovery authority.

Only own confirmed receipts may be started, stopped, or removed. Unknown write
outcomes retain all dependencies. stdout contains PRIVATE diagnostics/inputs.
"""
from copy import deepcopy
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packs/deployment/scripts'))
sys.path.insert(0, str(ROOT / 'tests/support'))
from deployment_compose_candidate_probe import UnixConnection, post_candidate, recipe_for, resources
from deployment_compose_log_probe import docker, inventory, diagnostic, IMAGE, ID
from deployment_compose_create import compile_create
from deployment_compose_create_inspect import compare_create_inspect_wire
from deployment_compose_image_defaults import commit_image_config, derive_defaults
from compose_runtime_probe import CHECKS, make_server_code, make_health_code, make_peer_code


def runtime_recipe(image, project, network_id, volume, bind, role, token):
    recipe = recipe_for(image, project, network_id, volume, bind)
    recipe.update(service=role, containerName=project + '-' + role)
    # Keep the existing recipe argument-size contract. Fixture source is a
    # precreated read-only file, not a widened arbitrary command allowance.
    recipe['process']['cmd'] = ['-u', '/probe/runtime.py']
    env = {item.partition('=')[0]: item.partition('=')[2] for item in recipe['process']['env']}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    recipe['process']['env'] = sorted(key + '=' + value for key, value in env.items())
    recipe['networks'][0]['aliases'] = [role]
    recipe['mounts'][1].update(target='/usr/local/include' if role == 'backend' else '/data',
                                readOnly=role == 'frontend')
    for filename, target in ((role + '-runtime.py', '/probe/runtime.py'),
                             (role + '-health.py', '/probe/health.py')):
        recipe['mounts'].append({'type': 'bind', 'source': str(Path(bind).with_name(filename)),
            'target': target, 'readOnly': True, 'noCopy': False, 'createHostPath': False})
    recipe['mounts'].sort(key=lambda item: item['target'])
    recipe['health'].update(test=['CMD', '/usr/local/bin/python3', '/probe/health.py'],
                            retries=8)
    return recipe


def wait_healthy(run, receipt, *, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + 120
    while clock() < deadline:
        values = json.loads(run('container', 'inspect', receipt))
        if len(values) != 1 or values[0]['Id'] != receipt:
            raise ValueError('unexpected-runtime-container')
        state = values[0]['State']
        if state.get('Running') is not True:
            raise ValueError('runtime-container-not-running')
        health = state.get('Health', {}).get('Status')
        if health == 'healthy':
            return values[0]
        if health == 'unhealthy':
            raise ValueError('runtime-container-unhealthy')
        sleep(1)
    raise ValueError('runtime-health-deadline')


def stop_container(receipt):
    """Stop a known ID by fixed API status, independent of CLI presentation."""
    if type(receipt) is not str or not ID.fullmatch(receipt):
        raise ValueError('invalid-stop-identity')
    connection = UnixConnection('localhost', timeout=20)
    try:
        connection.request('POST', '/v1.45/containers/' + receipt + '/stop?t=10')
        response = connection.getresponse()
        body = response.read(4097)
        if response.status not in (204, 304) or body:
            raise ValueError('unknown-stop-response')
        return receipt
    finally:
        connection.close()


def probe(run=docker, post=post_candidate, healthy=wait_healthy, stop=stop_container, *, image_evidence=None):
    project = 'dw-compose-sample-' + uuid.uuid4().hex[:24]
    names = {'network': project + '-net', 'volume': project + '-data'}
    result = {'schemaVersion': 1, 'kind': 'compose-runtime-candidate-probe',
        'project': project, 'authorityGranted': False, 'executionAvailable': False,
        'reconstructionValidated': False, 'productionReady': False,
        'unknownWriteResult': False, 'containers': {}, 'cleanup': []}
    network_id = bind_root = None
    volume_created = False
    receipts, started = [], set()
    phase = 'preflight'
    try:
        info = json.loads(run('info', '--format', '{{json .}}'))
        if info.get('OSType') != 'linux' or not info.get('ID'):
            raise ValueError('unsupported-daemon')
        result['beforeContainers'], result['beforeResources'] = inventory(run), resources(run)
        if (names['network'] in result['beforeResources']['networkNames']
                or names['volume'] in result['beforeResources']['volumeNames']):
            raise ValueError('existing-probe-name')
        image_ref = IMAGE if image_evidence is None else image_evidence['Id']
        images = json.loads(run('image', 'inspect', image_ref))
        if len(images) != 1:
            raise ValueError('unexpected-image')
        if image_evidence is None:
            if IMAGE not in images[0]['RepoDigests']:
                raise ValueError('unexpected-image')
            image = images[0]
        else:
            if (type(image_evidence) is not dict or IMAGE not in image_evidence.get('RepoDigests', [])
                    or json.dumps({k:images[0].get(k) for k in ('Id','Os','Architecture','Config')},
                                  sort_keys=True,allow_nan=False) !=
                       json.dumps({k:image_evidence.get(k) for k in ('Id','Os','Architecture','Config')},
                                  sort_keys=True,allow_nan=False)):
                raise ValueError('imported-image-identity-mismatch')
            image = deepcopy(image_evidence)
            result['importedImageInspect'] = deepcopy(images[0])
            result['imageTransferIdentityMatched'] = True
            result['imageRegistryEvidenceSource'] = 'unmodified-source-daemon-inspection'
            result['registryProvenanceVerified'] = False
        key = os.urandom(32)
        defaults = derive_defaults(image, commit_image_config(image, 'probe-test-key', key), key,
            expected_image_id=image['Id'], expected_registry_digest=IMAGE,
            expected_architecture=image['Architecture'])
        if any(defaults[key] for key in ('Volumes', 'ExposedPorts', 'Healthcheck', 'Labels')):
            raise ValueError('unsupported-image-defaults')
        result['imageDefaults'] = defaults
        phase = 'network-create'
        result['unknownWriteResult'] = True
        receipt = run('network', 'create', '--internal', '--driver=bridge',
            '--label=com.docker.compose.project=' + project, names['network']).strip()
        if not ID.fullmatch(receipt) or receipt in result['beforeResources']['networkIds']:
            raise ValueError('unknown-network-receipt')
        network_id = receipt
        result['unknownWriteResult'] = False
        net = json.loads(run('network', 'inspect', network_id))[0]
        if (net['Id'] != network_id or net['Name'] != names['network'] or net['Driver'] != 'bridge'
                or net['Internal'] is not True or net['Labels'].get('com.docker.compose.project') != project):
            raise ValueError('unexpected-network')
        phase = 'volume-create'
        result['unknownWriteResult'] = True
        receipt = run('volume', 'create', '--driver=local',
            '--label=com.docker.compose.project=' + project, names['volume']).strip()
        if receipt != names['volume']:
            raise ValueError('unknown-volume-receipt')
        vol = json.loads(run('volume', 'inspect', names['volume']))[0]
        if (vol['Name'] != names['volume'] or vol['Driver'] != 'local'
                or vol['Labels'].get('com.docker.compose.project') != project):
            raise ValueError('unexpected-volume')
        volume_created, result['unknownWriteResult'] = True, False
        bind_root = tempfile.mkdtemp(prefix=project + '-')
        bind = Path(bind_root) / 'config.txt'
        bind.write_text(project + '\n')
        bind.chmod(0o600)
        for role in ('backend', 'frontend'):
            phase = role + '-compile'
            for filename, source in ((role + '-runtime.py', make_server_code(role, project)),
                                     (role + '-health.py', make_health_code(role, project))):
                path = Path(bind_root) / filename
                path.write_text(source)
                path.chmod(0o600)
            recipe = runtime_recipe(image, project, network_id, names['volume'], str(bind), role, project)
            candidate = compile_create(recipe, baseline_image_id=image['Id'], image_defaults=defaults,
                identity={'hostId': 'diagnostic-host', 'daemonId': info['ID'], 'project': project,
                    'service': role, 'containerName': recipe['containerName']},
                network_ids={names['network']: network_id}, allowed_mounts=deepcopy(recipe['mounts']), hostname=role)
            observation = result['containers'][role] = {'candidate': candidate}
            phase = role + '-create'
            result['unknownWriteResult'] = True
            response = post(candidate)
            receipt = response.get('Id') if type(response) is dict else None
            if (type(receipt) is not str or not ID.fullmatch(receipt) or receipt in receipts
                    or receipt in {item['id'] for item in result['beforeContainers']}):
                raise ValueError('unknown-container-receipt')
            receipts.append(receipt)
            observation['receipt'] = receipt
            result['unknownWriteResult'] = False
            phase = role + '-inspect'
            values = json.loads(run('container', 'inspect', receipt))
            if (len(values) != 1 or values[0]['State']['Running'] is not False
                    or values[0]['State']['Status'] != 'created'):
                raise ValueError('unexpected-created-container')
            observation['createdInspect'] = values[0]
            comparison = compare_create_inspect_wire(candidate, values[0], expected_receipt_id=receipt,
                                                      image_defaults=defaults)
            observation['comparison'] = comparison
            if not comparison['requestedFieldsMatchUnderWireProfile']:
                raise ValueError('unexplained-create-difference')
        for role in ('backend', 'frontend'):
            observation = result['containers'][role]
            receipt = observation['receipt']
            phase = role + '-start'
            result['unknownWriteResult'] = True
            if run('container', 'start', receipt).strip() != receipt:
                raise ValueError('unknown-start-receipt')
            started.add(receipt)
            result['unknownWriteResult'] = False
            phase = role + '-health'
            observation['healthyInspect'] = healthy(run, receipt)
        for role, peer in (('backend', 'frontend'), ('frontend', 'backend')):
            phase = role + '-peer-exec'
            # Exec is treated as a write: it may have run if transport fails.
            result['unknownWriteResult'] = True
            output = run('container', 'exec', result['containers'][role]['receipt'],
                '/usr/local/bin/python3', '-c', make_peer_code(peer, project))
            response = json.loads(output)
            if (type(response) is not dict or set(response) != {'role', 'token', 'checks'}
                    or response['role'] != peer or response['token'] != project
                    or type(response['checks']) is not dict or set(response['checks']) != set(CHECKS[peer])
                    or any(value is not True for value in response['checks'].values())):
                raise ValueError('unexpected-peer-receipt')
            result['containers'][role]['peerResult'] = response
            result['unknownWriteResult'] = False
        result['bindSentinelUnchanged'] = bind.read_text() == project + '\n'
        if not result['bindSentinelUnchanged']:
            raise ValueError('bind-sentinel-changed')
        result['completed'] = True
    except (OSError, ValueError, KeyError, TypeError, IndexError, http.client.HTTPException,
            subprocess.SubprocessError) as error:
        result['privateFailure'] = diagnostic(error, phase)
    finally:
        clean = not result['unknownWriteResult']
        for receipt in reversed(receipts):
            if not clean:
                break
            try:
                if receipt in started:
                    result['unknownWriteResult'] = True
                    if stop(receipt) != receipt:
                        raise ValueError('unknown-stop-receipt')
                    result['unknownWriteResult'] = False
                result['unknownWriteResult'] = True
                if run('container', 'rm', receipt).strip() != receipt:
                    raise ValueError('unknown-remove-receipt')
                result['unknownWriteResult'] = False
                result['cleanup'].append({'kind': 'container', 'removed': True})
            except (OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError) as error:
                clean = False
                result['cleanup'].append({'kind': 'container', 'removed': False,
                    'privateFailure': diagnostic(error, 'container-cleanup')})
        for kind, receipt in [('volume', names['volume'] if volume_created else None), ('network', network_id)]:
            if receipt is None or not clean:
                continue
            try:
                result['unknownWriteResult'] = True
                if run(kind, 'rm', receipt).strip() != receipt:
                    raise ValueError('unknown-cleanup-receipt')
                result['unknownWriteResult'] = False
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
        if bind_root and not result['bindDirectoryRemoved']:
            result['retainedBindDirectory'] = bind_root
        try:
            result['afterContainers'], result['afterResources'] = inventory(run), resources(run)
            result['existingContainersUnchanged'] = result.get('beforeContainers') == result['afterContainers']
            result['resourceInventoryUnchanged'] = result.get('beforeResources') == result['afterResources']
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            result['privateAfterFailure'] = diagnostic(error, 'after-inventory')
    result['success'] = bool(result.get('completed') and not result['unknownWriteResult']
        and len(result['cleanup']) == 4 and all(item['removed'] for item in result['cleanup'])
        and result['bindDirectoryRemoved'] and result.get('existingContainersUnchanged')
        and result.get('resourceInventoryUnchanged'))
    return result


if __name__ == '__main__':
    if sys.platform != 'linux':
        sys.exit('linux-required')
    evidence = probe()
    print(json.dumps(evidence, sort_keys=True, allow_nan=False))
    sys.exit(0 if evidence['success'] else 1)
