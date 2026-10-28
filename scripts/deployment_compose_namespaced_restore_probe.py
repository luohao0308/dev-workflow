"""Stopped same-image restore diagnostic on an already verified private daemon.

No production writes, startup, Permit, freshness or source-provenance claims.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import uuid

from deployment_compose_namespaced_runtime_probe import PrivateDaemon, transfer_image, ensure_capacity
from deployment_compose_namespaced_transition_probe import source_image, delete
from deployment_compose_log_probe import IMAGE, ID
from deployment_compose_restore_host_config import _fixed_policy, OOM_ENABLED_POLICY as HOST_POLICY
from deployment_compose_private import commit, MOUNT
from deployment_compose_artifacts import ServiceArtifact
from deployment_compose_image_defaults import commit_image_config
from deployment_compose_image_reference import POLICY as REFERENCE_POLICY
from deployment_compose_network_declaration import commit_network_declaration
from deployment_compose_snapshot import prepare_snapshot, _encode
from deployment_compose_restore_body_host import compile_restore_body, METADATA_POLICY

RUNTIME_ENDPOINT = {'EndpointID', 'Gateway', 'IPAddress', 'IPPrefixLen', 'IPv6Gateway',
                    'GlobalIPv6Address', 'GlobalIPv6PrefixLen', 'DNSNames', 'MacAddress'}
STATIC_ENDPOINT = {'NetworkID', 'Aliases', 'IPAMConfig', 'Links', 'DriverOpts'}


def compare_restored(source, restored):
    """Exact private values; only explicitly classified generated network fields differ."""
    differences = []
    for field in ('Config', 'HostConfig', 'Mounts'):
        if _encode(source[field]) != _encode(restored[field]):
            differences.append(field)
    left, right = source['NetworkSettings'], restored['NetworkSettings']
    if set(left) != {'Ports', 'SandboxID', 'SandboxKey', 'Networks'} or set(right) != set(left):
        raise ValueError('unclassified-container-network-fields')
    if _encode(left['Ports']) != _encode(right['Ports']):
        differences.append('Ports')
    if set(left['Networks']) != set(right['Networks']):
        raise ValueError('restored-network-membership-drift')
    runtime = []
    for name, endpoint in left['Networks'].items():
        other = right['Networks'][name]
        allowed = STATIC_ENDPOINT | RUNTIME_ENDPOINT | {'GwPriority'}
        if set(endpoint) - allowed or set(other) != set(endpoint):
            raise ValueError('unclassified-endpoint-fields')
        for key in STATIC_ENDPOINT | ({'GwPriority'} & set(endpoint)):
            if _encode(endpoint[key]) != _encode(other[key]):
                differences.append('endpoint.' + key)
        runtime.extend('endpoint.' + key for key in RUNTIME_ENDPOINT
                       if _encode(endpoint[key]) != _encode(other[key]))
    runtime.extend(key for key in ('SandboxID', 'SandboxKey') if left[key] != right[key])
    return {'exactConfigHostMountAndDeclarationMatch': not differences,
            'unexplainedDifferenceFields': sorted(set(differences)),
            'classifiedGeneratedNetworkDifferenceFields': sorted(set(runtime)),
            'fullRuntimeNetworkIdentityEqual': not runtime}


def run_restore(root, info):
    target = PrivateDaemon(root, info)
    project = 'dw-restore-' + uuid.uuid4().hex[:24]
    network_name, volume = project + '-net', project + '-data'
    source_name = project + '-baseline'
    result = {'kind': 'namespace-stopped-restore', 'success': False,
              'unknownWriteResult': False, 'productionReady': False,
              'authorityGranted': False, 'executionAvailable': False,
              'actualProductWriterValidated': False, 'crashRecoveryValidated': False,
              'freshnessVerified': False, 'sourceProvenanceVerified': False,
              'cleanup': [], 'createdIds': []}
    known = []; network = None; volume_created = loaded = False
    phase = 'preflight'; bind = root / 'restore-config'
    before_networks = None
    def write(fn):
        result['unknownWriteResult'] = True
        value = fn()
        result['unknownWriteResult'] = False
        return value
    def inspect(receipt):
        rows = json.loads(target.run('container', 'inspect', receipt))
        if (len(rows) != 1 or rows[0]['Id'] != receipt
                or rows[0]['State']['Running'] is not False
                or rows[0]['State']['Status'] != 'created'):
            raise ValueError('stopped-container-identity-drift')
        return rows[0]
    def create(path, body):
        allowed = ('/v1.45/containers/create?name=' + source_name,
                   '/v1.45/containers/create?name=' + project + '-backend')
        if path not in allowed:
            raise ValueError('restore-create-path-outside-scope')
        connection = target.connection()
        try:
            connection.request('POST', path, _encode(body), {'Content-Type': 'application/json'})
            response = connection.getresponse(); raw = response.read(65537)
            if response.status != 201 or len(raw) > 65536:
                raise ValueError('unknown-restore-create-response')
            value = json.loads(raw); receipt = value.get('Id')
            if type(receipt) is not str or not ID.fullmatch(receipt) or receipt in known:
                raise ValueError('unknown-restore-create-id')
            known.append(receipt); result['createdIds'].append(receipt)
            return receipt
        finally:
            connection.close()
    try:
        fresh = json.loads(target.run('info', '--format', '{{json .}}'))
        if (fresh.get('ID') != info['ID'] or fresh.get('DockerRootDir') != str(root/'data')
                or fresh.get('SwapLimit') is not True or target.run('ps', '-aq').strip()
                or target.run('images', '-aq').strip() or target.run('volume', 'ls', '-q').strip()):
            raise ValueError('restore-daemon-not-private-and-empty')
        before_networks = sorted(target.run('network', 'ls', '-q', '--no-trunc').split())
        image = source_image(IMAGE); ensure_capacity(root, image)
        phase = 'image-import'; write(lambda: transfer_image(image['Id'], target)); loaded = True
        imported = json.loads(target.run('image', 'inspect', image['Id']))
        if len(imported) != 1 or any(_encode(imported[0].get(k)) != _encode(image.get(k))
                                    for k in ('Id', 'Os', 'Architecture', 'Config', 'RootFS')):
            raise ValueError('restore-imported-image-drift')
        phase = 'network-create'
        def make_network():
            receipt = target.run('network', 'create', '--internal', '--driver=bridge',
                                 '--label=com.docker.compose.project=' + project, network_name).strip()
            if not ID.fullmatch(receipt): raise ValueError('unknown-restore-network-id')
            return receipt
        network = write(make_network)
        phase = 'volume-create'
        def make_volume():
            if target.run('volume', 'create', '--driver=local',
                          '--label=com.docker.compose.project=' + project, volume).strip() != volume:
                raise ValueError('unknown-restore-volume')
        write(make_volume); volume_created = True
        volume_info = json.loads(target.run('volume', 'inspect', volume))[0]
        mountpoint = Path(volume_info['Mountpoint'])
        if (volume_info['Name'] != volume or volume_info['Driver'] != 'local'
                or volume_info['Labels'].get('com.docker.compose.project') != project
                or mountpoint != root/'data/volumes'/volume/'_data' or any(mountpoint.iterdir())):
            raise ValueError('restore-volume-ownership-drift')
        sentinel = mountpoint/'sentinel.txt'; sentinel.write_text(project + '\n')
        bind.mkdir(mode=0o700); (bind/'config.txt').write_text(project + '\n')
        host = _fixed_policy(policy=HOST_POLICY)
        host.update(NetworkMode=network_name, Mounts=[
            {'Type': 'volume', 'Source': volume, 'Target': '/sample-data', 'ReadOnly': False,
             'VolumeOptions': {'NoCopy': True}},
            {'Type': 'bind', 'Source': str(bind), 'Target': '/sample-config', 'ReadOnly': True}])
        body = {'Image': image['Id'], 'Hostname': 'restore-baseline', 'WorkingDir': '/tmp',
                'Cmd': ['/usr/local/bin/python3', '-c', 'pass'], 'Entrypoint': None,
                'Env': deepcopy(image['Config']['Env']),
                'Labels': {'com.docker.compose.project': project, 'com.docker.compose.service': 'backend',
                           'dev-workflow.fixture-metadata': 'retained-observed-value'},
                'Healthcheck': {'Test': ['CMD', '/usr/local/bin/python3', '-c', 'pass'],
                                'Interval': 1000000000, 'Timeout': 1000000000,
                                'StartPeriod': 1000000000, 'Retries': 3},
                'HostConfig': host, 'NetworkingConfig': {'EndpointsConfig': {
                    network_name: {'NetworkID': network, 'Aliases': ['backend']}}}}
        phase = 'baseline-create'
        baseline_id = write(lambda: create('/v1.45/containers/create?name=' + source_name, body))
        baseline = inspect(baseline_id)
        raw = {k: deepcopy(baseline[k]) for k in ('Id', 'Name', 'Image', 'Config', 'HostConfig', 'NetworkSettings', 'Mounts')}
        identity = dict(project=project, service='backend', containerId=baseline_id,
            containerName=source_name, imageId=image['Id'], hostId='restore-diagnostic',
            daemonId=info['ID'], requestedApiVersion='1.45', engineVersion=fresh['ServerVersion'])
        key, image_key, declaration_key = (os.urandom(32) for _ in range(3))
        projection = {k: raw[k] for k in ('Config', 'HostConfig', 'NetworkSettings')}
        projection['Mounts'] = [{**{k: None for k in MOUNT}, **m} for m in raw['Mounts']]
        artifact = ServiceArtifact('backend', 'a'*40, 'docker.io/library/' + IMAGE,
            image['Id'], 'linux', image['Architecture'], 'restore-test-key',
            commit(project, 'backend', projection, 'restore-test-key', key)['configHmac'], 'd'*64, 'none')
        networks = {network_name: network}
        mounts = {'/sample-data': {'type': 'volume', 'source': volume, 'readOnly': False},
                  '/sample-config': {'type': 'bind', 'source': str(bind), 'readOnly': True}}
        evidence = root/'restore-source.private.json'
        evidence.write_text(json.dumps({'raw': raw, 'identity': identity, 'artifact': asdict(artifact),
            'networkIds': networks, 'expectedMounts': mounts, 'image': image, 'fixturePrivateKeyHex': key.hex()},indent=2))
        evidence.chmod(0o600)
        phase = 'authenticated-composition'
        snapshot = prepare_snapshot(raw, identity, artifact, key, networks, mounts)
        declaration = {'schemaVersion': 1, 'identity': identity, 'sourceSha': artifact.source_sha,
            'sourceModelDigest': 'e'*64, 'sourceSnapshotDigest': hashlib.sha256(_encode(snapshot)).hexdigest(),
            'networks': {network_name: {'id': network,
                'aliases': deepcopy(raw['NetworkSettings']['Networks'][network_name]['Aliases']),
                'addressPolicy': 'dynamic-no-requested-addresses', 'requestedMac': None,
                'ipamConfig': None, 'links': None, 'driverOpts': None}}}
        proof = commit_network_declaration(declaration, 'restore-declaration-test', declaration_key)
        # Fixture assertions are labelled synthetic, never production provenance.
        candidate = compile_restore_body(raw, identity, artifact, key, networks, mounts,
            image, commit_image_config(image, 'restore-image-test', image_key), image_key,
            declaration, proof, declaration_key,
            expected_image_key_id='restore-image-test',
            expected_declaration_key_id='restore-declaration-test',
            expected_declaration_hmac=proof['declarationHmac'], expected_source_model_digest='e'*64,
            host_config_policy=HOST_POLICY, metadata_policy=METADATA_POLICY,
            operation_nonce=project[len('dw-restore-'):] + '0'*40,
            expected_observed_reference=IMAGE, reference_policy=REFERENCE_POLICY)
        phase = 'restored-create'
        restored_id = write(lambda: create(candidate['path'], candidate['body']))
        restored = inspect(restored_id)
        # The mapper's complete original snapshot defines the bounded network set.
        restored_raw = {k: deepcopy(restored[k]) for k in raw}
        comparison = compare_restored(raw, restored_raw)
        result['comparison'] = comparison
        result['compositionDigest'] = candidate['compositionDigest']
        result['bodySha256'] = candidate['bodySha256']
        result['sentinelPreserved'] = sentinel.read_text() == project + '\n'
        result['baselineUnchanged'] = _encode(inspect(baseline_id)) == _encode(baseline)
        if (not comparison['exactConfigHostMountAndDeclarationMatch'] or not result['sentinelPreserved']
                or not result['baselineUnchanged']):
            raise ValueError('restore-equivalence-or-data-preservation-failed')
        result['stoppedReconstructionValidated'] = True
    except Exception as error:
        result['failureType'] = type(error).__name__; result['failurePhase'] = phase
        if type(error) is ValueError: result['failureReason'] = str(error)
    finally:
        if not result['unknownWriteResult']:
            try:
                for receipt in reversed(known):
                    write(lambda receipt=receipt: delete(target, receipt)); result['cleanup'].append('container')
                if volume_created: write(lambda: target.run('volume', 'rm', volume)); result['cleanup'].append('volume')
                if network: write(lambda: target.run('network', 'rm', network)); result['cleanup'].append('network')
                if loaded: write(lambda: target.run('image', 'rm', image['Id'])); result['cleanup'].append('image')
                if bind.exists(): shutil.rmtree(bind)
                if (target.run('ps', '-aq').strip() or target.run('images', '-aq').strip()
                        or target.run('volume', 'ls', '-q').strip()
                        or sorted(target.run('network', 'ls', '-q', '--no-trunc').split()) != before_networks):
                    raise ValueError('restore-cleanup-inventory-drift')
                result['cleanupComplete'] = True
            except Exception as error:
                result['cleanupFailureType'] = type(error).__name__
        result['success'] = (result.get('stoppedReconstructionValidated') is True
                             and result.get('cleanupComplete') is True and not result['unknownWriteResult'])
    return result
