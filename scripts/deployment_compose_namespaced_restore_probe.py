"""Same-image restore diagnostic on an already verified private daemon.

Startup is opt-in for an isolated restart experiment. No production writes,
Permit, freshness or source-provenance claims.
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
from deployment_compose_restore_body_host import compile_restore_body, METADATA_POLICY, RUNNING_METADATA_POLICY

RUNTIME_ENDPOINT = {'EndpointID', 'Gateway', 'IPAddress', 'IPPrefixLen', 'IPv6Gateway',
                    'GlobalIPv6Address', 'GlobalIPv6PrefixLen', 'DNSNames', 'MacAddress'}
from deployment_compose_runtime_probe import wait_healthy
from compose_restore_probe import server_code, health_code, client_code

STABLE_FIELDS = ('Id', 'Name', 'Image', 'Config', 'HostConfig', 'NetworkSettings', 'Mounts')

def stable_snapshot(row):
    return {k: deepcopy(row[k]) for k in STABLE_FIELDS}

def verify_running_source(baseline, current):
    if (_encode(stable_snapshot(baseline)) != _encode(stable_snapshot(current))
            or current.get('State', {}).get('Running') is not True
            or current.get('State', {}).get('Health', {}).get('Status') != 'healthy'
            or ('StartedAt' in baseline.get('State', {}) and
                baseline['State']['StartedAt'] != current.get('State', {}).get('StartedAt'))
            or ('RestartCount' in baseline and
                _encode(baseline['RestartCount']) != _encode(current.get('RestartCount')))):
        raise ValueError('restore-running-source-drift')

def compare_created(source, restored, body, server):
    adjusted = deepcopy(restored)
    accepted = []
    if (body['HostConfig'].get('OomKillDisable', 'missing') is None
            and source['HostConfig'].get('OomKillDisable', 'missing') is None
            and restored['HostConfig'].get('OomKillDisable') is False
            and server.get('Version') == '29.8.2'
            and server.get('GitCommit') in ('8af9fe3', '8af9fe3a36bab3e039862a2ab1cef1880c9b4d03')
            and server.get('RequestedApiVersion') == '1.45'):
        adjusted['HostConfig']['OomKillDisable'] = None
        accepted.append('HostConfig.OomKillDisable:null-to-false-at-create')
    result = compare_restored(source, adjusted)
    result['acceptedCreateDefaultFields'] = accepted
    result['rawExactConfigHostMountAndDeclarationMatch'] = compare_restored(source, restored)['exactConfigHostMountAndDeclarationMatch']
    return result

def created_id(value, known):
    receipt = value.get('Id') if type(value) is dict else None
    if type(receipt) is not str or not ID.fullmatch(receipt) or receipt in known:
        raise ValueError('unknown-restore-create-id')
    return receipt

def switch_stopped_restore(target, old, new, write, start, precheck, *, baseline):
    if (baseline.get('Id') != old or precheck['exactConfigHostMountAndDeclarationMatch'] is not True):
        raise ValueError('restore-precheck-failed-before-switch')
    write(lambda: target.stop(old))
    rows = json.loads(target.run('container', 'inspect', old))
    if len(rows) != 1 or rows[0]['Id'] != old or rows[0]['State']['Running'] is not False:
        raise ValueError('restore-old-stop-not-confirmed')
    stopped = rows[0]
    if (any(_encode(baseline[field]) != _encode(stopped.get(field))
            for field in ('Config', 'HostConfig', 'Mounts'))
            or ('StartedAt' in baseline.get('State', {}) and
                _encode(baseline['State']['StartedAt']) != _encode(stopped['State'].get('StartedAt')))
            or ('RestartCount' in baseline and
                _encode(baseline['RestartCount']) != _encode(stopped.get('RestartCount')))):
        raise ValueError('restore-old-lifecycle-or-configuration-drift-after-stop')
    start(new)

def complete_restore_validation(result, *, restore_running):
    if (result['comparison']['exactConfigHostMountAndDeclarationMatch'] is not True
            or result['sentinelPreserved'] is not True or result['baselineUnchanged'] is not True):
        raise ValueError('restore-equivalence-or-data-preservation-failed')
    result['runningReconstructionValidated' if restore_running else 'stoppedReconstructionValidated'] = True

def restore_succeeded(result, *, restore_running):
    return (result.get('runningReconstructionValidated' if restore_running else 'stoppedReconstructionValidated') is True
            and result.get('comparison', {}).get('exactConfigHostMountAndDeclarationMatch') is True
            and result.get('sentinelPreserved') is True and result.get('baselineUnchanged') is True
            and result.get('cleanupComplete') is True and result.get('unknownWriteResult') is False
            and 'failureType' not in result and 'cleanupFailureType' not in result)

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


def run_restore(root, info, *, restore_running=False, source_host_config_policy=HOST_POLICY,
                retain_archive=False, archive_fault=None, archive_transport='test-seam',
                registry_enrollment=None):
    target = PrivateDaemon(root, info)
    project = 'dw-restore-' + uuid.uuid4().hex[:24]
    network_name, volume = project + '-net', project + '-data'
    source_name = project + '-baseline'
    result = {'kind': 'namespace-running-restore' if restore_running else 'namespace-stopped-restore', 'success': False,
              'unknownWriteResult': False, 'productionReady': False,
              'authorityGranted': False, 'executionAvailable': False,
              'actualProductWriterValidated': False, 'crashRecoveryValidated': False,
              'freshnessVerified': False, 'sourceProvenanceVerified': False,
              'cleanup': [], 'createdIds': [], 'switchEntered': False}
    recovery_store = None
    gateway_close = whole_check = None
    registered_reference = None
    recovery = observer = observation = None
    archive_reference = None
    initial_retention_binding = None
    result.update(archiveInputRequested=retain_archive, realObservationTransportValidated=False)
    running = set()
    known = []; network = None; volume_created = loaded = False
    phase = 'preflight'; bind = root / 'restore-config'
    before_networks = None
    def write(fn):
        if result['unknownWriteResult']:
            raise ValueError('restore-write-blocked-after-unknown')
        result['unknownWriteResult'] = True
        value = fn()
        result['unknownWriteResult'] = False
        return value
    def start(receipt):
        def execute():
            if target.run('container', 'start', receipt).strip() != receipt:
                raise ValueError('unknown-restore-start-response')
        write(execute); running.add(receipt)
        return wait_healthy(target.run, receipt)
    def business(receipt, expected_ip):
        def execute():
            data = json.loads(target.run('container', 'exec', receipt, '/usr/local/bin/python3', '-c',
                client_code('backend', project, expected_ip)))
            expected = {'token': project, 'dnsMatchesExpectedIP': True, 'health': True, 'business': True,
                'checks': {'sentinelPreserved': True, 'bindReadonly': True, 'rootReadonly': True}}
            if _encode(data) != _encode(expected): raise ValueError('restore-business-probe-failed')
            return data
        return write(execute)
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
            receipt = created_id(json.loads(raw), known)
            known.append(receipt); result['createdIds'].append(receipt)
            return receipt
        finally:
            connection.close()
    try:
        if type(restore_running) is not bool or type(retain_archive) is not bool:
            raise ValueError('restore-mode-not-boolean')
        if archive_transport not in ('test-seam','mtls-source') or archive_transport=='mtls-source' and not retain_archive:
            raise ValueError('invalid-archive-observation-transport')
        if registry_enrollment is not None:
            from deployment_compose_registry_enrollment_probe import registry_settings
            registered_reference,_,_ = registry_settings(registry_enrollment)
        if retain_archive and not restore_running:
            raise ValueError('retained-restore-requires-running-diagnostic')
        allowed_faults = {None, *(mode+'-before-'+stage for mode in ('missing','tampered','swapped') for stage in ('create','switch'))}
        if archive_fault not in allowed_faults or archive_fault is not None and not retain_archive:
            raise ValueError('invalid-retained-restore-fault')
        _fixed_policy(policy=source_host_config_policy)
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
        if registry_enrollment is not None:
            from deployment_compose_registry_enrollment_probe import enroll_image
            phase = 'registry-enrollment'
            image, result['registryEnrollment'] = write(lambda: enroll_image(root,target,image,registry=registry_enrollment))
        artifact_reference = registered_reference or 'docker.io/library/' + IMAGE
        observed_reference = registered_reference or IMAGE
        phase = 'network-create'
        def make_network():
            receipt = target.run('network', 'create', '--internal', '--driver=bridge',
                                 '--label=com.docker.compose.project=' + project, network_name).strip()
            if not ID.fullmatch(receipt): raise ValueError('unknown-restore-network-id')
            return receipt
        network = write(make_network)
        phase = 'volume-create'
        def make_volume():
            if archive_transport=='mtls-source':
                connection=target.connection()
                try:
                    connection.request('POST','/v1.45/volumes/create',_encode({'Name':volume,'Driver':'local',
                        'DriverOpts':{},'Labels':{'com.docker.compose.project':project}}),{'Content-Type':'application/json'})
                    response=connection.getresponse();data=response.read(65537)
                    if response.status!=201 or len(data)>65536:
                        raise ValueError('unknown-restore-volume')
                    value=json.loads(data)
                    if value.get('Name')!=volume or value.get('Driver')!='local' or value.get('Labels',{}).get('com.docker.compose.project')!=project:
                        raise ValueError('unknown-restore-volume')
                finally:connection.close()
            elif target.run('volume', 'create', '--driver=local',
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
        host = _fixed_policy(policy=source_host_config_policy)
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
        if restore_running:
            body['Cmd'] = ['/usr/local/bin/python3', '-c', server_code(project)]
            body['Healthcheck']['Test'] = ['CMD', '/usr/local/bin/python3', '-c', health_code(project)]
            body['Healthcheck']['Timeout'] = 20000000000
        phase = 'baseline-create'
        baseline_id = write(lambda: create('/v1.45/containers/create?name=' + source_name, body))
        baseline = start(baseline_id) if restore_running else inspect(baseline_id)
        raw = {k: deepcopy(baseline[k]) for k in ('Id', 'Name', 'Image', 'Config', 'HostConfig', 'NetworkSettings', 'Mounts')}
        engine_raw = deepcopy(raw)
        if retain_archive:
            from compose_restore_observer_fixture import archive_snapshot
            raw = archive_snapshot(baseline)
        identity = dict(project=project, service='backend', containerId=baseline_id,
            containerName=source_name, imageId=image['Id'], hostId='restore-diagnostic',
            daemonId=info['ID'], requestedApiVersion='1.45', engineVersion=fresh['ServerVersion'])
        key, image_key, declaration_key = (os.urandom(32) for _ in range(3))
        projection = {k: raw[k] for k in ('Config', 'HostConfig', 'NetworkSettings')}
        projection['Mounts'] = [{**{k: None for k in MOUNT}, **m} for m in raw['Mounts']]
        artifact = ServiceArtifact('backend', 'a'*40, artifact_reference,
            image['Id'], 'linux', image['Architecture'], 'restore-test-key',
            commit(project, 'backend', projection, 'restore-test-key', key)['configHmac'], 'd'*64, 'none')
        networks = {network_name: network}
        mounts = {'/sample-data': {'type': 'volume', 'source': volume, 'readOnly': False},
                  '/sample-config': {'type': 'bind', 'source': str(bind), 'readOnly': True}}
        evidence = root/'restore-source.private.json'
        evidence.write_text(json.dumps({'raw': raw, 'identity': identity, 'artifact': asdict(artifact),
            'networkIds': networks, 'expectedMounts': mounts, 'image': image, 'fixturePrivateKeyHex': key.hex(),
            'engineRaw': engine_raw, 'volumeInfo':volume_info,'archiveProjectionRepresentation': retain_archive},indent=2))
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
        image_proof = commit_image_config(image, 'restore-image-test', image_key)
        compile_pins = dict(identity=identity, private_key=key, network_ids=networks,
            expected_mounts=mounts, image=image, image_commitment=image_proof, image_key=image_key,
            declaration=declaration, declaration_proof=proof, declaration_key=declaration_key,
            expected_image_key_id='restore-image-test', expected_declaration_key_id='restore-declaration-test',
            expected_declaration_hmac=proof['declarationHmac'], expected_source_model_digest='e'*64,
            host_config_policy=source_host_config_policy,
            metadata_policy=RUNNING_METADATA_POLICY if restore_running else METADATA_POLICY,
            operation_nonce=project[len('dw-restore-'):] + '0'*40,
            expected_observed_reference=observed_reference, reference_policy=REFERENCE_POLICY)
        def corrupt_archive(stage):
            nonlocal archive_reference
            if archive_fault is None or not archive_fault.endswith('-before-'+stage):
                return
            control = retained_candidate()
            if initial_retention_binding is not None and _encode(control['retentionBinding']) != _encode(initial_retention_binding):
                raise ValueError('archive-fault-control-binding-drift')
            observer.retention_commitment(observation)
            result['archiveControlValidBeforeFault'] = True
            result['archiveFaultInjected'] = archive_fault
            entry = archive_root/archive_reference
            if archive_fault.startswith('missing-'): entry.unlink()
            elif archive_fault.startswith('tampered-'): entry.write_bytes(b'corrupt-fixture-archive')
            else: archive_reference = recovery_store.put(b'{"kind":"other-fixture-archive"}')
        def retained_candidate():
            from deployment_compose_restore_body_host import compile_retained_restore_body
            return compile_retained_restore_body(recovery, archive_reference, observer, observation,
                service=artifact.service, **compile_pins)
        if retain_archive:
            from compose_restore_observer_fixture import archive_observer
            from deployment_compose_recovery_host import ComposeRecoveryHost
            from deployment_compose_recovery_store import ComposeRecoveryStore
            from deployment_compose_operations import BaselineContainer
            phase = 'archive-retain'
            if archive_transport == 'mtls-source':
                from compose_restore_tls_fixture import source_observer
                observer, observation, gateway_close, tls_evidence, whole_check = source_observer(
                    root,target,identity,artifact,key,raw,networks,mounts)
                result.update(tls_evidence)
                try: observer.commitment(observation)
                except ValueError as error:
                    if str(error) != 'whole-project-observation-required': raise
                    result['sourceAuthorityCommitmentDenied'] = True
                else: raise ValueError('source-view-authority-must-be-denied')
            else:
                observer, observation = archive_observer(target, identity, artifact, key, image,
                    image_proof, image_key, expected_image_key_id='restore-image-test', expected_observed_reference=observed_reference)
            archive_root = root/'restore-archive'; archive_root.mkdir(mode=0o700)
            archive_key = os.urandom(32)
            keyfile = root/'restore-archive-test.key'; keyfile.write_bytes(archive_key); keyfile.chmod(0o600)
            recovery_store = ComposeRecoveryStore(archive_root, key=archive_key)
            recovery = ComposeRecoveryHost(store=recovery_store, observer=observer,
                baseline=(BaselineContainer('backend', baseline_id, source_name, image['Id']),),
                projections={'backend': projection}, private_keys={'restore-test-key': key})
            archive_reference = recovery.retain(observation)
            result.update(archiveReference=archive_reference,
                archiveObservationKind=('real-mtls-pinned-container-source' if archive_transport=='mtls-source'
                                        else 'test-seam-with-live-private-daemon-reads'),
                archiveSnapshotRepresentation='private-projection-complete-mount-fields-v1')
            corrupt_archive('create'); phase = 'archive-compile'
            retained = retained_candidate(); candidate = retained['candidate']
            direct = compile_restore_body(raw=raw, artifact=artifact, **compile_pins)
            if _encode(candidate) != _encode(direct):
                raise ValueError('retained-and-direct-restore-body-drift')
            initial_retention_binding = retained['retentionBinding']
            result['retentionBinding'] = initial_retention_binding
            result['retainedCandidateMatchesDirect'] = True
        else:
            candidate = compile_restore_body(raw=raw, artifact=artifact, **compile_pins)
        phase = 'restored-create'
        restored_id = write(lambda: create(candidate['path'], candidate['body']))
        restored = inspect(restored_id)
        if whole_check is not None:
            result['wholeInventoryRejectedAdditionalCandidate'] = whole_check(403)
        # The mapper's complete original snapshot defines the bounded network set.
        restored_raw = {k: deepcopy(restored[k]) for k in raw}
        if retain_archive:
            restored_raw = archive_snapshot(restored)
        if restore_running:
            phase = 'running-precheck'
            server = json.loads(target.run('version', '--format', '{{json .Server}}'))
            # The create path is fixed above to API1.45; server ApiVersion is its maximum.
            server = dict(server, RequestedApiVersion='1.45')
            result['privateServerVersion'] = server
            comparison = compare_created(raw, restored_raw, candidate['body'], server)
            if not comparison['exactConfigHostMountAndDeclarationMatch']:
                raise ValueError('restore-precheck-failed-before-switch')
            healthy_source = wait_healthy(target.run, baseline_id)
            verify_running_source(baseline, healthy_source)
            result['baselineStableBeforeSwitch'] = True
            old_ip = raw['NetworkSettings']['Networks'][network_name]['IPAddress']
            result['oldBusinessProbe'] = business(baseline_id, old_ip)
            verify_running_source(baseline, wait_healthy(target.run, baseline_id))
            if retain_archive:
                phase = 'archive-pre-switch-recheck'; corrupt_archive('switch')
                checked = retained_candidate()
                if (_encode(checked['retentionBinding']) != _encode(initial_retention_binding)
                        or _encode(checked['candidate']) != _encode(candidate)):
                    raise ValueError('retained-restore-pre-switch-drift')
                result['archiveReverifiedBeforeSwitch'] = True
                if archive_transport=='mtls-source':
                    if _encode(observer._reader.gateway_info()) != _encode(result['bootInfo']):
                        raise ValueError('source-tls-gateway-restarted')
                    result['sourceGatewayStableAcrossCandidate'] = True
            phase = 'running-switch'
            def start_replacement(receipt):
                result['switchBaselineStopped'] = True
                running.discard(baseline_id)
                start(receipt)
            result['switchEntered'] = True
            switch_stopped_restore(target, baseline_id, restored_id, write, start_replacement, comparison, baseline=baseline)
            replacement = wait_healthy(target.run, restored_id)
            new_ip = replacement['NetworkSettings']['Networks'][network_name]['IPAddress']
            result['restoredBusinessProbe'] = business(restored_id, new_ip)
            result['createComparison'] = comparison
            comparison = compare_restored(raw, archive_snapshot(replacement) if retain_archive else stable_snapshot(replacement))
            if archive_transport=='mtls-source':
                result['sourceObservationInvalidAfterOldStop'] = observer.recheck(observation) is False
                if result['sourceObservationInvalidAfterOldStop'] is not True:
                    raise ValueError('stopped-source-observation-must-expire')
        else:
            comparison = compare_restored(raw, restored_raw)
        result['comparison'] = comparison
        result['compositionDigest'] = candidate['compositionDigest']
        result['bodySha256'] = candidate['bodySha256']
        result['sentinelPreserved'] = sentinel.read_text() == project + '\n'
        result['baselineUnchanged'] = (_encode(stable_snapshot(json.loads(target.run('container', 'inspect', baseline_id))[0])) == _encode(raw)
            if not restore_running else result.get('baselineStableBeforeSwitch') is True)
        complete_restore_validation(result, restore_running=restore_running)
    except Exception as error:
        result['failureType'] = type(error).__name__; result['failurePhase'] = phase
        if type(error) is ValueError: result['failureReason'] = str(error)
        if result.get('archiveFaultInjected') is not None:
            try:
                observer.retention_commitment(observation)
                result['archiveObservationStillValidAfterFault'] = True
                if archive_fault.startswith('swapped-'):
                    value = recovery_store.get(archive_reference)
                    result['archiveStorageFaultVerified'] = value == b'{"kind":"other-fixture-archive"}' and archive_reference != result['archiveReference']
                    recovery.verify(result['archiveReference'], observer, observation)
                    result['archiveOriginalStillValidAfterSwap'] = True
                else:
                    try: recovery_store.get(archive_reference)
                    except ValueError: result['archiveStorageFaultVerified'] = True
                    else: result['archiveStorageFaultVerified'] = False
            except Exception:
                result['archiveFaultControlFailure'] = True
    finally:
        if not result['unknownWriteResult']:
            try:
                for receipt in reversed(known):
                    if receipt in running:
                        write(lambda receipt=receipt: target.stop(receipt))
                        stopped = json.loads(target.run('container', 'inspect', receipt))
                        if len(stopped) != 1 or stopped[0]['Id'] != receipt or stopped[0]['State']['Running'] is not False:
                            raise ValueError('restore-cleanup-stop-not-confirmed')
                        running.discard(receipt); result['cleanup'].append('stop-container')
                    write(lambda receipt=receipt: delete(target, receipt)); result['cleanup'].append('container')
                if volume_created: write(lambda: target.run('volume', 'rm', volume)); result['cleanup'].append('volume')
                if network: write(lambda: target.run('network', 'rm', network)); result['cleanup'].append('network')
                if loaded:
                    if registered_reference is None:
                        write(lambda: target.run('image','rm',image['Id']))
                    else:
                        write(lambda: target.run('image','rm',registered_reference))
                        remaining=set(target.run('images','-aq','--no-trunc').split())
                        if remaining-{image['Id']}:raise ValueError('unknown-image-during-cleanup')
                        if remaining:write(lambda: target.run('image','rm',image['Id']))
                    result['cleanup'].append('image')
                if bind.exists(): shutil.rmtree(bind)
                if (target.run('ps', '-aq').strip() or target.run('images', '-aq').strip()
                        or target.run('volume', 'ls', '-q').strip()
                        or sorted(target.run('network', 'ls', '-q', '--no-trunc').split()) != before_networks):
                    raise ValueError('restore-cleanup-inventory-drift')
                result['cleanupComplete'] = True
            except Exception as error:
                result['cleanupFailureType'] = type(error).__name__
        if gateway_close is not None:
            try: gateway_close(); result['sourceGatewayStopped'] = True
            except Exception as error: result['cleanupFailureType'] = type(error).__name__
        if recovery_store is not None:
            try: recovery_store.close()
            except OSError as error: result['cleanupFailureType'] = type(error).__name__
        result['success'] = restore_succeeded(result, restore_running=restore_running)
    return result
