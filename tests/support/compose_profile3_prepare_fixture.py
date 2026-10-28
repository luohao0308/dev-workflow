"""Preparation-only live private Engine fixture. Never opens a product writer.

The controller authenticates the callback's daemon boundary and source revision.
The returned session is PRIVATE; only ``public`` may be published. The caller
holds the daemon alive and calls cleanup, including on preparation failures.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import threading
import uuid

from deployment_compose_namespaced_runtime_probe import PrivateDaemon, transfer_image, ensure_capacity
from deployment_compose_namespaced_transition_probe import source_image, V2, delete
from deployment_compose_log_probe import IMAGE, ID
from deployment_compose_restore_host_config import _fixed_policy, OOM_ENABLED_POLICY
from deployment_compose_restore_body_host import RUNNING_METADATA_POLICY
from deployment_compose_private import commit, MOUNT
from deployment_compose_artifacts import ServiceArtifact, ComposeArtifacts
from deployment_compose_image_defaults import commit_image_config
from deployment_compose_network_declaration import commit_network_declaration
from deployment_compose_snapshot import prepare_snapshot, _encode
from deployment_compose_reader_host import ComposeReaderHostPolicy, create_gateway
from deployment_compose_reader import ComposeReadPolicy
from deployment_compose_observation_host import ComposeObservationHost
from deployment_compose_recovery_host import ComposeRecoveryHost
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_operations import BaselineContainer
from deployment_compose_prepare_v3_host import ComposePreparationHostV3
from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3
from deployment_contract_v2 import SourceIdentity, TargetIdentity
from deployment_compose_runtime_probe import wait_healthy
from compose_restore_probe import server_code

REPOSITORY = 'luohao0308/dev-workflow'
REPOSITORY_ID = 1327491026


def validate_controller(root, info, *, source_sha, host_id, expected_daemon_id, keys, policy_hash, expiry_seconds):
    """Reject invalid controller inputs before creating any local/Engine resource."""
    if (type(source_sha) is not str or not re.fullmatch('[0-9a-f]{40}', source_sha)
            or source_sha in ('0'*40, 'a'*40) or type(host_id) is not str or not host_id
            or type(expected_daemon_id) is not str or not expected_daemon_id
            or type(info) is not dict or info.get('ID') != expected_daemon_id
            or type(keys) is not dict or set(keys) != {'config','image','declaration','archive','target'}
            or any(type(k) is not bytes or not 32 <= len(k) <= 4096 for k in keys.values())
            or type(policy_hash) is not str or not re.fullmatch('[0-9a-f]{64}',policy_hash)
            or type(expiry_seconds) is not int or not 1 <= expiry_seconds <= 900):
        raise ValueError('profile3-controller-input-rejected')
    target = PrivateDaemon(root, info)
    if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o777 != 0o700:
        raise ValueError('profile3-unowned-root')
    return target


def fixture_command(project):
    # Same code in both images reports the actual Python runtime version.
    return server_code(project).replace('import errno,json\n', 'import errno,json,sys\n', 1).replace("'version': 'same-image'", "'version': sys.version")


def public_payload(prepared):
    return {'request':asdict(prepared['request']),'review':prepared['bundle'].public_review()}


class PreparationSession:
    def __init__(self, target, project):
        self.target, self.project = target, project
        self.created_ids, self.resources, self.listeners = [], [], []
        self.unknown_write_result = False
        self.store = None
        self.public = None

    def write(self, fn):
        if self.unknown_write_result:
            raise ValueError('profile3-write-blocked-after-unknown')
        self.unknown_write_result = True
        value = fn()
        self.unknown_write_result = False
        return value

    def cleanup(self):
        # Local read resources must close even when Engine writes are blocked.
        close_errors = []
        remaining = []
        for server, thread in self.listeners:
            try:
                try:
                    server.shutdown(); thread.join(timeout=5)
                finally:
                    server.server_close()
                if thread.is_alive(): raise ValueError('profile3-listener-not-stopped')
            except Exception as error:
                close_errors.append(error); remaining.append((server, thread))
        self.listeners = remaining
        if self.store is not None:
            try:
                self.store.close(); self.store = None
            except Exception as error:
                close_errors.append(error)
        # Never infer ownership from a name after an ambiguous write result.
        if self.unknown_write_result:
            raise ValueError('profile3-cleanup-blocked-after-unknown') from (close_errors[0] if close_errors else None)
        if close_errors:
            raise ValueError('profile3-local-cleanup-failed') from close_errors[0]
        for cid in reversed(self.created_ids):
            self.write(lambda cid=cid: self.target.stop(cid))
            self.write(lambda cid=cid: delete(self.target, cid))
        self.created_ids.clear()
        for kind, receipt in reversed(self.resources):
            self.write(lambda kind=kind, receipt=receipt: self.target.run(kind, 'rm', receipt))
        self.resources.clear()


def _observers(root, session, scope, artifacts, key):
    directory = root/'profile3-tls'; directory.mkdir(mode=0o700)
    def openssl(*args):
        subprocess.run(['openssl', *args], cwd=directory, capture_output=True, check=True, timeout=20)
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1',
            '-subj','/CN=Private preparation CA','-addext','basicConstraints=critical,CA:TRUE')
    for name in ('server','reader'):
        openssl('req','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name)
        (directory/(name+'.ext')).write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage='+('serverAuth' if name=='server' else 'clientAuth')+'\n')
        openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','1','-extfile',name+'.ext')
    for path in directory.iterdir(): path.chmod(0o600)
    def fingerprint(name):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory/(name+'.pem')).read_text())).hexdigest()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(directory/'server.pem'), str(directory/'server.key'))
    context.load_verify_locations(str(directory/'ca.pem')); context.verify_mode=ssl.CERT_REQUIRED
    ids=tuple(sorted(list(scope['selectedContainerIds'].values())+list(scope['protectedContainerIds'].values())))
    observers=[]
    for source_view in (False, True):
        policy=ComposeReaderHostPolicy(scope['project'], scope['daemonId'], fingerprint('reader'),
            ('backend','peer'), ids, tuple(sorted(set(scope['imageIds'].values()))),
            tuple(sorted(scope['networks'].values())), tuple(sorted(scope['volumes'])),
            private_key_id='profile3-config', source_view=source_view)
        server=create_gateway(policy,tls_context=context,docker_socket=Path(session.target.socket),private_hmac_key=key)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start(); session.listeners.append((server,thread))
        reader=ComposeReadPolicy('https://localhost:'+str(server.server_port), fingerprint('server'),scope['daemonId'],
            scope['project'],tuple(sorted(scope['volumes'])),gateway_policy_hash=policy.digest(),
            private_key_id='profile3-config',source_container_ids=ids if source_view else ())
        observer=ComposeObservationHost(reader_policy=reader,scope_policy=scope,baseline_artifacts=artifacts,
            ca_file=directory/'ca.pem',cert_file=directory/'reader.pem',key_file=directory/'reader.key',max_age_seconds=300)
        observers.append(observer)
    return tuple(observers)


def prepare_profile3(root, info, *, source_sha, host_id, expected_daemon_id, keys, policy_hash,
                     environment='test', expiry_seconds=600, registry='ecr-public'):
    target=validate_controller(root,info,source_sha=source_sha,host_id=host_id,expected_daemon_id=expected_daemon_id,
        keys=keys,policy_hash=policy_hash,expiry_seconds=expiry_seconds)
    fresh=json.loads(target.run('info','--format','{{json .}}'))
    if (fresh.get('ID') != expected_daemon_id or fresh.get('DockerRootDir') != str(root/'data')
            or fresh.get('SwapLimit') is not True or target.run('ps','-aq').strip()
            or target.run('images','-aq').strip() or target.run('volume','ls','-q').strip()):
        raise ValueError('profile3-daemon-not-private-and-empty')
    from deployment_compose_registry_enrollment_probe import enroll_image, registry_settings
    references=[registry_settings(registry,image_reference=ref)[0] for ref in (IMAGE,V2)]
    project='dw-restore-'+uuid.uuid4().hex[:24]
    session=PreparationSession(target,project)
    try:
        images=[]
        for ref, enrolled_ref in zip((IMAGE,V2), references):
            image=source_image(ref); ensure_capacity(root,image)
            session.write(lambda image=image: transfer_image(image['Id'],target))
            image, receipt=session.write(lambda image=image,ref=ref: enroll_image(root,target,image,registry=registry,image_reference=ref))
            if enrolled_ref not in image['RepoDigests']: raise ValueError('profile3-real-registry-digest-required')
            images.append(image)
            session.resources.append(('image', enrolled_ref))
        network_name=project+'-net'; volume=project+'-data'
        def make_network():
            connection=target.connection()
            try:
                connection.request('POST','/v1.45/networks/create',_encode(dict(Name=network_name,Driver='bridge',Internal=True,Labels={'com.docker.compose.project':project})),{'Content-Type':'application/json'})
                response=connection.getresponse(); raw=response.read(65537)
                if response.status != 201 or len(raw)>65536: raise ValueError('profile3-network-receipt-rejected')
                receipt=json.loads(raw).get('Id')
                if type(receipt) is not str or not ID.fullmatch(receipt): raise ValueError('profile3-network-receipt-rejected')
                session.resources.append(('network',receipt))
                return receipt
            finally: connection.close()
        network=session.write(make_network)
        def create(path, body, expected=None):
            connection=target.connection()
            try:
                connection.request('POST',path,_encode(body),{'Content-Type':'application/json'})
                response=connection.getresponse(); raw=response.read(1048577)
                if response.status != 201 or len(raw)>1048576: raise ValueError('profile3-create-receipt-rejected')
                value=json.loads(raw)
                if expected is not None:
                    if value.get('Name') != expected or value.get('Labels',{}).get('com.docker.compose.project') != project:
                        raise ValueError('profile3-volume-receipt-rejected')
                    session.resources.append(('volume',expected)); return value
                cid=value.get('Id')
                if type(cid) is not str or not ID.fullmatch(cid) or cid in session.created_ids: raise ValueError('profile3-container-receipt-rejected')
                session.created_ids.append(cid); return cid
            finally: connection.close()
        session.write(lambda: create('/v1.45/volumes/create',dict(Name=volume,Driver='local',DriverOpts={},Labels={'com.docker.compose.project':project}),volume))
        volume_info=json.loads(target.run('volume','inspect',volume))[0]
        mountpoint=Path(volume_info['Mountpoint'])
        if mountpoint != root/'data/volumes'/volume/'_data' or any(mountpoint.iterdir()): raise ValueError('profile3-volume-ownership-drift')
        (mountpoint/'sentinel.txt').write_text(project+'\n')
        bind=root/'profile3-config'; bind.mkdir(mode=0o700); (bind/'config.txt').write_text(project+'\n')
        host=_fixed_policy(policy=OOM_ENABLED_POLICY)
        host.update(NetworkMode=network_name,Mounts=[dict(Type='volume',Source=volume,Target='/sample-data',ReadOnly=False,VolumeOptions={'NoCopy':True}),dict(Type='bind',Source=str(bind),Target='/sample-config',ReadOnly=True)])
        body=dict(Image=images[0]['Id'],Hostname='profile3',WorkingDir='/tmp',Cmd=['/usr/local/bin/python3','-c',fixture_command(project)],Entrypoint=None,
            Env=deepcopy(images[0]['Config']['Env']),Labels={},Healthcheck=dict(Test=['CMD','/usr/local/bin/python3','-c',"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=5).read()"],Interval=1000000000,Timeout=20000000000,StartPeriod=1000000000,Retries=3),
            HostConfig=host,NetworkingConfig={'EndpointsConfig':{network_name:dict(NetworkID=network,Aliases=['backend'])}})
        rows={}
        bodies={}
        for service in ('backend','peer'):
            own=deepcopy(body); own['Labels']={'com.docker.compose.project':project,'com.docker.compose.service':service}
            own['NetworkingConfig']['EndpointsConfig'][network_name]['Aliases']=[service]
            bodies[service]=deepcopy(own)
            cid=session.write(lambda service=service,own=own: create('/v1.45/containers/create?name='+project+'-'+service,own))
            if session.write(lambda cid=cid: target.run('container','start',cid).strip()) != cid:
                session.unknown_write_result=True; raise ValueError('profile3-start-receipt-rejected')
            wait_healthy(target.run,cid)
            connection=target.connection()
            try:
                connection.request('GET','/v1.45/containers/'+cid+'/json')
                response=connection.getresponse(); raw=response.read(8388609)
                if response.status!=200 or len(raw)>8388608: raise ValueError('profile3-raw-get-rejected')
                rows[service]=json.loads(raw)
            finally: connection.close()
        # Baseline fixture creation ends here. All subsequent Engine operations are GETs.
        raw={k:deepcopy(rows['backend'][k]) for k in ('Id','Name','Image','Config','HostConfig','NetworkSettings','Mounts')}
        raw['Mounts']=[{**dict.fromkeys(MOUNT),**m} for m in raw['Mounts']]
        projection={k:raw[k] for k in ('Config','HostConfig','NetworkSettings','Mounts')}
        networks={network_name:network}
        mounts={'/sample-data':dict(type='volume',source=volume,readOnly=False),'/sample-config':dict(type='bind',source=str(bind),readOnly=True)}
        identity=dict(project=project,service='backend',containerId=raw['Id'],containerName=project+'-backend',imageId=images[0]['Id'],hostId=host_id,daemonId=expected_daemon_id,requestedApiVersion='1.45',engineVersion=fresh['ServerVersion'])
        artifact=ServiceArtifact('backend',source_sha,references[0],images[0]['Id'],'linux',images[0]['Architecture'],'profile3-config',commit(project,'backend',projection,'profile3-config',keys['config'])['configHmac'],hashlib.sha256(b'').hexdigest(),'none')
        peer_projection={k:deepcopy(rows['peer'][k]) for k in ('Config','HostConfig','NetworkSettings','Mounts')}
        peer_projection['Mounts']=[{**dict.fromkeys(MOUNT),**m} for m in peer_projection['Mounts']]
        peer_hash=commit(project,'peer',peer_projection,'profile3-config',keys['config'])['configHmac']
        scope=dict(project=project,daemonId=expected_daemon_id,selectedServices=['backend'],protectedServices=['peer'],protectedContainerIds={'peer':rows['peer']['Id']},protectedConfigHmacs={'peer':peer_hash},selectedContainerIds={'backend':raw['Id']},containerNames={s:project+'-'+s for s in rows},imageIds={s:images[0]['Id'] for s in rows},baselineSourceShas={'backend':source_sha},networks=networks,volumes={volume:dict(driver='local',options={})},mounts={s:[dict(type=m['type'],source=m['source'],target=p,readOnly=m['readOnly']) for p,m in mounts.items()] for s in rows},networkAttachments={s:{network_name:rows[s]['NetworkSettings']['Networks'][network_name]['Aliases']} for s in rows})
        session.whole_observer,session.retention_observer=_observers(root,session,scope,ComposeArtifacts(1,(artifact,)),keys['config'])
        session.whole_observation=session.whole_observer.issue(); session.retention_observation=session.retention_observer.issue()
        if session.whole_observation is None or session.retention_observation is None: raise ValueError('profile3-live-observation-not-issued')
        archive=root/'profile3-archive'; archive.mkdir(mode=0o700)
        session.store=ComposeRecoveryStore(archive,key=keys['archive'])
        baseline=(BaselineContainer('backend',raw['Id'],identity['containerName'],images[0]['Id']),)
        session.recovery=ComposeRecoveryHost(store=session.store,observer=session.retention_observer,baseline=baseline,projections={'backend':projection},private_keys={'profile3-config':keys['config']})
        reference=session.recovery.retain(session.retention_observation)
        snapshot=prepare_snapshot(raw,identity,artifact,keys['config'],networks,mounts)
        model=dict(sourceSha=source_sha,command=fixture_command(project),createBodies=bodies)
        model_digest=hashlib.sha256(_encode(model)).hexdigest()
        declaration=dict(schemaVersion=1,identity=identity,sourceSha=source_sha,sourceModelDigest=model_digest,sourceSnapshotDigest=hashlib.sha256(_encode(snapshot)).hexdigest(),networks={network_name:dict(id=network,aliases=raw['NetworkSettings']['Networks'][network_name]['Aliases'],addressPolicy='dynamic-no-requested-addresses',requestedMac=None,ipamConfig=None,links=None,driverOpts=None)})
        proof=commit_network_declaration(declaration,'profile3-declaration',keys['declaration'])
        inputs=dict(identity=identity,private_key=keys['config'],network_ids=networks,expected_mounts=mounts,image=images[0],image_commitment=commit_image_config(images[0],'profile3-image',keys['image']),image_key=keys['image'],declaration=declaration,declaration_proof=proof,declaration_key=keys['declaration'],expected_image_key_id='profile3-image',expected_declaration_key_id='profile3-declaration',expected_declaration_hmac=proof['declarationHmac'],expected_source_model_digest=model_digest,host_config_policy=OOM_ENABLED_POLICY,metadata_policy=RUNNING_METADATA_POLICY)
        targets=dict(image=images[1],commitment=commit_image_config(images[1],'profile3-target',keys['target']),key=keys['target'],expected_key_id='profile3-target',expected_image_id=images[1]['Id'],expected_registry_digest=references[1],expected_architecture=images[1]['Architecture'])
        session.producer=TrustedPhaseStateProducerV3(socket_path=target.socket,project=project,daemon_id=expected_daemon_id,container_ids=tuple(sorted(r['Id'] for r in rows.values())))
        session.preparer=ComposePreparationHostV3(whole_observer=session.whole_observer,retention_observer=session.retention_observer,recovery=session.recovery,baseline=baseline,source_inputs={'backend':inputs},target_inputs={'backend':targets},source=SourceIdentity('github.com','https://github.com/'+REPOSITORY+'.git',REPOSITORY_ID,REPOSITORY,source_sha),target=TargetIdentity('compose',project,environment),host_id=host_id,daemon_id=expected_daemon_id,environment=environment,policy_hash=policy_hash,dependencies={'backend':()},protected_names={'peer':project+'-peer'},protected_ids={'peer':rows['peer']['Id']},protected_hashes={'peer':peer_hash},archive_reference=reference,phase_state_producer=session.producer,protected_private_keys={'peer':('profile3-config',keys['config'])})
        expires=(datetime.now(timezone.utc)+timedelta(seconds=expiry_seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')
        session.prepared=session.preparer.prepare_intent(session.whole_observation,session.retention_observation,operation_nonce=uuid.uuid4().hex+uuid.uuid4().hex,expires_at=expires)
        version=json.loads(target.run('version','--format','{{json .Server}}'))
        version={k:version[k] for k in ('Version','GitCommit')}
        pinned_rows=TrustedPhaseStateProducerV3.reload(session.store,session.prepared['bundle'],read_json=session.producer._get,daemon_version=version,expected_docker_root=str(root/'data'))
        session.guard=PhaseGuardV3(session.prepared['bundle'],pinned_rows,read_json=session.producer._get,daemon_version=version,expected_docker_root=str(root/'data'))
        session.raw_source,session.raw_rows,session.source_inputs,session.source_model=raw,rows,inputs,model
        session.public=public_payload(session.prepared)
        return session
    except Exception as error:
        # Caller retains ownership and may clean up only confirmed receipts.
        error.preparation_session=session
        raise
