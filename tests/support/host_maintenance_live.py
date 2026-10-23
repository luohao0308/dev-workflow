#!/usr/bin/env python3
"""Linux Actions-only real Docker/mTLS maintenance proof on two synthetic repos."""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import threading
import traceback
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import p15_recovery_live as live
import deployment_host_config as configuration
import deployment_host_doctor as doctor
import deployment_host_maintenance as maintenance
import deployment_host_rotation as rotation


def private(path, raw):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def denied(action):
    try:
        action()
    except Exception:
        return True
    raise AssertionError('Retired authority remained usable')


def bundle(config, state, coordinator, executor):
    directory = state['directory'].resolve()
    metadata = state['metadata']
    head = subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,check=True,capture_output=True,text=True).stdout.strip()
    paths = dict(candidate_root=str(state['candidate'].resolve()),store_root=str(directory/'store'),gate_root=str(directory/'gate'))
    for name, filename in dict(store_key_file='maintenance-store.key',gate_key_file='maintenance-gate.key',ca_file='ca.pem',reader_cert_file='reader.pem',reader_key_file='reader.key',writer_cert_file='writer.pem',writer_key_file='writer.key').items():
        paths[name] = str(directory/filename)
    private(Path(paths['store_key_file']), bytes.fromhex(config['storeKey']))
    private(Path(paths['gate_key_file']), bytes.fromhex(config['gateKey']))
    token = directory/'doctor-token'
    private(token, os.environ.get('HOST_DOCTOR_TOKEN','').encode())
    for name in ('ca_file','reader_cert_file','reader_key_file','writer_cert_file','writer_key_file'):
        Path(paths[name]).chmod(0o600)
    github = dict(host_repository=metadata['hostRepository'],host_repository_id=metadata['hostRepositoryId'],
        workflow_ref=os.environ['GITHUB_WORKFLOW_REF'],workflow_sha=os.environ['GITHUB_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
        environment='p15-observer',reviewer_ids=[84822776],ledger_repository=metadata['hostRepository'],
        ledger_repository_id=metadata['hostRepositoryId'],ledger_sha=os.environ['GITHUB_SHA'],
        expires_at=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),prevent_self_review=False,
        credential_file=str(token),deploy_approval_environment='p1-deploy-approval',
        rollback_approval_environment='p1-rollback-approval',recovery_approval_environment='p15-recovery-approval')
    document=dict(schemaVersion=1,**paths,distribution_commit=head,github=github,runtime=asdict(coordinator.collector.policy),
        execution={k:v for k,v in asdict(executor.policy).items() if k!='runtime_policy'},
        probe=asdict(executor.verifier.policy),gate=asdict(coordinator.gate.policy),
        store={k:v for k,v in asdict(coordinator.store.policy).items() if k!='runtime_policy'})
    path=directory/'maintenance-config.json'
    private(path,json.dumps(document).encode())
    return configuration.load_host_config(path)


def destination(source, label):
    cfg=source.config
    root=cfg.store_root.parent
    store=replace(cfg.store_policy,store_id=label,key_id=label+'-key')
    gate=replace(cfg.gate_policy,store_id=label,key_id=label+'-key',scope_hash=live.runtime.digest(store._scope()))
    execution=replace(cfg.execution_policy,history_policy_hash=store.identity_hash(),gateway_policy_hash=gate.identity_hash())
    store_key,gate_key=secrets.token_bytes(32),secrets.token_bytes(32)
    store_path,gate_path=root/(label+'.store-key'),root/(label+'.gate-key')
    private(store_path,store_key); private(gate_path,gate_key)
    return maintenance.MaintenanceHost(replace(cfg,store_policy=store,gate_policy=gate,execution_policy=execution,
        store_root=root/(label+'-store'),gate_root=root/(label+'-gate'),store_key_file=store_path,gate_key_file=gate_path),store_key,gate_key)


def after_recovery(coordinator, collector, executor, config, state):
    cfg=bundle(config,state,coordinator,executor)
    source=maintenance.MaintenanceHost(cfg,bytes.fromhex(config['storeKey']),bytes.fromhex(config['gateKey']))
    report=doctor.diagnose(cfg,online=True)
    output=ROOT/'host-maintenance-results'; output.mkdir()
    live.provision.save(output/'doctor.json',report)
    runtime_check=next(item for item in report['checks'] if item['id']=='runtime')
    assert runtime_check['status']=='pass', 'Real runtime doctor did not verify'
    captured=collector.collect()
    reference=coordinator.store.capture_history(collector,captured)
    before=collector.collect()
    old_history=coordinator.store.load_history(reference,collector=collector,before=before)
    old_history.snapshot()
    raw=maintenance.backup(source)
    maintenance.verify(source,raw)
    successor=destination(source,'maintenance-next')
    result=rotation.rotate(source,successor)
    assert result['status']=='complete'
    denied(old_history.snapshot)
    denied(coordinator.gate.info)
    denied(lambda:coordinator.store.capture_history(collector,before))
    after=collector.collect()
    assert {k:v for k,v in before.snapshot().items() if k!='capturedAt'}=={k:v for k,v in after.snapshot().items() if k!='capturedAt'}
    assert before.to_dict()['instances']==after.to_dict()['instances']
    new_store=live.history.HostStore(successor.config.store_policy,successor.config.store_root,key=successor.store_key)
    cfg.store_key_file.unlink()
    imported=new_store.load_history(reference,collector=collector,before=after)
    assert imported.snapshot()==captured.snapshot()
    unavailable=maintenance.MaintenanceHost(replace(cfg,store_root=cfg.store_root.with_name('absent-source-store')),source.store_key,source.gate_key)
    restored=destination(source,'maintenance-restored')
    maintenance.verify(unavailable,raw)
    maintenance.restore(unavailable,restored,raw)
    assert not restored.config.gate_root.exists()
    restored_store=live.history.HostStore(restored.config.store_policy,restored.config.store_root,key=restored.store_key)
    assert restored_store.load_history(reference,collector=collector,before=after).snapshot()==captured.snapshot()
    new_gate=live.gateway.FileWriterGate(successor.config.gate_policy,successor.config.gate_root,key=successor.gate_key)
    directory=state['directory']
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(directory/'server.pem'),str(directory/'server.key'))
    context.load_verify_locations(str(directory/'ca.pem')); context.verify_mode=ssl.CERT_REQUIRED
    server=live.gateway_host.create_gateway(successor.config.runtime_policy,new_gate,tls_context=context,
        reader_certificate_sha256=state['certificate_hash']('reader'),docker_socket=Path('/var/run/docker.sock'))
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        policy=replace(successor.config.runtime_policy,endpoint='https://localhost:'+str(server.server_port))
        client=live.runtime.DockerTLSClient(policy,ca_file=directory/'ca.pem',cert_file=directory/'reader.pem',key_file=directory/'reader.key')
        fresh=live.runtime.TrustedDockerCollector(policy,client)
        observed=fresh.collect()
        assert new_gate.verify_info(client.get('/v1.45/workflow/gate-info'))
        assert {k:v for k,v in observed.snapshot().items() if k not in ('capturedAt','provenance')}=={k:v for k,v in before.snapshot().items() if k not in ('capturedAt','provenance')}
        assert new_store.load_history(reference,collector=fresh,before=observed).snapshot()==captured.snapshot()
    finally:
        server.shutdown(); server.server_close(); thread.join(3)
    live.provision.save(output/'summary.json',dict(result='passed',realDocker=True,realMTLS=True,
        archiveHash=hashlib.sha256(raw).hexdigest(),rotated=True,retiredObjectsDenied=True,
        importedWithoutOldKeyFile=True,sourceAbsentRestore=True,restoreGateAbsent=True,
        dockerInstancesUnchanged=True,newGatewayVerified=True,productionReady=False,
        githubDoctorStatus=next(c['status'] for c in report['checks'] if c['id']=='github')))


def exercise(state):
    metadata=state['metadata']
    if (metadata['targetRepository']!='luohao0308/dev-workflow-p0-target-20261022'
        or metadata['targetRepositoryId']!=1428943581
        or metadata['hostRepository']!='luohao0308/dev-workflow-p0-host-public-20261022'
        or metadata['hostRepositoryId']!=1428943173
        or metadata['hostRepositoryId']!=int(os.environ['GITHUB_REPOSITORY_ID'])
        or os.environ['GITHUB_REPOSITORY']!=metadata['hostRepository']):
        raise ValueError('Synthetic repository identity required')
    live.exercise(state,after_recovery=after_recovery)


def main():
    if sys.platform!='linux' or os.environ.get('GITHUB_ACTIONS')!='true':
        raise SystemExit('Disposable Linux Actions fixture only')
    os.environ['P14_MODE']='smoke'
    os.environ['P15_REAL_AUTHORITY']='false'
    os.environ['P15_CRASH_AFTER']='3'
    os.environ['P15_RECOVERY_CRASH_AFTER']='0'
    live.provision.main(exercise=exercise)

if __name__=='__main__':
    try:
        main()
    except Exception as error:
        output=ROOT/'host-maintenance-results'; output.mkdir(exist_ok=True)
        live.provision.save(output/'failure.json', dict(result='failed', errorType=type(error).__name__, locations=[Path(item.filename).name+':'+str(item.lineno) for item in traceback.extract_tb(error.__traceback__)]))
        raise SystemExit('Host maintenance fixture failed: '+type(error).__name__)
