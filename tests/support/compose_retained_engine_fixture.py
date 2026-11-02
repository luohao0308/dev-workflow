"""Opt-in real isolated Engine diagnostic; history/admission are synthetic.

A bounded parent owns the daemon, fixture writes, witness keys and final cleanup.
No product writer, GitHub approval, admission or recovery execution is opened.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import traceback

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts','tests/support')]
from compose_live_phase_fixture import load, produce, record, start_witness_server
from deployment_compose_witness_store import canonical
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_live_phase_v3_host import LiveRecoveryPhaseCaptureV3
from deployment_compose_checkpoint_prepare_v3_host import CheckpointRecoveryPreparationHostV3
from deployment_compose_recovery_store import ComposeRecoveryStore

ENTRYPOINT='compose_retained_engine_fixture.remote_main'


def digest(raw):return hashlib.sha256(raw).hexdigest()


def consume(directory,*,cleaned=False):
    config,pins,raw,context,calls=load(directory,material_path=directory/'validated-material.private.json')
    if canonical(pins)!=(directory/'validated-pins.private.json').read_bytes():raise ValueError('fixture-pins-changed')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    observer=ObservedRecoveryDaemonV3(config['daemonRoot'],context.history._request.daemon_id,kernel_boot=boot)
    store=None
    try:
        if cleaned:
            try:
                LiveRecoveryPhaseCaptureV3(original_history=context.history,baseline_bytes=context.baseline_bytes,
                    daemon=observer,expected_version=config['expectedVersion']).capture()
            except ValueError:
                return dict(blockedAfterCleanup=True,consumerPid=os.getpid(),readonlyRPC=sorted(set(calls)))
            raise AssertionError('cleaned candidate unexpectedly accepted')
        cas=directory/'native-draft-cas';cas.mkdir(mode=0o700)
        store=ComposeRecoveryStore(cas.resolve(strict=True),key=secrets.token_bytes(32))
        host=CheckpointRecoveryPreparationHostV3(restart_material=raw,
            expected_material_digest=pins['expectedDigest'],expected_context=pins['expectedContext'],
            gate_key=bytes.fromhex(config['gateKeyHex']),witness_public_key=context.history._client._public,
            witness_transport=context.history._client._transport,daemon=observer,
            expected_version=config['expectedVersion'],store=store)
        expires=(datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        prepared=host.prepare_intent(expires_at=expires)
        verified=host.verify_context(prepared['recovery_context_reference'],prepared['request'],prepared['reviewed_history'])
        record(directory/'draft-context.private.json',canonical(verified))
        return dict(consumerPid=os.getpid(),requestDigest=prepared['request'].digest(),
            requestProfileId=prepared['request'].profile_id,historyDigest=verified['historyDigest'],
            baselineDigest=verified['baselineStateDigest'],contextDigest=prepared['request'].observation_hash,
            daemonBindingDigest=digest(canonical(verified['liveEndpointBinding']['daemonBinding'])),
            draftVerified=True,approvalReady=False,runtimePermit=False,recoveryAuthorized=False,
            daemonContinuityVerified=False,productionReady=False,readonlyRPC=sorted(set(calls)),
            realEngine=True,nativeEndpointIdentity=True,syntheticAdmissionHistory=True)
    finally:
        if store is not None:store.close()
        observer.close()


def _child(mode,directory):
    completed=subprocess.run([sys.executable,str(Path(__file__).resolve()),mode,str(directory)],
        capture_output=True,timeout=90,check=False)
    record(directory/(mode+'-stdout.private.json'),completed.stdout)
    record(directory/(mode+'-stderr.private.txt'),completed.stderr)
    if completed.returncode or completed.stderr:raise ValueError('retained-fixture-child-rejected:'+mode)
    value=json.loads(completed.stdout)
    if type(value) is not dict:raise ValueError('retained-fixture-child-result')
    return value


def _binding(root,daemon_id):
    observer=ObservedRecoveryDaemonV3(str(root),daemon_id,
        kernel_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    try:return observer.binding()
    finally:observer.close()


def _defaults(session):
    from deployment_compose_image_defaults import derive_defaults,ZERO_DEFAULTS
    result={}
    for service,inputs in session.preparer._target_inputs.items():
        if inputs['commitment']['keyId']!=inputs['expected_key_id']:raise ValueError('fixture-default-key-mismatch')
        derived=derive_defaults(inputs['image'],inputs['commitment'],inputs['key'],
            **{key:inputs[key] for key in ('expected_image_id','expected_registry_digest','expected_architecture')})
        result[service]={key:deepcopy(derived[key]) for key in ZERO_DEFAULTS}
    return result


def workload(root,info,config):
    from compose_profile3_prepare_fixture import prepare_profile3
    from compose_retained_history_fixture import SyntheticClosedCreateHistory
    from deployment_compose_restart_material_v3_host import capture_material
    session=witness=observer=None;server=thread=None;primary=None
    owner=root/'retained-owner';owner.mkdir(mode=0o700)
    directory=root/'retained-handoff';directory.mkdir(mode=0o700)
    result=None
    try:
        witness=SyntheticClosedCreateHistory(owner)
        observer=ObservedRecoveryDaemonV3(str(root),info['ID'],
            kernel_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        observer.begin_resource_observation()
        keys={key:secrets.token_bytes(32) for key in ('config','image','declaration','archive','target')}
        session=prepare_profile3(root,info,source_sha=config['sourceSha'],host_id=config['hostId'],
            expected_daemon_id=info['ID'],keys=keys,policy_hash=witness.policy.identity_hash())
        bundle=session.prepared['bundle'];request=session.prepared['request']
        baseline=session.store.get(bundle.to_dict()['baselineStateReference'])
        op=bundle.creation_operations()[0]
        # This POST is fixture provisioning, never a product writer dispatch.
        cid=session.write(lambda:session.create(op['path'],op['body']))
        history=witness.close_create(bundle,request,cid)
        raw=capture_material(history,baseline_bytes=baseline,authenticated_image_defaults=_defaults(session),
            archive_digest=config['archiveDigest'])
        snapshot=history.capture()
        pins=dict(expectedDigest=digest(raw),expectedContext=dict(sourceSha=config['sourceSha'],hostId=config['hostId'],
            daemonId=info['ID'],archiveDigest=config['archiveDigest'],historyDigest=snapshot.digest,
            baselineStateDigest=bundle.to_dict()['baselineStateDigest']))
        for name,data in (('material.private.json',raw),('pins.private.json',canonical(pins)),('witness.pub',witness.public)):
            record(directory/name,data)
        socket=root/'retained-witness.sock'
        server,thread,rpc=start_witness_server(witness,socket)
        child_config=dict(daemonRoot=str(root),witnessSocket=str(socket),gateKeyHex=witness.gate_key.hex(),
            expectedVersion=session.guard._version)
        record(directory/'config.private.json',canonical(child_config))
        before=(witness.store.root/'state.json').read_bytes()
        binding=_binding(root,info['ID'])
        producer=_child('produce',directory)  # run() has waited/reaped before return.
        if _binding(root,info['ID'])!=binding:raise ValueError('daemon-changed-after-producer')
        session.store.close();session.store=None
        consumer=_child('consume',directory)
        if (consumer['consumerPid']==producer['producerPid'] or not consumer['draftVerified']
                or consumer['daemonBindingDigest']!=digest(canonical(binding))
                or _binding(root,info['ID'])!=binding):raise ValueError('retained-process-seam-rejected')
        known_images=sorted({image['Id'] for image in session.enrolled_images})
        session.cleanup()
        rejected=_child('reject-cleaned',directory)
        if not rejected['blockedAfterCleanup']:raise ValueError('cleaned-scene-not-rejected')
        # These IDs are confirmed private fixture transfers/enrollments only.
        for image_id in known_images:session.target.run('image','rm','--force',image_id)
        inventory_digest=observer.verify_resources_restored()
        if (before!=(witness.store.root/'state.json').read_bytes()
                or not rpc or not set(rpc)<={'read','check','events_after','chain_status'}):
            raise ValueError('fixture-witness-mutated')
        result=dict(success=True,realEngine=True,nativeEndpointIdentity=True,syntheticAdmissionHistory=True,
            realApprovalConsumptions=0,productWriterDispatches=0,fixtureEngineWritesPerformed=True,
            producerPid=producer['producerPid'],consumerPid=consumer['consumerPid'],producerExitedBeforeConsumer=True,
            ownerPid=os.getpid(),daemonAliveAfterProducerExit=True,cleanedSceneRejected=True,
            sessionCleaned=True,apiInventoryRestored=True,inventoryDigest=inventory_digest,
            requestDigest=consumer['requestDigest'],historyDigest=consumer['historyDigest'],
            contextDigest=consumer['contextDigest'],daemonBindingDigest=consumer['daemonBindingDigest'],
            approvalReady=False,runtimePermit=False,recoveryAuthorized=False,daemonContinuityVerified=False,productionReady=False)
    except BaseException as error:
        primary=error
        if session is None:session=getattr(error,'preparation_session',None)
        record(root/'retained-failure.private.json',canonical(dict(type=type(error).__name__,message=str(error),
            trace=traceback.format_exception(type(error),error,error.__traceback__))))
        raise
    finally:
        failures=[]
        actions=[]
        if session is not None:actions.append(session.cleanup)
        if server is not None:actions.extend([server.shutdown,server.server_close,lambda:thread.join(timeout=5)])
        if observer is not None:actions.append(observer.close)
        if witness is not None:actions.append(witness.close)
        for action in actions:
            try:action()
            except BaseException as error:failures.append(type(error).__name__)
        if thread is not None and thread.is_alive():failures.append('witness-thread-not-stopped')
        if failures:
            record(root/'retained-cleanup-failure.private.json',canonical(dict(failures=failures)))
            if primary is None:raise ValueError('retained-fixture-cleanup-failed')
    return result


def remote_main(config):
    import re
    from deployment_compose_isolated_daemon_probe import probe
    fields={'entrypoint','sourceSha','archiveDigest','hostId','channelNonce'}
    if (type(config) is not dict or set(config)!=fields or any(type(config[key]) is not str for key in fields) or config['entrypoint']!=ENTRYPOINT
            or re.fullmatch('[0-9a-f]{40}',config['sourceSha']) is None
            or any(re.fullmatch('[0-9a-f]{64}',config[key]) is None for key in ('archiveDigest','channelNonce'))
            or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',config['hostId']) is None):
        raise ValueError('retained-fixture-config-rejected')
    result=probe(lambda root,info:workload(root,info,config),storage_driver='overlayfs',
        workload_lifetime_seconds=3600,bind_to_owned_writer=False)
    summary=dict(success=result['completed'],remoteRoot=result['root'],sourceSha=config['sourceSha'],
        archiveDigest=config['archiveDigest'],daemonStopped=result['stopped'],
        productionSnapshotUnchanged=result['productionSnapshotUnchanged'],
        workload=result.get('workload'),failureReason=result.get('failureReason'),productionReady=False)
    record(Path(result['root'])/'retained-summary.private.json',canonical(summary))
    return summary


if __name__=='__main__':
    mode,destination=sys.argv[1:]
    directory=Path(destination).resolve(strict=True)
    if mode=='produce':value=produce(directory)
    elif mode in ('consume','reject-cleaned'):value=consume(directory,cleaned=mode=='reject-cleaned')
    else:raise ValueError('retained-fixture-mode-rejected')
    print(json.dumps(value),flush=True)
