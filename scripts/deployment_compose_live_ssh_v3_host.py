"""Mac private LIVE controller primitives.

Only owned SSH supplies capsules. Validation binds their contents; it does not
turn serialized observations into fresh opaque host observations. No networking
or workflow dispatch occurs at import time.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import threading
import time
from dataclasses import asdict
from types import SimpleNamespace

from deployment_compose_profile3_prepare_ssh_probe import _BOOTSTRAP, _published_archive
from deployment_compose_operation_witness_client_v3 import encode
from deployment_compose_bundle_v3 import ExecutionBundleV3, FIELDS
from deployment_contract_v2 import RequestV2
from deployment_compose_image_defaults import derive_defaults, ZERO_DEFAULTS
from deployment_compose_artifacts import ComposeArtifacts
from deployment_compose_private import commit, MOUNT
from deployment_compose_phase_guard_v3_host import baseline_state_digest, protected_state_digest
from deployment_compose_collect import _snapshot, image_catalog_digest
from deployment_compose_v3_channel_worker import read_frame, write_frame

ENTRYPOINT = 'deployment_compose_live_worker_v3_host.run'
REPOSITORY = 'luohao0308/dev-workflow'
REPOSITORY_ID = 1327491026


def reject():
    raise ValueError('compose-live-ssh-v3-rejected') from None


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def live_bootstrap(archive_digest, source_sha):
    """Fixed audited loader, with no caller-selectable Python entry point."""
    if (not re.fullmatch('[0-9a-f]{64}', archive_digest)
            or not re.fullmatch('[0-9a-f]{40}', source_sha)):
        reject()
    code = _BOOTSTRAP.replace('deployment_compose_profile3_prepare_ssh_probe._remote_main', ENTRYPOINT)
    code = code.replace(' from deployment_compose_profile3_prepare_ssh_probe import _remote_main',
                        ' from deployment_compose_live_worker_v3_host import run')
    code = code.replace(' result=_remote_main(config)',
                        ' run(config,sys.stdin.buffer,sys.stdout.buffer)')
    code = code.replace("write_frame(sys.stdout.buffer,dict(channelNonce=config['channelNonce'],result=result),timeout=30)", '')
    return code.replace('ARCHIVE_DIGEST', repr(archive_digest)).replace('SOURCE_SHA', repr(source_sha))


def ssh_argv(alias, archive_digest, source_sha):
    if type(alias) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', alias):
        reject()
    return ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15',
            '-o', 'ServerAliveCountMax=3', '-o', 'ClearAllForwardings=yes',
            '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o',
            'PermitLocalCommand=no', '-T', alias,
            'exec python3 -I -u -c ' + shlex.quote(live_bootstrap(archive_digest, source_sha))]


def published_live_archive(source_sha):
    import io
    import zipfile
    raw = _published_archive(source_sha)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if 'scripts/deployment_compose_live_worker_v3_host.py' not in archive.namelist():
            reject()
    return raw


def _write_private(path, value):
    raw=encode(value)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as output:output.write(raw)


def _live_key(root, name):
    key=root/name
    subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C',name,
                    '-f',str(key)],capture_output=True,check=True,timeout=10)
    key.chmod(0o600);key.with_suffix('.pub').chmod(0o600)
    return key,key.with_suffix('.pub').read_bytes()


def _spawn_live(argv):
    return subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,bufsize=0)


def _review_adapter(root, source_sha, recipient_private_key):
    from deployment_compose_live_review_v3_host import GitHubLiveReviewV3
    return GitHubLiveReviewV3(root,source_sha=source_sha,recipient_private_key=recipient_private_key)


def _complete_history(admission, operation, parent=None):
    """Authenticate the entire intended segment before accepting completion."""
    entry=admission._current
    if (entry is None or admission._pending is not None
            or entry['request'].operation!=operation):reject()
    snapshot=admission._history(entry).capture()
    value=json.loads(snapshot.canonical)
    writes=[op for op in entry['bundle'].resolve_operations(value['receiptMap']) if op['method']!='GET']
    status=value['chainStatus']
    if (value['blocker'] is not None or value['pending'] is not None
            or value['originalRequestHash']!=entry['request'].digest()
            or value['bundleDigest']!=entry['bundle'].digest
            or encode(value['knownPrefix'])!=encode(writes) or len(value['scopes'])!=len(writes)
            or status['activePhase']!='closed' or status['activeSeq']!=6
            or value['closedTail']!=dict(binding=status['activeBinding'],seq=6,head=status['activeHead'])):reject()
    if operation=='deploy':
        if value['schemaVersion']!=1 or parent is not None or entry is not admission._root:reject()
    elif operation=='rollback':
        if parent is None or value['schemaVersion']!=2:reject()
        original=json.loads(parent.canonical)
        expected=dict(historyDigest=parent.digest,originalRequestHash=original['originalRequestHash'],
            bundleDigest=original['bundleDigest'],tail=original['closedTail'],
            scopeCount=len(original['scopes']),startWriteIndex=0)
        if (encode(value.get('parent'))!=encode(expected)
                or entry['request'].history_hash!=parent.digest
                or entry['parentSnapshot'].canonical!=parent.canonical):reject()
    else:reject()
    return snapshot


def run_live_acceptance(private_root, ssh_alias, source_sha, *, on_review, recipient_private_key):
    """Own one frozen SSH worker and two separately reviewed staging intents.

    on_review only notifies the operator. Its return value grants no authority.
    Actual consent is read from GitHub, verified and consumed by the adapter.
    No connection, intent, witness mutation or ledger consumption is retried.
    """
    from deployment_compose_profile3_prepare_ssh_probe import _private_root
    from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
    from deployment_compose_live_admission_v3_host import MacLiveAdmissionV3
    from deployment_contract_v2 import TargetIdentity
    from deployment_gateway import GatePolicy
    from deployment_gate_witness import key_material
    if not callable(on_review):reject()
    root=_private_root(private_root)
    archive=published_live_archive(source_sha)
    archive_digest=hashlib.sha256(archive).hexdigest()
    argv=ssh_argv(ssh_alias,archive_digest,source_sha)
    case=root/('live-'+secrets.token_hex(12));case.mkdir(mode=0o700)
    review_root=case/'reviews';review_root.mkdir(mode=0o700)
    review=_review_adapter(review_root,source_sha,Path(recipient_private_key).resolve(strict=True))
    witness_signer,witness_public=_live_key(case,'live-witness')
    status_signer,status_public=_live_key(case,'live-intent-status')
    keys={name:secrets.token_bytes(32) for name in ('config','image','declaration','archive','target')}
    gate_key=secrets.token_bytes(32);store_key=secrets.token_bytes(32)
    for name,key in dict(keys,gate=gate_key,witness=store_key).items():
        fd=os.open(case/(name+'.key'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as output:output.write(key)
    state=case/'witness';state.mkdir(mode=0o700)
    store=OperationWitnessStoreV3(state,key=store_key)
    stdout_path=case/'frames.private.jsonl';stderr_path=case/'stderr.private.txt'
    for path in (stdout_path,stderr_path):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    channel_nonce=secrets.token_hex(32)
    initial=dict(entrypoint=ENTRYPOINT,sourceSha=source_sha,archiveDigest=archive_digest,
                 hostId=ssh_alias,channelNonce=channel_nonce,archiveBase64=base64.b64encode(archive).decode())
    process=None;thread=None;errors=[];deadline=time.monotonic()+3600
    hello=policy=admission=facts=deployed=final=None
    last_rpc=0;seen_nonces=set();intent_count=0
    def remaining(limit=900):
        left=deadline-time.monotonic()
        if left<=0 or errors:reject()
        return min(limit,left)
    def send(kind, **data):
        write_frame(process.stdin,dict(kind=kind,channelNonce=channel_nonce,**data),timeout=remaining(30))
    def history():
        return admission._history(admission._current).capture()
    try:
        process=_spawn_live(argv)
        def drain():
            size=0
            with open(stderr_path,'ab',buffering=0) as output:
                while True:
                    chunk=process.stderr.read(65536)
                    if not chunk:break
                    if size<1024*1024:output.write(chunk[:1024*1024-size])
                    size+=len(chunk)
                    if size>1024*1024 and not errors:errors.append('stderr-bound')
        thread=threading.Thread(target=drain,daemon=True);thread.start()
        write_frame(process.stdin,initial,timeout=remaining(30))
        for index in range(4096):
            frame=read_frame(process.stdout,timeout=remaining())
            if (type(frame) is not dict or frame.get('channelNonce')!=channel_nonce
                    or type(frame.get('kind')) is not str):reject()
            # Private source material stays in this owned directory, never GitHub.
            raw=encode(frame)
            with open(stdout_path,'ab',buffering=0) as output:
                if output.tell()+len(raw)+1>64*1024*1024:reject()
                output.write(raw+b'\n')
            kind=frame['kind'];data={k:v for k,v in frame.items() if k not in ('kind','channelNonce')}
            if kind=='hello':
                required={'root','daemonId','writerCertificateSha256','serverCertificateSha256',
                          'sourceSha','archiveDigest','hostId'}
                if (hello is not None or set(data)!=required or data['sourceSha']!=source_sha
                        or data['archiveDigest']!=archive_digest or data['hostId']!=ssh_alias
                        or not re.fullmatch('/var/tmp/dw-engine-[0-9a-f]{16}',data['root'])
                        or not isinstance(data['daemonId'],str) or not data['daemonId']
                        or any(not re.fullmatch('[0-9a-f]{64}',data[p]) for p in
                               ('writerCertificateSha256','serverCertificateSha256'))):reject()
                hello=data
                policy=GatePolicy('live-'+case.name,'live-gate-v3',digest(hello),
                    hello['writerCertificateSha256'],True,'0'*64,
                    hashlib.sha256(key_material(witness_public)).hexdigest(),operation_profile='compose-v3')
                admission=MacLiveAdmissionV3(store=store,gate_policy=policy,gate_key=gate_key,
                    witness_signer=witness_signer,witness_public_key=witness_public,
                    intent_signer=status_signer,intent_public_key=status_public)
                send('configure',policy=asdict(policy),epoch=admission._epoch,
                    witnessPublicKey=base64.b64encode(witness_public).decode(),
                    statusPublicKey=base64.b64encode(status_public).decode(),
                    keys={k:base64.b64encode(v).decode() for k,v in keys.items()},
                    gateKey=base64.b64encode(gate_key).decode())
            elif kind=='observer-facts':
                if hello is None or facts is not None:reject()
                expected='deploy' if intent_count==0 else 'rollback'
                if (set(data)!={'operation','root','daemonId','sourceSha','archiveDigest','bootId','bindDigest'}
                        or data['operation']!=expected or data['root']!=hello['root']
                        or data['daemonId']!=hello['daemonId'] or data['sourceSha']!=source_sha
                        or data['archiveDigest']!=archive_digest
                        or not re.fullmatch('[0-9a-f]{32}',data['bootId']) or data['bindDigest'] is not None):reject()
                facts=data
            elif kind in ('prepared-private','rollback-prepared-private'):
                expected='deploy' if intent_count==0 else 'rollback'
                if (facts is None or intent_count>=2 or kind!=('prepared-private' if expected=='deploy' else 'rollback-prepared-private')):reject()
                supplied_history=data.pop('history',None)
                bundle,request=verify_private_capsule(data,hello=hello,source_sha=source_sha,
                    ssh_alias=ssh_alias,policy=policy,keys=keys,
                    trusted_boot_id=facts['bootId'],trusted_bind_digest=facts['bindDigest'])
                if request.operation!=expected or process.poll() is not None:reject()
                parent=None
                if expected=='rollback':
                    parent=history()
                    if (deployed is None or supplied_history is None
                            or encode(supplied_history)!=parent.canonical
                            or parent.canonical!=deployed.canonical
                            or request.history_hash!=parent.digest):reject()
                elif supplied_history is not None:reject()
                approval,consumption,metadata=review.consume_prepared(bundle,request,on_review)
                if process.poll() is not None:reject()
                binding=admission.register_intent(bundle,request,approval,consumption,reviewed_parent=parent)
                receipt_hash=digest(asdict(consumption))
                _write_private(case/('review-'+str(intent_count)+'.private.json'),metadata)
                send('consume-intent',requestHash=request.digest(),receiptHash=receipt_hash,firstBinding=binding)
                intent_count+=1;facts=None
            elif kind=='rpc':
                if (admission is None or set(data)!={'rpcId','service','method','request'}
                        or type(data['rpcId']) is not int or data['rpcId']!=last_rpc+1
                        or type(data['request']) is not dict):reject()
                nonce=data['request'].get('rpcNonce')
                if type(nonce) is not str or nonce in seen_nonces:reject()
                seen_nonces.add(nonce);last_rpc=data['rpcId']
                reply=admission.authorize_rpc(data['service'],data['method'],data['request'])
                send('reply',rpcId=last_rpc,response=reply)
            elif kind=='deployed':
                if intent_count!=1 or deployed is not None or set(data)!={'result','history'}:reject()
                deployed=_complete_history(admission,'deploy')
                if encode(data['history'])!=deployed.canonical or deployed.snapshot['blocker'] is not None:reject()
            elif kind=='final':
                if (intent_count!=2 or deployed is None or facts is not None
                        or set(data)!={'result','history','success','cleanupCompleted','daemonStopped','productionSnapshotUnchanged'}
                        or any(data[k] is not True for k in ('success','cleanupCompleted','daemonStopped','productionSnapshotUnchanged'))):reject()
                latest=_complete_history(admission,'rollback',deployed)
                if encode(data['history'])!=latest.canonical or latest.snapshot['blocker'] is not None:reject()
                final=dict(success=True,operationCount=2,requestCount=intent_count,
                    daemonStopped=True,productionSnapshotUnchanged=True,cleanupCompleted=True,
                    root=hello['root'],sourceSha=source_sha,productionReady=False,
                    witnessFinal=private_json_status(store.chain_status(admission._current['first'])))
                process.stdin.close();process.wait(timeout=60)
                thread.join(timeout=5)
                if process.returncode or thread.is_alive() or errors:reject()
                _write_private(case/'result.private.json',final)
                return final
            else:reject()
        reject()
    finally:
        if process is not None:
            if not process.stdin.closed:process.stdin.close()
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=60)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10)
            if thread is not None:thread.join(timeout=5)
            process.stdout.close();process.stderr.close()
        store.close()


def private_json_status(value):
    return json.loads(encode(value))


def _projection(row):
    result = {key: row[key] for key in ('Config', 'HostConfig', 'Mounts', 'NetworkSettings')}
    result['Mounts'] = [{**dict.fromkeys(MOUNT), **mount} for mount in row['Mounts']]
    return result


def _batch(domain, value):
    return hashlib.sha256(domain + json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')).hexdigest()


def scope_bind_paths(scope):
    return scope.get('bindPaths', [])


def verify_private_capsule(capsule, *, hello, source_sha, ssh_alias, policy, keys,
                           trusted_boot_id, trusted_bind_digest):
    """Reconstruct commitments before publishing any review.

    Boot and bind pins must come from the controller's owned-host provenance
    boundary, never copied out of this capsule by its caller. This function
    validates captured material; Linux retains responsibility for live rechecks.
    """
    try:
        if (hello['sourceSha'] != source_sha or hello['hostId'] != ssh_alias
                or not re.fullmatch('[0-9a-f]{32}', trusted_boot_id)):
            reject()
        value = capsule['bundle']
        request = RequestV2.from_json(encode(capsule['request']).decode('ascii'))
        from datetime import datetime, timezone
        expires = datetime.strptime(request.expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        if not 0 < (expires-datetime.now(timezone.utc)).total_seconds() <= 900:
            reject()
        project = value['identity']['project']
        if (not project.startswith('dw-restore-') or request.host_id != ssh_alias
                or request.daemon_id != hello['daemonId']
                or request.target.runtime != 'compose' or request.target.namespace != project
                or request.target.target_id != 'staging' or request.environment != 'staging'
                or request.production is not False or request.policy_hash != policy.identity_hash()
                or request.source.provider_id != 'github.com'
                or request.source.origin != 'https://github.com/' + REPOSITORY + '.git'
                or request.source.project_id != REPOSITORY_ID or request.source.project_path != REPOSITORY
                or request.source.source_sha != source_sha or request.operation not in ('deploy', 'rollback')):
            reject()
        if value['identity'] != dict(hostId=ssh_alias, daemonId=hello['daemonId'],
                project=project, sourceIdentity=encode(capsule['request']['source']).decode('ascii')):
            reject()
        from deployment_compose_log_probe import IMAGE
        from deployment_compose_namespaced_transition_probe import V2
        fixed_target = 'public.ecr.aws/docker/library/' + (V2 if request.operation == 'deploy' else IMAGE)
        defaults, manifests = {}, {}
        for service in value['services']:
            name = service['name']; ti = capsule['targetInputs'][name]
            if ti['expected_registry_digest'] != fixed_target:
                reject()
            derived = derive_defaults(ti['image'], ti['commitment'], keys['target'],
                **{k:ti[k] for k in ('expected_image_id','expected_registry_digest','expected_architecture')})
            if ti['commitment']['keyId'] != ti['expected_key_id']:
                reject()
            defaults[name] = {k:derived[k] for k in ZERO_DEFAULTS}
            manifests[name] = dict(image=ti['image'], commitment=ti['commitment'],
                expectedKeyId=ti['expected_key_id'], registryDigest=ti['expected_registry_digest'],
                architecture=ti['expected_architecture'])
        bundle = ExecutionBundleV3({k:value[k] for k in FIELDS}, authenticated_image_defaults=defaults)
        if (encode(bundle.to_dict()) != encode(value)
                or encode(bundle.public_review()) != encode(capsule['publicReview'])
                or request.plan_hash != bundle.digest
                or request.after_hash != digest({s['name']:s['targetCreateBody'] for s in value['services']})
                or request.artifact_digest != digest(manifests)):
            reject()
        artifacts = ComposeArtifacts.from_json(encode(capsule['baselineArtifacts']).decode('ascii'))
        rows = capsule['rawRows']; by_id = {row['Id']:row for row in rows.values()}
        if len(by_id) != len(rows) or baseline_state_digest(by_id) != value['baselineStateDigest']:
            reject()
        if (request.components != ('backend',) or request.protected_components != ('peer',)
                or value['protectedContainers'] != [dict(containerId=rows['peer']['Id'],
                    staticConfigDigest=protected_state_digest(rows['peer']))]):
            reject()
        private = {}
        for name, row in rows.items():
            private[row['Id']] = commit(project, name, _projection(row), 'profile3-config', keys['config'])['configHmac']
        for artifact in artifacts.services:
            row = rows[artifact.service]
            if (artifact.source_sha != source_sha or artifact.image_id != row['Image']
                    or artifact.config_key_id != 'profile3-config'
                    or artifact.config_hmac != private[row['Id']]):
                reject()
        if request.before_hash != artifacts.digest():
            reject()
        from deployment_compose_restore_body_host import compile_restore_body
        if digest(capsule['sourceModel']) != capsule['sourceFacts']['expected_source_model_digest']:
            reject()
        facts = dict(capsule['sourceFacts'])
        facts.update(private_key=keys['config'], image_key=keys['image'], declaration_key=keys['declaration'])
        # The fixed fixture selects exactly one backend service; source facts
        # are the preparer's single authenticated retained-source input.
        if len(value['services']) != 1 or value['services'][0]['name'] != 'backend':
            reject()
        raw = {k:rows['backend'][k] for k in ('Id','Name','Image','Config','HostConfig','NetworkSettings','Mounts')}
        raw['Mounts'] = _projection(rows['backend'])['Mounts']
        candidate = compile_restore_body(raw=raw, artifact=artifacts.services[0],
            operation_nonce=value['operationNonce'], **facts)
        if encode(candidate['body']) != encode(value['services'][0]['baselineCreateBody']):
            reject()
        material = capsule['observationMaterial']
        if set(material) != {'boot','structure','private','instance','catalog','bind'}:
            reject()
        if (trusted_bind_digest is not None or scope_bind_paths(capsule['scopePolicy'])
                or material['boot'] != trusted_boot_id or material['bind'] is not None
                or request.observation_hash != _batch(b'dev-workflow:compose-host-observation:v1\0', material)):
            reject()
        resources = capsule['phaseSnapshot']['resources']
        catalog = {item['Id']:item for item in capsule['imageCatalog']}
        scope = capsule['scopePolicy']
        class CapturedReader:
            list_path = '/inventory'
            policy = SimpleNamespace(private_key_id='profile3-config', bind_count=0)
            def get(self, path, **kwargs):
                if path == '/v1.45/info': return {'ID':hello['daemonId']}
                if path == self.list_path:
                    return [dict(Id=row['Id'], Labels=row['Config']['Labels']) for row in rows.values()]
                for cid, row in by_id.items():
                    if path == '/v1.45/containers/'+cid+'/json': return row
                    if path == '/v1.45/workflow/private/'+cid: return {'configHmac':private[cid]}
                for name, ident in scope['networks'].items():
                    if path == '/v1.45/networks/'+ident: return resources['network:'+name]
                for name in scope['volumes']:
                    if path == '/v1.45/volumes/'+name: return resources['volume:'+name]
                for ident, image in catalog.items():
                    if path == '/v1.45/images/'+ident+'/json': return image
                reject()
        assessment, commitments, instances, images, _ = _snapshot(CapturedReader(), scope, time.monotonic()+10)
        if (assessment['structuralStatus'] == 'blocked'
                or material['structure'] != assessment['structureDigest']
                or material['private'] != _batch(b'dev-workflow:compose-private-batch:v1\0', commitments)
                or material['instance'] != _batch(b'dev-workflow:compose-instance-batch:v1\0', instances)
                or material['catalog'] != image_catalog_digest(images)):
            reject()
        return bundle, request
    except Exception:
        reject()
