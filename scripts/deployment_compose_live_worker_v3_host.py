"""Fixed Linux private worker. This module has no CLI and is never a consent UI.

Private length-prefixed canonical JSON protocol (existing 4 MiB frame limit):
hello -> configure -> observer-facts -> prepared-private -> consume-intent -> rpc/reply* ->
deployed -> observer-facts -> rollback-prepared-private -> consume-intent -> rpc/reply* -> final.
Every frame pins channelNonce. configure carries GatePolicy.public dataclass
fields, epoch, witnessPublicKey, statusPublicKey, keys (five base64 HMAC keys),
and gateKey. consume-intent carries exactly requestHash, receiptHash,
firstBinding. These are references, never approval; fresh signed status and the
independent witness store remain mandatory. No credentials/PAT enter this host.
Only publicReview may be copied out of the private SSH channel. The final frame
is emitted after the outer probe confirms daemon shutdown and the unchanged
production snapshot; the controller must also require a successful worker exit.
"""
import base64
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
import threading
import uuid

from deployment_compose_v3_channel_worker import read_frame, write_frame
from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3, hex_value
from deployment_compose_intent_status_v3 import IntentStatusClientV3
from deployment_compose_coordinator_v3_host import Profile3StepExecutor, ComposeCoordinatorV3, canonical
from deployment_compose_history_v3_host import AuthenticatedHistoryV3
from deployment_gateway import GatePolicy

ENTRYPOINT = 'deployment_compose_live_worker_v3_host.run'
RPC_TIMEOUT = 90
KEYS = {'config','image','declaration','archive','target'}


def private_json(value):
    from collections.abc import Mapping
    if isinstance(value, Mapping): return {k:private_json(v) for k,v in value.items()}
    if isinstance(value,(tuple,list)): return [private_json(v) for v in value]
    if type(value) is bytes: return {'bodyBase64':base64.b64encode(value).decode('ascii')}
    return value


def reject():
    raise ValueError('compose-live-worker-v3-rejected')


class Channel:
    def __init__(self, config, stdin, stdout):
        if (type(config) is not dict or set(config) != {'entrypoint','channelNonce','sourceSha','archiveDigest','hostId'}
                or config['entrypoint'] != ENTRYPOINT or not hex_value(config['channelNonce'])
                or not hex_value(config['archiveDigest'])
                or type(config['sourceSha']) is not str or not re.fullmatch('[0-9a-f]{40}',config['sourceSha'])
                or not isinstance(config['hostId'],str) or not config['hostId']): reject()
        self.config, self.stdin, self.stdout = config, stdin, stdout
        self.deadline = time.monotonic()+3600
        self.count = 0
        self.failed = False
        self._rpc_lock = threading.Lock()
        self._step_deadline = None

    def timeout(self):
        deadline=min(self.deadline,self._step_deadline) if self._step_deadline is not None else self.deadline
        left=deadline-time.monotonic()
        if self.failed or left <= 0: reject()
        return min(900,left)

    def emit(self, kind, **payload):
        try: write_frame(self.stdout,private_json(dict(kind=kind,channelNonce=self.config['channelNonce'],**payload)),timeout=self.timeout())
        except BaseException:
            self.failed=True
            raise

    def receive(self, kind):
        try:
            value=read_frame(self.stdin,timeout=self.timeout())
            if type(value) is not dict or value.get('kind') != kind or value.get('channelNonce') != self.config['channelNonce']: reject()
            return {k:v for k,v in value.items() if k not in ('kind','channelNonce')}
        except BaseException:
            self.failed=True
            raise

    @contextmanager
    def operation_scope(self, deadline):
        with self._rpc_lock:
            if self._step_deadline is not None or deadline <= time.monotonic(): reject()
            self._step_deadline = deadline
        try:
            yield
        finally:
            with self._rpc_lock:
                self._step_deadline = None

    def rpc(self, service, method, request):
        acquired = False
        try:
            deadline = time.monotonic() + min(RPC_TIMEOUT, self.timeout())
            acquired = self._rpc_lock.acquire(timeout=max(0, deadline-time.monotonic()))
            if not acquired: reject()
            def remaining():
                left = min(deadline-time.monotonic(), self.timeout())
                if left <= 0: reject()
                return left
            if self.count >= 4096: reject()
            self.count += 1
            rpc_id = self.count
            write_frame(self.stdout,private_json(dict(kind='rpc',channelNonce=self.config['channelNonce'],
                rpcId=rpc_id,service=service,method=method,request=request)),timeout=remaining())
            reply=read_frame(self.stdin,timeout=remaining())
            if (type(reply) is not dict or set(reply)!={'kind','channelNonce','rpcId','response'}
                    or reply['kind']!='reply' or reply['channelNonce']!=self.config['channelNonce']
                    or type(reply['rpcId']) is not int or reply['rpcId']!=rpc_id): reject()
            return reply['response']
        except BaseException:
            self.failed = True
            raise
        finally:
            if acquired: self._rpc_lock.release()


def writer_tls(root):
    """Generate host-owned mutual TLS with restrictive certificate key usages."""
    if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o777 != 0o700: reject()
    directory=root/'live-writer-tls'; directory.mkdir(mode=0o700)
    def openssl(*args):
        subprocess.run(['openssl',*args],cwd=directory,capture_output=True,check=True,timeout=20)
        for p in directory.iterdir(): p.chmod(0o600)
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=Private live CA',
            '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
    for name,usage in (('server','serverAuth'),('writer','clientAuth')):
        openssl('req','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name)
        fd=os.open(directory/(name+'.ext'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:
            f.write('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\n')
        openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','1','-extfile',name+'.ext')
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(directory/'server.pem',directory/'server.key')
    server.load_verify_locations(directory/'ca.pem'); server.verify_mode=ssl.CERT_REQUIRED
    client=ssl.create_default_context(cafile=str(directory/'ca.pem'))
    client.load_cert_chain(directory/'writer.pem',directory/'writer.key')
    def pin(name): return hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory/(name+'.pem')).read_text())).hexdigest()
    return server,client,pin('server'),pin('writer')


# Fixed host code only; arguments contain validated addresses/token/version, never
# source code. Enter only the protected peer's net namespace, keeping host rootfs.
PROBE_CODE = r'''
import sys,json,socket,struct,http.client,pathlib,secrets
args=json.loads(sys.argv[1]); assert set(args)=={'addresses','versions','token'}
cg=[x.split(':',2)[2] for x in pathlib.Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::')]; assert len(cg)==1
root=pathlib.Path('/sys/fs/cgroup')/cg[0].lstrip('/')
assert (root/'memory.max').read_text().strip()=='67108864'
assert (root/'memory.swap.max').read_text().strip()=='0'
assert (root/'pids.max').read_text().strip()=='16'
quota,period=map(int,(root/'cpu.max').read_text().split()); assert 0<quota<=period//4
for name in ('backend','peer'):
    ident=secrets.randbelow(65536); q=name.encode(); packet=struct.pack('!HHHHHH',ident,256,1,0,0,0)+bytes([len(q)])+q+b'\0'+struct.pack('!HH',1,1)
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(packet,('127.0.0.11',53)); data,source=s.recvfrom(4096)
    finally: s.close()
    assert source==('127.0.0.11',53)
    rid,flags,nq,na,ns,nr=struct.unpack('!HHHHHH',data[:12]); assert rid==ident and flags&32768 and flags&0x7a0f==0 and nq==1 and 1<=na<=16
    assert data[12:len(packet)]==packet[12:]; pos=len(packet); found=[]
    for _ in range(na):
        if data[pos]&192==192: pos+=2
        else:
            while data[pos]: pos+=1+data[pos]
            pos+=1
        typ,cls,ttl,n=struct.unpack('!HHIH',data[pos:pos+10]); pos+=10
        if typ==1 and cls==1 and n==4: found.append(socket.inet_ntoa(data[pos:pos+4]))
        pos+=n
    assert found==[args['addresses'][name]]
    for path in ('/health','/business/probe'):
        connection=http.client.HTTPConnection(args['addresses'][name],8080,timeout=3)
        try:
            connection.request('GET',path,headers={'Connection':'close'})
            r=connection.getresponse()
            assert r.status==200; raw=r.read(16385); assert len(raw)<=16384
        finally: connection.close()
        def unique(pairs):
            result={}
            for k,v in pairs:
                assert k not in result; result[k]=v
            return result
        value=json.loads(raw,object_pairs_hook=unique)
        assert set(value)=={'token','version','path','checks'}
        assert value['token']==args['token'] and value['path']==path
        assert value['version'].startswith(args['versions'][name]+' ') and '\n' not in value['version']
        assert type(value['checks']) is dict and set(value['checks'])=={'sentinelPreserved','bindReadonly','rootReadonly'}
        assert all(check is True for check in value['checks'].values())
print('{"success":true}')
'''


def probe_command(unit, namespace_fd, addresses, versions, token):
    if (not re.fullmatch('dw-live-probe-[0-9a-f]{32}\\.service',unit)
            or type(namespace_fd) is not int or namespace_fd<3
            or set(addresses) != {'backend','peer'} or set(versions) != {'backend','peer'}
            or not re.fullmatch('dw-restore-[0-9a-f]{24}',token)): reject()
    for ip in addresses.values():
        if str(ipaddress.IPv4Address(ip)) != ip or ipaddress.IPv4Address(ip).is_unspecified or ipaddress.IPv4Address(ip).is_loopback: reject()
    if any(type(v) is not str or not re.fullmatch(r'3\.[0-9]+\.[0-9]+',v) for v in versions.values()): reject()
    return ['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
        '--property=MemoryMax=64M','--property=MemorySwapMax=0','--property=CPUQuota=25%',
        '--property=TasksMax=16','--property=RuntimeMaxSec=30','--',
        'nsenter','--net=/proc/'+str(os.getpid())+'/fd/'+str(namespace_fd),'--','/usr/bin/python3','-I','-c',PROBE_CODE,
        canonical(dict(addresses=addresses,versions=versions,token=token)).decode('ascii')]


def stop_probe_unit(unit):
    """Confirm the one owned unit is gone, including collected units."""
    def state():
        result=subprocess.run(['systemctl','show',unit,'--property=LoadState,ActiveState,MainPID,ControlGroup'],
            capture_output=True,timeout=10,check=False)
        values=dict(line.split('=',1) for line in result.stdout.decode('ascii').splitlines() if '=' in line)
        if set(values)!={'LoadState','ActiveState','MainPID','ControlGroup'}: reject()
        return values
    before=state()
    group=before['ControlGroup']
    if before['LoadState']!='not-found' and before['ActiveState'] not in ('inactive','failed'):
        subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=10,check=False)
    after=state()
    if (after['LoadState'] not in ('not-found','loaded') or after['ActiveState'] not in ('inactive','failed')
            or after['MainPID']!='0'): reject()
    for name in {group,after['ControlGroup']} - {''}:
        # A unit path is authoritative systemd output, but must remain beneath
        # the cgroup mount and identify our exact owned transient service.
        path=Path('/sys/fs/cgroup')/name.lstrip('/')
        if '..' in Path(name).parts or path.name!=unit: reject()
        try: events=dict(line.split() for line in (path/'cgroup.events').read_text().splitlines())
        except FileNotFoundError: continue
        if events.get('populated')!='0': reject()


def readiness(session, cid):
    from deployment_compose_phase_guard_v3_host import protected_state_digest
    protected=session.raw_rows['peer']
    peer_id=protected['Id']
    deadline=time.monotonic()+90
    while True:
        rows={name:session.producer._get('/v1.45/containers/'+identity+'/json') for name,identity in
              (('backend',cid),('peer',peer_id))}
        if protected_state_digest(rows['peer'])!=protected_state_digest(protected): reject()
        if all(row['State']['Running'] is True and row['State']['Health']['Status']=='healthy' for row in rows.values()): break
        if any(row['State']['Health']['Status'] not in ('starting','healthy') for row in rows.values()): reject()
        if time.monotonic()>=deadline: raise TimeoutError('compose-live-readiness-deadline')
        time.sleep(min(1,max(0,deadline-time.monotonic())))
    addresses={}; versions={}
    for name,row in rows.items():
        networks=row['NetworkSettings']['Networks']
        if len(networks)!=1: reject()
        addresses[name]=next(iter(networks.values()))['IPAddress']
        image=session.producer._get('/v1.45/images/'+row['Image']+'/json')
        # Only enrolled immutable image facts determine the expected version.
        enrolled=next((item for item in session.enrolled_images if item['Id']==row['Image']),None)
        if enrolled is None or canonical(image)!=canonical(enrolled): reject()
        env=[x.split('=',1)[1] for x in enrolled['Config']['Env'] if x.startswith('PYTHON_VERSION=')]
        if len(env)!=1: reject()
        versions[name]=env[0]
    pid=rows['peer']['State']['Pid']
    if type(pid) is not int or pid<=1: reject()
    fd=os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY|os.O_CLOEXEC)
    unit='dw-live-probe-'+uuid.uuid4().hex+'.service'
    attempted=False
    try:
        fresh=session.producer._get('/v1.45/containers/'+peer_id+'/json')
        if (protected_state_digest(fresh)!=protected_state_digest(protected)
                or fresh['State']['Pid']!=pid or fresh['State']['StartedAt']!=rows['peer']['State']['StartedAt']
                or os.stat('/proc/'+str(pid)+'/ns/net').st_ino!=os.fstat(fd).st_ino): reject()
        command=probe_command(unit,fd,addresses,versions,session.project)
        attempted=True
        result=subprocess.run(command,capture_output=True,check=True,timeout=40)
        if result.stdout.strip()!=b'{"success":true}': reject()
        if protected_state_digest(session.producer._get('/v1.45/containers/'+peer_id+'/json'))!=protected_state_digest(protected): reject()
        return True
    finally:
        original=sys.exc_info()[1]
        try:
            if attempted: stop_probe_unit(unit)
        except BaseException as error:
            if original is None: raise
            if hasattr(original,'add_note'): original.add_note('owned probe cleanup failed: '+str(error))
        finally: os.close(fd)


def execute_operation(channel, session, prepared, policy, gate_key, public, status_public,
                      tls, tracker, *, parent=None, reviewed=None, fence=None):
    bundle,request=prepared['bundle'],prepared['request']
    consumed=channel.receive('consume-intent')
    if (set(consumed)!={'requestHash','receiptHash','firstBinding'} or consumed['requestHash']!=request.digest()
            or not hex_value(consumed['receiptHash'])): reject()
    binding=consumed['firstBinding']
    descriptor=Profile3StepExecutor.scope_descriptor(bundle,request,consumed['receiptHash'],bundle.creation_operations()[0],0,{})
    if (type(binding) is not dict or binding.get('scopeHash')!=descriptor['scopeHash']
            or binding.get('generation')!=descriptor['generation']
            or binding.get('policyHash')!=policy.identity_hash() or binding.get('epoch')!=tracker.epoch): reject()
    authority=IntentStatusClientV3(request,status_public,lambda req:channel.rpc('intent','check',req))
    authority.check_consumed_intent(request)
    factory=lambda b:OperationWitnessClientV3(b,public,lambda method,req:channel.rpc('witness',method,req))
    history=AuthenticatedHistoryV3(bundle,request,gate_policy=policy,gate_key=gate_key,
        consumption_receipt_hash=consumed['receiptHash'],witness_client=factory(binding),witness_client_factory=factory,
        parent_history=parent,reviewed_parent_snapshot=reviewed)
    @contextmanager
    def operation_scope(deadline):
        with channel.operation_scope(deadline), session.producer.operation_scope(deadline):
            yield
    server,client,pin,_=tls
    session.unknown_write_result=True; tracker.mark_product_pending()
    try:
        executor=Profile3StepExecutor(bundle,request,intent_authority=authority,phase_guard=session.guard,
            gate_root=session.root/('live-gate-'+request.digest()),gate_key=gate_key,gate_policy=policy,
            consumption_receipt_hash=consumed['receiptHash'],witness_client_factory=factory,
            registered_binding=binding,tls_server_context=server,tls_client_context=client,
            server_certificate_sha256=pin,docker_socket=Path(session.target.socket),startup_fence=fence,operation_scope=operation_scope)
        def verify(receipts):
            done=bundle.creation_operations()
            op=bundle.resolve_operations(dict(receipts))[len(done)]
            return session.guard(dict(phase_index=len(done),operation=op,receipts=dict(receipts),completed_operations=done)) is True
        def verify_readiness(service,cid):
            if service!='backend' or readiness(session,cid) is not True: return False
            receipts={service:cid}
            done=bundle.resolve_operations(receipts)
            # There is no next write after readiness. Reuse the guard's final
            # state capture, as current-baseline preparation does, to pin the
            # full approved target body/image and unchanged protected peer.
            first=session.guard._capture(done,receipts)
            return canonical(first)==canonical(session.guard._capture(done,receipts))
        coordinator=ComposeCoordinatorV3(executor,verify_candidates=verify,readiness=verify_readiness)
        result=coordinator.run()
    finally:
        original=sys.exc_info()[1]
        try: tracker.apply_to_session(session,history)
        except BaseException as error:
            if original is None: raise
            if hasattr(original,'add_note'): original.add_note('ownership reconciliation failed: '+str(error))
    return result,history


def private_capsule(session, prepared):
    observation=session.whole_observation
    commitment=session.whole_observer.commitment(observation)
    if commitment != prepared['request'].observation_hash: reject()
    operation=prepared['bundle'].creation_operations()[0]
    phase=session.guard.capture_phase(dict(phase_index=0,operation=operation,receipts={},completed_operations=[]))
    target=session.preparer._target_inputs
    return dict(bundle=prepared['bundle'].to_dict(),request=asdict(prepared['request']),
        publicReview=prepared['bundle'].public_review(),sourceModel=session.source_model,rawRows=session.raw_rows,
        sourceFacts={k:v for k,v in session.source_inputs.items() if type(v) is not bytes},
        targetInputs={name:{k:v for k,v in values.items() if type(v) is not bytes} for name,values in target.items()},
        baselineArtifacts=asdict(session.preparer._artifacts),scopePolicy=session.whole_observer._policy,
        imageCatalog=session.enrolled_images,phaseSnapshot=private_json(phase),
        observationMaterial={name:getattr(observation,'_'+name) for name in ('boot','structure','private','instance','catalog','bind')})


def bind_prepared_guard(session, prepared, root):
    """A newly derived nonce needs its own guard over the pinned CAS baseline."""
    from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
    from deployment_compose_phase_guard_v3_host import PhaseGuardV3
    version=session.producer._get('/v1.45/version')
    version={key:version[key] for key in ('Version','GitCommit')}
    rows=TrustedPhaseStateProducerV3.reload(session.store,prepared['bundle'],read_json=session.producer._get,
        daemon_version=version,expected_docker_root=str(root/'data'))
    session.guard=PhaseGuardV3(prepared['bundle'],rows,read_json=session.producer._get,
        daemon_version=version,expected_docker_root=str(root/'data'))
    return session.guard


def emit_observer_facts(channel, session, prepared, root):
    """Report fresh owned TLS gateway facts separately from the private capsule."""
    from deployment_compose_reader import ComposeDockerReader
    observer=session.whole_observer
    observation=session.whole_observation
    if type(observer._reader) is not ComposeDockerReader or observer._reader._transport is not None: reject()
    info=observer._reader.gateway_info()
    if info['bootId']!=observation._boot or observation._bind is not None: reject()
    request=prepared['request']
    channel.emit('observer-facts',operation=request.operation,root=str(root),daemonId=request.daemon_id,
        sourceSha=channel.config['sourceSha'],archiveDigest=channel.config['archiveDigest'],
        bootId=info['bootId'],bindDigest=None)


def finish_probe(channel, report, final_payload):
    """Publish success only after the owned daemon's outer finally completed."""
    if (type(report) is not dict or any(report.get(key) is not True for key in
            ('completed','stopped','productionSnapshotUnchanged'))
            or type(final_payload) is not dict
            or final_payload.get('success') is not True or final_payload.get('cleanupCompleted') is not True): reject()
    channel.emit('final',**final_payload,daemonStopped=True,productionSnapshotUnchanged=True)
    return report


def run(config, stdin, stdout):
    channel=Channel(config,stdin,stdout)
    from deployment_compose_profile3_prepare_ssh_probe import _probe
    from compose_profile3_prepare_fixture import prepare_profile3,prepare_current_profile3
    from compose_profile3_ownership_fixture import FixtureOwnershipTrackerV3
    from deployment_compose_rollback_prepare_v3_host import RollbackPreparationHostV3
    from deployment_compose_startup_fence_v3_host import Profile3StartupFenceV3
    final_payload=None
    workload_error=None
    def workload(root,info):
        nonlocal final_payload,workload_error
        session=None
        try:
            tls=writer_tls(root)
            channel.emit('hello',root=str(root),daemonId=info['ID'],writerCertificateSha256=tls[3],
                serverCertificateSha256=tls[2],sourceSha=config['sourceSha'],archiveDigest=config['archiveDigest'],hostId=config['hostId'])
            setup=channel.receive('configure')
            if set(setup)!={'policy','epoch','witnessPublicKey','statusPublicKey','keys','gateKey'}: reject()
            policy=GatePolicy(**setup['policy'])
            public=base64.b64decode(setup['witnessPublicKey'],validate=True)
            status=base64.b64decode(setup['statusPublicKey'],validate=True)
            gate_key=base64.b64decode(setup['gateKey'],validate=True)
            keys={k:base64.b64decode(v,validate=True) for k,v in setup['keys'].items()}
            from deployment_gate_witness import key_material
            if (set(keys)!=KEYS or any(len(v)!=32 for v in keys.values()) or len(gate_key)!=32
                    or not hex_value(setup['epoch']) or policy.writer_certificate_sha256!=tls[3]
                    or policy.operation_profile!='compose-v3' or policy.witness_scope_hash!='0'*64
                    or policy.witness_key_sha256!=hashlib.sha256(key_material(public)).hexdigest()): reject()
            session=prepare_profile3(root,info,source_sha=config['sourceSha'],host_id=config['hostId'],
                expected_daemon_id=info['ID'],keys=keys,policy_hash=policy.identity_hash(),environment='staging',expiry_seconds=600)
            bundle=session.prepared['bundle']; request=session.prepared['request']
            tracker=FixtureOwnershipTrackerV3(project=session.project,daemon_id=info['ID'],policy_hash=policy.identity_hash(),
                witness_pub_hash=policy.witness_key_sha256,epoch=setup['epoch'],initial_confirmed_ids=session.created_ids,
                protected_ids=[x['containerId'] for x in bundle.to_dict()['protectedContainers']])
            emit_observer_facts(channel,session,session.prepared,root)
            channel.emit('prepared-private',**private_capsule(session,session.prepared))
            result,history=execute_operation(channel,session,session.prepared,policy,gate_key,public,status,tls,tracker)
            snapshot=history.capture()
            channel.emit('deployed',result=result,history=json.loads(snapshot.canonical))
            current=prepare_current_profile3(session,original_bundle=bundle,original_request=request,authenticated_history=history,
                keys=keys,source_sha=config['sourceSha'],host_id=config['hostId'],policy_hash=policy.identity_hash())
            rollback=RollbackPreparationHostV3(original_bundle=bundle,original_request=request,original_history=history,
                original_archive_store=session.store,original_private_keys={'profile3-config':keys['config']},current_preparation=current['preparer'])
            prepared=rollback.prepare_intent(current['whole_observation'],current['retention_observation'],
                operation_nonce=uuid.uuid4().hex+uuid.uuid4().hex,expires_at=current['prepared']['request'].expires_at)
            current['private_session'].enrolled_images=session.enrolled_images
            current['guard']=bind_prepared_guard(current['private_session'],prepared,root)
            emit_observer_facts(channel,current['private_session'],prepared,root)
            channel.emit('rollback-prepared-private',**private_capsule(current['private_session'],prepared),history=json.loads(snapshot.canonical))
            def quiesce():
                # StepExecutor closes each owned gateway before returning. A fresh
                # authenticated closed tail proves no active writer remains.
                return history.capture().canonical==snapshot.canonical
            fence=Profile3StartupFenceV3(original_history=history,reviewed_history=snapshot,quiesce_writer=quiesce)
            session.guard=current['guard']
            session.producer=current['private_session'].producer
            result,child=execute_operation(channel,session,prepared,policy,gate_key,public,status,tls,tracker,
                parent=history,reviewed=snapshot,fence=fence)
            final_history=json.loads(child.capture().canonical)
            session.cleanup()
            session=None
            final_payload=dict(result=result,history=final_history,success=True,cleanupCompleted=True)
            return dict(success=True)
        except BaseException as error:
            workload_error=error
            if session is None: session=getattr(error,'preparation_session',None)
            raise
        finally:
            if session is not None:
                original=sys.exc_info()[1]
                try: session.cleanup()
                except BaseException as error:
                    if original is None:
                        workload_error=error
                        raise
                    if hasattr(original,'add_note'): original.add_note('fixture cleanup failed: '+str(error))
    report=_probe(workload)
    if workload_error is not None: raise workload_error
    return finish_probe(channel,report,final_payload)
