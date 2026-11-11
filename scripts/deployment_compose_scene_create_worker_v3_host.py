"""Fixed attached first-create worker; consent still comes from signed live RPC.

The service supplies its frozen scene/preparation and business trust roots. This
worker creates no daemon and never deletes the service's preparation resources.
A consume reference is not approval: original intent, witness and Gate checks
remain mandatory before the sole create. There is no ordinary CLI.
"""
import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import ssl
import stat
import sys
import time
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/p) for p in ('scripts','core/scripts','packs/deployment/scripts','packs/release/scripts','tests/support')]
import deployment_compose_live_worker_v3_host as live
import deployment_compose_owned_recovery_worker_v3_host as original
from deployment_compose_owned_recovery_unit_v3_host import OwnedRecoveryUnitV3
from deployment_compose_executor_capture_v3_host import reconstruct_initial_capture
from deployment_compose_live_ssh_v3_host import verify_private_capsule
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_phase_state_v3_host import TrustedPhaseStateProducerV3
from deployment_compose_phase_guard_v3_host import PhaseGuardV3
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical
from deployment_gate_witness import key_material
from deployment_gateway import GatePolicy
from compose_profile3_ownership_fixture import FixtureOwnershipTrackerV3
from deployment_compose_namespaced_runtime_probe import PrivateDaemon

ENTRYPOINT='deployment_compose_scene_create_worker_v3_host.run'
_BASE={'entrypoint','sourceSha','archiveDigest','channelNonce','hostId'}
_CONTEXT={'daemonBinding','hello','capsuleBase64','integrityKeys','gatePolicy','gateKey',
          'witnessPublicKey','intentPublicKey','consume','observerFacts','normalizationVersion'}
_FALSE=('authorityGranted','runtimePermit','recoveryAuthorized','productionReady')


def reject():raise ValueError('compose-scene-create-worker-v3-rejected') from None


def _bytes(value,limit):
    if type(value) is not str or len(value)>((limit+2)//3)*4:reject()
    raw=base64.b64decode(value,validate=True)
    if not 0<len(raw)<=limit or base64.b64encode(raw).decode('ascii')!=value:reject()
    return raw


class SceneCreateUnitV3(OwnedRecoveryUnitV3):
    def __init__(self,archive_digest,source_sha):
        super().__init__(archive_digest,source_sha)
        module='deployment_compose_owned_recovery_worker_v3_host'
        if self._code.count(module)!=2:reject()
        self._code=self._code.replace(module,'deployment_compose_scene_create_worker_v3_host')


class Channel(live.Channel):
    def __init__(self,config,stdin,stdout,consume):
        super().__init__(dict(config,entrypoint=live.ENTRYPOINT),stdin,stdout)
        self.config=dict(config);self._consume=decode(canonical(consume));self._consume_used=False
    def receive(self,kind):
        if kind!='consume-intent' or self._consume_used:reject()
        self._consume_used=True
        return decode(canonical(self._consume))
    def rpc(self,service,method,request):
        allowed={'intent':{'check'},'witness':{'read','check','events_after','chain_status','append_event'}}
        if service not in allowed or method not in allowed[service]:reject()
        return super().rpc(service,method,request)


def _fresh(binding):
    if type(binding) is not dict:reject()
    observer=ObservedRecoveryDaemonV3(binding['root'],binding['daemonId'],kernel_boot=binding['kernelBoot'])
    try:
        if canonical(observer.binding())!=canonical(binding):reject()
        info=observer._request('/v1.45/info',time.monotonic()+5,[8*1024*1024])
        if info.get('ID')!=binding['daemonId'] or info.get('DockerRootDir')!=binding['root']+'/data':reject()
        return info
    finally:observer.close()


def _tls(root,hello):
    directory=root/'live-writer-tls';info=directory.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:reject()
    for name in ('ca.pem','server.pem','server.key','writer.pem','writer.key'):
        info=(directory/name).stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:reject()
    def pin(name):return hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory/name).read_text())).hexdigest()
    if pin('server.pem')!=hello['serverCertificateSha256'] or pin('writer.pem')!=hello['writerCertificateSha256']:reject()
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(directory/'server.pem',directory/'server.key')
    server.load_verify_locations(directory/'ca.pem');server.verify_mode=ssl.CERT_REQUIRED
    client=ssl.create_default_context(cafile=str(directory/'ca.pem'))
    client.load_cert_chain(directory/'writer.pem',directory/'writer.key')
    return server,client,hello['serverCertificateSha256'],hello['writerCertificateSha256']


def run(config,stdin,stdout):
    retained={};store=None;channel=None
    try:
        if type(config) is not dict or set(config)!=_BASE|{'context'} or config['entrypoint']!=ENTRYPOINT:reject()
        base={key:config[key] for key in _BASE};context=config['context']
        if type(context) is not dict or set(context)!=_CONTEXT:reject()
        context=decode(canonical(context));binding=context['daemonBinding'];hello=context['hello']
        info=_fresh(binding);root=Path(binding['root'])
        if (type(hello) is not dict or set(hello)!={'root','daemonId','serverCertificateSha256','writerCertificateSha256','sourceSha','archiveDigest','hostId'}
                or any(hello[key]!=base[key] for key in ('sourceSha','archiveDigest','hostId'))
                or hello['root']!=str(root) or hello['daemonId']!=binding['daemonId']):reject()
        policy=GatePolicy(**context['gatePolicy'])
        public=key_material(_bytes(context['witnessPublicKey'],8192))
        status_public=key_material(_bytes(context['intentPublicKey'],8192))
        if (public==status_public or hashlib.sha256(public).hexdigest()!=policy.witness_key_sha256
                or policy.scope_hash!=hashlib.sha256(canonical(hello)).hexdigest()
                or policy.writer_certificate_sha256!=hello['writerCertificateSha256']):reject()
        encoded=context['integrityKeys']
        if type(encoded) is not dict or set(encoded)!=live.KEYS:reject()
        keys={key:_bytes(value,32) for key,value in encoded.items()}
        if any(len(value)!=32 for value in keys.values()):reject()
        gate_key=_bytes(context['gateKey'],4096)
        if len(gate_key)<32:reject()
        capsule=_bytes(context['capsuleBase64'],4*1024*1024)
        facts=context['observerFacts']
        if (type(facts) is not dict or set(facts)!={'operation','root','daemonId','sourceSha','archiveDigest','bootId','bindDigest'}
                or facts['operation']!='deploy' or facts['bindDigest'] is not None
                or any(facts[key]!=hello[key] for key in ('root','daemonId','sourceSha','archiveDigest'))):reject()
        expected=dict(hello=hello,source_sha=base['sourceSha'],ssh_alias=base['hostId'],policy=policy,
            trusted_boot_id=facts['bootId'],trusted_bind_digest=None)
        initial=reconstruct_initial_capture(capsule,expected=expected,integrity_keys=keys,
            cas_root=str(root/'profile3-archive'),cas_key=keys['archive'],docker_socket=str(root/'docker.sock'),
            daemon_version=context['normalizationVersion'],docker_root=str(root/'data'))
        bundle,request=verify_private_capsule(decode(capsule),keys=keys,**expected)
        if canonical(bundle.to_dict())!=initial.bundle_bytes or request.canonical_json().encode('ascii')!=initial.request_bytes:reject()
        request.ensure_fresh(datetime.now(timezone.utc),maximum_seconds=900)
        channel=Channel(base,stdin,stdout,context['consume'])
        producer=TrustedPhaseStateProducerV3(socket_path=str(root/'docker.sock'),project=bundle.to_dict()['identity']['project'],
            daemon_id=binding['daemonId'],container_ids=tuple(sorted(row['Id'] for row in decode(capsule)['rawRows'].values())))
        store=ComposeRecoveryStore(root/'profile3-archive',key=keys['archive'])
        rows=TrustedPhaseStateProducerV3.reload(store,bundle,read_json=producer._get,
            daemon_version=context['normalizationVersion'],expected_docker_root=str(root/'data'))
        guard=PhaseGuardV3(bundle,rows,read_json=producer._get,daemon_version=context['normalizationVersion'],expected_docker_root=str(root/'data'))
        session=SimpleNamespace(root=root,project=bundle.to_dict()['identity']['project'],target=PrivateDaemon(root,info),
            guard=guard,producer=producer,created_ids=list(rows),unknown_write_result=False)
        prepared=dict(bundle=bundle,request=request)
        consume=context['consume']
        if type(consume) is not dict or set(consume)!={'requestHash','receiptHash','firstBinding'}:reject()
        tracker=FixtureOwnershipTrackerV3(project=session.project,daemon_id=binding['daemonId'],policy_hash=policy.identity_hash(),
            witness_pub_hash=hashlib.sha256(public).hexdigest(),epoch=consume['firstBinding']['epoch'],initial_confirmed_ids=list(rows),
            protected_ids=[item['containerId'] for item in bundle.to_dict()['protectedContainers']])
        tls=_tls(root,hello)
        original.preflight();_fresh(binding)
        history=original.create_cut(channel,session,prepared,policy,gate_key,public,status_public,tls,tracker,retained)
        snapshot=history.capture();value=decode(snapshot.canonical)
        if (value['pending'] is not None or value['blocker'] is not None or len(value['knownPrefix'])!=1
                or canonical(value['knownPrefix'])!=canonical(bundle.creation_operations()) or len(value['scopes'])!=1
                or value['scopes'][0]['seq']!=6 or value['chainStatus']['activePhase']!='closed'):reject()
        _fresh(binding)
        channel.emit('scene-create-closed',requestHash=request.digest(),bundleDigest=bundle.digest,
            historyDigest=snapshot.digest,receiptMap=value['receiptMap'],history=value,**{key:False for key in _FALSE})
    finally:
        primary=sys.exc_info()[1]
        executor=retained.get('executor')
        cleanup_error=None
        if executor is not None:
            try:executor.retry_owned_cleanup(time.monotonic()+5)
            except BaseException as error:cleanup_error=error
        if store is not None:
            try:store.close()
            except BaseException as error:
                if cleanup_error is None:cleanup_error=error
        if cleanup_error is not None:
            if primary is None:raise cleanup_error
            if hasattr(primary,'add_note'):primary.add_note('scene create local writer cleanup incomplete')
