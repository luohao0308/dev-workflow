"""Scene-held staging preparation and immutable private capsule transfer.

Fixture provisioning is not product dispatch or approval. Partial sessions are
retained before their first write, including through BaseException unwinding.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import sys
import threading
import time
import weakref

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests/support'))
from compose_profile3_prepare_fixture import PreparationSession,prepare_profile3
import deployment_compose_live_worker_v3_host as live
from deployment_compose_recovery_daemon_v3_host import ObservedRecoveryDaemonV3
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_operation_witness_client_v3 import encode,hex_value
from deployment_compose_restart_checkpoint_v3_host import directory,read_file,publish
from deployment_compose_witness_store import canonical

_RECORDS=weakref.WeakKeyDictionary()
_FALSE=('approvalReady','authorityGranted','runtimePermit','recoveryAuthorized','productionReady','executionAvailable')


def reject():raise ValueError('compose-scene-preparation-v3-rejected') from None


def digest(raw):return hashlib.sha256(raw).hexdigest()


def _record(owner):
    record=_RECORDS.get(owner)
    if type(owner) is not PreparationOwnerV3 or record is None or record['owner']!=(os.getpid(),threading.get_ident()):reject()
    return record


def _fresh(record,end=None):
    def budget(maximum):
        if end is None:return maximum
        remaining=min(maximum,end-time.monotonic())
        if remaining<=0:reject()
        return remaining
    held=record['observer'];held._root_same()
    if canonical(held.binding())!=record['binding']:reject()
    fresh=ObservedRecoveryDaemonV3(str(record['root']),record['daemon'],kernel_boot=decode(record['binding'])['kernelBoot'],timeout=budget(15))
    try:
        if canonical(fresh.binding())!=record['binding']:reject()
        info=fresh._request('/v1.45/info',time.monotonic()+budget(5),[8*1024*1024])
        if (type(info) is not dict or info.get('ID')!=record['daemon']
                or info.get('DockerRootDir')!=str(record['root']/'data')
                or canonical(fresh.binding())!=record['binding']):reject()
    finally:fresh.close()
    held._root_same()
    return info


class PreparationOwnerV3:
    def __init__(self,observer,source_sha,archive_digest):
        if (type(observer) is not ObservedRecoveryDaemonV3 or type(source_sha) is not str
                or re.fullmatch('[0-9a-f]{40}',source_sha) is None or not hex_value(archive_digest)):reject()
        binding=canonical(observer.binding())
        _RECORDS[self]=dict(owner=(os.getpid(),threading.get_ident()),observer=observer,binding=binding,
            root=Path(observer.root),daemon=observer.daemon_id,source=source_sha,archive=archive_digest,
            state='new',identity=None,tls=None,session=None,raw=None,metadata=None,fileIdentity=None,host=None,keys=None,product_pending=False)

    def __copy__(self):reject()
    def __deepcopy__(self,memo):reject()
    def __reduce_ex__(self,protocol):reject()

    def status(self):
        record=_record(self)
        return dict(preparationState=record['state'],capsule=decode(canonical(record['metadata'])),
            preparationIdentity=decode(record['identity']) if record['identity'] is not None else None,
            **{key:False for key in _FALSE})

    def identity(self,host_id):
        record=_record(self)
        if record['identity'] is not None and record['state'] in ('identity','preparing','prepared'):
            if host_id!=record['host']:reject()
            return decode(record['identity'])
        if record['state']!='new' or type(host_id) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',host_id) is None:reject()
        record['state']='identity-starting'
        try:
            _fresh(record)
            tls=live.writer_tls(record['root']);record['tls']=tls
            hello=dict(root=str(record['root']),daemonId=record['daemon'],serverCertificateSha256=tls[2],
                writerCertificateSha256=tls[3],sourceSha=record['source'],archiveDigest=record['archive'],hostId=host_id)
            _fresh(record)
            record.update(state='identity',identity=canonical(hello),host=host_id)
            return decode(record['identity'])
        except BaseException:
            record['state']='failed';raise

    def prepare(self,policy_hash,keys):
        record=_record(self)
        if (record['state']!='identity' or not hex_value(policy_hash) or type(keys) is not dict
                or set(keys)!={'config','image','declaration','archive','target'}
                or any(type(value) is not bytes or len(value)!=32 for value in keys.values())):reject()
        record['state']='preparing';frozen_keys=dict(keys);record['keys']=frozen_keys
        try:
            actual_info=_fresh(record)
            def created(session):
                if record['session'] is not None or type(session) is not PreparationSession:reject()
                # Take custody before any later check can raise.
                record['session']=session
                if (session.target.socket!=str(record['root']/'docker.sock')
                        or session.target.daemon_id!=record['daemon']):reject()
            session=prepare_profile3(record['root'],actual_info,source_sha=record['source'],
                host_id=record['host'],expected_daemon_id=record['daemon'],keys=frozen_keys,policy_hash=policy_hash,
                environment='staging',expiry_seconds=900,on_session_created=created)
            if session is not record['session']:reject()
            raw=encode(live.private_json(live.private_capsule(session,session.prepared)))
            if not 0<len(raw)<=4*1024*1024:reject()
            facts=[]
            class Capture:
                config={'sourceSha':record['source'],'archiveDigest':record['archive']}
                def emit(self,kind,**value):
                    if kind!='observer-facts' or facts:reject()
                    facts.append(decode(canonical(value)))
            live.emit_observer_facts(Capture(),session,session.prepared,record['root'])
            if len(facts)!=1:reject()
            _fresh(record)
            path=record['root']/'scene-preparation';path.mkdir(mode=0o700)
            fd,identity=directory(path)
            try:
                publish(fd,'capsule.private.json',raw)
                stored,file_id=read_file(fd,'capsule.private.json',4*1024*1024)
                if stored!=raw:reject()
            finally:os.close(fd)
            meta=dict(preparationId=__import__('secrets').token_hex(32),capsuleDigest=digest(raw),totalBytes=len(raw),
                requestDigest=session.prepared['request'].digest(),expiresAt=session.prepared['request'].expires_at,
                observerFacts=facts[0],**{key:False for key in _FALSE})
            record.update(state='prepared',raw=raw,metadata=meta,fileIdentity=(identity,file_id))
            return decode(canonical(meta))
        except BaseException:
            record['state']='failed';raise

    def chunk(self,preparation_id,capsule_digest,offset,length):
        record=_record(self);meta=record['metadata']
        if (record['state']!='prepared' or meta is None or preparation_id!=meta['preparationId'] or capsule_digest!=meta['capsuleDigest']
                or type(offset) is not int or type(length) is not int or offset<0 or not 0<length<=4096
                or offset>=meta['totalBytes']):reject()
        fd,identity=directory(record['root']/'scene-preparation')
        try:
            raw,file_id=read_file(fd,'capsule.private.json',4*1024*1024)
            if (identity,file_id)!=record['fileIdentity'] or raw!=record['raw'] or digest(raw)!=capsule_digest:reject()
        finally:os.close(fd)
        return dict(preparationId=preparation_id,capsuleDigest=capsule_digest,totalBytes=len(raw),offset=offset,
            dataBase64=base64.b64encode(raw[offset:offset+length]).decode('ascii'),**{key:False for key in _FALSE})

    def business_inputs(self):
        """Borrow native private inputs inside the owning service thread only."""
        record=_record(self)
        if record['state']!='prepared' or record['raw'] is None or record['session'] is None:reject()
        self.chunk(record['metadata']['preparationId'],record['metadata']['capsuleDigest'],0,1)
        _fresh(record)
        return dict(session=record['session'],capsule=record['raw'],tls=record['tls'],
            hello=decode(record['identity']),daemonBinding=decode(record['binding']),keys=dict(record['keys']),metadata=decode(canonical(record['metadata'])))

    def mark_product_pending(self):
        record=_record(self)
        if record['state']!='prepared' or record['product_pending'] or record['session'].unknown_write_result:reject()
        record['product_pending']=True
        record['session'].unknown_write_result=True

    def _reconcile_closed_create(self,receipts):
        # Only the fixed broker calls this after its pinned closure verifier.
        record=_record(self);session=record['session']
        if not record['product_pending'] or not session.unknown_write_result or type(receipts) is not dict:reject()
        bundle=session.prepared['bundle'];creates=bundle.creation_operations()
        if len(creates)!=1 or set(receipts)!={creates[0]['service']}:reject()
        cid=receipts[creates[0]['service']]
        if (not hex_value(cid) or cid in session.created_ids or cid in session.guard._base
                or cid in session.guard._protected):reject()
        operations=bundle.resolve_operations(receipts)
        if len(operations)<2:reject()
        _fresh(record)
        session.guard.capture_phase(dict(phase_index=1,operation=operations[1],receipts=dict(receipts),
            completed_operations=operations[:1]))
        _fresh(record)
        session.created_ids.append(cid)
        session.unknown_write_result=False

    def _observe_closed_create_phase(self,receipts,end):
        """Only original prepared inputs select the GET-only phase subject."""
        record=_record(self);session=record['session']
        if (record['state']!='prepared' or session is None or not record['product_pending']
                or session.unknown_write_result or type(receipts) is not dict):reject()
        bundle=session.prepared['bundle'];creates=bundle.creation_operations()
        if len(creates)!=1 or set(receipts)!={creates[0]['service']}:reject()
        cid=receipts[creates[0]['service']]
        if not hex_value(cid) or cid not in session.created_ids:reject()
        operations=bundle.resolve_operations(receipts)
        if len(operations)<2:reject()
        context=dict(phase_index=1,operation=operations[1],receipts=dict(receipts),completed_operations=operations[:1])
        _fresh(record,end)
        remaining=end-time.monotonic()
        if remaining<=0:reject()
        phase,endpoint=ObservedRecoveryDaemonV3.capture_recovery_phase(record['observer'],bundle,
            session.guard._base,context,expected_version=session.guard._version,timeout=min(30,remaining))
        if canonical(record['observer'].binding())!=record['binding'] or time.monotonic()>=end:reject()
        return phase,endpoint,canonical(session.guard._version),bundle.to_dict()['baselineStateDigest']

    def _reconcile_closed_scene_delete(self, receipts, *, terminal_digest=None):
        """Release the deleted baseline from cleanup after observing its absence."""
        record = _record(self)
        session = record['session']
        if (record['state'] != 'prepared' or not record['product_pending'] or session is None
                or not session.unknown_write_result):
            reject()
        bundle = session.prepared['bundle']
        operations = bundle.resolve_operations(receipts)
        if operations[2]['phase'] != 'delete' or operations[3]['phase'] != 'rename':
            reject()
        _fresh(record)
        if terminal_digest is None:
            session.guard.capture_phase(dict(phase_index=3, operation=operations[3], receipts=receipts,
                                             completed_operations=operations[:3]))
        else:
            from deployment_compose_phase_guard_v3_host import _plain

            phase = session.guard.capture_phase(dict(phase_index=sum(op['method'] != 'GET' for op in operations),
                                                      operation=None, receipts=receipts,
                                                      completed_operations=operations), terminal=True)
            if digest(canonical(_plain(phase))) != terminal_digest:
                reject()
        _fresh(record)
        service = bundle.to_dict()['services'][0]
        deleted = service['baselineContainerId']
        if deleted in session.created_ids:
            session.created_ids.remove(deleted)
        session.unknown_write_result = False

    def cleanup(self):
        record=_record(self)
        if record['state']=='cleaned':return dict(preparationCleaned=True,**{key:False for key in _FALSE})
        try:
            if record['session'] is not None:
                if not record['session'].unknown_write_result:_fresh(record)
                record['session'].cleanup()
            record['state']='cleaned'
            return dict(preparationCleaned=True,**{key:False for key in _FALSE})
        except BaseException:
            record['state']='failed';raise
