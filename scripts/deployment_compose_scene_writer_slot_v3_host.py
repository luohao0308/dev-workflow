"""One pre-dispatch writer slot, held by its original live native issuer.

Reserve sends no archive/config/GO; inspect sends only fixed read-only archive
and attachment configuration. No business GO or product request is sent. Controller and
slot generations are separate; draining this slot is not a global writer fence.
Unknown creation/stop results block replacement, with original loader/service
lifetime bounds retained. Serialized origin records never recreate stop authority.
"""
import os
import re
import threading
import weakref

from deployment_compose_owned_recovery_unit_v3_host import OwnedRecoveryUnitV3
from deployment_compose_cold_writer_v3_host import observe_stopped_writer,validate_origin
from deployment_compose_witness_store import canonical
from deployment_compose_recovery_phase_capsule_v3_host import decode
import hashlib
import time
from deployment_compose_scene_attach_read_v3_host import AttachReadUnitV3,run_attached_read

_RECORDS=weakref.WeakKeyDictionary()
_FALSE=('authorityGranted','runtimePermit','recoveryAuthorized','productionReady','writerQuiescenceVerified',
        'sourceRevalidated','executionAvailable')


def reject():raise ValueError('compose-scene-writer-slot-v3-rejected') from None


def _construct_unit(source_sha,archive_digest):
    return OwnedRecoveryUnitV3(archive_digest,source_sha)


def _record(slot):
    value=_RECORDS.get(slot)
    if type(slot) is not SlotOwnerV3 or value is None or value['issuer']!=(os.getpid(),threading.get_ident()):reject()
    return value


def _generation(value):
    if type(value) is not int or not 0<=value<2**53:reject()


def _summary(record):
    return dict(slotGeneration=record['generation'],slotState=record['state'],
        writerSourceSha=record['source'],writerArchiveDigest=record['archive'],
        creationOutcomeUnknown=record['unknown'],writerOrigin=decode(record['origin']) if record['origin'] is not None else None,
        writerOriginDigest=hashlib.sha256(record['origin']).hexdigest() if record['origin'] is not None else None,
        slotRole=record['role'],closedReadReceipt=record['receipt'],slotStoppedObserved=record['state']=='drained',**{key:False for key in _FALSE})


class SlotOwnerV3:
    def __init__(self,source_sha,archive_digest):
        if (type(source_sha) is not str or re.fullmatch('[0-9a-f]{40}',source_sha) is None
                or type(archive_digest) is not str or re.fullmatch('[0-9a-f]{64}',archive_digest) is None):reject()
        _RECORDS[self]=dict(issuer=(os.getpid(),threading.get_ident()),source=source_sha,archive=archive_digest,
            generation=0,state='empty',owner=None,origin=None,unknown=False,result=None,role='waiting',receipt=None)

    def __copy__(self):reject()
    def __deepcopy__(self,memo):reject()
    def __reduce_ex__(self,protocol):reject()

    def status(self):return _summary(_record(self))

    def reserve(self,expected_slot_generation):
        record=_record(self);_generation(expected_slot_generation)
        if record['generation']!=expected_slot_generation or record['state'] not in ('empty','drained'):reject()
        record.update(generation=record['generation']+1,state='starting',unknown=True,owner=None,origin=None,result=None,role='waiting',receipt=None)
        try:
            owner=_construct_unit(record['source'],record['archive']);record['owner']=owner
            if type(owner) is not OwnedRecoveryUnitV3:reject()
            owner.start(timeout=15)
            origin=owner.capture_origin(timeout=5)
            parsed=validate_origin(origin)
            if parsed['sourceSha']!=record['source'] or parsed['archiveDigest']!=record['archive']:reject()
            record.update(state='waiting',unknown=False,origin=origin)
            return _summary(record)
        except BaseException:
            record['state']='failed'
            raise

    def reserve_create(self,expected_slot_generation):
        """Internal fixed first-create allocation; never imports JSON ownership."""
        record=_record(self);_generation(expected_slot_generation)
        if record['generation']!=expected_slot_generation or record['state'] not in ('empty','drained'):reject()
        record.update(generation=record['generation']+1,state='starting',unknown=True,owner=None,
            origin=None,result=None,role='scene-create',receipt=None)
        try:
            from deployment_compose_scene_create_worker_v3_host import SceneCreateUnitV3
            owner=SceneCreateUnitV3(record['archive'],record['source']);record['owner']=owner
            if type(owner) is not SceneCreateUnitV3:reject()
            owner.start(timeout=15)
            origin=owner.capture_origin(timeout=5);parsed=validate_origin(origin)
            if parsed['sourceSha']!=record['source'] or parsed['archiveDigest']!=record['archive']:reject()
            record.update(state='waiting',unknown=False,origin=origin)
            return _summary(record)
        except BaseException:
            record['state']='failed';raise

    def borrow_create_unit(self):
        record=_record(self)
        from deployment_compose_scene_create_worker_v3_host import SceneCreateUnitV3
        if record['role']!='scene-create' or record['state']!='waiting' or type(record['owner']) is not SceneCreateUnitV3:reject()
        return record['owner']

    def inspect_attached(self,raw_archive,daemon_binding,expected_slot_generation):
        record=_record(self);_generation(expected_slot_generation)
        if (record['generation']!=expected_slot_generation or record['state'] not in ('empty','drained')
                or type(raw_archive) is not bytes or not 0<len(raw_archive)<=2*1024*1024
                or hashlib.sha256(raw_archive).hexdigest()!=record['archive']):reject()
        record.update(generation=record['generation']+1,state='starting',unknown=True,
            owner=None,origin=None,result=None,role='attach-read',receipt=None)
        end=time.monotonic()+55
        def left():
            value=end-time.monotonic()
            if value<=0:reject()
            return value
        try:
            owner=AttachReadUnitV3(record['archive'],record['source']);record['owner']=owner
            if type(owner) is not AttachReadUnitV3:reject()
            owner.start(timeout=min(15,left()))
            origin=owner.capture_origin(timeout=min(5,left()));parsed=validate_origin(origin)
            if parsed['sourceSha']!=record['source'] or parsed['archiveDigest']!=record['archive']:reject()
            record.update(state='waiting',unknown=False,origin=origin)
            receipt=run_attached_read(owner,raw_archive,daemon_binding,source_sha=record['source'],
                archive_digest=record['archive'],timeout=min(15,left()))
            self._drain(record,end)
            record['receipt']=decode(canonical(receipt))
            result=_summary(record);result['stopObservationDigest']=decode(record['result'])['stopObservationDigest']
            record['result']=canonical(result)
            left()
            return result
        except BaseException:
            record['state']='failed'
            raise

    def drain(self,expected_slot_generation):
        record=_record(self);_generation(expected_slot_generation)
        if record['generation']!=expected_slot_generation:reject()
        if record['state']=='drained':return decode(record['result'])
        if record['state'] not in ('waiting','failed') or record['owner'] is None:reject()
        return self._drain(record)

    def _drain(self,record,deadline=None):
        def budget(limit):
            left=limit if deadline is None else min(limit,deadline-time.monotonic())
            if left<=0:reject()
            return left
        try:
            expected_type=AttachReadUnitV3 if record['role']=='attach-read' else OwnedRecoveryUnitV3
            if record['role']=='scene-create':
                from deployment_compose_scene_create_worker_v3_host import SceneCreateUnitV3
                expected_type=SceneCreateUnitV3
            if type(record['owner']) is not expected_type:reject()
            record['owner'].stop(timeout=budget(30))
            origin=record['origin']
            if origin is None:reject()  # Stop may clean the original issuer, but no proof can be minted.
            observed=observe_stopped_writer(origin,expected_digest=hashlib.sha256(origin).hexdigest(),
                expected_source_sha=record['source'],expected_archive_digest=record['archive'],timeout=budget(5))
            if observed.writerStoppedObserved is not True:reject()
            record['owner'].close()
            record.update(state='drained',unknown=False)
            result=_summary(record);result['stopObservationDigest']=observed.observation_digest
            record['result']=canonical(result)
            return decode(record['result'])
        except BaseException:
            record['state']='failed'
            raise
