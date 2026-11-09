"""Current managed-writer identity bound to a cold checkpoint, without stop authority.

Writer source fields are trusted loader configuration and remain unattested.
A stopped original writer observation supplements the host's global fence.
"""
import hashlib
import os
import re
import secrets
import threading
import weakref

import deployment_compose_isolated_daemon_probe as probe
import deployment_compose_owned_recovery_unit_v3_host as units
import deployment_compose_cold_writer_v3_host as cold
from deployment_compose_writer_cgroup_v3_host import events
from deployment_compose_bounded_restart_material_v3_host import capture_material, reopen_material
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_restart_material_v3_host import _context
from deployment_compose_recovery_phase_capsule_v3_host import decode
from deployment_compose_witness_store import canonical, hex_value

_LIFECYCLES = weakref.WeakKeyDictionary()
_REGISTRATIONS = weakref.WeakKeyDictionary()
_HOST_REGISTRATIONS = weakref.WeakKeyDictionary()
_OBSERVERS = weakref.WeakKeyDictionary()
_FLAGS = dict(authorityGranted=False, runtimePermit=False, recoveryAuthorized=False,
              linuxQuiescenceVerified=False, sourceRevalidated=False, productionReady=False)
_DESCRIPTOR = {'schemaVersion','kind','recordReference','recordDigest','materialReference','materialDigest',
               'context','originDigest','writerSourceSha','writerArchiveDigest'}
_RECORD = {'schemaVersion','kind','nonce','materialReference','materialDigest','context','origin','originDigest',
           'writerSourceSha','writerArchiveDigest','requestHash','bundleDigest','receiptHash','firstBinding',
           'witnessKeyHash','policyHash','closedTail','writeIndex'} | set(_FLAGS)


def reject():
    raise ValueError('compose-native-writer-lifecycle-v3-rejected') from None


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _store_seal(store):
    if type(store) is not ComposeRecoveryStore:
        reject()
    return id(store), store._root, store._fd, store._identity, digest(store._key)


def _capture_current_origin(source_sha, archive_digest):
    units._environment()
    boot = units._boot()
    namespace = cold.pid_namespace()
    unit, state = probe._owned_writer_binding()
    pid = os.getpid()
    group = '/system.slice/'+unit
    identity = units._pid_identity(str(pid), group)
    if identity != (pid, int(state['StartTime'])) or cold.process_pid_namespace(pid) != namespace:
        reject()
    root = os.open(units.CGROUP, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        parent = os.open('system.slice', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=root)
    finally:
        os.close(root)
    try:
        child = os.open(unit, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=parent)
        try:
            parent_id = os.fstat(parent)
            child_id = os.fstat(child)
            def read(name):
                fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=child)
                try:
                    raw = os.read(fd, 65537)
                    if len(raw)>65536:
                        reject()
                    return raw.decode('ascii')
                finally:
                    os.close(fd)
            if read('cgroup.type').strip() != 'domain' or events(read('cgroup.events'))['populated'] != 1:
                reject()
            raw = canonical(dict(schemaVersion=1, kind='compose-owned-writer-origin-v3',
                sourceSha=source_sha, archiveDigest=archive_digest, unit=unit, kernelBoot=boot,
                invocationId=state['InvocationID'], mainPid=pid, mainStartTicks=identity[1],
                cgroupDevice=child_id.st_dev, cgroupInode=child_id.st_ino,
                parentDevice=parent_id.st_dev, parentInode=parent_id.st_ino,
                pidNamespaceDevice=namespace[0], pidNamespaceInode=namespace[1]))
            cold.validate_origin(raw)
            current = os.stat(unit, dir_fd=parent, follow_symlinks=False)
            current_parent = os.stat(units.CGROUP/'system.slice', follow_symlinks=False)
            if ((current.st_dev,current.st_ino)!=(child_id.st_dev,child_id.st_ino)
                    or (current_parent.st_dev,current_parent.st_ino)!=(parent_id.st_dev,parent_id.st_ino)
                    or probe._owned_writer_binding()!=(unit,state)
                    or units._pid_identity(str(pid),group)!=identity or units._boot()!=boot
                    or cold.pid_namespace()!=namespace or cold.process_pid_namespace(pid)!=namespace
                    or read('cgroup.type').strip()!='domain' or events(read('cgroup.events'))['populated']!=1):
                reject()
            return raw
        finally:
            os.close(child)
    finally:
        os.close(parent)


class NativeWriterRegistrationV3:
    __slots__ = ('__weakref__',)


class NativeWriterLifecycleV3:
    __slots__ = ('_source','_archive','_store','_owner','__weakref__')

    def __init__(self, *, writer_source_sha, writer_archive_digest, store):
        if (type(writer_source_sha) is not str or re.fullmatch('[a-f0-9]{40}',writer_source_sha) is None
                or not hex_value(writer_archive_digest)):
            reject()
        self._source, self._archive, self._store = writer_source_sha, writer_archive_digest, store
        self._owner = (os.getpid(),threading.get_ident())
        _LIFECYCLES[self] = self._owner, writer_source_sha, writer_archive_digest, _store_seal(store)

    def _sealed_config(self):
        seal = _LIFECYCLES.get(self)
        if (type(self) is not NativeWriterLifecycleV3 or seal is None
                or seal != (self._owner,self._source,self._archive,_store_seal(self._store))
                or self._owner[0] != os.getpid()):
            reject()
        return seal

    def _owned(self):
        seal = NativeWriterLifecycleV3._sealed_config(self)
        if self._owner != (os.getpid(),threading.get_ident()):
            reject()
        return seal

    def preflight(self, host):
        from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
        NativeWriterLifecycleV3._owned(self)
        ColdRecoveryHostV3._owned(host)
        ColdRecoveryHostV3._check_prepared(host)
        if host._native_lifecycle is not self:
            reject()
        _capture_current_origin(self._source,self._archive)
        NativeWriterLifecycleV3._owned(self)
        ColdRecoveryHostV3._check_prepared(host)
        return dict(writerAvailable=True,**_FLAGS)

    def begin(self, host):
        from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
        NativeWriterLifecycleV3._owned(self)
        frame = ColdRecoveryHostV3._native_frame(host)
        if (frame['lifecycle'] is not self or frame['finished'] or host in _HOST_REGISTRATIONS):
            reject()
        origin = _capture_current_origin(self._source,self._archive)
        record = NativeWriterRegistrationV3()
        _REGISTRATIONS[record] = dict(lifecycle=weakref.ref(self), host=weakref.ref(host),
            owner=self._owner, frame_nonce=frame['nonce'],request=frame['request_bytes'],receipt=frame['receipt_hash'],
            binding=frame['binding'],origin=origin,child=None,finished=False,published=False)
        _HOST_REGISTRATIONS[host] = record
        NativeWriterLifecycleV3._owned(self)
        ColdRecoveryHostV3._native_frame(host)
        return record

    def attach(self, registration, host):
        from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
        record = NativeWriterLifecycleV3._record(self,registration,host)
        frame = ColdRecoveryHostV3._native_frame(host)
        child = frame['child']
        if (record['finished'] or record['child'] is not None or child is None
                or child._request.canonical_json()!=record['request'] or child._receipt!=record['receipt']
                or canonical(child._client.binding)!=record['binding']
                or child._parent is not host._reader.history
                or child._reviewed_parent is not host._candidate['reviewed_history']):
            reject()
        if _capture_current_origin(self._source,self._archive)!=record['origin']:
            reject()
        record['child'] = child

    def finish(self, registration, host):
        record = NativeWriterLifecycleV3._record(self,registration,host)
        from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
        if not ColdRecoveryHostV3._native_frame(host)['finished']:
            reject()
        record['finished'] = True

    def _record(self, registration, host):
        from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
        NativeWriterLifecycleV3._owned(self)
        ColdRecoveryHostV3._owned(host)
        frame = ColdRecoveryHostV3._native_frame(host)
        record = _REGISTRATIONS.get(registration)
        if (type(registration) is not NativeWriterRegistrationV3 or record is None
                or record['lifecycle']() is not self or record['host']() is not host
                or record['owner']!=(os.getpid(),threading.get_ident())
                or _HOST_REGISTRATIONS.get(host) is not registration or record['frame_nonce']!=frame['nonce']
                or record['request']!=frame['request_bytes'] or record['receipt']!=frame['receipt_hash']
                or record['binding']!=frame['binding']):
            reject()
        return record

    def capture_checkpoint(self, registration, host, *, baseline_bytes_by_bundle,
                           authenticated_image_defaults_by_bundle, archive_digest):
        from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
        record = NativeWriterLifecycleV3._record(self,registration,host)
        frame = ColdRecoveryHostV3._native_frame(host)
        if (not frame['finished'] or frame['child'] is not record['child'] or not record['finished'] or record['published'] or record['child'] is None
                or host._native_executing or host._state!='spent' or host._child_history is not record['child']):
            reject()
        record['published'] = True
        origin = _capture_current_origin(self._source,self._archive)
        if origin!=record['origin']:
            reject()
        child = record['child']
        fingerprint = child._ancestry_fingerprint()
        snapshot = child.capture()
        raw = capture_material(child, baseline_bytes_by_bundle=baseline_bytes_by_bundle,
            authenticated_image_defaults_by_bundle=authenticated_image_defaults_by_bundle, archive_digest=archive_digest)
        context = _context(child,snapshot,archive_digest)
        material_reference = self._store.put(raw)
        if self._store.get(material_reference)!=raw:
            reject()
        value = dict(schemaVersion=1,kind='compose-native-writer-checkpoint-v3',nonce=secrets.token_hex(32),
            materialReference=material_reference,materialDigest=digest(raw),context=context,
            origin=decode(origin),originDigest=digest(origin),writerSourceSha=self._source,writerArchiveDigest=self._archive,
            requestHash=child._request.digest(),bundleDigest=child._bundle.digest,receiptHash=child._receipt,
            firstBinding=child._client.binding,witnessKeyHash=child._client.key_hash,policyHash=child._policy.identity_hash(),
            closedTail=decode(snapshot.canonical)['closedTail'],writeIndex=len(snapshot.snapshot['knownPrefix']),**_FLAGS)
        payload = canonical(value)
        reference = self._store.put(payload)
        if (self._store.get(reference)!=payload or child.capture().canonical!=snapshot.canonical
                or child._ancestry_fingerprint()!=fingerprint or _capture_current_origin(self._source,self._archive)!=origin):
            reject()
        self._record(registration,host)
        return dict(schemaVersion=1,kind='compose-native-writer-checkpoint-descriptor-v3',recordReference=reference,
            recordDigest=digest(payload),materialReference=material_reference,materialDigest=digest(raw),context=decode(canonical(context)),
            originDigest=digest(origin),writerSourceSha=self._source,writerArchiveDigest=self._archive)


class NativeCheckpointStopObserver:
    __slots__ = ('__weakref__',)

    def __init__(self):
        reject()

    def _sealed(self):
        state = _OBSERVERS.get(self)
        if (type(self) is not NativeCheckpointStopObserver or state is None
                or state['owner'][0]!=os.getpid() or _store_seal(state['store'])!=state['store_seal']):
            reject()
        return state['owner'], state['store_seal'], canonical(state['record']), state['origin'], state['snapshot']

    def _owned(self):
        NativeCheckpointStopObserver._sealed(self)
        if _OBSERVERS[self]['owner']!=(os.getpid(),threading.get_ident()):
            reject()

    def observe_for(self, host):
        from deployment_compose_cold_recovery_v3_host import ColdRecoveryHostV3
        NativeCheckpointStopObserver._owned(self)
        state = _OBSERVERS.get(self)
        if (type(self) is not NativeCheckpointStopObserver or state is None
                or state['owner']!=(os.getpid(),threading.get_ident()) or _store_seal(state['store'])!=state['store_seal']
                or type(host) is not ColdRecoveryHostV3):
            reject()
        ColdRecoveryHostV3._owned(host)
        history = host._reader.history
        record = state['record']
        if (host._reader.material_digest!=record['materialDigest'] or history._request.digest()!=record['requestHash']
                or history._bundle.digest!=record['bundleDigest'] or history._receipt!=record['receiptHash']
                or history._client.binding!=record['firstBinding'] or history._client.key_hash!=record['witnessKeyHash']
                or history._policy.identity_hash()!=record['policyHash']
                or _context(history,host._reader.snapshot,record['context']['archiveDigest'])!=record['context']
                or history.capture().canonical!=state['snapshot']):
            reject()
        result = cold.observe_stopped_writer(state['origin'],expected_digest=record['originDigest'],
            expected_source_sha=record['writerSourceSha'],expected_archive_digest=record['writerArchiveDigest'])
        if (type(result) is not cold.StoppedWriterObservationV3 or result.origin_digest!=record['originDigest']
                or result.writerStoppedObserved is not True or not hex_value(result.observation_digest)
                or any(getattr(result,key,None) is not False for key in ('daemonStoppedVerified','historyFreshnessVerified',
                    'linuxQuiescenceVerified','authorityGranted','runtimePermit','recoveryAuthorized','productionReady'))
                or history.capture().canonical!=state['snapshot']):
            reject()
        return result


def load_native_checkpoint(descriptor, *, store, gate_key, pub, readonly_transport):
    if type(descriptor) is not dict or set(descriptor)!=_DESCRIPTOR:
        reject()
    pins = decode(canonical(descriptor))
    if (type(pins['schemaVersion']) is not int or pins['schemaVersion']!=1
            or pins['kind']!='compose-native-writer-checkpoint-descriptor-v3'
            or any(not hex_value(pins[key]) for key in ('recordReference','recordDigest','materialReference','materialDigest','originDigest','writerArchiveDigest'))):
        reject()
    seal = _store_seal(store)
    raw_record = store.get(pins['recordReference'])
    if digest(raw_record)!=pins['recordDigest']:
        reject()
    record = decode(raw_record)
    if (type(record) is not dict or set(record)!=_RECORD or type(record['schemaVersion']) is not int
            or record['schemaVersion']!=1 or record['kind']!='compose-native-writer-checkpoint-v3'
            or not hex_value(record['nonce']) or any(record[key] is not False for key in _FLAGS)
            or any(record[key]!=pins[key] for key in ('materialReference','materialDigest','context','originDigest','writerSourceSha','writerArchiveDigest'))):
        reject()
    origin = canonical(record['origin'])
    native = cold.validate_origin(origin)
    if (digest(origin)!=record['originDigest'] or native['sourceSha']!=record['writerSourceSha']
            or native['archiveDigest']!=record['writerArchiveDigest']):
        reject()
    raw = store.get(record['materialReference'])
    context = reopen_material(raw,expected_digest=record['materialDigest'],expected_context=record['context'],
                              gate_key=gate_key,witness_public_key=pub,witness_transport=readonly_transport)
    snapshot = context.history.capture()
    child = context.history
    value = decode(snapshot.canonical)
    if (child._request.digest()!=record['requestHash'] or child._bundle.digest!=record['bundleDigest']
            or child._receipt!=record['receiptHash'] or child._client.binding!=record['firstBinding']
            or child._client.key_hash!=record['witnessKeyHash'] or child._policy.identity_hash()!=record['policyHash']
            or value['closedTail']!=record['closedTail'] or type(record['writeIndex']) is not int
            or len(value['knownPrefix'])!=record['writeIndex'] or _store_seal(store)!=seal
            or canonical(descriptor)!=canonical(pins)):
        reject()
    result = object.__new__(NativeCheckpointStopObserver)
    _OBSERVERS[result] = dict(owner=(os.getpid(),threading.get_ident()),store=store,store_seal=seal,
                              record=record,origin=origin,snapshot=snapshot.canonical)
    return result
