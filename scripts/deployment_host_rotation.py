"""Offline, gate-first rotation of a healthy trusted host. No deployment IO."""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import deployment_host_maintenance as maintenance
import deployment_history_archive as archive
import deployment_store as store
import deployment_gateway as gateway
import deployment_recover as recovery
import deployment_maintenance_state as state
from workflow_lock import pending_upgrades

Error = maintenance.MaintenanceError
INTENT = 'rotation-intent.json'
PREPARED = 'rotation-prepared.json'
IMPORT = 'maintenance-import-manifest.json'
DOMAIN = b'deployment-host-rotation-v1\0'
MAX_INTENT = 72 * 1024 * 1024


def _require(value, code):
    if not value:
        raise Error(code)


def _raw(value):
    return store.runtime.canonical(value).encode('ascii')


def _digest(value):
    return hashlib.sha256(_raw(value)).hexdigest()


def _identity(host):
    c = host.config
    return dict(storePolicy=c.store_policy.identity_hash(), gatePolicy=c.gate_policy.identity_hash(),
        runtimePolicy=c.runtime_policy.identity_hash(), executionPolicy=c.execution_policy.identity_hash(),
        storeRoot=str(c.store_root), gateRoot=str(c.gate_root), candidateRoot=str(c.candidate_root),
        storeKey=hashlib.sha256(host.store_key).hexdigest(), gateKey=hashlib.sha256(host.gate_key).hexdigest())


def _binding_id(binding):
    return dict(root=str(binding.root), rootIdentity=list(binding.root_identity),
                mutexIdentity=list(binding.mutex_identity), policy=binding.policy_hash, kind=binding.kind)


def _bindings(host):
    c = host.config
    return (state._binding(c.store_root, c.store_policy.identity_hash(), host.store_key, 'store'),
            state._binding(c.gate_root, c.gate_policy.identity_hash(), host.gate_key, 'gate'))


def _boundary(source, destination):
    _require(type(source) is maintenance.MaintenanceHost and type(destination) is maintenance.MaintenanceHost,
             'typed-maintenance-host-required')
    _require(all(type(h.gate_key) is bytes and len(h.gate_key) >= 32 for h in (source, destination)),
             'rotation-gate-key-required')
    a, b = source.config, destination.config
    for host in (source, destination):
        c = host.config
        _require(c.store_policy.runtime_policy == c.runtime_policy
                 and c.execution_policy.runtime_policy == c.runtime_policy
                 and c.gate_policy.store_id == c.store_policy.store_id
                 and c.gate_policy.key_id == c.store_policy.key_id
                 and c.gate_policy.scope_hash == _digest(c.store_policy._scope())
                 and c.execution_policy.history_policy_hash == c.store_policy.identity_hash()
                 and c.execution_policy.gateway_policy_hash == c.gate_policy.identity_hash()
                 and c.execution_policy.writer_certificate_sha256 == c.gate_policy.writer_certificate_sha256,
                 'rotation-policy-bindings-mismatch')
    _require(a.candidate_root == b.candidate_root and a.runtime_policy.identity_hash() == b.runtime_policy.identity_hash()
             and a.store_policy._scope() == b.store_policy._scope(), 'rotation-scope-changed')
    _require(a.store_policy.store_id != b.store_policy.store_id and a.store_policy.key_id != b.store_policy.key_id,
             'rotation-new-identities-required')
    _require(all(not hmac.compare_digest(new, old) for new in (destination.store_key, destination.gate_key)
                 for old in (source.store_key, source.gate_key)), 'rotation-new-key-material-required')
    roots = [a.store_root, a.gate_root, b.store_root, b.gate_root, a.candidate_root,
             Path(__file__).resolve().parents[1]]
    for i, path in enumerate(roots):
        _require(isinstance(path, Path) and path.is_absolute(), 'rotation-absolute-root-required')
        state._ancestors(path)
        for other in roots[i + 1:]:
            _require(path != other and path not in other.parents and other not in path.parents,
                     'rotation-root-overlap')
    candidate_info = a.candidate_root.lstat()
    _require(stat.S_ISDIR(candidate_info.st_mode) and not getattr(candidate_info, 'st_file_attributes', 0) & 0x400,
             'rotation-candidate-root-invalid')
    _require(a.gate_policy.writer_certificate_sha256 == b.gate_policy.writer_certificate_sha256,
             'rotation-is-not-transport-migration')


def _seal(host, payload):
    return _raw(dict(payload=payload, signature=hmac.new(host.store_key, DOMAIN + _raw(payload), hashlib.sha256).hexdigest()))


def _read_signed(host, name):
    raw = state._bytes(host.config.store_root / name, MAX_INTENT)
    try:
        value = store.runtime.parse_json(raw.decode('ascii'))
        _require(type(value) is dict and set(value) == {'payload', 'signature'} and raw == _raw(value),
                 'rotation-record-invalid')
        _require(type(value['signature']) is str and hmac.compare_digest(value['signature'],
                 hmac.new(host.store_key, DOMAIN + _raw(value['payload']), hashlib.sha256).hexdigest()),
                 'rotation-record-invalid')
        return value['payload']
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise Error('rotation-record-invalid') from None


def _write_signed(host, name, payload):
    maintenance._write_new(host.config.store_root, name, _seal(host, payload))


def _core_idle(host):
    root = host.config.candidate_root
    _require(not pending_upgrades(root) and recovery.HostCoordinator._owner(root) is None,
             'rotation-core-operation-unresolved')


def _snapshot(host):
    """Exact immutable source inventory; maintenance metadata never hides history."""
    result = {}
    for kind, root in (('store', host.config.store_root), ('gate', host.config.gate_root)):
        with state._directory(root) as directory:
            names = sorted(os.listdir(directory if directory is not None else root))
        for name in names:
            if name in ({'history.lock', 'target.lock', 'maintenance.json', INTENT, PREPARED} if kind == 'store'
                        else {'mutex', 'maintenance.json'}):
                continue
            path = root / name
            if kind == 'store':
                _require(store._REF.fullmatch(name) or re.fullmatch(r'journal-[0-9a-f]{64}-[0-9]{8}\.json', name)
                         or name == IMPORT, 'rotation-unknown-source-entry')
                children = [(name, path)]
            elif name == 'policy.json':
                children = [(name, path)]
            else:
                _require(re.fullmatch(r'[0-9a-f]{64}', name), 'rotation-unknown-gate-entry')
                identity = state._identity(path, True)
                result[kind + '/' + name + '/'] = dict(identity=list(identity), directory=True)
                with state._directory(path) as fd:
                    entries = sorted(os.listdir(fd if fd is not None else path))
                _require(all(re.fullmatch(r'[0-9]{8}\.json|admitted-[0-9a-f]{64}', n) for n in entries),
                         'rotation-unknown-generation-entry')
                children = [(name + '/' + n, path / n) for n in entries]
            for relative, child in children:
                identity = state._identity(child)
                raw = state._bytes(child, archive.MAX_RECORD)
                _require(state._identity(child) == identity, 'rotation-source-file-replaced')
                result[kind + '/' + relative] = dict(identity=list(identity), size=len(raw),
                                                      sha256=hashlib.sha256(raw).hexdigest())
    _require(len(result) <= 16384, 'rotation-source-too-large')
    return result


def _healthy(host, backend, gate):
    """Authenticate terminal journals and the original inode-bound gate in place."""
    _core_idle(host)
    c = host.config
    expected_coordinator = _digest(dict(domain='deployment-host-coordinator-v1', store=c.store_policy.identity_hash(),
        gate=c.gate_policy.identity_hash(), runtime=c.runtime_policy.identity_hash(), execution=c.execution_policy.identity_hash()))
    with backend._directory() as fd:
        names = sorted(os.listdir(fd if fd is not None else backend.root))
        if IMPORT in names:
            raw = state._bytes(backend.root / IMPORT, archive.MAX_ARCHIVE)
            value = store.runtime.parse_json(raw.decode('ascii'))
            _require(type(value) is dict and set(value) == {'manifest', 'signature'} and raw == _raw(value),
                     'rotation-import-manifest-invalid')
            manifest = value['manifest']
            _require(type(manifest) is dict and set(manifest) == {'schemaVersion', 'kind', 'archiveHash',
                'destinationPolicy', 'importedAt', 'records'} and type(manifest['schemaVersion']) is int
                and manifest['schemaVersion'] == 1 and manifest['kind'] == 'history-only-import'
                and manifest['destinationPolicy'] == c.store_policy.identity_hash()
                and type(manifest['archiveHash']) is str and store.runtime.HEX.fullmatch(manifest['archiveHash'])
                and type(manifest['records']) is dict and type(value['signature']) is str
                and hmac.compare_digest(value['signature'], hmac.new(host.store_key,
                    b'deployment-history-import-v1\0' + _raw(manifest), hashlib.sha256).hexdigest()),
                'rotation-import-manifest-invalid')
            store._utc(manifest['importedAt'])
            for name, digest in manifest['records'].items():
                _require(type(name) is str and store._REF.fullmatch(name) and type(digest) is str
                         and store.runtime.HEX.fullmatch(digest)
                         and hashlib.sha256(state._bytes(backend.root / name, archive.MAX_RECORD)).hexdigest() == digest,
                         'rotation-import-manifest-invalid')
        groups = {}
        for name in names:
            if name.startswith('journal-'):
                match = re.fullmatch(r'journal-([0-9a-f]{64})-([0-9]{8})\.json', name)
                _require(match is not None, 'rotation-unknown-journal-entry')
                groups.setdefault(match[1], []).append(name)
        for oid, entries in groups.items():
            previous, last = recovery.ZERO, None
            for index, name in enumerate(entries):
                _require(name == 'journal-' + oid + '-' + format(index, '08d') + '.json', 'rotation-journal-gap')
                raw = state._bytes(backend.root / name, recovery.MAX_RECORD)
                envelope = store.runtime.parse_json(raw.decode('ascii'))
                payload = envelope['payload']
                signature = hmac.new(host.store_key, recovery.DOMAIN + _raw(payload), hashlib.sha256).hexdigest()
                _require(set(envelope) == {'payload', 'signature'} and raw == _raw(envelope)
                         and type(envelope['signature']) is str and hmac.compare_digest(envelope['signature'], signature)
                         and payload['operationId'] == oid and payload['sequence'] == index
                         and payload['previous'] == previous and payload['store'] == c.store_policy.identity_hash(),
                         'rotation-journal-invalid')
                if index == 0:
                    _require(payload['kind'] == 'begin' and payload['data']['root'] == str(c.candidate_root)
                             and payload['data']['coordinatorHash'] == expected_coordinator, 'rotation-journal-scope')
                previous, last = _digest(envelope), payload
            _require(last is not None and last['kind'] == 'terminal', 'rotation-unresolved-journal')
    for name in os.listdir(gate.root):
        if re.fullmatch(r'[0-9a-f]{64}', name):
            checked = gate._state(name)
            _require(checked['closed'] and checked['proof'] is not None
                     and all(x['status'] == 'done' for x in checked['admissions'].values()), 'rotation-writer-not-drained')
    histories = {name: state._bytes(backend.root / name, archive.MAX_RECORD) for name in names if store._REF.fullmatch(name)}
    return archive.build_archive(c.store_policy, histories, host.store_key, created_at=maintenance._now())


@contextmanager
def _target_lock(host, expected):
    root = host.config.store_root
    with state._directory(root) as directory:
        fd = state._open_at(root, directory, 'target.lock', os.O_RDWR)
        locked = False
        try:
            info = os.fstat(fd)
            _require([info.st_dev, info.st_ino] == expected, 'rotation-target-lock-changed')
            if os.name == 'posix':
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                import errno, msvcrt, time
                while True:
                    try:
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as error:
                        if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                            raise
                        time.sleep(0.05)
            locked = True
            _require(list(state._identity(root / 'target.lock')) == expected, 'rotation-target-lock-changed')
            yield
        finally:
            if locked:
                if os.name == 'posix':
                    fcntl.flock(fd, fcntl.LOCK_UN)
                else:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            os.close(fd)


def _intent(source, destination):
    _boundary(source, destination)
    value = _read_signed(source, INTENT)
    _require(type(value) is dict and set(value) == {'transaction', 'request'}, 'rotation-intent-invalid')
    request = value['request']
    _require(value['transaction'] == _digest(request) and request['source'] == _identity(source)
             and request['destination'] == _identity(destination), 'rotation-intent-mismatch')
    return value['transaction'], request


def prepare_rotation(source, destination):
    _boundary(source, destination)
    c = source.config
    _require(c.store_root.is_dir() and c.gate_root.is_dir(), 'rotation-source-missing')
    _require(not os.path.lexists(c.store_root / INTENT) and not os.path.lexists(c.store_root / PREPARED),
             'rotation-resume-existing-transaction')
    _require(not os.path.lexists(destination.config.store_root) and not os.path.lexists(destination.config.gate_root),
             'rotation-destination-exists')
    backend = store.HostStore(c.store_policy, c.store_root, key=source.store_key)
    gate = gateway.FileWriterGate(c.gate_policy, c.gate_root, key=source.gate_key)
    with backend.target_lock(), backend.history_lock(), gate._locked():
        _require(not os.path.lexists(c.store_root / INTENT) and not os.path.lexists(c.store_root / PREPARED),
             'rotation-resume-existing-transaction')
        raw = _healthy(source, backend, gate)
        bindings = _bindings(source)
        request = dict(nonce=secrets.token_hex(32), source=_identity(source), destination=_identity(destination),
            sourceBindings=[_binding_id(x) for x in bindings], targetLock=list(state._identity(c.store_root / 'target.lock')),
            snapshot=_snapshot(source), archive=store.runtime.parse_json(raw.decode('ascii')), importedAt=maintenance._now())
        transaction = _digest(request)
        _write_signed(source, INTENT, dict(transaction=transaction, request=request))
    return transaction


def _imports(source, destination, request):
    raw = _raw(request['archive'])
    verified = archive.verify_archive(raw, source.config.store_policy, source.store_key)
    records = {}
    for item in verified.records:
        original = maintenance._plain(item.record)
        _require(store.HostStore._entries(destination.config.runtime_policy, original['observation']) == original['entries'],
                 'rotation-historical-recipe-changed')
        identity = dict(verified.source, recordHash=_digest(original))
        imported = store.imported_history_record(original, identity, verified.archive_hash,
            destination.config.store_policy, item.reference, request['importedAt'])
        signature = hmac.new(destination.store_key, store._DOMAIN + _raw(imported), hashlib.sha256).hexdigest()
        records[item.reference] = _raw(dict(record=imported, signature=signature))
    manifest = dict(schemaVersion=1, kind='history-only-import', archiveHash=verified.archive_hash,
        destinationPolicy=destination.config.store_policy.identity_hash(), importedAt=request['importedAt'],
        records={name: hashlib.sha256(raw).hexdigest() for name, raw in records.items()})
    signature = hmac.new(destination.store_key, b'deployment-history-import-v1\0' + _raw(manifest), hashlib.sha256).hexdigest()
    records[IMPORT] = _raw(dict(manifest=manifest, signature=signature))
    return records


def _ensure_pending(host, kind, transaction):
    c = host.config
    root, policy, key = ((c.store_root, c.store_policy, host.store_key) if kind == 'store'
                         else (c.gate_root, c.gate_policy, host.gate_key))
    if not os.path.lexists(root):
        return state._initialize_pending(root, policy, key, kind, transaction)
    binding = state._binding(root, policy.identity_hash(), key, kind)
    current = state._read(binding)
    _require(current is not None and current['phase'] == 'pending' and current['transaction'] == transaction,
             'rotation-destination-not-owned-pending')
    return binding


def _destination_inventory(destination, bindings, records, *, populate=False):
    expected = set(records) | {'maintenance.json', 'history.lock'}
    with state._directory(destination.config.store_root) as fd:
        names = set(os.listdir(fd if fd is not None else destination.config.store_root))
    _require(names <= expected and (populate or names == expected), 'rotation-destination-inventory-changed')
    for name, raw in records.items():
        if name not in names and populate:
            maintenance._write_new(destination.config.store_root, name, raw)
        _require(state._bytes(destination.config.store_root / name, archive.MAX_RECORD) == raw,
                 'rotation-destination-record-changed')
        if name != IMPORT:
            store.authenticate_history(raw, destination.config.store_policy, destination.store_key, name)
    gate_root = destination.config.gate_root
    with state._directory(gate_root) as fd:
        names = set(os.listdir(fd if fd is not None else gate_root))
    _require(names == {'mutex', 'policy.json', 'maintenance.json'}, 'rotation-destination-gate-not-empty')
    value = dict(version=1, domain='dev-workflow.writer-gate.policy', policy=destination.config.gate_policy._binding(),
        payload=dict(binding=destination.config.gate_policy._binding(), root=list(bindings[1].root_identity),
                     mutex=list(bindings[1].mutex_identity)))
    value['mac'] = hmac.new(destination.gate_key, _raw(value), hashlib.sha256).hexdigest()
    _require(state._bytes(gate_root / 'policy.json', 4096) == _raw(value), 'rotation-destination-gate-binding-changed')


def _phase(binding):
    value = state._read(binding)
    return 'legacy' if value is None else value['phase']


def _retire(binding, transaction):
    try:
        state._read(binding)
    except state.MaintenanceStateError:
        # Only the primitive's narrowly recognized durable latch is repairable.
        return state._complete_latched_retirement(binding, transaction)
    return state._transition(binding, transaction, 'retired')


def rotation_resume(source, destination):
    """Complete only the authenticated transaction; never reactivate successors."""
    transaction, request = _intent(source, destination)
    source_bindings = _bindings(source)
    _require([_binding_id(x) for x in source_bindings] == request['sourceBindings'], 'rotation-source-binding-changed')
    records = _imports(source, destination, request)
    with _target_lock(source, request['targetLock']), ExitStack() as stack:
        for binding in source_bindings:
            stack.enter_context(state._locked_binding(binding))
        _core_idle(source)
        _require(_snapshot(source) == request['snapshot'], 'rotation-source-inventory-drift')
        prepared_exists = os.path.lexists(source.config.store_root / PREPARED)
        if prepared_exists:
            prepared = _read_signed(source, PREPARED)
            _require(type(prepared) is dict and set(prepared) == {'transaction', 'bindings', 'records'}
                     and prepared['transaction'] == transaction
                     and prepared['records'] == {n: hashlib.sha256(v).hexdigest() for n, v in records.items()},
                     'rotation-prepared-mismatch')
            destination_bindings = _bindings(destination)
            _require([_binding_id(x) for x in destination_bindings] == prepared['bindings'],
                     'rotation-destination-binding-changed')
        else:
            # No source retirement is permitted until this signed prepare record
            # is durable. Its absence after any fence is therefore corruption.
            _require(all(_phase(x) in ('legacy', 'active') for x in source_bindings), 'rotation-prepare-evidence-missing')
            destination_bindings = (_ensure_pending(destination, 'store', transaction),
                                    _ensure_pending(destination, 'gate', transaction))
        for binding in destination_bindings:
            stack.enter_context(state._locked_binding(binding))
        target_states = [state._read(x) for x in destination_bindings]
        _require(all(x is not None for x in target_states), 'rotation-destination-state-missing')
        # A successor that has since rotated must remain retired. Do not inspect
        # its changed history or overwrite its later maintenance transaction.
        if any(x['phase'] == 'retired' for x in target_states):
            source_states = [state._read(x) for x in source_bindings]
            _require(prepared_exists and all(x and x['phase'] == 'retired' and x['transaction'] == transaction
                                           for x in source_states), 'rotation-successor-state-unproven')
            return dict(status='complete-successor-retired', transaction=transaction, productionReady=False)
        _require(all(x['transaction'] == transaction and x['phase'] in ('pending', 'active') for x in target_states),
                 'rotation-destination-transaction-mismatch')
        if all(x['phase'] == 'active' for x in target_states):
            _require(prepared_exists and all((state._read(x) or {}).get('phase') == 'retired'
                     and state._read(x)['transaction'] == transaction for x in source_bindings),
                     'rotation-source-retirement-missing')
            return dict(status='complete', transaction=transaction, productionReady=False)
        _destination_inventory(destination, destination_bindings, records, populate=not prepared_exists)
        if not prepared_exists:
            _write_signed(source, PREPARED, dict(transaction=transaction,
                bindings=[_binding_id(x) for x in destination_bindings],
                records={n: hashlib.sha256(v).hexdigest() for n, v in records.items()}))
        # Re-read durable intent and inventory before the first execution fence.
        _require(_intent(source, destination) == (transaction, request)
                 and _snapshot(source) == request['snapshot'], 'rotation-source-inventory-drift')
        # The primitive can repair only a latched retirement, never activation;
        # independent signed intent, prepared binding and exact source inventory
        # have all been checked above under the original kernel locks.
        _retire(source_bindings[1], transaction)
        _retire(source_bindings[0], transaction)
        for binding in source_bindings:
            value = state._read(binding)
            _require(value['phase'] == 'retired' and value['transaction'] == transaction,
                     'rotation-source-retirement-missing')
        _destination_inventory(destination, destination_bindings, records)
        for binding in destination_bindings:
            state._transition(binding, transaction, 'active')
    return dict(status='complete', transaction=transaction, imported=len(records) - 1, productionReady=False)


def rotation_status(source, destination):
    transaction, request = _intent(source, destination)
    source_bindings = _bindings(source)
    _require([_binding_id(x) for x in source_bindings] == request['sourceBindings'], 'rotation-source-binding-changed')
    phases, source_states, destination_states = {}, [], []
    with _target_lock(source, request['targetLock']), ExitStack() as stack:
        for binding in source_bindings:
            stack.enter_context(state._locked_binding(binding))
        prepared = None
        if os.path.lexists(source.config.store_root / PREPARED):
            prepared = _read_signed(source, PREPARED)
            _require(prepared.get('transaction') == transaction, 'rotation-prepared-mismatch')
        for name, binding in zip(('sourceStore', 'sourceGate'), source_bindings):
            try:
                value = state._read(binding)
                _require(not value or value['phase'] != 'retired' or value['transaction'] == transaction,
                         'rotation-source-retirement-missing')
                phases[name] = 'legacy' if value is None else value['phase']
                source_states.append(value)
            except (state.MaintenanceStateError, Error):
                phases[name] = 'blocked'
                source_states.append(None)
        for index, (kind, root) in enumerate((('store', destination.config.store_root), ('gate', destination.config.gate_root))):
            name = 'destinationStore' if kind == 'store' else 'destinationGate'
            if not os.path.lexists(root):
                phases[name] = 'absent'
                destination_states.append(None)
                continue
            try:
                c = destination.config
                binding = state._binding(root, (c.store_policy if kind == 'store' else c.gate_policy).identity_hash(),
                                         destination.store_key if kind == 'store' else destination.gate_key, kind)
                stack.enter_context(state._locked_binding(binding))
                value = state._read(binding)
                _require(value is not None and (value['phase'] == 'retired' or value['transaction'] == transaction),
                         'rotation-destination-transaction-mismatch')
                _require(prepared is None or _binding_id(binding) == prepared['bindings'][index],
                         'rotation-destination-binding-changed')
                phases[name] = value['phase']
                destination_states.append(value)
            except (ValueError, OSError, KeyError, IndexError):
                phases[name] = 'blocked'
                destination_states.append(None)
        complete = prepared is not None and all(v and v['phase'] == 'retired' and v['transaction'] == transaction
                                               for v in source_states)
        if complete and all(v and v['phase'] == 'active' and v['transaction'] == transaction for v in destination_states):
            status = 'complete'
        elif complete and any(v and v['phase'] == 'retired' for v in destination_states) and 'blocked' not in phases.values():
            status = 'complete-successor-retired'
        else:
            status = 'incomplete'
        return dict(status=status, transaction=transaction, phases=phases, productionReady=False)


def rotate(source, destination):
    prepare_rotation(source, destination)
    return rotation_resume(source, destination)


# Fixed diagnostics only; never reflect an arbitrary exception or input path.
ERROR_CODES = frozenset(('rotation-absolute-root-required', 'rotation-candidate-root-invalid', 'rotation-core-operation-unresolved', 'rotation-destination-binding-changed', 'rotation-destination-exists', 'rotation-destination-gate-binding-changed', 'rotation-destination-gate-not-empty', 'rotation-destination-inventory-changed', 'rotation-destination-not-owned-pending', 'rotation-destination-record-changed', 'rotation-destination-state-missing', 'rotation-destination-transaction-mismatch', 'rotation-gate-key-required', 'rotation-historical-recipe-changed', 'rotation-import-manifest-invalid', 'rotation-intent-invalid', 'rotation-intent-mismatch', 'rotation-is-not-transport-migration', 'rotation-journal-gap', 'rotation-journal-invalid', 'rotation-journal-scope', 'rotation-new-identities-required', 'rotation-new-key-material-required', 'rotation-policy-bindings-mismatch', 'rotation-prepare-evidence-missing', 'rotation-prepared-mismatch', 'rotation-record-invalid', 'rotation-resume-existing-transaction', 'rotation-root-overlap', 'rotation-scope-changed', 'rotation-source-binding-changed', 'rotation-source-file-replaced', 'rotation-source-inventory-drift', 'rotation-source-missing', 'rotation-source-retirement-missing', 'rotation-source-too-large', 'rotation-successor-state-unproven', 'rotation-target-lock-changed', 'rotation-unknown-gate-entry', 'rotation-unknown-generation-entry', 'rotation-unknown-journal-entry', 'rotation-unknown-source-entry', 'rotation-unresolved-journal', 'rotation-writer-not-drained', 'typed-maintenance-host-required'))
