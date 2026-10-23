"""Distribution-only authenticated history maintenance with explicit host keys."""
from __future__ import annotations
import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from deployment_host_config import ConfigurationError, load_host_config, read_private_bytes
import deployment_history_archive as archive
import deployment_gateway as gateway
import deployment_store as store
import deployment_maintenance_state as state

class MaintenanceError(ValueError):
    pass

@dataclass(frozen=True)
class MaintenanceHost:
    config: object = field(repr=False)
    store_key: bytes = field(repr=False)
    gate_key: bytes | None = field(default=None, repr=False)

    def __post_init__(self):
        keys = (self.store_key,) if self.gate_key is None else (self.store_key, self.gate_key)
        if any(type(key) is not bytes or len(key) < 32 for key in keys):
            raise MaintenanceError('invalid-maintenance-key')


_DISTRIBUTION = Path(__file__).resolve().parents[1]
_CODES = frozenset({
    'invalid-maintenance-key', 'invalid-host-policy', 'invalid-host-path', 'host-path-overlap',
    'output-path-overlap', 'source-store-missing', 'unknown-history-entry',
    'destination-scope-mismatch', 'destination-identity-reused', 'destination-path-overlap',
    'import-verification-failed', 'destination-inventory-mismatch', 'import-manifest-mismatch',
    'output-required', 'archive-required', 'destination-required',
    'maintenance-private-storage-required', 'maintenance-storage-identity-changed',
    'maintenance-record-too-large', 'maintenance-destination-invalid',
    'maintenance-state-invalid', 'maintenance-permanently-retired',
    'invalid-history-archive', 'invalid-archive-input',
    'maintenance-authority-unavailable', 'maintenance-latch-invalid', 'maintenance-mutex-missing',
    'maintenance-record-invalid', 'maintenance-activation-mismatch', 'maintenance-resume-mismatch',
    'maintenance-atomic-publication-rejected', 'maintenance-atomic-publication-unsupported',
})


def _overlap(left, right):
    return left == right or left in right.parents or right in left.parents


def _path(value):
    if not isinstance(value, Path) or not value.is_absolute() or '..' in value.parts:
        raise MaintenanceError('invalid-host-path')
    # Existing ancestors must be real directories, even if the leaf is absent.
    for parent in (value, *value.parents):
        if os.path.lexists(parent):
            if parent.is_symlink() or getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400:
                raise MaintenanceError('invalid-host-path')
    return value


def _validate_host(host):
    config = host.config
    policy = getattr(config, 'store_policy', None)
    if type(policy) is not store.StorePolicy:
        raise MaintenanceError('invalid-host-policy')
    policy.__post_init__()
    runtime_policy = getattr(config, 'runtime_policy', policy.runtime_policy)
    if runtime_policy.identity_hash() != policy.runtime_policy.identity_hash():
        raise MaintenanceError('invalid-host-policy')
    gate = getattr(config, 'gate_policy', None)
    if gate is not None:
        if type(gate) is not gateway.GatePolicy or gate.scope_hash != store.runtime.digest(policy._scope()):
            raise MaintenanceError('invalid-host-policy')
        gate.__post_init__()
    root = _path(config.store_root)
    prohibited = [_DISTRIBUTION]
    for name in ('candidate_root', 'gate_root'):
        value = getattr(config, name, None)
        if value is not None:
            prohibited.append(_path(value))
    if any(_overlap(root, value) for value in prohibited):
        raise MaintenanceError('host-path-overlap')
    return config


def _protected_roots(*hosts):
    roots = [_DISTRIBUTION]
    for host in hosts:
        _validate_host(host)
        for name in ('store_root', 'gate_root', 'candidate_root'):
            value = getattr(host.config, name, None)
            if value is not None:
                roots.append(_path(value))
    return roots


def backup_to(host, output):
    output = _path(output)
    if any(_overlap(output, root) for root in _protected_roots(host)):
        raise MaintenanceError('output-path-overlap')
    _write_new(output.parent, output.name, backup(host))


def _error_code(error):
    if isinstance(error, (MaintenanceError, state.MaintenanceStateError, archive.ArchiveError)):
        code = str(error)
        from deployment_host_rotation import ERROR_CODES
        if code in _CODES or code in ERROR_CODES:
            return code
    if isinstance(error, FileExistsError):
        return 'destination-already-exists'
    if isinstance(error, PermissionError):
        return 'private-storage-access-denied'
    if isinstance(error, store.StoreError):
        return 'history-authentication-failed'
    return 'maintenance-validation-failed'


def _now():
    return datetime.now(timezone.utc).isoformat()


def _write_new(root, name, raw):
    if type(name) is not str or name in ('', '.', '..') or Path(name).name != name or '/' in name or '\\' in name:
        raise MaintenanceError('invalid-host-path')
    with state._directory(root) as directory:
        fd = state._open_at(root, directory, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            os.fchmod(fd, 0o600) if os.name == 'posix' else None
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            # Preserve partial evidence; never silently repair or replace it.
            raise
        if directory is not None:
            os.fsync(directory)


def verify(host, raw):
    _validate_host(host)
    return archive.verify_archive(raw, host.config.store_policy, host.store_key)


def backup(host):
    config = _validate_host(host)
    if not config.store_root.is_dir():
        raise MaintenanceError('source-store-missing')
    binding = state._binding(config.store_root, config.store_policy.identity_hash(), host.store_key, 'store')
    with state._locked_binding(binding):
        state._guard(config.store_root, config.store_policy.identity_hash(), host.store_key, 'store')
        histories = {}
        with state._directory(config.store_root) as directory:
            names = os.listdir(directory if directory is not None else config.store_root)
            for name in names:
                if name.startswith('history-'):
                    if not store._REF.fullmatch(name):
                        raise MaintenanceError('unknown-history-entry')
                    histories[name] = state._bytes(config.store_root / name, archive.MAX_RECORD)
        return archive.build_archive(config.store_policy, histories, host.store_key, created_at=_now())


def _plain(value):
    from collections.abc import Mapping
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def restore(source, destination, raw):
    """Import only history into a new pending store; never initialize a gate."""
    verified = verify(source, raw)
    config = _validate_host(destination)
    if config.store_policy._scope() != source.config.store_policy._scope():
        raise MaintenanceError('destination-scope-mismatch')
    if (config.store_policy.store_id == source.config.store_policy.store_id
            or config.store_policy.key_id == source.config.store_policy.key_id
            or hmac.compare_digest(source.store_key, destination.store_key)):
        raise MaintenanceError('destination-identity-reused')
    roots = _protected_roots(source) + [_DISTRIBUTION]
    for name in ('candidate_root', 'gate_root'):
        value = getattr(destination.config, name, None)
        if value is not None:
            roots.append(_path(value))
    if any(_overlap(config.store_root, root) for root in roots):
        raise MaintenanceError('destination-path-overlap')
    imported_at = _now()
    records = {}
    for item in verified.records:
        original = _plain(item.record)
        identity = dict(verified.source, recordHash=store.runtime.digest(original))
        record = store.imported_history_record(original, identity, verified.archive_hash,
                                               config.store_policy, item.reference, imported_at)
        signature = hmac.new(destination.store_key, store._DOMAIN + store.runtime.canonical(record).encode(), hashlib.sha256).hexdigest()
        records[item.reference] = store.runtime.canonical(dict(record=record, signature=signature)).encode()
    manifest = dict(schemaVersion=1, kind='history-only-import', archiveHash=verified.archive_hash,
                    destinationPolicy=config.store_policy.identity_hash(), importedAt=imported_at,
                    records={name: hashlib.sha256(value).hexdigest() for name, value in records.items()})
    transaction = store.runtime.digest(manifest)
    binding = state._initialize_pending(config.store_root, config.store_policy, destination.store_key, 'store', transaction)
    with state._locked_binding(binding):
        for name, value in records.items():
            _write_new(config.store_root, name, value)
        for name, value in records.items():
            actual = state._bytes(config.store_root / name, archive.MAX_RECORD)
            if actual != value:
                raise MaintenanceError('import-verification-failed')
            store.authenticate_history(actual, config.store_policy, destination.store_key, name)
        envelope = dict(manifest=manifest, signature=hmac.new(destination.store_key,
                        b'deployment-history-import-v1\x00' + store.runtime.canonical(manifest).encode(), hashlib.sha256).hexdigest())
        _write_new(config.store_root, 'maintenance-import-manifest.json', store.runtime.canonical(envelope).encode())
        expected = set(records) | {'maintenance-import-manifest.json', state._MARKER, state._mutex_name('store')}
        with state._directory(config.store_root) as directory:
            if set(os.listdir(directory if directory is not None else config.store_root)) != expected:
                raise MaintenanceError('destination-inventory-mismatch')
        persisted = state._bytes(config.store_root / 'maintenance-import-manifest.json', archive.MAX_ARCHIVE)
        if persisted != store.runtime.canonical(envelope).encode():
            raise MaintenanceError('import-manifest-mismatch')
        state._transition(binding, transaction, 'active')
    return dict(schemaVersion=1, status='complete', transaction=transaction, imported=len(records), productionReady=False)


def _load(path, *, require_gate=False):
    config = load_host_config(path)
    return MaintenanceHost(config, read_private_bytes(config.store_key_file, maximum=4096, minimum=32),
                           read_private_bytes(config.gate_key_file, maximum=4096, minimum=32) if require_gate else None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('backup', 'verify', 'restore', 'rotate', 'rotation-status', 'rotation-resume'))
    parser.add_argument('--config', required=True)
    parser.add_argument('--destination-config')
    parser.add_argument('--archive')
    parser.add_argument('--output')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        host = _load(args.config, require_gate=args.command in ('rotate', 'rotation-status', 'rotation-resume'))
        if args.command == 'backup':
            if not args.output:
                raise MaintenanceError('output-required')
            output = Path(args.output)
            backup_to(host, output)
            result = dict(status='complete')
        elif args.command in ('verify', 'restore'):
            if not args.archive:
                raise MaintenanceError('archive-required')
            raw = read_private_bytes(Path(args.archive), maximum=archive.MAX_ARCHIVE)
            if args.command == 'verify':
                checked = verify(host, raw)
                result = dict(status='verified', records=len(checked.records), archiveHash=checked.archive_hash)
            else:
                if not args.destination_config:
                    raise MaintenanceError('destination-required')
                result = restore(host, _load(args.destination_config), raw)
        else:
            import deployment_host_rotation as rotation
            if not args.destination_config:
                raise MaintenanceError('destination-required')
            destination = _load(args.destination_config, require_gate=True)
            result = getattr(rotation, args.command.replace('-', '_'))(host, destination)
        print(json.dumps(dict(result, schemaVersion=1, productionReady=False), sort_keys=True))
        return 0
    except ConfigurationError as exc:
        incomplete = str(exc) == 'private-acl-unverified'
        print(json.dumps(dict(schemaVersion=1, status='incomplete' if incomplete else 'blocked',
                              code='private-acl-unverified' if incomplete else 'maintenance-validation-failed',
                              productionReady=False)))
        return 2 if incomplete else 1
    except (ValueError, OSError, ImportError, TypeError, KeyError, AttributeError) as exc:
        print(json.dumps(dict(schemaVersion=1, status='blocked', code=_error_code(exc), productionReady=False)))
        return 1

if __name__ == '__main__':
    # The rotation module must see the same typed host/error classes as this CLI.
    sys.modules.setdefault('deployment_host_maintenance', sys.modules[__name__])
    raise SystemExit(main())
