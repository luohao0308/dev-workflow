"""Bounded, canonical history archives; this module performs no storage IO."""
from __future__ import annotations
from dataclasses import dataclass
from types import MappingProxyType
from pathlib import Path
import sys
import hashlib
import hmac
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
import deployment_store as store

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_RECORD = 8 * 1024 * 1024
MAX_ENTRIES = 4096
_DOMAIN = b'deployment-history-archive-v1\x00'

class ArchiveError(ValueError):
    """Archive authentication or validation failed."""

@dataclass(frozen=True)
class VerifiedRecord:
    reference: str
    raw: bytes
    record: object

@dataclass(frozen=True)
class VerifiedArchive:
    archive_hash: str
    source: object
    created_at: str
    manifest: tuple
    records: tuple[VerifiedRecord, ...]


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if type(value) is list:
        return tuple(_freeze(v) for v in value)
    return value


def _bytes(value):
    return store.runtime.canonical(value).encode('ascii')


def _identity(policy, key):
    if type(policy) is not store.StorePolicy or type(key) is not bytes or len(key) < 32:
        raise ArchiveError('invalid-archive-input')
    return dict(storeId=policy.store_id, keyId=policy.key_id, storePolicyHash=policy.identity_hash())


def build_archive(source_policy, histories, source_key, *, created_at):
    try:
        source = _identity(source_policy, source_key)
        when = store._utc(created_at)
        if type(histories) is not dict or len(histories) > MAX_ENTRIES:
            raise ValueError
        manifest, records = [], []
        total = 0
        for reference in sorted(histories):
            raw = histories[reference]
            if type(raw) is not bytes or len(raw) > MAX_RECORD:
                raise ValueError
            total += len(raw)
            if total > MAX_ARCHIVE:
                raise ValueError
            record = store.authenticate_history(raw, source_policy, source_key, reference)
            if store._utc(record['capturedAt']) > when:
                raise ValueError
            manifest.append(dict(reference=reference, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw)))
            records.append(dict(reference=reference, envelope=store.runtime.parse_json(raw.decode('ascii'))))
        body = dict(schemaVersion=1, kind='deployment-history-archive', source=source,
                    createdAt=created_at, manifest=manifest, records=records)
        raw = _bytes(dict(archive=body, signature=hmac.new(source_key, _DOMAIN + _bytes(body), hashlib.sha256).hexdigest()))
        verify_archive(raw, source_policy, source_key)
        return raw
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        raise ArchiveError('invalid-history-archive') from None


def verify_archive(raw, source_policy, source_key):
    try:
        source = _identity(source_policy, source_key)
        if type(raw) is not bytes or len(raw) > MAX_ARCHIVE:
            raise ValueError
        envelope = store.runtime.parse_json(raw.decode('ascii'))
        if type(envelope) is not dict or set(envelope) != {'archive', 'signature'} or _bytes(envelope) != raw:
            raise ValueError
        body = envelope['archive']
        if (type(body) is not dict or set(body) != {'schemaVersion', 'kind', 'source', 'createdAt', 'manifest', 'records'}
                or type(body['schemaVersion']) is not int or body['schemaVersion'] != 1
                or body['kind'] != 'deployment-history-archive' or body['source'] != source
                or type(envelope['signature']) is not str
                or not hmac.compare_digest(envelope['signature'], hmac.new(source_key, _DOMAIN + _bytes(body), hashlib.sha256).hexdigest())):
            raise ValueError
        when = store._utc(body['createdAt'])
        manifest, entries = body['manifest'], body['records']
        if (type(manifest) is not list or type(entries) is not list
                or len(manifest) != len(entries) or len(entries) > MAX_ENTRIES):
            raise ValueError
        verified, previous = [], ''
        for item, entry in zip(manifest, entries):
            if (type(item) is not dict or set(item) != {'reference', 'sha256', 'size'}
                    or type(entry) is not dict or set(entry) != {'reference', 'envelope'}):
                raise ValueError
            ref = item['reference']
            if type(ref) is not str or not store._REF.fullmatch(ref) or ref <= previous or entry['reference'] != ref:
                raise ValueError
            previous = ref
            record_raw = _bytes(entry['envelope'])
            if (len(record_raw) > MAX_RECORD or type(item['size']) is not int or item['size'] != len(record_raw)
                    or item['sha256'] != hashlib.sha256(record_raw).hexdigest()):
                raise ValueError
            record = store.authenticate_history(record_raw, source_policy, source_key, ref)
            if store._utc(record['capturedAt']) > when:
                raise ValueError
            verified.append(VerifiedRecord(ref, record_raw, _freeze(record)))
        return VerifiedArchive(hashlib.sha256(raw).hexdigest(), _freeze(source), body['createdAt'],
                               tuple(_freeze(x) for x in manifest), tuple(verified))
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        raise ArchiveError('invalid-history-archive') from None
