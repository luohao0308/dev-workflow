"""Verify host-attested Compose safety reports; no signing or execution API.

Keys and schema/backup pins are provisioned outside project input. An attestor
must verify the actual build/migration/backup reports before authenticating a
record. A valid MAC authenticates that attestor's assertion, not the underlying
build or backup by itself. This module does not implement those producers.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re

DOMAIN = b'dev-workflow:compose-safety-proof:v1\0'
BUNDLE_DOMAIN = b'dev-workflow:compose-safety-bundle:v1\0'
KINDS = ('provenance', 'migration', 'backup')
HEX = re.compile(r'[0-9a-f]{64}\Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hash(value):
    return type(value) is str and HEX.fullmatch(value) and value != '0' * 64


def _time(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value):
        raise ValueError('proof-rejected')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def _bounded(value):
    """Bound plain JSON input before copying or serializing any report."""
    nodes, size = 0, 0
    def visit(item, depth):
        nonlocal nodes, size
        nodes += 1
        if depth > 12 or nodes > 2048:
            raise ValueError('proof-rejected')
        if type(item) is str:
            if len(item) > 4096:
                raise ValueError('proof-rejected')
            size += len(item.encode('ascii', errors='backslashreplace'))
        elif type(item) is dict and len(item) <= 128:
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError('proof-rejected')
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif type(item) is list and len(item) <= 128:
            for child in item:
                visit(child, depth + 1)
        elif type(item) not in (bool, int, type(None)):
            raise ValueError('proof-rejected')
        elif type(item) is int and not -2**63 <= item < 2**63:
            raise ValueError('proof-rejected')
        if size > 65536:
            raise ValueError('proof-rejected')
    visit(value, 0)


class ComposeProofHost:
    def __init__(self, *, keys, schema_digest, backup_digest, restore_test_digest):
        if (type(keys) is not dict or set(keys) != set(KINDS)
                or any(type(value) is not tuple or len(value) != 2
                       or type(value[0]) is not str
                       or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value[0])
                       or type(value[1]) is not bytes or len(value[1]) < 32
                       for value in keys.values())
                or len({value[1] for value in keys.values()}) != len(KINDS)
                or not all(_hash(v) for v in (schema_digest, backup_digest, restore_test_digest))):
            raise ValueError('invalid-proof-host-policy')
        self._keys = dict(keys)
        self._schema, self._backup, self._restore = schema_digest, backup_digest, restore_test_digest

    def verify(self, request, baseline, target, bundle):
        """Return a commitment after all three attested reports match exact intent."""
        from deployment_contract_v2 import RequestV2
        from deployment_compose_artifacts import ComposeArtifacts
        from deployment_compose_target_artifacts import ComposeTargetArtifacts
        if (type(request) is not RequestV2 or type(baseline) is not ComposeArtifacts
                or type(target) is not ComposeTargetArtifacts
                or request.operation != 'deploy' or request.profile_id != 'compose-application-batch-v1'
                or request.profile_version != '1' or request.target.runtime != 'compose'
                or request.before_hash != baseline.digest()
                or request.after_hash != target.digest() or request.artifact_digest != target.digest()
                or type(bundle) is not dict or set(bundle) != set(KINDS)):
            raise ValueError('proof-rejected')
        # Copy before validating to avoid retaining caller-owned mutable records.
        _bounded(bundle)
        records = deepcopy(bundle)
        if len(canonical(records)) > 65536:
            raise ValueError('proof-rejected')
        statements = {
            'provenance': {'targetDigest': target.digest(), 'source': {
                'provider': request.source.provider_id, 'projectId': request.source.project_id,
                'origin': request.source.origin, 'sha': request.source.source_sha}},
            'migration': {'schemaDigest': self._schema, 'services': [
                {'service': old.service, 'baselineMigration': old.migration_digest,
                 'targetMigration': new.migration_digest, 'mode': 'none'}
                for old, new in zip(baseline.services, target.services)]},
            'backup': {'baselineDigest': baseline.digest(), 'backupDigest': self._backup,
                       'restoreTestDigest': self._restore},
        }
        if (tuple(x.service for x in baseline.services) != request.components
                or tuple(x.service for x in target.services) != request.components
                or any(x.migration_mode != 'none' for x in baseline.services + target.services)
                or any(x.source_sha != request.source.source_sha for x in target.services)):
            raise ValueError('proof-rejected')
        now = datetime.now(timezone.utc)
        request.ensure_fresh(now)
        for kind in KINDS:
            record = records[kind]
            if (type(record) is not dict or set(record) != {'body', 'mac'}
                    or type(record['body']) is not dict or not _hash(record['mac'])):
                raise ValueError('proof-rejected')
            body = record['body']
            key_id, key = self._keys[kind]
            if (set(body) != {'version', 'kind', 'keyId', 'requestHash', 'statement',
                             'reportDigest', 'issuedAt', 'expiresAt', 'status'}
                    or type(body['version']) is not int or body['version'] != 1
                    or body['kind'] != kind or body['keyId'] != key_id
                    or body['requestHash'] != request.digest() or body['status'] != 'verified'
                    or canonical(body['statement']) != canonical(statements[kind]) or not _hash(body['reportDigest'])):
                raise ValueError('proof-rejected')
            issued, expires = _time(body['issuedAt']), _time(body['expiresAt'])
            if (not issued <= now < expires or (now - issued).total_seconds() > 3600
                    or not 0 < (expires - issued).total_seconds() <= 3600
                    or expires < _time(request.expires_at)):
                raise ValueError('proof-rejected')
            expected = hmac.new(key, DOMAIN + canonical(body), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, record['mac']):
                raise ValueError('proof-rejected')
        return hashlib.sha256(BUNDLE_DOMAIN + canonical(records)).hexdigest()
