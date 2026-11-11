"""Read one pinned Git JSON blob and issue a bounded network assertion.

No Compose evaluation, YAML, interpolation, includes, overrides or Docker calls.
Git membership and byte digest do not authenticate repository ownership or prove
that this model was the one used to create the observed container.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from deployment_compose_network_declaration import commit_network_declaration, bind_network_declaration
from deployment_compose_snapshot import prepare_snapshot, _encode

MAX_BYTES = 128 * 1024
SERVICE_FIELDS = {'image', 'command', 'environment', 'read_only', 'tmpfs', 'restart',
                  'logging', 'healthcheck', 'volumes', 'depends_on', 'networks'}


def _fail():
    raise ValueError('invalid-compose-network-source')


def _pairs(pairs):
    value = {}
    for k, v in pairs:
        if k in value:
            _fail()
        value[k] = v
    return value


def _git(root, *args):
    env = {'PATH': os.defpath, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
           'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
           'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'}
    result = subprocess.run(['git', '--no-replace-objects', '--literal-pathspecs', '-C', str(root), *args],
                            env=env, capture_output=True, timeout=10, check=False)
    if result.returncode != 0:
        _fail()
    return result.stdout


def issue_network_from_git(root, relative_path, raw, identity, artifact, private_key,
                           network_ids, expected_mounts, *, expected_blob_digest,
                           declaration_key_id, declaration_key):
    """Host must independently pin repository, source SHA, path, digest and keys."""
    try:
        if (type(relative_path) is not str or len(relative_path) > 512
                or not re.fullmatch(r'[A-Za-z0-9._/-]+', relative_path)
                or any(p in ('', '.', '..') for p in relative_path.split('/'))
                or type(expected_blob_digest) is not str
                or not re.fullmatch('[0-9a-f]{64}', expected_blob_digest)):
            _fail()
        root = Path(root).resolve(strict=True)
        snapshot = prepare_snapshot(raw, identity, artifact, private_key, network_ids, expected_mounts)
        # Older Git ignores GIT_NO_LAZY_FETCH. Inspect effective configuration
        # (including includes/worktree config) before any object lookup.
        config = _git(root, 'config', '--includes', '--null', '--list')
        for item in config.split(b'\0'):
            key = item.split(b'\n', 1)[0].lower()
            if key == b'extensions.partialclone' or (key.startswith(b'remote.') and key.endswith(b'.promisor')):
                _fail()
        sha = artifact.source_sha
        if _git(root, 'cat-file', '-t', sha) != b'commit\n':
            _fail()
        entry = _git(root, 'ls-tree', '-z', sha, '--', relative_path)
        metadata, path = entry.removesuffix(b'\0').split(b'\t')
        mode, kind, oid = metadata.split(b' ')
        if mode != b'100644' or kind != b'blob' or path.decode('ascii') != relative_path:
            _fail()
        object_id = oid.decode('ascii')
        size = int(_git(root, 'cat-file', '-s', object_id))
        if not 0 < size <= MAX_BYTES:
            _fail()
        content = _git(root, 'cat-file', 'blob', object_id)
        if len(content) != size or hashlib.sha256(content).hexdigest() != expected_blob_digest:
            _fail()
        model = json.loads(content.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _fail())
        if (type(model) is not dict or set(model) != {'services', 'networks'}
                or type(model['services']) is not dict or not model['services']
                or type(model['networks']) is not dict or len(model['networks']) != 1):
            _fail()
        # No recursive interpolation/evaluation is performed. Reject template
        # syntax anywhere, including fields not consumed by this network parser.
        if '$' in json.dumps(model, ensure_ascii=False):
            _fail()
        for service in model['services'].values():
            if type(service) is not dict or set(service) - SERVICE_FIELDS:
                _fail()
        selected = model['services'][identity['service']]
        if type(selected.get('networks')) is not dict or len(selected['networks']) != 1:
            _fail()
        logical, attachment = next(iter(selected['networks'].items()))
        network = model['networks'][logical]
        if (type(network) is not dict or set(network) != {'name', 'external'}
                or network['external'] is not True or type(network['name']) is not str
                or set(network_ids) != {network['name']}
                or type(attachment) is not dict or set(attachment) != {'aliases'}):
            _fail()
        declaration = {'schemaVersion': 1, 'identity': deepcopy(snapshot['identity']),
            'sourceSha': sha, 'sourceModelDigest': expected_blob_digest,
            'sourceSnapshotDigest': hashlib.sha256(_encode(snapshot)).hexdigest(),
            'networks': {network['name']: {'id': network_ids[network['name']],
                'aliases': deepcopy(attachment['aliases']), 'addressPolicy': 'dynamic-no-requested-addresses',
                'requestedMac': None, 'ipamConfig': None, 'links': None, 'driverOpts': None}}}
        proof = commit_network_declaration(declaration, declaration_key_id, declaration_key)
        # Do not return an assertion for an incompatible authenticated snapshot.
        bind_network_declaration(raw, identity, artifact, private_key, network_ids, expected_mounts,
            declaration, proof, declaration_key, expected_key_id=declaration_key_id,
            expected_declaration_hmac=proof['declarationHmac'], expected_source_model_digest=expected_blob_digest)
        return {'schemaVersion': 1, 'kind': 'compose-git-network-source-assertion',
                'declaration': declaration, 'commitment': proof,
                'sourceEvidence': {'sourceSha': sha, 'path': relative_path, 'blobId': object_id,
                                   'sha256': expected_blob_digest, 'gitBlobMembershipVerified': True},
                'repositoryOwnershipVerified': False, 'deploymentSourceMatchVerified': False,
                'authorityGranted': False, 'executionAvailable': False, 'productionReady': False}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError,
            OSError, subprocess.SubprocessError, UnicodeError):
        raise ValueError('invalid-compose-network-source') from None
