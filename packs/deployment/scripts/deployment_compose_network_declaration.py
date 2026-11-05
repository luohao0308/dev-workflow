"""Host-asserted original network declaration binding; no execution authority.

HMAC checks an independently pinned host assertion, not source-model provenance
or freshness. Never manufacture a declaration from inspect in this module.
"""
from copy import deepcopy
import hashlib
import hmac

from deployment_compose_recipe import HEX, NAME
from deployment_compose_snapshot import _encode, prepare_snapshot

DOMAIN = b'dev-workflow:compose-network-declaration:v1\0'
RESULT_DOMAIN = b'dev-workflow:compose-bound-network-fragment:v1\0'


def _fail():
    raise ValueError('invalid-compose-network-declaration')


def _canonical(declaration):
    if (type(declaration) is not dict or set(declaration) != {
            'schemaVersion', 'identity', 'sourceSha', 'sourceModelDigest', 'sourceSnapshotDigest', 'networks'}
            or type(declaration['schemaVersion']) is not int or declaration['schemaVersion'] != 1):
        _fail()
    for field in ('sourceModelDigest', 'sourceSnapshotDigest'):
        if type(declaration[field]) is not str or not HEX.fullmatch(declaration[field]):
            _fail()
    sha = declaration['sourceSha']
    if type(sha) is not str or len(sha) != 40 or any(c not in '0123456789abcdef' for c in sha):
        _fail()
    if type(declaration['identity']) is not dict:
        _fail()
    networks = declaration['networks']
    if type(networks) is not dict or len(networks) != 1:
        _fail()
    for name, net in networks.items():
        if (type(name) is not str or not NAME.fullmatch(name) or type(net) is not dict
                or set(net) != {'id', 'aliases', 'addressPolicy', 'requestedMac', 'ipamConfig', 'links', 'driverOpts'}
                or type(net['id']) is not str or not HEX.fullmatch(net['id'])
                or type(net['addressPolicy']) is not str or net['addressPolicy'] != 'dynamic-no-requested-addresses'
                or any(net[k] is not None for k in ('requestedMac', 'ipamConfig', 'links', 'driverOpts'))):
            _fail()
        aliases = net['aliases']
        if (type(aliases) is not list or not 1 <= len(aliases) <= 32
                or any(type(a) is not str or not NAME.fullmatch(a) for a in aliases)
                or len(set(aliases)) != len(aliases)):
            _fail()
    return _encode(declaration)


def commit_network_declaration(declaration, key_id, key):
    """Seal a host-supplied declaration, not recovered inspect-origin proof."""
    try:
        if type(key_id) is not str or not NAME.fullmatch(key_id) or type(key) is not bytes or len(key) < 32:
            _fail()
        label = key_id.encode('ascii')
        digest = hmac.new(key, DOMAIN + len(label).to_bytes(2, 'big') + label + _canonical(declaration), hashlib.sha256).hexdigest()
        return {'keyId': key_id, 'declarationHmac': digest}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        _fail()


def bind_network_declaration(raw, identity, artifact, private_key, network_ids, expected_mounts,
                             declaration, proof, declaration_key, *, expected_key_id,
                             expected_declaration_hmac, expected_source_model_digest):
    """Recheck full source and exact externally pinned declaration commitment."""
    try:
        snapshot = prepare_snapshot(raw, identity, artifact, private_key, network_ids, expected_mounts)
        if (type(proof) is not dict or set(proof) != {'keyId', 'declarationHmac'}
                or type(expected_key_id) is not str or proof['keyId'] != expected_key_id
                or type(expected_declaration_hmac) is not str or not HEX.fullmatch(expected_declaration_hmac)
                or type(proof['declarationHmac']) is not str
                or not hmac.compare_digest(proof['declarationHmac'], expected_declaration_hmac)
                or type(expected_source_model_digest) is not str or not HEX.fullmatch(expected_source_model_digest)):
            _fail()
        actual = commit_network_declaration(declaration, expected_key_id, declaration_key)
        if not hmac.compare_digest(actual['declarationHmac'], expected_declaration_hmac):
            _fail()
        snapshot_digest = hashlib.sha256(_encode(snapshot)).hexdigest()
        if (_encode(declaration['identity']) != _encode(snapshot['identity'])
                or declaration['sourceSha'] != artifact.source_sha
                or declaration['sourceModelDigest'] != expected_source_model_digest
                or declaration['sourceSnapshotDigest'] != snapshot_digest
                or set(declaration['networks']) != set(network_ids)):
            _fail()
        fragments = {}
        for name, net in declaration['networks'].items():
            endpoint = snapshot['networkSettings']['rawNetworkSettings']['Networks'][name]
            if (net['id'] != network_ids[name] or endpoint['NetworkID'] != net['id']
                    or _encode(endpoint['Aliases']) != _encode(net['aliases'])
                    or any(endpoint[k] is not None for k in ('IPAMConfig', 'Links', 'DriverOpts'))
                    or ('GwPriority' in endpoint and endpoint['GwPriority'] != 0)):
                _fail()
            # Explicit host policy, never a deduction from the observed MAC/IP.
            # No assigned addresses, DNSNames, sandbox IDs or endpoint IDs copied.
            fragments[name] = {'NetworkID': net['id'], 'Aliases': deepcopy(net['aliases'])}
        result = {
            'schemaVersion': 1, 'kind': 'compose-host-asserted-network-fragment',
            'sourceSnapshotDigest': snapshot_digest, 'declaration': deepcopy(declaration),
            'declarationCommitment': deepcopy(proof), 'networkFragment': fragments,
            'hostAssertionAuthenticated': True, 'sourceModelProvenanceVerified': False,
            'addressOriginIndependentlyVerified': False, 'freshnessVerified': False,
            'blockers': ['trusted-original-source-model-producer-required',
                         'fresh-network-and-protected-alias-evidence-required',
                         'config-host-network-composition-and-metadata-policy-required',
                         'independent-engine-reconstruction-required',
                         'trusted-approval-writer-and-independent-anchor-required'],
            'completeCreatePayloadAvailable': False, 'authorityGranted': False,
            'executionAvailable': False, 'reconstructionValidated': False, 'productionReady': False,
        }
        result['fragmentDigest'] = hashlib.sha256(RESULT_DOMAIN + _encode(result)).hexdigest()
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise ValueError('invalid-compose-network-declaration') from None
