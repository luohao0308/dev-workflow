"""Private restore-network field classification; never a create projection.

An inspect MAC cannot establish whether it was explicitly requested. Keep all
values, classify their evidence role, and require original declaration proof.
"""
from copy import deepcopy
import hashlib

from deployment_compose_network import ENDPOINT_FIELDS
from deployment_compose_snapshot import _encode, prepare_snapshot

DOMAIN = b'dev-workflow:compose-restore-network-audit:v1\0'
DECLARATION = frozenset({'IPAMConfig', 'Links', 'Aliases', 'DriverOpts'})
RUNTIME = frozenset({'EndpointID', 'Gateway', 'IPAddress', 'IPPrefixLen',
                     'IPv6Gateway', 'GlobalIPv6Address', 'GlobalIPv6PrefixLen', 'DNSNames'})


def audit_restore_network(raw, identity, artifact, private_key, network_ids, expected_mounts):
    """Authenticate source before classifying; no origin or API-write inference."""
    try:
        snapshot = prepare_snapshot(raw, identity, artifact, private_key, network_ids, expected_mounts)
        if DECLARATION | RUNTIME | {'NetworkID', 'MacAddress'} != ENDPOINT_FIELDS:
            raise ValueError()
        settings = snapshot['networkSettings']['rawNetworkSettings']
        endpoints = {}
        for name, endpoint in settings['Networks'].items():
            endpoints[name] = {
                'identityEvidence': {'NetworkID': endpoint['NetworkID']},
                'declarationEvidence': {k: deepcopy(endpoint[k]) for k in sorted(DECLARATION)},
                'runtimeEvidence': {k: deepcopy(endpoint[k]) for k in sorted(RUNTIME)},
                'ambiguousOriginEvidence': {'MacAddress': endpoint['MacAddress']},
                # Observed on a newer Engine even under API1.45; do not assume
                # that this field can be submitted to the fixed write API.
                'writeVersionUnverifiedEvidence': ({'GwPriority': endpoint['GwPriority']}
                                                    if 'GwPriority' in endpoint else {}),
            }
            classified = set().union(*(part.keys() for part in endpoints[name].values()))
            if classified != set(endpoint):
                raise ValueError()
        result = {
            'schemaVersion': 1, 'kind': 'compose-restore-network-audit',
            'sourceSnapshotDigest': hashlib.sha256(_encode(snapshot)).hexdigest(),
            'sourceConfigHmac': artifact.config_hmac,
            'endpoints': endpoints,
            'containerRuntimeEvidence': {k: deepcopy(settings[k]) for k in ('Ports', 'SandboxID', 'SandboxKey')},
            'declarationOriginVerified': False, 'dynamicAddressOriginVerified': False,
            'writeApiSemanticsVerified': False,
            'blockers': ['authenticated-original-network-declaration-required',
                         'mac-and-static-or-dynamic-address-origin-required',
                         'fixed-write-api-field-support-required',
                         'fresh-network-identity-and-alias-protection-required',
                         'independent-engine-reconstruction-required'],
            'completeCreatePayloadAvailable': False, 'authorityGranted': False,
            'executionAvailable': False, 'reconstructionValidated': False, 'productionReady': False,
        }
        result['auditDigest'] = hashlib.sha256(DOMAIN + _encode(result)).hexdigest()
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise ValueError('invalid-compose-restore-network-audit') from None
