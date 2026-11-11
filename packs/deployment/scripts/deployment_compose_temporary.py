"""Authenticate v3 final-name input and derive a temporary create description.

This does not establish that v3 was reviewed: the current RequestHost accepts
v2 recipes. No version upgrade, Gate operation or execution permit is issued.
The returned private envelope may contain Env and must not be published.
"""
from copy import deepcopy
import hashlib
import hmac
import re

from deployment_compose_create import compile_create, _encode, _digest
from deployment_compose_operations import CANDIDATE_DOMAIN
from deployment_compose_recipe import NAME
from deployment_compose_recipe_v3 import canonical_recipe_v3, commit_recipe_v3

DOMAIN = b'dev-workflow:compose-temporary-derivation:v1\0'
HEX = re.compile(r'[0-9a-f]{64}\Z')


def fail():
    raise ValueError('invalid-compose-temporary-derivation')


def derive_temporary(recipe, commitment, *, key, expected_key_id, expected_recipe_hmac,
                     expected_project, expected_service, expected_final_name, operation_nonce,
                     baseline_image_id, image_defaults, identity, network_ids, allowed_mounts, hostname):
    """Pin original recipe identity/MAC; only its cloned containerName changes."""
    try:
        recipe = deepcopy(recipe)
        commitment = deepcopy(commitment)
        image_defaults, identity, network_ids, allowed_mounts = deepcopy((
            image_defaults, identity, network_ids, allowed_mounts))
        canonical_recipe_v3(recipe)
        if (type(expected_key_id) is not str or not NAME.fullmatch(expected_key_id)
                or type(expected_recipe_hmac) is not str or not HEX.fullmatch(expected_recipe_hmac)
                or type(operation_nonce) is not str or not HEX.fullmatch(operation_nonce)
                or any(type(value) is not str or not NAME.fullmatch(value) for value in (
                    expected_project, expected_service, expected_final_name))
                or recipe['project'] != expected_project or recipe['service'] != expected_service
                or recipe['containerName'] != expected_final_name
                or type(commitment) is not dict or set(commitment) != {'keyId', 'hmac'}
                or commitment['keyId'] != expected_key_id
                or type(commitment['hmac']) is not str
                or not hmac.compare_digest(commitment['hmac'], expected_recipe_hmac)):
            fail()
        actual = commit_recipe_v3(recipe, expected_key_id, key)
        if not hmac.compare_digest(actual['hmac'], expected_recipe_hmac):
            fail()
        # The unchanged source compile checks all original identity/image/input
        # constraints, including source identity.containerName == finalName.
        source = compile_create(recipe, baseline_image_id=baseline_image_id,
            image_defaults=image_defaults, identity=identity, network_ids=network_ids,
            allowed_mounts=allowed_mounts, hostname=hostname)
        temporary_name = 'dwc-' + hashlib.sha256(CANDIDATE_DOMAIN + operation_nonce.encode('ascii')
            + b'\0' + expected_service.encode('ascii')).hexdigest()
        if temporary_name == expected_final_name:
            fail()
        transformed = deepcopy(recipe)
        transformed['containerName'] = temporary_name
        temporary_identity = dict(identity, containerName=temporary_name)
        candidate = compile_create(transformed, baseline_image_id=baseline_image_id,
            image_defaults=image_defaults, identity=temporary_identity, network_ids=network_ids,
            allowed_mounts=allowed_mounts, hostname=hostname)
        if source['method'] != candidate['method'] or _encode(source['body']) != _encode(candidate['body']):
            fail()
        result = {'schemaVersion': 1, 'kind': 'compose-temporary-create-derivation',
            'sourceRecipeSchemaVersion': 3, 'sourceRecipeCommitment': actual,
            'sourceRecipeDigest': _digest(recipe), 'sourceCandidateDigest': source['candidateDigest'],
            'project': expected_project, 'service': expected_service,
            'finalName': expected_final_name, 'temporaryName': temporary_name,
            'operationNonce': operation_nonce, 'candidate': candidate,
            'sourceVerification': 'host-key-verified-v3-not-review-authority',
            'createBodyUnchanged': True, 'authorityGranted': False, 'executionAvailable': False,
            'productionReady': False, 'reconstructionValidated': False,
            'blockers': ['v3-request-review-integration-required',
                'temporary-name-gateway-support-required', 'receipt-plan-binding-required',
                'independent-anchor-required', 'step-sequencing-authority-required',
                'recovery-authorization-required', *candidate['validationBlockers']]}
        result['derivationDigest'] = hashlib.sha256(DOMAIN + _encode(result)).hexdigest()
        _encode(result)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, UnicodeError):
        raise ValueError('invalid-compose-temporary-derivation') from None


def verify_temporary(derivation, recipe, commitment, **trusted_inputs):
    """Rebuild from independently pinned inputs; a self-rehashed export is insufficient."""
    try:
        derivation = deepcopy(derivation)
        expected = derive_temporary(recipe, commitment, **trusted_inputs)
        if type(derivation) is not dict or _encode(derivation) != _encode(expected):
            fail()
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, UnicodeError):
        raise ValueError('invalid-compose-temporary-derivation') from None


def verify_temporary_operation(derivation, recipe, commitment, *, operation, **trusted_inputs):
    """Check an exact method/path/canonical-body-hash tuple, without approving it.

    Call before provisioning receipt expectations. This does not establish plan
    index, Gate compatibility, approval, freshness or permission to send bytes.
    """
    try:
        derivation = deepcopy(derivation)
        verify_temporary(derivation, recipe, commitment, **trusted_inputs)
        candidate = derivation['candidate']
        expected = (candidate['method'], candidate['path'],
                    hashlib.sha256(_encode(candidate['body'])).hexdigest())
        if (type(operation) is not tuple or len(operation) != 3
                or any(type(value) is not str for value in operation) or operation != expected):
            fail()
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, UnicodeError):
        raise ValueError('invalid-compose-temporary-derivation') from None
