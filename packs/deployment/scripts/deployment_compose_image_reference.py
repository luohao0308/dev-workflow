"""Opt-in image reference binding; original Engine evidence is never rewritten.

The deliberately narrow policy accepts the Docker Hub official-image shorthand
only. This is a naming equivalence check over authenticated local image data,
not registry contact, image provenance, freshness, or execution authorization.
"""
from copy import deepcopy
import hashlib
import json
import re

from deployment_compose_image_defaults import derive_defaults
from deployment_compose_recipe import NAME
from deployment_prepare import registry_reference

POLICY = 'docker-hub-official-digest-v1'
DOMAIN = b'dev-workflow:compose-image-reference-binding:v1\0'
SHORT = re.compile(r'([a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)@(sha256:[0-9a-f]{64})\Z')


def _fail():
    raise ValueError('invalid-compose-image-reference-binding')


def derive_bound_defaults(image, proof, key, *, expected_key_id,
                          expected_image_id, expected_artifact_reference,
                          expected_observed_reference, expected_architecture,
                          policy):
    """Authenticate original image, then bind one independently pinned spelling.

    Full artifact reference and observed spelling are host inputs. Policy is
    explicit; no fallback is added to existing exact-reference callers.
    """
    try:
        if (type(policy) is not str or policy != POLICY
                or type(expected_key_id) is not str or not NAME.fullmatch(expected_key_id)
                or type(proof) is not dict or proof.get('keyId') != expected_key_id
                or type(expected_artifact_reference) is not str
                or not registry_reference(expected_artifact_reference)
                or type(expected_observed_reference) is not str):
            _fail()
        observed = expected_observed_reference
        canonical = observed
        rule = 'exact'
        if observed != expected_artifact_reference:
            short = SHORT.fullmatch(observed)
            if short is None:
                _fail()
            canonical = 'docker.io/library/' + short[1] + '@' + short[2]
            rule = 'docker-hub-official-shorthand'
        if canonical != expected_artifact_reference:
            _fail()
        # This verifies membership of the *original* spelling in RepoDigests,
        # plus original complete Config HMAC, immutable image and platform pins.
        defaults = derive_defaults(image, proof, key,
                                   expected_image_id=expected_image_id,
                                   expected_registry_digest=observed,
                                   expected_architecture=expected_architecture)
        binding = {'schemaVersion': 1, 'policy': policy, 'rule': rule,
                   'artifactReference': expected_artifact_reference,
                   'observedReference': observed, 'imageId': expected_image_id,
                   'architecture': expected_architecture,
                   'imageCommitment': deepcopy(proof),
                   'registryContactVerified': False, 'sourceProvenanceVerified': False,
                   'freshnessVerified': False, 'authorityGranted': False}
        material = json.dumps(binding, sort_keys=True, separators=(',', ':'),
                              ensure_ascii=True, allow_nan=False).encode('ascii')
        binding['referenceBindingDigest'] = hashlib.sha256(DOMAIN + material).hexdigest()
        return defaults, binding
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        _fail()
