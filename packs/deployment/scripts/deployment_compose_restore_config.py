"""Private, same-image Config fragment; never a complete Engine request.

Inputs are host-pinned observations and image commitments. This preserves
observed lifecycle metadata for baseline analysis only; it does not authorize
reusing that metadata or establish freshness, reconstruction, or write safety.
"""
from copy import deepcopy
import hashlib

from deployment_compose_image_defaults import derive_defaults
from deployment_compose_image_reference import derive_bound_defaults
from deployment_compose_recipe import ENV_NAME, NAME
from deployment_compose_snapshot import _encode, prepare_snapshot

DOMAIN = b'dev-workflow:compose-restore-config-fragment:v1\0'
REFERENCE_DOMAIN = b'dev-workflow:compose-restore-config-fragment:v2\0'


def _fail():
    raise ValueError('invalid-compose-restore-config-fragment')


def compile_restore_config(raw, identity, artifact, private_key, network_ids,
                           expected_mounts, image, image_commitment, image_key,
                           *, expected_image_key_id):
    """Reauthenticate full source and image before deriving a private fragment.

    The expected key identity, topology and artifact must come independently
    from the host. Returned digests are content bindings, not authorization.
    """
    try:
        return _compile(raw, identity, artifact, private_key, network_ids,
                        expected_mounts, image, image_commitment, image_key,
                        expected_image_key_id)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        _fail()


def compile_restore_config_with_reference(raw, identity, artifact, private_key,
                                          network_ids, expected_mounts, image,
                                          image_commitment, image_key, *,
                                          expected_image_key_id,
                                          expected_observed_reference,
                                          reference_policy):
    """Explicit schema2 fragment with authenticated original reference binding.

    No changes are made to the exact-reference schema1 entry point or image
    catalog. This remains private baseline analysis, with all write gates shut.
    """
    try:
        return _compile(raw, identity, artifact, private_key, network_ids,
                        expected_mounts, image, image_commitment, image_key,
                        expected_image_key_id,
                        reference_options={'expected_observed_reference': expected_observed_reference,
                                           'policy': reference_policy})
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        _fail()


def _compile(raw, identity, artifact, private_key, network_ids, expected_mounts,
             image, proof, image_key, expected_key, *, reference_options=None):
    snapshot = prepare_snapshot(raw, identity, artifact, private_key,
                                network_ids, expected_mounts)
    if (type(expected_key) is not str or not NAME.fullmatch(expected_key)
            or type(proof) is not dict or proof.get('keyId') != expected_key):
        _fail()
    if reference_options is None:
        defaults = derive_defaults(image, proof, image_key,
                                   expected_image_id=artifact.image_id,
                                   expected_registry_digest=artifact.registry_digest,
                                   expected_architecture=artifact.architecture)
        binding = None
    else:
        defaults, binding = derive_bound_defaults(image, proof, image_key,
                                   expected_key_id=expected_key,
                                   expected_image_id=artifact.image_id,
                                   expected_artifact_reference=artifact.registry_digest,
                                   expected_architecture=artifact.architecture,
                                   **reference_options)
    config = deepcopy(snapshot['config']['rawConfig'])
    accepted_references = (artifact.image_id, artifact.registry_digest)
    if binding is not None:
        accepted_references += (binding['observedReference'],)
    if config['Image'] not in accepted_references:
        _fail()
    # No additional image collections may be silently inherited. Nonempty
    # image health defaults can also change omitted/zero timing fields.
    for field in ('Labels', 'Volumes', 'ExposedPorts', 'Healthcheck'):
        if defaults[field] is not None and defaults[field] != {}:
            _fail()
    if defaults['StopSignal'] != '':
        _fail()
    for field in ('User', 'WorkingDir'):
        if config[field] == '' and defaults[field] != '':
            _fail()
    # Reject ambiguous reset/inheritance argv forms. Preserve null entrypoint
    # only when the pinned image has exactly the same null entrypoint.
    for field in ('Cmd', 'Entrypoint'):
        vector = config[field]
        if field == 'Entrypoint' and vector is None and defaults[field] is None:
            continue
        if type(vector) is not list or not vector or any(not item for item in vector):
            _fail()
    env = defaults['Env']
    if env is not None:
        if type(env) is not list or len(env) > 128:
            _fail()
        keys = []
        for item in env:
            if type(item) is not str or len(item) > 8192 or '\0' in item:
                _fail()
            key, separator, _ = item.partition('=')
            if not separator or not ENV_NAME.fullmatch(key):
                _fail()
            keys.append(key)
        if len(keys) != len(set(keys)) or not set(keys) <= {e.partition('=')[0] for e in config['Env']}:
            _fail()
    original_image = config['Image']
    config['Image'] = artifact.image_id
    result = {
        'schemaVersion': 1, 'kind': 'compose-same-image-restore-config-fragment',
        'sourceSnapshotDigest': hashlib.sha256(_encode(snapshot)).hexdigest(),
        'sourceConfigHmac': artifact.config_hmac,
        'imageCommitment': deepcopy(proof),
        'imageDefaultsDigest': hashlib.sha256(_encode(defaults)).hexdigest(),
        'configFragment': config,
        'imageReferenceRewrite': {'from': original_image, 'to': artifact.image_id},
        'metadataPolicy': 'retain-observed-baseline-values-origin-unverified',
        'blockers': ['complete-host-and-network-create-semantics-required',
                     'hostname-and-lifecycle-metadata-policy-required',
                     'fresh-source-image-bind-and-daemon-evidence-required',
                     'independent-engine-reconstruction-required',
                     'trusted-approval-writer-and-independent-anchor-required'],
        'completeCreatePayloadAvailable': False, 'authorityGranted': False,
        'executionAvailable': False, 'reconstructionValidated': False,
        'productionReady': False,
    }
    domain = DOMAIN
    if binding is not None:
        result['schemaVersion'] = 2
        result['kind'] = 'compose-same-image-restore-config-fragment-with-reference'
        result['referenceBinding'] = binding
        domain = REFERENCE_DOMAIN
    result['fragmentDigest'] = hashlib.sha256(domain + _encode(result)).hexdigest()
    return result
