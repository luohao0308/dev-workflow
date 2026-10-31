"""Authenticated same-image diagnostic composition; never an execution permit.

All identities, keys, commitments and policies are independently pinned host
inputs. The private result can contain secrets and must not enter public logs.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_restore_config import compile_restore_config, compile_restore_config_with_reference
from deployment_compose_restore_host_config import compile_restore_host_config
from deployment_compose_network_declaration import bind_network_declaration
from deployment_compose_snapshot import _encode
from deployment_compose_recipe import HEX, NAME

METADATA_POLICY = 'retain-observed-baseline-for-stopped-diagnostic-only'
RUNNING_METADATA_POLICY = 'retain-observed-baseline-for-isolated-restart-diagnostic-only'
DOMAIN = b'dev-workflow:compose-restore-body-diagnostic:v1\0'


def compile_restore_body(raw, identity, artifact, private_key, network_ids, expected_mounts,
                         image, image_commitment, image_key, declaration, declaration_proof,
                         declaration_key, *, expected_image_key_id, expected_declaration_key_id,
                         expected_declaration_hmac, expected_source_model_digest,
                         host_config_policy, metadata_policy, operation_nonce,
                         expected_observed_reference=None, reference_policy=None):
    """Reauthenticate all three fragments from one copied source before composition.

    This is a stopped-container diagnostic body, not a supported product write
    operation. Dynamic endpoint values and inferred origin claims are excluded.
    """
    try:
        if (type(metadata_policy) is not str or metadata_policy not in (METADATA_POLICY, RUNNING_METADATA_POLICY)
                or type(operation_nonce) is not str or not HEX.fullmatch(operation_nonce)):
            raise ValueError()
        (raw, identity, artifact, network_ids, expected_mounts, image, image_commitment,
         declaration, declaration_proof) = deepcopy((raw, identity, artifact, network_ids,
            expected_mounts, image, image_commitment, declaration, declaration_proof))
        service = identity['service']
        if type(service) is not str or not NAME.fullmatch(service):
            raise ValueError()
        name = 'dw-restore-' + operation_nonce[:24] + '-' + service
        if len(name) > 255 or name == identity['containerName']:
            raise ValueError()
        common = (raw, identity, artifact, private_key, network_ids, expected_mounts)
        image_args = (image, image_commitment, image_key)
        if expected_observed_reference is None and reference_policy is None:
            config = compile_restore_config(*common, *image_args,
                expected_image_key_id=expected_image_key_id)
        else:
            if expected_observed_reference is None or reference_policy is None:
                raise ValueError()
            config = compile_restore_config_with_reference(*common, *image_args,
                expected_image_key_id=expected_image_key_id,
                expected_observed_reference=expected_observed_reference, reference_policy=reference_policy)
        host = compile_restore_host_config(*common, policy=host_config_policy)
        network = bind_network_declaration(*common, declaration, declaration_proof,
            declaration_key, expected_key_id=expected_declaration_key_id,
            expected_declaration_hmac=expected_declaration_hmac,
            expected_source_model_digest=expected_source_model_digest)
        if (len({part['sourceSnapshotDigest'] for part in (config, host, network)}) != 1
                or config['sourceConfigHmac'] != artifact.config_hmac
                or host['sourceConfigHmac'] != artifact.config_hmac
                or {'HostConfig', 'NetworkingConfig'} & config['configFragment'].keys()
                or config['configFragment']['Image'] != artifact.image_id):
            raise ValueError()
        body = {**config['configFragment'], 'HostConfig': host['hostConfigFragment'],
                'NetworkingConfig': {'EndpointsConfig': network['networkFragment']}}
        result = {'schemaVersion': 1, 'kind': 'compose-same-image-restore-body-diagnostic',
            'identity': identity, 'originalFinalName': identity['containerName'],
            'sourceSnapshotDigest': config['sourceSnapshotDigest'],
            'sourceConfigHmac': artifact.config_hmac,
            'fragmentDigests': {key: part['fragmentDigest'] for key, part in
                               (('config', config), ('hostConfig', host), ('network', network))},
            'metadataPolicy': metadata_policy, 'operationNonce': operation_nonce,
            'temporaryName': name, 'method': 'POST',
            'path': '/v1.45/containers/create?name=' + name,
            'body': body, 'bodySha256': hashlib.sha256(_encode(body)).hexdigest(),
            'blockers': sorted(set().union(*(part['blockers'] for part in (config, host, network)))),
            'sourceModelProvenanceVerified': False, 'freshnessVerified': False,
            'daemonEffectiveDefaultsVerified': False, 'bindSourceTypesVerified': False,
            'diagnosticCreateBodyAvailable': True, 'completeCreatePayloadAvailable': False,
            'authorityGranted': False, 'executionAvailable': False,
            'reconstructionValidated': False, 'productionReady': False}
        result['compositionDigest'] = hashlib.sha256(DOMAIN + _encode(result)).hexdigest()
        _encode(result)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError, OverflowError):
        raise ValueError('compose-restore-body-diagnostic-rejected') from None


RETENTION_DOMAIN = b'dev-workflow:compose-retained-restore-body:v1\0'


def compile_retained_restore_body(recovery, reference, observer, observation, *, service, identity,
                                  private_key, network_ids, expected_mounts, image, image_commitment,
                                  image_key, declaration, declaration_proof, declaration_key,
                                  expected_image_key_id, expected_declaration_key_id,
                                  expected_declaration_hmac, expected_source_model_digest,
                                  host_config_policy, metadata_policy, operation_nonce,
                                  expected_observed_reference=None, reference_policy=None):
    """Compose only an exact retained source, preserving its separate archive binding."""
    from deployment_compose_recovery_host import ComposeRecoveryHost
    try:
        if type(recovery) is not ComposeRecoveryHost:
            raise ValueError()
        identity = deepcopy(identity)
        raw, artifact = recovery.read_source(reference, observer, observation, service=service, identity=identity)
        candidate = compile_restore_body(raw, identity, artifact, private_key, network_ids, expected_mounts,
            image, image_commitment, image_key, declaration, declaration_proof, declaration_key,
            expected_image_key_id=expected_image_key_id,
            expected_declaration_key_id=expected_declaration_key_id,
            expected_declaration_hmac=expected_declaration_hmac,
            expected_source_model_digest=expected_source_model_digest,
            host_config_policy=host_config_policy, metadata_policy=metadata_policy,
            operation_nonce=operation_nonce, expected_observed_reference=expected_observed_reference,
            reference_policy=reference_policy)
        again, again_artifact = recovery.read_source(reference, observer, observation,
                                                    service=service, identity=identity)
        if _encode(again) != _encode(raw) or again_artifact != artifact:
            raise ValueError()
        binding = {'archiveReference': reference, 'compositionDigest': candidate['compositionDigest'],
                   'bodySha256': candidate['bodySha256']}
        binding['bindingDigest'] = hashlib.sha256(RETENTION_DOMAIN + _encode(binding)).hexdigest()
        return {'candidate': candidate, 'retentionBinding': binding}
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError, OverflowError):
        raise ValueError('retained-restore-body-rejected') from None
