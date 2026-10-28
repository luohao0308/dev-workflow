"""Prepare a new rollback intent from a completely successful signed deployment.

Private archive material never enters the review. This is request preparation,
not crash recovery or execution authority; approval and startup fencing remain
required for the newly prepared request.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json

from deployment_compose_prepare_v3_host import ComposePreparationHostV3
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_history_v3_host import AuthenticatedHistoryV3, pairs
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_artifacts import ComposeArtifacts
from deployment_compose_snapshot import prepare_snapshot
from deployment_compose_baseline_recipe import verify_baseline_recipe
from deployment_compose_operation_witness_client_v3 import hex_value
from deployment_compose_operations import BaselineContainer
from deployment_contract_v2 import RequestV2
from deployment_compose_coordinator_v3_host import canonical


def reject():
    raise ValueError('compose-rollback-preparation-v3-rejected')


class RollbackPreparationHostV3:
    def __init__(self, *, original_bundle, original_request, original_history,
                 original_archive_store, original_private_keys, current_preparation):
        if (type(original_bundle) is not ExecutionBundleV3
                or type(original_request) is not RequestV2
                or original_request.operation != 'deploy'
                or type(original_history) is not AuthenticatedHistoryV3
                or type(original_archive_store) is not ComposeRecoveryStore
                or type(current_preparation) is not ComposePreparationHostV3
                or type(original_private_keys) is not dict
                or any(type(k) is not str or type(v) is not bytes or len(v) < 32
                       for k, v in original_private_keys.items())
                or original_request.plan_hash != original_bundle.digest
                or original_history._bundle.canonical_bytes != original_bundle.canonical_bytes
                or original_history._request.digest() != original_request.digest()):
            reject()
        self._bundle, self._request, self._history = original_bundle, original_request, original_history
        self._store, self._keys = original_archive_store, deepcopy(original_private_keys)
        self._current = current_preparation

    def _history_capture(self):
        snapshot = self._history.capture()
        value = json.loads(snapshot.canonical)
        original = self._bundle.to_dict()
        receipts = value['receiptMap']
        expected = [op for op in self._bundle.resolve_operations(receipts) if op['method'] != 'GET']
        if (value['bundleDigest'] != self._bundle.digest
                or value['originalRequestHash'] != self._request.digest()
                or value['sourceArchiveRef'] != original['archiveReference']
                or value['blocker'] is not None or value['pending'] is not None
                or value['closedTail'] is None
                or set(receipts) != {s['name'] for s in original['services']}
                or canonical(value['knownPrefix']) != canonical(expected)
                or len(value['scopes']) != len(expected)):
            reject()
        return snapshot, value

    def _archive(self):
        original = self._bundle.to_dict()
        raw = self._store.get(original['archiveReference'])
        value = json.loads(raw, object_pairs_hook=pairs)
        fields = {'schemaVersion','kind','project','daemonId','observationHash','baselineDigest',
                  'artifacts','containers','privateProjections','recoveryRecipes',
                  'recipeEquivalenceVerified','reconstructionValidated','executionAvailable'}
        if (type(value) is not dict or set(value) not in (fields, fields | {'observationScope'})
                or canonical(value) != raw or type(value['schemaVersion']) is not int
                or value['schemaVersion'] != 1 or value['kind'] != 'compose-committed-baseline'
                or not hex_value(value['observationHash'])
                or value['project'] != original['identity']['project']
                or value['daemonId'] != original['identity']['daemonId']
                or value['reconstructionValidated'] is not False or value['executionAvailable'] is not False
                or type(value['recipeEquivalenceVerified']) is not bool
                or value['recipeEquivalenceVerified'] is not (value['recoveryRecipes'] is not None)):
            reject()
        artifacts = ComposeArtifacts.from_json(canonical(value['artifacts']).decode('ascii'))
        names = {s['name'] for s in original['services']}
        if (artifacts.digest() != value['baselineDigest'] or artifacts.digest() != self._request.before_hash
                or {a.service for a in artifacts.services} != names
                or type(value['privateProjections']) is not dict or set(value['privateProjections']) != names
                or type(value['containers']) is not list or len(value['containers']) != len(names)):
            reject()
        containers = [BaselineContainer(**row) for row in value['containers']]
        expected_containers = [BaselineContainer(s['name'],s['baselineContainerId'],s['finalName'],s['baselineImageId'])
                               for s in original['services']]
        if canonical(value['containers']) != canonical([dict(service=b.service,container_id=b.container_id,
                final_name=b.final_name,image_id=b.image_id) for b in expected_containers]):
            reject()
        if 'observationScope' in value:
            scope = value['observationScope']
            if (type(scope) is not dict or set(scope) != {'kind','containerIds','projectCompletenessVerified'}
                    or scope['kind'] != 'pinned-containers'
                    or scope['containerIds'] != [b.container_id for b in containers]
                    or scope['projectCompletenessVerified'] is not False):
                reject()
        if value['recoveryRecipes'] is not None:
            if type(value['recoveryRecipes']) is not dict or set(value['recoveryRecipes']) != names:
                reject()
        for service, artifact in zip(original['services'], artifacts.services):
            name = service['name']; projection = value['privateProjections'][name]
            if type(projection) is not dict or set(projection) != {'Config','HostConfig','NetworkSettings','Mounts'}:
                reject()
            if value['recoveryRecipes'] is not None:
                verify_baseline_recipe(projection,value['recoveryRecipes'][name],project=value['project'],
                    service=name,container_name=service['finalName'],image_id=service['baselineImageId'])
            target = self._current._target_inputs[name]
            if (target['expected_image_id'] != artifact.image_id
                    or target['expected_registry_digest'] != artifact.registry_digest
                    or target['expected_architecture'] != artifact.architecture):
                reject()
            body = service['baselineCreateBody']
            identity = deepcopy(self._current._source_inputs[name]['identity'])
            identity.update(hostId=original['identity']['hostId'],daemonId=value['daemonId'],project=value['project'],
                service=name,containerId=service['baselineContainerId'],containerName=service['finalName'],imageId=service['baselineImageId'])
            mounts = {m['Target']:dict(type=m['Type'],source=m['Source'],readOnly=m.get('ReadOnly',False))
                      for m in body['HostConfig']['Mounts']}
            networks = {n:e['NetworkID'] for n,e in body['NetworkingConfig']['EndpointsConfig'].items()}
            inspected = dict(Id=service['baselineContainerId'],Name='/'+service['finalName'],Image=service['baselineImageId'],**deepcopy(projection))
            prepare_snapshot(inspected, identity, artifact, self._keys[artifact.config_key_id], networks, mounts)
            config = deepcopy(projection['Config'])
            if config['Image'] not in (artifact.image_id, artifact.registry_digest): reject()
            config['Image'] = artifact.image_id
            reconstructed = dict(config,HostConfig=projection['HostConfig'],NetworkingConfig=body['NetworkingConfig'])
            if canonical(reconstructed) != canonical(body): reject()
            for net, endpoint in body['NetworkingConfig']['EndpointsConfig'].items():
                observed = projection['NetworkSettings']['Networks'][net]
                if (canonical(observed['Aliases']) != canonical(endpoint['Aliases'])
                        or any(observed[k] is not None for k in ('IPAMConfig','Links','DriverOpts'))
                        or ('GwPriority' in observed and canonical(observed['GwPriority']) != b'0')):
                    reject()
        return raw

    def prepare_intent(self, current_whole_observation, current_retention_observation, *, operation_nonce, expires_at):
        try:
            history, signed = self._history_capture()
            archive = self._archive()
            prepared = self._current.prepare_intent(current_whole_observation,current_retention_observation,
                operation_nonce=operation_nonce,expires_at=expires_at)
            original, current = self._bundle.to_dict(), prepared['bundle'].to_dict()
            for key in ('protectedContainers','networks','mounts'):
                if canonical(original[key]) != canonical(current[key]): reject()
            for key in ('hostId','daemonId','project'):
                if original['identity'][key] != current['identity'][key]: reject()
            if len(original['services']) != len(current['services']): reject()
            for old, new in zip(original['services'],current['services']):
                if (any(canonical(old[k]) != canonical(new[k]) for k in ('name','finalName','dependsOn'))
                        or new['baselineContainerId'] != signed['receiptMap'][old['name']]
                        or new['baselineImageId'] != old['targetImageId']
                        or new['targetImageId'] != old['baselineImageId']
                        or canonical(new['baselineCreateBody']) != canonical(old['targetCreateBody'])
                        or canonical(new['targetCreateBody']) != canonical(old['baselineCreateBody'])):
                    reject()
            request = replace(prepared['request'],operation='rollback',history_hash=history.digest)
            request.ensure_fresh(datetime.now(timezone.utc))
            review = deepcopy(prepared['review'])
            review.update(requestDigest=request.digest(),historyDigest=history.digest,operation='rollback',runtimePermit=False)
            review['blockers'] = sorted(set(review['blockers']) | {'fresh-profile3-github-approval-required','startup-fence-required'})
            if self._archive() != archive or self._history_capture()[0].canonical != history.canonical:
                reject()
            return dict(bundle=prepared['bundle'],request=request,review=review)
        except Exception:
            reject()
