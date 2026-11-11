"""Host-bound profile-2 create preparation, not approval or a complete plan.

All constructor inputs come from trusted host configuration. Public review
material contains hashes and identities; private derivations may contain Env.
No legacy target conversion, approval consumption, Permit or transport exists.
"""
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_contract_v2 import RequestV2, SourceIdentity, TargetIdentity
from deployment_compose_observation_host import ComposeObservationHost
from deployment_compose_operations import BaselineContainer, _topological
from deployment_compose_target_v2 import ComposeTargetArtifactsV2, PROFILE, PROFILE_VERSION
from deployment_compose_temporary import derive_temporary, verify_temporary_operation
from deployment_compose_create import _encode
from deployment_compose_recipe import HEX, NAME
from deployment_compose_recipe_v3 import canonical_recipe_v3

DOMAIN = b'dev-workflow:compose-create-preparation:v2\0'
SYMBOLIC_PLAN_DOMAIN = b'dev-workflow:compose-symbolic-plan:v2\0'
MAX_BYTES = 3 * 1024 * 1024
INPUT_FIELDS = {'baseline_image_id', 'image_defaults', 'identity', 'network_ids', 'allowed_mounts', 'hostname'}


def fail():
    raise ValueError('compose-preparation-v2-rejected')


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False).encode('ascii')
    if len(raw) > MAX_BYTES:
        fail()
    return raw


class ComposePreparationHostV2:
    def __init__(self, *, observer, baseline, target, recipes, recipe_keys, creation_inputs,
                 dependencies, source, target_identity, host_id, daemon_id, environment,
                 production, policy_hash, protected_names):
        try:
            if (type(observer) is not ComposeObservationHost or observer.scope_kind != 'whole-project'
                    or type(target) is not ComposeTargetArtifactsV2
                    or type(source) is not SourceIdentity or type(target_identity) is not TargetIdentity
                    or target_identity.runtime != 'compose' or type(baseline) is not tuple
                    or not 1 <= len(baseline) <= 32 or any(type(x) is not BaselineContainer for x in baseline)
                    or any(type(x) is not str or not NAME.fullmatch(x) for x in (host_id, environment))
                    or type(daemon_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}', daemon_id)
                    or type(production) is not bool or type(policy_hash) is not str or not HEX.fullmatch(policy_hash)):
                fail()
            services = tuple(item.service for item in target.services)
            scope = observer._policy
            if (tuple(item.service for item in baseline) != services
                    or tuple(scope.get('selectedServices', ())) != services
                    or scope.get('project') != target_identity.namespace or scope.get('daemonId') != daemon_id
                    or scope.get('selectedContainerIds') != {item.service: item.container_id for item in baseline}
                    or any(scope.get('containerNames', {}).get(x.service) != x.final_name for x in baseline)
                    or tuple(x.service for x in observer._baseline_artifacts.services) != services
                    or len({x.container_id for x in baseline}) != len(baseline)
                    or any(x.image_id != y.image_id for x, y in zip(baseline, observer._baseline_artifacts.services))
                    or any(item.source_sha != source.source_sha for item in target.services)
                    or type(recipes) is not dict or set(recipes) != set(services)
                    or type(creation_inputs) is not dict or set(creation_inputs) != set(services)
                    or type(recipe_keys) is not dict or set(recipe_keys) != {x.recipe_key_id for x in target.services}
                    or any(type(key) is not bytes or not 32 <= len(key) <= 4096 for key in recipe_keys.values())):
                fail()
            order = _topological(services, dependencies)
            protected = scope.get('protectedServices')
            if (type(protected) is not list or len(protected) > 128
                    or type(protected_names) is not dict or set(protected_names) != set(protected)
                    or any(type(name) is not str or not NAME.fullmatch(name) for name in protected_names.values())):
                fail()
            all_names = [x.final_name for x in baseline] + list(protected_names.values())
            if len(set(all_names)) != len(all_names):
                fail()
            for item in baseline:
                inputs = creation_inputs[item.service]
                canonical_recipe_v3(recipes[item.service])
                if (type(inputs) is not dict or set(inputs) != INPUT_FIELDS
                        or inputs['baseline_image_id'] != item.image_id
                        or type(inputs['identity']) is not dict
                        or inputs['identity'].get('hostId') != host_id
                        or inputs['identity'].get('daemonId') != daemon_id):
                    fail()
                _encode(inputs)
            self._observer, self._target, self._baseline = observer, target, baseline
            self._source, self._target_identity = source, target_identity
            self._host, self._daemon, self._environment = host_id, daemon_id, environment
            self._production, self._policy = production, policy_hash
            self._recipes, self._keys, self._inputs = deepcopy((recipes, recipe_keys, creation_inputs))
            self._dependencies, self._protected_names = deepcopy((dependencies, protected_names))
            self._order, self._scope = order, deepcopy(scope)
            self._baseline_digest = observer._baseline_artifacts.digest()
        except Exception:
            raise ValueError('compose-preparation-v2-rejected') from None

    def prepare(self, observation, *, operation_nonce, expires_at):
        try:
            if type(operation_nonce) is not str or not HEX.fullmatch(operation_nonce):
                fail()
            if (encode(self._observer._policy) != encode(self._scope)
                    or self._observer._baseline_artifacts.digest() != self._baseline_digest):
                fail()
            before = self._observer._baseline_artifacts.digest()
            observation_hash = self._observer.commitment(observation)
            # This value is scope validation only, not a reviewed Request or
            # the return value. The complete operation plan does not yet exist.
            scope = RequestV2(2, 'deploy', PROFILE, PROFILE_VERSION, self._source,
                self._target_identity, self._environment, self._production, self._daemon,
                tuple(x.service for x in self._target.services), tuple(self._scope['protectedServices']),
                before, self._target.digest(), self._target.digest(), observation_hash, None,
                self._host, '0' * 64, self._policy, expires_at, 1)
            now = datetime.now(timezone.utc)
            scope.ensure_fresh(now)
            if (datetime.strptime(expires_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) - now).total_seconds() > 3600:
                fail()
            old = {x.service: x for x in self._baseline}
            targets = {x.service: x for x in self._target.services}
            derivations, entries, aliases, candidate_blockers = {}, [], set(), set()
            occupied = {x.final_name for x in self._baseline} | set(self._protected_names.values())
            for index, service in enumerate(self._order):
                item, original = targets[service], old[service]
                inputs = self._inputs[service]
                defaults = inputs['image_defaults']
                if (type(defaults) is not dict or defaults.get('Os') != item.os
                        or defaults.get('Architecture') != item.architecture
                        or defaults.get('ImageId') != item.image_id):
                    fail()
                pins = dict(key=self._keys[item.recipe_key_id], expected_key_id=item.recipe_key_id,
                    expected_recipe_hmac=item.recipe_hmac, expected_project=self._target_identity.namespace,
                    expected_service=service, expected_final_name=original.final_name,
                    operation_nonce=operation_nonce, **inputs)
                commitment = {'keyId': item.recipe_key_id, 'hmac': item.recipe_hmac}
                derivation = derive_temporary(self._recipes[service], commitment, **pins)
                if derivation['temporaryName'] in occupied:
                    fail()
                occupied.add(derivation['temporaryName'])
                for network in self._recipes[service]['networks']:
                    for alias in network['aliases']:
                        identity = (network['id'], alias)
                        if identity in aliases:
                            fail()
                        aliases.add(identity)
                candidate = derivation['candidate']
                candidate_blockers.update(candidate['validationBlockers'])
                body_hash = hashlib.sha256(_encode(candidate['body'])).hexdigest()
                operation = (candidate['method'], candidate['path'], body_hash)
                verify_temporary_operation(derivation, self._recipes[service], commitment, operation=operation, **pins)
                derivations[service] = derivation
                entries.append({'createIndex': index, 'service': service, 'recipeSchemaVersion': 3,
                    'recipeKeyId': item.recipe_key_id, 'recipeHmac': item.recipe_hmac,
                    'finalName': original.final_name, 'temporaryName': derivation['temporaryName'],
                    'derivationDigest': derivation['derivationDigest'], 'candidateDigest': candidate['candidateDigest'],
                    'method': operation[0], 'path': operation[1], 'canonicalBodySha256': body_hash})
            review = {'schemaVersion': 2, 'kind': 'compose-create-preparation',
                'profileId': PROFILE, 'profileVersion': PROFILE_VERSION, 'recipeSchemaVersion': 3,
                'scope': asdict(scope), 'operationNonce': operation_nonce,
                'dependencies': {name: list(self._dependencies[name]) for name in sorted(self._dependencies)},
                'protectedNames': self._protected_names, 'createEntries': entries,
                'indexScope': 'create-prefix-only', 'completeOperationPlan': False,
                'scopeIsApprovalRequest': False,
                'approvalConsumptionAvailable': False, 'authorityGranted': False, 'executionAvailable': False,
                'productionReady': False, 'replaySafe': False, 'reconstructionValidated': False,
                'quiescenceProven': False, 'nextGenerationAuthorized': False, 'sequencingEnforced': False,
                'blockers': ['complete-operation-plan-required', 'profile2-approval-proof-integration-required',
                    'v3-baseline-reconstruction-required', 'fresh-image-and-build-provenance-required',
                    'temporary-name-gateway-support-required', 'independent-anchor-required',
                    'step-sequencing-authority-required', 'recovery-authorization-required']}
            review['blockers'] = sorted(set(review['blockers']) | candidate_blockers)
            review['preparationDigest'] = hashlib.sha256(DOMAIN + encode(review)).hexdigest()
            # Recheck both issued observation and host policy after all work.
            if (self._observer.commitment(observation) != observation_hash
                    or encode(self._observer._policy) != encode(self._scope)
                    or self._observer._baseline_artifacts.digest() != self._baseline_digest):
                fail()
            scope.ensure_fresh(datetime.now(timezone.utc))
            return deepcopy({'review': review, 'derivations': derivations})
        except Exception:
            raise ValueError('compose-preparation-v2-rejected') from None

    def verify(self, prepared, observation, *, operation_nonce, expires_at):
        try:
            expected = self.prepare(observation, operation_nonce=operation_nonce, expires_at=expires_at)
            if type(prepared) is not dict or encode(prepared) != encode(expected):
                fail()
        except Exception:
            raise ValueError('compose-preparation-v2-rejected') from None

    def prepare_with_symbolic_plan(self, observation, *, operation_nonce, expires_at):
        """Describe all phases without resolving candidate IDs or authorizing writes.

        Candidate references identify an authenticated derivation, never a name
        lookup. A later receipt-bound generation must resolve them before use.
        """
        try:
            prepared = self.prepare(observation, operation_nonce=operation_nonce, expires_at=expires_at)
            original = deepcopy(prepared)
            review = prepared['review']
            creates = {entry['service']: entry for entry in review['createEntries']}
            old = {item.service: item for item in self._baseline}
            steps = []

            def append(phase, service, **values):
                index = len(steps)
                steps.append(dict(globalIndex=index, predecessorIndex=index - 1 if index else None,
                    phase=phase, service=service, **values))

            def candidate_reference(service):
                entry = creates[service]
                return {'kind': 'unresolved-create-receipt', 'service': service,
                    'createIndex': entry['createIndex'], 'candidateDigest': entry['candidateDigest'],
                    'derivationDigest': entry['derivationDigest'],
                    'canonicalBodySha256': entry['canonicalBodySha256']}

            for service in self._order:
                append('create', service, createEntry=deepcopy(creates[service]))
            for phase in ('stop-old', 'remove-old'):
                for service in reversed(self._order):
                    append(phase, service, oldContainerId=old[service].container_id,
                        finalName=old[service].final_name,
                        **({'force': False, 'removeVolumes': False} if phase == 'remove-old' else {}))
            for service in self._order:
                append('rename-candidate', service, candidateReference=candidate_reference(service),
                    finalName=old[service].final_name)
            for service in self._order:
                for phase in ('start-candidate', 'readiness'):
                    append(phase, service, candidateReference=candidate_reference(service),
                        finalName=old[service].final_name)
            plan = {'schemaVersion': 1, 'kind': 'compose-profile2-symbolic-phase-plan',
                'preparationDigest': original['review']['preparationDigest'],
                'scope': deepcopy(review['scope']), 'operationNonce': operation_nonce,
                'dependencies': deepcopy(review['dependencies']),
                'protectedIdentities': {'containerNames': deepcopy(self._protected_names),
                    'containerIds': deepcopy(self._scope.get('protectedContainerIds', {})),
                    'imageIds': {name: self._scope['imageIds'][name] for name in self._protected_names},
                    'configHmacs': deepcopy(self._scope.get('protectedConfigHmacs', {})),
                    'observationHash': review['scope']['observation_hash']},
                'baseline': [asdict(item) for item in self._baseline], 'steps': steps,
                'symbolicPhaseCoverageComplete': True, 'completeOperationPlan': False,
                'protectedContainerIdsVerified': 'protectedContainerIds' in self._scope,
                'executionAvailable': False, 'authorityGranted': False}
            plan_hash = hashlib.sha256(SYMBOLIC_PLAN_DOMAIN + encode(plan)).hexdigest()
            review.pop('preparationDigest')
            review.update(kind='compose-create-preparation-with-symbolic-plan', symbolicPlan=plan,
                symbolicPlanHash=plan_hash, symbolicPhaseCoverageComplete=True)
            review['blockers'] = sorted(set(review['blockers']) | {
                'receipt-resolved-candidate-ids-required', 'receipt-bound-generation-required',
                'complete-profile2-approval-request-required', 'protected-container-ids-required'})
            if plan['protectedContainerIdsVerified']:
                review['blockers'].remove('protected-container-ids-required')
            review['preparationDigest'] = hashlib.sha256(DOMAIN + encode(review)).hexdigest()
            # Fresh preparation repeats observation, policy, baseline and expiry
            # checks and compares the authenticated inputs after phase assembly.
            fresh = self.prepare(observation, operation_nonce=operation_nonce, expires_at=expires_at)
            if encode(fresh) != encode(original):
                fail()
            return deepcopy(prepared)
        except Exception:
            raise ValueError('compose-preparation-v2-rejected') from None

    def verify_with_symbolic_plan(self, prepared, observation, *, operation_nonce, expires_at):
        try:
            expected = self.prepare_with_symbolic_plan(observation, operation_nonce=operation_nonce,
                expires_at=expires_at)
            if type(prepared) is not dict or encode(prepared) != encode(expected):
                fail()
        except Exception:
            raise ValueError('compose-preparation-v2-rejected') from None

    def prepare_with_recovery(self, observation, *, operation_nonce, expires_at, recovery, reference):
        """Bind retained original bytes and closed v3 values, not Engine recovery."""
        from deployment_compose_recovery_v3_host import ComposeRecoveryHostV3
        try:
            if type(recovery) is not ComposeRecoveryHostV3:
                fail()
            archive = recovery.verify(reference, self._observer, observation)
            recovery.verify_target_configuration(self._recipes)
            prepared = self.prepare(observation, operation_nonce=operation_nonce, expires_at=expires_at)
            # Recheck retention/configuration after source preparation too.
            recovery.verify(reference, self._observer, observation)
            recovery.verify_target_configuration(self._recipes)
            review = prepared['review']
            review.pop('preparationDigest')
            review.update(kind='compose-create-preparation-with-v3-retention',
                recoveryArchiveReference=archive, recoveryRecipeSchemaVersion=3,
                recoveryValueComparison='closed-v3-subset')
            # v3-baseline-reconstruction-required remains: value matching is
            # deliberately weaker than a successful Engine reconstruction.
            review['preparationDigest'] = hashlib.sha256(DOMAIN + encode(review)).hexdigest()
            self._observer.commitment(observation)
            if (encode(self._observer._policy) != encode(self._scope)
                    or self._observer._baseline_artifacts.digest() != self._baseline_digest):
                fail()
            RequestV2.from_json(encode(review['scope']).decode('ascii')).ensure_fresh(datetime.now(timezone.utc))
            return prepared
        except Exception:
            raise ValueError('compose-preparation-v2-rejected') from None

    def verify_with_recovery(self, prepared, observation, *, operation_nonce, expires_at, recovery, reference):
        try:
            expected = self.prepare_with_recovery(observation, operation_nonce=operation_nonce,
                expires_at=expires_at, recovery=recovery, reference=reference)
            if type(prepared) is not dict or encode(prepared) != encode(expected):
                fail()
        except Exception:
            raise ValueError('compose-preparation-v2-rejected') from None
