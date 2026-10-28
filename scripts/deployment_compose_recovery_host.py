"""Retain authenticated original Compose specs before review; no recovery executor.

The store contains secrets and belongs exclusively to the host. Committed private
projections are preserved intact rather than claiming that a target recipe can
represent every original Engine field. Optional recipes must match the closed
value subset; real Engine reconstruction remains unverified.
"""
from copy import deepcopy
from dataclasses import asdict
import hmac
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_observation_host import ComposeObservationHost
from deployment_compose_private import commit
from deployment_compose_baseline_recipe import verify_baseline_recipe
from deployment_compose_proof_host import canonical
from deployment_compose_operations import BaselineContainer
from deployment_compose_recovery_store import ComposeRecoveryStore


class ComposeRecoveryHost:
    def __init__(self, *, store, observer, baseline, projections, private_keys, recipes=None):
        if (type(store) is not ComposeRecoveryStore or type(observer) is not ComposeObservationHost
                or type(baseline) is not tuple or not baseline
                or any(type(x) is not BaselineContainer for x in baseline)
                or type(projections) is not dict or type(private_keys) is not dict):
            raise ValueError('invalid-recovery-host')
        names = tuple(x.service for x in baseline)
        artifacts = observer._baseline_artifacts
        scope = observer._policy
        if (names != tuple(x.service for x in artifacts.services)
                or set(projections) != set(names)
                or scope.get('selectedContainerIds') != {x.service: x.container_id for x in baseline}
                or any(scope.get('containerNames', {}).get(x.service) != x.final_name
                       for x in baseline)
                or any(x.image_id != y.image_id for x, y in zip(baseline, artifacts.services))):
            raise ValueError('recovery-baseline-scope-mismatch')
        # Validate before copying: commit bounds the full private JSON tree.
        for item in artifacts.services:
            try:
                actual = commit(scope['project'], item.service, projections[item.service],
                                item.config_key_id, private_keys[item.config_key_id])
            except (ValueError, KeyError, TypeError):
                raise ValueError('recovery-config-rejected') from None
            if not hmac.compare_digest(actual['configHmac'], item.config_hmac):
                raise ValueError('recovery-config-rejected')
        if recipes is not None:
            if type(recipes) is not dict or set(recipes) != set(names):
                raise ValueError('recovery-recipe-scope-mismatch')
            for item in baseline:
                verify_baseline_recipe(projections[item.service], recipes[item.service],
                    project=scope['project'], service=item.service,
                    container_name=item.final_name, image_id=item.image_id)
        self._recipes = deepcopy(recipes)
        self._store, self._observer, self._baseline = store, observer, baseline
        self._projections = deepcopy(projections)
        self._artifacts = artifacts
        self._project = scope['project']
        self._daemon = scope.get('daemonId')
        if type(self._daemon) is not str or not self._daemon:
            raise ValueError('invalid-recovery-host')

    def _payload(self, observer, observation):
        if observer is not self._observer or observer._baseline_artifacts != self._artifacts:
            raise ValueError('recovery-observer-mismatch')
        observation_hash = observer.commitment(observation)
        return canonical({'schemaVersion': 1, 'kind': 'compose-committed-baseline',
            'project': self._project, 'daemonId': self._daemon,
            'observationHash': observation_hash, 'baselineDigest': self._artifacts.digest(),
            'artifacts': asdict(self._artifacts),
            'containers': [asdict(x) for x in self._baseline],
            'privateProjections': self._projections, 'recoveryRecipes': self._recipes,
            'recipeEquivalenceVerified': self._recipes is not None,
            'reconstructionValidated': False, 'executionAvailable': False})

    def retain(self, observation):
        """Persist old private specs; return only an authenticated archive reference."""
        payload = self._payload(self._observer, observation)
        reference = self._store.put(payload)
        if self._store.get(reference) != payload:
            raise ValueError('recovery-archive-mismatch')
        self._observer.commitment(observation)
        return reference

    def verify(self, reference, observer, observation, *, require_recipe_equivalence=False):
        """Require retained bytes to still exist; never recreate a missing archive."""
        if require_recipe_equivalence and self._recipes is None:
            raise ValueError('verified-baseline-recipes-required')
        expected = self._payload(observer, observation)
        if self._store.get(reference) != expected:
            raise ValueError('recovery-archive-mismatch')
        observer.commitment(observation)
        return reference

    def verify_target_configuration(self, target_recipes):
        """The first batch profile changes image identity only, not configuration."""
        if (self._recipes is None or type(target_recipes) is not dict
                or set(target_recipes) != set(self._recipes)):
            raise ValueError('verified-baseline-recipes-required')
        for service, baseline_recipe in self._recipes.items():
            target_recipe = target_recipes[service]
            if type(target_recipe) is not dict:
                raise ValueError('target-config-change-not-supported')
            old = {k: v for k, v in baseline_recipe.items() if k != 'imageId'}
            new = {k: v for k, v in target_recipe.items() if k != 'imageId'}
            if canonical(old) != canonical(new):
                raise ValueError('target-config-change-not-supported')
