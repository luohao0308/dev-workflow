"""Authenticated original retention plus closed v3 value checks, no recovery writer.

Original inspect bytes are never normalized for retention. Passing the recipe
comparison does not establish Engine reconstruction, antirollback or authority.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'))
from deployment_compose_recovery_host import ComposeRecoveryHost
from deployment_compose_baseline_recipe_v3 import verify_baseline_recipe_v3
from deployment_compose_recipe_v3 import canonical_recipe_v3


def fail():
    raise ValueError('compose-v3-recovery-rejected')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


class ComposeRecoveryHostV3:
    def __init__(self, *, store, observer, baseline, projections, private_keys, recipes):
        try:
            if observer.scope_kind != 'whole-project':
                fail()
            # Existing host verifies full original private HMACs before copying.
            original = ComposeRecoveryHost(store=store, observer=observer, baseline=baseline,
                projections=projections, private_keys=private_keys, recipes=None)
            if type(recipes) is not dict or set(recipes) != {item.service for item in baseline}:
                fail()
            for item in baseline:
                verify_baseline_recipe_v3(original._projections[item.service], recipes[item.service],
                    project=original._project, service=item.service,
                    container_name=item.final_name, image_id=item.image_id)
            self._original, self._recipes = original, deepcopy(recipes)
        except Exception:
            raise ValueError('compose-v3-recovery-rejected') from None

    def _payload(self, observer, observation):
        source = json.loads(self._original._payload(observer, observation))
        return canonical({'schemaVersion': 2, 'kind': 'compose-committed-baseline-v3',
            'recipeSchemaVersion': 3, 'original': source, 'recoveryRecipesV3': self._recipes,
            'recipeValueComparison': 'closed-v3-subset',
            'reconstructionValidated': False, 'replaySafe': False,
            'authorityGranted': False, 'executionAvailable': False, 'productionReady': False})

    def retain(self, observation):
        try:
            payload = self._payload(self._original._observer, observation)
            reference = self._original._store.put(payload)
            if self._original._store.get(reference) != payload:
                fail()
            self._original._observer.commitment(observation)
            return reference
        except Exception:
            raise ValueError('compose-v3-recovery-rejected') from None

    def verify(self, reference, observer, observation):
        try:
            expected = self._payload(observer, observation)
            if self._original._store.get(reference) != expected:
                fail()
            observer.commitment(observation)
            return reference
        except Exception:
            raise ValueError('compose-v3-recovery-rejected') from None

    def verify_target_configuration(self, target_recipes):
        """Only image identity may differ; this is not image compatibility proof."""
        try:
            if type(target_recipes) is not dict or set(target_recipes) != set(self._recipes):
                fail()
            for service, baseline in self._recipes.items():
                target = target_recipes[service]
                canonical_recipe_v3(target)
                old = {key: value for key, value in baseline.items() if key != 'imageId'}
                new = {key: value for key, value in target.items() if key != 'imageId'}
                if canonical(old) != canonical(new):
                    fail()
        except Exception:
            raise ValueError('compose-v3-recovery-rejected') from None
