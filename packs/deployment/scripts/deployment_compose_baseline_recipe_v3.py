"""Closed v3 value comparison; no authentication or Engine reconstruction proof.

Original private values must be authenticated by the caller. Only verified v3
additions are normalized on copies before reusing the unchanged v2 comparator.
"""
from copy import deepcopy

from deployment_compose_baseline_recipe import _same, verify_baseline_recipe
from deployment_compose_private import _projection
from deployment_compose_recipe_v3 import canonical_recipe_v3

RESOURCE_FIELDS = {
    'Memory': 'memoryBytes', 'MemorySwap': 'memorySwapBytes',
    'NanoCpus': 'nanoCpus', 'PidsLimit': 'pidsLimit',
}


def verify_baseline_recipe_v3(projection, recipe, *, project, service, container_name, image_id):
    """Compare restricted observed values without granting authority or freshness."""
    try:
        canonical_recipe_v3(recipe)
        _projection(projection)
        host, declared = projection['HostConfig'], recipe['hostConfig']
        restart = declared['restartPolicy']
        if not _same(host['RestartPolicy'], {
                'Name': restart['name'], 'MaximumRetryCount': restart['maximumRetryCount']}):
            raise ValueError()
        log = declared['logConfig']
        if not _same(host['LogConfig'], {'Type': log['type'], 'Config': log['config']}):
            raise ValueError()
        for observed, field in RESOURCE_FIELDS.items():
            if type(host[observed]) is not int or host[observed] != declared['resources'][field]:
                raise ValueError()
        normalized_projection, normalized_recipe = deepcopy(projection), deepcopy(recipe)
        normalized_host = normalized_projection['HostConfig']
        for field in RESOURCE_FIELDS:
            del normalized_host[field]
        normalized_host['RestartPolicy'] = {'Name': 'no', 'MaximumRetryCount': 0}
        normalized_host['LogConfig'] = {'Type': 'none', 'Config': {}}
        normalized_recipe['schemaVersion'] = 2
        recipe_host = normalized_recipe['hostConfig']
        del recipe_host['resources']
        del recipe_host['restartPolicy']
        recipe_host['logConfig'] = {'type': 'none', 'config': {}}
        verify_baseline_recipe(normalized_projection, normalized_recipe, project=project,
            service=service, container_name=container_name, image_id=image_id)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError):
        raise ValueError('baseline-v3-recipe-not-representable') from None
