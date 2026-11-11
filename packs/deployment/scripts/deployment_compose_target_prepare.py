"""Host-only comparison of a reviewed Compose target with private recipes.

The caller supplies trusted key material and fixed container names. Matching
values are preparation evidence, never an execution permit or Docker plan.
"""
from __future__ import annotations

import hmac

from deployment_compose_recipe import commit_recipe
from deployment_compose_target_artifacts import ComposeTargetArtifacts, verify_target_request
from deployment_contract_v2 import RequestV2


def verify_target_recipes(request: RequestV2, manifest: ComposeTargetArtifacts,
                          recipes: dict, *, container_names: dict, keys: dict) -> None:
    """Recompute each host-private recipe HMAC against the exact target manifest."""
    verify_target_request(request, manifest)
    services = {item.service for item in manifest.services}
    if (type(recipes) is not dict or set(recipes) != services
            or type(container_names) is not dict or set(container_names) != services
            or type(keys) is not dict or not keys
            or any(type(name) is not str for name in container_names.values())
            or len(set(container_names.values())) != len(container_names)
            or any(type(key_id) is not str or type(key) is not bytes or len(key) < 32
                   for key_id, key in keys.items())):
        raise ValueError('invalid-target-recipe-scope')
    aliases = set()
    host_ports = set()
    for item in manifest.services:
        recipe = recipes[item.service]
        if (type(recipe) is not dict or recipe.get('project') != request.target.namespace
                or recipe.get('service') != item.service
                or recipe.get('containerName') != container_names[item.service]
                or recipe.get('imageId') != item.image_id
                or item.recipe_key_id not in keys):
            raise ValueError('target-recipe-identity-mismatch')
        try:
            commitment = commit_recipe(recipe, item.recipe_key_id, keys[item.recipe_key_id])
        except ValueError:
            raise ValueError('invalid-target-recipe') from None
        if not hmac.compare_digest(commitment['hmac'], item.recipe_hmac):
            raise ValueError('target-recipe-commitment-mismatch')
        for network in recipe['networks']:
            for alias in network['aliases']:
                key = (network['id'], alias)
                if key in aliases:
                    raise ValueError('target-network-alias-collision')
                aliases.add(key)
        for port in recipe['ports']:
            # Wildcard binds overlap specific addresses; first profile rejects
            # any shared host port/protocol across selected services.
            key = (port['hostPort'], port['protocol'])
            if key in host_ports:
                raise ValueError('target-host-port-collision')
            host_ports.add(key)
