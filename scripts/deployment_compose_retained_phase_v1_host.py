"""Exact container phase checks for the production retained-frontend worker."""
from copy import deepcopy
from dataclasses import dataclass, replace
import hashlib
import json

from deployment_compose_phase_guard_v3_host import _lifecycle, _same, _stable
from deployment_compose_production_frontend_v3_host import _encode

FINAL_NAME = 'blog-frontend'


class FrontendNotReady(ValueError):
    pass


@dataclass(frozen=True)
class FrontendPhase:
    original_name: str = FINAL_NAME
    original_running: bool = True
    candidate_name: str | None = None
    candidate_running: bool = False
    candidate_started: bool = False
    original_restored: bool = False


def switched_phase(plan, prefix, *, candidate_present=True, candidate_running=None):
    if type(prefix) is not int or not 0 <= prefix <= 4 or not candidate_present and prefix:
        raise ValueError('invalid-switch-prefix')
    running = prefix == 4 if candidate_running is None else candidate_running
    if type(running) is not bool or running and prefix != 4:
        raise ValueError('invalid-candidate-lifecycle')
    return FrontendPhase(
        original_name=FINAL_NAME if prefix < 2 else plan.retained_name,
        original_running=prefix == 0,
        candidate_name=None if not candidate_present else (plan.candidate_name if prefix < 3 else FINAL_NAME),
        candidate_running=running,
        candidate_started=prefix == 4,
    )


def restored_phase(plan, phase, operation):
    if operation.phase == 'stop-candidate':
        return replace(phase, candidate_running=False)
    if operation.phase == 'unname-candidate':
        return replace(phase, candidate_name=plan.candidate_name)
    if operation.phase == 'rename-original':
        return replace(phase, original_name=FINAL_NAME)
    if operation.phase == 'start-original':
        return replace(phase, original_running=True, original_restored=True)
    raise ValueError('invalid-restoration-operation')


def original_projection(row):
    """Match the existing read-only preflight shape, without volatile health logs."""
    value = _stable(row)
    value['State']['Health'] = {'Status': value.pop('Health')}
    return value


def _endpoint_config(row):
    endpoints = row['NetworkSettings']['Networks']
    if type(endpoints) is not dict or not endpoints:
        raise ValueError('missing-frontend-network')
    for endpoint in endpoints.values():
        if (endpoint.get('IPAMConfig') not in (None, {}) or endpoint.get('Links') not in (None, [])
                or endpoint.get('DriverOpts') not in (None, {})
                or 'GwPriority' in endpoint and (type(endpoint['GwPriority']) is not int or endpoint['GwPriority'] != 0)):
            raise ValueError('frontend-network-options-drift')
    return {name: {key: endpoint[key] for key in ('NetworkID', 'Aliases')}
            for name, endpoint in endpoints.items()}


def _state(row, *, container_id, name, running):
    _lifecycle(row)
    if (row['Id'] != container_id or row['Name'] != '/' + name
            or row['State']['Running'] is not running):
        raise ValueError('frontend-phase-state-mismatch')
    if running:
        for endpoint in row['NetworkSettings']['Networks'].values():
            if not endpoint.get('IPAddress') or not endpoint.get('EndpointID'):
                raise ValueError('frontend-network-endpoint-missing')


def verify_phase(plan, baseline, original, candidate, *, candidate_id, phase, require_ready=False):
    """Return stable observation bytes. The caller double-samples the native endpoint."""
    body = json.loads(plan.body)
    _state(original, container_id=plan.original_id, name=phase.original_name, running=phase.original_running)
    if not phase.original_running and original['State']['Status'] != 'exited':
        raise ValueError('original-frontend-not-stopped')
    for key in ('Image', 'Config', 'HostConfig', 'Mounts', 'RestartCount'):
        if not _same(original[key], baseline[key]):
            raise ValueError('original-frontend-configuration-drift')
    if not _same(_endpoint_config(original), _endpoint_config(baseline)):
        raise ValueError('original-frontend-network-drift')
    if (original['State']['StartedAt'] != baseline['State']['StartedAt']) is not phase.original_restored:
        raise ValueError('original-frontend-lifecycle-drift')
    if phase.original_running and not phase.original_restored:
        if original['State']['Pid'] != baseline['State']['Pid'] or original['State']['Health']['Status'] != 'healthy':
            raise ValueError('original-frontend-not-healthy')
    if phase.candidate_name is None:
        if candidate is not None or candidate_id is not None:
            raise ValueError('unexpected-frontend-candidate')
    else:
        plan._candidate(candidate_id)
        _state(candidate, container_id=candidate_id, name=phase.candidate_name, running=phase.candidate_running)
        if not phase.candidate_running and candidate['State']['Status'] != (
                'exited' if phase.candidate_started else 'created'):
            raise ValueError('frontend-candidate-lifecycle-drift')
        config = {key: value for key, value in body.items() if key not in ('HostConfig', 'NetworkingConfig')}
        # Engine 29's Linux container inspect omits the image-only ArgsEscaped
        # metadata. Any exposed value still has to match the approved body.
        if 'ArgsEscaped' not in candidate['Config']:
            config.pop('ArgsEscaped', None)
        host_config = deepcopy(body['HostConfig'])
        if host_config.get('OomKillDisable') is None and candidate['HostConfig'].get('OomKillDisable') is False:
            host_config['OomKillDisable'] = False
        if (candidate['Image'] != body['Image'] or not _same(candidate['Config'], config)
                or not _same(candidate['HostConfig'], host_config) or candidate['Mounts'] != []
                or candidate['RestartCount'] != 0
                or not _same(_endpoint_config(candidate), body['NetworkingConfig']['EndpointsConfig'])):
            raise ValueError('frontend-candidate-reconstruction-drift')
    if require_ready:
        active = original if phase.original_running else candidate
        if active is None or active['State']['Running'] is not True or active['State']['Health']['Status'] != 'healthy':
            raise FrontendNotReady('frontend-not-ready')
    return _encode({'original': _stable(original), 'candidate': _stable(candidate) if candidate is not None else None})


def phase_digest(observation):
    return hashlib.sha256(observation).hexdigest()
