"""Bounded deployment acceptance profile and conservative evidence assessment.

Only an in-process host adapter may call ``_assess_trusted`` after observing each
stage through the fixed SDK. Serialized reports are never an authority source.
"""

from dataclasses import dataclass
import re

import deployment_runtime as runtime


_KIND = 'deployment-acceptance-profile'
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
_STAGES = ('approval', 'deployment', 'health', 'smoke', 'rollback', 'recovery')
_FIELDS = frozenset(('schemaVersion', 'kind', 'profileName', 'repositoryId', 'environment',
                     'target', 'component', 'runtimePolicyHash', 'executionPolicyHash',
                     'verificationPolicyHash', 'storePolicyHash', 'gatePolicyHash',
                     'allowInterruption', 'requireHealth', 'requireSmoke', 'rollbackRef',
                     'platform', 'adapter', 'state', 'readOnly', 'mounts'))


class AcceptanceError(ValueError):
    def __init__(self, code='invalid-acceptance-profile'):
        super().__init__(code)


def _validate(value):
    if (type(value) is not dict or set(value) != _FIELDS
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['kind'] != _KIND):
        raise AcceptanceError()
    names = ('profileName', 'environment', 'target', 'component', 'rollbackRef')
    if any(type(value[k]) is not str or not _NAME.fullmatch(value[k]) for k in names):
        raise AcceptanceError()
    hashes = ('runtimePolicyHash', 'executionPolicyHash', 'verificationPolicyHash',
              'storePolicyHash', 'gatePolicyHash')
    if any(type(value[k]) is not str or not runtime.HEX.fullmatch(value[k]) for k in hashes):
        raise AcceptanceError()
    if type(value['repositoryId']) is not int or value['repositoryId'] <= 0:
        raise AcceptanceError()
    for key in ('allowInterruption', 'requireHealth', 'requireSmoke', 'readOnly'):
        if type(value[key]) is not bool:
            raise AcceptanceError()
    if any(type(value[k]) is not str or len(value[k]) > 64 for k in ('platform', 'adapter', 'state')):
        raise AcceptanceError()
    if (type(value['mounts']) is not list or len(value['mounts']) > 16
            or any(type(v) is not str or len(v) > 256 for v in value['mounts'])):
        raise AcceptanceError()


@dataclass(frozen=True)
class AcceptanceProfile:
    profile_name: str
    repository_id: int
    environment: str
    target: str
    component: str
    runtime_policy_hash: str
    execution_policy_hash: str
    verification_policy_hash: str
    store_policy_hash: str
    gate_policy_hash: str
    allow_interruption: bool
    require_health: bool
    require_smoke: bool
    rollback_ref: str
    platform: str
    adapter: str
    state: str
    read_only: bool
    mounts: tuple

    def __post_init__(self):
        if type(self.mounts) is not tuple:
            raise AcceptanceError()
        _validate(self.to_mapping())

    @classmethod
    def from_mapping(cls, value):
        _validate(value)
        hashes = ('runtimePolicyHash', 'executionPolicyHash', 'verificationPolicyHash',
                  'storePolicyHash', 'gatePolicyHash')
        return cls(value['profileName'], value['repositoryId'],
                   value['environment'], value['target'], value['component'],
                   *(value[k] for k in hashes), value['allowInterruption'],
                   value['requireHealth'], value['requireSmoke'], value['rollbackRef'],
                   value['platform'], value['adapter'], value['state'], value['readOnly'],
                   tuple(value['mounts']))

    def to_mapping(self):
        return dict(schemaVersion=1, kind=_KIND, profileName=self.profile_name,
                    repositoryId=self.repository_id, environment=self.environment,
                    target=self.target, component=self.component,
                    runtimePolicyHash=self.runtime_policy_hash,
                    executionPolicyHash=self.execution_policy_hash,
                    verificationPolicyHash=self.verification_policy_hash,
                    storePolicyHash=self.store_policy_hash, gatePolicyHash=self.gate_policy_hash,
                    allowInterruption=self.allow_interruption, requireHealth=self.require_health,
                    requireSmoke=self.require_smoke, rollbackRef=self.rollback_ref,
                    platform=self.platform, adapter=self.adapter, state=self.state,
                    readOnly=self.read_only, mounts=list(self.mounts))

    def identity_hash(self):
        return runtime.digest(self.to_mapping())


def _supported(profile):
    return (profile.platform == 'linux' and profile.adapter == 'docker'
            and profile.state == 'stateless' and profile.read_only and not profile.mounts)


def _requirements(profile):
    return (profile.allow_interruption and profile.require_health and profile.require_smoke
            and bool(profile.rollback_ref))


def _report(profile, stages):
    if not _supported(profile):
        status, reason = 'unsupported', 'unsupported-deployment-scope'
    elif not _requirements(profile):
        status, reason = 'blocked', 'required-safety-contract-missing'
    elif all(stages[s] == 'passed' for s in _STAGES):
        status, reason = 'accepted', 'host-observed-stages-complete'
    elif any(stages[s] == 'blocked' for s in _STAGES):
        status, reason = 'blocked', 'host-observed-stage-blocked'
    else:
        status, reason = 'unknown', 'host-observation-incomplete'
    return dict(schemaVersion=1, kind='deployment-acceptance-assessment',
                profileHash=profile.identity_hash(), status=status, reason=reason,
                stages=dict(stages), productionReady=False,
                authorityGranted=False, executionAvailable=False)


def assess_supplied(profile, evidence):
    """Assess untrusted supplied data without granting an acceptance state."""
    if type(profile) is not AcceptanceProfile or type(evidence) is not dict:
        raise AcceptanceError('invalid-acceptance-input')
    return _report(profile, {s: 'unknown' for s in _STAGES})


def _assess_trusted(profile, observations):
    """Private aggregation of SDK-observed stages; caller must authenticate them."""
    if type(profile) is not AcceptanceProfile or type(observations) is not dict or set(observations) != set(_STAGES):
        raise AcceptanceError('invalid-host-observations')
    if any(value not in ('passed', 'unknown', 'blocked') for value in observations.values()):
        raise AcceptanceError('invalid-host-observations')
    return _report(profile, observations)
