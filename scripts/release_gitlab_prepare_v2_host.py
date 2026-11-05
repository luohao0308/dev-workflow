"""Pinned-host, GET-only GitLab v2 request preparation; never issues authority."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from release_gitlab_preflight_host import GitLabPreflightHost, DOMAIN as PREFLIGHT_DOMAIN
from release_contract_v2 import ProviderIdentity, RequestV2
from release_execute import canonical

PROFILE = 'gitlab-lightweight-tag-v2'
PLAN_DOMAIN = b'dev-workflow:gitlab-tag-preparation:v2\0'


class GitLabRequestPreparationV2:
    """Host configuration is independent of candidate intent and observed JSON.

    Every preparation performs two fresh preflights (four API snapshots).
    Matching reads are evidence only, not an atomic tag reservation or approval.
    """
    def __init__(self, *, preflight, expected_identity, host_id, policy_hash):
        if (type(preflight) is not GitLabPreflightHost
                or type(expected_identity) is not ProviderIdentity
                or expected_identity.provider_id != 'gitlab.com'
                or canonical(asdict(preflight.identity)) != canonical(asdict(expected_identity))
                or type(host_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', host_id)
                or type(policy_hash) is not str or not re.fullmatch(r'[0-9a-f]{64}', policy_hash)):
            raise ValueError('invalid-gitlab-preparation-host')
        self._preflight = preflight
        self._identity = ProviderIdentity(**asdict(expected_identity))
        self._host_id, self._policy_hash = host_id, policy_hash
        self._client = preflight.client
        self._configuration = self._configuration_bytes()

    def _configuration_bytes(self):
        p = self._preflight
        if (type(p.identity) is not ProviderIdentity
                or not isinstance(p.repository, Path)
                or type(p.remote) is not str
                or type(p.maximum_seconds) is not int or not 0 < p.maximum_seconds <= 60
                or p.client is not self._client):
            raise ValueError('gitlab-preparation-host-drift')
        # Revalidate, rather than relying on dataclass equality (True == 1).
        identity = ProviderIdentity(**asdict(p.identity))
        return canonical({'identity': asdict(identity), 'repository': str(p.repository),
                          'remote': p.remote, 'maximumSeconds': p.maximum_seconds})

    def _observe(self, intent):
        if self._configuration_bytes() != self._configuration:
            raise ValueError('gitlab-preparation-host-drift')
        evidence = self._preflight.observe(intent, operation='remote-tag-push')
        if (self._configuration_bytes() != self._configuration
                or type(evidence) is not dict or set(evidence) != {'context', 'digest'}
                or evidence['digest'] != hashlib.sha256(PREFLIGHT_DOMAIN + canonical(evidence['context']).encode('ascii')).hexdigest()):
            raise ValueError('gitlab-preparation-evidence-drift')
        return evidence

    def prepare(self, intent, *, expires_at, operation='remote-tag-push'):
        if type(operation) is not str or operation != 'remote-tag-push':
            raise ValueError('unsupported-gitlab-preparation-operation')
        # Validate expiry and fixed fields before any network activity.
        initial = RequestV2(2, operation, self._identity, self._host_id, PROFILE,
                            self._identity.source_sha, 'v0.0.0', self._identity.origin,
                            '{}', '0'*64, self._policy_hash, expires_at, 1)
        initial.ensure_fresh(datetime.now(timezone.utc))
        supplied = json.loads(canonical(intent))
        if type(supplied) is not dict:
            raise ValueError('invalid-gitlab-preparation-intent')
        first = self._observe(supplied)
        second = self._observe(supplied)
        if canonical(first) != canonical(second):
            raise ValueError('gitlab-preparation-observation-drift')
        context = second['context']
        if (canonical(context['identity']) != canonical(asdict(self._identity))
                or context['operation'] != operation
                or context['authorityGranted'] is not False
                or context['executionAvailable'] is not False):
            raise ValueError('invalid-gitlab-preparation-context')
        payload = {'tag': context['tag'], 'targetSha': self._identity.source_sha,
                   'preflightDigest': second['digest']}
        plan = {'profile': PROFILE, 'hostId': self._host_id,
                'identity': asdict(self._identity), 'payload': payload}
        request = RequestV2(2, operation, self._identity, self._host_id, PROFILE,
                            self._identity.source_sha, context['tag'], self._identity.origin,
                            canonical(payload), hashlib.sha256(PLAN_DOMAIN + canonical(plan).encode('ascii')).hexdigest(),
                            self._policy_hash, expires_at, 1)
        request.ensure_fresh(datetime.now(timezone.utc))
        return {'request': request, 'preflight': second,
                'authorityGranted': False, 'executionAvailable': False, 'productionReady': False}
