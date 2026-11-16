"""Verify one protected release review and claim an exact derived stage once."""
from datetime import datetime, timezone
import re
import time

from deployment_compose_production_frontend_approval_v1_host import (
    ProductionFrontendGrantV1, ProductionFrontendReceiptV1, _production_authority_reads,
)
from deployment_compose_retained_release_plan_v1_host import propose_release_stage
from deployment_compose_retained_release_review_v1_host import MAX_TOKEN_SECONDS, slot_audience, verify_release_review
from deployment_compose_witness_store import canonical
from deployment_contract_v2 import RequestV2
from release_host import GitHubActionsApproval, _deny, timestamp, verify_oidc


class RetainedReleaseStageApprovalV1(GitHubActionsApproval):
    """A single derivation under the exact protected approval and fresh slot."""

    request_type = RequestV2
    operations = frozenset(('deploy', 'rollback'))
    grant_type = ProductionFrontendGrantV1
    receipt_type = ProductionFrontendReceiptV1
    ledger_namespace = 'workflow-retained-release-stage-v1'
    grant_namespace = 'github-retained-release-stage-v1'

    def __init__(self, client, token, artifact, env, *, reviewed_digest, slot, stage, current_review,
                 witness_source=None, readiness_failure=None, verifier=None):
        root, policy = verify_release_review(artifact, env, expected_digest=reviewed_digest)
        proposed = propose_release_stage(
            root['plan'], reviewed_digest=reviewed_digest, runtime_sha=policy.workflow_sha,
            current_review=current_review, stage=stage, witness_source=witness_source,
            readiness_failure=readiness_failure,
        )
        self.audience = slot_audience(root['approvalHash'], slot)
        self._approval_hash = root['approvalHash']
        self._release_digest = reviewed_digest
        self._stage, self._stage_request, self._claim_key = stage, proposed.request, proposed.claim_key
        self._readiness_failure = readiness_failure
        self._claim_object = None
        authenticate = verifier or verify_oidc

        def bounded(raw):
            claims = authenticate(raw)
            if (not isinstance(claims, dict) or type(claims.get('iat')) is not int
                    or type(claims.get('exp')) is not int or not 0 < claims['exp'] - claims['iat'] <= MAX_TOKEN_SECONDS):
                _deny('Release OIDC slot exceeds its lifetime')
            return claims

        super().__init__(client, token, [proposed.request], policy, verifier=bounded)

    @property
    def request(self):
        return self._stage_request

    @property
    def stage(self):
        return self._stage

    @property
    def release_binding(self):
        return self._release_digest, self._approval_hash, self.policy.run_id

    @property
    def readiness_failure(self):
        return self._readiness_failure

    def provisional_grant(self, request):
        self._match(request)
        if self._expires is None or time.time() >= self._grant_expiry(request):
            _deny('Release stage handoff expired')
        return self._grant_for_checked_authority(request)

    def _reviewed_bundle_hash(self):
        return self._approval_hash

    def _prefetch_authority(self):
        if type(self) is not RetainedReleaseStageApprovalV1:
            return None
        return _production_authority_reads(self.client, self._authority_queries())

    def _match(self, request):
        if type(request) is not RequestV2 or request != self._stage_request or not time.time() < timestamp(request.expires_at).timestamp():
            _deny('Stage request differs from reviewed release')

    def _ledger_marker(self, request):
        return 'tags/' + self.ledger_namespace + '/' + self._claim_key

    def _claim_message(self, request):
        return canonical(dict(
            release=self._release_digest, approval=self._approval_hash, stage=self._stage,
            requestHash=request.digest(), claimKey=self._claim_key,
        )).decode('ascii')

    def _check_tag(self, value, sha, request):
        marker = self._ledger_marker(request)
        if (type(value) is not dict or not isinstance(sha, str) or re.fullmatch('[0-9a-f]{40}', sha) is None
                or value.get('sha') != sha or value.get('tag') != marker.removeprefix('tags/')
                or value.get('message') != self._claim_message(request) or type(value.get('object')) is not dict
                or (value['object'].get('type'), value['object'].get('sha')) != ('commit', self.policy.ledger_sha)):
            _deny('Release stage claim object differs from exact request')

    def consume(self, grant, request, *, before_consume=None):
        if before_consume is not None and not callable(before_consume):
            _deny('Invalid release stage preflight')
        with self._lock:
            self._match(request)
            if self._consumed or type(grant) is not self.grant_type or grant != self._grant_for_checked_authority(request):
                _deny('Release stage changed or was already attempted')
            self._consumed.add(request.digest())
            ledger = '/repos/' + self.policy.ledger_repository + '/git/'
            marker = self._ledger_marker(request)

            def current():
                self._match(request)
                self._check_authority()
                if self._grant_for_checked_authority(request) != grant:
                    _deny('Release stage grant changed')

            def before_ref():
                current()
                if before_consume is not None:
                    before_consume()
                if time.time() >= self._grant_expiry(request):
                    _deny('Release stage expired before durable claim')

            try:
                # An unattached tag object grants nothing. The create-only ref
                # makes the stable stage key and exact request a single claim.
                tag, _ = self.client.request('POST', ledger + 'tags', dict(
                    tag=marker.removeprefix('tags/'), message=self._claim_message(request),
                    object=self.policy.ledger_sha, type='commit',
                ), before_send=current)
                sha = tag.get('sha') if type(tag) is dict else None
                self._check_tag(tag, sha, request)
                value, _ = self.client.request('POST', ledger + 'refs', dict(ref='refs/'+marker, sha=sha),
                                               before_send=before_ref)
                if (type(value) is not dict or value.get('ref') != 'refs/'+marker
                        or type(value.get('object')) is not dict
                        or (value['object'].get('type'), value['object'].get('sha')) != ('tag', sha)):
                    _deny('Release stage ref could not be verified')
                self._check_tag(self._get(ledger + 'tags/' + sha), sha, request)
            except Exception:
                _deny('Release stage claim was rejected or is uncertain')
            self._claim_object = sha
            self._verified_consumptions.add(request.digest())
            return self.receipt_type(grant.grant_id, request.digest(), 1, datetime.now(timezone.utc).isoformat())

    def guard(self, request):
        _deny('Release stage consent is not a Docker runtime permit')

    def check_consumed_intent(self, request):
        self._match(request)
        self._check_authority()
        if self._claim_object is None or request.digest() not in self._verified_consumptions:
            _deny('Release stage lacks a verified durable claim')
        ledger = '/repos/' + self.policy.ledger_repository + '/git/'
        marker = self._ledger_marker(request)
        value = self._get(ledger + 'ref/' + marker)
        if (type(value) is not dict or value.get('ref') != 'refs/'+marker
                or type(value.get('object')) is not dict
                or (value['object'].get('type'), value['object'].get('sha')) != ('tag', self._claim_object)):
            _deny('Durable release stage ref changed')
        self._check_tag(self._get(ledger + 'tags/' + self._claim_object), self._claim_object, request)
        if time.time() >= self._grant_expiry(request):
            _deny('Release stage expired while checking durable claim')
