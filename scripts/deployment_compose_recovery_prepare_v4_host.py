"""Local non-authorizing V4 recovery preparation. No approval or writer activation.

Binds a witness phase, not current Engine state. Fixed diagnostic actor only;
original plan hashes are retained without claiming a V4 plan compiler exists.
"""
from dataclasses import replace
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'packs/deployment/scripts'))
from deployment_contract_v2 import RequestV2
from deployment_compose_actor_supervisor_v4 import registered_supervisor, verified_termination_digest
from deployment_compose_operation_witness_v4 import OperationWitnessStoreV4, digest
from deployment_compose_recovery_store import ComposeRecoveryStore
from deployment_compose_witness_store import canonical, hex_value


class PreparedRecoveryV4:
    @property
    def request(self):
        return self._issuer._record(self)[2]


class RecoveryPreparationHostV4:
    def __init__(self, *, witness, root_request, baseline_store, supervisor, actor, termination):
        if (type(witness) is not OperationWitnessStoreV4 or type(root_request) is not RequestV2
                or root_request.profile_id != 'compose-application-batch-v1'
                or root_request.profile_version != '4' or root_request.operation != 'deploy'
                or root_request.production is not False or root_request.target.runtime != 'compose'
                or type(baseline_store) is not ComposeRecoveryStore or not registered_supervisor(supervisor)):
            raise ValueError('v4-recovery-preparation-rejected')
        self._witness, self._store, self._supervisor = witness, baseline_store, supervisor
        self._root = RequestV2.from_json(root_request.canonical_json())
        self._actor, self._termination = actor, termination
        self._issued = {}
        self._facts(witness.read())

    def _facts(self, state):
        session = state['session']; scope = state['scopes'][-1]
        if (session['rootRequestHash'] != self._root.digest() or session['bundleDigest'] != self._root.plan_hash
                or session['policyHash'] != self._root.policy_hash or session['supervisorBoot'] != self._supervisor.boot
                or scope['phase'] not in ('open', 'prepared')
                or self._supervisor.actor_identity(self._actor, session['sessionHash']) != scope['actorEpoch']):
            raise ValueError('v4-recovery-preparation-rejected')
        termination = verified_termination_digest(self._supervisor, self._actor, self._termination,
            session['sessionHash'], {'sequence': state['sequence'], 'head': state['head']})
        baseline = self._store.get(session['baselineReference'])
        return baseline, termination

    def _context(self, state, nonce, expires_at):
        if not hex_value(nonce): raise ValueError('v4-recovery-preparation-rejected')
        baseline, termination = self._facts(state)
        scope = state['scopes'][-1]
        return dict(schemaVersion=4, kind='compose-recovery-context-v4', session=deepcopy(state['session']),
                    originalRequestHash=self._root.digest(), historyDigest=digest({k:state[k] for k in ('schemaVersion','session','scopes','sequence','head')}),
                    cursor={k:state[k] for k in ('sequence','head')}, witnessPhaseSnapshot=deepcopy(scope),
                    baselineReference=state['session']['baselineReference'], baselineContentDigest=hashlib.sha256(baseline).hexdigest(),
                    terminationDigest=termination, recoveryNonce=nonce, expiresAt=expires_at,
                    successorScopeOrdinal=scope['scopeOrdinal']+1, successorActorRule='v4-intent-and-termination-digest')

    def _request(self, context):
        request = replace(self._root, operation='recovery', profile_id='compose-recovery-v4', profile_version='4',
                          history_hash=context['historyDigest'], observation_hash=digest(context), expires_at=context['expiresAt'])
        request.ensure_fresh(datetime.now(timezone.utc), maximum_seconds=900)
        return request

    def prepare(self, *, operation_nonce, expires_at):
        state = self._witness.read()
        context = self._context(state, operation_nonce, expires_at)
        request = self._request(context)
        raw = canonical(context); reference = self._store.put(raw)
        if self._store.get(reference) != raw or self._context(self._witness.read(), operation_nonce, expires_at) != context:
            raise ValueError('v4-recovery-preparation-drift')
        self._request(context)  # Freshness again after the second I/O pass.
        result = PreparedRecoveryV4(); result._issuer = self
        self._issued[id(result)] = (result, reference, request, raw)
        return result

    def _record(self, prepared):
        record = self._issued.get(id(prepared))
        if (type(prepared) is not PreparedRecoveryV4 or getattr(prepared, '_issuer', None) is not self
                or record is None or record[0] is not prepared):
            raise ValueError('v4-recovery-preparation-rejected')
        return record

    def review(self, prepared):
        record = self._record(prepared)
        return dict(request=record[2], contextReference=record[1], contextDigest=record[2].observation_hash,
                    authorityGranted=False, executionAvailable=False, productionReady=False)

    def verify_for_store(self, prepared, witness, state, supervisor, actor, termination):
        record = self._record(prepared)
        if (witness is not self._witness or supervisor is not self._supervisor
                or actor is not self._actor or termination is not self._termination):
            raise ValueError('v4-recovery-preparation-rejected')
        request = record[2]
        raw = self._store.get(record[1])
        context = self._context(state, json.loads(record[3])['recoveryNonce'], request.expires_at)
        if raw != record[3] or canonical(context) != raw or self._request(context).canonical_json() != request.canonical_json():
            raise ValueError('v4-recovery-preparation-drift')
        session=state['session']; scope=state['scopes'][-1]
        return dict(session, schemaVersion=4, profile='compose-recovery-v4', historyHead=state['head'],
                    actorEpoch=scope['actorEpoch'], scopeOrdinal=scope['scopeOrdinal'], planWriteIndex=scope['planWriteIndex'],
                    nonce=context['recoveryNonce'], expiresAt=request.expires_at,
                    recoveryRequestHash=request.digest(), recoveryContextDigest=request.observation_hash)
