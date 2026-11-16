"""One reviewed plan and independently authenticated per-stage witnesses."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import os
import shutil
import unittest

from tests import test_deployment_compose_retained_witness_admission_v1_host as witness_fixture
from deployment_compose_production_frontend_approval_v1_host import STAGED_PROTECTION_MODE
from deployment_compose_retained_release_plan_v1_host import (
    VerifiedReadinessFailure, prepare_release_plan, propose_release_stage, release_plan_digest, verify_release_plan,
)
from deployment_compose_retained_witness_admission_v1_host import RetainedWitnessAdmissionV1, _digest
from deployment_gate_witness import key_material


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class ReleasePlanTests(unittest.TestCase):
    def setUp(self):
        fixture = witness_fixture.RetainedWitnessAdmissionTests()
        fixture.staged_only = True
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture = fixture
        self.creation = fixture._registration(stage='create', protection_mode=STAGED_PROTECTION_MODE)
        request = self.creation['request']
        self.runtime = self.creation['approval'].policy.workflow_sha
        self.plan = prepare_release_plan(self.creation['review'], policy_hash=request.policy_hash,
                                         runtime_sha=self.runtime, expires_at=request.expires_at)
        self.reviewed = release_plan_digest(self.plan)
        self.source = dict(root=fixture.root, public_key=fixture.public,
                           expected_key_hash=hashlib.sha256(key_material(fixture.public)).hexdigest(),
                           pending=dict(requestHash=request.digest(), generation=1, journalDigest='d'*64))

    def propose(self, stage, review, *, readiness_failure=None, witness=True):
        return propose_release_stage(
            self.plan, reviewed_digest=self.reviewed, runtime_sha=self.runtime,
            current_review=review, stage=stage, witness_source=self.source if witness else None,
            readiness_failure=readiness_failure,
        )

    def _creation_witness(self):
        create = RetainedWitnessAdmissionV1(**self.creation)
        self.fixture._create(create)
        return create, create.closed_chain()[1][0]

    def _switch(self, *, unknown=False):
        fixture = self.fixture
        creator, witness = self._creation_witness()
        creation_request = self.creation['request']
        review = deepcopy(self.creation['review'])
        review['retainedCutover'].update(stage='switch', candidateId=fixture.candidate,
                                         creationRequestHash=creation_request.digest(), creationWitnessDigest=witness,
                                         observationDigest='6'*64, scopeGeneration=1)
        stage = self.propose('switch', review)
        changed = deepcopy(review)
        changed['retainedCutover']['observationDigest'] = '2'*64
        proposal = self.propose('switch', changed)
        # A fresh observation does not allow a second claim for the same stage.
        self.assertNotEqual(proposal.request.digest(), stage.request.digest())
        self.assertEqual(proposal.claim_key, stage.claim_key)
        changed['retainedCutover']['candidateId'] = '3'*64
        with self.assertRaises(ValueError):
            self.propose('switch', changed)

        switch = fixture._registration(stage='switch', creation=creation_request, creation_witness=witness,
                                       protection_mode=STAGED_PROTECTION_MODE, expires_at=creation_request.expires_at)
        self.assertEqual(stage.request, switch['request'])
        worker = RetainedWitnessAdmissionV1(**switch, parent=creator)
        binding = worker.first_binding
        for index, operation in enumerate(fixture.plan.switch(fixture.candidate)):
            if index:
                binding = fixture._advance(worker, client, operation, index)
            client = fixture._complete(worker, binding, operation, index, admit_only=unknown and index == 3)
        return switch, worker

    @staticmethod
    def _rollback_review(switch, witness):
        review = deepcopy(switch['review'])
        review['retainedCutover'].update(stage='rollback', parentRequestHash=switch['request'].digest(),
                                         switchWitnessDigest=witness, switchPrefix=4, candidateRunning=False)
        return review

    def test_one_review_binds_distinct_stages_and_confirmation_policy(self):
        create = self.propose('create', self.creation['review'], witness=False)
        self.assertEqual(create.request, self.creation['request'])
        for patch in (
            dict(automaticRollback={'outcome': 'any-failure', 'closedSwitchWrites': 0, 'requireKnownEffects': False}),
            dict(stageOrder=['switch', 'create', 'rollback']), dict(maxUsesPerStage=2),
            dict(runtimeSha='c'*40),
        ):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                verify_release_plan(dict(self.plan, **patch), reviewed_digest=self.reviewed, runtime_sha=self.runtime)
        changed = deepcopy(self.creation['review'])
        changed['retainedCutover']['operationNonce'] = '4'*64
        with self.assertRaises(ValueError):
            self.propose('create', changed, witness=False)
        with self.assertRaises(ValueError):
            self.propose('switch', self.creation['review'], witness=False)
        with self.assertRaises(ValueError):
            verify_release_plan(self.plan, reviewed_digest=self.reviewed, runtime_sha=self.runtime,
                                now=datetime.now(timezone.utc) + timedelta(hours=1))

    def test_automatic_rollback_requires_exact_typed_failure_and_four_closed_writes(self):
        switch, worker = self._switch()
        _, proofs = worker.closed_chain()
        review = self._rollback_review(switch, _digest(proofs))
        failure = VerifiedReadinessFailure(switch['request'].digest(), 1,
                                            review['retainedCutover']['observationDigest'], False)
        for invalid in (None, replace(failure, request_hash='8'*64), replace(failure, scope_generation=2),
                        replace(failure, observation_digest='a'*64), replace(failure, candidate_running=True)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.propose('rollback', review, readiness_failure=invalid)
        accepted = self.propose('rollback', review, readiness_failure=failure)
        changed = deepcopy(review)
        changed['retainedCutover']['switchWitnessDigest'] = '7'*64
        with self.assertRaises(ValueError):
            self.propose('rollback', changed, readiness_failure=failure)
        rollback = self.fixture._registration(
            stage='rollback', parent=switch['request'], prefix=4, creation=self.creation['request'],
            creation_witness=switch['review']['retainedCutover']['creationWitnessDigest'],
            switch_witness=_digest(proofs), protection_mode=STAGED_PROTECTION_MODE,
            expires_at=self.creation['request'].expires_at,
        )
        self.assertEqual(accepted.request, rollback['request'])

    def test_uncertain_switch_tail_cannot_propose_rollback(self):
        switch, _ = self._switch(unknown=True)
        review = self._rollback_review(switch, '6'*64)
        failure = VerifiedReadinessFailure(switch['request'].digest(), 1,
                                            review['retainedCutover']['observationDigest'], False)
        with self.assertRaises(ValueError):
            self.propose('rollback', review, readiness_failure=failure)
