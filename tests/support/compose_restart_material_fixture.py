"""Exited-producer/new-consumer fixture; Engine/provider are explicit doubles."""
import base64
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), *(str(ROOT / p) for p in
    ('scripts', 'packs/deployment/scripts', 'packs/release/scripts'))]

from tests.test_deployment_compose_gate_witness_v3 import GateFixture
from tests.test_deployment_compose_history_v3_host import HistoryTests
from tests.test_deployment_compose_prepare_v3_host import fixture
from tests.test_deployment_compose_recovery_prepare_v3_host import RecoveryPreparationTests, expiry
from deployment_compose_image_defaults import ZERO_DEFAULTS
from deployment_compose_phase_guard_v3_host import PhaseGuardV3, baseline_state_bytes
from deployment_compose_prepare_v3_host import ComposePreparationHostV3
from deployment_compose_recovery_prepare_v3_host import RecoveryPreparationHostV3
from deployment_compose_operation_witness_v3 import OperationWitnessStoreV3
from deployment_compose_operation_witness_client_v3 import dispatch_request, encode, NAMESPACE
from deployment_compose_witness_store import canonical

ARCHIVE_DIGEST = '7' * 64
STORE_KEY = b'h' * 32  # External test-host provision, never read from restart material.
GATE_KEY = b'g' * 32


class RestartFixture(GateFixture, unittest.TestCase):
    open_scope = HistoryTests.open_scope
    factory = HistoryTests.factory
    finish = HistoryTests.finish
    history = HistoryTests.history
    close_create = RecoveryPreparationTests.close_create
    read = RecoveryPreparationTests.read

    def setUp(self):
        self.setup_gate_fixture()
        self.kw, observation = fixture()
        self.archive_store = self.kw['recovery']._store
        self.addCleanup(self.archive_store.close)
        prepared = ComposePreparationHostV3(**self.kw).prepare_intent(
            observation, observation, operation_nonce='f' * 64, expires_at=expiry())
        self.bundle = prepared['bundle']
        self.req = replace(prepared['request'], policy_hash=self.policy.identity_hash(),
                           expires_at='2020-01-01T00:00:00Z')
        self.defaults = {s['name']: deepcopy(ZERO_DEFAULTS)
                         for s in self.bundle.to_dict()['services']}
        self.rows = deepcopy(self.kw['whole_observer']._unit_rows)
        self.baseline_bytes = baseline_state_bytes(self.rows)
        self.version = {'Version': '29.8.2', 'GitCommit': '8af9fe3'}
        self.guard = PhaseGuardV3(self.bundle, self.rows, read_json=self.read,
                                  daemon_version=self.version)
        self.receipts, self.index = {}, 0
        self.signed = self
        self.open_scope()

    def material(self):
        from deployment_compose_restart_material_v3_host import capture_material
        return capture_material(self.history(), baseline_bytes=self.baseline_bytes,
            authenticated_image_defaults=self.defaults, archive_digest=ARCHIVE_DIGEST)

    def expected_context(self):
        return dict(sourceSha=self.req.source.source_sha, hostId=self.req.host_id,
            daemonId=self.req.daemon_id, archiveDigest=ARCHIVE_DIGEST,
            historyDigest=self.history().capture().digest,
            baselineStateDigest=self.bundle.to_dict()['baselineStateDigest'])

    def capsule(self):
        prepared = RecoveryPreparationHostV3(original_history=self.history(),
            store=self.archive_store, phase_guard=self.guard,
            readiness=lambda service, cid: True).prepare_intent(
                operation_nonce='b' * 64, expires_at=expiry())
        return canonical(dict(request=asdict(prepared['request']),
            context=json.loads(self.archive_store.get(prepared['recovery_context_reference']))))


def record(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def produce(directory):
    case = RestartFixture()
    case.setUp()
    try:
        case.close_create()
        raw = case.material()
        record(directory / 'material.private.json', raw)
        pins = dict(expectedDigest=hashlib.sha256(raw).hexdigest(),
                    expectedContext=case.expected_context(), producerPid=os.getpid())
        record(directory / 'pins.private.json', canonical(pins))
        record(directory / 'capsule.private.json', case.capsule())
        # External test-host storage outlives producer fixture cleanup. These
        # host keys are separate from the private restart material/pins.
        shutil.copytree(case.store.root, directory / 'witness')
        record(directory / 'host-signing.private', case.key.read_bytes())
        record(directory / 'host-signing.pub', case.public)
        return dict(producerPid=os.getpid(), materialDigest=pins['expectedDigest'])
    finally:
        case.doCleanups()


def consume(directory):
    from deployment_compose_restart_material_v3_host import reopen_material
    from deployment_compose_recovery_phase_capsule_v3_host import verify_captured_recovery_phase
    pins = json.loads((directory / 'pins.private.json').read_bytes())
    store = OperationWitnessStoreV3(directory / 'witness', key=STORE_KEY)
    calls = []
    before = (directory / 'witness/state.json').read_bytes()
    def transport(method, request):
        if method not in ('read', 'check', 'events_after', 'chain_status'):
            raise AssertionError('mutation reached external test host')
        calls.append(method)
        payload = dispatch_request(store, method, request)
        signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f',
            str(directory / 'host-signing.private'), '-n', NAMESPACE],
            input=encode(payload), capture_output=True, check=True, timeout=10)
        return dict(payload=payload, signature=base64.b64encode(signed.stdout).decode('ascii'))
    try:
        result = reopen_material((directory / 'material.private.json').read_bytes(),
            expected_digest=pins['expectedDigest'], expected_context=pins['expectedContext'],
            gate_key=GATE_KEY, witness_public_key=(directory / 'host-signing.pub').read_bytes(),
            witness_transport=transport)
        # The original capsule validator consumes this actual history/baseline,
        # without accepting old approval, admission, or a permit from JSON.
        original = result.history._request
        capsule = verify_captured_recovery_phase((directory / 'capsule.private.json').read_bytes(),
            original_history=result.history, baseline_bytes=result.baseline_bytes,
            expected_daemon_version={'Version': '29.8.2', 'GitCommit': '8af9fe3'},
            expected_source=original.source, expected_host_id=original.host_id,
            expected_daemon_id=original.daemon_id, expected_target=original.target,
            expected_policy_hash=original.policy_hash)
        assert capsule.phaseConsistencyVerified and not capsule.phaseFreshnessVerified
        summary = result.public_summary()
        assert before == (directory / 'witness/state.json').read_bytes()
        assert calls and set(calls) <= {'read', 'check', 'events_after', 'chain_status'}
        return dict(summary=summary, producerPid=pins['producerPid'], consumerPid=os.getpid(),
            witnessUnchanged=True, readMethods=sorted(set(calls)), capsuleConsistencyVerified=True,
            newApprovalConsumptions=0, engineRequests=0, executionRecovered=False)
    finally:
        store.close()


if __name__ == '__main__':
    action, destination = sys.argv[1:]
    directory = Path(destination).resolve(strict=True)
    if action not in ('produce', 'consume'):
        raise ValueError('fixture action rejected')
    print(json.dumps(produce(directory) if action == 'produce' else consume(directory)), flush=True)
