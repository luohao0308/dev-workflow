import hashlib
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / path) for path in (
    'scripts', 'core/scripts', 'packs/deployment/scripts', 'packs/release/scripts',
)]

import deployment_compose_frontend_reconciliation_v1_host as frontend
import deployment_compose_production_scope_v1_host as scope
from deployment_compose_witness_store import ZERO, canonical


@unittest.skipUnless(os.name == 'posix', 'POSIX scope and no-follow opens required')
class FrontendRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve() / 'scope'
        root.mkdir(mode=0o700)
        self.registration = scope.provision_scope(root, host_id='host-a', project='luohao-blog-prod',
                                                  daemon_id='docker-1')
        self.request, self.generation = 'a' * 64, 'b' * 64
        with scope.acquire_scope(self.registration, self.request):
            pass
        self.gate = root / ('gate-' + self.request)
        self.events = self.gate / self.generation
        self.events.mkdir(parents=True, mode=0o700)
        self.gate.chmod(0o700)
        for name in ('mutex', 'policy.json'):
            (self.gate / name).touch(mode=0o600)
        self.operation = ['POST', '/v1.45/containers/create?name=fixture', 'c' * 64]
        opened = dict(kind='open', generation=self.generation, previous=ZERO, directory=[1, 2],
                      data=dict(request_hash=self.request, operations=[self.operation]))
        prepared = dict(kind='prepare', generation=self.generation, directory=[1, 2],
                        previous=hashlib.sha256(canonical(opened)).hexdigest(),
                        data=dict(operation=self.operation, ref='d' * 64))
        digests = []
        for index, event in enumerate((opened, prepared)):
            raw = canonical(dict(payload=event))
            path = self.events / f'{index:08}.json'
            path.touch(mode=0o600)
            path.write_bytes(raw)
            digests.append(hashlib.sha256(raw).hexdigest())
        self.digests = tuple(digests)

    def prepared(self):
        return frontend._prepared_gate(
            self.registration, self.request, self.generation, self.digests, self.operation,
        )

    def test_exact_prepared_gate_and_reject_admission_or_drift(self):
        self.assertEqual(self.prepared(), self.digests)
        admitted = self.events / '00000002.json'
        admitted.touch(mode=0o600)
        with self.assertRaises(scope.ScopeBlocked):
            self.prepared()
        admitted.unlink()
        (self.events / '00000001.json').write_bytes(b'different prepared event')
        with self.assertRaises(scope.ScopeBlocked):
            self.prepared()

    def test_symlink_event_is_rejected(self):
        path = self.events / '00000001.json'
        path.unlink()
        path.symlink_to(self.events / '00000000.json')
        with self.assertRaises(OSError):
            self.prepared()

    def test_gate_replacement_while_reading_events_is_rejected(self):
        read = frontend._private_file

        def replace_gate(fd, name, maximum):
            raw = read(fd, name, maximum)
            if name == '00000001.json':
                self.gate.rename(self.gate.with_name('old-gate'))
                self.gate.mkdir(mode=0o700)
            return raw

        with patch.object(frontend, '_private_file', side_effect=replace_gate):
            with self.assertRaises(scope.ScopeBlocked):
                self.prepared()

    def test_read_only_payload_holds_lock_and_does_not_change_journal(self):
        journal, = self.registration.root.glob('*.journal')
        before = journal.read_bytes()

        def observe(*args, **kwargs):
            with self.assertRaisesRegex(scope.ScopeBlocked, 'live writer'):
                scope.acquire_scope(self.registration, 'c' * 64)
            return 'd' * 64

        with patch.object(frontend, '_observe', side_effect=observe):
            approval = frontend.prepare_frontend_reconciliation(
                self.registration, self.request, evidence_digest='e' * 64, expires_at=1000,
            )
        self.assertEqual(approval['observationDigest'], 'd' * 64)
        self.assertEqual(approval['pending']['requestHash'], self.request)
        self.assertEqual(journal.read_bytes(), before)

    def test_missing_independent_signer_pin_blocks_reconciliation(self):
        with self.assertRaises(FileNotFoundError):
            frontend.reconcile_frontend_scope(self.registration, self.request,
                                               approval={}, signature=b'', public_key=b'')

    def test_unconsumed_observation_checks_ledger_under_lock_and_rechecks_gate(self):
        self._check_observation(frontend.LEDGER_UNCONSUMED)

    def test_consumed_before_gate_observation_requires_exact_live_marker_and_absent_gate(self):
        self._check_observation(frontend.LEDGER_CONSUMED_BEFORE_GATE)

    def test_unknown_first_create_requires_exact_gate_chain_and_admission_marker(self):
        attempt = 'd' * 64
        info = self.events.stat()
        identity = [info.st_dev, info.st_ino]
        policy = dict(operation_profile='compose-v3', witness_required=True)
        marker = self.events / ('admitted-' + attempt)

        def envelope(domain, payload):
            return canonical(dict(version=1, domain='dev-workflow.writer-gate.' + domain,
                                  policy=policy, payload=payload, mac='1' * 64))

        def setup_gate(**response_overrides):
            response = dict(ref=attempt, definitive=False, response_hash=None,
                            response_binding_schema=1, status=0, bodyBase64='')
            response.update(response_overrides)
            previous = ZERO
            digests = []
            for index, (kind, data) in enumerate((
                ('open', dict(request_hash=self.request, operations=[self.operation])),
                ('prepare', dict(operation=self.operation, ref=attempt)),
                ('admit', attempt),
                ('finish', response),
            )):
                event = dict(kind=kind, generation=self.generation, directory=identity,
                             previous=previous, data=data)
                path = self.events / f'{index:08}.json'
                path.touch(mode=0o600)
                raw = envelope('event', event)
                path.write_bytes(raw)
                previous = hashlib.sha256(canonical(event)).hexdigest()
                digests.append(hashlib.sha256(raw).hexdigest())
            marker.touch(mode=0o600)
            marker.write_bytes(envelope('admission', dict(generation=self.generation, ref=attempt)))
            return tuple(digests)

        def observe(digests):
            return frontend._prepared_gate(self.registration, self.request, self.generation,
                                           digests, self.operation, outcome_unknown=True)

        digests = setup_gate()
        self.assertEqual(observe(digests), (*digests, hashlib.sha256(marker.read_bytes()).hexdigest()))
        extra = self.events / '00000004.json'
        extra.touch(mode=0o600)
        with self.assertRaises(scope.ScopeBlocked):
            observe(digests)
        extra.unlink()
        marker.write_bytes(envelope('admission', dict(generation=self.generation, ref='2' * 64)))
        with self.assertRaises(scope.ScopeBlocked):
            observe(digests)
        with self.assertRaises(scope.ScopeBlocked):
            observe(setup_gate(definitive=True, status=201))

    def _check_observation(self, basis):
        self.gate.rename(self.gate.with_name('old-gate'))
        caddy, network, endpoint = 'e' * 64, 'f' * 64, '1' * 64
        plan = {'publicReview': dict(identity=dict(hostId='host-a', project='luohao-blog-prod',
                                                  daemonId='docker-1', imageId='image'),
                                     snapshotDigest='snapshot', protectedContainerIds=[caddy])}
        cutover = SimpleNamespace(protected_ids=(caddy,), original_id='original', digest='digest',
                                  create=lambda: None)
        original = dict(NetworkSettings=dict(Networks={'luohao-blog-prod_default': dict(NetworkID=network)}))
        observer = Mock()
        observer.descriptor.return_value = {'endpointDigest': endpoint}
        observer._get.side_effect = lambda path, *_: (
            original if '/containers/' in path else dict(Id='image', Os='linux', Architecture='arm64', Config={})
        )

        consumed = basis == frontend.LEDGER_CONSUMED_BEFORE_GATE
        marker = dict(ref='refs/tags/workflow-production-frontend-intent-v1/' + self.request,
                      objectSha='3' * 40)

        def verify_ledger(request):
            self.assertEqual(request, self.request)
            with self.assertRaisesRegex(scope.ScopeBlocked, 'live writer'):
                scope.acquire_scope(self.registration, 'c' * 64)
            return marker if consumed else True

        def prepare(callback):
            ledger = (dict(verify_ledger_consumed=callback, ledger_target_sha=marker['objectSha'])
                      if consumed else dict(verify_ledger_absent=callback))
            return frontend.prepare_frontend_reconciliation(
                self.registration, self.request, evidence_digest='2' * 64, expires_at=1000,
                recovery_basis=basis, **ledger,
                private_plan=plan, operation_nonce='nonce', caddy_id=caddy, network_id=network,
                endpoint_digest=endpoint,
            )

        def gate_appears(request):
            result = verify_ledger(request)
            self.gate.symlink_to('does-not-exist')
            return result

        with (patch.object(frontend, '_require_quiescent'),
              patch.object(frontend, 'prepare_retained_frontend_cutover', return_value=cutover),
              patch.object(frontend, '_operation_tuple', return_value=self.operation),
              patch.object(frontend, 'HostSnapshotV3', return_value=observer),
              patch.object(frontend, 'original_projection', side_effect=lambda row: row),
              patch.object(frontend, 'prepare_frontend_plan', return_value=plan),
              patch.object(frontend, 'ProductionCaddyProbeV1', return_value=lambda _: True),
              patch.object(frontend, 'ProductionFrontendProtectionV1',
                           return_value=SimpleNamespace(verify=lambda: 'protection'))):
            first = prepare(verify_ledger)
            self.assertEqual(first, prepare(verify_ledger))
            self.assertEqual(first['recoveryBasis'], basis)
            self.assertEqual(first['legacyMacAuthentication'], 'not-applicable')
            failures = [None, lambda _: False, lambda _: 1]
            if consumed:
                self.assertEqual(first['ledgerTargetSha'], marker['objectSha'])
                failures.extend((lambda _: dict(marker, ref=marker['ref'] + 'other'),
                                 lambda _: dict(marker, objectSha='4' * 40)))
            for callback in (*failures, gate_appears):
                with self.subTest(callback=callback), self.assertRaises(scope.ScopeBlocked):
                    prepare(callback)
