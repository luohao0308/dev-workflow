"""Process loss with real OpenSSH signatures and production-scope flock."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import test_deployment_compose_retained_witness_admission_v1_host as witness_fixture
from deployment_compose_production_scope_v1_host import (
    ScopeBlocked, ScopeRegistrationV1, acquire_scope, inspect_pending_scope, provision_scope,
)
from deployment_compose_retained_crash_evidence_v1_host import inspect_retained_crash_evidence
from deployment_compose_witness_store import canonical
from deployment_gate_witness import key_material


def _crash_fixture(parent, admit_only):
    tempfile.tempdir = str(parent)
    fixture = witness_fixture.RetainedWitnessAdmissionTests()
    fixture.staged_only = True
    fixture.setUp()
    scope = parent/'scope'
    scope.mkdir(mode=0o700)
    registration = provision_scope(scope, host_id='host', project='luohao-blog-prod', daemon_id='daemon')
    create = fixture._registration(stage='create')
    request = create['request'].digest()
    with acquire_scope(registration, request):
        creator = witness_fixture.RetainedWitnessAdmissionV1(**create)
        fixture._create(creator)
        _, witnesses = creator.closed_chain()
        switch = fixture._registration(stage='switch', creation=create['request'], creation_witness=witnesses[0])
        broker = witness_fixture.RetainedWitnessAdmissionV1(**switch, parent=creator)
        stop, rename, *_ = fixture.plan.switch(fixture.candidate)
        writer = fixture._complete(broker, broker.first_binding, stop, 0)
        if admit_only:
            binding = fixture._advance(broker, writer, rename, 1)
            fixture._complete(broker, binding, rename, 1, admit_only=True)
        print(json.dumps(dict(scope=str(scope), root=str(fixture.root), request=request,
                              scopeIdentity=registration.root_identity, journalIdentity=registration.journal_identity,
                              keyHash=hashlib.sha256(key_material(fixture.public)).hexdigest())), flush=True)
        sys.stdin.buffer.read(1)


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class RetainedCrashEvidenceTests(unittest.TestCase):
    def _interrupt(self, *, admit_only):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        command = [sys.executable, '-B', '-c',
                   'import sys; from pathlib import Path; '
                   'from tests.test_deployment_compose_retained_crash_evidence_v1_host import _crash_fixture; '
                   '_crash_fixture(Path(sys.argv[1]).resolve(), sys.argv[2]=="True")',
                   temporary.name, str(admit_only)]
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, cwd=Path(__file__).resolve().parents[1]) as child:
            try:
                with selectors.DefaultSelector() as select:
                    select.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(select.select(20), 'writer did not reach crash point')
                line = child.stdout.readline()
                if not line:
                    self.fail(child.stderr.read().decode())
                result = json.loads(line)
                scope = ScopeRegistrationV1(Path(result['scope']), tuple(result['scopeIdentity']),
                                            tuple(result['journalIdentity']), 'host', 'luohao-blog-prod', 'daemon')
                with self.assertRaisesRegex(ScopeBlocked, 'live writer'):
                    inspect_pending_scope(scope, result['request'])
            finally:
                child.kill()
                child.wait(timeout=5)
        pending = inspect_pending_scope(scope, result['request'])
        with self.assertRaisesRegex(ScopeBlocked, 'Unresolved'):
            acquire_scope(scope, 'f'*64)
        root = Path(result['root'])
        public = (root/'witness-key.pub').read_bytes()
        (root/'witness-key').unlink()
        report = inspect_retained_crash_evidence(root, pending, public_key=public,
                                                expected_key_hash=result['keyHash'])
        self.assertEqual(inspect_pending_scope(scope, result['request']), pending)
        return root, pending, public, result['keyHash'], report

    def test_killed_after_closed_stop_recovers_verified_prefix_without_private_keys(self):
        root, pending, public, key_hash, report = self._interrupt(admit_only=False)
        self.assertEqual([item['stage'] for item in report['stages']], ['create', 'switch'])
        self.assertEqual([len(item['witnessDigests']) for item in report['stages']], [1, 1])
        self.assertFalse(report['uncertain'])
        self.assertFalse(report['authorityGranted'])
        self.assertFalse(report['productionReady'])
        checkpoint, = (name for name in root.glob('*.retained-checkpoint-1.json')
                       if not name.name.startswith(pending['requestHash']))
        value = json.loads(checkpoint.read_bytes())
        value['payload']['candidateId'] = 'd'*64
        checkpoint.write_bytes(canonical(value))
        with self.assertRaises(ValueError):
            inspect_retained_crash_evidence(root, pending, public_key=public, expected_key_hash=key_hash)

    def test_killed_after_next_admission_keeps_prior_prefix_but_marks_tail_uncertain(self):
        _, _, _, _, report = self._interrupt(admit_only=True)
        self.assertTrue(report['uncertain'])
        _, switch = report['stages']
        self.assertEqual(len(switch['witnessDigests']), 1)
        self.assertFalse(switch['checkpointMatches'])
        self.assertFalse(report['authorityGranted'])
