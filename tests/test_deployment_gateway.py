"""Local filesystem authority tests. No Docker, sockets, credentials or services."""
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
import pickle
import subprocess
import shutil
import threading
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1] / 'packs/deployment/scripts'
sys.path.insert(0, str(SCRIPTS))
import deployment_gateway as gateway

H = 'a' * 64
CERT = 'b' * 64
GEN = 'c' * 64
KEY = b'host-only-test-key-material-32-bytes!'
CREATE = '/v1.45/containers/create?name=dev-workflow-' + GEN
STOP = '/v1.45/containers/' + H + '/stop?t=10'
START = '/v1.45/containers/' + H + '/start'
DELETE = '/v1.45/containers/' + H + '?force=false&v=false'
BODY = b'{"Image":"sha256:synthetic"}'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def policy():
    return gateway.GatePolicy('host-store', 'host-key', H, CERT)


# Each subprocess imports the actual module, opens a new gate and uses the same
# protected filesystem; no inherited locks, mocks or in-memory capabilities.
CHILD = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import deployment_gateway as g
p = g.GatePolicy('host-store', 'host-key', 'a'*64, 'b'*64)
f = g.FileWriterGate(p, Path(sys.argv[2]), key=b'host-only-test-key-material-32-bytes!')
'''


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'host-gate'
        self.gate = gateway.FileWriterGate(policy(), self.root, key=KEY)

    def open(self, operations=None, generation=GEN):
        if operations is None:
            operations = (('POST', CREATE, sha(BODY)),)
        return self.gate.open_generation(generation=generation, request_hash=H,
                                        receipt_hash=H, operations=operations)

    def prepared(self):
        session = self.open()
        return session, session.prepare_attempt('POST', CREATE, BODY)

    def admit(self, attempt, gate=None, **overrides):
        arguments = dict(method=attempt.method, path=attempt.path, body=BODY,
                         writer_certificate_sha256=CERT)
        arguments.update(overrides)
        return (gate or self.gate).admit(attempt.generation, attempt.ref, **arguments)

    def child(self, code, *arguments):
        return subprocess.run([sys.executable, '-B', '-c', CHILD + code, str(SCRIPTS),
                               str(self.root), *arguments], capture_output=True, text=True,
                              timeout=15)

    def test_full_lifecycle_all_fixed_routes(self):
        operations = (('POST', CREATE, sha(BODY)), ('POST', STOP, sha(b'')),
                      ('POST', START, sha(b'')), ('DELETE', DELETE, sha(b'')))
        session = self.open(operations)
        for method, path, body_hash in operations:
            body = BODY if path == CREATE else b''
            attempt = session.prepare_attempt(method, path, body)
            self.assertEqual(attempt.body_sha256, body_hash)
            headers = session.headers(attempt)
            self.assertEqual(headers, {'X-Dev-Workflow-Generation': GEN,
                                      'X-Dev-Workflow-Attempt': attempt.ref})
            ticket = self.admit(attempt, body=body)
            self.gate.finish(ticket, definitive=True, response_hash=sha(b'HTTP-full-response'))
        proof = self.gate.close_generation(GEN)
        self.assertIs(type(proof), gateway.QuiescenceProof)
        self.assertTrue(self.gate.validate_proof(proof))
        self.assertTrue(self.gate.validate_proof(self.gate.close_generation(GEN)))
        self.assertEqual(json.loads(proof.to_json())['payload']['generation'], GEN)

    def test_diagnose_is_read_only_redacted_and_never_issues_proof(self):
        _, attempt = self.prepared()

        def diagnose(expected):
            directory = self.root / GEN
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            proofs = dict(self.gate._proofs)
            result = self.gate.diagnose_generation(GEN)
            self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)
            self.assertEqual(self.gate._proofs, proofs)
            for key, value in expected.items():
                self.assertEqual(result[key], value)
            self.assertIs(result['authorityGranted'], False)
            encoded = json.dumps(result)
            for secret in (GEN, H, CERT, attempt.ref, CREATE, BODY.decode(), KEY.decode()):
                self.assertNotIn(secret, encoded)
            return result

        diagnose(dict(closed=False, pending=0, unknown=0, done=0,
                      blocker='generation-open', nextStep='close-generation'))
        ticket = self.admit(attempt)
        diagnose(dict(closed=False, pending=1, unknown=0, done=0,
                      blocker='upstream-write-pending', nextStep='await-original-writer-completion'))
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)
        diagnose(dict(closed=True, pending=1, blocker='upstream-write-pending'))
        self.gate.finish(ticket, definitive=True, response_hash=H)
        diagnose(dict(closed=True, pending=0, done=1, blocker=None, nextStep='close-generation'))
        self.gate.close_generation(GEN)
        diagnose(dict(closed=True, done=1, blocker=None, nextStep='load-proof'))

    def test_diagnose_unknown_remains_blocked_after_restart(self):
        _, attempt = self.prepared()
        ticket = self.admit(attempt)
        self.gate.finish(ticket, definitive=False, response_hash=None)
        restarted = gateway.FileWriterGate(policy(), self.root, key=KEY)
        result = restarted.diagnose_generation(GEN)
        self.assertEqual(result['unknown'], 1)
        self.assertEqual(result['pending'], 0)
        self.assertEqual(result['done'], 0)
        self.assertEqual(result['blocker'], 'upstream-outcome-unknown')
        self.assertEqual(result['nextStep'], 'investigate-upstream-outcome')
        self.assertFalse(result['closed'])
        with self.assertRaises(gateway.GateError):
            restarted.load_proof(GEN)

    def test_diagnose_rejects_tampered_signed_state(self):
        self.open()
        record = self.root / GEN / '00000000.json'
        value = json.loads(record.read_text())
        value['unexpected'] = 'secret-raw-diagnostic-value'
        record.write_text(json.dumps(value))
        with self.assertRaises(gateway.GateError) as caught:
            self.gate.diagnose_generation(GEN)
        self.assertNotIn('secret-raw-diagnostic-value', str(caught.exception))

    def test_diagnose_reports_pending_and_unknown_together(self):
        session = self.open((('POST', CREATE, sha(BODY)), ('POST', STOP, sha(b''))))
        first = self.admit(session.prepare_attempt('POST', CREATE, BODY))
        self.gate.finish(first, definitive=False, response_hash=None)
        self.admit(session.prepare_attempt('POST', STOP, b''), body=b'')
        result = self.gate.diagnose_generation(GEN)
        self.assertEqual((result['pending'], result['unknown'], result['done']), (1, 1, 0))
        self.assertEqual(result['blocker'], 'upstream-outcome-unknown')
        self.assertFalse(result['authorityGranted'])

    def test_close_prepared_but_unadmitted_denies_delayed_old_http(self):
        session, attempt = self.prepared()
        proof = self.gate.close_generation(GEN)
        with self.assertRaises(gateway.GateError):
            self.admit(attempt)
        with self.assertRaises(gateway.GateError):
            session.prepare_attempt('POST', CREATE, BODY)
        self.assertTrue(self.gate.validate_proof(proof))
        restarted = gateway.FileWriterGate(policy(), self.root, key=KEY)
        with self.assertRaises(gateway.GateError):
            self.admit(attempt, gate=restarted)
        with self.assertRaises(gateway.GateError):
            self.open()

    def test_pending_close_is_durable_finish_then_retry(self):
        _, attempt = self.prepared()
        ticket = self.admit(attempt)
        for gate in (self.gate, gateway.FileWriterGate(policy(), self.root, key=KEY)):
            with self.assertRaisesRegex(gateway.GateError, '^writer-not-quiescent$'):
                gate.close_generation(GEN)
            with self.assertRaises(gateway.GateError):
                gate.load_proof(GEN)
            with self.assertRaises(gateway.GateError):
                self.admit(attempt, gate=gate)
        # The still-live upstream owner may durably finish after closure.
        self.gate.finish(ticket, definitive=True, response_hash=H)
        proof = self.gate.close_generation(GEN)
        self.assertTrue(self.gate.validate_proof(proof))

    def test_unknown_is_permanent_no_timeout_or_finish_upgrade(self):
        _, attempt = self.prepared()
        ticket = self.admit(attempt)
        self.gate.finish(ticket, definitive=False, response_hash=None)
        with self.assertRaises(gateway.GateError):
            self.gate.finish(ticket, definitive=True, response_hash=H)
        for _ in range(3):
            restarted = gateway.FileWriterGate(policy(), self.root, key=KEY)
            with self.assertRaisesRegex(gateway.GateError, 'writer-not-quiescent'):
                restarted.close_generation(GEN)

    def test_restart_cannot_adopt_pending_ticket_or_mint_completion(self):
        _, attempt = self.prepared()
        ticket = self.admit(attempt)
        restarted = gateway.FileWriterGate(policy(), self.root, key=KEY)
        with self.assertRaises(gateway.GateError):
            restarted.finish(ticket, definitive=True, response_hash=H)
        result = self.child('''
try:
    f.close_generation('c'*64)
except g.GateError as e:
    assert str(e) == 'writer-not-quiescent'
else:
    raise AssertionError('pending request drained')
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_restart_reissues_fresh_proof_not_exported_json(self):
        session, attempt = self.prepared()
        ticket = self.admit(attempt)
        self.gate.finish(ticket, definitive=True, response_hash=H)
        proof = self.gate.close_generation(GEN)
        restarted = gateway.FileWriterGate(policy(), self.root, key=KEY)
        for unissued in (proof, json.loads(proof.to_json()), proof.to_json(), replace(proof)):
            with self.assertRaises(gateway.GateError):
                restarted.validate_proof(unissued)
        fresh = restarted.load_proof(GEN)
        self.assertTrue(restarted.validate_proof(fresh))
        result = self.child("assert f.validate_proof(f.load_proof('c'*64))\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaises(gateway.GateError):
            self.gate.validate_proof(fresh)

    def test_capabilities_issued_exact_and_noncopyable(self):
        session, attempt = self.prepared()
        ticket = self.admit(attempt)
        self.gate.finish(ticket, definitive=True, response_hash=H)
        proof = self.gate.close_generation(GEN)
        for issued in (session, attempt, ticket, proof):
            for duplicate in (copy, deepcopy, pickle.dumps):
                with self.assertRaises(gateway.GateError):
                    duplicate(issued)
        with self.assertRaises(gateway.GateError):
            replace(session).prepare_attempt('POST', CREATE, BODY)
        with self.assertRaises(gateway.GateError):
            session.headers(replace(attempt))
        with self.assertRaises(gateway.GateError):
            self.gate.finish(replace(ticket), definitive=True, response_hash=H)
        with self.assertRaises(FrozenInstanceError):
            policy().scope_hash = GEN

    def test_headers_rechecks_authority_after_guard(self):
        session, attempt = self.prepared()
        with mock.patch.object(self.gate, '_locked', side_effect=gateway.GateError('replaced')):
            with self.assertRaises(gateway.GateError):
                session.headers(attempt)

    def test_exact_operations_required_and_no_broad_routes(self):
        with self.assertRaises(TypeError):
            self.gate.open_generation(generation=GEN, request_hash=H, receipt_hash=H)
        for operations in ((), [], (('POST', CREATE, sha(BODY)),) * 2,
                           (('POST', CREATE, 'no-hash'),)):
            with self.subTest(operations=operations), self.assertRaises(gateway.GateError):
                self.open(operations)
        invalid = [('GET', START), ('POST', '/v1.45/containers/short/start'),
                   ('POST', CREATE + '&x=y'), ('POST', CREATE.replace('dev-workflow-', 'dwf-invalid-')),
                   ('POST', STOP.replace('10', '0')), ('POST', STOP.replace('10', '61')),
                   ('DELETE', DELETE.replace('false', 'true')), ('POST', START + '/'),
                   ('POST', START.replace('/v1.45/', '/v1.44/')),
                   ('POST', CREATE.replace(GEN, '../escape'))]
        for method, path in invalid:
            with self.subTest(path=path), self.assertRaises(gateway.GateError):
                self.open(((method, path, sha(b'')),))
        session = self.open()
        for method, path, body in [('POST', START, b''), ('POST', CREATE, b'changed'),
                                   ('DELETE', CREATE, BODY), ('POST', CREATE, bytearray(BODY))]:
            with self.subTest(path=path), self.assertRaises(gateway.GateError):
                session.prepare_attempt(method, path, body)

    def test_wrong_body_path_certificate_unknown_generation_ref_and_replay(self):
        _, attempt = self.prepared()
        for overrides in (dict(body=b'changed'), dict(path=CREATE + '&extra=1'),
                          dict(writer_certificate_sha256=H), dict(method='DELETE')):
            with self.assertRaises(gateway.GateError):
                self.admit(attempt, **overrides)
        for generation, ref in ((H, attempt.ref), (GEN, H), ('../escape', attempt.ref)):
            with self.assertRaises(gateway.GateError):
                self.gate.admit(generation, ref, method='POST', path=CREATE,
                                body=BODY, writer_certificate_sha256=CERT)
        ticket = self.admit(attempt)
        with self.assertRaises(gateway.GateError):
            self.admit(attempt)
        self.gate.finish(ticket, definitive=True, response_hash=H)
        with self.assertRaises(gateway.GateError):
            self.admit(attempt)

    def test_finish_requires_full_response_digest_and_boolean(self):
        _, attempt = self.prepared()
        ticket = self.admit(attempt)
        for definitive, response_hash in ((True, None), (True, 'bad'), (1, H), (False, H)):
            with self.assertRaises(gateway.GateError):
                self.gate.finish(ticket, definitive=definitive, response_hash=response_hash)
        with self.assertRaisesRegex(gateway.GateError, 'writer-not-quiescent'):
            self.gate.close_generation(GEN)
        self.gate.finish(ticket, definitive=True, response_hash=H)
        with self.assertRaises(gateway.GateError):
            self.gate.finish(ticket, definitive=True, response_hash=H)

    def test_info_mac_scope_domain_and_key(self):
        info = self.gate.info()
        self.assertTrue(self.gate.verify_info(info))
        self.assertNotIn(KEY.decode(), json.dumps(info))
        for bad in (dict(info, mac=H), dict(info, domain='dev-workflow.writer-gate.proof'),
                    dict(info, extra=True), dict(info, version=True)):
            with self.assertRaises(gateway.GateError):
                self.gate.verify_info(bad)
        for changed in (replace(policy(), scope_hash=GEN), replace(policy(), store_id='different'),
                        replace(policy(), key_id='different'),
                        replace(policy(), writer_certificate_sha256=H)):
            other = gateway.FileWriterGate(changed, self.root.parent / changed.identity_hash(), key=KEY)
            with self.assertRaises(gateway.GateError):
                other.verify_info(info)
        with self.assertRaises(gateway.GateError):
            gateway.FileWriterGate(policy(), self.root, key=b'x' * 32)
        with self.assertRaises(gateway.GateError):
            gateway.FileWriterGate(policy(), self.root, key=b'short')

    def test_tampered_fresh_disk_invalidates_issued_proof(self):
        self.open()
        proof = self.gate.close_generation(GEN)
        record = self.root / GEN / '00000001.json'
        value = json.loads(record.read_text())
        value['payload']['kind'] = 'admit'
        record.write_bytes(gateway._canonical(value))
        with self.assertRaises(gateway.GateError):
            self.gate.validate_proof(proof)
        with self.assertRaises(gateway.GateError):
            self.gate.load_proof(GEN)

    def test_strict_canonical_json_duplicates_and_truncation(self):
        self.open()
        record = self.root / GEN / '00000000.json'
        original = record.read_bytes()
        for raw in (original + b'\n', original[:-1], b'{"version":1,"version":1}',
                    b'{"version":NaN}', b'[]', b'\xff'):
            record.write_bytes(raw)
            with self.subTest(raw=raw[:40]), self.assertRaises(gateway.GateError):
                self.gate.close_generation(GEN)
        record.write_bytes(original)
        self.assertTrue(self.gate.validate_proof(self.gate.close_generation(GEN)))

    def test_record_chain_gap_and_wrong_domain(self):
        self.open()
        record = self.root / GEN / '00000000.json'
        original = record.read_bytes()
        record.write_bytes(gateway._canonical(self.gate._seal('proof', json.loads(original)['payload'])))
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)
        record.write_bytes(original)
        record.rename(record.with_name('00000001.json'))
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)

    @unittest.skipIf(os.name == 'nt', 'POSIX ownership and mode contract; Windows ACLs are host managed')
    def test_posix_modes_and_insecure_root_file_denied(self):
        self.open()
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        record = self.root / GEN / '00000000.json'
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        record.chmod(0o644)
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)
        record.chmod(0o600)
        self.root.chmod(0o755)
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)

    def test_links_hardlinks_and_parent_alias_refused(self):
        self.open()
        record = self.root / GEN / '00000000.json'
        backup = self.root.parent / 'backup'
        backup.write_bytes(record.read_bytes())
        if os.name != 'nt':
            backup.chmod(0o600)
        record.unlink()
        try:
            record.symlink_to(backup)
        except OSError:
            self.skipTest('symlink creation unavailable on this Windows host')
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)
        record.unlink()
        os.link(backup, record)
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)
        alias = self.root.parent / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(gateway.GateError):
            gateway.FileWriterGate(policy(), alias, key=KEY)
        with self.assertRaises(gateway.GateError):
            gateway.FileWriterGate(policy(), alias / 'child', key=KEY)

    def test_generation_directory_link_and_lock_link_refused(self):
        other = self.root.parent / 'other'
        other.mkdir(mode=0o700)
        try:
            (self.root / GEN).symlink_to(other, target_is_directory=True)
        except OSError:
            self.skipTest('symlink creation unavailable on this Windows host')
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)
        with self.assertRaises(gateway.GateError):
            self.open()
        (self.root / 'mutex').unlink()
        (self.root / 'mutex').symlink_to(other / 'lock')
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)

    def test_reparse_point_attribute_refusal(self):
        # Windows junctions/reparse points need not report S_IFLNK.
        real_lstat = Path.lstat
        def reparse(path):
            value = real_lstat(path)
            if path == self.root:
                class Reparse:
                    st_mode = value.st_mode
                    st_ino = value.st_ino
                    st_file_attributes = 0x400
                return Reparse()
            return value
        with mock.patch.object(Path, 'lstat', reparse):
            with self.assertRaises(gateway.GateError):
                self.gate.close_generation(GEN)

    def test_windows_byte_lock_contention_retries_and_unlocks(self):
        # Exercise Windows dispatch even on POSIX. Actual Windows ACL and
        # filesystem durability still need a Windows host validation run.
        import errno
        calls = []
        def locking(fd, mode, length):
            calls.append((mode, length, os.lseek(fd, 0, os.SEEK_CUR)))
            if len(calls) < 3:
                raise OSError(errno.EACCES, 'held by live owner')
        windows = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, locking=locking)
        with mock.patch.dict(sys.modules, msvcrt=windows), \
                mock.patch.object(gateway.os, 'name', 'nt'), \
                mock.patch('time.sleep') as pause:
            with self.gate._locked():
                self.assertEqual(len(calls), 3)
        self.assertEqual(calls, [(1, 1, 0)] * 3 + [(2, 1, 0)])
        self.assertEqual(pause.call_count, 2)

    def test_root_and_identifier_boundaries(self):
        for root in (Path('relative'), self.root / '..' / 'alias', SCRIPTS / 'unsafe-gate'):
            with self.assertRaises(gateway.GateError):
                gateway.FileWriterGate(policy(), root, key=KEY)
        for generation in ('../escape', H.upper(), 'a' * 63, None):
            with self.assertRaises(gateway.GateError):
                self.open(generation=generation)
        for change in (dict(scope_hash='bad'), dict(store_id='../escape'), dict(key_id=''),
                       dict(writer_certificate_sha256='invalid')):
            with self.assertRaises(gateway.GateError):
                replace(policy(), **change)

    def synchronized_replacement(self, action, mutate, *, boundary='_sync_parent'):
        reached, replaced = threading.Event(), threading.Event()
        errors = []
        def attacker():
            try:
                if not reached.wait(5):
                    raise AssertionError('operation did not reach replacement boundary')
                mutate()
            except BaseException as error:
                errors.append(error)
            finally:
                replaced.set()
        original = getattr(self.gate, boundary)
        triggered = False
        def pause(*args, **kwargs):
            nonlocal triggered
            result = original(*args, **kwargs)
            if not triggered:
                triggered = True
                reached.set()
                if not replaced.wait(5):
                    raise AssertionError('replacement did not complete')
            return result
        thread = threading.Thread(target=attacker)
        thread.start()
        rejected = False
        try:
            with mock.patch.object(self.gate, boundary, side_effect=pause):
                try:
                    action()
                except gateway.GateError:
                    rejected = True
        finally:
            reached.set()
            thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertTrue(triggered, 'replacement boundary was never exercised')
        if errors:
            # Windows denies rename/unlink of these open handles. Prove the
            # attack was prevented and the original signed store is still live;
            # a permitted original write is then the correct outcome.
            self.assertEqual(os.name, 'nt', errors)
            self.assertTrue(all(isinstance(error, PermissionError) for error in errors), errors)
            self.assertFalse(rejected, errors)
            self.gate._live()
            self.assertEqual(len(self.gate._attempts), 1)
            self.gate.validate_proof(self.gate.close_generation(GEN))
            return False
        self.assertTrue(rejected, 'successful replacement did not block capability issuance')
        return True

    def test_root_replaced_during_reserved_write_cannot_emit_attempt(self):
        session = self.open()
        old = self.root.with_name('detached-root')
        def replace_root():
            self.root.rename(old)
            shutil.copytree(old, self.root)
        if not self.synchronized_replacement(
                lambda: session.prepare_attempt('POST', CREATE, BODY), replace_root):
            return
        self.assertEqual(self.gate._attempts, {})
        self.assertEqual((self.root / GEN / '00000001.json').read_bytes(), b'')
        with self.assertRaises(gateway.GateError):
            gateway.FileWriterGate(policy(), self.root, key=KEY)

    def test_generation_replaced_during_reserved_write_keeps_blocker(self):
        session = self.open()
        directory = self.root / GEN
        old = self.root / 'detached-generation'
        def replace_generation():
            directory.rename(old)
            shutil.copytree(old, directory)
        if not self.synchronized_replacement(
                lambda: session.prepare_attempt('POST', CREATE, BODY), replace_generation):
            return
        self.assertEqual(self.gate._attempts, {})
        self.assertEqual((directory / '00000001.json').read_bytes(), b'')
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)
        restarted = gateway.FileWriterGate(policy(), self.root, key=KEY)
        with self.assertRaises(gateway.GateError):
            restarted.close_generation(GEN)

    def test_reservation_replacement_is_not_overwritten(self):
        session = self.open()
        record = self.root / GEN / '00000001.json'
        def replace_reservation():
            record.unlink()
            record.write_bytes(b'foreign blocker')
            if os.name != 'nt':
                record.chmod(0o600)
        if not self.synchronized_replacement(
                lambda: session.prepare_attempt('POST', CREATE, BODY), replace_reservation):
            return
        self.assertEqual(record.read_bytes(), b'foreign blocker')
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)

    @unittest.skipIf(os.name == 'nt', 'Windows open mutex denies unlink on some hosts')
    def test_replaced_mutex_never_splits_live_transactions(self):
        _, attempt = self.prepared()
        old = self.root / 'old-mutex'
        errors = []
        with self.assertRaises(gateway.GateError), self.gate._locked():
            (self.root / 'mutex').rename(old)
            (self.root / 'mutex').write_bytes(b'')
            (self.root / 'mutex').chmod(0o600)
            result = self.child("print('unexpected authority')\n")
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertNotIn('unexpected authority', result.stdout)
            for action in (self.gate.info, lambda: self.admit(attempt)):
                try:
                    action()
                except gateway.GateError:
                    errors.append(True)
        self.assertEqual(errors, [True, True])
        # The enclosing transaction also rejects its replaced lock on exit.

    def test_mutex_replacement_after_acquire_blocks_capability(self):
        session, attempt = self.prepared()
        def replace_mutex():
            path = self.root / 'mutex'
            path.rename(self.root / 'old-mutex')
            path.write_bytes(b'')
            if os.name != 'nt':
                path.chmod(0o600)
        if os.name == 'nt':
            self.skipTest('Windows open mutex denies unlink on some hosts')
        self.synchronized_replacement(self.gate.info, replace_mutex, boundary='_read')
        with self.assertRaises(gateway.GateError):
            session.headers(attempt)
        with self.assertRaises(gateway.GateError):
            gateway.FileWriterGate(policy(), self.root, key=KEY)

    def test_signed_policy_requires_attested_mutex_identity(self):
        binding = self.root / 'policy.json'
        # Even an authentic old-format policy is insufficient lock attestation.
        binding.write_bytes(gateway._canonical(self.gate._seal('policy', policy()._binding())))
        with self.assertRaises(gateway.GateError):
            gateway.FileWriterGate(policy(), self.root, key=KEY)
        with self.assertRaises(gateway.GateError):
            self.gate.info()

    def test_mutex_missing_is_never_recreated(self):
        (self.root / 'mutex').unlink()
        with self.assertRaises(gateway.GateError):
            self.gate.info()
        with self.assertRaises(gateway.GateError):
            gateway.FileWriterGate(policy(), self.root, key=KEY)
        self.assertFalse((self.root / 'mutex').exists())

    def test_copied_generation_rejected_even_by_new_gate(self):
        self.open()
        directory = self.root / GEN
        directory.rename(self.root / 'old-generation')
        shutil.copytree(self.root / 'old-generation', directory)
        restarted = gateway.FileWriterGate(policy(), self.root, key=KEY)
        with self.assertRaises(gateway.GateError):
            restarted.close_generation(GEN)

    def test_generation_replacement_cannot_clear_old_unknown_capability(self):
        _, attempt = self.prepared()
        ticket = self.admit(attempt)
        self.gate.finish(ticket, definitive=False, response_hash=None)
        directory = self.root / GEN
        directory.rename(self.root / 'old-generation')
        shutil.copytree(self.root / 'old-generation', directory)
        with self.assertRaises(gateway.GateError):
            self.gate.finish(ticket, definitive=True, response_hash=H)
        for gate in (self.gate, gateway.FileWriterGate(policy(), self.root, key=KEY)):
            with self.assertRaises(gateway.GateError):
                gate.close_generation(GEN)
            with self.assertRaises(gateway.GateError):
                gate.load_proof(GEN)

    def test_ancestor_replacement_with_same_root_inode_rejected(self):
        parent = self.root.parent / 'ancestor'
        parent.mkdir(mode=0o700)
        self.root = parent / 'gate'
        self.gate = gateway.FileWriterGate(policy(), self.root, key=KEY)
        session = self.open()
        identity = self.gate._identity(self.root)
        moved = parent.with_name('moved-ancestor')
        def replace_ancestor():
            parent.rename(moved)
            parent.mkdir(mode=0o700)
            (moved / 'gate').rename(self.root)
        if not self.synchronized_replacement(
                lambda: session.prepare_attempt('POST', CREATE, BODY), replace_ancestor):
            return
        self.assertEqual(self.gate._identity(self.root), identity)
        with self.assertRaises(gateway.GateError):
            self.gate.info()

    @unittest.skipIf(os.name == 'nt', 'fcntl-specific acquisition race')
    def test_mutex_replacement_immediately_after_kernel_acquire(self):
        import fcntl
        original = fcntl.flock
        def acquire(fd, operation):
            original(fd, operation)
            if operation == fcntl.LOCK_EX:
                path = self.root / 'mutex'
                path.rename(self.root / 'old-mutex')
                path.write_bytes(b'')
                path.chmod(0o600)
        with mock.patch.object(fcntl, 'flock', side_effect=acquire):
            with self.assertRaises(gateway.GateError):
                self.gate.info()

    def test_windows_fallback_uses_no_directory_fd_and_checks_reparse_records(self):
        windows = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, locking=lambda *args: None)
        original_open = os.open
        def open_without_dir_fd(*args, **kwargs):
            self.assertNotIn('dir_fd', kwargs)
            return original_open(*args, **kwargs)
        with mock.patch.dict(sys.modules, msvcrt=windows), \
                mock.patch.object(gateway.os, 'name', 'nt'), \
                mock.patch.object(gateway.os, 'open', side_effect=open_without_dir_fd):
            session = self.open()
            attempt = session.prepare_attempt('POST', CREATE, BODY)
            self.assertEqual(session.headers(attempt)['X-Dev-Workflow-Attempt'], attempt.ref)
            record = self.root / GEN / '00000000.json'
            real_lstat = self.root.__class__.lstat
            def reparse(path):
                value = real_lstat(path)
                if path == record:
                    return SimpleNamespace(st_mode=value.st_mode, st_ino=value.st_ino, st_file_attributes=0x400,
                                           st_nlink=1)
                return value
            with mock.patch.object(self.root.__class__, 'lstat', reparse):
                with self.assertRaises(gateway.GateError):
                    self.gate.close_generation(GEN)

    @unittest.skipUnless(os.name == 'nt', 'actual Windows junction validation')
    def test_actual_windows_junction_is_rejected(self):
        target = self.root.parent / 'junction-target'
        target.mkdir()
        link = self.root / GEN
        result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(target)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(link.lstat().st_file_attributes & 0x400)
        with self.assertRaises(gateway.GateError):
            self.gate.close_generation(GEN)

    def test_missing_filesystem_identity_fails_closed(self):
        item = SimpleNamespace(st_mode=0o100600, st_ino=0, st_dev=1,
                               st_nlink=1, st_file_attributes=0)
        with mock.patch.object(gateway.os, 'name', 'nt'):
            with self.assertRaises(gateway.GateError):
                self.gate._check_item(item)

    @unittest.skipIf(os.name == 'nt', 'fcntl-specific waiter replacement race')
    def test_waiter_on_original_mutex_rejects_replacement_after_wait(self):
        import fcntl
        waiter = gateway.FileWriterGate(policy(), self.root, key=KEY)
        original = fcntl.flock
        waiting = threading.Event()
        results = []
        def flock(fd, operation):
            if operation == fcntl.LOCK_EX and threading.current_thread() is thread:
                waiting.set()
            return original(fd, operation)
        def run_waiter():
            try:
                waiter.info()
            except gateway.GateError:
                results.append('denied')
            else:
                results.append('issued')
        thread = threading.Thread(target=run_waiter)
        with mock.patch.object(fcntl, 'flock', side_effect=flock):
            with self.assertRaises(gateway.GateError), self.gate._locked():
                thread.start()
                self.assertTrue(waiting.wait(5))
                path = self.root / 'mutex'
                path.rename(self.root / 'old-mutex')
                path.write_bytes(b'')
                path.chmod(0o600)
                result = self.child("print('unexpected authority')\n")
                self.assertNotEqual(result.returncode, 0)
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results, ['denied'])

    def test_partial_root_without_mutex_is_not_initialized(self):
        root = self.root.parent / 'partial-root'
        root.mkdir(mode=0o700)
        with self.assertRaises(gateway.GateError):
            gateway.FileWriterGate(policy(), root, key=KEY)
        self.assertEqual(list(root.iterdir()), [])

    def test_concurrent_initialization_cannot_wait_on_unattested_mutex(self):
        root = self.root.parent / 'initializing-root'
        reached, resume = threading.Event(), threading.Event()
        results = []
        original = gateway.FileWriterGate._write
        def pause(gate, path, envelope):
            if gate.root == root and path.name == 'policy.json':
                reached.set()
                if not resume.wait(5):
                    raise AssertionError('initializer not released')
            return original(gate, path, envelope)
        def initialize():
            try:
                results.append(gateway.FileWriterGate(policy(), root, key=KEY))
            except BaseException as error:
                results.append(error)
        thread = threading.Thread(target=initialize)
        with mock.patch.object(gateway.FileWriterGate, '_write', pause):
            thread.start()
            try:
                self.assertTrue(reached.wait(5))
                with self.assertRaises(gateway.GateError):
                    gateway.FileWriterGate(policy(), root, key=KEY)
            finally:
                resume.set()
                thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), 1)
        self.assertIs(type(results[0]), gateway.FileWriterGate)
        reopened = gateway.FileWriterGate(policy(), root, key=KEY)
        self.assertEqual(reopened.info(), results[0].info())

    def test_dwf_and_existing_create_prefixes_remain_allowed(self):
        for name in ('dwf-' + GEN, 'dev-workflow-' + GEN):
            path = '/v1.45/containers/create?name=' + name
            self.assertEqual(gateway._operation('POST', path, sha(BODY)), ('POST', path, sha(BODY)))

    def test_parallel_process_admit_once(self):
        _, attempt = self.prepared()
        code = CHILD + '''
try:
    f.admit('c'*64, sys.argv[3], method='POST',
            path='/v1.45/containers/create?name=dev-workflow-'+'c'*64,
            body=b'{"Image":"sha256:synthetic"}', writer_certificate_sha256='b'*64)
except g.GateError:
    print('denied')
else:
    print('admitted')
'''
        processes = [subprocess.Popen([sys.executable, '-B', '-c', code, str(SCRIPTS),
                                       str(self.root), attempt.ref], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True) for _ in range(6)]
        results = [p.communicate(timeout=15) for p in processes]
        self.assertTrue(all(p.returncode == 0 for p in processes), results)
        self.assertEqual(sum(out.strip() == 'admitted' for out, _ in results), 1, results)
        with self.assertRaisesRegex(gateway.GateError, 'writer-not-quiescent'):
            self.gate.close_generation(GEN)

    def test_kernel_mutex_blocks_live_owner_and_releases_after_kill(self):
        code = CHILD + '''
with f._locked():
    print('locked', flush=True)
    sys.stdin.read()
'''
        owner = subprocess.Popen([sys.executable, '-B', '-c', code, str(SCRIPTS), str(self.root)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True)
        self.addCleanup(lambda: owner.poll() is None and owner.kill())
        self.assertEqual(owner.stdout.readline().strip(), 'locked')
        waiter = subprocess.Popen([sys.executable, '-B', '-c', CHILD + "print('acquired')\n",
                                   str(SCRIPTS), str(self.root)], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: waiter.poll() is None and waiter.kill())
        time.sleep(0.15)
        self.assertIsNone(waiter.poll(), 'live owner lock was stolen')
        owner.kill()
        owner.communicate(timeout=10)
        out, error = waiter.communicate(timeout=10)
        self.assertEqual(waiter.returncode, 0, error)
        self.assertEqual(out.strip(), 'acquired')

    def test_phase_crashes_never_forge_quiescence(self):
        # Kill the actual writing process immediately before/after each durable
        # replace or fsync boundary. Every surviving partial record must block.
        for phase in ('prepare', 'marker', 'admit', 'finish', 'close', 'proof'):
            for boundary in ('reserve', 'temp-fsync', 'replace', 'dir-fsync'):
                with self.subTest(phase=phase, boundary=boundary):
                    root = self.root.parent / (phase + '-' + boundary)
                    gate = gateway.FileWriterGate(policy(), root, key=KEY)
                    attempt = None
                    if phase != 'prepare':
                        session = gate.open_generation(generation=GEN, request_hash=H,
                                receipt_hash=H, operations=(('POST', CREATE, sha(BODY)),))
                        attempt = session.prepare_attempt('POST', CREATE, BODY)
                    # Finish crash needs a ticket issued inside that process.
                    code = CHILD + '''
import os
phase, boundary = sys.argv[3:5]
ref = sys.argv[5]
if phase == 'prepare':
    import hashlib
    session = f.open_generation(generation='c'*64, request_hash='a'*64,
        receipt_hash='a'*64, operations=(('POST',
        '/v1.45/containers/create?name=dev-workflow-'+'c'*64,
        hashlib.sha256(b'{"Image":"sha256:synthetic"}').hexdigest()),))
if phase == 'finish':
    ticket = f.admit('c'*64, ref, method='POST',
        path='/v1.45/containers/create?name=dev-workflow-'+'c'*64,
        body=b'{"Image":"sha256:synthetic"}', writer_certificate_sha256='b'*64)
original = f._write
# Trigger only the intended transition, not admission markers or close before proof.
def crash_write(path, envelope):
    payload = envelope['payload']
    if ((envelope['domain'].endswith('.event') and payload['kind'] == phase)
            or (phase == 'marker' and envelope['domain'].endswith('.admission'))):
        original_sync = f._sync_parent
        original_replace = os.replace
        original_fsync = os.fsync
        count = [0]
        def sync(directory, fd):
            count[0] += 1
            if boundary == 'reserve' and count[0] == 1:
                os._exit(91)
            original_sync(directory, fd)
            if boundary == 'dir-fsync' and count[0] == 2:
                os._exit(91)
        def replace(source, destination, **kwargs):
            original_replace(source, destination, **kwargs)
            if boundary == 'replace':
                os._exit(91)
        def fsync(fd):
            original_fsync(fd)
            import stat
            if boundary == 'temp-fsync' and stat.S_ISREG(os.fstat(fd).st_mode):
                os._exit(91)
        f._sync_parent = sync
        os.replace = replace
        os.fsync = fsync
    return original(path, envelope)
f._write = crash_write
if phase == 'prepare':
    session.prepare_attempt('POST', '/v1.45/containers/create?name=dev-workflow-'+'c'*64,
                            b'{"Image":"sha256:synthetic"}')
elif phase in ('admit', 'marker'):
    f.admit('c'*64, ref, method='POST',
        path='/v1.45/containers/create?name=dev-workflow-'+'c'*64,
        body=b'{"Image":"sha256:synthetic"}', writer_certificate_sha256='b'*64)
elif phase == 'finish':
    f.finish(ticket, definitive=True, response_hash='a'*64)
else:
    f.close_generation('c'*64)
'''
                    result = subprocess.run([sys.executable, '-B', '-c', code, str(SCRIPTS),
                            str(root), phase, boundary, attempt.ref if attempt else 'unused'],
                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 91, result.stderr)
                    restarted = gateway.FileWriterGate(policy(), root, key=KEY)
                    # After atomic replacement a completed transition is valid;
                    # admission without full completion ALWAYS remains blocked.
                    can_close = boundary in ('replace', 'dir-fsync') and phase not in ('admit', 'marker')
                    if can_close:
                        proof = restarted.close_generation(GEN)
                        self.assertTrue(restarted.validate_proof(proof))
                    else:
                        with self.assertRaises(gateway.GateError):
                            restarted.close_generation(GEN)

    def test_open_crash_permanently_consumes_generation(self):
        for boundary in ('directory', 'record'):
            generation = ('d' if boundary == 'directory' else 'e') * 64
            code = CHILD + '''
import os
generation, boundary = sys.argv[3:5]
if boundary == 'directory':
    f._append = lambda *a, **kw: os._exit(91)
else:
    f._fsync_dir = lambda *a, **kw: None
    original = os.replace
    def crash_replace(*a, **kw):
        os._exit(91)
    os.replace = crash_replace
f.open_generation(generation=generation, request_hash='a'*64, receipt_hash='a'*64,
    operations=(('POST', '/v1.45/containers/'+'a'*64+'/start',
                 __import__('hashlib').sha256(b'').hexdigest()),))
'''
            result = self.child(code[len(CHILD):], generation, boundary)
            self.assertEqual(result.returncode, 91, result.stderr)
            with self.assertRaisesRegex(gateway.GateError, 'generation-already-used'):
                self.open(generation=generation)
            with self.assertRaises(gateway.GateError):
                self.gate.close_generation(generation)

    def test_crash_after_admission_marker_before_event_blocks(self):
        _, attempt = self.prepared()
        with mock.patch.object(self.gate, '_append', side_effect=OSError('crash')):
            with self.assertRaises(gateway.GateError):
                self.admit(attempt)
        restarted = gateway.FileWriterGate(policy(), self.root, key=KEY)
        with self.assertRaises(gateway.GateError):
            restarted.close_generation(GEN)
        with self.assertRaises(gateway.GateError):
            self.admit(attempt, gate=restarted)


if __name__ == '__main__':
    unittest.main()
