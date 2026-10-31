"""Private readonly reconstruction; Unix Engine responses are explicit doubles."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_live_ssh_v3_host import CapsuleTests
import deployment_compose_executor_capture_v3_host as capture
from deployment_compose_operation_witness_client_v3 import encode


class CaptureTests(CapsuleTests):
    def inputs(self):
        capsule, expected = self.capsule()
        keys = expected.pop('keys')
        return capsule, dict(expected=expected, integrity_keys=keys,
            cas_root=str(self.root/'profile3-archive'), cas_key=keys['archive'],
            docker_socket=str(self.root/'docker.sock'),
            daemon_version=dict(Version='29.8.2', GitCommit='8af9fe3'),
            docker_root=str(self.root/'data'))

    def reconstruct(self, capsule, kw):
        self.calls.clear()
        result = capture.reconstruct_initial_capture(encode(capsule), **kw)
        self.assertTrue(self.calls)
        self.assertEqual({method for method, path in self.calls}, {'GET'})
        self.assertEqual(sum(path == '/v1.45/version' for _, path in self.calls), 2)
        self.assertFalse(result.authorityGranted)
        self.assertFalse(result.productionReady)
        self.assertNotIn('targetCreateBody', repr(result))
        with self.assertRaises(FrozenInstanceError):result.phase_digest = 'x'
        return result

    def test_reopens_cas_and_performs_two_fresh_get_captures(self):
        capsule, kw = self.inputs()
        before = self.session.store.get(capsule['bundle']['baselineStateReference'])
        result = self.reconstruct(capsule, kw)
        self.assertEqual(json.loads(result.bundle_bytes), capsule['bundle'])
        self.assertEqual(json.loads(result.request_bytes), capsule['request'])
        self.assertEqual(self.session.store.get(capsule['bundle']['baselineStateReference']), before)

    def test_parser_and_untrusted_extra_pins_reject(self):
        capsule, kw = self.inputs()
        raw = encode(capsule)
        for bad in (b'{"bundle":1,"bundle":2}', b'{"a":NaN}', raw+b' ', b'x'*(capture.MAX_CAPSULE+1)):
            with self.subTest(size=len(bad)), self.assertRaisesRegex(ValueError, '^compose-executor-capture-v3-rejected$'):
                capture.reconstruct_initial_capture(bad, **kw)
        tampered = deepcopy(capsule)
        tampered['rawRows']['backend']['Config']['Env'].append('SECRET=changed')
        with self.assertRaises(ValueError):capture.reconstruct_initial_capture(encode(tampered), **kw)
        expired = deepcopy(capsule)
        expired['request']['expires_at'] = '2020-01-01T00:00:00Z'
        with self.assertRaises(ValueError):capture.reconstruct_initial_capture(encode(expired), **kw)
        for name in ('docker_socket', 'cas_root', 'keys', 'receipt', 'authority'):
            changed = deepcopy(capsule); changed[name] = 'attacker'
            with self.subTest(name=name), self.assertRaises(ValueError):
                capture.reconstruct_initial_capture(encode(changed), **kw)

    def test_substituted_independent_pins_and_cas_reject(self):
        capsule, kw = self.inputs()
        variants = []
        for key, value in (('trusted_boot_id','e'*32), ('source_sha','e'*40), ('ssh_alias','other')):
            changed = dict(kw, expected=dict(kw['expected'], **{key:value})); variants.append(changed)
        variants.append(dict(kw, expected=dict(kw['expected'], policy=SimpleNamespace(identity_hash=lambda:'e'*64))))
        variants.extend([dict(kw, cas_key=b'z'*32), dict(kw, docker_root='/wrong'),
            dict(kw, daemon_version=dict(Version='wrong',GitCommit='wrong'))])
        for changed in variants:
            with self.subTest(keys=sorted(changed)), self.assertRaises(ValueError):
                capture.reconstruct_initial_capture(encode(capsule), **changed)
        link = self.root/'archive-link';link.symlink_to(self.root/'profile3-archive')
        with self.assertRaises(ValueError):capture.reconstruct_initial_capture(encode(capsule), **dict(kw,cas_root=str(link)))

    def test_changed_protected_state_and_second_read_reject(self):
        capsule, kw = self.inputs()
        self.rows['2'*64]['RestartCount'] += 1
        with self.assertRaises(ValueError):capture.reconstruct_initial_capture(encode(capsule), **kw)
        self.rows['2'*64]['RestartCount'] -= 1
        old = self.rows['1'*64]['State']['StartedAt']
        self.rows['1'*64]['State']['StartedAt'] = 'changed-lifecycle'
        with self.assertRaises(ValueError):capture.reconstruct_initial_capture(encode(capsule), **kw)
        self.rows['1'*64]['State']['StartedAt'] = old
        original = capture.TrustedPhaseStateProducerV3._get
        reads = 0
        def changed(producer, path):
            nonlocal reads
            value = original(producer, path)
            if path == '/v1.45/info':
                reads += 1
                if reads == 2:value['ID'] = 'other-daemon'
            return value
        with patch.object(capture.TrustedPhaseStateProducerV3, '_get', changed), self.assertRaises(ValueError):
            capture.reconstruct_initial_capture(encode(capsule), **kw)
        volume_reads = 0
        def inconsistent(producer, path):
            nonlocal volume_reads
            value = original(producer, path)
            if path.startswith('/v1.45/volumes/'):
                volume_reads += 1
                value['Status'] = {'observation': volume_reads}
            return value
        with patch.object(capture.TrustedPhaseStateProducerV3, '_get', inconsistent), self.assertRaises(ValueError):
            capture.reconstruct_initial_capture(encode(capsule), **kw)
        self.assertEqual(volume_reads, 2)

    def test_expiry_during_reads_timeout_and_cas_fd_cleanup(self):
        capsule, kw = self.inputs()
        before = len(os.listdir('/dev/fd'))
        expiry = datetime.strptime(capsule['request']['expires_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        clock = unittest.mock.Mock()
        clock.now.side_effect = [datetime.now(timezone.utc), expiry+timedelta(seconds=1)]
        with patch.object(capture,'datetime',clock), self.assertRaises(ValueError):
            capture.reconstruct_initial_capture(encode(capsule), **kw)
        with patch.object(capture.TrustedPhaseStateProducerV3,'_get',side_effect=TimeoutError('SECRET')), self.assertRaisesRegex(ValueError,'^compose-executor-capture-v3-rejected$'):
            capture.reconstruct_initial_capture(encode(capsule), **kw)
        self.assertEqual(len(os.listdir('/dev/fd')), before)

    def test_replaced_cas_root_is_rejected_and_fd_closed(self):
        capsule, kw = self.inputs()
        root = Path(kw['cas_root']); moved = self.root/'original-archive'
        original = capture.ComposeRecoveryStore._validate_root
        before = len(os.listdir('/dev/fd'))
        def replaced(store):
            root.rename(moved); root.mkdir(mode=0o700)
            try: return original(store)
            finally:
                root.rmdir(); moved.rename(root)
        with patch.object(capture.ComposeRecoveryStore, '_validate_root', replaced), self.assertRaises(ValueError):
            capture.reconstruct_initial_capture(encode(capsule), **kw)
        self.assertEqual(len(os.listdir('/dev/fd')), before)
        self.session.store.get(capsule['bundle']['baselineStateReference'])
        entry = root/capsule['bundle']['baselineStateReference']
        raw = entry.read_bytes()
        try:
            entry.write_bytes(raw+b' ')
            with self.assertRaises(ValueError):capture.reconstruct_initial_capture(encode(capsule), **kw)
        finally: entry.write_bytes(raw)
        self.session.store.get(capsule['bundle']['baselineStateReference'])

    @unittest.skipUnless(sys.platform == 'linux', 'real Linux fresh-exec CAS admission')
    def test_fresh_isolated_interpreter_reopens_linux_cas_get_only(self):
        capsule, kw = self.inputs()
        expected = dict(kw['expected']);expected['policy'] = 'c'*64
        spec = dict(kw)
        spec.update(capsule=capsule, expected=expected,
            integrity_keys={k:v.hex() for k,v in kw['integrity_keys'].items()}, cas_key=kw['cas_key'].hex())
        root = Path(__file__).resolve().parents[1]
        code = """import sys,json
from types import SimpleNamespace
root=sys.argv[1]
for rel in ('scripts','packs/deployment/scripts','packs/release/scripts','tests/support'):sys.path.insert(0,root+'/'+rel)
from deployment_compose_executor_capture_v3_host import reconstruct_initial_capture
from deployment_compose_operation_witness_client_v3 import encode
spec=json.loads(sys.stdin.buffer.read())
capsule=spec.pop('capsule');policy=spec['expected']['policy']
spec['expected']['policy']=SimpleNamespace(identity_hash=lambda:policy)
spec['integrity_keys']={k:bytes.fromhex(v) for k,v in spec['integrity_keys'].items()}
spec['cas_key']=bytes.fromhex(spec['cas_key'])
r=reconstruct_initial_capture(encode(capsule),**spec)
print(json.dumps(dict(phase=r.phase_digest,authority=r.authorityGranted,production=r.productionReady)))
"""
        self.calls.clear()
        result = subprocess.run([sys.executable,'-I','-S','-c',code,str(root)],input=json.dumps(spec).encode(),capture_output=True,timeout=40)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(set(json.loads(result.stdout)), {'phase','authority','production'})
        self.assertFalse(json.loads(result.stdout)['authority'])
        self.assertTrue(self.calls)
        self.assertEqual({m for m,p in self.calls},{'GET'})


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(CaptureTests(name) for name in CaptureTests.__dict__ if name.startswith('test_'))
