"""Native checkpoint authentication; SSH, source handshake and phase issuer are doubles.

The server's original PhaseGuard/Unix read behavior is tested separately. These
tests exercise the Mac response binding and owned transport lifecycle.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import os
import secrets
import shutil
import threading
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_scene_checkpoint_security_v3_host as security
from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3
from deployment_compose_scene_control_ssh_v3_host import SceneSSHClientV3, SceneSSHHandleV3
import deployment_compose_scene_control_ssh_v3_host as ssh
import deployment_compose_scene_live_phase_v3_host as phase
from deployment_compose_scene_create_certificate_v3_host import CHALLENGE
from deployment_compose_witness_store import canonical


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX/OpenSSL/OpenSSH required')
class SceneLivePhaseTests(unittest.TestCase):
    setUpClass = classmethod(security.SceneSecurityTests.setUpClass.__func__)
    reader = security.SceneSecurityTests.reader

    def invoke(self, reader, attack=''):
        payload, origin, archive = SceneCheckpointReaderV3._authenticate(reader)
        closure = payload['closure']['payload']; evidence = payload['evidence']
        handle = SceneSSHHandleV3(closure['sceneId'], '/var/tmp/'+closure['sceneId']+'/control.sock',
            secrets.token_bytes(32), payload['context']['hostId'], payload['context']['sourceSha'], archive)
        version = dict(Version='27.1', GitCommit='fixture')
        ns = [evidence['writerOrigin']['pidNamespaceDevice'], evidence['writerOrigin']['pidNamespaceInode']]
        endpoint = dict(daemonBinding=evidence['daemonBinding'], pidNamespace=ns, daemonPidNamespace=ns,
            networkNamespace=[1, 2], mountNamespace=[1, 3], normalizationVersion=version,
            rootIdentity=[1, 4], socketIdentity=[1, 5], pidFileIdentity=['dockerd.pid', [1, 6]])
        calls = []; clients = []
        def initialize(subject, selected):
            self.assertIs(selected, handle); subject._handle=handle; subject._closed=False
            subject._owner=(os.getpid(), threading.get_ident()); clients.append(subject)
        def call(subject, command, args=None):
            self.assertFalse(subject._closed); calls.append(command)
            if command == 'status':
                return dict(sceneId=closure['sceneId'], slotState='drained', slotGeneration=closure['slotGeneration'],
                    preparation={key:closure[key] for key in ('preparationId', 'capsuleDigest')},
                    daemonBinding=evidence['daemonBinding'], business=dict(businessState='reconciled',
                    closureReconciled=True, closureChallenge={key:closure[key] for key in CHALLENGE},
                    witnessKeyHash=self.descriptor['witnessKeyHash'], intentKeyHash=self.descriptor['intentKeyHash'],
                    checkpointEvidence=evidence))
            self.assertEqual(command, 'observe_closed_phase')
            result = dict(schemaVersion=1, kind='scene-live-phase-summary-v3', requestNonce=args['requestNonce'],
                closure=deepcopy(closure), phaseIndex=1, baselineDigest=payload['context']['baselineStateDigest'],
                phaseDigest=hashlib.sha256(b'actual phase belongs to server tests').hexdigest(),
                endpointBinding=deepcopy(endpoint), endpointBindingDigest=hashlib.sha256(canonical(endpoint)).hexdigest(),
                normalizationVersion=deepcopy(version), readOnly=True, **{key:False for key in phase._FALSE})
            if attack == 'nonce': result['requestNonce']='0'*64
            if attack == 'closure': result['closure']['attemptId']='0'*64
            if attack == 'daemon':
                result['endpointBinding']['daemonBinding']=dict(evidence['daemonBinding'], daemonId='other')
                result['endpointBindingDigest']=hashlib.sha256(canonical(result['endpointBinding'])).hexdigest()
            if attack == 'version': result['normalizationVersion']['Version']='different'
            if attack == 'namespace':
                result['endpointBinding']['pidNamespace']=[float(x) for x in ns]
                result['endpointBinding']['daemonPidNamespace']=[float(x) for x in ns]
                result['endpointBindingDigest']=hashlib.sha256(canonical(result['endpointBinding'])).hexdigest()
            if attack == 'authority': result['runtimePermit']=True
            if attack == 'boolean-index': result['phaseIndex']=True
            if attack == 'material': self.binding.chmod(0o644)
            return {'phaseObservation':result}
        def detach(subject):
            calls.append('detach'); subject._closed=True
            if attack == 'detach': raise ValueError('unclean relay EOF')
        def close(subject):
            calls.append('close'); subject._closed=True
        try:
            with ExitStack() as stack:
                for name, replacement in (('__init__', initialize), ('_call', call), ('detach', detach), ('close', close)):
                    stack.enter_context(patch.object(SceneSSHClientV3, name, replacement))
                stack.enter_context(patch.object(ssh, '_issued_scene_ssh_client', return_value=None))
                result=reader.observe_live_phase(handle=handle)
            self.assertTrue(all(client._closed for client in clients))
            return result, calls
        finally:
            if attack == 'material': self.binding.chmod(0o600)

    def test_summary_is_bound_to_original_scene_and_confers_no_recovery_authority(self):
        with self.reader() as reader:
            result, calls=self.invoke(reader)
            self.assertEqual(calls, ['status', 'observe_closed_phase', 'detach', 'close'])
            self.assertTrue(result.phaseApplicabilityVerified)
            self.assertFalse(result.rawPhaseAvailable)
            self.assertFalse(result.phaseFreshnessVerified)
            self.assertFalse(result.writerQuiescenceVerified)
            self.assertFalse(result.recoveryAuthorized)
            self.assertEqual(result.history_digest, self.descriptor['context']['historyDigest'])

    def test_wrong_nonce_closure_endpoint_version_or_authority_rejects(self):
        for attack in ('nonce', 'closure', 'daemon', 'version', 'namespace', 'authority', 'boolean-index', 'detach'):
            with self.subTest(attack=attack), self.reader() as reader, self.assertRaises(ValueError):
                self.invoke(reader, attack)

    def test_material_change_during_transport_rejects_after_owned_close(self):
        with self.reader() as reader, self.assertRaises(ValueError):
            self.invoke(reader, 'material')
