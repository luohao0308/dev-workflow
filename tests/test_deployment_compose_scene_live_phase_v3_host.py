"""Native checkpoint authentication; SSH, source handshake and phase issuer are doubles.

The server's original PhaseGuard/Unix read behavior is tested separately. These
tests exercise the Mac response binding and owned transport lifecycle.
"""
from contextlib import ExitStack
from copy import deepcopy
import base64
import hashlib
import os
import secrets
import shutil
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_deployment_compose_scene_checkpoint_security_v3_host as security
from deployment_compose_scene_checkpoint_v3_host import SceneCheckpointReaderV3
from deployment_compose_scene_control_ssh_v3_host import SceneSSHClientV3, SceneSSHHandleV3
import deployment_compose_scene_control_ssh_v3_host as ssh
import deployment_compose_scene_live_phase_v3_host as phase
from deployment_compose_scene_create_certificate_v3_host import CHALLENGE
from deployment_compose_witness_store import canonical
from deployment_compose_recovery_phase_capsule_v3_host import decode


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX/OpenSSL/OpenSSH required')
class SceneLivePhaseTests(unittest.TestCase):
    setUpClass = classmethod(security.SceneSecurityTests.setUpClass.__func__)
    reader = security.SceneSecurityTests.reader

    def invoke(self, reader, attack='', snapshot_mode=False):
        payload, origin, archive = SceneCheckpointReaderV3._authenticate(reader)
        closure = payload['closure']['payload']; evidence = payload['evidence']
        handle = SceneSSHHandleV3(closure['sceneId'], '/var/tmp/'+closure['sceneId']+'/control.sock',
            secrets.token_bytes(32), payload['context']['hostId'], payload['context']['sourceSha'], archive)
        version = dict(Version='27.1', GitCommit='fixture')
        ns = [evidence['writerOrigin']['pidNamespaceDevice'], evidence['writerOrigin']['pidNamespaceInode']]
        endpoint = dict(daemonBinding=evidence['daemonBinding'], pidNamespace=ns, daemonPidNamespace=ns,
            networkNamespace=[1, 2], mountNamespace=[1, 3], normalizationVersion=version,
            rootIdentity=[1, 4], socketIdentity=[1, 5], pidFileIdentity=['dockerd.pid', [1, 6]])
        rows=deepcopy(decode(reader.context.baseline_bytes))
        bundle=reader.context.history._bundle.to_dict()
        candidate=deepcopy(rows[bundle['services'][0]['baselineContainerId']])
        cid=next(iter(closure['receiptMap'].values()));candidate['Id']=cid
        candidate['Config']['Env'].append('PAD='+'x'*9000)
        rows[cid]=candidate
        resources={'network:'+name:{} for name in bundle['networks']}
        resources.update({'volume:'+m['Name']:{} for row in rows.values() for m in row['Mounts'] if m['Type']=='volume'})
        full=canonical(dict(rows=rows,resources=resources))
        if attack=='shape':full=canonical(dict(rows=[],resources=resources))
        calls = []; clients = []; clock=[0.0]
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
            if command=='read_closed_phase_chunk':
                if attack=='budget':clock[0]=121.0
                offset=args['offset'];data=full[offset:offset+args['length']]
                if attack=='truncated':data=data[:-1]
                return {'phaseChunk':dict(snapshotId='8'*64 if attack=='mixed' else '9'*64,
                    phaseDigest=hashlib.sha256(full).hexdigest(),totalBytes=len(full),offset=offset,
                    dataBase64=base64.b64encode(data).decode('ascii'))}
            self.assertEqual(command, 'capture_closed_phase_snapshot' if snapshot_mode else 'observe_closed_phase')
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
            if snapshot_mode:
                if attack=='heartbeat':clock[0]=14.0
                result['phaseDigest']=hashlib.sha256(full).hexdigest()
                return {'phaseSnapshot':dict(observation=result,snapshotId='9'*64,
                    totalBytes=True if attack=='bool-size' else len(full),chunkBytes=4096)}
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
                if attack in ('budget','heartbeat'):
                    import deployment_compose_scene_phase_snapshot_v3_host as snapshots
                    stack.enter_context(patch.object(snapshots,'time',SimpleNamespace(monotonic=lambda:clock[0])))
                result=(reader.capture_live_phase_snapshot(handle=handle) if snapshot_mode else
                        reader.observe_live_phase(handle=handle))
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

    def test_full_snapshot_multichunk_and_issued_object_boundary(self):
        from copy import copy
        from dataclasses import replace
        from deployment_compose_scene_phase_snapshot_v3_host import validate_scene_phase_snapshot
        with self.reader() as reader:
            result,calls=self.invoke(reader,snapshot_mode=True)
            self.assertGreater(calls.count('read_closed_phase_chunk'),1)
            self.assertTrue(result.rawPhaseAvailable)
            self.assertFalse(result.phaseFreshnessVerified)
            self.assertFalse(result.recoveryAuthorized)
            self.assertEqual(validate_scene_phase_snapshot(result,reader=reader)[0],result.phase_bytes)
            self.assertEqual(result.public_summary()['history_digest'],self.descriptor['context']['historyDigest'])
            with self.assertRaises(ValueError):copy(result)
            with self.assertRaises(ValueError):validate_scene_phase_snapshot(replace(result),reader=reader)
            errors=[]
            def foreign():
                try:validate_scene_phase_snapshot(result,reader=reader)
                except ValueError:errors.append(True)
            thread=threading.Thread(target=foreign);thread.start();thread.join(timeout=5)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,[True])
            pid=os.fork()
            if pid==0:
                try:validate_scene_phase_snapshot(result,reader=reader)
                except ValueError:os._exit(0)
                os._exit(1)
            self.assertEqual(os.waitpid(pid,0)[1],0)
            object.__setattr__(result,'historicalSnapshotVerified',1)
            with self.assertRaises(ValueError):validate_scene_phase_snapshot(result,reader=reader)
            object.__setattr__(result,'historicalSnapshotVerified',True)
        with self.assertRaises(ValueError):validate_scene_phase_snapshot(result,reader=reader)

    def test_snapshot_rejects_mixed_truncated_shape_bool_and_final_transport_failure(self):
        from deployment_compose_scene_phase_snapshot_v3_host import _SNAPSHOTS
        for attack in ('mixed','truncated','shape','bool-size','detach','material','budget'):
            with self.subTest(attack=attack),self.reader() as reader:
                before={id(item) for item in _SNAPSHOTS}
                with self.assertRaises(ValueError):self.invoke(reader,attack,snapshot_mode=True)
                self.assertFalse({id(item) for item in _SNAPSHOTS}-before)

    def test_snapshot_renews_only_through_original_status_after_slow_capture(self):
        with self.reader() as reader:
            result,calls=self.invoke(reader,'heartbeat',snapshot_mode=True)
            self.assertEqual(calls.count('status'),2)
            self.assertTrue(result.historicalSnapshotVerified)
