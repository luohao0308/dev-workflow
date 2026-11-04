"""Native checkpoint authentication; SSH, source handshake and phase issuer are doubles.

The server's original PhaseGuard/Unix read behavior is tested separately. These
tests exercise the Mac response binding and owned transport lifecycle.
"""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
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

    def invoke(self, reader, attack='', snapshot_mode=False, recheck=None, intent=None,
               session=None, fixture_material=None, intent_signer=None, prepare_worker=False, launch_worker=False,
               execute_stop=False, through_delete=False, full_recovery=False):
        if fixture_material is None:
            payload, origin, archive = SceneCheckpointReaderV3._authenticate(reader)
            baseline = reader.context.baseline_bytes
            authenticated_bundle = reader.context.history._bundle
        else:
            payload, origin, archive, baseline, authenticated_bundle = fixture_material
        closure = payload['closure']['payload']; evidence = payload['evidence']
        handle = SceneSSHHandleV3(closure['sceneId'], '/var/tmp/'+closure['sceneId']+'/control.sock',
            secrets.token_bytes(32), payload['context']['hostId'], payload['context']['sourceSha'], archive)
        version = dict(Version='27.1', GitCommit='fixture')
        ns = [evidence['writerOrigin']['pidNamespaceDevice'], evidence['writerOrigin']['pidNamespaceInode']]
        endpoint = dict(daemonBinding=evidence['daemonBinding'], pidNamespace=ns, daemonPidNamespace=ns,
            networkNamespace=[1, 2], mountNamespace=[1, 3], normalizationVersion=version,
            rootIdentity=[1, 4], socketIdentity=[1, 5], pidFileIdentity=['dockerd.pid', [1, 6]])
        rows=deepcopy(decode(baseline))
        bundle=authenticated_bundle.to_dict()
        candidate=deepcopy(rows[bundle['services'][0]['baselineContainerId']])
        cid=next(iter(closure['receiptMap'].values()));candidate['Id']=cid
        candidate['Config']['Env'].append('PAD='+'x'*9000)
        rows[cid]=candidate
        resources={'network:'+name:{} for name in bundle['networks']}
        resources.update({'volume:'+m['Name']:{} for row in rows.values() for m in row['Mounts'] if m['Type']=='volume'})
        full=canonical(dict(rows=rows,resources=resources))
        if attack=='shape':full=canonical(dict(rows=[],resources=resources))
        calls = []; clients = []; clock=[0.0]; staged = {}
        def initialize(subject, selected):
            self.assertIs(selected, handle); subject._handle=handle; subject._closed=False
            subject._owner=(os.getpid(), threading.get_ident()); clients.append(subject)
        def call(subject, command, args=None):
            self.assertFalse(subject._closed); calls.append(command)
            if command == 'confirm_recovery_worker':
                proof = args['proof']
                self.assertEqual(proof['intent']['payload']['nonce'], 'a'*64)
                self.assertEqual(proof['witness']['payload'], proof['intent']['payload'])
                confirmation = dict(workerProofDigest=phase.digest(canonical(proof['intent']['payload'])),
                                    recoveryHandoffDigest=staged['digest'])
                if args.get('launchWorker') is True:
                    confirmation['workerStartupDigest'] = '5'*64
                if args.get('executeStop') is True:
                    confirmation['workerRelay'] = dict(attemptId='5'*64, channelNonce='6'*64)
                return {'workerConfirmation': confirmation}
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
            expected = ('observe_stopped_writer_phase' if recheck is not None else
                        'capture_closed_phase_snapshot' if snapshot_mode else 'observe_closed_phase')
            self.assertEqual(command, expected)
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
            if recheck is not None:
                result['phaseDigest'] = hashlib.sha256(full).hexdigest()
                if attack == 'phase-drift':
                    result['phaseDigest'] = 'f' * 64
                if attack == 'endpoint-drift':
                    result['endpointBinding']['socketIdentity'] = [1, 7]
                    result['endpointBindingDigest'] = hashlib.sha256(
                        canonical(result['endpointBinding'])).hexdigest()
            if attack == 'authority': result['runtimePermit']=True
            if attack == 'boolean-index': result['phaseIndex']=True
            if attack == 'material': self.binding.chmod(0o644)
            if snapshot_mode:
                if attack=='heartbeat':clock[0]=14.0
                result['phaseDigest']=hashlib.sha256(full).hexdigest()
                return {'phaseSnapshot':dict(observation=result,snapshotId='9'*64,
                    totalBytes=True if attack=='bool-size' else len(full),chunkBytes=4096)}
            if recheck is not None:
                snapshot, _ = recheck
                first_write = args['firstWrite']
                self.assertEqual(first_write['historyDigest'], snapshot.history_digest)
                self.assertEqual(first_write['slotGeneration'], closure['slotGeneration'])
                self.assertEqual(first_write['phaseDigest'], snapshot.phase_digest)
                self.assertEqual(first_write['endpointBindingDigest'], snapshot.endpoint_binding_digest)
                next_op = authenticated_bundle.resolve_operations(closure['receiptMap'])[1]
                self.assertEqual(first_write['nextOperationDigest'], next_op['requestDigest'])
                observation = dict(phaseObservation=result,
                    writerOriginDigest='0'*64 if attack=='writer-origin' else hashlib.sha256(origin).hexdigest(),
                    writerStopObservationDigest={'stop-digest': True, 'writer-stop-drift': 'f'*64}.get(attack, 'e'*64),
                    firstWriteBindingDigest='0'*64 if attack=='first-write-binding' else phase.digest(canonical(first_write)))
                if 'recoveryHandoff' in args:
                    handoff = args['recoveryHandoff']['payload']
                    self.assertEqual(handoff['nonce'], args['requestNonce'])
                    self.assertEqual(handoff['sceneId'], closure['sceneId'])
                    self.assertEqual(handoff['firstWriteBindingDigest'], observation['firstWriteBindingDigest'])
                    observation['recoveryHandoffDigest'] = ('0'*64 if attack=='handoff-ack'
                                                           else phase.digest(canonical(handoff)))
                    observation['recoveryWorkerNonce'] = 'a'*64
                    staged['digest'] = observation['recoveryHandoffDigest']
                return {'writerPhaseObservation': observation}
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
                if session is not None:
                    if full_recovery:
                        result = session.execute_recovery(handle=handle, intent_signer=intent_signer)
                    elif through_delete:
                        result = session.execute_through_delete(handle=handle, intent_signer=intent_signer)
                    elif execute_stop:
                        result = session.execute_first_stop(handle=handle, intent_signer=intent_signer)
                    elif launch_worker:
                        result = session.launch_first_worker(handle=handle, intent_signer=intent_signer)
                    elif prepare_worker:
                        result = session.prepare_first_worker(handle=handle, intent_signer=intent_signer)
                    elif intent_signer is not None:
                        result = session.stage_first_write(handle=handle, intent_signer=intent_signer)
                    else:
                        result = session.recheck_first_write(handle=handle)
                elif recheck is not None:
                    snapshot, expected_digest = recheck
                    inputs = dict(snapshot=snapshot, expected_draft_digest=expected_digest, handle=handle)
                    if intent is None:
                        result = reader.recheck_snapshot_recovery_draft(**inputs)
                    elif 'expires_at' in intent:
                        result = reader.prepare_scene_recovery_intent(**inputs, **intent)
                    elif 'approval' in intent:
                        result = reader.admit_scene_recovery(**inputs, **intent)
                    else:
                        result = reader.verify_scene_recovery_intent(**inputs, **intent)
                elif snapshot_mode:
                    result = reader.capture_live_phase_snapshot(handle=handle)
                else:
                    result = reader.observe_live_phase(handle=handle)
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

    def test_snapshot_recovery_draft_binds_history_and_keeps_phase_private(self):
        with self.reader() as reader:
            snapshot, _ = self.invoke(reader, snapshot_mode=True)
            result = reader.prepare_snapshot_recovery_draft(snapshot=snapshot)
            raw = result['draft_bytes']
            draft = decode(raw)
            review = result['review']
            self.assertEqual(canonical(draft['historicalPhaseSnapshot']), snapshot.phase_bytes)
            self.assertEqual(canonical(draft['phaseSnapshotDescriptor']), snapshot.descriptor_bytes)
            self.assertEqual(review['draftDigest'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(review['historyDigest'], self.descriptor['context']['historyDigest'])
            self.assertEqual(draft['receiptMap'], dict(reader.context.snapshot.snapshot['receiptMap']))
            self.assertEqual(draft['knownWritePrefix'][0]['phase'], 'create')
            self.assertEqual([op['phase'] for op in draft['remainingOperations']],
                             ['stop', 'delete', 'rename', 'start', 'readiness'])
            self.assertEqual(review['nextOperationPhase'], 'stop')
            self.assertEqual(review['nextOperationDigest'], draft['remainingOperations'][0]['requestDigest'])
            self.assertEqual(review['startWriteIndex'], 1)
            self.assertIs(review['draftOnly'], True)
            for key in ('phaseFreshnessVerified', 'sourceRevalidated', 'daemonContinuityVerified',
                        'writerQuiescenceVerified', 'approvalReady', 'authorityGranted',
                        'executionAvailable', 'runtimePermit', 'recoveryAuthorized', 'productionReady'):
                self.assertIs(review[key], False)
                self.assertIs(draft[key], False)
            for key in ('historicalPhaseSnapshot', 'phaseSnapshotDescriptor', 'receiptMap',
                        'knownWritePrefix', 'closedTail', 'remainingOperations'):
                self.assertNotIn(key, review)
            self.assertNotIn('request', result)
            with self.reader() as different_reader, self.assertRaises(ValueError):
                different_reader.prepare_snapshot_recovery_draft(snapshot=snapshot)
            with self.assertRaises(ValueError):
                reader.prepare_snapshot_recovery_draft(snapshot=replace(snapshot))
            self.binding.chmod(0o644)
            try:
                with self.assertRaises(ValueError):
                    reader.prepare_snapshot_recovery_draft(snapshot=snapshot)
            finally:
                self.binding.chmod(0o600)
        with self.assertRaises(ValueError):
            reader.prepare_snapshot_recovery_draft(snapshot=snapshot)

    def test_snapshot_renews_only_through_original_status_after_slow_capture(self):
        with self.reader() as reader:
            result,calls=self.invoke(reader,'heartbeat',snapshot_mode=True)
            self.assertEqual(calls.count('status'),2)
            self.assertTrue(result.historicalSnapshotVerified)

    def test_draft_recheck_requires_pinned_draft_and_matching_new_observation(self):
        with self.reader() as reader:
            snapshot, _ = self.invoke(reader, snapshot_mode=True)
            draft = reader.prepare_snapshot_recovery_draft(snapshot=snapshot)['review']
            with patch.object(SceneSSHClientV3, '__init__', side_effect=AssertionError('unexpected SSH')):
                with self.assertRaises(ValueError):
                    reader.recheck_snapshot_recovery_draft(snapshot=snapshot,
                        expected_draft_digest='0' * 64, handle=None)

            recheck = (snapshot, draft['draftDigest'])
            result, calls = self.invoke(reader, recheck=recheck)
            self.assertEqual(calls, ['status', 'observe_stopped_writer_phase', 'detach', 'close'])
            self.assertEqual(result['kind'], 'compose-scene-snapshot-draft-recheck-v3')
            self.assertEqual(result['draftDigest'], draft['draftDigest'])
            self.assertEqual(result['sourceSha'], self.descriptor['context']['sourceSha'])
            self.assertIs(result['livePhaseMatchesDraft'], True)
            self.assertIs(result['publishedSourceCheckedOnAttach'], True)
            self.assertIs(result['originalWriterStoppedBeforeAndAfter'], True)
            self.assertEqual(result['writerStopObservationDigest'], 'e'*64)
            first_write = {key:draft[key] for key in ('historyDigest', 'slotGeneration', 'nextOperationDigest',
                                                       'phaseDigest', 'endpointBindingDigest')}
            self.assertEqual(result['firstWriteBindingDigest'], phase.digest(canonical(first_write)))
            for key in ('phaseFreshnessVerified', 'sourceRevalidated', 'daemonContinuityVerified',
                        'writerQuiescenceVerified', 'approvalReady', 'authorityGranted',
                        'executionAvailable', 'runtimePermit', 'recoveryAuthorized', 'productionReady'):
                self.assertIs(result[key], False)
            for attack in ('phase-drift', 'endpoint-drift', 'writer-origin', 'stop-digest', 'first-write-binding',
                           'nonce', 'closure', 'detach', 'material'):
                with self.subTest(attack=attack), self.assertRaises(ValueError):
                    self.invoke(reader, attack, recheck=recheck)

    def test_draft_recheck_rejects_changed_published_ref_before_ssh_spawn(self):
        with self.reader() as reader:
            snapshot, _ = self.invoke(reader, snapshot_mode=True)
            review = reader.prepare_snapshot_recovery_draft(snapshot=snapshot)['review']
            pins = self.descriptor['context']
            handle = SceneSSHHandleV3(snapshot.scene_id, '/var/tmp/' + snapshot.scene_id + '/control.sock',
                secrets.token_bytes(32), pins['hostId'], pins['sourceSha'], reader.read_source_archive())
            original_git = ssh.source._git
            queries = []

            def git(*args):
                if args[0] == 'ls-remote':
                    queries.append(args)
                    return ('0' * 40 + '\t' + ssh.source.PUBLISHED_REF + '\n').encode()
                return original_git(*args)

            with patch.object(ssh.source, 'ROOT', self.source.repo), patch.object(ssh.source, '_git', git), \
                    patch.object(ssh, '_spawn') as spawn:
                with self.assertRaises(ValueError):
                    reader.recheck_snapshot_recovery_draft(snapshot=snapshot,
                        expected_draft_digest=review['draftDigest'], handle=handle)
                spawn.assert_not_called()
            self.assertEqual(queries, [('ls-remote', '--exit-code', 'origin', ssh.source.PUBLISHED_REF)])

    def test_scene_recovery_intent_binds_exact_first_write_and_requires_a_new_recheck(self):
        from deployment_compose_approval_v3_host import GitHubFullBodyApprovalV3
        from deployment_compose_scene_recovery_intent_v3_host import KIND, PROFILE
        from deployment_contract_v2 import RequestV2
        from release_execute import AuthorizationUnavailable

        expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        with self.reader() as reader:
            snapshot, _ = self.invoke(reader, snapshot_mode=True)
            draft = reader.prepare_snapshot_recovery_draft(snapshot=snapshot)['review']
            recheck = (snapshot, draft['draftDigest'])
            prepared, calls = self.invoke(reader, recheck=recheck, intent={'expires_at': expires})
            self.assertEqual(calls, ['status', 'observe_stopped_writer_phase', 'detach', 'close'])
            request = RequestV2.from_json(prepared['request'].canonical_json())
            raw = prepared['context_bytes']
            context = decode(raw)
            self.assertEqual(request.operation, 'recovery')
            self.assertEqual(request.profile_id, PROFILE)
            self.assertEqual(request.max_uses, 1)
            self.assertEqual(request.history_hash, snapshot.history_digest)
            self.assertEqual(request.observation_hash, phase.digest(raw))
            self.assertEqual(request.plan_hash, draft['originalBundleDigest'])
            self.assertEqual(request.source.source_sha, self.descriptor['context']['sourceSha'])
            self.assertEqual(context['kind'], KIND)
            self.assertEqual(context['nextOperationDigest'], draft['nextOperationDigest'])
            self.assertEqual(context['firstWriteBindingDigest'], prepared['review']['firstWriteBindingDigest'])
            self.assertNotIn('historicalPhaseSnapshot', context)
            self.assertNotEqual(context['intentNonce'], reader.context.history._bundle.to_dict()['operationNonce'])
            self.assertIs(prepared['review']['approvalReady'], False)
            self.assertIs(prepared['review']['runtimePermit'], False)

            old_approval = object.__new__(GitHubFullBodyApprovalV3)
            old_approval._requests = {request.digest(): request}
            old_approval.policy = SimpleNamespace(operation='recovery')
            with self.assertRaises(AuthorizationUnavailable):
                old_approval._match(request)

            verify = dict(request=request, expected_request_digest=request.digest(), context_bytes=raw)
            verified, calls = self.invoke(reader, recheck=recheck, intent=verify)
            self.assertEqual(calls.count('observe_stopped_writer_phase'), 1)
            self.assertEqual(verified['requestDigest'], request.digest())
            self.assertNotEqual(verified['liveObservationDigest'], prepared['review']['liveObservationDigest'])
            for attack in ('endpoint-drift', 'writer-stop-drift'):
                with self.subTest(attack=attack), self.assertRaises(ValueError):
                    self.invoke(reader, attack, recheck=recheck, intent=verify)
            tampered = canonical(dict(context, nextOperationDigest='0'*64))
            forged = replace(request, observation_hash=phase.digest(tampered))
            with self.assertRaises(ValueError):
                self.invoke(reader, recheck=recheck, intent=dict(request=forged,
                    expected_request_digest=forged.digest(), context_bytes=tampered))
            with patch.object(SceneSSHClientV3, '__init__', side_effect=AssertionError('unexpected SSH')):
                with self.assertRaises(ValueError):
                    reader.verify_scene_recovery_intent(snapshot=snapshot, expected_draft_digest=draft['draftDigest'],
                        handle=None, **dict(verify, expected_request_digest='0'*64))
                for expiry in ('2020-01-01T00:00:00Z', '2099-01-01T00:00:00Z'):
                    with self.subTest(expiry=expiry), self.assertRaises(ValueError):
                        reader.prepare_scene_recovery_intent(snapshot=snapshot,
                            expected_draft_digest=draft['draftDigest'], handle=None, expires_at=expiry)


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl') and shutil.which('ssh-keygen'),
                     'POSIX/OpenSSL/OpenSSH required')
class SceneRecoveryAdmissionTests(unittest.TestCase):
    setUpClass = classmethod(security.SceneSecurityTests.setUpClass.__func__)
    reader = security.SceneSecurityTests.reader
    invoke = SceneLivePhaseTests.invoke

    def test_original_ledger_activates_one_empty_stop_scope(self):
        from deployment_compose_approval_v3_host import GitHubSceneRecoveryApprovalV3, SceneRecoveryApprovalPolicyV3
        from deployment_compose_scene_checkpoint_v3_host import _arguments
        from deployment_compose_scene_recovery_intent_v3_host import scene_recovery_public_review
        from tests.test_deployment_compose_approval_v3_host import policy
        from tests.test_release_host import Client
        from release_execute import AuthorizationUnavailable

        expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        with self.reader() as reader:
            snapshot, _ = self.invoke(reader, snapshot_mode=True)
            draft = reader.prepare_snapshot_recovery_draft(snapshot=snapshot)['review']
            recheck = (snapshot, draft['draftDigest'])
            prepared, _ = self.invoke(reader, recheck=recheck, intent={'expires_at': expires})
            request = prepared['request']
            base = policy(operation='recovery', target_repository=request.source.project_path,
                          target_repository_id=request.source.project_id, source_sha=request.source.source_sha,
                          target=request.target, daemon_id=request.daemon_id, host_id=request.host_id,
                          components=request.components, protected_components=request.protected_components,
                          policy_hash=request.policy_hash, bundle_hash=request.plan_hash,
                          expected_history_hash=request.history_hash, expires_at=expires)
            config = SceneRecoveryApprovalPolicyV3(**vars(base), expected_observation_hash=request.observation_hash,
                expected_scene_review_hash=phase.digest(canonical(scene_recovery_public_review(prepared['review']))))
            client = Client(config, [request])

            def authority(subject):
                subject._match(request)
                subject._expires = datetime.now(timezone.utc).replace(microsecond=0).timestamp()+300

            with patch.object(GitHubSceneRecoveryApprovalV3, '_check_authority', authority):
                approval = GitHubSceneRecoveryApprovalV3(client, 'fixture', [request], config)
                with patch.object(approval, '_grant_expiry', return_value=approval._expires):
                    receipt = approval.consume(approval.validate(request), request)
                intent = dict(request=request, expected_request_digest=request.digest(),
                              context_bytes=prepared['context_bytes'], approval=approval, receipt=receipt)
                store = reader._reader._store
                state = store.root/'state.json'
                before = state.read_bytes()
                with self.assertRaises(AuthorizationUnavailable):
                    self.invoke(reader, recheck=recheck, intent=dict(intent, receipt=replace(receipt)))
                with self.assertRaises(ValueError):
                    self.invoke(reader, 'endpoint-drift', recheck=recheck, intent=intent)
                self.assertEqual(state.read_bytes(), before)

                copy_case = self.case.parent/'copied-admission'
                shutil.copytree(self.case, copy_case)
                with SceneCheckpointReaderV3(copy_case, **_arguments(self.descriptor)) as copied:
                    copied_snapshot, _ = self.invoke(copied, snapshot_mode=True)
                    with self.assertRaises(ValueError):
                        self.invoke(copied, recheck=(copied_snapshot, draft['draftDigest']), intent=intent)
                    self.assertEqual((copy_case/'witness/state.json').read_bytes(), before)

                fixture_material = (*SceneCheckpointReaderV3._authenticate(reader), reader.context.baseline_bytes,
                                    reader.context.history._bundle)
                result, calls = self.invoke(reader, recheck=recheck, intent=intent)
                self.assertEqual(calls, ['status', 'observe_stopped_writer_phase', 'detach', 'close'])
                self.assertIs(result['successorActivated'], True)
                self.assertIs(result['runtimePermit'], False)
                self.assertEqual(result['nextOperationDigest'], draft['nextOperationDigest'])
                child = store.read(result['firstBinding'])
                self.assertEqual(child['lineage'], [result['parentTail']])
                self.assertEqual((child['phase'], child['seq'], child['active']), ('empty', 0, True))
                after = state.read_bytes()
                session = result['session']
                with self.assertRaises(ValueError):
                    _ = reader.context
                first_binding = deepcopy(result['firstBinding'])
                result['firstBinding']['generation'] = '0'*64
                verified, calls = self.invoke(reader, recheck=recheck, session=session,
                                              fixture_material=fixture_material)
                self.assertEqual(calls, ['status', 'observe_stopped_writer_phase', 'detach', 'close'])
                self.assertEqual(verified['firstBinding'], first_binding)
                self.assertEqual(verified['nextOperationDigest'], draft['nextOperationDigest'])
                self.assertIs(verified['runtimePermit'], False)
                staged, calls = self.invoke(reader, recheck=recheck, session=session,
                    fixture_material=fixture_material, intent_signer=self.case/'intent-signing')
                self.assertEqual(calls, ['status', 'status', 'observe_stopped_writer_phase', 'detach', 'close'])
                self.assertEqual(staged['firstBinding'], first_binding)
                self.assertEqual(len(staged['recoveryHandoffDigest']), 64)
                ready, calls = self.invoke(reader, recheck=recheck, session=session,
                    fixture_material=fixture_material, intent_signer=self.case/'intent-signing', prepare_worker=True)
                self.assertEqual(calls, ['status', 'status', 'observe_stopped_writer_phase', 'status',
                                         'confirm_recovery_worker', 'detach', 'close'])
                self.assertEqual(len(ready['workerProofDigest']), 64)
                self.assertIs(ready['runtimePermit'], False)
                started, calls = self.invoke(reader, recheck=recheck, session=session,
                    fixture_material=fixture_material, intent_signer=self.case/'intent-signing', launch_worker=True)
                self.assertEqual(calls, ['status', 'status', 'observe_stopped_writer_phase', 'status',
                                         'confirm_recovery_worker', 'detach', 'close'])
                self.assertEqual(started['workerStartupDigest'], '5'*64)
                with self.assertRaises(ValueError):
                    self.invoke(reader, 'handoff-ack', recheck=recheck, session=session,
                        fixture_material=fixture_material, intent_signer=self.case/'intent-signing')
                with self.assertRaises(ValueError):
                    self.invoke(reader, 'endpoint-drift', recheck=recheck, session=session,
                                fixture_material=fixture_material)
                with self.assertRaises(ValueError):
                    type(session)().recheck_first_write(handle=None)
                with self.assertRaises(ValueError):
                    reader.admit_scene_recovery(snapshot=snapshot, expected_draft_digest=draft['draftDigest'],
                                                handle=None, **intent)
                self.assertEqual(state.read_bytes(), after)
                self.assertEqual(client.posts, 1)
                def drive(_, relay, proof, proof_digest, authorize, *, stop_verifier, through_delete=False,
                          full_recovery=False):
                    self.assertEqual(relay, dict(attemptId='5'*64, channelNonce='6'*64))
                    self.assertTrue(through_delete)
                    self.assertTrue(full_recovery)
                    self.assert_first_stop_witness(reader, session, request, result, first_binding, fixture_material,
                                                   authorize=authorize)
                    self.assertEqual(stop_verifier()['status'], 204)
                    return '7'*64
                with patch.object(phase, '_drive_recovery_relay', side_effect=drive) as transport:
                    executed, _ = self.invoke(reader, recheck=recheck, session=session,
                        fixture_material=fixture_material, intent_signer=self.case/'intent-signing', full_recovery=True)
                transport.assert_called_once()
                self.assertEqual(executed['stopReceipt']['status'], 204)
                self.assertEqual(executed['stopReceipt']['binding'], first_binding)
                self.assertEqual(executed['deleteReceipt']['status'], 204)
                self.assertNotEqual(executed['deleteReceipt']['binding'], first_binding)
                self.assertEqual(executed['renameReceipt']['status'], 204)
                self.assertEqual(executed['startReceipt']['status'], 204)
                self.assertIs(executed['recoveryComplete'], True)
                self.assertEqual(executed['workerRelayDigest'], '7'*64)
                authorize = transport.call_args.args[4]
                store._persist(store._read())
                with self.assertRaises(ValueError):
                    authorize.verify_stop()

    def assert_first_stop_witness(self, reader, session, request, result, binding, fixture_material, *, authorize):
        import subprocess
        from deployment_compose_coordinator_v3_host import Profile3StepExecutor
        from deployment_compose_gate_witness_v3 import GateOperationWitnessAdapterV3
        from deployment_compose_intent_status_v3 import IntentStatusClientV3
        from deployment_compose_operation_witness_client_v3 import OperationWitnessClientV3
        from deployment_compose_witness_store import ZERO
        from deployment_gateway import FileWriterGate

        signer = self.case/'intent-signing'
        public = subprocess.run(['/usr/bin/ssh-keygen', '-y', '-f', str(signer)], capture_output=True, check=True).stdout
        with self.assertRaises(ValueError):
            session.open_first_stop_rpc(intent_signer=signer)
        intent = IntentStatusClientV3(request, public, lambda rpc: authorize('intent', 'check', rpc), scene_recovery=True)
        intent.check_consumed_intent(request)
        history = reader._reader._context.history
        witness_key = history._client._public
        witness = OperationWitnessClientV3(binding, witness_key, lambda method, rpc: authorize('witness', method, rpc))
        self.assertEqual(witness.check(expected_seq=0, expected_head=ZERO)['lineage'], [result['parentTail']])
        with self.assertRaises(ValueError):
            witness.transition_successor(expected_seq=0, expected_head=ZERO,
                                         childBinding=dict(binding, generation='3'*64))
        receipts = fixture_material[0]['closure']['payload']['receiptMap']
        bundle = fixture_material[-1]
        operations = bundle.resolve_operations(receipts)
        operation = operations[1]
        delete_scope = Profile3StepExecutor.scope_descriptor(bundle, request, result['receiptDigest'], operations[2], 2, receipts)
        child = dict(binding, generation=delete_scope['generation'], scopeHash=delete_scope['scopeHash'])
        with self.assertRaises(ValueError):
            witness.transition_successor(expected_seq=0, expected_head=ZERO, childBinding=child)
        scope = Profile3StepExecutor.scope_descriptor(bundle, request, result['receiptDigest'], operation, 1, receipts)
        policy = replace(history._policy, witness_scope_hash=binding['scopeHash'])
        gate = FileWriterGate(policy, self.case/'first-stop-gate', key=history._key,
                              witness=GateOperationWitnessAdapterV3(witness))
        opening = gate.open_generation(generation=binding['generation'], request_hash=request.digest(),
            receipt_hash=result['receiptDigest'], operations=scope['operations'], source_context_digest=scope['source'])
        with self.assertRaises(ValueError):
            opening.prepare_attempt('DELETE', operation['path'], b'')
        attempt = opening.prepare_attempt(operation['method'], operation['path'], b'')
        ticket = gate.admit(binding['generation'], attempt.ref, method=operation['method'],
            path=operation['path'], body=b'', writer_certificate_sha256=policy.writer_certificate_sha256)
        gate.finish_response(ticket, definitive=True, status=204, body=b'')
        gate.close_generation(binding['generation'])
        self.assertEqual(witness.read()['phase'], 'closed')
        self.assertEqual(witness.read()['seq'], 6)
        with self.assertRaises(ValueError):
            witness.transition_successor(expected_seq=6, expected_head=witness.read()['head'],
                                         childBinding=dict(binding, generation='3'*64))
        stop_head = witness.read()['head']
        with self.assertRaises(ValueError):
            witness.transition_successor(expected_seq=6, expected_head='1'*64, childBinding=child)
        for index in range(2, 5):
            operation = operations[index]
            scope = Profile3StepExecutor.scope_descriptor(bundle, request, result['receiptDigest'], operation, index, receipts)
            child = dict(binding, generation=scope['generation'], scopeHash=scope['scopeHash'])
            witness.transition_successor(expected_seq=6, expected_head=witness.read()['head'], childBinding=child)
            witness = OperationWitnessClientV3(child, witness_key,
                lambda method, rpc: authorize('witness', method, rpc))
            gate = FileWriterGate(replace(policy, witness_scope_hash=child['scopeHash']),
                self.case/(operation['phase']+'-gate'), key=history._key, witness=GateOperationWitnessAdapterV3(witness))
            opening = gate.open_generation(generation=child['generation'], request_hash=request.digest(),
                receipt_hash=result['receiptDigest'], operations=scope['operations'], source_context_digest=scope['source'])
            attempt = opening.prepare_attempt(operation['method'], operation['path'], b'')
            ticket = gate.admit(child['generation'], attempt.ref, method=operation['method'], path=operation['path'],
                                body=b'', writer_certificate_sha256=policy.writer_certificate_sha256)
            gate.finish_response(ticket, definitive=True, status=204, body=b'')
            gate.close_generation(child['generation'])
            self.assertEqual(authorize.verify_stop()['head'], stop_head)
            verifier = getattr(authorize, 'verify_'+operation['phase'])
            self.assertEqual(verifier()['head'], witness.read()['head'])
        with self.assertRaises(ValueError):
            witness.transition_successor(expected_seq=6, expected_head=witness.read()['head'],
                                         childBinding=dict(child,generation='4'*64))
