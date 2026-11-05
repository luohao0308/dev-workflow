"""Real signed history and private archive; current builder seam is UNIT ONLY."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
import shutil
import unittest
from unittest.mock import patch

from tests.test_deployment_compose_prepare_v3_host import fixture
from tests import test_deployment_compose_history_v3_host as history_fixture
from tests.test_deployment_compose_snapshot import KEY
from deployment_compose_prepare_v3_host import ComposePreparationHostV3
from deployment_compose_bundle_v3 import ExecutionBundleV3
from deployment_compose_image_defaults import ZERO_DEFAULTS
from deployment_compose_coordinator_v3_host import canonical
from deployment_compose_rollback_prepare_v3_host import RollbackPreparationHostV3


def expiry():
    return (datetime.now(timezone.utc)+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH required')
class RollbackTests(unittest.TestCase):
    def setUp(self):
        kw, observation = fixture()
        self.kw, self.observation = kw, observation
        self.prep = ComposePreparationHostV3(**kw)
        self.original = self.prep.prepare_intent(observation,observation,operation_nonce='f'*64,expires_at=expiry())
        h = history_fixture.HistoryTests('test_two_scopes_and_no_local_files')
        h.setup_gate_fixture()
        self.addCleanup(h.doCleanups)
        h.bundle = self.original['bundle']
        # The historical grant is expired. No freshness renewal is attempted.
        h.req = replace(self.original['request'],expires_at='2020-01-01T00:00:00Z')
        h.receipts = {}; h.index = 0; h.open_scope()
        self.signed = h
        self.complete()
        current = h.bundle.to_dict()
        for key in ('resolverContract','resolverRules','resolverContractDigest','imageDefaultsDigests','operations'):
            current.pop(key,None)
        # Bundle-generated resolver fields are removed below using the actual schema.
        for key in tuple(current):
            if key not in {'schemaVersion','profile','profileVersion','identity','services','protectedContainers','networks','mounts','archiveReference','sourceSnapshotDigest','retentionBindingDigest','baselineStateReference','baselineStateDigest','operationNonce','expiresAt'}:
                current.pop(key)
        service=current['services'][0]; old=deepcopy(service)
        service.update(baselineContainerId='a'*64,baselineImageId=old['targetImageId'],targetImageId=old['baselineImageId'],
                       baselineCreateBody=old['targetCreateBody'],targetCreateBody=old['baselineCreateBody'])
        current['operationNonce']='b'*64
        self.current_bundle=ExecutionBundleV3(current,authenticated_image_defaults={'web':deepcopy(ZERO_DEFAULTS)})
        req=replace(self.original['request'],plan_hash=self.current_bundle.digest)
        self.current=dict(bundle=self.current_bundle,request=req,review=self.current_bundle.public_review())
        self.current['review'].update(blockers=['coordinator-admission-and-recovery-required'],authorityGranted=False,productionReady=False,executionAvailable=False)
        artifact=kw['whole_observer']._baseline_artifacts.services[0]
        self.prep._target_inputs['web'].update(expected_image_id=artifact.image_id,expected_registry_digest=artifact.registry_digest,expected_architecture=artifact.architecture)
        self.host=RollbackPreparationHostV3(original_bundle=h.bundle,original_request=h.req,original_history=h.history(),
            original_archive_store=kw['recovery']._store,original_private_keys={'inspect-key':KEY},current_preparation=self.prep)

    def complete(self):
        h=self.signed
        while True:
            h.finish(status=201 if h.op['phase']=='create' else 204,body=None if h.op['phase']=='create' else b'')
            h.receipts={'web':'a'*64}
            writes=[op for op in h.bundle.resolve_operations(h.receipts) if op['method']!='GET']
            if h.index==len(writes)-1: break
            h.index+=1; h.open_scope()

    def prepare(self, callback=None):
        with patch.object(self.prep,'prepare_intent',side_effect=callback or (lambda *a,**k:self.current)):
            return self.host.prepare_intent(self.observation,self.observation,operation_nonce='b'*64,expires_at=expiry())

    def test_expired_deploy_yields_fresh_rollback(self):
        result=self.prepare()
        self.assertEqual(result['request'].operation,'rollback')
        self.assertEqual(result['request'].history_hash,self.host._history.capture().digest)
        self.assertEqual(result['request'].plan_hash,result['bundle'].digest)
        self.assertFalse(result['review']['runtimePermit'])
        self.assertIn('startup-fence-required',result['review']['blockers'])
        self.assertNotIn('Env',json.dumps(result['review']))

    def test_archive_missing_tampered_or_extra_keys(self):
        store=self.host._store; raw=store.get(self.original['bundle'].to_dict()['archiveReference'])
        bad=json.loads(raw);bad['unexpected']=True
        alias=json.loads(raw);alias['schemaVersion']=True
        tampered=json.loads(raw);tampered['privateProjections']['web']['Config']['Env'].append('EXTRA=secret')
        for content in (b'{}',canonical(bad),canonical(alias),canonical(tampered)):
            with self.subTest(content=content[:12]),patch.object(store,'get',return_value=content),self.assertRaises(ValueError):self.prepare()

    def test_current_id_and_body_substitution(self):
        for field in ('baselineContainerId','targetCreateBody','protectedContainers'):
            value=self.current_bundle.to_dict()
            if field=='baselineContainerId':value['services'][0][field]='d'*64
            elif field=='targetCreateBody':
                for body in ('baselineCreateBody','targetCreateBody'):value['services'][0][body]['Env'].append('EXTRA=secret')
            else:value[field][0]['containerId']='d'*64
            for key in tuple(value):
                if key not in {'schemaVersion','profile','profileVersion','identity','services','protectedContainers','networks','mounts','archiveReference','sourceSnapshotDigest','retentionBindingDigest','baselineStateReference','baselineStateDigest','operationNonce','expiresAt'}:value.pop(key)
            self.current['bundle']=ExecutionBundleV3(value,authenticated_image_defaults={'web':deepcopy(ZERO_DEFAULTS)})
            with self.subTest(field=field),self.assertRaises(ValueError):self.prepare()

    def test_no_original_observer_recheck_and_archive_reread(self):
        with patch.object(self.prep._whole,'retention_commitment',side_effect=AssertionError('original observer forbidden')):
            self.prepare()
        original=self.host._store.get
        def mutate(*a,**k):
            self.host._store.get=lambda _:b'{}'
            return self.current
        try:
            with self.assertRaises(ValueError):self.prepare(mutate)
        finally:self.host._store.get=original

    def test_cross_request_and_wrong_key(self):
        self.host._keys={'inspect-key':b'wrong'*8}
        with self.assertRaises(ValueError):self.prepare()
        with self.assertRaises(ValueError):
            RollbackPreparationHostV3(original_bundle=self.signed.bundle,original_request=replace(self.signed.req,policy_hash='a'*64),
                original_history=self.signed.history(),original_archive_store=self.host._store,original_private_keys={'inspect-key':KEY},current_preparation=self.prep)

    def test_mid_preparation_history_advancement(self):
        def advance(*a, **k):
            h=self.signed
            view=h.client.read()
            binding=dict(h.binding,generation='c'*64,scopeHash='d'*64)
            h.client.transition_successor(expected_seq=view['seq'],expected_head=view['head'],childBinding=binding)
            return self.current
        with self.assertRaises(ValueError):self.prepare(advance)

    def test_incomplete_history_is_rejected(self):
        h=self.signed
        view=h.client.read()
        binding=dict(h.binding,generation='c'*64,scopeHash='d'*64)
        h.client.transition_successor(expected_seq=view['seq'],expected_head=view['head'],childBinding=binding)
        with self.assertRaises(ValueError):self.prepare()
