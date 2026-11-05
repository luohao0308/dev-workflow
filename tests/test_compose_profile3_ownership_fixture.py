"""Real signed Store/Gate evidence; no Docker calls."""
from types import SimpleNamespace
import os
import shutil
import unittest
from tests import test_deployment_compose_history_v3_host as history_fixtures
from tests.test_deployment_compose_gate_witness_v3 import GateFixture
from tests.support.compose_profile3_ownership_fixture import FixtureOwnershipTrackerV3


@unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'POSIX/OpenSSH witness')
class OwnershipTests(GateFixture, unittest.TestCase):
    setUp = history_fixtures.HistoryTests.setUp
    factory = history_fixtures.HistoryTests.factory
    open_scope = history_fixtures.HistoryTests.open_scope
    finish = history_fixtures.HistoryTests.finish
    history = history_fixtures.HistoryTests.history
    complete_deploy = history_fixtures.HistoryTests.complete_deploy
    start_child = history_fixtures.HistoryTests.start_child

    def tracker(self, **changes):
        args = dict(project=self.bundle.to_dict()['identity']['project'],
                    daemon_id=self.req.daemon_id, policy_hash=self.policy.identity_hash(),
                    witness_pub_hash=self.client.key_hash, epoch=self.binding['epoch'],
                    initial_confirmed_ids=['1'*64, '2'*64], protected_ids=['2'*64])
        args.update(changes)
        return FixtureOwnershipTrackerV3(**args)

    def test_reduce_and_repeat(self):
        tracker = self.tracker(); tracker.mark_product_pending()
        self.finish(); self.receipts = {'web':'a'*64}
        for index in (1,2):
            self.index=index; self.open_scope(); self.finish(status=204,body=b'')
        expected=('2'*64,'a'*64)
        self.assertEqual(tracker.reconcile(self.history()),expected)
        self.assertEqual(tracker.reconcile(self.history()),expected)
        self.assertFalse(tracker.uncertain)

    def test_pending_and_foreign_leave_session_frozen(self):
        tracker=self.tracker()
        session=SimpleNamespace(project=tracker.project,target=SimpleNamespace(daemon_id=tracker.daemon_id),created_ids=['1'*64,'2'*64],unknown_write_result=False)
        with self.assertRaises(ValueError):tracker.apply_to_session(session,self.history())
        self.assertTrue(session.unknown_write_result)
        self.assertEqual(session.created_ids,['1'*64,'2'*64])
        self.finish()
        with self.assertRaises(ValueError):self.tracker(epoch='f'*64).reconcile(self.history())
        with self.assertRaises(ValueError):tracker.reconcile(self.history().capture())

    def test_session_applies_fresh_proof(self):
        self.finish(); tracker=self.tracker()
        session=SimpleNamespace(project=tracker.project,target=SimpleNamespace(daemon_id=tracker.daemon_id),created_ids=[],unknown_write_result=True)
        tracker.apply_to_session(session,self.history())
        self.assertEqual(session.created_ids,['1'*64,'2'*64,'a'*64])
        self.assertFalse(session.unknown_write_result)

    def test_reused_initial_receipt_is_rejected_atomically(self):
        self.finish(); tracker=self.tracker(initial_confirmed_ids=['1'*64,'2'*64,'a'*64])
        with self.assertRaises(ValueError):tracker.reconcile(self.history())
        self.assertEqual(tracker.owned_ids,('1'*64,'2'*64,'a'*64))
        self.assertTrue(tracker.uncertain)

    def test_full_deploy_and_rollback(self):
        from dataclasses import replace
        from deployment_compose_bundle_v3 import ExecutionBundleV3
        from tests.test_deployment_compose_bundle_v3 import bind_baseline, fixture
        tracker=self.tracker()
        parent, reviewed=self.complete_deploy()
        self.assertEqual(tracker.reconcile(parent),('2'*64,'a'*64))
        value, defaults=fixture()
        value['identity']=self.bundle.to_dict()['identity']
        value['services'][0]['baselineContainerId']='a'*64
        bind_baseline(value)
        self.bundle=ExecutionBundleV3(value,authenticated_image_defaults=defaults)
        self.req=replace(self.req,plan_hash=self.bundle.digest)
        self.start_child(reviewed)
        self.finish(body=b'{"Id":"'+b'b'*64+b'"}')
        self.receipts={'web':'b'*64}
        for index in range(1,5):
            self.index=index; self.open_scope(); self.finish(status=204,body=b'')
        child=self.history(parent_history=parent,reviewed_parent_snapshot=reviewed)
        self.assertEqual(tracker.reconcile(child),('2'*64,'b'*64))
        self.assertEqual(tracker.reconcile(child),('2'*64,'b'*64))

    def test_protected_delete_is_atomic(self):
        tracker=self.tracker(protected_ids=['1'*64,'2'*64])
        parent,_=self.complete_deploy()
        with self.assertRaises(ValueError):tracker.reconcile(parent)
        self.assertEqual(tracker.owned_ids,('1'*64,'2'*64))

    def test_recovery_skips_registered_parent_prefix(self):
        from dataclasses import replace
        tracker=self.tracker(); self.finish(); self.receipts={'web':'a'*64}
        parent=self.history(); reviewed=parent.capture()
        self.assertEqual(tracker.reconcile(parent),('1'*64,'2'*64,'a'*64))
        self.req=replace(self.req,operation='recovery',history_hash=reviewed.digest)
        self.index=1; self.open_scope(); self.finish(status=204,body=b'')
        child=self.history(parent_history=parent,reviewed_parent_snapshot=reviewed)
        self.assertEqual(tracker.reconcile(child),('1'*64,'2'*64,'a'*64))

    def test_unknown_and_tampered_history_stay_uncertain(self):
        tracker=self.tracker(); self.finish(status=0,body=b'',definitive=False)
        with self.assertRaises(ValueError):tracker.reconcile(self.history())
        self.assertTrue(tracker.uncertain)
        self.assertEqual(tracker.owned_ids,('1'*64,'2'*64))
        history=self.history(); history._key=b'x'*32
        with self.assertRaises(ValueError):tracker.reconcile(history)
        self.assertTrue(tracker.uncertain)

    def test_shorter_snapshot_is_rejected_without_mutation(self):
        from unittest.mock import patch
        from deployment_compose_history_v3_host import AuthenticatedHistoryV3
        self.finish(); self.receipts={'web':'a'*64}
        history=self.history(); earlier=history.capture(); tracker=self.tracker()
        tracker.reconcile(history)
        self.index=1; self.open_scope(); self.finish(status=204,body=b'')
        tracker.reconcile(self.history())
        before=tracker.owned_ids
        # Even an authenticated older observation cannot rewind the local cursor.
        with patch.object(AuthenticatedHistoryV3,'capture',return_value=earlier):
            with self.assertRaises(ValueError):tracker.reconcile(history)
        self.assertTrue(tracker.uncertain)
        self.assertEqual(tracker.owned_ids,before)

    def test_session_target_daemon_required(self):
        self.finish(); tracker=self.tracker()
        for target in (None, SimpleNamespace(daemon_id='foreign')):
            session=SimpleNamespace(project=tracker.project,target=target,
                                    created_ids=['1'*64,'2'*64],unknown_write_result=False)
            with self.assertRaises(ValueError):tracker.apply_to_session(session,self.history())
            self.assertTrue(session.unknown_write_result)
            self.assertTrue(tracker.uncertain)
            self.assertEqual(session.created_ids,['1'*64,'2'*64])

    def test_first_root_requires_exact_bootstrap_roles(self):
        self.finish()  # genuine signed, authenticated successful create receipt
        history=self.history()
        for changes in (dict(initial_confirmed_ids=['9'*64,'2'*64]),
                        dict(initial_confirmed_ids=['1'*64,'2'*64,'9'*64]),
                        dict(protected_ids=[]),
                        dict(protected_ids=['1'*64,'2'*64])):
            tracker=self.tracker(**changes)
            before=tracker.owned_ids
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError,'bootstrap-context'):
                tracker.reconcile(history)
            self.assertEqual(tracker.owned_ids,before)
            self.assertEqual(tracker._seen,set(before))
            self.assertEqual(tracker._requests,{})
            self.assertIsNone(tracker._root)
            self.assertTrue(tracker.uncertain)

    def test_second_root_context_is_rejected(self):
        from dataclasses import replace
        self.finish(); tracker=self.tracker(); history=self.history()
        tracker.reconcile(history)
        before=tracker.owned_ids
        pinned=tracker._root
        # The same daemon/project/policy/key/epoch cannot introduce another root.
        self.req=replace(self.req,artifact_digest='e'*64)
        alternate=self.history()
        with self.assertRaisesRegex(ValueError,'second-root'):
            tracker.reconcile(alternate)
        self.assertEqual(tracker.owned_ids,before)
        self.assertEqual(tracker._root,pinned)
        self.assertEqual(len(tracker._requests),1)
        self.assertTrue(tracker.uncertain)
