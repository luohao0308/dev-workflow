import hashlib
import unittest

from tests.test_deployment_compose_production_frontend_v3_host import adapter, material
from deployment_compose_production_cutover_v1_host import prepare_retained_frontend_cutover
from deployment_gateway import _profile_operation


class RetainedCutoverTests(unittest.TestCase):
    def test_exact_paths_retain_original_and_define_inverse(self):
        row, image, options = material()
        options['protected_container_ids'] = ['d'*64]
        options['expected_snapshot_digest'] = adapter.snapshot_digest(row, image, ['d'*64])
        plan = prepare_retained_frontend_cutover(adapter.prepare_frontend_plan(row, image, **options),
                                                operation_nonce='1'*64)
        candidate = 'f'*64
        switch = plan.switch(candidate)
        restore = plan.restore(candidate, switch_prefix=4, candidate_running=True)
        self.assertEqual([op.phase for op in switch],
                         ['stop-original', 'retain-original', 'name-candidate', 'start-candidate'])
        self.assertEqual([op.phase for op in restore],
                         ['stop-candidate', 'unname-candidate', 'rename-original', 'start-original'])
        for op in (plan.create(), *switch, *restore):
            _profile_operation('compose-v3', 'POST', op.path, hashlib.sha256(op.body).hexdigest())
        for invalid in (row['Id'], 'd'*64, 'short', candidate + '/start'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                plan.restore(invalid, switch_prefix=4, candidate_running=True)
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                plan.switch(invalid)

    def test_restoration_from_closed_prefixes_only_reverses_observed_changes(self):
        row, image, options = material()
        plan = prepare_retained_frontend_cutover(adapter.prepare_frontend_plan(row, image, **options),
                                                operation_nonce='1'*64)
        candidate = 'f'*64
        for prefix, phases in (
            (1, ['start-original']),
            (2, ['rename-original', 'start-original']),
            (3, ['unname-candidate', 'rename-original', 'start-original']),
            (4, ['unname-candidate', 'rename-original', 'start-original']),
        ):
            ops = plan.restore(candidate, switch_prefix=prefix, candidate_running=False)
            self.assertEqual([op.phase for op in ops], phases)
        for prefix, running in ((0, False), (3, True), (True, False), (4, None)):
            with self.subTest(prefix=prefix, running=running), self.assertRaises(ValueError):
                plan.restore(candidate, switch_prefix=prefix, candidate_running=running)

    def test_plan_digest_changes_with_reserved_names_and_body_tampering_fails(self):
        row, image, options = material()
        prepared = adapter.prepare_frontend_plan(row, image, **options)
        original = prepare_retained_frontend_cutover(prepared, operation_nonce='1'*64)
        changed = prepare_retained_frontend_cutover(prepared, operation_nonce='2'*64)
        self.assertNotEqual(original.digest, changed.digest)
        prepared['privateBody']['Env'].append('DRIFT=yes')
        with self.assertRaises(ValueError):
            prepare_retained_frontend_cutover(prepared, operation_nonce='1'*64)
