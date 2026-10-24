"""Reviewed upgrade decisions remain bound to the original conflict plan."""
import base64
import hashlib
import json
from pathlib import Path
import unittest

from tests import test_upgrade as support


ADOPTION = 'docs/WORKFLOW-ADOPTION.md'
GUARD = 'scripts/delivery_guard.py'
LIMIT_DRIVER = r'''
import importlib.util
import sys
engine, limit, *arguments = sys.argv[1:]
spec = importlib.util.spec_from_file_location('bounded_upgrade', engine)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.MAX_JOURNAL_BYTES = int(limit)
sys.argv = [engine] + arguments
raise SystemExit(module.main())
'''


def sha(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


class ReviewedUpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        support.UpgradeTests.setUpClass.__func__(cls)

    setUp = support.UpgradeTests.setUp
    cli = support.UpgradeTests.cli
    manifest = support.UpgradeTests.manifest
    plan = support.UpgradeTests.plan
    apply = support.UpgradeTests.apply
    rollback = support.UpgradeTests.rollback

    def conflict_fixture(self):
        agents = self.target / 'AGENTS.md'
        agents.write_text(agents.read_text().replace(
            '# AI 协作协议（通用核心）', '# Blog AI 协作协议（通用核心）', 1)
            + '\nBlog exterior rule remains.\n')
        source_agents = self.source / 'core/AGENTS.md'
        source_agents.write_text(source_agents.read_text().replace(
            '# AI 协作协议（通用核心）', '# Distribution AI 协作协议（通用核心）', 1))
        local_adoption = self.target / ADOPTION
        local_adoption.write_text(local_adoption.read_text().replace('updated: YYYY-MM-DD', 'updated: 2026-01-01', 1))
        source_adoption = self.source / 'core' / ADOPTION
        source_adoption.write_text(source_adoption.read_text().replace('updated: YYYY-MM-DD', 'updated: 2026-02-01', 1))
        guard = self.target / GUARD
        guard.write_text(guard.read_text() + '\n# Blog delivery permission rule.\n')
        source_guard = self.source / 'core' / GUARD
        source_guard.write_text(source_guard.read_text() + '\n# Distribution guard change.\n')
        plan = self.plan()
        self.assertEqual(set(plan['conflicts']), {'AGENTS.md', ADOPTION, GUARD}, plan['conflicts'])
        self.assertFalse(plan['ready'])
        return plan

    def resolution(self, plan):
        rows = {row['path']: row for row in plan['entries']}
        entries = []
        for path, decision in [('AGENTS.md', 'replace-core-block'),
                               (ADOPTION, 'replace-file'), (GUARD, 'retain')]:
            row = rows[path]
            item = {key: row[key] for key in
                    ('path', 'beforeSha256', 'baselineSha256', 'nextBaselineSha256')}
            item['decision'] = decision
            if decision == 'replace-core-block':
                current = (self.target / path).read_bytes()
                incoming = (self.source / 'core' / path).read_bytes()
                start_marker = b'<!-- AI-WORKFLOW:CORE:START -->'
                end_marker = b'<!-- AI-WORKFLOW:CORE:END -->'
                current_start = current.index(start_marker)
                current_end = current.index(end_marker) + len(end_marker) + 1
                incoming_start = incoming.index(start_marker)
                incoming_end = incoming.index(end_marker) + len(end_marker) + 1
                result = current[:current_start] + incoming[incoming_start:incoming_end] + current[current_end:]
                item['resultBase64'] = base64.b64encode(result).decode('ascii')
            elif decision == 'replace-file':
                current = (self.target / path).read_bytes()
                result = current + b'\nReviewed adoption evidence.\n'
                item['resultBase64'] = base64.b64encode(result).decode('ascii')
            else:
                item['resultSha256'] = sha((self.target / path).read_bytes())
            entries.append(item)
        return {'schemaVersion': 1, 'kind': 'workflow-upgrade-resolution', 'entries': entries}

    def resolve(self, value, success=True):
        resolution_path = self.root / 'resolution.json'
        resolved_path = self.root / 'resolved.json'
        support.write_json(resolution_path, value)
        result = self.cli('resolve-plan', '--target', self.target, '--plan', self.plan_path,
                          '--resolution', resolution_path, '--output', resolved_path)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return resolved_path if success else result

    def test_three_reviewed_conflicts_apply_and_rollback_without_permission_drift(self):
        plan = self.conflict_fixture()
        before = support.snapshot(self.target)
        permissions = self.manifest()['gitPolicy']
        self.apply(success=False)
        resolved = self.resolve(self.resolution(plan))
        self.assertEqual(support.snapshot(self.target), before)
        result = self.cli('apply-resolved', '--target', self.target, '--plan', resolved)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        transaction = json.loads(result.stdout)['transaction']
        self.assertIn('Distribution AI 协作协议', (self.target / 'AGENTS.md').read_text())
        self.assertIn('Blog exterior rule remains.', (self.target / 'AGENTS.md').read_text())
        self.assertIn('Reviewed adoption evidence.', (self.target / ADOPTION).read_text())
        self.assertEqual((self.target / GUARD).read_bytes(), before[GUARD])
        self.assertEqual(self.manifest()['gitPolicy'], permissions)
        self.assertEqual(self.manifest()['workflowVersion'], '0.9.0')
        guard_entry = next(item for item in self.manifest()['files'] if item['path'] == GUARD)
        self.assertEqual(guard_entry['installedSha256'], sha(before[GUARD]))
        audit = support.subprocess.run(['bash', str(self.source / 'scripts/audit.sh'),
                                        '--target', str(self.target)],
                                       capture_output=True, text=True, env=support.ENV)
        errors = [line for line in audit.stdout.splitlines() if '[error]' in line]
        self.assertFalse(any('delivery guard' in line or 'reviewedRetainedGuard' in line
                             for line in errors), errors)
        self.assertIn('Core delivery guard 已明确审阅并保留定制内容', audit.stdout)
        self.assertNotEqual(audit.returncode, 1,
                            '\n'.join(line for line in audit.stdout.splitlines() if '[error]' in line))
        self.plan_path.unlink()
        (self.source / 'VERSION').write_text('1.0.0\n')
        next_plan = self.cli('plan', '--target', self.target, '--output', self.plan_path)
        self.assertEqual(next_plan.returncode, 0, next_plan.stdout + next_plan.stderr)
        subsequent = json.loads(self.plan_path.read_text())
        self.assertIn(GUARD, subsequent['conflicts'])
        rollback = self.rollback(transaction)
        self.assertEqual(rollback.returncode, 0, rollback.stdout + rollback.stderr)
        for name, data in before.items():
            self.assertEqual(support.snapshot(self.target).get(name), data, name)

    def test_resolution_rejects_missing_extra_unknown_and_modified_conflict_binding(self):
        plan = self.conflict_fixture()
        original = self.resolution(plan)
        for changed in ('missing', 'extra', 'unknown', 'hash'):
            with self.subTest(changed=changed):
                value = json.loads(json.dumps(original))
                if changed == 'missing':
                    value['entries'].pop()
                elif changed == 'extra':
                    value['entries'].append(dict(value['entries'][-1]))
                elif changed == 'unknown':
                    value['entries'][0]['path'] = 'docs/UNKNOWN.md'
                else:
                    value['entries'][0]['beforeSha256'] = '0' * 64
                before = support.snapshot(self.target)
                self.resolve(value, success=False)
                self.assertEqual(support.snapshot(self.target), before)

    def test_resolved_plan_rejects_stale_target_and_tampering(self):
        plan = self.conflict_fixture()
        resolved = self.resolve(self.resolution(plan))
        before = support.snapshot(self.target)
        (self.target / ADOPTION).write_text('Changed after review.\n')
        changed = support.snapshot(self.target)
        result = self.cli('apply-resolved', '--target', self.target, '--plan', resolved)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(support.snapshot(self.target), changed)
        (self.target / ADOPTION).write_bytes(before[ADOPTION])
        value = json.loads(resolved.read_text())
        value['resolution']['entries'][0]['beforeSha256'] = '0' * 64
        support.write_json(resolved, value)
        result = self.cli('apply-resolved', '--target', self.target, '--plan', resolved)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(support.snapshot(self.target), before)

    def test_review_cannot_replace_project_core_exterior_or_custom_guard(self):
        plan = self.conflict_fixture()
        for changed in ('core-exterior', 'guard-hash'):
            with self.subTest(changed=changed):
                value = self.resolution(plan)
                if changed == 'core-exterior':
                    item = value['entries'][0]
                    result = base64.b64decode(item['resultBase64'])
                    item['resultBase64'] = base64.b64encode(result.replace(
                        b'Blog exterior rule remains.', b'Different exterior rule.', 1)).decode('ascii')
                else:
                    value['entries'][-1]['resultSha256'] = '0' * 64
                before = support.snapshot(self.target)
                self.resolve(value, success=False)
                self.assertEqual(support.snapshot(self.target), before)

    def test_large_successful_upgrade_can_roll_back_its_full_journal(self):
        large_path = 'docs/LARGE-UPGRADE-RECORD.md'
        payload = b'# Managed large record\n' + b'a' * (3 * 1024 * 1024)
        (self.source / 'core' / large_path).write_bytes(payload)
        before = support.snapshot(self.target)
        plan = self.plan()
        self.assertTrue(plan['ready'], plan)
        transaction = self.apply()
        self.assertEqual((self.target / large_path).read_bytes(), payload)
        journal = self.target / '.dev-workflow/upgrades' / transaction / 'journal.json'
        self.assertGreater(journal.stat().st_size, 4 * 1024 * 1024)
        result = self.rollback(transaction)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = support.snapshot(self.target)
        self.assertEqual({name: data for name, data in after.items()
                          if not name.startswith('.dev-workflow/upgrades/')}, before)

    def test_review_cannot_retain_a_deleted_required_guard(self):
        original = self.conflict_fixture()
        resolution = self.resolution(original)
        (self.target / GUARD).unlink()
        self.plan_path.unlink()
        plan = self.plan()
        self.assertIn(GUARD, plan['conflicts'])
        guard_row = next(row for row in plan['entries'] if row['path'] == GUARD)
        guard_choice = next(row for row in resolution['entries'] if row['path'] == GUARD)
        for field in ('beforeSha256', 'baselineSha256', 'nextBaselineSha256'):
            guard_choice[field] = guard_row[field]
        guard_choice['resultSha256'] = None
        before = support.snapshot(self.target)
        support.write_json(self.root / 'missing-resolution.json', resolution)
        result = self.cli('resolve-plan', '--target', self.target, '--plan', self.plan_path,
                          '--resolution', self.root / 'missing-resolution.json',
                          '--output', self.root / 'missing-resolved.json')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(support.snapshot(self.target), before)
        self.assertFalse((self.root / 'missing-resolved.json').exists())
        self.assertFalse(list((self.target / '.dev-workflow/upgrades').glob('*/journal.json')))

    def test_journal_limit_accounts_for_terminal_status_growth(self):
        support.UpgradeTests.new_text(self, support.OLD_TEXT + 'Boundary revision\n')
        self.assertTrue(self.plan()['ready'])
        first = self.apply()
        journal_path = self.target / '.dev-workflow/upgrades' / first / 'journal.json'
        prepared = json.loads(journal_path.read_text())
        prepared['status'] = 'prepared'
        prepared.pop('completedAt', None)
        prepared_size = len((json.dumps(prepared, ensure_ascii=False, indent=2) + '\n').encode())
        self.assertEqual(self.rollback(first).returncode, 0)
        before = support.snapshot(self.target)
        cap = prepared_size + 128
        def bounded(*arguments):
            return support.subprocess.run([support.sys.executable, '-c', LIMIT_DRIVER,
                                           str(self.source / 'scripts/upgrade.py'), str(cap),
                                           *map(str, arguments)],
                                          capture_output=True, text=True, env=support.ENV)
        result = bounded('apply', '--target', self.target, '--plan', self.plan_path)
        if result.returncode == 0:
            second = json.loads(result.stdout)['transaction']
            actual = self.target / '.dev-workflow/upgrades' / second / 'journal.json'
            self.assertLessEqual(actual.stat().st_size, cap)
            restored = bounded('rollback', '--target', self.target, '--transaction', second)
            self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        else:
            self.assertIn('journal exceeds the size limit', result.stderr)
        after = support.snapshot(self.target)
        self.assertEqual({name: data for name, data in after.items()
                          if not name.startswith('.dev-workflow/upgrades/')},
                         {name: data for name, data in before.items()
                          if not name.startswith('.dev-workflow/upgrades/')})


if __name__ == '__main__':
    unittest.main()
