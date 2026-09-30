from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "packs/delivery/scripts/report-worktrees.py"


class WorktreeReportTests(unittest.TestCase):
    def git(self, repo: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return result.stdout.strip()

    def test_report_is_read_only_and_reports_dirty_ahead_and_stale_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q", "-b", "main")
            self.git(repo, "config", "user.name", "test")
            self.git(repo, "config", "user.email", "test@example.invalid")
            (repo / "base.txt").write_text("base\n", encoding="utf-8")
            self.git(repo, "add", "base.txt")
            self.git(repo, "commit", "-qm", "base")
            worktree = Path(directory) / "feature"
            self.git(repo, "worktree", "add", "-qb", "feature/sample", str(worktree))
            (worktree / "feature.txt").write_text("feature\n", encoding="utf-8")
            self.git(worktree, "add", "feature.txt")
            self.git(worktree, "commit", "-qm", "feature")
            (worktree / "untracked.txt").write_text("local\n", encoding="utf-8")
            artifact = worktree / "dist"
            artifact.mkdir()
            (artifact / "bundle.js").write_text("artifact\n", encoding="utf-8")
            old = time.time() - 3 * 86400
            os.utime(artifact, (old, old))
            before = self.git(worktree, "status", "--porcelain=v1", "-uall")
            worktrees_before = self.git(repo, "worktree", "list", "--porcelain")
            result = subprocess.run(
                ["python3", str(SCRIPT), "--repo", str(repo), "--base-ref", "main", "--stale-days", "1", "--format", "json"],
                check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            report = json.loads(result.stdout)
            feature = next(item for item in report["worktrees"] if item.get("branch") == "feature/sample")
            self.assertTrue(report["readOnly"])
            self.assertTrue(feature["dirty"])
            self.assertEqual(feature["changes"], 2)
            self.assertEqual(feature["ahead"], 1)
            self.assertEqual(feature["behind"], 0)
            self.assertFalse(feature["merged"])
            self.assertEqual(feature["staleArtifacts"][0]["path"], str(artifact.resolve()))
            self.assertEqual(self.git(worktree, "status", "--porcelain=v1", "-uall"), before)
            self.assertEqual(self.git(repo, "worktree", "list", "--porcelain"), worktrees_before)
            self.assertTrue(worktree.exists())

            fast_result = subprocess.run(
                ["python3", str(SCRIPT), "--repo", str(repo), "--base-ref", "main", "--stale-days", "1", "--no-size", "--format", "json"],
                check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            fast_report = json.loads(fast_result.stdout)
            fast_feature = next(item for item in fast_report["worktrees"] if item.get("branch") == "feature/sample")
            self.assertIsNone(fast_feature["sizeBytes"])
            self.assertIsNone(fast_feature["staleArtifacts"][0]["sizeBytes"])

    def test_reports_merged_branch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self.git(repo, "init", "-q", "-b", "main")
            self.git(repo, "config", "user.name", "test")
            self.git(repo, "config", "user.email", "test@example.invalid")
            (repo / "base.txt").write_text("base\n", encoding="utf-8")
            self.git(repo, "add", "base.txt")
            self.git(repo, "commit", "-qm", "base")
            branch = self.git(repo, "branch", "--show-current")
            worktree = Path(directory) / "merged"
            self.git(repo, "worktree", "add", "-qb", "feature/merged", str(worktree))
            (worktree / "change.txt").write_text("merged\n", encoding="utf-8")
            self.git(worktree, "add", "change.txt")
            self.git(worktree, "commit", "-qm", "merged")
            self.git(repo, "merge", "--ff-only", "feature/merged")
            result = subprocess.run(
                ["python3", str(SCRIPT), "--repo", str(repo), "--base-ref", branch, "--format", "json"],
                check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            report = json.loads(result.stdout)
            feature = next(item for item in report["worktrees"] if item.get("branch") == "feature/merged")
            self.assertTrue(feature["merged"])
            self.assertEqual(feature["ahead"], 0)
            self.assertEqual(feature["behind"], 0)

    def test_duplicate_branch_parser(self) -> None:
        spec = importlib.util.spec_from_file_location("worktree_report", SCRIPT)
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        parsed = module.parse_worktrees(
            "worktree /a\nHEAD abc\nbranch refs/heads/topic\n\n"
            "worktree /b\nHEAD abc\nbranch refs/heads/topic\n\n"
        )
        self.assertEqual([item["branch"] for item in parsed], ["topic", "topic"])


if __name__ == "__main__":
    unittest.main()
