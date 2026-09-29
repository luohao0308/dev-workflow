from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "packs/delivery/scripts/check-git-boundaries.py"


class GitBoundaryTests(unittest.TestCase):
    def run_check(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), "--repo", str(repo), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def git(self, repo: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE)

    def test_passes_for_safe_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "README.md").write_text("safe\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "add", "README.md")
            result = self.run_check(repo)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_tracked_local_state_and_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "docs/project-memory").mkdir(parents=True)
            (repo / "docs/project-memory/note.md").write_text("local\n", encoding="utf-8")
            (repo / ".env.production").write_text("TOKEN=secret\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "add", "--all")
            result = self.run_check(repo, "--format", "json")
            self.assertEqual(result.returncode, 1)
            self.assertIn("docs/project-memory/note.md", result.stdout)
            self.assertIn(".env.production", result.stdout)

    def test_explicit_allow_path_is_narrow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "docs/project-memory").mkdir(parents=True)
            (repo / "docs/project-memory/approved.md").write_text("shared\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "add", "--all")
            result = self.run_check(repo, "--allow-path", "docs/project-memory/approved.md")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_high_confidence_credential_marker_without_printing_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            value = "ghp_" + "A" * 36
            (repo / "config.txt").write_text(f"token={value}\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "add", "config.txt")
            result = self.run_check(repo)
            self.assertEqual(result.returncode, 1)
            self.assertIn("high-confidence credential marker", result.stdout)
            self.assertNotIn(value, result.stdout)


if __name__ == "__main__":
    unittest.main()
