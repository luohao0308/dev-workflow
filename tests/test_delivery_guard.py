import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "core" / "scripts" / "delivery_guard.py"


class DeliveryGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "remote", "add", "origin", "git@example.test:team/repo.git"],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test"], check=True)
        (self.repo / "file.txt").write_text("test\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "file.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "initial"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "branch", "-M", "feat/example"], check=True)
        self.sha = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True
        ).strip()
        metadata = self.repo / ".dev-workflow"
        metadata.mkdir()
        self.authorizations = metadata / "authorizations"
        self.authorizations.mkdir()
        self.manifest = metadata / "manifest.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 4,
                    "managedBy": "dev-workflow",
                    "gitPolicy": {
                        "pushMode": "auto",
                        "pushActor": "ai",
                        "pullRequestMode": "manual",
                        "pullRequestActor": "ai",
                        "mergeMode": "manual",
                        "mergeActor": "ai",
                        "pullRequestRequired": True,
                        "ciRequired": True,
                        "forcePushAllowed": False,
                        "privilegedOperationsDefault": "deny",
                        "deleteAllowed": False,
                    },
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, name, value, directory=None):
        path = (directory or Path(self.temp.name)) / name
        path.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def grant(self, operation="push", **overrides):
        value = {
            "grantId": "grant-001",
            "repository": str(self.repo.resolve()),
            "remote": "origin",
            "remoteUrl": "git@example.test:team/repo.git",
            "operation": operation,
            "sourceRef": "feat/example",
            "targetRef": "feat/example" if operation == "push" else "main",
            "sha": self.sha,
            "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            "maxUses": 1,
            "approvedBy": "user",
        }
        value.update(overrides)
        if operation == "merge":
            value.setdefault("prNumber", 123)
        return self.write_json("grant.json", value, self.authorizations)

    def evidence(self, operation="push", **overrides):
        value = {
            "repository": str(self.repo.resolve()),
            "remote": "origin",
            "remoteUrl": "git@example.test:team/repo.git",
            "operation": operation,
            "sourceRef": "feat/example",
            "targetRef": "feat/example" if operation == "push" else "main",
            "headSha": self.sha,
            "verifiedAt": datetime.now(timezone.utc).isoformat(),
        }
        if operation == "push":
            value.update(
                {
                    "force": False,
                    "delete": False,
                    "fastForward": True,
                }
            )
        elif operation == "pull-request":
            value.update({"remoteSourceSha": self.sha, "targetBranchExists": True})
        value.update(overrides)
        return self.write_json("evidence.json", value)

    def run_guard(self, operation="push", grant=None, evidence=None, consume=False):
        command = [
            "python3",
            str(GUARD),
            "check",
            "--operation",
            operation,
            "--repo",
            str(self.repo),
            "--remote",
            "origin",
            "--source-ref",
            "feat/example",
            "--target-ref",
            "feat/example" if operation == "push" else "main",
            "--sha",
            self.sha,
        ]
        if operation == "merge":
            command += ["--pr-number", "123"]
        if grant:
            command += ["--authorization-file", str(grant)]
        if evidence is None:
            evidence = self.evidence(operation)
        if evidence:
            command += ["--provider-evidence-file", str(evidence)]
        if consume:
            command.append("--consume")
        return subprocess.run(command, text=True, capture_output=True)

    def result_json(self, result):
        return json.loads(result.stdout)

    def test_ai_operation_requires_scoped_authorization_even_in_auto_mode(self):
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authorization", self.result_json(result)["errors"][0].lower())

    def test_push_accepts_exact_unexpired_single_use_grant(self):
        result = self.run_guard(grant=self.grant(), consume=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.result_json(result)["decision"], "allow")

    def test_grant_fails_closed_on_scope_or_sha_mismatch(self):
        for field, value in (
            ("remote", "upstream"),
            ("targetRef", "main"),
            ("sha", "0" * 40),
            ("repository", str(Path(self.temp.name) / "other")),
        ):
            with self.subTest(field=field):
                result = self.run_guard(grant=self.grant(**{field: value}))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.result_json(result)["decision"], "deny")

    def test_grant_expiry_and_consumption_are_enforced(self):
        expired = self.grant(expiresAt=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
        self.assertNotEqual(self.run_guard(grant=expired).returncode, 0)

        grant = self.grant()
        self.assertEqual(self.run_guard(grant=grant, consume=True).returncode, 0)
        reused = self.run_guard(grant=grant, consume=True)
        self.assertNotEqual(reused.returncode, 0)
        self.assertIn("maxuses", " ".join(self.result_json(reused)["errors"]).lower())

    def test_actor_user_cannot_be_executed_by_ai(self):
        policy = json.loads(self.manifest.read_text(encoding="utf-8"))
        policy["gitPolicy"]["pushActor"] = "user"
        policy["gitPolicy"]["pushMode"] = "manual"
        self.manifest.write_text(json.dumps(policy), encoding="utf-8")
        result = self.run_guard(grant=self.grant())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("actor", " ".join(self.result_json(result)["errors"]).lower())

    def test_remote_url_with_embedded_credentials_is_rejected_without_echoing_secret(self):
        secret_url = "https://token-value@example.test/team/repo.git"
        subprocess.run(
            ["git", "-C", str(self.repo), "remote", "set-url", "origin", secret_url], check=True
        )
        result = self.run_guard(grant=self.grant(remoteUrl=secret_url))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("token-value", result.stdout + result.stderr)

    def test_plain_http_remote_is_rejected(self):
        plain_url = "http://example.test/team/repo.git"
        subprocess.run(
            ["git", "-C", str(self.repo), "remote", "set-url", "origin", plain_url], check=True
        )
        result = self.run_guard(grant=self.grant(remoteUrl=plain_url))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("scheme", " ".join(self.result_json(result)["errors"]).lower())

    def test_remote_with_multiple_push_urls_is_rejected(self):
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "remote",
                "set-url",
                "--add",
                "--push",
                "origin",
                "git@example.test:mirror/repo.git",
            ],
            check=True,
        )
        result = self.run_guard(grant=self.grant())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", " ".join(self.result_json(result)["errors"]).lower())

    def test_merge_requires_fresh_exact_pr_and_ci_evidence(self):
        evidence = self.write_json(
            "evidence.json",
            {
                "repository": str(self.repo.resolve()),
                "remote": "origin",
                "remoteUrl": "git@example.test:team/repo.git",
                "operation": "merge",
                "prNumber": 123,
                "grantId": "grant-001",
                "state": "open",
                "sourceRef": "feat/example",
                "targetRef": "main",
                "headSha": self.sha,
                "requiredChecksPassed": True,
                "mergeable": True,
                "verifiedAt": datetime.now(timezone.utc).isoformat(),
            },
        )
        result = self.run_guard("merge", self.grant("merge"), evidence)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        broken = json.loads(evidence.read_text(encoding="utf-8"))
        broken["requiredChecksPassed"] = False
        evidence.write_text(json.dumps(broken), encoding="utf-8")
        self.assertNotEqual(self.run_guard("merge", self.grant("merge"), evidence).returncode, 0)

        broken["requiredChecksPassed"] = True
        broken["prNumber"] = 124
        evidence.write_text(json.dumps(broken), encoding="utf-8")
        self.assertNotEqual(self.run_guard("merge", self.grant("merge"), evidence).returncode, 0)

    def test_push_accepts_provider_evidence_without_extra_platform_gate(self):
        result = self.run_guard(grant=self.grant(), evidence=self.evidence())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_authorization_must_be_inside_local_authorizations_directory(self):
        outside = self.write_json("outside.json", json.loads(self.grant().read_text(encoding="utf-8")))
        result = self.run_guard(grant=outside)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authorizations", " ".join(self.result_json(result)["errors"]).lower())

    def test_delete_and_privileged_operations_are_not_supported(self):
        result = subprocess.run(
            ["python3", str(GUARD), "check", "--operation", "delete", "--repo", str(self.repo)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
