#!/usr/bin/env python3
"""Fail-closed preflight for dev-workflow remote delivery operations."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


OPERATIONS = {"push", "pull-request", "merge"}
MODE_FIELDS = {
    "push": ("pushMode", "pushActor"),
    "pull-request": ("pullRequestMode", "pullRequestActor"),
    "merge": ("mergeMode", "mergeActor"),
}
REQUIRED_TRUE = ("pullRequestRequired", "ciRequired")
REQUIRED_FALSE = ("forcePushAllowed", "deleteAllowed")
SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REF_RE = re.compile(r"^(?!/)(?!.*(?:\.\.|@\{|//|\\))[A-Za-z0-9._/-]+(?<![/.])$")


class GuardError(Exception):
    pass


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GuardError(f"{label} is unreadable or invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise GuardError(f"{label} must be a JSON object: {path}")
    return value


def git(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GuardError(f"Git state could not be verified: {' '.join(args)}") from exc
    return result.stdout.strip()


def git_lines(repo: Path, *args: str) -> list[str]:
    return [line for line in git(repo, *args).splitlines() if line]


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise GuardError(f"{label} must be a non-empty RFC3339 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise GuardError(f"{label} must be a valid RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GuardError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def require_exact(obj: dict[str, Any], field: str, expected: Any, label: str) -> None:
    if obj.get(field) != expected:
        raise GuardError(f"{label}.{field} does not match the requested operation")


def validate_ref(value: str, label: str) -> None:
    if not REF_RE.fullmatch(value) or value.startswith("refs/") or value.endswith(".lock"):
        raise GuardError(f"{label} is not a safe short branch name")


def validate_remote_url(value: str) -> None:
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise GuardError("remote URL is empty or contains control characters")
    if value.startswith(("/", "./", "../", "~", "file:")):
        raise GuardError("local-path remotes are not eligible for remote delivery authorization")
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme not in {"https", "ssh"} or not parsed.hostname:
            raise GuardError("remote URL scheme or host is unsupported")
        if parsed.password is not None or parsed.query or parsed.fragment:
            raise GuardError("remote URL must not contain credentials, query, or fragment")
        if parsed.username and not (parsed.scheme == "ssh" and parsed.username == "git"):
            raise GuardError("remote URL must not contain embedded user credentials")
        return
    if not re.fullmatch(r"(?:git@)?[A-Za-z0-9.-]+:[A-Za-z0-9._/-]+(?:\.git)?", value):
        raise GuardError("remote URL must be an HTTPS, SSH, or scp-style repository URL")


def validate_manifest(manifest: dict[str, Any], operation: str) -> tuple[str, str]:
    if manifest.get("managedBy") != "dev-workflow":
        raise GuardError("manifest is not managed by dev-workflow")
    if manifest.get("schemaVersion") not in {4, 5}:
        raise GuardError("manifest schema is unsupported by delivery_guard")
    policy = manifest.get("gitPolicy")
    if not isinstance(policy, dict):
        raise GuardError("manifest.gitPolicy is missing or invalid")
    for field in REQUIRED_TRUE:
        if policy.get(field) is not True:
            raise GuardError(f"manifest.gitPolicy.{field} must be true")
    for field in REQUIRED_FALSE:
        if policy.get(field) is not False:
            raise GuardError(f"manifest.gitPolicy.{field} must be false")
    if policy.get("privilegedOperationsDefault") != "deny":
        raise GuardError("manifest.gitPolicy.privilegedOperationsDefault must be deny")
    mode_field, actor_field = MODE_FIELDS[operation]
    mode, actor = policy.get(mode_field), policy.get(actor_field)
    if mode not in {"manual", "auto"} or actor not in {"user", "ai"}:
        raise GuardError(f"manifest policy for {operation} is invalid")
    if mode == "auto" and actor != "ai":
        raise GuardError(f"manifest auto policy for {operation} requires actor ai")
    return mode, actor


def validate_git_request(repo: Path, remote: str, source_ref: str, target_ref: str, sha: str) -> tuple[Path, str]:
    root = Path(git(repo, "rev-parse", "--show-toplevel")).resolve()
    if root != repo.resolve():
        raise GuardError("--repo must be the exact Git top-level directory")
    if not SHA_RE.fullmatch(sha):
        raise GuardError("--sha must be a full lowercase Git object id")
    validate_ref(source_ref, "sourceRef")
    validate_ref(target_ref, "targetRef")
    if source_ref.startswith("codex/"):
        raise GuardError("codex/* branches cannot be delivered remotely")
    actual_sha = git(root, "rev-parse", f"refs/heads/{source_ref}")
    if actual_sha != sha:
        raise GuardError("source branch does not resolve to the requested exact SHA")
    fetch_urls = git_lines(root, "remote", "get-url", "--all", remote)
    push_urls = git_lines(root, "remote", "get-url", "--push", "--all", remote)
    if len(fetch_urls) != 1 or len(push_urls) != 1 or fetch_urls != push_urls:
        raise GuardError("remote must have exactly one identical fetch and push URL")
    fetch_url = fetch_urls[0]
    validate_remote_url(fetch_url)
    return root, fetch_url


def validate_authorization(
    authorization: dict[str, Any], *, root: Path, remote: str, remote_url: str,
    operation: str, source_ref: str, target_ref: str, sha: str, pr_number: int | None
) -> tuple[str, int]:
    expected = {
        "repository": str(root),
        "remote": remote,
        "remoteUrl": remote_url,
        "operation": operation,
        "sourceRef": source_ref,
        "targetRef": target_ref,
        "sha": sha,
    }
    for field, value in expected.items():
        require_exact(authorization, field, value, "authorization")
    if operation == "merge":
        require_exact(authorization, "prNumber", pr_number, "authorization")
    grant_id = authorization.get("grantId")
    if not isinstance(grant_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", grant_id):
        raise GuardError("authorization.grantId is missing or invalid")
    if authorization.get("approvedBy") != "user":
        raise GuardError("authorization.approvedBy must be user")
    expires_at = parse_time(authorization.get("expiresAt"), "authorization.expiresAt")
    if expires_at <= datetime.now(timezone.utc):
        raise GuardError("authorization has expired")
    max_uses = authorization.get("maxUses")
    if not isinstance(max_uses, int) or isinstance(max_uses, bool) or not 1 <= max_uses <= 100:
        raise GuardError("authorization.maxUses must be an integer between 1 and 100")
    return grant_id, max_uses


def validate_evidence_binding(
    evidence: dict[str, Any], *, root: Path, remote: str, remote_url: str,
    operation: str, source_ref: str, target_ref: str, sha: str
) -> None:
    expected = {
        "repository": str(root),
        "remote": remote,
        "remoteUrl": remote_url,
        "operation": operation,
        "sourceRef": source_ref,
        "targetRef": target_ref,
        "headSha": sha,
    }
    for field, value in expected.items():
        require_exact(evidence, field, value, "providerEvidence")
    verified_at = parse_time(evidence.get("verifiedAt"), "providerEvidence.verifiedAt")
    now = datetime.now(timezone.utc)
    if verified_at > now + timedelta(seconds=30) or now - verified_at > timedelta(minutes=5):
        raise GuardError("provider evidence is stale or has a future timestamp")


def validate_push_evidence(evidence: dict[str, Any]) -> None:
    for field, expected in (
        ("force", False),
        ("delete", False),
        ("fastForward", True),
    ):
        require_exact(evidence, field, expected, "providerEvidence")


def validate_pull_request_evidence(evidence: dict[str, Any], sha: str) -> None:
    require_exact(evidence, "remoteSourceSha", sha, "providerEvidence")
    require_exact(evidence, "targetBranchExists", True, "providerEvidence")


def validate_merge_evidence(
    evidence: dict[str, Any], source_ref: str, target_ref: str, sha: str,
    pr_number: int, grant_id: str
) -> None:
    require_exact(evidence, "prNumber", pr_number, "providerEvidence")
    require_exact(evidence, "grantId", grant_id, "providerEvidence")
    require_exact(evidence, "state", "open", "prEvidence")
    require_exact(evidence, "sourceRef", source_ref, "prEvidence")
    require_exact(evidence, "targetRef", target_ref, "prEvidence")
    require_exact(evidence, "headSha", sha, "prEvidence")
    for field in ("requiredChecksPassed", "mergeable"):
        require_exact(evidence, field, True, "prEvidence")


def consumption_count(path: Path, grant_id: str) -> int:
    if not path.exists():
        return 0
    count = 0
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if isinstance(entry, dict) and entry.get("grantId") == grant_id:
                count += 1
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GuardError("authorization consumption ledger is invalid") from exc
    return count


def consume_grant(ledger: Path, grant_id: str, max_uses: int, operation: str, sha: str) -> None:
    ledger.parent.mkdir(parents=True, exist_ok=True)
    lock = ledger.with_suffix(ledger.suffix + ".lock")
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise GuardError("authorization ledger is busy; retry after the current preflight finishes") from exc
    try:
        os.close(lock_fd)
        if consumption_count(ledger, grant_id) >= max_uses:
            raise GuardError("authorization maxUses has already been reached")
        record = json.dumps(
            {
                "grantId": grant_id,
                "operation": operation,
                "sha": sha,
                "consumedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        fd, temp_name = tempfile.mkstemp(prefix=ledger.name + ".", dir=ledger.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                if ledger.exists():
                    existing = ledger.read_text(encoding="utf-8")
                    handle.write(existing)
                    if existing and not existing.endswith("\n"):
                        handle.write("\n")
                handle.write(record + "\n")
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, ledger)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
    finally:
        try:
            os.unlink(lock)
        except FileNotFoundError:
            pass


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="validate a remote delivery operation")
    check.add_argument("--operation", required=True, choices=sorted(OPERATIONS))
    check.add_argument("--repo", required=True, type=Path)
    check.add_argument("--remote", required=True)
    check.add_argument("--source-ref", required=True)
    check.add_argument("--target-ref", required=True)
    check.add_argument("--sha", required=True)
    check.add_argument("--pr-number", type=int)
    check.add_argument("--authorization-file", type=Path)
    check.add_argument("--provider-evidence-file", type=Path)
    check.add_argument("--consume", action="store_true")
    return result


def run(args: argparse.Namespace) -> dict[str, Any]:
    root = args.repo.resolve()
    manifest = load_json(root / ".dev-workflow" / "manifest.json", "manifest")
    mode, actor = validate_manifest(manifest, args.operation)
    if actor != "ai":
        raise GuardError("policy actor is user; this guard cannot authorize AI execution")
    if args.operation == "merge" and (args.pr_number is None or args.pr_number <= 0):
        raise GuardError("merge requires a positive --pr-number")
    root, remote_url = validate_git_request(
        root, args.remote, args.source_ref, args.target_ref, args.sha
    )
    if args.authorization_file is None:
        raise GuardError(
            "authorization file is required for every AI remote operation"
        )
    authorization_path = args.authorization_file.resolve()
    authorization_root = (root / ".dev-workflow" / "authorizations").resolve()
    if authorization_path.parent != authorization_root:
        raise GuardError("authorization file must be directly inside .dev-workflow/authorizations")
    try:
        if os.name != "nt" and authorization_path.stat().st_mode & 0o077:
            raise GuardError("authorization file must not be accessible by group or other users")
    except OSError as exc:
        raise GuardError("authorization file metadata could not be verified") from exc
    authorization = load_json(authorization_path, "authorization")
    grant_id, max_uses = validate_authorization(
        authorization,
        root=root,
        remote=args.remote,
        remote_url=remote_url,
        operation=args.operation,
        source_ref=args.source_ref,
        target_ref=args.target_ref,
        sha=args.sha,
        pr_number=args.pr_number,
    )
    if consumption_count(root / ".dev-workflow" / "authorization-consumptions.jsonl", grant_id) >= max_uses:
        raise GuardError("authorization maxUses has already been reached")
    if args.provider_evidence_file is None:
        raise GuardError(f"{args.operation} requires a provider evidence file")
    evidence = load_json(args.provider_evidence_file, "provider evidence")
    validate_evidence_binding(
        evidence,
        root=root,
        remote=args.remote,
        remote_url=remote_url,
        operation=args.operation,
        source_ref=args.source_ref,
        target_ref=args.target_ref,
        sha=args.sha,
    )
    if args.operation == "push":
        validate_push_evidence(evidence)
    elif args.operation == "pull-request":
        validate_pull_request_evidence(evidence, args.sha)
    else:
        validate_merge_evidence(
            evidence, args.source_ref, args.target_ref, args.sha, args.pr_number, grant_id
        )
    if args.consume:
        consume_grant(
            root / ".dev-workflow" / "authorization-consumptions.jsonl",
            grant_id,
            max_uses,
            args.operation,
            args.sha,
        )
    return {
        "decision": "allow",
        "operation": args.operation,
        "mode": mode,
        "actor": actor,
        "repository": str(root),
        "remote": {"name": args.remote, "url": remote_url},
        "sourceRef": args.source_ref,
        "targetRef": args.target_ref,
        "sha": args.sha,
        "authorization": {"grantId": grant_id, "consumed": bool(args.consume)},
        "trustBoundary": "local-compliance-preflight",
        "errors": [],
    }


def main() -> int:
    args = parser().parse_args()
    try:
        output = run(args)
        code = 0
    except GuardError as exc:
        output = {"decision": "deny", "operation": getattr(args, "operation", None), "errors": [str(exc)]}
        code = 3
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
