#!/usr/bin/env python3
"""Fail closed when local workflow state or obvious secrets are tracked by Git."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


FORBIDDEN_PREFIXES = (
    ".dev-workflow/",
    ".omx/",
    "docs/project-memory/",
    "docs/working-context/",
    "docs/工作日志/",
)
FORBIDDEN_PATHS = {
    "docs/TASKS.md",
    "docs/WORKING-CONTEXT.md",
}
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks")
SECRET_NAMES = {".env", ".env.local", ".env.production", ".env.development"}
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b"),
)


def tracked_paths(repo: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return [item for item in result.stdout.decode("utf-8").split("\0") if item]


def is_forbidden(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    if normalized in FORBIDDEN_PATHS:
        return "local workflow state"
    if normalized.startswith(FORBIDDEN_PREFIXES):
        return "local workflow state"
    name = Path(normalized).name
    if name in SECRET_NAMES:
        return "environment secret file"
    if name.startswith(".env.") and not name.endswith(SAFE_ENV_SUFFIXES):
        return "environment secret file"
    if normalized.endswith(SECRET_SUFFIXES):
        return "private key or certificate"
    return None


def contains_secret_marker(file_path: Path) -> bool:
    try:
        if file_path.is_symlink() or not file_path.is_file():
            return False
        if file_path.stat().st_size > 2_000_000:
            return False
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    return any(pattern.search(content) for pattern in SECRET_PATTERNS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--allow-path", action="append", default=[], help="Exact tracked path allowed by project policy")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    repo = args.repo.resolve()
    allowed = {value.replace("\\", "/").lstrip("./") for value in args.allow_path}
    paths = tracked_paths(repo)
    findings = []
    for path in paths:
        if path in allowed:
            continue
        reason = is_forbidden(path)
        if reason is None and contains_secret_marker(repo / path):
            reason = "high-confidence credential marker"
        if reason:
            findings.append({"path": path, "reason": reason})
    payload = {"repository": str(repo), "trackedFiles": len(paths), "findings": findings}
    if args.format == "json":
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    elif findings:
        for finding in findings:
            print(f"[error] {finding['path']}: {finding['reason']}")
    else:
        print(f"Git boundary check passed: {payload['trackedFiles']} tracked files")
    return 1 if findings else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Git boundary check could not inspect repository: {exc}", file=sys.stderr)
        raise SystemExit(2)
