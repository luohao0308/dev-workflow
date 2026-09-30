#!/usr/bin/env python3
"""Read-only inventory and lifecycle report for Git worktrees."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ARTIFACT_NAMES = {"node_modules", "dist", "build", ".venv", "venv", "target", "coverage"}


class ReportError(Exception):
    pass


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args], check=check, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReportError(f"Git could not inspect repository ({' '.join(args)})") from exc


def parse_worktrees(output: str) -> list[dict[str, Any]]:
    worktrees: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in output.splitlines():
        if not line:
            if current:
                worktrees.append(current)
                current = None
            continue
        key, _, value = line.partition(" ")
        if key == "worktree":
            if current:
                worktrees.append(current)
            current = {"path": value, "locked": False, "prunable": False}
        elif current is not None:
            if key == "HEAD":
                current["head"] = value
            elif key == "branch":
                current["branch"] = value.removeprefix("refs/heads/")
            elif key == "detached":
                current["detached"] = True
            elif key == "locked":
                current["locked"] = True
                current["lockReason"] = value or None
            elif key == "prunable":
                current["prunable"] = True
                current["prunableReason"] = value or None
    if current:
        worktrees.append(current)
    return worktrees


def choose_base(repo: Path, requested: str | None) -> str | None:
    if requested:
        result = git(repo, "rev-parse", "--verify", f"{requested}^{{commit}}", check=False)
        if result.returncode:
            raise ReportError(f"Base ref does not resolve to a commit: {requested}")
        return requested
    remote_head = git(repo, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD", check=False)
    if remote_head.returncode == 0:
        return remote_head.stdout.strip().removeprefix("refs/remotes/")
    for candidate in ("origin/main", "origin/master", "main", "master"):
        if git(repo, "rev-parse", "--verify", f"{candidate}^{{commit}}", check=False).returncode == 0:
            return candidate
    return None


def directory_size(path: Path) -> int:
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.name == ".git":
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def artifact_dirs(root: Path, stale_days: int, include_sizes: bool = True) -> list[dict[str, Any]]:
    cutoff = time.time() - stale_days * 86400
    found: list[dict[str, Any]] = []
    stack = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth >= 5:
            continue
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        continue
                    child = Path(entry.path)
                    if entry.name == ".git":
                        continue
                    if entry.name in ARTIFACT_NAMES:
                        try:
                            modified = entry.stat(follow_symlinks=False).st_mtime
                            if modified < cutoff:
                                found.append({
                                    "path": str(child),
                                    "ageDays": int((time.time() - modified) // 86400),
                                    "sizeBytes": directory_size(child) if include_sizes else None,
                                })
                        except OSError:
                            pass
                    else:
                        stack.append((child, depth + 1))
        except OSError:
            continue
    return found


def inspect_worktree(
    repo: Path,
    item: dict[str, Any],
    base: str | None,
    stale_days: int,
    include_sizes: bool = True,
) -> dict[str, Any]:
    path = Path(item["path"])
    result = dict(item)
    result["exists"] = path.is_dir() and not path.is_symlink()
    result["orphan"] = bool(item.get("prunable")) or not result["exists"]
    result["dirty"] = None
    result["changes"] = None
    result["ahead"] = None
    result["behind"] = None
    result["merged"] = None
    result["sizeBytes"] = None
    result["staleArtifacts"] = []
    if not result["exists"]:
        result["recommendation"] = "missing or symlinked worktree path; inspect metadata before any prune"
        return result
    status = git(path, "status", "--porcelain=v1", "-uall")
    changes = [line for line in status.stdout.splitlines() if line]
    result["dirty"] = bool(changes)
    result["changes"] = len(changes)
    if include_sizes:
        result["sizeBytes"] = directory_size(path)
    result["staleArtifacts"] = artifact_dirs(path, stale_days, include_sizes)
    if base and item.get("head"):
        counts = git(repo, "rev-list", "--left-right", "--count", f"{base}...{item['head']}", check=False)
        if counts.returncode == 0:
            behind, ahead = (int(part) for part in counts.stdout.split())
            result["ahead"] = ahead
            result["behind"] = behind
            merge = git(repo, "merge-base", "--is-ancestor", item["head"], base, check=False)
            result["merged"] = merge.returncode == 0
    reasons = []
    if result.get("prunable"):
        reasons.append("Git marks this worktree metadata prunable; inspect before pruning")
    if result.get("locked"):
        reasons.append("worktree is locked")
    if result.get("dirty"):
        reasons.append("uncommitted or untracked files exist")
    if result.get("merged"):
        reasons.append("HEAD is already an ancestor of the selected base")
    if not reasons:
        reasons.append("no automatic cleanup recommended")
    result["recommendation"] = "; ".join(reasons)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base-ref", help="Comparison base; auto-detected when omitted")
    parser.add_argument("--stale-days", type=int, default=30)
    parser.add_argument(
        "--no-size",
        action="store_true",
        help="skip recursive directory size scans for faster reports",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    if args.stale_days < 1:
        parser.error("--stale-days must be positive")
    repo = Path(git(args.repo.resolve(), "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    base = choose_base(repo, args.base_ref)
    listing = git(repo, "worktree", "list", "--porcelain", "--expire", "now")
    worktrees = parse_worktrees(listing.stdout)
    branches: dict[str, list[str]] = {}
    for item in worktrees:
        if item.get("branch"):
            branches.setdefault(item["branch"], []).append(item["path"])
    duplicate_branches = {name: paths for name, paths in branches.items() if len(paths) > 1}
    report = {
        "repository": str(repo),
        "baseRef": base,
        "readOnly": True,
        "worktrees": [
            inspect_worktree(repo, item, base, args.stale_days, include_sizes=not args.no_size)
            for item in worktrees
        ],
        "duplicateBranches": duplicate_branches,
    }
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(f"Worktree report: {repo}")
        print(f"Comparison base: {base or 'not detected'}")
        for item in report["worktrees"]:
            print(f"- {item.get('branch', '(detached)')} | {item['path']}")
            print(f"  exists={item['exists']} dirty={item['dirty']} changes={item['changes']} ahead={item['ahead']} behind={item['behind']} merged={item['merged']} sizeBytes={item['sizeBytes']}")
            if item.get("orphan") or item.get("locked") or item.get("staleArtifacts"):
                print(f"  lifecycle: {item['recommendation']}; staleArtifacts={len(item['staleArtifacts'])}")
        for branch, paths in duplicate_branches.items():
            print(f"[warning] branch appears in multiple worktrees: {branch}: {', '.join(paths)}")
        print("No worktree, branch, or file was modified.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReportError) as exc:
        print(f"Worktree report failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
