#!/usr/bin/env python3
"""Validate, query, and render a project feature catalog.

The tool deliberately uses only the Python standard library.  JSON Schema
describes the public shape; this module enforces cross-entry semantics,
repository-relative references, maturity evidence, and generated-matrix
drift.  Project paths are resolved from the target repository, not from the
distribution repository.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


def _infer_root() -> Path:
    script = Path(__file__).resolve()
    candidate = script.parents[1]
    if candidate.name == "feature-catalog" and candidate.parent.name == "packs":
        return candidate.parent.parent
    return candidate


DEFAULT_ROOT = _infer_root()
DEFAULT_CATALOG = Path("docs/development/ai/feature-catalog.json")
DEFAULT_SCHEMA = Path("docs/development/ai/feature-catalog.schema.json")
DEFAULT_TEMPLATE = Path("docs/development/ai/feature-catalog.template.json")
DEFAULT_MATRIX = Path("docs/FEATURE-MATRIX.md")

ITEM_LEVELS = ("domain", "capability", "feature")
IMPLEMENTATION_STATUSES = ("not_started", "in_progress", "implemented", "verified")
MATURITIES = ("prototype", "beta", "production_candidate", "production_ready", "production_proven")
EVIDENCE_KINDS = ("unit", "integration", "e2e", "smoke", "release", "live", "docs")
EVIDENCE_RESULTS = ("passed", "blocked", "partial")
SEARCH_STOPWORDS = {"a", "an", "and", "for", "in", "of", "on", "or", "the", "to", "with"}
ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PLATFORM_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
TASK_PATTERN = re.compile(r"^\S+$")
DATE_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
ITEM_FIELDS = {
    "id", "parent_id", "level", "name", "summary", "keywords", "platforms",
    "implementation_status", "maturity", "acceptance_criteria", "code_paths",
    "spec_paths", "test_paths", "evidence", "known_gaps", "task_ids",
}
EVIDENCE_FIELDS = {"kind", "command", "result", "verified_at", "commit", "ref"}


class CatalogError(ValueError):
    """A user-facing catalog validation or CLI error."""


@dataclass(frozen=True)
class CatalogPaths:
    root: Path
    catalog: Path
    schema: Path
    template: Path
    matrix: Path


def _fail(message: str) -> None:
    raise CatalogError(message)


def _is_string(value: Any, field: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        _fail(f"{field} must be a non-empty string")
    return value


def _string_list(value: Any, field: str) -> List[str]:
    if not isinstance(value, list):
        _fail(f"{field} must be an array")
    result = [_is_string(item, f"{field}[]") for item in value]
    if len(result) != len(set(result)):
        _fail(f"{field} contains duplicates")
    return result


def _safe_path(value: str, root: Path, field: str, must_exist: bool = True) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or any(char in value for char in "*?["):
        _fail(f"{field} must be a safe repository-relative path: {value}")
    resolved_root = root.resolve()
    resolved = (resolved_root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        _fail(f"{field} escapes the repository: {value}")
    if must_exist and not resolved.exists():
        _fail(f"{field} references missing path: {value}")
    return resolved


def resolve_paths(
    root_value: Optional[str] = None,
    catalog_value: Optional[str] = None,
    schema_value: Optional[str] = None,
    template_value: Optional[str] = None,
    matrix_value: Optional[str] = None,
) -> CatalogPaths:
    if root_value:
        root = Path(root_value).expanduser().resolve()
    else:
        root = DEFAULT_ROOT.resolve()
    if not root.is_dir():
        _fail(f"repository root does not exist: {root}")

    def select(value: Optional[str], default: Path, field: str) -> Path:
        selected = value or str(default)
        return _safe_path(selected, root, field, must_exist=False)

    return CatalogPaths(
        root=root,
        catalog=select(catalog_value, DEFAULT_CATALOG, "catalog path"),
        schema=select(schema_value, DEFAULT_SCHEMA, "schema path"),
        template=select(template_value, DEFAULT_TEMPLATE, "template path"),
        matrix=select(matrix_value, DEFAULT_MATRIX, "matrix path"),
    )


def _load_json(path: Path, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _fail(f"missing {label}: {path}")
    except json.JSONDecodeError as exc:
        _fail(f"invalid JSON in {label}: {exc}")
    if not isinstance(value, dict):
        _fail(f"{label} must contain a JSON object")
    return value


def _validate_schema_document(paths: CatalogPaths) -> None:
    schema = _load_json(paths.schema, "feature catalog schema")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        _fail("feature catalog schema must declare JSON Schema 2020-12")
    if schema.get("title") != "Project Feature Catalog":
        _fail("feature catalog schema has an unexpected title")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict) or "item" not in definitions or "evidence" not in definitions:
        _fail("feature catalog schema must define item and evidence")


def _validate_evidence(item_id: str, evidence: Any, root: Path) -> List[Dict[str, Any]]:
    if not isinstance(evidence, list):
        _fail(f"{item_id}.evidence must be an array")
    validated: List[Dict[str, Any]] = []
    for index, raw in enumerate(evidence):
        if not isinstance(raw, dict):
            _fail(f"{item_id}.evidence[{index}] must be an object")
        unknown = set(raw) - EVIDENCE_FIELDS
        if unknown:
            _fail(f"{item_id}.evidence[{index}] has unknown fields: {sorted(unknown)}")
        missing = EVIDENCE_FIELDS - set(raw)
        if missing:
            _fail(f"{item_id}.evidence[{index}] missing fields: {sorted(missing)}")
        kind = _is_string(raw["kind"], f"{item_id}.evidence[{index}].kind")
        result = _is_string(raw["result"], f"{item_id}.evidence[{index}].result")
        if kind not in EVIDENCE_KINDS:
            _fail(f"{item_id}.evidence[{index}] has unknown kind: {kind}")
        if result not in EVIDENCE_RESULTS:
            _fail(f"{item_id}.evidence[{index}] has unknown result: {result}")
        verified_at = _is_string(raw["verified_at"], f"{item_id}.evidence[{index}].verified_at")
        if not DATE_PATTERN.fullmatch(verified_at):
            _fail(f"{item_id}.evidence[{index}].verified_at must be YYYY-MM-DD")
        _is_string(raw["command"], f"{item_id}.evidence[{index}].command")
        ref = _is_string(raw["ref"], f"{item_id}.evidence[{index}].ref")
        _safe_path(ref, root, f"{item_id}.evidence[{index}].ref")
        commit = raw["commit"]
        if commit is not None:
            _is_string(commit, f"{item_id}.evidence[{index}].commit")
        validated.append(raw)
    return validated


def _validate_item(raw: Any, index: int, root: Path) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        _fail(f"items[{index}] must be an object")
    item_id = raw.get("id", f"items[{index}]")
    _is_string(item_id, f"items[{index}].id")
    unknown = set(raw) - ITEM_FIELDS
    if unknown:
        _fail(f"{item_id} has unknown fields: {sorted(unknown)}")
    missing = ITEM_FIELDS - set(raw)
    if missing:
        _fail(f"{item_id} missing fields: {sorted(missing)}")
    if not ID_PATTERN.fullmatch(item_id):
        _fail(f"{item_id}.id must be kebab-case")
    parent_id = raw["parent_id"]
    if parent_id is not None:
        _is_string(parent_id, f"{item_id}.parent_id")
    level = _is_string(raw["level"], f"{item_id}.level")
    if level not in ITEM_LEVELS:
        _fail(f"{item_id}.level has unknown value: {level}")
    for field in ("name", "summary"):
        _is_string(raw[field], f"{item_id}.{field}")
    keywords = _string_list(raw["keywords"], f"{item_id}.keywords")
    platforms = _string_list(raw["platforms"], f"{item_id}.platforms")
    if any(not PLATFORM_PATTERN.fullmatch(platform) for platform in platforms):
        _fail(f"{item_id}.platforms must contain lowercase kebab-case tags")
    implementation_status = _is_string(raw["implementation_status"], f"{item_id}.implementation_status")
    if implementation_status not in IMPLEMENTATION_STATUSES:
        _fail(f"{item_id}.implementation_status has unknown value: {implementation_status}")
    maturity = _is_string(raw["maturity"], f"{item_id}.maturity")
    if maturity not in MATURITIES:
        _fail(f"{item_id}.maturity has unknown value: {maturity}")
    for field in ("acceptance_criteria", "code_paths", "spec_paths", "test_paths", "known_gaps"):
        _string_list(raw[field], f"{item_id}.{field}")
    task_ids = _string_list(raw["task_ids"], f"{item_id}.task_ids")
    if any(not TASK_PATTERN.fullmatch(task_id) for task_id in task_ids):
        _fail(f"{item_id}.task_ids contains an invalid task ID")
    for field in ("code_paths", "spec_paths", "test_paths"):
        for path in raw[field]:
            _safe_path(path, root, f"{item_id}.{field}[]")
    evidence = _validate_evidence(item_id, raw["evidence"], root)

    if level == "domain" and parent_id is not None:
        _fail(f"{item_id}: domain entries cannot have a parent")
    if level != "domain" and parent_id is None:
        _fail(f"{item_id}: {level} entries must have a parent")
    if level == "feature":
        if not raw["acceptance_criteria"]:
            _fail(f"{item_id}: feature requires acceptance_criteria")
    if implementation_status == "not_started" and maturity not in ("prototype", "beta"):
        _fail(f"{item_id}: not_started cannot claim {maturity}")
    if implementation_status == "in_progress" and maturity in ("production_ready", "production_proven"):
        _fail(f"{item_id}: in_progress cannot claim {maturity}")
    if implementation_status == "verified" and level == "feature":
        if not raw["test_paths"]:
            _fail(f"{item_id}: verified feature requires test_paths")
        if not any(entry["result"] == "passed" for entry in evidence):
            _fail(f"{item_id}: verified feature requires passed evidence")
    if maturity == "production_candidate" and level == "feature":
        if not any(entry["result"] == "passed" for entry in evidence):
            _fail(f"{item_id}: production_candidate requires passed evidence")
    if maturity in ("production_ready", "production_proven") and implementation_status != "verified":
        _fail(f"{item_id}: {maturity} requires verified implementation status")
    if maturity in ("production_ready", "production_proven") and level == "feature":
        required = {"unit", "integration", "e2e", "release"}
        actual = {entry["kind"] for entry in evidence if entry["result"] == "passed"}
        if not required.issubset(actual):
            _fail(f"{item_id}: {maturity} requires passed unit/integration/e2e/release evidence")
    if maturity == "production_proven" and level == "feature":
        if not any(entry["kind"] == "live" and entry["result"] == "passed" for entry in evidence):
            _fail(f"{item_id}: production_proven requires passed live evidence")
    return {**raw, "keywords": keywords, "platforms": platforms, "evidence": evidence}


def validate_catalog_data(catalog: Any, paths: CatalogPaths) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    if not isinstance(catalog, dict):
        _fail("catalog must contain a JSON object")
    expected = {"schema_version", "catalog_version", "updated_at", "title", "items"}
    unknown = set(catalog) - expected
    if unknown:
        _fail(f"catalog has unknown fields: {sorted(unknown)}")
    if set(catalog) != expected:
        _fail(f"catalog missing fields: {sorted(expected - set(catalog))}")
    if catalog["schema_version"] != 1:
        _fail("catalog schema_version must be 1")
    if not isinstance(catalog["catalog_version"], int) or catalog["catalog_version"] < 1:
        _fail("catalog_version must be a positive integer")
    updated_at = _is_string(catalog["updated_at"], "catalog.updated_at")
    if not DATE_PATTERN.fullmatch(updated_at):
        _fail("catalog.updated_at must be YYYY-MM-DD")
    _is_string(catalog["title"], "catalog.title")
    if not isinstance(catalog["items"], list) or not catalog["items"]:
        _fail("catalog.items must be a non-empty array")

    items = [_validate_item(raw, index, paths.root) for index, raw in enumerate(catalog["items"])]
    by_id: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if item["id"] in by_id:
            _fail(f"duplicate item id: {item['id']}")
        by_id[item["id"]] = item
    for item in items:
        parent_id = item["parent_id"]
        if parent_id is None:
            continue
        parent = by_id.get(parent_id)
        if parent is None:
            _fail(f"{item['id']} references missing parent: {parent_id}")
        expected_parent = {"capability": "domain", "feature": "capability"}[item["level"]]
        if parent["level"] != expected_parent:
            _fail(f"{item['id']} must have a {expected_parent} parent")
    for item in items:
        seen = set()
        current = item
        while current["parent_id"] is not None:
            if current["id"] in seen:
                _fail(f"catalog hierarchy contains a cycle at {current['id']}")
            seen.add(current["id"])
            current = by_id[current["parent_id"]]
    return catalog, by_id


def load_catalog(paths: CatalogPaths) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    _validate_schema_document(paths)
    catalog = _load_json(paths.catalog, "feature catalog")
    return validate_catalog_data(catalog, paths)


def _ordered_items(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_id = {item["id"]: item for item in items}
    children: Dict[Optional[str], List[Dict[str, Any]]] = defaultdict(list)
    for item in by_id.values():
        children[item["parent_id"]].append(item)
    for values in children.values():
        values.sort(key=lambda item: item["id"])
    result: List[Dict[str, Any]] = []

    def visit(parent_id: Optional[str]) -> None:
        for item in children.get(parent_id, []):
            result.append(item)
            visit(item["id"])

    visit(None)
    if len(result) != len(by_id):
        _fail("catalog cannot be deterministically ordered")
    return result


def _plain(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def _search_score(item: Dict[str, Any], query: str) -> int:
    normalized = _plain(query)
    if not normalized:
        return 0
    if normalized == item["id"]:
        return 1000
    content = _plain(" ".join([
        item["id"], item["name"], item["summary"], *item["keywords"],
        *item["known_gaps"], *item["task_ids"],
    ]))
    score = 20 if normalized in content else 0
    tokens = [
        token for token in re.split(r"[^a-z0-9]+", normalized)
        if token and token not in SEARCH_STOPWORDS
    ]
    score += sum(
        4 for token in tokens
        if re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", content)
    )
    return score


def query_catalog(
    paths: CatalogPaths,
    query: str,
    limit: int = 8,
    platform: Optional[str] = None,
    status: Optional[str] = None,
    maturity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    _, by_id = load_catalog(paths)
    if limit < 1:
        _fail("query limit must be positive")
    if platform is not None and not PLATFORM_PATTERN.fullmatch(platform):
        _fail(f"invalid platform filter: {platform}")
    if status is not None and status not in IMPLEMENTATION_STATUSES:
        _fail(f"unknown status filter: {status}")
    if maturity is not None and maturity not in MATURITIES:
        _fail(f"unknown maturity filter: {maturity}")

    scored = []
    for item in by_id.values():
        if platform is not None and platform not in item["platforms"]:
            continue
        if status is not None and item["implementation_status"] != status:
            continue
        if maturity is not None and item["maturity"] != maturity:
            continue
        score = _search_score(item, query)
        if score > 0:
            scored.append((score, item))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))

    selected: List[Dict[str, Any]] = []
    selected_ids = set()
    for _, item in scored:
        candidate = [item]
        parent_id = item["parent_id"]
        while parent_id is not None:
            candidate.append(by_id[parent_id])
            parent_id = by_id[parent_id]["parent_id"]
        new_ids = {entry["id"] for entry in candidate} - selected_ids
        if selected and len(selected) + len(new_ids) > limit:
            continue
        for entry in candidate:
            if entry["id"] not in selected_ids:
                selected.append(entry)
                selected_ids.add(entry["id"])
        if len(selected) >= limit:
            break
    return selected[:limit]


def _md(value: str) -> str:
    return value.replace("|", r"\|").replace("\n", " ").replace("`", "'")


def _relative_display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _evidence_summary(item: Dict[str, Any]) -> str:
    if not item["evidence"]:
        return "—"
    return "; ".join(f"{entry['kind']}:{entry['result']}" for entry in item["evidence"])


def _ancestor_label(item: Dict[str, Any], by_id: Dict[str, Dict[str, Any]]) -> str:
    labels = [item["name"]]
    parent_id = item["parent_id"]
    while parent_id is not None:
        parent = by_id[parent_id]
        labels.append(parent["name"])
        parent_id = parent["parent_id"]
    return " / ".join(reversed(labels))


def render_matrix(catalog: Dict[str, Any], by_id: Dict[str, Dict[str, Any]], paths: CatalogPaths) -> str:
    items = _ordered_items(by_id.values())
    domains = [item for item in items if item["level"] == "domain"]
    capabilities = [item for item in items if item["level"] == "capability"]
    leaves = [item for item in items if item["level"] == "feature"]
    verified = sum(item["implementation_status"] == "verified" for item in leaves)
    in_progress = sum(item["implementation_status"] == "in_progress" for item in leaves)
    script_path = Path(__file__).resolve()
    try:
        generator = script_path.relative_to(paths.root).as_posix()
    except ValueError:
        generator = "scripts/feature_catalog.py"
    catalog_display = _relative_display(paths.catalog, paths.root)
    lines = [
        f"<!-- AUTO-GENERATED from {catalog_display} — do not hand-edit -->",
        f"<!-- Regenerate: python3 {generator} --generate -->",
        "",
        f"# {catalog['title']}",
        "",
        f"目录版本：`{catalog['catalog_version']}` · 更新：`{catalog['updated_at']}` · 领域：`{len(domains)}` · 能力：`{len(capabilities)}` · 具体功能：`{len(leaves)}`",
        "",
        f"实现统计：已验证 `{verified}` · 进行中 `{in_progress}` · 其他 `{len(leaves) - verified - in_progress}`",
        "",
        "> 实现状态和生产成熟度分开记录；没有通过证据的功能不能升级为生产级。",
        "",
        "## Domain overview",
        "",
        "| Domain | Capabilities | Features | Gaps |",
        "|---|---:|---:|---|",
    ]
    for domain in domains:
        domain_capabilities = [item for item in capabilities if item["parent_id"] == domain["id"]]
        domain_features = [
            item for item in leaves
            if any(ancestor["id"] == domain["id"] for ancestor in _ancestors(item, by_id))
        ]
        gaps = "; ".join(domain["known_gaps"]) or "—"
        lines.append(f"| {_md(domain['name'])} | {len(domain_capabilities)} | {len(domain_features)} | {_md(gaps)} |")

    lines.extend([
        "",
        "## Feature details",
        "",
        "| Feature | Implementation | Maturity | Platforms | Evidence | Known gaps |",
        "|---|---|---|---|---|---|",
    ])
    for item in leaves:
        gaps = "; ".join(item["known_gaps"]) or "—"
        lines.append(
            f"| {_md(_ancestor_label(item, by_id))} | `{item['implementation_status']}` | `{item['maturity']}` | "
            f"{_md(', '.join(item['platforms']) or '—')} | {_md(_evidence_summary(item))} | {_md(gaps)} |"
        )
    lines.extend([
        "",
        "## Machine entry points",
        "",
        f"- Validate: `python3 {generator} --validate`",
        f"- Generate: `python3 {generator} --generate`",
        f"- Drift check: `python3 {generator} --check`",
        f"- Query: `python3 {generator} --query \"feature terms\"`",
        "",
    ])
    return "\n".join(lines)


def _ancestors(item: Dict[str, Any], by_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    parent_id = item["parent_id"]
    while parent_id is not None:
        parent = by_id[parent_id]
        result.append(parent)
        parent_id = parent["parent_id"]
    return result


def _atomic_write(path: Path, content: str, overwrite: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not overwrite:
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            _fail(f"refusing to overwrite existing file: {path}")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=str(path.parent), delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def initialize(paths: CatalogPaths) -> None:
    _validate_schema_document(paths)
    template = _load_json(paths.template, "feature catalog template")
    template["updated_at"] = datetime.now(timezone.utc).date().isoformat()
    validate_catalog_data(template, paths)
    content = json.dumps(template, ensure_ascii=False, indent=2) + "\n"
    _atomic_write(paths.catalog, content, overwrite=False)
    print(f"initialized {_relative_display(paths.catalog, paths.root)}")


def run_validate(paths: CatalogPaths) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    catalog, by_id = load_catalog(paths)
    items = list(by_id.values())
    print(
        f"feature catalog valid: {len(items)} items, "
        f"{sum(item['level'] == 'domain' for item in items)} domains, "
        f"{sum(item['level'] == 'capability' for item in items)} capabilities, "
        f"{sum(item['level'] == 'feature' for item in items)} features"
    )
    return catalog, by_id


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and render a project feature catalog.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--init", action="store_true", help="Create the active catalog from the template without overwriting it.")
    mode.add_argument("--validate", action="store_true", help="Validate catalog structure, semantics, and references.")
    mode.add_argument("--generate", action="store_true", help="Validate and generate the Markdown matrix.")
    mode.add_argument("--check", action="store_true", help="Validate and check generated matrix drift.")
    mode.add_argument("--query", metavar="TEXT", help="Query matching items and required ancestors.")
    parser.add_argument("--root", help="Target repository root; defaults to the current installed project root.")
    parser.add_argument("--catalog", help="Active catalog path relative to --root.")
    parser.add_argument("--schema", help="Schema path relative to --root.")
    parser.add_argument("--template", help="Template path relative to --root.")
    parser.add_argument("--matrix", help="Generated matrix path relative to --root.")
    parser.add_argument("--limit", type=int, default=8, help="Maximum query results, including ancestors.")
    parser.add_argument("--platform", help="Filter query results by a project-defined platform tag.")
    parser.add_argument("--status", choices=IMPLEMENTATION_STATUSES, help="Filter query results by implementation status.")
    parser.add_argument("--maturity", choices=MATURITIES, help="Filter query results by maturity.")
    parser.add_argument("--json", action="store_true", help="Render query results as JSON.")
    args = parser.parse_args(argv)
    try:
        paths = resolve_paths(args.root, args.catalog, args.schema, args.template, args.matrix)
        if args.init:
            initialize(paths)
            return 0
        if args.query is not None:
            matches = query_catalog(paths, args.query, args.limit, args.platform, args.status, args.maturity)
            if args.json:
                print(json.dumps(matches, ensure_ascii=False, indent=2, sort_keys=True))
            elif not matches:
                print("no feature matches")
            else:
                for item in matches:
                    print(
                        f"{item['id']}\t{item['level']}\t{item['implementation_status']}\t"
                        f"{item['maturity']}\t{item['name']}"
                    )
            return 0

        catalog, by_id = run_validate(paths)
        rendered = render_matrix(catalog, by_id, paths)
        if args.generate:
            _atomic_write(paths.matrix, rendered)
            print(f"generated {_relative_display(paths.matrix, paths.root)}")
        elif args.check:
            if not paths.matrix.is_file():
                _fail(f"missing generated matrix: {_relative_display(paths.matrix, paths.root)}")
            current = paths.matrix.read_text(encoding="utf-8")
            if current != rendered:
                _fail("generated matrix is stale: run feature_catalog.py --generate")
            print(f"feature matrix current: {_relative_display(paths.matrix, paths.root)}")
        return 0
    except CatalogError as exc:
        print(f"feature catalog validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
