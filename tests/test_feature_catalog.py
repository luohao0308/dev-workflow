#!/usr/bin/env python3
"""Standard-library regression tests for the optional feature-catalog pack."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PACK_ROOT = REPO_ROOT / "packs/feature-catalog"
MODULE_PATH = PACK_ROOT / "scripts/feature_catalog.py"
SPEC = importlib.util.spec_from_file_location("dev_workflow_feature_catalog", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import contract failure
    raise RuntimeError(f"cannot load {MODULE_PATH}")
feature_catalog = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = feature_catalog
SPEC.loader.exec_module(feature_catalog)


class FeatureCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative, content in {
            "AGENTS.md": "# Project rules\n",
            "docs/README.md": "# Docs\n",
            "docs/spec.md": "# Login specification\n",
            "docs/evidence.md": "# Verification evidence\n",
            "scripts/feature_catalog.py": "# installed tool\n",
            "src/login.py": "# implementation\n",
            "tests/test_login.py": "# tests\n",
        }.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        ai_dir = self.root / "docs/development/ai"
        ai_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PACK_ROOT / "docs/development/ai/feature-catalog.schema.json", ai_dir)
        shutil.copy2(PACK_ROOT / "docs/development/ai/feature-catalog.template.json", ai_dir)
        shutil.copy2(PACK_ROOT / "docs/development/ai/FEATURE-CATALOG.md", ai_dir)
        self.catalog = self._valid_catalog()
        self.catalog_path = ai_dir / "feature-catalog.json"
        self._write_catalog(self.catalog)
        self.paths = feature_catalog.resolve_paths(str(self.root))

    @staticmethod
    def _valid_catalog():
        return {
            "schema_version": 1,
            "catalog_version": 1,
            "updated_at": "2026-08-17",
            "title": "Example Product Feature Matrix",
            "items": [
                {
                    "id": "product",
                    "parent_id": None,
                    "level": "domain",
                    "name": "Product",
                    "summary": "Product capabilities.",
                    "keywords": ["product"],
                    "platforms": ["web"],
                    "implementation_status": "verified",
                    "maturity": "production_candidate",
                    "acceptance_criteria": [],
                    "code_paths": ["src"],
                    "spec_paths": ["docs/spec.md"],
                    "test_paths": [],
                    "evidence": [],
                    "known_gaps": [],
                    "task_ids": [],
                },
                {
                    "id": "identity",
                    "parent_id": "product",
                    "level": "capability",
                    "name": "Identity",
                    "summary": "Account and authentication capabilities.",
                    "keywords": ["identity", "auth"],
                    "platforms": ["web"],
                    "implementation_status": "verified",
                    "maturity": "production_candidate",
                    "acceptance_criteria": [],
                    "code_paths": ["src/login.py"],
                    "spec_paths": ["docs/spec.md"],
                    "test_paths": [],
                    "evidence": [],
                    "known_gaps": [],
                    "task_ids": [],
                },
                {
                    "id": "user-login",
                    "parent_id": "identity",
                    "level": "feature",
                    "name": "User login",
                    "summary": "Users can sign in with verified credentials.",
                    "keywords": ["login", "authentication", "登录"],
                    "platforms": ["web"],
                    "implementation_status": "verified",
                    "maturity": "production_candidate",
                    "acceptance_criteria": ["Valid users can sign in."],
                    "code_paths": ["src/login.py"],
                    "spec_paths": ["docs/spec.md"],
                    "test_paths": ["tests/test_login.py"],
                    "evidence": [
                        {
                            "kind": "integration",
                            "command": "python3 -m unittest tests.test_login",
                            "result": "passed",
                            "verified_at": "2026-08-17",
                            "commit": None,
                            "ref": "docs/evidence.md",
                        }
                    ],
                    "known_gaps": ["Passkey support is not implemented."],
                    "task_ids": ["AUTH-1"],
                },
            ],
        }

    def _write_catalog(self, catalog) -> None:
        self.catalog_path.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _variant(self, mutate):
        variant = copy.deepcopy(self.catalog)
        mutate(variant)
        return variant

    def _evidence(self, kind: str, result: str = "passed"):
        return {
            "kind": kind,
            "command": f"verify {kind}",
            "result": result,
            "verified_at": "2026-08-17",
            "commit": "abc123",
            "ref": "docs/evidence.md",
        }

    def test_valid_catalog_and_schema_pass(self) -> None:
        catalog, by_id = feature_catalog.load_catalog(self.paths)
        self.assertEqual(catalog["title"], "Example Product Feature Matrix")
        self.assertEqual(list(by_id), ["product", "identity", "user-login"])

    def test_missing_parent_is_rejected(self) -> None:
        variant = self._variant(lambda data: data["items"][2].update(parent_id="missing"))
        with self.assertRaisesRegex(feature_catalog.CatalogError, "missing parent"):
            feature_catalog.validate_catalog_data(variant, self.paths)

    def test_hierarchy_cycle_or_level_jump_is_rejected(self) -> None:
        variant = self._variant(lambda data: data["items"][1].update(parent_id="user-login"))
        with self.assertRaisesRegex(feature_catalog.CatalogError, "domain parent"):
            feature_catalog.validate_catalog_data(variant, self.paths)

    def test_verified_feature_requires_passed_evidence(self) -> None:
        missing_tests = self._variant(lambda data: data["items"][2].update(test_paths=[]))
        with self.assertRaisesRegex(feature_catalog.CatalogError, "requires test_paths"):
            feature_catalog.validate_catalog_data(missing_tests, self.paths)
        variant = self._variant(lambda data: data["items"][2]["evidence"][0].update(result="blocked"))
        with self.assertRaisesRegex(feature_catalog.CatalogError, "passed evidence"):
            feature_catalog.validate_catalog_data(variant, self.paths)

    def test_planned_feature_allows_project_platform_and_no_evidence(self) -> None:
        def mutate(data):
            feature = data["items"][2]
            feature.update(
                implementation_status="not_started",
                maturity="prototype",
                platforms=["cli-extension"],
                test_paths=[],
                evidence=[],
                task_ids=["#123"],
            )

        variant = self._variant(mutate)
        self._write_catalog(variant)
        feature_catalog.load_catalog(self.paths)
        matches = feature_catalog.query_catalog(self.paths, "login", platform="cli-extension")
        self.assertEqual(matches[0]["id"], "user-login")

        variant["items"][2]["platforms"] = ["CLI Extension"]
        with self.assertRaisesRegex(feature_catalog.CatalogError, "lowercase kebab-case"):
            feature_catalog.validate_catalog_data(variant, self.paths)

    def test_production_ready_requires_complete_evidence(self) -> None:
        variant = self._variant(lambda data: data["items"][2].update(maturity="production_ready"))
        with self.assertRaisesRegex(feature_catalog.CatalogError, "unit/integration/e2e/release"):
            feature_catalog.validate_catalog_data(variant, self.paths)

    def test_production_proven_requires_live_evidence(self) -> None:
        def mutate(data):
            feature = data["items"][2]
            feature["maturity"] = "production_proven"
            feature["evidence"] = [self._evidence(kind) for kind in ("unit", "integration", "e2e", "release")]

        variant = self._variant(mutate)
        with self.assertRaisesRegex(feature_catalog.CatalogError, "live evidence"):
            feature_catalog.validate_catalog_data(variant, self.paths)
        variant["items"][2]["evidence"].append(self._evidence("live"))
        feature_catalog.validate_catalog_data(variant, self.paths)

    def test_unsafe_or_missing_paths_are_rejected(self) -> None:
        unsafe = self._variant(lambda data: data["items"][2].update(code_paths=["../secret"]))
        with self.assertRaisesRegex(feature_catalog.CatalogError, "safe repository-relative"):
            feature_catalog.validate_catalog_data(unsafe, self.paths)
        missing = self._variant(lambda data: data["items"][2].update(code_paths=["src/missing.py"]))
        with self.assertRaisesRegex(feature_catalog.CatalogError, "missing path"):
            feature_catalog.validate_catalog_data(missing, self.paths)

    def test_matrix_is_deterministic_and_escapes_markdown(self) -> None:
        variant = self._variant(lambda data: data["items"][2].update(name="Login | `UI`", known_gaps=["line one\nline two"]))
        catalog, by_id = feature_catalog.validate_catalog_data(variant, self.paths)
        first = feature_catalog.render_matrix(catalog, by_id, self.paths)
        second = feature_catalog.render_matrix(catalog, dict(reversed(list(by_id.items()))), self.paths)
        self.assertEqual(first, second)
        self.assertIn("Login \\| 'UI'", first)
        self.assertIn("line one line two", first)

    def test_generate_check_and_drift_detection(self) -> None:
        self.assertEqual(feature_catalog.main(["--root", str(self.root), "--generate"]), 0)
        self.assertEqual(feature_catalog.main(["--root", str(self.root), "--check"]), 0)
        matrix = self.root / "docs/FEATURE-MATRIX.md"
        matrix.write_text(matrix.read_text(encoding="utf-8") + "manual edit\n", encoding="utf-8")
        self.assertEqual(feature_catalog.main(["--root", str(self.root), "--check"]), 1)

    def test_query_returns_match_and_required_ancestors(self) -> None:
        matches = feature_catalog.query_catalog(self.paths, "login authentication", limit=6)
        self.assertEqual([item["id"] for item in matches[:3]], ["user-login", "identity", "product"])
        filtered = feature_catalog.query_catalog(self.paths, "login", platform="desktop")
        self.assertEqual(filtered, [])
        self.assertEqual(feature_catalog.query_catalog(self.paths, "nonexistent term"), [])

    def test_init_creates_once_and_never_overwrites(self) -> None:
        self.catalog_path.unlink()
        feature_catalog.initialize(self.paths)
        initialized = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        self.assertEqual(initialized["schema_version"], 1)
        self.assertEqual(len(initialized["items"]), 2)
        with self.assertRaisesRegex(feature_catalog.CatalogError, "refusing to overwrite"):
            feature_catalog.initialize(self.paths)

    def test_cli_paths_cannot_escape_root(self) -> None:
        with self.assertRaisesRegex(feature_catalog.CatalogError, "safe repository-relative"):
            feature_catalog.resolve_paths(str(self.root), catalog_value="../catalog.json")


if __name__ == "__main__":
    unittest.main()
