#!/usr/bin/env python3
"""Read one scalar field from a dev-workflow manifest.

This small helper keeps the shell installers from parsing JSON with regular
expressions. It intentionally accepts only scalar values so malformed or
unexpected manifest shapes fail closed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("field")
    parser.add_argument("--git-policy", action="store_true")
    args = parser.parse_args()

    try:
        with args.path.open(encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read manifest: {exc}", file=sys.stderr)
        return 2

    if not isinstance(document, dict):
        print("manifest must contain a JSON object", file=sys.stderr)
        return 2
    value = document.get("gitPolicy") if args.git_policy else document
    if not isinstance(value, dict):
        return 1
    if args.field not in value and not args.git_policy:
        onboarding = value.get("onboarding")
        if isinstance(onboarding, dict) and args.field in onboarding:
            value = onboarding
    if args.field not in value:
        # Optional manifest fields are intentionally absent in older schemas.
        return 1 if args.git_policy else 0
    value = value[args.field]
    if value is None:
        return 1 if args.git_policy else 0
    if isinstance(value, (dict, list)):
        return 1
    if isinstance(value, bool):
        print(str(value).lower())
    else:
        print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
