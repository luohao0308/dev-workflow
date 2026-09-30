#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
export LC_ALL=C
export LANG=C

python3 -m unittest discover -s "$repo_root/tests" -p 'test_*.py'
bash -n "$repo_root/scripts/install.sh" "$repo_root/scripts/audit.sh" "$repo_root/scripts/uninstall.sh" "$repo_root/tests/integration.sh"
python3 -m compileall -q "$repo_root/core/scripts" "$repo_root/packs" "$repo_root/scripts" "$repo_root/tests"
bash "$repo_root/tests/integration.sh" >/dev/null
printf 'All dev-workflow checks passed.\n'
