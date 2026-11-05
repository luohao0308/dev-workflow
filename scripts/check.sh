#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
export LC_ALL=C
export LANG=C
export PYTHONDONTWRITEBYTECODE=1

if [[ $# -gt 1 ]] || [[ $# -eq 1 && "$1" != --fast ]]; then
  printf 'Usage: %s [--fast]\n' "$0" >&2
  exit 2
fi

cd "$repo_root"
printf '== Syntax checks ==\n'
for script in scripts/install.sh scripts/audit.sh scripts/uninstall.sh tests/integration.sh scripts/check.sh; do
  bash -n "$script"
done
python3 - "$repo_root" <<'PYTHON'
import ast
from pathlib import Path
import sys
root = Path(sys.argv[1])
for directory in ('core/scripts', 'packs', 'scripts', 'tests'):
    for path in (root / directory).rglob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
PYTHON

if [[ ${1:-} == --fast ]]; then
  printf '== Smoke tests ==\n'
  python3 -m unittest tests.test_workflow_config tests.test_deployment_spec tests.test_feature_catalog
  printf 'Fast dev-workflow checks passed.\n'
else
  printf '== Python suite ==\n'
  python3 -m unittest discover -s tests -p 'test_*.py'
  printf '== Bash integration ==\n'
  bash tests/integration.sh >/dev/null
  printf 'Full test suite passed.\n'
fi
