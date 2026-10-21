#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
export LC_ALL=C
export LANG=C
export PYTHONDONTWRITEBYTECODE=1

python3 -m unittest discover -s "$repo_root/tests" -p 'test_*.py'
bash -n "$repo_root/scripts/install.sh" "$repo_root/scripts/audit.sh" "$repo_root/scripts/uninstall.sh" "$repo_root/tests/integration.sh"
python3 - "$repo_root" <<'PYTHON'
import ast
from pathlib import Path
import sys
root = Path(sys.argv[1])
for directory in ('core/scripts', 'packs', 'scripts', 'tests'):
    for path in (root / directory).rglob('*.py'):
        ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
PYTHON
bash "$repo_root/tests/integration.sh" >/dev/null
printf 'All dev-workflow checks passed.\n'
