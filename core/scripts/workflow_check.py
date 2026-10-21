#!/usr/bin/env python3
"""Read-only, local workflow diagnostics. Never executes declared commands."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from workflow_config import CAPABILITY_PACKS, resolve_configuration, safe_path


def git(root: Path, *arguments: str) -> str | None:
    try:
        process = subprocess.run(['git', '--no-optional-locks', '-C', str(root), *arguments], capture_output=True, text=True, timeout=10)
        return process.stdout.strip() if process.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def check(root: Path) -> dict:
    resolved = resolve_configuration(root)
    issues = [dict(item, severity='error') for item in resolved['errors']]
    issues.extend(dict(item, severity='warning') for item in resolved['warnings'])

    def issue(code, message, path=None):
        item = dict(code=code, severity='warning', message=message)
        if path:
            item['path'] = path
        issues.append(item)

    manifest = resolved['manifest']
    installed = manifest.get('installedPacks', [])
    if not isinstance(installed, list) or any(not isinstance(p, str) for p in installed):
        installed = []
        issues.append(dict(code='manifest.packs_invalid', severity='error', message='Installed pack list is invalid.'))
    capabilities = []
    tools = {'release': 'scripts/release_prepare.py',
             **{capability: 'scripts/deployment_prepare.py' for capability, pack in CAPABILITY_PACKS.items() if pack == 'deployment'}}
    for capability in resolved['capabilities']:
        pack = CAPABILITY_PACKS[capability]
        tool = tools.get(capability)
        executable = False
        if tool:
            try:
                executable = safe_path(root, tool).is_file()
            except ValueError:
                pass
        capabilities.append(dict(id=capability, installed=pack in installed, configured=True,
                                 executable=executable if tool else None, verification='unknown'))
        if pack not in installed:
            issue('capability.pack_missing', 'Declared capability lacks its specialist pack: ' + capability)
        elif tool and not executable:
            issue('capability.tool_missing', 'Declared capability lacks its local tool: ' + capability)
    if installed and not resolved['capabilities']:
        issue('capability.empty', 'Packs are installed but no technical capabilities are declared; no automatic activation was performed.')
    indicators = [('.github/workflows', 'cicd:github-actions'), ('deploy/docker-compose.yml', 'containers:compose'),
                  ('deploy/compose.prod.yml', 'deployment:compose'), ('backend/openapi.yaml', 'api:rest-openapi')]
    for path, suggested in indicators:
        try:
            exists = safe_path(root, path).exists()
        except ValueError:
            exists = False
        if exists and suggested not in resolved['capabilities']:
            issue('capability.suggested', 'Local path suggests a capability to review: ' + suggested, path)

    for name, spec in resolved['config'].get('commands', {}).items():
        try:
            exists = safe_path(root, spec.get('cwd', '.')).is_dir()
        except ValueError:
            exists = False
        if not exists:
            issue('command.cwd_missing', 'Declared command working directory is missing: ' + name)
    for name, path in resolved['config'].get('documents', {}).items():
        try:
            exists = safe_path(root, path).is_file()
        except ValueError:
            exists = False
        if not exists:
            issue('document.missing', 'Declared document is missing: ' + name)

    # Fixed known rule files only: never recursively scan configuration, logs or credentials.
    text = ''
    try:
        path = safe_path(root, 'AGENTS.md')
        if path.is_file() and path.stat().st_size <= 262144:
            text = path.read_text(encoding='utf-8')
    except (OSError, ValueError, UnicodeError):
        issue('rules.unreadable', 'Project AGENTS.md cannot be safely read.')
    if '当前为空仓库阶段' in text:
        try:
            populated = any(safe_path(root, p).is_dir() for p in ('backend', 'frontend', 'src'))
        except ValueError:
            populated = False
        if populated:
            issue('rules.stale_scaffold', 'Rules describe an empty scaffold but source directories exist.', 'AGENTS.md')
    policy = manifest.get('gitPolicy', {})
    if not isinstance(policy, dict):
        policy = {}
    project_text = text.split('<!-- AI-WORKFLOW:PROJECT:START -->', 1)[-1]
    declared = re.search(r'gitPolicy[^\n]{0,40}?(manual|auto)\s*\+\s*(user|ai)', project_text)
    if declared and (declared.group(1), declared.group(2)) != (policy.get('pushMode'), policy.get('pushActor')):
        issue('rules.policy_conflict', 'Project rule shorthand conflicts with the local push policy; read per-operation fields.', 'AGENTS.md')
    head = git(root, 'rev-parse', '--verify', 'HEAD')
    branch = git(root, 'symbolic-ref', '--quiet', '--short', 'HEAD')
    baseline_ref = git(root, 'symbolic-ref', '--quiet', '--short', 'refs/remotes/origin/HEAD')
    if not baseline_ref:
        baseline_ref = next((ref for ref in ('origin/main', 'origin/master', 'main', 'master') if git(root, 'rev-parse', '--verify', ref)), None)
    baseline = git(root, 'rev-parse', '--verify', baseline_ref) if baseline_ref else None
    divergence = git(root, 'rev-list', '--left-right', '--count', f'HEAD...{baseline_ref}') if head and baseline else None
    if divergence and divergence.split() != ['0', '0']:
        issue('git.baseline_differs', 'Working HEAD differs from the locally cached baseline; select the relevant revision before drawing conclusions.')
    if not head:
        issue('git.unverified', 'No committed Git HEAD could be verified locally.')
    state = 'invalid' if any(i['severity'] == 'error' for i in issues) else 'warning' if issues else 'ready'
    return dict(schemaVersion=1, result=state, configurationSource=resolved['source'],
                installedPacks=installed, capabilities=capabilities, issues=issues,
                git=dict(head=head, branch=branch, baselineRef=baseline_ref, baselineSha=baseline, divergence=divergence),
                remote='unknown', production='unknown', commandsExecuted=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--strict', action='store_true')
    args = parser.parse_args()
    report = check(args.repo.resolve())
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        print('dev-workflow doctor: ' + report['result'])
        print('configuration: ' + report['configurationSource'])
        for item in report['issues']:
            print(f"[{item['severity']}] {item['code']}: {item['message']}")
        print('remote: unknown; production: unknown; declared commands were not executed')
    return int(report['result'] == 'invalid' or (args.strict and bool(report['issues'])))


if __name__ == '__main__':
    sys.exit(main())
