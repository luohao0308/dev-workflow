---
name: workflow-doctor
description: Inspect a project's dev-workflow installation, capability configuration, branch baseline and conflicting project knowledge. Use for workflow health checks; report findings without repairing files.
---

# Project workflow health

Run from the target project root: `python3 scripts/workflow_check.py --repo . --json`.
If the tool is absent, report the missing Core installation; do not fetch or install it silently. A project can also use the tool directly without this Skill.

Interpret findings against the user's task and project rules. Read only the mapped rules, current task and specific conflicting passages needed to explain a finding. For capability configuration consult `python3 scripts/workflow_config.py --help`; do not adopt, enable or synchronize configuration during a health check.

Separate deterministic findings from semantic judgments, and give evidence paths and confidence for the latter. Describe installed packages, configured capabilities and executable tools separately. Installed packages do not prove an intention to enable a capability.

Identify the current branch and the freshness of available local references. Old branch files are not proof of current main or production state. Do not fetch, checkout, scan secrets, change permissions or repair content. Remote and production facts remain unverified unless independently supplied evidence supports them.

Return prioritized findings, their practical impact, and a bounded repair plan. If documents disagree, preserve the disagreement rather than choosing the most optimistic statement. No finding or Skill installation grants action permissions.
