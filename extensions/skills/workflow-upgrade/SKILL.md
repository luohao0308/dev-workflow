---
name: workflow-upgrade
description: Plan and review a dev-workflow installation upgrade against its exact old distribution, preserving project customizations. Apply authorized conflict-free plans, safely roll back a transaction, or explicitly transfer adopted documents to project ownership.
---

# Upgrade an installed workflow

Use `scripts/upgrade.py` from the new dev-workflow distribution, not the target project's installed scripts. Locate that distribution and either the exact previous distribution used by the installation or the verified baseline snapshot recorded by an earlier successful upgrade. Omit `--baseline` only when that recorded snapshot exists. If required evidence is unavailable, report it; do not download a guessed baseline or copy the engine into the target project. The engine reads the installed package selection from the target manifest; do not substitute all packages or infer a new selection.

Default to planning and reviewing differences. For example:

```sh
python3 /path/to/dev-workflow/scripts/upgrade.py plan --target /project --baseline /old-distribution --output /tmp/upgrade-plan.json
```

The source defaults to the distribution containing the script. Inspect the plan and relevant old/current/new content, including managed Core blocks. Explain proposed updates, user modifications, conflicts, unknown baselines and preserved paths. Do not treat a missing or mismatched baseline as an unmodified installation, invent ancestor content, or automatically merge uncertain content. Leave conflicts for review; do not edit away a conflict to make apply succeed.

Apply only when the user has authorized the concrete migration scope and the plan is conflict-free. Existing authorization for that scope is sufficient; installation, push permission and configuration do not grant upgrade authority. Re-plan if the inspected inputs change; do not bypass engine refusal or modify the plan to defeat its checks.

```sh
python3 /path/to/dev-workflow/scripts/upgrade.py apply --target /project --plan /tmp/upgrade-plan.json
```

Preserve permission fields, local authorization records, user edits and unrelated files. Upgrading does not adopt, withdraw or synchronize project configuration, enable capabilities, change Git tracking/index policy, or authorize external actions. A configuration migration request needs its separate configuration workflow. This Skill does not execute S5 publishing: no local/remote tag creation, remote Release, artifact publishing or deployment.

For an explicitly requested rollback, identify the recorded transaction and use its path-level recovery:

```sh
python3 /path/to/dev-workflow/scripts/upgrade.py rollback --target /project --transaction ID
```

Inspect the result and preserve user changes made after apply. If a path no longer matches the transaction's post-upgrade state, report the rollback conflict instead of restoring over it. After interruption, inspect the transaction record and current paths before choosing recovery; do not claim an incomplete transaction succeeded or blindly rerun mutations.

For explicitly transferring adopted rule/document templates to project maintenance, preview only the named paths first:

```sh
python3 /path/to/dev-workflow/scripts/upgrade.py transfer --target /project --paths docs/PROJECT-SUMMARY.md --dry-run
```

Perform transfer without `--dry-run` only within the authorized path scope after reviewing the preview. Transferred documents must be preserved by later upgrades/uninstall. Transfer does not approve sharing, stage files, change permission policy, or make local state/authorization records transferable. Refuse paths outside the project and protected local records even if the user calls them documentation.

Return the reviewed scope, actual command results, conflicts or evidence gaps, and any transaction identity. Distinguish a proposed plan, applied changes, partial recovery and completed rollback. This optional entry point is not required to run the engine directly.
