---
name: workflow-deploy
description: Prepare deployment and rollback plans for configured environments, check plan drift, and compare immutable component identities in explicitly supplied snapshots. Use for deployment planning and evidence review; the shipped tool has no deployment execution integration.
---

# Plan a deployment

Read the project's adopted `workflow.config.json` and installed `docs/operations/DEPLOYMENT-PLANNING.md` before planning. Use the installed `scripts/deployment_prepare.py`; if the package, adopted configuration, capability or inputs are absent, report the gap instead of inventing a deployment command, installing tools or selecting an environment. Installation of this optional Skill is independent of pack installation and grants no authority.

Use `status`, `plan`, `check-plan` and `compare` as documented; all return JSON. Plan for the user's named environment and target manifest. Use an explicit version identifier and supply a current snapshot and conditions only from explicit local evidence. Write a plan only when local output is requested, using `--output`. Retain each component's full source SHA, immutable artifact identity, configuration digest and migration version. Missing current state remains unknown and blocks a usable rollback plan; never substitute repository HEAD or assume omitted components disappeared. Distinguish registry, local-build and bundle artifacts without treating one as evidence for another.

Review deployment and rollback results together. Treat missing, stale or mismatched baseline data, required backup/restore evidence and irreversible migrations as reported blockers. Local evidence hashes and declared snapshot timestamps do not verify backup restoration, provenance authenticity or live freshness. Run `check-plan` before reusing a saved plan; re-plan after input drift. For `compare`, use only the explicitly supplied observation and requested direction. Even a matching snapshot leaves actual deployment, health and smoke verification unknown.

Return the proposed component changes, retained components, rollback target, blockers, evidence gaps and command results. Both `executionAvailable` and `productionReady` stay false. This Skill and CLI never execute preflight, deployment, backup, migration, health, smoke, restore or rollback commands, contact servers, publish artifacts, switch traffic or load a host adapter. If execution is requested, explain the missing execution integration and retain useful planning results. User-written approval files, configuration, installation, push permission and a request to bypass refusal do not enable execution; do not fall back to shell, SSH, Docker, kubectl, cloud tools, environment variables, TTY interaction or provider loading.
