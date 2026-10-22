---
name: workflow-deploy
description: Prepare deployment and rollback plans, check drift, and compare supplied snapshots. When an actual trusted execution host is configured, route single-component Docker deployment or rollback through its execution-bound SDK; otherwise retain offline planning and report the integration gap.
---

# Deployment planning and trusted execution

Read the project's adopted `workflow.config.json` and installed `docs/operations/DEPLOYMENT-PLANNING.md`. Use installed `scripts/deployment_prepare.py` for `status`, `plan`, `check-plan` and `compare` (JSON output). If the pack, adopted configuration, capability or inputs are missing, report the gap. Skill installation grants no authority and does not install the pack.

Plan for the named environment and explicit target. Use current snapshots and conditions from supplied local evidence; write a plan only when local output is requested. Retain full source SHAs, immutable artifacts, configuration digests and migration versions, including unselected components. Missing, stale or mismatched state blocks usable rollback; do not substitute HEAD, target values or guessed evidence. Local hashes and timestamps do not prove provenance, live freshness or backup restoration. Check saved plans before reuse and re-plan after drift. A matching supplied snapshot alone leaves execution, health and smoke unknown. Planner comparison still checks the global version strictly, including business aliases.

## Trusted host routing

For runtime collection or authorization, read installed `docs/operations/DEPLOYMENT-RUNTIME.md`. For actual deployment or rollback, also read `docs/operations/DEPLOYMENT-EXECUTION.md`. Use the SDK only through an actual trusted, configured execution profile loaded from fixed trusted source. SDK files, project configuration, approval JSON, push permission or a claimed auth-only permit do not establish that profile. If it is unavailable, return useful planning results and the precise integration gap.

Preserve the user's existing explicit authorization; do not ask again for the same scope. A new exact scope requires new approval. Host verification of signed OIDC, the exact bundle approval and one-use CAS consumption remains mandatory. Deployment and rollback require distinct fresh requests and grants. Bind the executor-issued intent through `Request.execution_json` and the host's exact `execution_policy_hash`; never dispatch an old auth-only permit, even after claim.

The fixed `docker-container-replace-v1` backend replaces exactly one component using preloaded immutable Linux images and a trusted recipe: create a stopped candidate, stop the exact old ID, remove it without force/volume deletion, then start the exact new ID. Preserve unselected instances. Full specs and private Env stay inside the host; requests/audits carry digests, not raw configuration. Semantic recipe digests do not replace full raw-state drift hashes. Reader/writer TLS principals must be separate, with server-enforced route/resource permissions and certificate-hash scope binding.

On SDK success, retain the returned collector-issued `observation` in the same trusted process and remove it from the result before JSON serialization; `runtimeObservation` is audit evidence only. Rollback needs a fresh complete current baseline, a new plan/intent/request/grant, and the same collector's older proof plus retained old image/spec. It recreates an instance, not old container IDs or logs. Exported JSON cannot recover capabilities or process-local history.

Stop on failure, unknown response or drift. Do not retry, clean up, automatically roll back, refund or resume from JSON. Incomplete intermediate state blocks normal rollback authorization until reconciled; recovery is future P1-5 work.

## Results and boundaries

Report changed and retained components, rollback identity, blockers, evidence and actual command/SDK results. Offline CLI and authorization-only results have `executionAvailable: false`; the actual backend can report `executionAvailable: true` and `executed-verified`. Keep `productionReady: false`, health/smoke unknown, and distinguish `declaredVersion` from `runtimeVersion`. Do not infer real GitHub proof from fixture `fakeTestApproval` smoke or claim tests have run without evidence.

Do not execute project stage commands or fall back to host shell, SSH, Docker/Compose CLI, kubectl, cloud tools, plugins or environment credential discovery. This profile does not perform production acceptance, traffic switching, database operations, backup/restore, migrations, health/smoke probes or readiness. Unique resource names do not preserve service DNS or Compose names; actual static IPv4 port mappings are checked, while daemon network security remains outside the profile.
