---
name: workflow-release
description: Prepare a configured project's release and execution plans and release notes, checking version strategy, source commit and tag conflicts. The shipped CLI and skill remain preparation-only; no production execution adapter is included.
---

# Prepare a release

Read the project's release configuration and installed `docs/release/README.md`. Run `python3 scripts/release_prepare.py --repo . --json` from the project root; consult `--help` for explicitly requested version or target parameters. If the tool/package/configuration is absent, report what is needed instead of choosing or installing a release policy.

Keep `none`, `commit-sha` and `semver-tag` strategies distinct. Ordinary pushes do not require tags. A same-name tag pointing elsewhere is a blocker; never move or delete it. Bind results to the exact source commit and repeat preparation after target or configuration drift. Preparation accepts existing annotated tags that peel to the same commit; the execution foundation refuses annotated tags because it requires exact raw object identity and creates only lightweight tags.

When execution planning is requested, read `docs/release/EXECUTION.md`. `python3 scripts/release_execute.py status` returns JSON with `executionAvailable: false`. Use `plan --repo . --preparation PATH` for a requested saved preparation; provide `--remote`, `--release-spec` or `--output` only for the user's intended target and output. Do not write notes, release specifications, records or other project files unless the user requested that local output.

Draft notes from the agreed scope and verified changes. Report merged code, CI, artifacts, deployment and production verification separately; tag or Release success does not establish any of those states. For partial releases retain each component's source, artifact identity and unchanged components. Distinguish locally built artifacts from CI artifacts. Missing facts stay unknown.

Return the plan, checks, conflicts, evidence gaps and next steps. The execution foundation requires a trusted host to inject authenticated, scoped approval and bound remote providers in process; no production adapter ships. The CLI `execute` refuses before repository reads, network access or mutation. Installation, configuration, ordinary push permissions, project audit records and user-authored approval JSON do not grant execution authority. Do not create tags (including local tags), push, create remote Releases, publish artifacts, deploy, change permissions, manufacture grants, load provider files or use environment/TTY/command fallbacks to bypass a blocked execution. Report the missing trusted integration and retain preparation-only results.
