---
name: workflow-release
description: Prepare a configured project's release plan and release notes, checking version strategy, source commit and tag conflicts. This entry point only prepares releases and never executes publishing or deployment.
---

# Prepare a release

Read the project's release configuration and installed release package guidance. Run `python3 scripts/release_prepare.py --repo . --json` from the project root; consult `--help` for explicitly requested version or target parameters. If the tool/package/configuration is absent, report what is needed instead of silently choosing or installing a release policy.

Keep `none`, `commit-sha` and `semver-tag` strategies distinct. Ordinary pushes do not require tags. A same-name tag pointing elsewhere is a blocker; never move or delete it. Bind every result to the exact inspected source commit and repeat preparation if that target changes.

Draft release notes only from the agreed scope and verified changes. Report merged code, CI, artifacts, deployment and production verification separately; CI success does not establish deployment. For partial releases retain each component's source, artifact identity and unchanged components. Distinguish locally built artifacts from CI artifacts. Missing facts stay unknown.

Return the plan, checks, conflicts, evidence gaps and next steps. Do not create tags (including local tags), push, create remote Releases, publish artifacts, deploy, change permissions, or manufacture authorization. This preparation-only boundary applies even if existing policy authorizes ordinary pushes. Installation and configuration are not execution authorization. Do not write release records or project files unless the user requested that local output.
