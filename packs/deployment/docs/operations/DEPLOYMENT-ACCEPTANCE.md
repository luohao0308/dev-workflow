# Scoped deployment acceptance (P2)

The optional deployment pack can assess evidence for **one named project target and environment**. This is an acceptance record for the narrow Linux Docker container-replacement profile; it is not a deployment permit. The existing `productionReady: false` result remains unchanged. A report can describe what was observed for the named scope without declaring the framework or every project production ready.

Start with [the example profile](../../../../examples/deployment-acceptance/profile.example.json). Its repository ID, rollback reference and policy hashes are synthetic placeholders. Replace them with the actual trusted host's values; a profile copied unchanged is not an accepted deployment. Keep the profile with project-owned reviewable configuration, and keep keys, certificates and approval credentials in the private trusted host.

## Profile contract

The JSON has `schemaVersion: 1`, `kind: "deployment-acceptance-profile"` and the exact fields shown in the example. `profileName` labels this acceptance case; `repositoryId`, `environment`, `target` and `component` bind its scope. The five policy hashes pin the runtime, execution, verification, history store and gateway policies. Changes to any of them require a new assessment. `rollbackRef` names the intended authenticated historical target; it is not itself proof that an image or historical record is present and recoverable.

This initial profile fixes `platform: "linux"`, `adapter: "docker"`, `state: "stateless"`, `readOnly: true` and `mounts: []`. `allowInterruption: true` acknowledges that the fixed replacement stops and removes the old container before starting the new one. It does not promise a maximum outage or stable service address. `requireHealth` and `requireSmoke` must both be true; the target needs configured read-only health and business checks. See [execution](DEPLOYMENT-EXECUTION.md) and [verification](DEPLOYMENT-VERIFICATION.md) for their actual guarantees.

The profile does not add a new command runner, Docker endpoint, image source, storage adapter or approval route. Any configuration outside this bounded shape must be reported unsupported or blocked rather than silently downgraded. Database migrations, persistent volumes, traffic switching, multiple components, multiple hosts and Windows Docker execution require separate contracts and validation.

## Evidence and decisions

An assessment should bind every item to the profile identity and its exact host scope. Record a source class, digest or reference, observed result and reason for each decision. Use `verified`, `unknown`, `blocked` and `not-applicable` distinctly: missing or user-supplied JSON is `unknown`; a concrete mismatch or unsafe state is `blocked`. Historical reports remain useful audit records but do not grant authority for a later run.

The required evidence is a current trusted runtime observation; policy and component match; a fresh, separately approved deployment request and actual execution outcome; real health and business responses; a separately approved rollback and its checks; recovery behavior after a supported interruption; and authenticated history maintenance where the profile relies on retained history. A doctor pass checks host configuration and selected read-only observations, but does not verify deployment or grant an execution permit. A signed archive backs up **deployment history metadata**, not application data or databases.

The GitHub protected-environment approval for deployment cannot be reused for rollback or recovery. Each action needs its own fresh exact request, OIDC verification and one-time authorization. Synthetic approvals in CI prove software behavior only; they must be labeled synthetic and must not satisfy the real-approval item. Keep real run links, commit identities, approval environment and observed results in the validation record. If an action has already written to Docker and its result is unknown, stop normal execution and reconcile the actual host state before making another claim or request.

For a project to cite a scoped acceptance report, the required items must be verified by the trusted host and the tested scope must match the intended one. The report does not itself trigger deploy, rollback or recovery. An accepted staging run cannot be promoted into a production authorization. Follow [trusted host setup](DEPLOYMENT-HOST.md), [authorization](DEPLOYMENT-GOVERNANCE.md), [recovery](DEPLOYMENT-RECOVERY.md) and [history maintenance](DEPLOYMENT-MAINTENANCE.md) for the underlying boundaries.
