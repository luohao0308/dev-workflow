# Authenticated history maintenance

Maintenance preserves authenticated historical evidence and can retire a healthy host's authority in favor of a new host generation. It is not general production disaster recovery. An archive contains history, its fixed manifest and source identity; it excludes keys, permits, approval ledgers, live gateway authority, locks and raw environment configuration. Restoring it cannot resume an old execution or restore an approval.

Use the trusted distribution and private configuration described in [host setup](DEPLOYMENT-HOST.md). All commands below emit JSON including `productionReady:false`. Exit 0 indicates the command succeeded, 1 indicates blocked validation, and 2 indicates unverified Windows private ACLs. `--json` is accepted; output is JSON even without it.

## Backup and independent verification

Prepare a private backup parent directory outside candidate, distribution and store/gate roots. The output file must not exist; the tool does not overwrite an earlier backup.

```sh
python3 -I /trusted/dev-workflow/scripts/deployment_host_maintenance.py backup --config /srv/private/source.json --output /srv/private-backups/history.json --json
python3 -I /trusted/dev-workflow/scripts/deployment_host_maintenance.py verify --config /srv/private/source.json --archive /srv/private-backups/history.json --json
```

Verification checks canonical encoding, source identity, manifest completeness, references, signatures, digests, sizes and timestamps. Completeness is relative to the signed manifest; it is not proof that this is the latest backup. Limits are 64 MiB per archive, 8 MiB per history record and 4096 entries. JSON traversal names, duplicate entries/keys, unexpected fields and nonfinite values are rejected.

Trust comes from an independently retained source verification key, never a key in the archive. The pure `deployment_history_archive.verify_archive(raw, source_policy, source_key)` API needs no source directories or initialized store. The CLI loads the full host configuration, but backup and verification read only the configured store key. Restore reads the source and destination store keys; none of these three commands reads gate key files. Keep source store verification keys separately secured from the backup so verification still works after source-directory loss.

## History-only restore

Create a destination configuration with the same target scope, a new store ID, key ID and actual key bytes, plus a new absent store root outside all protected roots. Provision its key files separately. Do not pre-create the destination store directory.

```sh
python3 -I /trusted/dev-workflow/scripts/deployment_host_maintenance.py restore --config /srv/private/source.json --archive /srv/private-backups/history.json --destination-config /srv/private/restored.json --json
```

Restore validates the entire source archive before import. It creates a pending destination, writes destination-signed schema-v2 history records, verifies the records and completed import manifest, then activates history storage. It does not initialize a live writer gate. A failure after pending initialization leaves the partial destination non-issuable; there is no generic restore-resume command. Retrying restore into that existing directory is rejected. Preserve partial evidence and use a distinct new destination for a fresh verified restore rather than deleting maintenance markers.

Imported records retain original observations, capture times and recipe/evidence hashes. Constant-depth provenance records the original and immediate source identity/digest, archive hash and import time. Subsequent `HostStore.load_history` uses the destination key and still requires a fresh collector baseline and compatible catalog/specifications. Old source keys are not needed to read successfully imported history, but are needed to independently verify the original backup. Retain those keys under a separate archival policy before retiring operational access to them.

## Healthy-host rotation

Rotation requires a healthy source: authenticated terminal journals, every gate generation definitively closed/drained, no unresolved admission or unknown write outcome, and no active Core operation. New destination store and gate roots must be absent and separate. Within each host configuration, store and gate share the logical store ID and key ID; their secret key bytes may differ. Configure new successor IDs and new key material that does not reuse either source key; preserve runtime scope and writer transport identity. All three rotation commands read both hosts’ store and gate keys. This is not a certificate or target migration command.

```sh
python3 -I /trusted/dev-workflow/scripts/deployment_host_maintenance.py rotate --config /srv/private/source.json --destination-config /srv/private/successor.json --json
python3 -I /trusted/dev-workflow/scripts/deployment_host_maintenance.py rotation-status --config /srv/private/source.json --destination-config /srv/private/successor.json --json
python3 -I /trusted/dev-workflow/scripts/deployment_host_maintenance.py rotation-resume --config /srv/private/source.json --destination-config /srv/private/successor.json --json
```

The SDK exposes `prepare_rotation(source, destination)`, `rotation_resume(source, destination)`, `rotation_status(source, destination)` and `rotate(source, destination)`. Its inputs are `MaintenanceHost` values with explicit typed configuration and key bytes. The CLI uses those same configured identities and derives the exact transaction from the source’s signed intent. There is no `--transaction`, skip-validation or allow-pending switch. `rotation-status` reports observed phases; it does not grant execution authority or prove that an incomplete transaction can safely resume.

Rotation records an authenticated intent and source inventory, prepares pending destination storage, retires the source gate first, retires the source store next, and activates the destination only after both source retirements and the complete destination inventory are verified. Gate state and permits are not copied or re-signed. The successor gate is new and empty.

A crash between gate and store retirement can leave historical capture possible while execution is already fenced. Any resulting source inventory drift blocks resume. Resume does not overwrite, discard or re-sign drifted records. Resume must match the original transaction, keys, roots, inode bindings and inventory. Changing configuration or selecting an unrelated destination cannot bypass pending retirement.

## Failure diagnosis

The CLI intentionally sanitizes exceptions. Use its actual `code` and retain the original private evidence; do not paste keys, raw specifications or credentials into incident reports.

| CLI code | Check and next safe action |
| --- | --- |
| `private-acl-unverified` | Windows private access cannot be proven by the CLI. Treat exit 2 as incomplete; use a supported verified host or an SDK host that independently establishes ACLs. |
| `private-storage-access-denied`, `maintenance-private-storage-required` | Verify ownership, private file/directory permissions and access using the intended host account. Preserve existing storage identities. |
| `destination-already-exists`, `maintenance-destination-invalid` | A backup output or destination already exists or is unsuitable. Keep partial evidence; select a new output or a new restore destination. For an existing rotation, use exact resume instead of another rotate. |
| `invalid-history-archive`, `history-authentication-failed` | Check that the original unmodified archive, source policy and independently retained source store key belong together. Do not re-sign damaged evidence. |
| `destination-scope-mismatch`, `destination-identity-reused` | Check target scope and provide new destination store/key IDs and actual key bytes before creating a fresh restore destination. |
| `host-path-overlap`, `output-path-overlap`, `destination-path-overlap` | Separate candidate, distribution, host storage and output paths. Do not move an existing rotation's bound directories. |
| `source-store-missing` | Backup needs the live source history directory. If it is lost, verify a retained archive using its original source policy/key instead. |
| `import-verification-failed`, `destination-inventory-mismatch`, `import-manifest-mismatch` | Preserve the pending restore directory and investigate changed or incomplete files. Retry the validated archive only into a distinct new destination. |
| `maintenance-permanently-retired` | Stop using this generation for authority; identify the intended successor. Retirement cannot be undone. |
| `maintenance-state-invalid`, `maintenance-latch-invalid`, `maintenance-storage-identity-changed`, `maintenance-mutex-missing` | Retain markers, locks and transaction evidence. Investigate corruption or replacement; do not remove files to make construction succeed. |
| `maintenance-validation-failed` | An error outside the fixed diagnostic allowlist occurred. Check configuration and required inputs without exposing raw exceptions or credential contents. |

Rotation CLI failures preserve these fixed diagnostic codes; arbitrary exception text is still sanitized.

| Rotation CLI code | Check and next safe action |
| --- | --- |
| `rotation-resume-existing-transaction` | An intent/prepared record already exists. Use status and exact resume with the original configuration pair; do not issue a fresh rotate or delete intent records. |
| `rotation-source-inventory-drift`, `rotation-source-file-replaced` | Source contents or file identities changed after preparation. Preserve the changed records and reconcile the cause; resume never overwrites them. |
| `rotation-destination-record-changed`, `rotation-destination-inventory-changed` | Destination bytes or entries differ from the authenticated prepared inventory. Preserve the pending destination for investigation. |
| `rotation-intent-mismatch`, `rotation-destination-transaction-mismatch` | Verify that configuration, keys and destination belong to the source's signed intent. There is no transaction override option. |
| `rotation-writer-not-drained`, `rotation-unresolved-journal`, `rotation-core-operation-unresolved` | Resolve the existing operation through its normal authenticated recovery path before preparing rotation. Unknown outcomes cannot be treated as completion. |
| `rotation-policy-bindings-mismatch`, `rotation-scope-changed`, `rotation-is-not-transport-migration` | Check matching policy hashes, target/runtime scope and writer transport identity. Rotation cannot migrate scope or certificates. |
| `rotation-new-identities-required`, `rotation-new-key-material-required`, `rotation-gate-key-required` | Supply new successor logical IDs and actual key material, and explicit gate keys for both hosts. Never alter credentials of an already prepared transaction to bypass its identity checks. |
| `rotation-destination-exists`, `rotation-destination-not-owned-pending` | Fresh rotation needs absent destination roots. Existing pending roots must belong to this exact transaction; an unrelated destination is not reusable. |
| `rotation-source-binding-changed`, `rotation-destination-binding-changed`, `rotation-target-lock-changed` | Storage or mutex identity differs. Preserve the original paths and evidence; do not replace locks or reconstruct authority from copied directories. |
| `rotation-record-invalid`, `rotation-prepared-mismatch`, `rotation-prepare-evidence-missing`, `rotation-source-retirement-missing` | Authentication or required durable phase evidence is missing/inconsistent. Keep authority fenced and retain all records for reconciliation. |
| `rotation-historical-recipe-changed`, `rotation-import-manifest-invalid` | Check the trusted catalog/specifications and authenticated import manifest against original evidence. Do not re-sign incompatible history. |

Resume does not repair mismatches by replacing records. Preserve authenticated state and reconcile the underlying cause; never manufacture terminal or quiescence records.

## Pending, retired and unknown states

- `pending`: preserve the exact configuration, keys and filesystem evidence. Public authority construction remains blocked. For a rotation use `rotation-status`, then `rotation-resume` for the same source/destination pair.
- `retired`: permanent authority retirement. Existing objects and newly constructed objects must not issue old authority. There is no unretire command.
- `blocked`, unknown or incomplete evidence: investigate the reported code and authenticated transaction records. Unresolved external outcomes are not evidence of quiescence. Do not infer safety from elapsed time or dead process IDs.
- `complete-successor-retired`: a previously activated successor has itself retired. Resuming the older transaction must not reactivate it or recreate its gate.

Never delete or replace lock files, maintenance markers, transaction records or partial destination records to make validation pass. Preserve evidence for operator reconciliation. A full privileged filesystem rollback is outside the retirement contract. Do not reuse old approvals or permits after restoration or rotation.

On Windows the CLI fails closed when private ACLs cannot be proven; substitute `python -I C:\trusted\dev-workflow\scripts\deployment_host_maintenance.py` and absolute Windows paths for invocation, but do not interpret argument parsing as evidence that maintenance or Docker execution is supported there. SDK users must satisfy the host ACL precondition independently. These instructions describe operation contracts, not a claim that all platform or crash-validation matrices have passed.
