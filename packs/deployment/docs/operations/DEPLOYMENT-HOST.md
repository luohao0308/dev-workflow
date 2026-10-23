# Trusted host configuration and diagnosis

These distribution-only tools help configure and inspect a trusted deployment host. They do not install host credentials into a candidate checkout, initialize execution authority, deploy containers, or grant approval. Run them from a separately trusted, pinned dev-workflow distribution. Do not run a candidate's copy of the scripts as a trusted host.

Start with [`examples/deployment-host/host.example.json`](../../../../examples/deployment-host/host.example.json) and its [usage guide](../../../../examples/deployment-host/USAGE.md). The values are synthetic fixtures, including the catalog, specifications, certificates, identities and commit hashes. Replace them for the intended host; the example is not a ready deployment configuration.

## Configuration contract

The JSON has `schemaVersion: 1` and exactly the following sections and paths. Unknown fields and duplicate keys are rejected. Policy sections use the existing Python policy field names.

| Field | Purpose |
| --- | --- |
| `runtime` | Pinned reader endpoint and certificate, daemon, repository, environment, target, project, component set, freshness limits, catalog and specifications |
| `store` | Repository ID and history store/key IDs; the loader supplies the configured runtime policy |
| `gate` | Writer gate/key IDs, target scope hash and writer certificate pin |
| `execution` | Writer pin, time limits and history/gateway/verification policy hashes; the loader supplies runtime policy |
| `probe` | Optional probe policy, or `null` |
| `github` | Host and ledger repository identities, pinned workflow/ledger commits, workflow/run metadata, reviewers, expiration, three approval environments, and explicit `credential_file` |
| `distribution_commit` | Expected commit of the trusted distribution |
| `candidate_root` | Candidate checkout boundary |
| `store_root`, `gate_root` | Separate private host storage roots |
| `store_key_file`, `gate_key_file` | Explicit private HMAC key files, at least 32 bytes each |
| `ca_file`, `reader_cert_file`, `reader_key_file` | Reader mTLS trust and client credentials |
| `writer_cert_file`, `writer_key_file` | Separate writer client credentials |

`runtime.components` is an array. Catalog, specification and probe documents use the policy's JSON-string fields. Recalculate policy hashes with the actual policy `identity_hash()` methods after edits. The gate scope hash is `deployment_runtime.digest(store_policy._scope())`. Store and gate use matching logical `store_id` and `key_id` within a host; their separately provisioned key bytes may differ. Do not copy hashes from the example into a different host. Raw specification environment values can be sensitive; protect the configuration itself.

Paths must be absolute, without `..`, symbolic-link ancestors or Windows reparse traversal. Keep host storage and secret files outside candidate and distribution checkouts; storage roots must not overlap. On POSIX provision private host-owned directories and files (0700 and 0600). Backups also contain sensitive historical metadata and require private storage. Loaders do not discover credentials from environment variables or execute configurable imports. Source storage directories may be absent when independently verifying an archive.

## Doctor

```sh
python3 -I /trusted/dev-workflow/scripts/deployment_host_doctor.py --config /srv/private/host.json --json
python3 -I /trusted/dev-workflow/scripts/deployment_host_doctor.py --config /srv/private/host.json --online --json
```

Offline diagnosis checks locally available configuration, private credentials, distribution identity/integrity and TLS loadability. It performs no network requests, store/gate initialization or authority issuance. Runtime and GitHub evidence remains `unknown`, so a valid offline report normally exits 2. Loading matching TLS files does not prove certificate chain acceptance, expiry or peer identity.

`--online` adds bounded read-only GET observations against the configured pinned runtime reader and fixed `api.github.com` endpoints. It observes repository/commit identities and host approval-environment reviewer policies. It does not send Docker write requests, approve deployments or issue OIDC. Unavailable or inconclusive evidence remains unknown. Remove ambient `SSLKEYLOGFILE` before online diagnosis: the tool refuses that output configuration. Encrypted TLS keys are rejected without an interactive password prompt.

Reports contain `schemaVersion`, `status`, individual `checks`, and `productionReady:false`. Exit 0 means the performed required checks passed, 1 means a failure, and 2 means incomplete evidence. Even a passing online report grants no authority; fresh runtime observation, fresh OIDC and independent execution approval remain required.

## SDK and platform boundary

`load_host_config(path)` returns a typed immutable policy bundle without constructing a live store or gate. Hosts embedding SDK classes own credential provisioning, trusted imports, private storage and runtime lifecycle. Maintenance backup/verify read only the store key; restore reads both store keys. Only rotation commands read both store and gate keys for each host. The CLI is an operational configuration/diagnostic surface, not a general adapter loader.

On Windows the private-file reader cannot prove private ACLs, so it fails closed with `private-acl-unverified`; doctor reports unknown and exits 2, and maintenance reports incomplete and exits 2. A Windows invocation uses the same arguments:

```powershell
python -I C:\trusted\dev-workflow\scripts\deployment_host_doctor.py --config C:\host-private\host.json --json
```

The SDK's filesystem support requires the embedding host to establish equivalent private ACLs. That condition does not establish Windows Docker runtime execution support. Consult recorded platform validation rather than treating filesystem tests as deployment certification.

See [history maintenance](DEPLOYMENT-MAINTENANCE.md) for backup, restore and authority retirement.
