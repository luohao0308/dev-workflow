# Explicit trusted host configuration

Copy `host.example.json` outside the candidate checkout, replace the synthetic runtime catalog, specifications, identities and paths, and restrict the configuration and referenced files to the host account (0600 on POSIX). Paths must be absolute and contain no symbolic-link ancestors. The JSON never selects executable code or a distribution directory. Run the scripts from a separately pinned trusted distribution with isolated Python:

```sh
python3 -I /trusted/dev-workflow/scripts/deployment_host_doctor.py --config /srv/private/host.json --json
python3 -I /trusted/dev-workflow/scripts/deployment_host_doctor.py --config /srv/private/host.json --online --json
```

Policy sections use the existing Python policy field names. `runtime.components` is an array; embedded catalog/specification/probe documents are canonical JSON strings. `store` and `execution` omit their runtime_policy field because the loader binds the single configured runtime. Hashes must be recomputed using policy identity_hash methods after any change; gate scope_hash is deployment_runtime.digest(store_policy._scope()).

Offline checks do not create stores, gates, ledgers, authority, TLS logs or network connections. Online adds only bounded GET observations of the pinned runtime daemon and fixed api.github.com repository/environment. TLS loading is not peer/expiry proof. Fresh OIDC and actual execution approval remain execution-time requirements. Windows private ACL validation is unavailable and private reads fail closed. Distribution checks verify the configured HEAD and source integrity. GitHub checks observe host/target/ledger repository identities and the independent host approval environments. Exit codes: 0 proven checks, 1 invalid inputs, 2 incomplete evidence. productionReady is always false. No deployment, initialization or approval action is available through this CLI.

The checked-in example contains synthetic, internally consistent policy hashes. Store and gate use the same logical `store_id` and `key_id`; their private key files may contain different key bytes. After editing runtime/catalog/specification or host identity, recompute hashes in this order from the trusted distribution API:

```python
from deployment_host_config import RuntimePolicy, StorePolicy, GatePolicy, ProbePolicy, digest
r = dict(document['runtime'])
r['components'] = tuple(r['components'])
runtime = RuntimePolicy(**r)
store = StorePolicy(runtime_policy=runtime, **document['store'])
document['gate'].update(store_id=store.store_id, key_id=store.key_id,
                        scope_hash=digest(store._scope()))
gate = GatePolicy(**document['gate'])
probe = None
if document['probe'] is not None:
    document['probe']['runtime_policy_hash'] = runtime.identity_hash()
    probe = ProbePolicy(**document['probe'])
document['execution'].update(
    history_policy_hash=store.identity_hash(),
    gateway_policy_hash=gate.identity_hash(),
    verification_policy_hash=probe.identity_hash() if probe else None)
```

Here `document` is the parsed private configuration. Set matching writer certificate pins in `gate` and `execution` before computing these hashes. The loader derives deployment, rollback and recovery host-policy hashes from the resulting exact policies; GitHub fields do not accept caller-supplied replacement policy hashes. This calculation is configuration preparation only and grants no execution authority.
