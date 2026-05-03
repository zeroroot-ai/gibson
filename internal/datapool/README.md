# `internal/datapool` — Per-tenant data store patterns

Every per-tenant store follows one of **two** patterns. Pick the right one
before writing code; the rest is a checklist.

The `Pool` interface (`pool.go`) does not change between patterns. Handlers
call `Pool.For(tenant) -> Conn` then `Conn.Postgres() / Redis() / Neo4j() /
Vector()`. Pattern choice is invisible above the resolver layer.

Credential rules (admin vs. per-tenant) live in
[`/core/gibson/docs/secrets.md`](../../docs/secrets.md) — read that first.

---

## Pattern A — DB-per-tenant on a shared instance

**One** cluster, **many** logical databases. The tenant-operator issues
`CREATE DATABASE` (Redis: logical DB index allocation) on onboard. The daemon
connects with admin credentials and routes per-tenant.

Use Pattern A whenever the engine supports multi-DB at a price you'll pay.
Cheapest operationally — one cluster to backup, monitor, upgrade, patch.

**Worked examples:**
- Postgres — `pgxpool_per_tenant.go`
- Redis (logical-DB index) — `redis_per_tenant.go`
- Vector / Qdrant (deferred) — `vectordb/doc.go`

### 8-step add-a-store flow

1. **Config struct.** Add `Tenant<X>Config` to `internal/config/config.go`
   with admin host, port, database, username, password, ssl mode.
2. **Loader env-interpolation.** Extend the env block in
   `internal/config/loader.go` so `${...}` resolves at startup. Admin
   password env-injected from a K8s Secret — never plaintext in a ConfigMap.
3. **Per-tenant impl.** Add `<store>_per_tenant.go` exposing
   `For(tenant) -> *<store>Client`. Cache one client per tenant, derive the
   per-tenant DB name from `auth.TenantID`, return `NotProvisionedError`
   when the tenant DB does not exist (fail-closed, no implicit creation).
4. **Wire into pool.** Construct in `pool_impl.go:NewPool`; surface via
   `Conn.<X>()`.
5. **Bootstrap guard.** In `internal/daemon/daemon.go` validate that
   `Tenant<X>Config` is populated when the feature is enabled.
6. **Tenant-operator provisioner.** Add `Provision` / `Deprovision` under
   `enterprise/platform/tenant-operator/internal/dataplane/<store>.go`
   that issues the `CREATE DATABASE` and writes any per-tenant credentials
   to the tenant's Vault namespace. Idempotent.
7. **Chart subchart + values.** Add `tenant-<store>:` subchart; expose
   `dataPlane.<store>.adminY` values. Admin password via
   `valueFrom.secretKeyRef`.
8. **Validator.** Extend `validateTenantStoresConfigured` in
   `enterprise/deploy/helm/gibson/templates/_validators.tpl`.

---

## Pattern B — Instance-per-tenant

**N** clusters, one per tenant. The tenant-operator deploys a `StatefulSet +
Service + PVC + Secret` per tenant. The daemon does not know the URI at
compile time — an `EndpointResolver` looks it up at request time; the daemon
caches one driver per tenant.

Use Pattern B when the engine paywalls multi-DB **and** fleet size is small
enough that per-instance overhead is tolerable. The only existing example is
**Neo4j Community** (`neo4j_per_tenant.go`) — Community is hard-capped at one
user database per instance.

Per-tenant credentials live in the tenant's **Vault namespace**, NOT in K8s
Secrets surfaced to the daemon. The daemon's secrets broker
(`internal/secrets/service.go`) reads `infra/<store>/{username,password}`
from the per-tenant Vault namespace at resolve time.

### 9-step add-a-store flow

1. **Config struct.** Same as Pattern A. Add a `TenantMode` enum if the same
   code path should support a future migration to Pattern A.
2. **Loader env-interpolation.** Same as Pattern A.
3. **EndpointResolver.** Add `<store>_endpoint_resolver.go` defining
   `Resolve(ctx, tenant) -> *<X>Endpoint, error` plus **two** impls — an
   `instanceResolver` (active) and a `multiDBResolver` (stub, built and
   unit-tested so a future Pattern A migration is a config flip, not new
   development). See `neo4j_endpoint_resolver.go` and the two
   `_instance` / `_multidb` files alongside it.
4. **Per-tenant client.** Add `<store>_per_tenant.go` holding a
   `map[auth.TenantID]<driver>` cache; call the resolver on first use, open
   and cache the driver lazily.
5. **Wire into pool.** Same as Pattern A — construct in
   `pool_impl.go:NewPool` with the resolver injected.
6. **Tenant-operator provisioner.** Deploys per-tenant StatefulSet +
   Service + PVC + Secret cloned from a chart-managed template ConfigMap.
   Writes credentials to the per-tenant Vault namespace. Writes the URI +
   tier to the daemon-side `tenant_<x>_endpoints` registry table (URI only
   — credentials are NOT in the registry).
7. **Chart template.** Ship a `tenant-<store>-template:` ConfigMap the
   operator clones from. Tier-aware resource requests/limits.
8. **Validator.** Same as Pattern A.
9. **Migration doc.** Document Pattern B → Pattern A migration. See
   [`MIGRATION-NEO4J.md`](./MIGRATION-NEO4J.md) as the worked example.

---

## Decision tree — when to migrate Pattern B → Pattern A

| Condition | Decision |
|---|---|
| Fleet **< 75 tenants** AND no Enterprise license | **Stay on B** — per-instance Community is cheaper |
| Fleet **75-100 tenants** OR Enterprise license already procured | **Migrate to A** — Enterprise multi-DB wins on infra + ops |
| Enterprise license **>= $80k/yr** AND fleet revenue insufficient | **Stay on B** — license dominates the per-instance bill |
| Operator burden of N StatefulSets exceeds team tolerance | **Migrate to A** regardless of fleet size |

Crossover for Neo4j sits around 75-100 tenants; revisit at fleet size 75.
Runbook: [`MIGRATION-NEO4J.md`](./MIGRATION-NEO4J.md) — five steps,
config-swap + per-tenant export/import, no code rewrite.
