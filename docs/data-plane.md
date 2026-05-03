# data-plane.md — Gibson daemon

Per-tenant data-plane reference for AI agents editing the daemon.
Spec: `.spec-workflow/specs/database-per-tenant-data-plane/`.

## What this is

The daemon's data plane is **physically isolated per tenant** across four
storage backends: a Postgres database, a dedicated Neo4j instance, a Redis logical
DB, and a vector-store collection — one of each per tenant. The chokepoint API is
`Pool.For(ctx, tenant) → *Conn` defined in
[`internal/datapool/pool.go:102`](../internal/datapool/pool.go) and
[`internal/datapool/conn.go:28`](../internal/datapool/conn.go). Every
storage operation in the daemon goes through a `Conn`. Forgetting to scope a
query is structurally impossible because the connection itself is the tenant
boundary — there is no `tenant_id` column, no `WHERE tenant_id = ?` clause,
and no `tenant:` key prefix anywhere in normal handler code.

## Architecture at a glance

```
                       ┌────────────────────────────────────────────┐
   gRPC handler ──▶    │    auth.TenantFromContext(ctx)             │
   (tenant on ctx)     │              │                             │
                       │              ▼                             │
                       │    pool.For(ctx, tenant)                   │
                       │   internal/datapool/pool_impl.go           │
                       └──────────────┬─────────────────────────────┘
                                      │ (lazy init + KEK derivation)
                                      ▼
                       ┌────────────────────────────────────────────┐
                       │   *Conn (internal/datapool/conn.go)        │
                       │     .Tenant   auth.TenantID                │
                       │     .Postgres *pgxpool.Pool   ──▶ tenant_<id> DB
                       │     .Redis    *redis.Client   ──▶ logical DB N
                       │     .Neo4j    SessionWith…    ──▶ tenant_<id>-neo4j-0
                       │     .Vector   vectordb.Client ──▶ tenant_<id> coll.
                       │     .KEK      []byte (HKDF, 32B, ephemeral)
                       └──────────────┬─────────────────────────────┘
                                      │ defer conn.Release()
                                      ▼
                       ┌────────────────────────────────────────────┐
                       │ connRelease (conn_release.go)              │
                       │   1. zero KEK bytes                        │
                       │   2. close session, return pool slot       │
                       │   3. mark tenant pool eligible for evict   │
                       └────────────────────────────────────────────┘
```

Cross-tenant access (billing, fleet metrics) does NOT go through `Pool.For`.
It goes through `Pool.Admin(ctx) → *AdminConn`, which is delegated to
`internal/datapool/admin/AdminPool.Acquire`. See [Admin pool](#admin-pool).

## The Conn pattern

Every handler that touches storage looks like this:

```go
func (s *server) ListMissions(ctx context.Context, req *pb.Req) (*pb.Resp, error) {
    tenant, err := auth.TenantFromContext(ctx)
    if err != nil {
        return nil, status.Error(codes.Unauthenticated, "no tenant on context")
    }

    conn, err := s.pool.For(ctx, tenant)
    if err != nil {
        var notProv *datapool.NotProvisionedError
        if errors.As(err, &notProv) {
            return nil, status.Error(codes.NotFound, notProv.Error())
        }
        return nil, status.Errorf(codes.Internal, "data plane: %v", err)
    }
    defer conn.Release()

    // From here on: ordinary database code. No tenant filter, no key prefix.
    ids, err := conn.Missions().ListDefinitionNames(ctx)
    // ...
}
```

Long-lived streaming RPCs hold the `Conn` for the duration of the stream. The
evictor will not tear down a tenant's sub-pools while any `Conn` is checked
out. Always `defer conn.Release()` — the release path zeros the KEK; skipping
it is a security regression.

Method receivers on `Conn` (e.g. `*MissionOps`) live in
[`internal/datapool/conn_ops_*.go`](../internal/datapool/). Add new operations
there — see [`how-to-add-a-store-operation.md`](./how-to-add-a-store-operation.md).

## Per-tenant KEK

Every `Conn` carries a 32-byte per-tenant key encryption key on
`Conn.KEK`. Derivation is HKDF-SHA256 against the master KEK held by the
configured `KeyProvider` (k8s/Vault/AWS/Azure/GCP):

```
KEK_tenant = HKDF-SHA256(masterKEK,
                         salt = tenant.String(),
                         info = "gibson/v1/tenant-kek",
                         L    = 32 bytes)
```

Implementation: [`internal/datapool/kek.go:41`](../internal/datapool/kek.go),
constants `kekInfo` and `kekLen` are versioned via the `info` string —
changing them invalidates every wrapped DEK in storage. Don't.

The KEK is **ephemeral**: it lives only for the lifetime of one `Conn` and is
zeroed in [`internal/datapool/conn_release.go:25`](../internal/datapool/conn_release.go).
It is never written to disk, never logged, and never forwarded outside the
daemon process. `slog.LogValue` redaction is not enough — the byte slice is
wiped at the source.

The tenant-operator derives the same KEK independently
([`tenant-operator/internal/dataplane/kek.go:50`](../../../enterprise/platform/tenant-operator/internal/dataplane/kek.go))
to set the per-tenant Postgres role password. The shared `info` string
`"gibson/v1/tenant-kek"` is the contract.

## Envelope encryption

Anything secret-shaped (BYOK LLM keys, customer credentials, mission outputs
flagged sensitive) is stored as an envelope, never as plaintext. The envelope
package is [`internal/datapool/envelope/envelope.go`](../internal/datapool/envelope/envelope.go):

```go
ciphertext, err := envelope.Encrypt(conn.KEK, plaintext, aad)
// ...
plaintext, err := envelope.Decrypt(conn.KEK, ciphertext, aad)
if envelope.IsCrossTenantDecryptError(err) {
    metrics.IncCrossTenantDecrypt(conn.Tenant)
    return nil, status.Error(codes.Internal, "internal error")
}
```

Wire format (40+12+2+|aad|+|ct| bytes):
`wrapped_dek (40B) || nonce (12B) || aad_len (2B) || aad || ciphertext_with_tag`.

**AAD must bind the record to its context** — record type plus identifier.
Example: `aad = []byte("credentials:" + name)`. Without AAD a row could be
moved between tables or renamed and the decryption would still succeed; with
AAD any tampering surfaces as `ErrDecrypt`.

`IsCrossTenantDecryptError` is the structural defense in depth: if a bug ever
returns the wrong tenant's ciphertext, AES-Unwrap fails because the wrapped
DEK was wrapped under a different KEK. The DAO layer increments the
`gibson_xtenant_decrypt_attempt_total{tenant=...}` metric and returns a generic
internal error to the caller. Page on the metric.

## Admin pool

Cross-tenant access (billing aggregation, fleet metrics, capacity planning,
the migration runner) uses the admin pool. Code lives **exclusively** in
`internal/admin/` and `internal/datapool/admin/`. The
[`admin_pool_acquire`](../tools/gibsoncheck/checks/admin_pool_acquire.go) gibsoncheck
analyzer fails the build if any other package imports
`github.com/zero-day-ai/gibson/internal/datapool/admin`.

```go
adminConn, err := pool.Admin(ctx)  // delegates to admin.AdminPool.Acquire
if err != nil { return err }
defer adminConn.Release()

// Iterate all tenants:
err = admin.ForEachTenant(ctx, adminConn, lister, tenantPool,
    func(tenant auth.TenantID, tc *datapool.Conn) error {
        // tc.Postgres, tc.Redis, tc.Neo4j, tc.Vector are tenant-bound
        return nil
    })
```

Acquisition does three things in
[`internal/datapool/admin/admin_pool.go:195`](../internal/datapool/admin/admin_pool.go):

1. Resolves the calling identity via `auth.IdentityFromContext`.
2. Calls `fgaClient.Check(user:<subject>, platform_operator, system_tenant:_system)` — denial returns `ErrUnauthorizedAdmin`.
3. Emits an audit event (`AuditEmitter.EmitAdminAcquire`) and increments `gibson_admin_pool_acquire_total{rpc, subject}`.

The admin Postgres pool uses an admin role with `CONNECT` on every
`tenant_*` database. The admin Redis client is bound to db 0 (the master
index that maps tenant IDs to logical DB indices). Neither is reachable
from non-admin code.

## Provisioning

The daemon does **not** provision tenant data planes. The
[`gibson-tenant-operator`](../../../enterprise/platform/tenant-operator/) owns
the lifecycle: it creates the per-tenant Postgres database, role, dedicated
Neo4j StatefulSet, Redis logical-DB allocation, and Qdrant collection. Every
tenant gets its own `tenant-<id>-neo4j-0` pod at onboarding — there is no
shared Neo4j cluster; the daemon resolves per-tenant Neo4j sessions
exclusively via `Pool.For(tenant).Neo4j()`. See
[`../../../enterprise/platform/tenant-operator/docs/data-plane.md`](../../../enterprise/platform/tenant-operator/docs/data-plane.md).

The daemon is a **read-consumer of provisioning state**. Before returning a
`Conn`, `pool.For` calls
[`provisioningChecker.isProvisioned`](../internal/datapool/provisioning_check.go)
which queries the `Tenant` CRD's `status.dataPlane.ready` field via a
Kubernetes dynamic client. The result is cached for 30 s (configurable). If
the tenant CRD is missing, the field is absent, or the API call fails, the
checker fails closed with `*NotProvisionedError`. Handlers translate that to
gRPC `codes.NotFound`.

The check uses unstructured access (GVR `gibson.io/v1alpha1/tenants`) rather
than importing the tenant-operator's typed API to avoid a cyclic dependency
([`provisioning_check.go:22`](../internal/datapool/provisioning_check.go)).

## Migration runner

[`cmd/gibson-migrate`](../cmd/gibson-migrate/main.go) is the standalone CLI
for applying schema migrations across all provisioned tenant databases. It
enumerates tenants via the Tenant CRD list and iterates through each tenant's
Postgres DB and Neo4j DB, applying pending migrations.

Subcommands:

```
gibson-migrate up [--all|--tenant <id>] [--store postgres|neo4j|all] [--dry-run]
gibson-migrate status [--all|--tenant <id>]
gibson-migrate down --tenant <id> --to <migration_id> --confirm
```

Migration files:

- Postgres: [`migrations/postgres/`](../migrations/postgres/) (`*.up.sql` /
  `*.down.sql`, golang-migrate format).
- Neo4j: [`migrations/neo4j/`](../migrations/neo4j/) (`*.up.cypher` files
  applied in filename-sorted order).

**Daemon startup behaviour**: on first `Pool.For` for a given tenant, the
daemon checks the tenant's migration version. If the tenant's schema is behind
the embedded latest version, the daemon applies pending non-destructive
migrations before serving traffic for that tenant. Destructive migrations
require `gibson-migrate up --allow-destructive` from a human operator.

The runner uses the admin pool for tenant enumeration; the
[`forbid_raw_store_imports`](../tools/gibsoncheck/checks/forbid_raw_store_imports.go)
analyzer allowlists `cmd/gibson-migrate/` for raw pgx and neo4j-go-driver
imports.

## Per-tenant intelligence + drift detection

Spec: `graphrag-intelligence-tenant-scope` (closes the last shared-Neo4j coupling
points after `graphrag-tenant-scope`).

Three cross-mission consumers route through `pool.For(tenant).Neo4j()` rather
than a shared cluster: the IntelligenceService gRPC handlers
([`internal/daemon/intelligence_service.go`](../internal/daemon/intelligence_service.go),
five RPCs — `GetRecurringVulnerabilities`, `GetRemediationMetrics`,
`GetAssetRiskScore`, `GetAttackPatterns`, `GetSimilarTargets` — each
constructs a per-tenant `*graph.SessionGraphClient` per call); the startup
migration drift gate
([`internal/daemon/startup_migration_check.go`](../internal/daemon/startup_migration_check.go),
which iterates tenants via the Tenant CRD list with a worker-pool of
configurable concurrency, default 4, max 16, total deadline 30 s, surfacing
drift as `gibson_tenant_neo4j_migration_drift{tenant}`); and the orchestrator
Observer's graph-intelligence enrichment
([`internal/orchestrator/adapter.go`](../internal/orchestrator/adapter.go),
which dispatches through the `graph.GraphClient` interface — both
`*Neo4jClient` and `*SessionGraphClient` implement `ExecuteRead`/`ExecuteWrite`
— so the per-tenant session is the production path with no type-assertion
fallback). All three follow Pattern B per-call construction.

## Mission / finding / run stores — per-tenant cutover complete

Spec: `daemon-mission-finding-per-tenant-cutover` (2026-04-26).

**All three handler subsystems are now per-tenant.** Every mission, mission-run,
and finding RPC acquires a `Conn` from the pool and uses `conn.Missions()`,
`conn.Redis` (for run-event streams), and `conn.Findings()`. The process-wide
`NewRedisMissionStore`, `NewRedisMissionRunStore`, and `NewRedisFindingStore`
constructors are **deleted** from the codebase. Audit findings C6, C9, C14, C15
are now structurally closed.

Before this spec, three subsystems remained on the legacy global-Redis path:

| Subsystem | Old path | New path |
|---|---|---|
| Mission CRUD (Create, Get, List, Update) | `RedisMissionStore` (global) | `ConnBoundMissionStore(conn.Redis)` per RPC |
| Mission-run / event streams | `RedisMissionRunStore` (global) | `ConnBoundRunStore(conn.Redis)` per RPC |
| Finding store (Submit, Get, List) | `RedisFindingStore` (global) | `ConnBoundFindingStore(conn.Redis)` per RPC |

For operators: run the `legacy-mission-finding-cleanup` Helm hook with
`upgrade.cleanupLegacyMissionFinding=true` to delete orphaned keys from the
shared Redis from before the cutover. The Job ships in the chart and defaults
to scan-only on `helm upgrade`.

## Build guards

All guards live in [`tools/gibsoncheck/checks/`](../tools/gibsoncheck/checks/)
unless noted. They run as part of `make check` / `make lint`. Adding a guard
violation to a PR fails CI.

| Guard | File | What it forbids |
|---|---|---|
| `forbidrawstoreimports` | [`forbid_raw_store_imports.go`](../tools/gibsoncheck/checks/forbid_raw_store_imports.go) | `pgx`, `go-redis`, `neo4j-go-driver`, `qdrant`, `miniredis` imports outside `internal/datapool/`, `internal/admin/`, `internal/migrate/`, `cmd/gibson-migrate/`, `cmd/daemon/`, `internal/daemon/`, `tools/gibsoncheck/`. Test files may import miniredis. |
| `forbidrediskeyprefix` | [`forbid_redis_key_prefix.go`](../tools/gibsoncheck/checks/forbid_redis_key_prefix.go) | String literals starting with `tenant:`, `gibson:tenant:`, or `<word>:tenant:` passed to `*redis.Client` methods. The per-tenant client is already DB-scoped; prefixes are dead. |
| `forbidredisclientconstruction` | [`forbid_redis_client_construction.go`](../tools/gibsoncheck/checks/forbid_redis_client_construction.go) | `redis.NewClient(...)` calls outside `internal/datapool/` and `internal/admin/`. All Redis access must go through `Conn.Redis`. Test files exempt. Spec: daemon-mission-finding-per-tenant-cutover Req 5.3. |
| `adminpoolacquire` | [`admin_pool_acquire.go`](../tools/gibsoncheck/checks/admin_pool_acquire.go) | Importing `internal/datapool/admin` from anywhere outside `internal/admin/`, `internal/datapool/admin/`, `internal/migrate/`, `cmd/gibson-migrate/`. CODEOWNERS narrow waist. |
| `forbiddenimports` | [`forbidden_imports.go`](../tools/gibsoncheck/checks/forbidden_imports.go) | (auth-spec) `github.com/zitadel/*`, `github.com/openfga/*` outside the narrow allowlist. |
| check-no-tenant-id-column | [`scripts/check-no-tenant-id-column.sh`](../scripts/check-no-tenant-id-column.sh) | `tenant_id` references in `migrations/postgres/`, `migrations/neo4j/`, and embedded Cypher in Go. |
| check-no-redis-prefix | [`scripts/check-no-redis-prefix.sh`](../scripts/check-no-redis-prefix.sh) | Same as `forbidrediskeyprefix` but as a CI script for environments where the Go analyzer doesn't run. |
| forbid `tenant_id` in Cypher | covered by check-no-tenant-id-column above | `WHERE n.tenant_id` patterns in any `.cypher` or `.go` file. |

## Cross-link

- `auth.TenantID`, `auth.TenantFromContext`, `auth.IdentityFromContext`, and the auth chain that places identity on context are defined by the [`unified-identity-and-authorization`](../../../.spec-workflow/specs/unified-identity-and-authorization/) spec. The SDK type is at [`sdk/auth/tenantid.go`](../../sdk/auth/tenantid.go).
- The provisioner side of this story: [`../../../enterprise/platform/tenant-operator/docs/data-plane.md`](../../../enterprise/platform/tenant-operator/docs/data-plane.md).
- The SDK's (small) data-plane surface: [`../../sdk/docs/data-plane.md`](../../sdk/docs/data-plane.md).
- Forbidden patterns with code examples: [`forbidden-patterns.md`](./forbidden-patterns.md).
- Adding new ops on `Conn`: [`how-to-add-a-store-operation.md`](./how-to-add-a-store-operation.md).
- Machine-readable rules: [`rules.yaml`](./rules.yaml).
