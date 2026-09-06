# data-plane.md — tenant-operator

Per-tenant data-plane reference for AI agents editing the tenant-operator.
Spec: `.spec-workflow/specs/database-per-tenant-data-plane/`.

## What this operator owns

The tenant-operator owns the **lifecycle** of per-tenant data-plane
resources. The Gibson daemon is a read-consumer of provisioning state — it
acquires per-tenant connections through `pool.For(tenant)` and refuses to
serve traffic when the operator has not yet marked the tenant ready.

Concretely the operator owns:

- The `Tenant` CRD (`gibson.zeroroot.ai/v1alpha1.Tenant`) and its `status.dataPlane`
  schema (per-store provisioned flags + an aggregate `ready` bool).
  See [`api/v1alpha1/tenant_types.go`](../api/v1alpha1/tenant_types.go).
- The reconciler that runs the provisioning pipeline on `Pending` and the
  deprovisioning pipeline on deletion.
- A per-store provisioner package at
  [`internal/dataplane/`](../internal/dataplane/), one file per backend:
  - [`postgres.go`](../internal/dataplane/postgres.go) — `CREATE DATABASE`,
    role, password derivation, golang-migrate run.
  - [`neo4j.go`](../internal/dataplane/neo4j.go) — `CREATE DATABASE` against
    the `system` DB, apply `*.up.cypher` constraints/indexes.
  - [`redis.go`](../internal/dataplane/redis.go) — allocate next free logical
    DB index, persist mapping in master index DB 0.
  - [`vector.go`](../internal/dataplane/vector.go) — Qdrant collection
    create via HTTP API.
  - [`kek.go`](../internal/dataplane/kek.go) — HKDF derivation; matches the
    daemon byte-for-byte.
- The pipeline orchestrator at
  [`pipeline.go`](../internal/dataplane/pipeline.go), which runs the five
  steps in order with LIFO rollback on failure.
- Quota application at
  [`quotas.go`](../internal/dataplane/quotas.go) (Postgres CONNECTION LIMIT,
  Redis per-DB MAXMEMORY where supported).
- The standalone backup CLI
  [`cmd/gibson-backup/`](../cmd/gibson-backup/main.go).

## Provisioning order

```
Tenant CRD created
    │  reconcile loop sees Phase = "" / Pending
    ▼
┌──────────────────────────────────────────────────────────────┐
│ pipelineProvisioner.Provision(ctx, tenantID)                 │
│   internal/dataplane/pipeline.go:194                         │
│                                                              │
│   step 1: Postgres   ── CREATE DATABASE tenant_<id>          │
│              │           CREATE ROLE tenant_<id>_role        │
│              │           GRANT CONNECT, USAGE, CRUD          │
│              │           run *.up.sql migrations             │
│              │           ALTER ROLE … CONNECTION LIMIT       │
│              ▼                                               │
│   step 2: Neo4j      ── on system DB:                        │
│              │             CREATE DATABASE tenant_<id>       │
│              │           on tenant DB:                       │
│              │             apply *.up.cypher                 │
│              ▼                                               │
│   step 3: Redis      ── HSETNX tenant_db_index <id> N        │
│              │           verify DB N is empty                │
│              ▼                                               │
│   step 4: Vector     ── Qdrant PUT /collections/tenant_<id>  │
│              │                                               │
│              ▼                                               │
│   step 5: KEKInit    ── derive HKDF, sanity-check KMS        │
│              │           (pwd already baked into pg role)    │
│              ▼                                               │
│   status.dataPlane.ready = true, Phase = Active              │
└──────────────────────────────────────────────────────────────┘

  any step fails  →  rollback completed steps in LIFO order,
                     status.dataPlane.Phase = Failed,
                     status.dataPlane.LastError = <reason>
```

Each step is idempotent: re-running on a partially-provisioned tenant
detects existing resources and skips. The orchestrator emits Kubernetes
events (`StepStarted` / `StepSucceeded` / `StepFailed` / `RollbackStep`) on
the Tenant object for audit and debugging.

Deprovision runs steps in reverse: KEKInit → Vector → Redis → Neo4j →
Postgres. KEKInit's Rollback is a no-op (nothing persistent). Postgres uses
`DROP DATABASE … WITH (FORCE)` (Postgres 13+) with a fallback for older
servers.

## Per-tenant KEK

The operator's KEK derivation MUST match the daemon's byte-for-byte:

```
KEK_tenant = HKDF-SHA256(masterKEK,
                         salt = tenantID (UTF-8),
                         info = "gibson/v1/tenant-kek",
                         L    = 32 bytes)
```

Source of truth: [`internal/dataplane/kek.go:50`](../internal/dataplane/kek.go).
The daemon's matching implementation is at
[`../../../core/gibson/internal/infra/datapool/kek.go:41`](../../../core/gibson/internal/infra/datapool/kek.go).
The shared `info` string is the contract — changing it on either side
without coordinated KEK rotation breaks every encrypted record.

The operator uses the KEK to set the **Postgres role password**:

```
password = hex(KEK_tenant)[:32]
```

See [`tenantRolePassword` in `kek.go:66`](../internal/dataplane/kek.go) and
its caller in [`postgres.go:106`](../internal/dataplane/postgres.go). The
daemon reconstructs the same password at connection time from `masterKEK +
tenantID` — neither the password nor the KEK is persisted as a Kubernetes
Secret. Rotation is supported via `ALTER ROLE … PASSWORD` re-run on the
existing role.

The KEK is zeroed in a `defer` immediately after the password is extracted
([`kek.go:72`](../internal/dataplane/kek.go)). Never log it. Never include
it in a CRD field.

## Backup CLI

[`cmd/gibson-backup/main.go`](../cmd/gibson-backup/main.go) is the standalone
per-tenant backup tool. It encrypts each backup blob with a fresh DEK
wrapped by the tenant KEK and writes the manifest to S3-compatible storage.

Subcommands:

```
gibson-backup create   --tenant <id> [--store all|postgres|neo4j|redis|vector] [--note ...]
gibson-backup list     [--tenant <id>] [--limit N]
gibson-backup restore  --tenant <id> --backup-id <id> [--store ...] [--target-tenant <id>] [--confirm]
gibson-backup verify   --tenant <id> --backup-id <id>
```

Configuration is via environment variables (see the file's package comment
for the full list); `MASTER_KEK` is required so the tool can derive the
tenant KEK and unwrap stored DEKs. Restore supports `--target-tenant` for
copy-to-new-tenant flows; the source ciphertext is decrypted with the
source KEK and re-encrypted under the destination KEK before writing.

## Cross-link

- The consumer (daemon) side: [`../../../core/gibson/docs/data-plane.md`](../../../core/gibson/docs/data-plane.md).
- The SDK's (small) data-plane surface: [`../../../core/sdk/docs/data-plane.md`](../../../core/sdk/docs/data-plane.md).
- The auth model that places the calling tenant on context (`auth.TenantID`,
  `auth.TenantFromContext`) is owned by the [`unified-identity-and-authorization`](../../../.spec-workflow/specs/unified-identity-and-authorization/)
  spec.
- Forbidden patterns with code examples: [`forbidden-patterns.md`](./forbidden-patterns.md).
- Machine-readable rules: [`rules.yaml`](./rules.yaml).
