# forbidden-patterns.md — Gibson daemon, data-plane

Companion to [`rules.yaml`](./rules.yaml). For each pattern: the wrong shape
(annotated where possible with a pre-refactor file:line — these were the live
patterns the data-plane spec deleted), and the correct replacement.

Spec: `database-per-tenant-data-plane`.

## DP-001: importing raw store clients outside the data plane

Pre-refactor, every package that talked to Redis imported `go-redis`
directly. After the spec, only the allowlisted data-plane packages may.

Wrong (e.g. pre-refactor `internal/database/credential_dao.go`):

```go
package database

import "github.com/redis/go-redis/v9"

type credentialDAO struct{ rdb *redis.Client }
```

Correct — the Conn is already tenant-bound, the DAO becomes a method receiver:

```go
func (c *Conn) Credentials() *CredentialOps { return &CredentialOps{conn: c} }

func (o *CredentialOps) Get(ctx context.Context, name string) (*Credential, error) {
    // o.conn.Postgres is bound to tenant_<id>; o.conn.KEK is the tenant KEK.
}
```

Allowlist: `internal/datapool/**`, `internal/admin/**`, `internal/migrate/**`,
`cmd/gibson-migrate/**`, `cmd/daemon/**`, `internal/daemon/**`,
`tools/gibsoncheck/**`. Test files may import `miniredis` for fixtures.

## DP-002: missing `defer conn.Release()`

Wrong:

```go
conn, err := s.pool.For(ctx, tenant)
if err != nil { return nil, err }
return doWork(ctx, conn)   // KEK never zeroed; pool slot held forever
```

Correct:

```go
conn, err := s.pool.For(ctx, tenant)
if err != nil { return nil, err }
defer conn.Release()       // zeros KEK + returns slot
return doWork(ctx, conn)
```

For streaming RPCs, the defer goes at the outer Recv loop boundary, not
inside the per-message handler.

## DP-003: `tenant_id` columns and properties

Wrong (pre-refactor `migrations/postgres/003_missions.up.sql`):

```sql
CREATE TABLE missions (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,             -- forbidden
    name TEXT NOT NULL
);
CREATE INDEX missions_by_tenant ON missions(tenant_id);   -- forbidden
```

Correct — the database name is `tenant_<sanitized_id>` so the column is dead
weight:

```sql
CREATE TABLE missions (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL
);
```

Same for Neo4j. Wrong:

```cypher
CREATE CONSTRAINT mission_tenant_id IF NOT EXISTS
  FOR (m:Mission) REQUIRE m.tenant_id IS NOT NULL;     // forbidden
```

Correct (no tenant_id; each tenant has its own Neo4j database):

```cypher
CREATE CONSTRAINT mission_id_unique IF NOT EXISTS
  FOR (m:Mission) REQUIRE m.id IS UNIQUE;
```

## DP-004: `tenant:` Redis key prefixes

Wrong (pre-refactor `internal/state/tenant_scoped_store.go`):

```go
key := fmt.Sprintf("tenant:%s:mission:%s", tenantID, missionID)
err := rdb.Set(ctx, key, payload, 0).Err()
```

Correct — `Conn.Redis` is bound to the tenant's logical DB so the key is
plain:

```go
key := fmt.Sprintf("gibson:mission_run:%s", id)
err := conn.Redis.Set(ctx, key, payload, 0).Err()
```

See [`internal/datapool/conn_ops_mission.go:44`](../internal/datapool/conn_ops_mission.go)
for the canonical key shape.

## DP-005: importing the admin pool from a regular handler

Wrong:

```go
package server   // tenant-handler package

import "github.com/zero-day-ai/gibson/internal/datapool/admin"

func (s *server) ListAllMissions(ctx context.Context, req *pb.Req) (*pb.Resp, error) {
    ap, _ := admin.New(...)            // forbidden
    conn, _ := ap.Acquire(ctx)
    defer conn.Release()
    // ...
}
```

Correct — the cross-tenant query lives in `internal/admin/` (separate
CODEOWNERS narrow waist) and the handler delegates to it:

```go
// internal/admin/billing.go
func (b *BillingService) ListAllMissions(ctx context.Context) (*Report, error) {
    conn, err := b.pool.Admin(ctx)     // FGA-checked, audit-emitted
    if err != nil { return nil, err }
    defer conn.Release()
    return admin.ForEachTenant(ctx, conn, b.lister, b.tenantPool, /* fn */)
}
```

## DP-006: storing a secret without envelope encryption

Wrong:

```go
_, err := conn.Postgres.Exec(ctx,
    "INSERT INTO credentials (name, secret) VALUES ($1, $2)",
    name, plaintext)                   // plaintext at rest is forbidden
```

Correct — encrypt with `Conn.KEK`, AAD bound to the record:

```go
aad := []byte("credentials:" + name)
ct, err := envelope.Encrypt(conn.KEK, plaintext, aad)
if err != nil { return err }

_, err = conn.Postgres.Exec(ctx,
    "INSERT INTO credentials (name, ciphertext) VALUES ($1, $2)",
    name, ct)
```

On read, surface cross-tenant attempts loudly:

```go
pt, err := envelope.Decrypt(conn.KEK, ct, []byte("credentials:"+name))
if envelope.IsCrossTenantDecryptError(err) {
    metrics.IncCrossTenantDecrypt(conn.Tenant)
    return nil, status.Error(codes.Internal, "internal error")
}
```

## DP-007: `WHERE n.tenant_id` Cypher patterns

Wrong (pre-refactor `internal/orchestrator/neo4j_graph_querier.go`):

```go
result, err := session.Run(ctx,
    "MATCH (m:Mission) WHERE m.tenant_id = $tenant RETURN m",
    map[string]any{"tenant": tenantID.String()})       // forbidden
```

Correct — `Conn.Neo4j` is bound to `tenant_<id>` database:

```go
result, err := conn.Neo4j.Run(ctx,
    "MATCH (m:Mission) RETURN m", nil)
```

The `forbid_raw_store_imports` analyzer prevents passing a non-Conn-bound
session into this code path.
