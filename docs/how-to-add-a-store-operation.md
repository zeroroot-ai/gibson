# how-to-add-a-store-operation.md

Walkthrough for adding a new operation to the per-tenant data plane. Worked
example: **"add a `ListOlderThan(t time.Time)` query that returns mission
runs older than the given timestamp."**

Spec: `database-per-tenant-data-plane`. Read [`data-plane.md`](./data-plane.md)
first if you have not.

## Step 1 — Find the right ops file

Operations group by entity. Mission ops live on `*MissionOps`, defined in
[`internal/datapool/conn_ops_mission.go`](../internal/datapool/conn_ops_mission.go).
Findings live on `*FindingOps` in `conn_ops_finding.go`. Memory in
`conn_ops_memory.go`. Add a new file `conn_ops_<entity>.go` only when the
entity has no existing ops bundle.

For `ListOlderThan`, extend `MissionOps` in the existing file.

## Step 2 — Choose the right backing store

Follow the existing entity. Mission run records currently live in Redis
(`gibson:mission_run:<id>`); the new query is a Redis operation. If your new
operation is a structured aggregate (e.g. `COUNT` or `JOIN`), Postgres is the
right home — move the entity if needed, but do it in a separate refactor PR,
not as part of the operation addition.

## Step 3 — Write the method on the ops receiver

```go
// In internal/datapool/conn_ops_mission.go

// ListOlderThan returns the IDs of mission runs whose JSON document carries
// a created_at timestamp earlier than t. Tenant-scoped automatically because
// m.rdb is bound to the tenant's logical Redis DB.
func (m *MissionOps) ListOlderThan(ctx context.Context, t time.Time) ([]types.ID, error) {
    cursor := uint64(0)
    out := make([]types.ID, 0, 32)
    for {
        keys, next, err := m.rdb.Scan(ctx, cursor, "gibson:mission_run:*", 100).Result()
        if err != nil {
            return nil, fmt.Errorf("mission ops: scan older than: %w", err)
        }
        for _, k := range keys {
            // ... fetch JSON, compare created_at, append to out ...
        }
        if next == 0 { break }
        cursor = next
    }
    return out, nil
}
```

Use `m.conn.Postgres` / `m.conn.Redis` / `m.conn.Neo4j` / `m.conn.Vector`
directly — they are already tenant-bound. No tenant filter, no key prefix.

## Step 4 — If the operation reads or writes a secret, use envelope encryption

When the value is secret-shaped (BYOK key, customer credential), wrap it via
`internal/datapool/envelope`:

```go
aad := []byte("missions:older-than-payload:" + id.String())
ct, err := envelope.Encrypt(m.conn.KEK, payload, aad)
// ...
pt, err := envelope.Decrypt(m.conn.KEK, ct, aad)
if envelope.IsCrossTenantDecryptError(err) {
    metrics.IncCrossTenantDecrypt(m.conn.Tenant)
    return nil, status.Error(codes.Internal, "internal error")
}
```

AAD must bind the record to its context — record type plus a stable
identifier. Don't reuse AAD across record types.

## Step 5 — If the operation needs a new schema, write a migration

For Postgres, add a new file under
[`migrations/postgres/`](../migrations/postgres/):

```
005_mission_runs_created_at_index.up.sql
005_mission_runs_created_at_index.down.sql
```

```sql
-- 005_mission_runs_created_at_index.up.sql
CREATE INDEX IF NOT EXISTS idx_mission_runs_created_at
  ON mission_runs (created_at);
-- NO tenant_id column. (See docs/rules.yaml dp-003.)
```

For Neo4j, add `migrations/neo4j/00X_<name>.up.cypher` with no `tenant_id`
property (rule dp-007).

Apply the migration to test databases via `make gibson-migrate`. Daemon
startup applies pending migrations on first `Pool.For` per tenant for non-
destructive cases; destructive migrations require
`gibson-migrate up --allow-destructive`.

## Step 6 — Write a table-driven test

Tests for `MissionOps` live in
[`internal/datapool/conn_test.go`](../internal/datapool/conn_test.go) (and
sibling `*_test.go` files). For Redis ops, prefer `miniredis`; for Postgres,
prefer `pgxmock` for unit and a testcontainer for integration. The
`forbid_raw_store_imports` analyzer permits `miniredis` in `_test.go` files
only — see [`forbid_raw_store_imports.go:42`](../tools/gibsoncheck/checks/forbid_raw_store_imports.go).

```go
func TestMissionOps_ListOlderThan(t *testing.T) {
    // miniredis fixture, seed 3 runs with mixed timestamps,
    // call ListOlderThan, assert the right set of IDs returned.
}
```

## Step 7 — Wire into the handler

The handler acquires `Conn` once, calls the new method, releases:

```go
func (s *server) PurgeOldRuns(ctx context.Context, req *pb.PurgeReq) (*pb.PurgeResp, error) {
    tenant, err := auth.TenantFromContext(ctx)
    if err != nil { return nil, status.Error(codes.Unauthenticated, "no tenant") }

    conn, err := s.pool.For(ctx, tenant)
    if err != nil {
        var notProv *datapool.NotProvisionedError
        if errors.As(err, &notProv) {
            return nil, status.Error(codes.NotFound, notProv.Error())
        }
        return nil, status.Errorf(codes.Internal, "data plane: %v", err)
    }
    defer conn.Release()

    ids, err := conn.Missions().ListOlderThan(ctx, req.Cutoff.AsTime())
    if err != nil { return nil, status.Errorf(codes.Internal, "list: %v", err) }
    // ...
}
```

If the operation legitimately spans tenants (analytics, billing) it does NOT
go through `pool.For`. Move the code to `internal/admin/` and use
`pool.Admin(ctx)` — see [`data-plane.md` § "Admin pool"](./data-plane.md#admin-pool).
The `adminpoolacquire` analyzer enforces this boundary.

## Step 8 — Run the guard sweep

Before opening a PR:

```bash
make check        # runs gibsoncheck (all analyzers) + lint + test-race
make test-race    # extra paranoia for the new lock paths
./scripts/check-no-tenant-id-column.sh
./scripts/check-no-redis-prefix.sh
```

If any analyzer fires, fix the code — do not allowlist or comment-disable
the check. The allowlists in
[`forbid_raw_store_imports.go`](../tools/gibsoncheck/checks/forbid_raw_store_imports.go)
include a "transitional allowlist" for the Phase D cleanup; new code does not
extend that list.
