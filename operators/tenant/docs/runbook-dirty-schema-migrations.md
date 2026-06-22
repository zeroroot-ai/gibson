# Runbook: dirty per-tenant `schema_migrations` recovery

When a per-tenant Postgres migration aborts mid-flight (operator crash, OOM
during DDL, network partition between the operator and the DB), the
`golang-migrate` library sets `schema_migrations.dirty = true` and refuses every
subsequent `migrate.Up()` call against that database. The tenant's saga then
loops on:

```
provisionDataPlane: dataplane: step "Postgres" failed:
  dataplane/postgres: ... has dirty schema_migrations at version N
  (manual recovery required — see runbook)
```

This is by design: a tenant database may already contain partially-applied user
data from the half-finished migration. Auto-cleaning it on the next saga
iteration would silently overwrite that data.

---

## Decision: dev vs prod

The operator runs in one of two modes, selected by the `--dev-mode` flag at pod
startup (driven by the chart's `mode: dev` value).

### dev mode

In dev mode the saga **auto-recovers** by force-rolling the migration version
back by one (`m.Force(N-1)`) and re-running `Up()`. A kind dev cluster never
contains real user data, so the rollback is safe. The recovery log line looks
like:

```
dataplane/postgres: dev-mode dirty recovery: force(N-1) ok, up succeeded
```

If the dev-mode recovery itself fails (e.g. the rollback violates a constraint
because some down-migration is buggy), the saga returns the wrapped error and
sets `Blocked=true` like any other transient failure — but the underlying
dirty flag has already been cleared by the `Force()` call, so the next reconcile
restarts from a clean state.

### prod / self-host mode

In production the saga **returns a permanent error** and sets a
`DataPlaneNeedsManualRecovery` condition on the `Tenant` CR. The saga stops
retrying that step until an operator intervenes.

---

## Production recovery flow

When a `Tenant` shows `Blocked=true` with reason `SagaFailed` and the message
contains `manual recovery required`, follow this flow.

### 1. Identify the affected tenant + dirty version

```bash
NS=gibson
kubectl -n $NS get tenant -o jsonpath='{range .items[?(@.status.conditions[?(@.type=="Blocked")].status=="True")]}{.metadata.name}{"\n"}{end}'
# → list of blocked tenants

kubectl -n $NS get tenant <tenant-name> -o jsonpath='{range .status.conditions[?(@.type=="DataPlaneProvisioned")]}{.message}{"\n"}{end}'
# → message contains "dirty schema_migrations at version N"
```

### 2. Verify the dirty state in the tenant DB

```bash
TENANT_DB="tenant_${TENANT_NAME//-/_}"
kubectl -n $NS exec platform-postgres-1 -- psql -U postgres -d "$TENANT_DB" -c \
  "SELECT version, dirty FROM schema_migrations"
# version | dirty
# --------+-------
#       N | t
```

### 3. Decide: roll forward or roll back?

Open the migration that's dirty (the one at version `N`):

```
gibson/pkg/platform/migrations/tenant/00<N>_*.sql
```

Look at the SQL. Two cases:

**Case A: idempotent / safely re-runnable.** The migration's statements are
`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, etc.
**Force version N-1 and re-up:**

```bash
kubectl -n $NS exec platform-postgres-1 -- psql -U postgres -d "$TENANT_DB" -c \
  "UPDATE schema_migrations SET version = $((N-1)), dirty = false"

# Then bump the tenant's reconcile annotation to make the operator retry:
kubectl annotate tenant <tenant-name> \
  gibson.zeroroot.ai/saga-retry-from=Postgres --overwrite
```

The `saga-retry-from` annotation is honored by the operator's saga runner and
clears the `Blocked` condition without you having to edit `.status` by hand
(see issue #47 / the runbook entry on saga-retry-from).

**Case B: not safely re-runnable.** The migration ran a destructive statement
(`DROP TABLE`, `ALTER COLUMN TYPE` with a USING clause, etc.) before crashing.
Re-running it would either fail or destroy data:

1. Inspect what state the tenant DB is in: `\d` to list tables, `\d <table>`
   for each. Reconcile against the migration's intent.
2. Write a one-off compensating SQL — by hand, reviewed by a second engineer.
3. Apply it under audit:

   ```bash
   kubectl -n $NS exec platform-postgres-1 -- psql -U postgres -d "$TENANT_DB" \
     -f /tmp/compensation.sql
   ```

4. Mark the migration as clean:

   ```bash
   kubectl -n $NS exec platform-postgres-1 -- psql -U postgres -d "$TENANT_DB" -c \
     "UPDATE schema_migrations SET version = $N, dirty = false"
   ```

5. Bump the saga-retry annotation as in case A.

### 4. Watch the recovery

```bash
kubectl -n $NS get tenant <tenant-name> -w
```

Within a reconcile cycle the `Blocked` condition flips to `False` and the
`Phase` advances. If it loops on `Blocked` again, inspect the new error message
— a different failure mode is in play, treat it as a fresh incident.

---

## Detection in the wild

Filter Loki for the dirty-recovery emitted lines:

```
{app="gibson-tenant-operator"} |~ "dirty schema_migrations"
```

A frequent recurrence on a single tenant indicates the recovery is fragile (the
underlying cause keeps re-creating the dirty state) — escalate to the
data-plane owner before another reconcile loop fires.

---

## Related issues / spec

- zeroroot-ai/tenant-operator#46 (this runbook)
- zeroroot-ai/tenant-operator#47 (saga-retry-from annotation)
- `pkg/platform/migrations` (the embedded source — gibson repo)
- `internal/dataplane/postgres.go::recoverFromDirtyMigrations` (the recovery
  function)

## See also

- [Saga step recovery](runbook-saga-step-recovery.md) — how to retry a
  permanently-failed saga step after a bug fix is deployed
