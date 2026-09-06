# forbidden-patterns.md — tenant-operator

Companion to [`rules.yaml`](./rules.yaml). For each anti-pattern: the wrong
shape and the correct replacement.

Specs:
- `database-per-tenant-data-plane` — `DP-OP-*` patterns (data-plane provisioning).
- `unified-identity-and-authorization` — `TENANT-OPERATOR-AUTH-*` patterns (auth wiring).

## DP-OP-001: non-idempotent provisioning step

The reconciler retries on transient errors and re-runs the full pipeline on
restart. A non-idempotent step turns "transient API hiccup" into a permanent
`AlreadyExists`-style failure.

Wrong:

```go
// inside Provision:
_, err := adminConn.Exec(ctx,
    "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize())
if err != nil { return err }   // fails on the second run with "database already exists"
```

Correct (catalog pre-check + skip; pgsql lacks `CREATE DATABASE IF NOT
EXISTS`):

```go
var dbExists bool
row := adminConn.QueryRow(ctx,
    "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbName)
if err := row.Scan(&dbExists); err != nil { return err }
if !dbExists {
    _, err := adminConn.Exec(ctx,
        "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize())
    if err != nil { return err }
}
```

See [`postgres.go:91`](../internal/dataplane/postgres.go) for the canonical
pattern. Same idea on Deprovision: use `DROP … IF EXISTS` or ignore the
not-found error.

## DP-OP-002: unsanitized tenant ID in SQL identifiers

Even though provisioning runs as an admin role, raw concatenation of a
tenant identifier into a `CREATE DATABASE` / `CREATE ROLE` / `ALTER ROLE`
statement is a SQL-injection footgun. The tenant ID may flow from external
upstream systems where validation is incomplete.

Wrong:

```go
sql := "CREATE DATABASE tenant_" + tenantID         // forbidden
_, err := adminConn.Exec(ctx, sql)
```

Correct (use the helper, then `pgx.Identifier`):

```go
dbName, err := tenantDBName(tenantID)               // sanitize.go: lowercase + [a-z0-9_]
if err != nil { return err }
sql := "CREATE DATABASE " + pgx.Identifier{dbName}.Sanitize()
_, err = adminConn.Exec(ctx, sql)
```

See [`sanitize.go:30`](../internal/dataplane/sanitize.go) for the helper and
[`postgres.go:99`](../internal/dataplane/postgres.go) for the use site.

## DP-OP-003: logging or surfacing the KEK / derived password

Wrong:

```go
password, err := tenantRolePassword(p.cfg.MasterKEK, tenantID)
log.Info("provisioned role", "role", roleName, "password", password)   // forbidden
return fmt.Errorf("create role %q with password %q: %w", roleName, password, err)
```

Correct (zero the KEK in defer, redact from logs, generic error):

```go
password, err := tenantRolePassword(p.cfg.MasterKEK, tenantID)
if err != nil { return fmt.Errorf("derive role password: %w", err) }
// password is the only consumer; do not log it.

if _, err := adminConn.Exec(ctx, roleSQL); err != nil {
    return fmt.Errorf("create role %q: %w", roleName, err)   // password not in error
}
```

See [`kek.go:72`](../internal/dataplane/kek.go) for the zero-on-defer pattern
inside `tenantRolePassword`.

## DP-OP-004: missing rollback in the pipeline

When you add a new step to `pipelineProvisioner.buildSteps`, every step
needs both a `Provision` and an idempotent `Rollback`. Skipping the
rollback breaks LIFO failure recovery — a downstream step's failure leaves
the new step's resources orphaned.

Wrong (new "Foo" step with no Rollback):

```go
{
    Name:     "Foo",
    Provision: func(ctx context.Context, t string) error { return p.cfg.Foo.Provision(ctx, t) },
    // missing Rollback — pipeline cannot tear down Foo on subsequent failure
}
```

Correct:

```go
{
    Name:     "Foo",
    Provision: func(ctx context.Context, t string) error { return p.cfg.Foo.Provision(ctx, t) },
    Rollback:  func(ctx context.Context, t string) error { return p.cfg.Foo.Deprovision(ctx, t) },
    StatusUpdate: func(dp *gibsonv1alpha1.TenantDataPlaneStatus) {
        dp.FooProvisioned = true
    },
}
```

If the step has no persistent state to roll back (e.g. KEKInit), make
`Rollback` an explicit `func(ctx, t) error { return nil }` rather than
omitting it — the pipeline calls Rollback unconditionally.

See [`pipeline.go:98`](../internal/dataplane/pipeline.go) for the canonical
Step definitions.

## DP-OP-005: drifting the HKDF info string

The constant `hkdfInfo = "gibson/v1/tenant-kek"` MUST match the daemon's
value at `core/gibson/internal/infra/datapool/kek.go:18`. Any change invalidates
every wrapped DEK in tenant storage.

Wrong:

```go
const hkdfInfo = "tenant-operator/v2/kek"     // forbidden — diverges from daemon
```

Correct:

```go
const hkdfInfo = "gibson/v1/tenant-kek"       // matches daemon
```

If a future KMS rotation requires a new info string, both files change in
the same commit and the spec defines the re-encryption procedure.

## DP-OP-006: status update via Update instead of Status().Update

Wrong:

```go
tenant.Status.DataPlane.Phase = "Active"
err := k8sClient.Update(ctx, tenant)         // forbidden: races with non-status writers
```

Correct:

```go
tenant.Status.DataPlane.Phase = "Active"
err := k8sClient.Status().Update(ctx, tenant)
```

See [`pipelineProvisioner.patchStatus` in
`pipeline.go:319`](../internal/dataplane/pipeline.go) for the canonical
helper.

## TENANT-OPERATOR-AUTH-001: reusing the dashboard's Zitadel credentials

Wrong (the operator and the dashboard hold different Zitadel
service-account roles; reuse silently widens the operator's effective
privileges):

```go
clientID := os.Getenv("ZITADEL_DASHBOARD_CLIENT_ID")          // forbidden
clientSecret := os.Getenv("ZITADEL_DASHBOARD_CLIENT_SECRET")  // forbidden
```

Right ([`internal/grpc/client.go:78`](../internal/grpc/client.go)):

```go
clientID := os.Getenv("ZITADEL_TENANT_OPERATOR_CLIENT_ID")
clientSecret := os.Getenv("ZITADEL_TENANT_OPERATOR_CLIENT_SECRET")
```

The Helm chart materialises the operator's Secret separately from the
dashboard's; pulling the wrong env reads the wrong credentials.

## TENANT-OPERATOR-AUTH-002: parsing credentials from a local file

Wrong:

```go
data, err := os.ReadFile("/etc/gibson/zitadel-client-secret")  // forbidden
parts := strings.SplitN(string(data), ":", 2)
clientID, clientSecret := parts[0], parts[1]
```

Right — env-only:

```go
clientID := os.Getenv("ZITADEL_TENANT_OPERATOR_CLIENT_ID")
clientSecret := os.Getenv("ZITADEL_TENANT_OPERATOR_CLIENT_SECRET")
```

The Helm Secret `gibson-zitadel-tenant-operator` mounts the values as
env vars. Reading a file path is an extra surface, an extra failure
mode, and a guard the chart cannot enforce structurally.

## TENANT-OPERATOR-AUTH-003: logging the Zitadel admin PAT

Wrong:

```go
pat := os.Getenv("ZITADEL_IAM_ADMIN_PAT")
slog.Info("starting", "pat", pat)        // forbidden — leaks the highest-priv credential
fmt.Printf("DEBUG: PAT=%s\n", pat)       // forbidden
```

Right:

```go
pat := os.Getenv("ZITADEL_IAM_ADMIN_PAT")
if pat == "" {
    return errors.New("ZITADEL_IAM_ADMIN_PAT not configured")
}
slog.Info("zitadel client ready", "issuer", issuer)  // no PAT
```

The PAT is the only long-lived credential in the polyrepo. Operators
rotate it on schedule; logging it would defeat the rotation.

## TENANT-OPERATOR-AUTH-004: non-idempotent saga step

Wrong:

```go
func ensureZitadelOrg(ctx context.Context, t *Tenant) error {
    orgID, err := zitadel.CreateOrganization(ctx, t.Spec.Name, t.Spec.Slug)
    if err != nil {
        return err   // forbidden — 409 should be "already exists, fine"
    }
    t.Status.ZitadelOrgID = orgID
    return nil
}
```

Right ([`internal/saga/flows/provision_zitadel.go`](../internal/saga/flows/provision_zitadel.go)):

```go
if t.Status.ZitadelOrgID != "" {
    if _, err := zitadel.GetOrganization(ctx, t.Status.ZitadelOrgID); err == nil {
        return true, nil  // already provisioned, verified, done
    } else if !errors.Is(err, clients.ErrNotFound) {
        return false, err
    }
}
orgID, err := zitadel.CreateOrganization(ctx, name, slug)  // 409 → returns existing ID
if err != nil { return false, err }
t.Status.ZitadelOrgID = orgID
return true, nil
```

The same applies to teardown — 404 / not-found is success, the org is
already gone.

## TENANT-OPERATOR-AUTH-005: minting a `gsk_` API key

Wrong (audit-deleted code path):

```go
// internal/saga/flows/provision_apikey.go (deleted)
key := apikeys.New("gsk_")                 // forbidden — system gone
err := apikeyStore.Save(ctx, t.Spec.Name, key)
t.Status.AgentAPIKey = key                  // forbidden — Status leaks credentials
```

Right — onboarding emits a Zitadel user invitation for the owner email
on the Tenant CRD spec; the user accepts the invite, signs in via
Auth.js, and creates agents through the dashboard's "Register Agent"
UI:

```go
err := zitadel.SendInvitation(ctx, orgID, t.Spec.OwnerEmail, /* roles */ )
if err != nil { return false, err }
// Status carries org ID + invitation status; no credentials.
```

The agent client_id / client_secret are response-body of the dashboard
endpoint, never persisted to a CRD status.

## TENANT-OPERATOR-AUTH-006: dialing the daemon directly

Wrong:

```go
conn, err := grpc.Dial("gibson:50002",                     // forbidden
    grpc.WithTransportCredentials(insecure.NewCredentials()))
```

Right ([`internal/grpc/client.go`](../internal/grpc/client.go) — Envoy edge):

```go
addr := config.GibsonURL                  // chart-supplied Envoy URL
conn, err := grpc.NewClient(addr, dialOpts...)
```

The Envoy edge enforces the entire auth chain (jwt_authn + ext_authz +
SPIFFE mTLS upstream); a direct dial bypasses all of it. The operator's
Zitadel JWT would not even be validated on the way through.

