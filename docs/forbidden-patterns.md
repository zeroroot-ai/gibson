# forbidden-patterns.md — Gibson daemon

Companion to [`rules.yaml`](./rules.yaml). For each pattern: the wrong
shape (annotated where possible with a pre-refactor file:line — these
were the live patterns the relevant spec deleted), and the correct
replacement.

Specs:
- `unified-identity-and-authorization` — `GIBSON-AUTH-*` patterns
- `database-per-tenant-data-plane` — `GIBSON-DP-*` patterns

## GIBSON-AUTH-001: importing a Zitadel or OpenFGA SDK from the daemon

The daemon does not validate JWTs and does not call OpenFGA. JWT
validation is Envoy's `jwt_authn`; FGA decisions are ext-authz's job.

Wrong (would re-add work the spec moved upstream):

```go
package server

import "github.com/zitadel/oidc/v3/pkg/op"   // forbidden in daemon

func (s *Server) checkJWT(ctx context.Context, token string) error {
    return s.zitadelVerifier.Verify(ctx, token)
}
```

Right — handler trusts the headers ext-authz emitted:

```go
id, err := auth.IdentityFromContext(ctx)
if err != nil {
    return nil, status.Error(codes.PermissionDenied, "no identity on context")
}
```

The narrow exception is `internal/capabilitygrant/` (mints CG-JWTs with
Ed25519 + KMS-derived keys) and the residual FGA bridge in the same
package. Both are explicitly allowlisted in the
`forbiddenimports` analyzer ([`forbidden_imports.go:20`](../tools/gibsoncheck/checks/forbidden_imports.go)).

## GIBSON-AUTH-002: reintroducing TrustLocalhost

Wrong (audit C17 — the deleted bypass):

```go
func WithTrustLocalhost(skip bool) InterceptorOption {
    return func(o *interceptorOpts) { o.trustLocalhost = skip }
}

// inside the interceptor:
if isLoopback(peer.Addr) && o.trustLocalhost {
    return handler(ctx, req)        // forbidden — bypasses identity entirely
}
```

Right — the only inbound path is Envoy presenting its SPIFFE SVID. There
is no bypass. The `notrustlocalhost` analyzer
([`tools/gibsoncheck/checks/no_trust_localhost.go:11`](../tools/gibsoncheck/checks/no_trust_localhost.go))
fails CI on any reintroduction of the symbol.

## GIBSON-AUTH-003: reading tenant from the request body

Wrong (audit C11 — pre-refactor `internal/harness/callback_service.go:380`):

```go
func (s *Server) GetCredential(ctx context.Context, req *pb.GetCredentialRequest) (*pb.GetCredentialResponse, error) {
    tenant := req.Tenant                 // forbidden
    if tenant == "" { tenant = "_system" }   // forbidden — silent fallback
    // ...
}
```

Right — tenant comes from the verified identity:

```go
tenant, ok := auth.TenantFromContext(ctx)
if !ok {
    return nil, status.Error(codes.PermissionDenied, "no tenant on context")
}
```

The `tenantfromcontext` analyzer
([`tools/gibsoncheck/checks/tenant_from_context.go:10`](../tools/gibsoncheck/checks/tenant_from_context.go))
flags request-body tenant reads in handler bodies.

## GIBSON-AUTH-004: opening a parallel gRPC listener

Wrong (pre-refactor — three listeners on `:50001`, `:50002`, `:50100`):

```go
// internal/harness/callback_server.go (pre-refactor)
lis, err := net.Listen("tcp", ":50001")     // forbidden — second ingress
srv := grpc.NewServer( /* no auth interceptor */ )
pb.RegisterHarnessCallbackServiceServer(srv, h)
go srv.Serve(lis)
```

Right — single multiplexed listener built by the daemon factory:

```go
// internal/harness/callback_server.go:86
srv := grpc.NewServer(
    grpc.UnaryInterceptor(auth.UnaryServerInterceptor()),
    grpc.StreamInterceptor(auth.StreamServerInterceptor()),
    /* SPIFFE TLS configured by daemon.NewServer */
)
```

Envoy is the only ingress; binding a second listener is invisible to
ext-authz and bypasses the entire authz chain.

## GIBSON-AUTH-005: skipping the registry self-check

Wrong:

```go
// in daemon bootstrap:
srv := buildGRPCServer(...)
go srv.Serve(lis)            // no coverage check; stale registry slips in
```

Right ([`internal/daemon/grpc.go:762`](../internal/daemon/grpc.go)):

```go
if err := assertRegistryCoverage(srv); err != nil {
    return fmt.Errorf("daemon: registry coverage failed: %w", err)
}
```

A registered method without a registry entry means ext-authz will see
the method on the wire but have no policy for it — **default-deny**
ships traffic unable to reach handlers. The startup panic is the
fail-closed signal.

## GIBSON-AUTH-006: storing a CG-JWT signing key in plaintext

Wrong:

```yaml
# values.yaml
gibson:
  capabilityGrant:
    signingKey: |-                           # forbidden — plaintext on disk
      -----BEGIN PRIVATE KEY-----
      MC4CAQAwBQYDK2VwBCIEIB7Q...
```

```go
key := []byte(cfg.CapabilityGrant.SigningKey)   // forbidden — env / Secret read
```

Right ([`internal/capabilitygrant/mint.go`](../internal/capabilitygrant/mint.go)):

```go
master, err := keyProvider.Get(ctx, "gibson/cg-master")   // KMS / Vault / k8s
if err != nil { return nil, err }

// HKDF-SHA256 with domain separation:
// info = "gibson/v1/capability-grant-signing"
seed := hkdf.Expand(sha256.New, master, nil, []byte(infoCG))
priv := ed25519.NewKeyFromSeed(seed[:32])
```

The signing key never appears in plaintext outside the KMS-mediated
derivation; `KeyProvider` already abstracts the provider choice.

## GIBSON-DP-001: importing raw store clients outside the data plane

Pre-refactor, every package that talked to Redis imported `go-redis`
directly. After the spec, only the allowlisted data-plane packages may.

Wrong (pre-refactor `internal/database/credential_dao.go`):

```go
package database

import "github.com/redis/go-redis/v9"

type credentialDAO struct{ rdb *redis.Client }
```

Correct — the Conn is already tenant-bound, the DAO becomes a method
receiver:

```go
func (c *Conn) Credentials() *CredentialOps { return &CredentialOps{conn: c} }

func (o *CredentialOps) Get(ctx context.Context, name string) (*Credential, error) {
    // o.conn.Postgres is bound to tenant_<id>; o.conn.KEK is the tenant KEK.
}
```

## GIBSON-DP-002: missing `defer conn.Release()`

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

## GIBSON-DP-003: `tenant_id` columns and properties

Wrong (pre-refactor `migrations/postgres/003_missions.up.sql`):

```sql
CREATE TABLE missions (
    id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,             -- forbidden
    name TEXT NOT NULL
);
```

Correct — the database name is `tenant_<sanitized_id>`:

```sql
CREATE TABLE missions (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL
);
```

## GIBSON-DP-004: `tenant:` Redis key prefixes

Wrong:

```go
key := fmt.Sprintf("tenant:%s:mission:%s", tenantID, missionID)
err := rdb.Set(ctx, key, payload, 0).Err()
```

Correct — `Conn.Redis` is bound to the tenant's logical DB:

```go
key := fmt.Sprintf("gibson:mission_run:%s", id)
err := conn.Redis.Set(ctx, key, payload, 0).Err()
```

## GIBSON-DP-005: importing the admin pool from a regular handler

Wrong:

```go
package server   // tenant-handler package

import "github.com/zeroroot-ai/gibson/internal/datapool/admin"

func (s *server) ListAllMissions(ctx context.Context, req *pb.Req) (*pb.Resp, error) {
    ap, _ := admin.New(...)            // forbidden
    // ...
}
```

Correct — the cross-tenant query lives in `internal/admin/`:

```go
// internal/admin/billing.go
func (b *BillingService) ListAllMissions(ctx context.Context) (*Report, error) {
    conn, err := b.pool.Admin(ctx)     // FGA-checked, audit-emitted
    if err != nil { return nil, err }
    defer conn.Release()
    return admin.ForEachTenant(ctx, conn, b.lister, b.tenantPool, /* fn */)
}
```

## GIBSON-DP-006: storing a secret without envelope encryption

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

## GIBSON-DP-008: constructing `redis.NewClient` outside the allowlist

Spec: `daemon-mission-finding-per-tenant-cutover` Requirement 5.3.

Wrong — constructing a process-wide Redis client outside the datapool:

```go
package mypackage   // outside internal/datapool/ and internal/admin/

import goredis "github.com/redis/go-redis/v9"

func init() {
    rdb := goredis.NewClient(&goredis.Options{   // forbidden
        Addr: "redis:6379",
    })
    // ...
}
```

This creates a process-wide shared client with no tenant isolation.
All data written to it lands in the same DB index visible to every tenant.

Correct — acquire the tenant-bound `Conn.Redis` from the pool:

```go
conn, err := s.pool.For(ctx, tenant)
if err != nil { return nil, datapool.MapPoolError(err) }
defer conn.Release()

err = conn.Redis.Set(ctx, "gibson:mission:"+id.String(), data, 0).Err()
```

The `forbidredisclientconstruction` analyzer
([`tools/gibsoncheck/checks/forbid_redis_client_construction.go`](../tools/gibsoncheck/checks/forbid_redis_client_construction.go))
fails CI on any `redis.NewClient(...)` call outside `internal/datapool/`
and `internal/admin/`. Test files (`*_test.go`) are exempt.

## GIBSON-DP-007: `WHERE n.tenant_id` Cypher patterns

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
