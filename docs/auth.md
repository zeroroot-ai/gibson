# auth.md — Gibson daemon

Auth model from the daemon's perspective. AI-agent-facing.
Spec: `unified-identity-and-authorization`.

## What this is

The Gibson daemon does **no auth work**. It does not validate JWTs. It
does not call OpenFGA. It does not verify HMAC headers. It does not mint
its own session tokens.

The daemon's gRPC interceptor reads `x-gibson-identity-*` headers
ext-authz already emitted, builds a typed `auth.Identity`, and places it
on the request context. That is all. Every authentication and
authorization decision happened upstream.

What the daemon **does** own:

| Concern | File |
|---|---|
| Capability-grant minting (Ed25519, KMS-derived) | [`internal/capabilitygrant/mint.go`](../internal/capabilitygrant/mint.go) |
| JWKS publication for CG-JWT verifiers | [`internal/capabilitygrant/jwks.go`](../internal/capabilitygrant/jwks.go) |
| Single multiplexed gRPC listener with SDK auth interceptor | [`internal/daemon/grpc.go`](../internal/daemon/grpc.go) |
| Inbound SPIFFE peer pin (Envoy SVID only) | [`internal/daemon/grpc.go:179`](../internal/daemon/grpc.go) |
| Startup self-check: every registered method has a registry entry | [`internal/daemon/grpc.go:762`](../internal/daemon/grpc.go) |
| Forbidden-imports + tenant-from-context analyzers (`gibsoncheck`) | [`tools/gibsoncheck/checks/`](../tools/gibsoncheck/checks/) |

## The trust chain that ends at the daemon

```
caller --(Zitadel JWT)--> Envoy --(SPIFFE mTLS)--> daemon
                            |
                            | jwt_authn validates sig/iss/aud/exp
                            | ext_authz callout (gRPC):
                            |   - registry lookup for method
                            |   - CG-JWT short-circuit OR FGA check
                            |   - on allow, emits x-gibson-identity-* headers
                            |
                            +-- SVID belongs to spiffe://zeroroot.ai/platform/envoy
                                                       |
                                                       v
              daemon TLS listener (internal/daemon/grpc.go:183)
                            |
                            | tls.RequestClientCert + go-spiffe verifier
                            | rejects any peer SVID != Envoy's
                            v
              SDK auth interceptor (sdk/auth/interceptor.go)
                            |
                            | reads x-gibson-identity-{subject,issuer,
                            |       credential-type,tenant,issued-at}
                            | → auth.NewTenantID(tenant header)
                            | → auth.WithIdentity(ctx, Identity{...})
                            v
                       handler(ctx, req)
                            |
                            | auth.IdentityFromContext / TenantFromContext
                            | pool.For(ctx, tenant)            (data plane)
                            v
                       respond
```

The headers are not HMAC-signed. Channel security is the SPIFFE-pinned
mTLS hop — only Envoy can connect, so the daemon trusts whatever Envoy
sends. HMAC was the defense-in-depth against a man-in-the-middle on the
Envoy↔daemon hop that does not exist with mTLS-pinned ingress; removing
it deleted a whole secret-loading dance ([`grpc.go:163`](../internal/daemon/grpc.go)).

## RPC handler pattern

Every handler follows this exact shape:

```go
func (s *Server) ListMissions(ctx context.Context, req *pb.ListMissionsRequest) (*pb.ListMissionsResponse, error) {
    // 1. Read the verified identity (from headers ext-authz emitted).
    id, err := auth.IdentityFromContext(ctx)
    if err != nil {
        return nil, status.Error(codes.PermissionDenied, "no identity on context")
    }
    _ = id  // most handlers only need tenant; keep id for audit fields if needed.

    // 2. Tenant — sealed type, never read from req.
    tenant, ok := auth.TenantFromContext(ctx)
    if !ok {
        return nil, status.Error(codes.PermissionDenied, "no tenant on context")
    }

    // 3. Per-tenant connection bundle (data-plane spec).
    conn, err := s.pool.For(ctx, tenant)
    if err != nil {
        var notProv *datapool.NotProvisionedError
        if errors.As(err, &notProv) {
            return nil, status.Error(codes.NotFound, notProv.Error())
        }
        return nil, status.Errorf(codes.Internal, "data plane: %v", err)
    }
    defer conn.Release()

    // 4. Ordinary handler logic. No tenant filter, no key prefix.
    out, err := conn.Missions().List(ctx, req.PageSize, req.PageToken)
    // ...
}
```

Real examples in [`internal/daemon/api/server.go`](../internal/daemon/api/server.go):
the `auth.IdentityFromContext` calls at lines 2364, 2472, 2519, 2607, 2668
all follow this pattern.

**Never read `req.Tenant` / `req.TenantId` / `req.TenantID`.** The
`tenantfromcontext` analyzer ([`tools/gibsoncheck/checks/tenant_from_context.go`](../tools/gibsoncheck/checks/tenant_from_context.go))
flags request-body tenant reads in handler bodies. Tenant is whatever
ext-authz says it is; trusting the request body is audit C11 reopened.

## Capability-grant minting (KMS-derived Ed25519)

`internal/capabilitygrant/mint.go` is the daemon's single auth-related
piece of crypto. The orchestrator calls `Minter.Mint(ctx, ...)` at task
dispatch:

```go
token, err := s.minter.Mint(ctx, capabilitygrant.MintRequest{
    Subject:     agent.ServiceAccountID,
    Tenant:      tenant,           // sealed TenantID
    MissionID:   mission.ID,
    TaskID:      task.ID,
    AllowedRPCs: task.RequiredRPCs,
    TTL:         15 * time.Minute, // capped at MaxLifetime = 30m
})
```

Key derivation:

```
Ed25519 keypair = HKDF-SHA256(
    masterKEK = KeyProvider.Get("gibson/cg-master"),
    salt      = (none),
    info      = "gibson/v1/capability-grant-signing",
    L         = 32 bytes (used as Ed25519 seed)
)
```

`KeyProvider` is the existing interface ([`internal/crypto/`](../internal/crypto/))
that already supports k8s/Vault/AWS-KMS/Azure-KV/GCP-KMS. The
domain-separation `info` string keeps the signing key disjoint from the
encryption KEKs the data-plane uses.

JWKS is served at `/.well-known/jwks.json`
([`internal/capabilitygrant/jwks.go`](../internal/capabilitygrant/jwks.go)),
through Envoy externally. ext-authz fetches and caches it for 1 hour.

The daemon **only mints**. It does not verify its own CG-JWTs — that is
ext-authz's job ([`core/ext-authz/internal/cgjwt/verifier.go`](../../ext-authz/internal/cgjwt/verifier.go)).

## Authz registry self-check

Daemon startup walks every registered gRPC method and verifies it has a
matching entry in the SDK's generated registry
([`internal/daemon/grpc.go:762`](../internal/daemon/grpc.go)):

```go
for svcName, info := range srv.GetServiceInfo() {
    for _, m := range info.Methods {
        full := "/" + svcName + "/" + m.Name
        if _, ok := sdkregistry.Registry[full]; !ok {
            missing = append(missing, full)
        }
    }
}
```

A miss means the proto annotation is absent or the SDK pin is stale.
The daemon refuses to start in either case — **fail-closed**.

## Inbound SPIFFE peer pin

The TLS listener ([`internal/daemon/grpc.go:183`](../internal/daemon/grpc.go))
uses `tls.RequestClientCert` with a go-spiffe `MTLSServerConfig`
verifier. The verifier accepts only `spiffe://zeroroot.ai/platform/envoy`
(the Envoy SDS-resolved upstream SVID). Any other peer SVID is rejected
at the TLS handshake before headers are read.

Why `RequestClientCert` rather than `VerifyClientCertIfGiven` or
`RequireAnyClientCert` is documented inline at [`grpc.go:197-211`](../internal/daemon/grpc.go) —
it is the only setting that lets go-spiffe's `VerifyPeerCertificate`
callback run while preserving Bearer-only fallback for non-mTLS
callers (which never reach a handler because they fail the
header-presence check anyway).

## gibsoncheck guards (auth-relevant)

All analyzers live in [`tools/gibsoncheck/checks/`](../tools/gibsoncheck/checks/)
and run as part of `make check` / `make lint`.

| Analyzer | File | What it forbids |
|---|---|---|
| `forbiddenimports` | [`forbidden_imports.go`](../tools/gibsoncheck/checks/forbidden_imports.go) | `github.com/zitadel/*`, `github.com/openfga/*` outside the narrow allowlist (capabilitygrant FGA bridge for now). |
| `notrustlocalhost` | [`no_trust_localhost.go`](../tools/gibsoncheck/checks/no_trust_localhost.go) | Any reintroduction of the deleted `TrustLocalhost` interceptor option (audit C17). |
| `tenantfromcontext` | [`tenant_from_context.go`](../tools/gibsoncheck/checks/tenant_from_context.go) | Handler bodies that read `req.Tenant` / `req.TenantId` / `req.TenantID` (audit C11). |
| `adminpoolacquire` | [`admin_pool_acquire.go`](../tools/gibsoncheck/checks/admin_pool_acquire.go) | Importing `internal/datapool/admin` outside `internal/admin/`, `internal/migrate/`, `cmd/gibson-migrate/`. (Data-plane spec; cross-listed because admin ops still need a verified identity.) |
| `forbidrawstoreimports` | [`forbid_raw_store_imports.go`](../tools/gibsoncheck/checks/forbid_raw_store_imports.go) | `pgx`, `go-redis`, `neo4j-go-driver` outside the data-plane allowlist. |
| `forbidrediskeyprefix` | [`forbid_redis_key_prefix.go`](../tools/gibsoncheck/checks/forbid_redis_key_prefix.go) | `tenant:` / `gibson:tenant:` prefixes on per-tenant Redis keys. |

The auth-specific allowlists are narrow: the FGA bridge in
`internal/capabilitygrant/fga_bridge.go` is allowlisted because the
capability-grant feature still has a residual FGA call that spec Phase 3
plans to remove; until then the analyzer permits it explicitly.

## Impersonation tokens

The daemon mints platform-operator impersonation JWTs from
`PlatformOperatorService.ImpersonateTenant`. The minter
([`internal/impersonation/issuer.go`](../internal/impersonation/issuer.go))
HMAC-SHA256-signs short-lived (≤ 1 h) tokens whose `sub` claim is the
target tenant and whose `impersonator` claim is the operator's subject.

The signing key is REQUIRED at startup. The daemon refuses to come up
when `GIBSON_IMPERSONATION_KEY` is unset or shorter than 32 bytes
(RFC 7518 §3.2). There is no in-process random fallback — that was the
gibson#103 defect, which made every previously-issued token unverifiable
on each restart and silently diverged across HA replicas.

The chart sources both env vars from a single ESO-managed Secret
(`gibson-workloads-impersonation-key`, template
[`secrets/impersonation-key.yaml`](https://github.com/zeroroot-ai/deploy/blob/main/helm/gibson-workloads/templates/secrets/impersonation-key.yaml)):

| Env                                  | Purpose                                                       |
|--------------------------------------|---------------------------------------------------------------|
| `GIBSON_IMPERSONATION_KEY`           | **current** — the only key used to mint                       |
| `GIBSON_IMPERSONATION_KEY_PREVIOUS`  | **previous** — optional; Verify accepts tokens signed by it   |

`Issuer.Verify` (same file) accepts tokens signed by either key. The
previous slot is empty in steady state and populated only during a
rotation; once populated, in-flight operator sessions survive the
rotation. The operator clears the slot after maxTTL has elapsed (≤ 1 h).

Rotation procedure: [`deploy → docs/runbooks/impersonation-key-rotation.md`](https://github.com/zeroroot-ai/deploy/blob/main/docs/runbooks/impersonation-key-rotation.md).

Note: no in-tree caller of `Verify` exists today. The method ships
alongside the minter so the rotation contract lives next to the key
material; the consumer (a downstream impersonation-token verifier) is
not yet implemented.

## What's gone

| Removed | Why |
|---|---|
| `internal/identity/` | Moved to `sdk/auth/` so consumers share the same types. |
| `internal/apikeys/` | `gsk_` keys replaced by Zitadel service accounts. |
| `internal/extauthz/` (client) | Daemon does not talk to ext-authz; ext-authz is upstream. |
| HMAC header signing/verifying | Channel is SPIFFE-pinned mTLS; HMAC was redundant. |
| `TrustLocalhost` interceptor option | Audit C17. No bypass path remains. |
| `_system` fallback in `TenantFromContext` | Audit C11/C12. Empty tenant → PermissionDenied. |
| Three separate gRPC listeners (`:50001`, `:50002`, `:50100`) | Single multiplexed port behind Envoy. |
| `internal/capabilitygrant/` inline-secret implementation | Replaced by KMS-derived Ed25519 minting. |

## Cross-link

- Adding a new RPC end-to-end: [`how-to-add-a-rpc.md`](./how-to-add-a-rpc.md).
- Wrong vs right code shapes: [`forbidden-patterns.md`](./forbidden-patterns.md).
- Machine-readable rules: [`rules.yaml`](./rules.yaml).
- Per-tenant data plane: [`data-plane.md`](./data-plane.md).
- SDK identity types: `core/sdk/docs/auth.md`.
- ext-authz internals (the half upstream of this daemon): `core/ext-authz/docs/auth.md`.
- Helm wiring (Envoy, SPIRE, Vault, validators): `enterprise/deploy/docs/auth.md`.
