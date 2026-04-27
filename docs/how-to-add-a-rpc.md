# how-to-add-a-rpc.md — Gibson daemon

Step-by-step for adding a new RPC handler to the daemon. Worked example:
**"add `ListMyMissions` returning the caller's mission summaries."**

The proto for SDK-owned services lives in `zero-day-ai/sdk`; the proto
for `DaemonAdminService` lives in this repo at
[`internal/daemon/api/gibson/daemon/admin/v1/daemon_admin.proto`](../internal/daemon/api/gibson/daemon/admin/v1/daemon_admin.proto).
This guide covers both halves; pick the matching path.

Spec: `unified-identity-and-authorization`. Read [`auth.md`](./auth.md)
first if you have not.

## Step 1 — Decide which service the RPC belongs on

| Service | Proto in | Use when |
|---|---|---|
| `gibson.daemon.v1.DaemonService` | SDK | Public mission/component/agent control plane (most user-facing RPCs). |
| `gibson.daemon.admin.v1.DaemonAdminService` | this repo | Privileged ops (Shutdown, ImpersonateTenant, capability-grant ops, audit reads). |
| `gibson.component.v1.ComponentService` | SDK | Agent / tool / plugin → daemon (RegisterComponent, PollWork, SubmitResult). |
| `gibson.harness.v1.HarnessCallbackService` | SDK | Agent → daemon callbacks during a mission task (LLMComplete, MemoryGet, …). |
| `intelligence.v1.IntelligenceService` | SDK | Cross-mission analytics. |

For `ListMyMissions` the right place is `DaemonService` (SDK).

## Step 2 — Add the proto + authz annotation

If the RPC is on a SDK-owned service, do this work in `core/sdk/` and
follow `core/sdk/docs/how-to-add-a-rpc.md`. If it is on
`DaemonAdminService`, edit
[`internal/daemon/api/gibson/daemon/admin/v1/daemon_admin.proto`](../internal/daemon/api/gibson/daemon/admin/v1/daemon_admin.proto)
in this repo:

```proto
import "gibson/auth/v1/options.proto";

service DaemonAdminService {
  rpc ListMyMissions(ListMyMissionsRequest) returns (ListMyMissionsResponse) {
    option (gibson.auth.v1.authz) = {
      relation: "member"
      object_type: "tenant"
      object_deriver: "tenant_from_identity"
      allowed_identities: 1   // USER
    };
  }
}
```

The annotation is mandatory. The `authz-required` buf lint plugin fails
CI on omission and the daemon's startup self-check refuses to serve if
the registry has no entry for a registered method.

## Step 3 — Regenerate code

```
make proto       # this repo: regenerates DaemonAdminService bindings
```

For SDK-owned services, `make proto` happens in `core/sdk/` and the
daemon picks up the new types after the SDK pin is bumped.

## Step 4 — Implement the handler

Add the method in [`internal/daemon/api/server.go`](../internal/daemon/api/server.go)
or in a `server_<area>.go` split file (current splits:
`server_capabilitygrant.go`, `server_audit.go`, `server_chat.go`, …).

```go
// internal/daemon/api/server_missions.go (or wherever fits)

func (s *Server) ListMyMissions(ctx context.Context, req *adminpb.ListMyMissionsRequest) (*adminpb.ListMyMissionsResponse, error) {
    // 1. Identity is on the context — placed there by the SDK auth
    //    interceptor (sdk/auth/interceptor.go) which read x-gibson-identity-*
    //    headers ext-authz emitted.
    id, err := auth.IdentityFromContext(ctx)
    if err != nil {
        return nil, status.Error(codes.PermissionDenied, "no identity on context")
    }

    // 2. Tenant — sealed type. Never reads from req.
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
    out, next, err := conn.Missions().ListSummaries(ctx, req.PageSize, req.PageToken)
    if err != nil {
        return nil, status.Errorf(codes.Internal, "list missions: %v", err)
    }

    // 5. Audit-emit if the RPC is privileged. id.Subject is the principal.
    s.audit.EmitInvocation(ctx, id.Subject, "ListMyMissions", tenant)

    return &adminpb.ListMyMissionsResponse{Missions: out, NextToken: next}, nil
}
```

Real examples in [`internal/daemon/api/server.go`](../internal/daemon/api/server.go)
at lines 2364, 2472, 2519, 2607, 2668 — all five follow the
identity → tenant → pool → release pattern.

## Step 5 — Wire the handler

Most handlers are auto-wired because `Server` is the registered gRPC
service implementer (`pb.RegisterDaemonServiceServer(srv, s)` in
`internal/daemon/grpc.go`). Adding a method to the `Server` struct is
enough — gRPC-Go's generated `RegisterFooServiceServer` enforces
interface satisfaction at compile time.

If the new RPC requires a new dependency (e.g. a new store), thread it
through `Server` via the existing constructor option pattern; do not
add globals.

## Step 6 — Verify the startup self-check passes

Boot the daemon (or `go test ./internal/daemon/...`); if the SDK
registry is missing an entry for the new method, the daemon panics with:

```
the following gRPC methods are registered on the daemon but missing
from the SDK auth registry — regenerate sdk/auth/registry by running
`make proto` in zero-day-ai/sdk and bumping the gibson SDK pin:
  - /gibson.daemon.admin.v1.DaemonAdminService/ListMyMissions
```

Two common fixes:

1. SDK proto change not yet released: tag a new SDK version and bump
   the pin in `go.mod` (see top-level `CLAUDE.md` for the bump-sdk
   workflow).
2. Local proto change in this repo not regenerated: `make proto`.

## Step 7 — Build guards

Before opening a PR:

```
make check                         # gibsoncheck (forbidden imports, no
                                   # TrustLocalhost, tenantfromcontext,
                                   # admin pool acquire, redis prefix,
                                   # raw store imports) + lint + test-race
make test-race
./scripts/check-no-tenant-id-column.sh
./scripts/check-no-redis-prefix.sh
```

If any analyzer fires, fix the code — do not allowlist or comment-disable
the check. The allowlists in
[`forbidden_imports.go`](../tools/gibsoncheck/checks/forbidden_imports.go)
are already narrow; widening them re-introduces the boundary the spec
deleted.

## Step 8 — Update the dashboard (if user-facing)

If the RPC is reachable from a dashboard route, regenerate TS bindings
on the dashboard side (`pnpm build` in
`enterprise/platform/dashboard/`). Use `userClient(svc)` for user-acting
calls and `serviceClient(svc, tenantId)` for in-cluster service-acting
calls — see `enterprise/platform/dashboard/docs/auth.md`.

The corresponding `permissions.ts` constant gates the UI control. UI
gating is informational; ext-authz remains the authoritative
enforcement point.

## Step 9 — End-to-end validation

For non-trivial RPCs, ship an integration test under `tests/` or
`internal/daemon/api/*_integration_test.go` that exercises the full
chain (Envoy → ext-authz → daemon) against `make deploy-local` per the
E2E rules in this repo's `CLAUDE.md`. Don't mark the task `[x]` until
the test exits 0 with evidence.
