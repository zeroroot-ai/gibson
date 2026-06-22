# how-to-add-an-auth-call.md — `zeroroot-ai/tenant-operator`

The tenant-operator does not own RPCs in the gRPC sense. "Adding an
auth-touching code path" from this repo's perspective means:

1. Adding a new saga step that calls an external auth-bearing API
   (Zitadel / FGA / daemon admin).
2. Adding a new code path that needs the operator's authenticated
   `*grpc.ClientConn` to call the daemon.

Worked example: **"add a saga step that creates a per-tenant FGA
'capability:llm-budget' tuple after the tenant's data plane is ready."**

Spec: `unified-identity-and-authorization`. Read [`auth.md`](./auth.md)
first if you have not.

## Step 1 — Reuse the existing clients

The operator wires two auth-bearing clients at startup
([`cmd/main.go`](../cmd/main.go)):

- `clients.Zitadel` ([`internal/clients/zitadel/client.go`](../internal/clients/zitadel/client.go))
  for org / member CRUD against Zitadel admin API.
- `clients.FGA` ([`internal/clients/fga/`](../internal/clients/fga/))
  for tuple writes against the FGA HTTP API.
- `clients.Daemon` ([`internal/grpc/client.go`](../internal/grpc/client.go))
  for outbound RPCs to the daemon (Envoy edge).

New saga steps receive the same `ProvisionDeps` bundle. Reuse those
clients; do not stand up new ones.

## Step 2 — Define the saga step

Saga steps are idempotent functions wrapped with a CRD condition
([`internal/saga/step.go`](../internal/saga/step.go)). For the FGA
budget tuple:

```go
// internal/saga/flows/provision_budget.go

func EnsureBudgetTupleStep(deps ProvisionDeps) saga.Step {
    return saga.Step{
        Name:          "EnsureBudgetTuple",
        ConditionType: gibsonv1alpha1.ConditionBudgetTupleReady,
        Idempotent:    true,
        Fn:            ensureBudgetTuple(deps),
    }
}

func ensureBudgetTuple(deps ProvisionDeps) saga.StepFn {
    return func(ctx context.Context, obj saga.ConditionedObject) (bool, error) {
        t, ok := obj.(*gibsonv1alpha1.Tenant)
        if !ok {
            return false, fmt.Errorf("ensureBudgetTuple: expected *Tenant, got %T", obj)
        }
        // FGA tuple writes are inherently idempotent — re-writing an
        // identical tuple succeeds with no effect.
        tuples := []fga.Tuple{
            {User: "tenant:" + t.Spec.Name, Relation: "has_capability", Object: "capability:llm-budget"},
        }
        return deps.FGA.WriteTuples(ctx, tuples)
    }
}
```

## Step 3 — Add a teardown step

Every provision step has a corresponding teardown step. For the budget
tuple:

```go
// internal/saga/flows/teardown_budget.go

func RemoveBudgetTupleStep(deps TeardownDeps) saga.Step {
    return saga.Step{
        Name:       "RemoveBudgetTuple",
        Idempotent: true,
        Fn: func(ctx context.Context, obj saga.ConditionedObject) (bool, error) {
            t := obj.(*gibsonv1alpha1.Tenant)
            tuples := []fga.Tuple{
                {User: "tenant:" + t.Spec.Name, Relation: "has_capability", Object: "capability:llm-budget"},
            }
            err := deps.FGA.DeleteTuples(ctx, tuples)
            if errors.Is(err, fga.ErrNotFound) { return true, nil }   // already gone
            return err == nil, err
        },
    }
}
```

Teardown order is the reverse of provision order — see
[`internal/saga/flows/teardown.go`](../internal/saga/flows/teardown.go).

## Step 4 — Wire the step into the saga runner

The saga's `Provision` and `Teardown` lists live in
[`internal/saga/flows/provision.go`](../internal/saga/flows/provision.go)
and `teardown.go`. Add the new step at the right point in the order:

```go
// in Provision(...):
steps := []saga.Step{
    EnsureZitadelOrgStep(deps),
    EnsureFGAOwnerTupleStep(deps),
    ProvisionPostgresStep(deps),
    ProvisionNeo4jStep(deps),
    ProvisionRedisStep(deps),
    ProvisionVectorStep(deps),
    EnsureBudgetTupleStep(deps),       // new
}
```

The CRD condition (`ConditionBudgetTupleReady`) is added to
`api/v1alpha1/conditions.go` at the same time. CRD generation
(`make manifests`) regenerates the schema.

## Step 5 — If the step needs a daemon RPC

For example, a step that asks the daemon to seed a per-tenant
provider-config baseline:

```go
func ensureProviderConfigBaseline(deps ProvisionDeps) saga.StepFn {
    return func(ctx context.Context, obj saga.ConditionedObject) (bool, error) {
        t := obj.(*gibsonv1alpha1.Tenant)

        // deps.Daemon is the operator's authenticated client (Zitadel
        // service-account JWT attached automatically). Never instantiate
        // a new client here.
        adminClient := adminpb.NewDaemonAdminServiceClient(deps.Daemon)
        _, err := adminClient.SeedProviderBaseline(ctx, &adminpb.SeedProviderBaselineRequest{
            Tenant: t.Spec.Name,
        })
        if err != nil { return false, err }
        return true, nil
    }
}
```

The operator's identity reaches the daemon via Envoy + ext-authz; the
daemon's handler reads `auth.IdentityFromContext` and `auth.TenantFromContext`
to act in the right scope. The operator does **not** invent a tenant
header — the FGA tuple it just wrote authorises this call.

## Step 6 — Avoid these patterns

- **Never** stand up a second auth path. Reuse `deps.Zitadel`,
  `deps.FGA`, `deps.Daemon`.
- **Never** mint `gsk_` API keys. The legacy issuance path is gone;
  agent credentials come from the dashboard's Register Agent UI only.
- **Never** dial the daemon directly. The address in `deps.Daemon` is
  the Envoy edge.
- **Never** log the Zitadel admin PAT or any client_secret. The pre-
  commit gitleaks config catches accidental commits; the
  `tenant-operator-auth-002` and `tenant-operator-auth-003` rules
  enforce sanitisation in source.

## Step 7 — Run the build guards

```
make check          # gofmt + vet + lint + test-race
make manifests      # regenerate CRD if you added a Condition
make generate       # regenerate zz_generated.deepcopy if needed
```

Per the operator's AGENTS.md and the kubebuilder conventions, never
edit `config/crd/bases/*.yaml`, `config/rbac/role.yaml`, or
`zz_generated.*.go` by hand — they regenerate from the source types
plus markers.

## Step 8 — Smoke-test against a Kind cluster

```
make deploy-local                # deploys operator + daemon + dashboard
kubectl apply -f config/samples/tenant.yaml
kubectl wait --for=condition=Ready tenant/test-tenant --timeout=5m
```

Verify:

- Zitadel org created (`kubectl get tenant test-tenant -o jsonpath='{.status.zitadelOrgID}'`).
- FGA tuples present (call `fga query` against the FGA pod).
- Per-tenant data plane provisioned (see `data-plane.md`).
- Daemon admin RPC (the new SeedProviderBaseline) succeeded.

A CRD condition is the saga's source of truth — every provisioned
resource has one. Teardown reverses the conditions in order.
