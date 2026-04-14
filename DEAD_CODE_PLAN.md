# Dead Code Removal Plan

This document enumerates daemon + SDK code that will be deleted once the
`gibson-tenant-operator` (spec: `tenant-control-plane-foundation`) and its
sister specs (`tenant-lifecycle-flows`, `agent-enrollment-crd`,
`component-grant-crd`, `dashboard-crd-migration`) are all shipped.

The code listed here is currently **deprecated but functional**. It
cannot be deleted before `dashboard-crd-migration` lands because the
dashboard still calls these RPCs for user-facing flows.

## Removal Gate

All of these must be true before any file on this list is deleted:

1. `gibson-tenant-operator` deployed and green in staging
2. `tenant-lifecycle-flows` saga steps ship and handle signup/invite/teardown end-to-end
3. `dashboard-crd-migration` ships and the dashboard calls K8s API instead of these RPCs
4. `gibson_dashboard_legacy_call_total` metric reports zero for 7 consecutive days in production
5. No non-dashboard consumer (CLI, e2e, external scripts) still calls these RPCs

Until all five are true, nothing on this list is removed. Removal PRs
must cite this checklist in their description.

## RPCs Scheduled for Deletion

Defined in `internal/daemon/api/gibson/daemon/v1/daemon.proto`:

| RPC | Replacement | Handler |
|-----|-------------|---------|
| `CreateTenant` | Apply `Tenant` CRD | `server.go:CreateTenant` |
| `GetTenant` | `kubectl get tenant` / K8s GET | `server.go:GetTenant` |
| `ListTenants` | `kubectl get tenants` / K8s LIST | `server.go:ListTenants` |
| `UpdateTenant` | `kubectl patch tenant` / K8s PATCH | `server.go:UpdateTenant` |
| `DeleteTenant` | `kubectl delete tenant` / K8s DELETE | `server.go:DeleteTenant` |
| `ProvisionTenant` | Tenant CRD reconciler saga | `server.go:ProvisionTenant` |
| `DeprovisionTenant` | Tenant CRD finalizer saga | `server.go:DeprovisionTenant` |
| `UpdateTenantBilling` | Stripe webhook → Tenant CRD patch | `server.go:UpdateTenantBilling` |
| `GetTenantBilling` | Read from Tenant CRD status | `server.go:GetTenantBilling` |

**Retained** (not on this list): `GetTenantLangfuseCredentials`,
`DeleteTenantLangfuseCredentials`, `GetTenantByStripeCustomerId`,
`GetTenantByEmail`, `ListTenantMembers` — still needed by dashboard and
Stripe webhook runtime paths. May eventually move to K8s-API-backed
equivalents but out of scope for this plan.

## Internal Packages Scheduled for Deletion

| Path | Reason | Replacement |
|------|--------|-------------|
| `internal/provisioner/provisioner.go` | Multi-step tenant provisioning | Operator saga (`tenant-lifecycle-flows`) |
| `internal/provisioner/signup_handlers.go` | Dashboard signup webhook handlers | Dashboard creates Tenant CRD directly (`dashboard-crd-migration`) |
| `internal/provisioner/provisioner_test.go` | Tests for removed code | — |
| `internal/provisioner/signup_handlers_test.go` | Tests for removed code | — |
| `internal/component/tenant_service.go` | Tenant CRUD backed by Redis | K8s API on Tenant CRD |
| `internal/component/tenant_service_test.go` | Tests for removed code | — |
| `internal/daemon/onboarding/*` (if present) | In-daemon onboarding state | Tenant CRD `status.phase` |

## SDK Packages to Audit at Deletion Time

These may or may not have removable code; audit before deletion PR:

- `core/sdk/tenantprovision/` (if exists) — tenant provisioning client helpers
- Any dashboard admin client wrappers in SDK that target removed RPCs

Run at deletion time:

```bash
# Confirm dashboard stopped using these
grep -r "CreateTenant\|ProvisionTenant\|DeprovisionTenant" enterprise/dashboard/src/

# Confirm no other consumer
grep -r "CreateTenant\|ProvisionTenant\|DeprovisionTenant" core/gibson/cmd/ core/gibson/tests/ core/sdk/
```

Both must return zero matches outside test fixtures / historical docs.

## E2E Tests to Migrate or Delete

`core/gibson/tests/e2e/provisioning_test.go` and
`core/gibson/tests/e2e/multi_tenant_test.go` currently exercise these
RPCs. At deletion time they should either:

- Be rewritten to apply `Tenant` CRDs via the K8s API, OR
- Be deleted in favor of the operator's E2E suite
  (`core/tenant-operator/test/e2e/kind_test.sh`)

## Checklist for the Deletion PR

- [ ] All five removal gates satisfied (see top of this doc)
- [ ] Deleted proto RPCs and regenerated Go via `buf generate`
- [ ] Deleted server handler functions
- [ ] Deleted internal packages listed above
- [ ] Deleted or migrated E2E tests
- [ ] Updated PR description with full file/function deletion list
- [ ] `make check` passes
- [ ] `gibson_dashboard_legacy_call_total` metric confirmed zero for 7d

## History

Created 2026-04-14 alongside `tenant-control-plane-foundation`
implementation. Deprecation comments added to:
- `CreateTenant`
- `UpdateTenant`
- `DeleteTenant`
- `ProvisionTenant`
- `DeprovisionTenant`
