// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"strconv"
	"testing"
	"time"

	grpcmetadata "google.golang.org/grpc/metadata"

	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
	"github.com/zeroroot-ai/sdk/auth"
)

// The daemon requires the tenant header on the same rule ext-authz applies
// before it: only where the registry entry derives its object from the
// caller's tenant. The Platform owner has no tenant by design and
// administers the platform through system_tenant-derived RPCs.
func TestLooseModeForEntry_FollowsTheObjectDeriver(t *testing.T) {
	for deriver, loose := range map[string]bool{
		"tenant_from_identity":     false,
		"tenant_and_field('name')": false,
		"system_tenant":            true,
		"from_field('mission_id')": true,
		"component_from_identity":  true,
	} {
		if got := looseModeForEntry(registry.Entry{ObjectDeriver: deriver}); got != loose {
			t.Errorf("%s: loose = %v, want %v", deriver, got, loose)
		}
	}
	if !looseModeForEntry(registry.Entry{Self: true, ObjectDeriver: "tenant_from_identity"}) {
		t.Error("a self-mode entry stays loose")
	}
	if !looseModeForEntry(registry.Entry{Unauthenticated: true}) {
		t.Error("an unauthenticated entry stays loose")
	}
}

func tenantlessOwnerMD() grpcmetadata.MD {
	return grpcmetadata.Pairs(
		auth.HeaderSubject, "392987811122249774",
		auth.HeaderIssuer, string(auth.IssuerOIDC),
		auth.HeaderCredentialType, string(auth.CredentialOIDCUser),
		auth.HeaderTenant, "",
		auth.HeaderIssuedAt, strconv.FormatInt(time.Now().Unix(), 10),
	)
}

// The real registry: AdminProvisionTenant (platform_owner on the system
// tenant) resolves a tenantless Platform owner into an identity with the
// zero tenant; ListMissions (member on the caller's tenant) does not, and
// falls through to the strict interceptor, which refuses the empty header.
func TestResolveLooseOrBypassIdentity_SystemTenantRPCAcceptsNoTenant(t *testing.T) {
	noBypass := func(ctx context.Context, _ string) (context.Context, bool, error) { return ctx, false, nil }
	ctx := grpcmetadata.NewIncomingContext(context.Background(), tenantlessOwnerMD())

	const provision = "/gibson.tenant.v1.AdminTenantService/AdminProvisionTenant"
	if e, ok := registry.Registry[provision]; !ok || e.ObjectDeriver != "system_tenant" {
		t.Fatalf("registry entry for %s = %+v, want a system_tenant rule", provision, e)
	}
	gotCtx, ok, err := resolveLooseOrBypassIdentity(ctx, provision, noBypass)
	if err != nil || !ok {
		t.Fatalf("AdminProvisionTenant without a tenant header: ok=%v err=%v, want resolved", ok, err)
	}
	id, err := auth.IdentityFromContext(gotCtx)
	if err != nil || id.Subject != "392987811122249774" || !id.Tenant.IsZero() {
		t.Fatalf("identity = %+v (err %v), want the owner's subject with the zero tenant", id, err)
	}

	const list = "/gibson.daemon.v1.DaemonService/ListMissions"
	if e, ok := registry.Registry[list]; !ok || e.ObjectDeriver != "tenant_from_identity" {
		t.Fatalf("registry entry for %s = %+v, want a tenant_from_identity rule", list, e)
	}
	if _, ok, err := resolveLooseOrBypassIdentity(ctx, list, noBypass); ok || err != nil {
		t.Fatalf("ListMissions without a tenant header: ok=%v err=%v, want the strict path", ok, err)
	}
	if _, err := auth.IdentityFromMetadata(tenantlessOwnerMD()); err == nil {
		t.Fatalf("the strict parser must refuse the empty tenant header")
	}
}
