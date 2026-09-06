// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// fakeTargetGetter is a minimal targetGetter for resolution tests.
type fakeTargetGetter struct {
	byID map[types.ID]*types.Target
}

func (f fakeTargetGetter) Get(_ context.Context, id types.ID) (*types.Target, error) {
	return f.byID[id], nil
}

func TestResolveTargetUUID(t *testing.T) {
	owned := &types.Target{ID: types.NewID(), Name: "prod-web", TenantID: "tenant-a", URL: "https://prod"}
	legacy := &types.Target{ID: types.NewID(), Name: "legacy", TenantID: ""}
	store := fakeTargetGetter{byID: map[types.ID]*types.Target{
		owned.ID:  owned,
		legacy.ID: legacy,
	}}
	missingUUID := types.NewID().String()

	t.Run("non-UUID is invalid argument, never name-resolved", func(t *testing.T) {
		_, err := resolveTargetUUID(context.Background(), store, "scanme.nmap.org", "tenant-a")
		if err == nil || !strings.Contains(err.Error(), "invalid target_id") {
			t.Fatalf("want invalid target_id error, got %v", err)
		}
	})

	t.Run("valid UUID for own tenant resolves", func(t *testing.T) {
		got, err := resolveTargetUUID(context.Background(), store, owned.ID.String(), "tenant-a")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != owned.ID {
			t.Fatalf("want %s, got %s", owned.ID, got.ID)
		}
	})

	t.Run("valid UUID not in store is not found", func(t *testing.T) {
		_, err := resolveTargetUUID(context.Background(), store, missingUUID, "tenant-a")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("want not found error, got %v", err)
		}
	})

	t.Run("cross-tenant access is not found", func(t *testing.T) {
		_, err := resolveTargetUUID(context.Background(), store, owned.ID.String(), "tenant-b")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("want not found error for cross-tenant, got %v", err)
		}
	})

	t.Run("system caller bypasses tenant check", func(t *testing.T) {
		_, err := resolveTargetUUID(context.Background(), store, owned.ID.String(), auth.SystemTenant.String())
		if err != nil {
			t.Fatalf("system caller should resolve any target, got %v", err)
		}
	})

	t.Run("target with no stamped tenant is not found for a tenant caller", func(t *testing.T) {
		// The target store is daemon-wide and keyed by UUID alone, so an
		// unstamped row must not be resolvable by whichever tenant happens to
		// know the id. CreateTarget always stamps the tenant, so this shape is
		// malformed data rather than a supported legacy case.
		_, err := resolveTargetUUID(context.Background(), store, legacy.ID.String(), "tenant-b")
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("want not found error for an unstamped target, got %v", err)
		}
	})

	t.Run("target with no stamped tenant still resolves for the system caller", func(t *testing.T) {
		got, err := resolveTargetUUID(context.Background(), store, legacy.ID.String(), auth.SystemTenant.String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != legacy.ID {
			t.Fatalf("want %s, got %s", legacy.ID, got.ID)
		}
	})
}

// TestResolveTargetCallerTenant pins the actual enforcement of the "system
// tenant has no wire path" invariant: a context with NO tenant must resolve
// to "" — never to auth.SystemTenant.String() — so it can never satisfy
// resolveTargetUUID's system-tenant exemption. Only a context carrying an
// EXPLICITLY-constructed auth.SystemTenant identity may reach that branch.
func TestResolveTargetCallerTenant(t *testing.T) {
	t.Run("no identity on context yields empty, not SystemTenant", func(t *testing.T) {
		got := resolveTargetCallerTenant(context.Background())
		if got != "" {
			t.Fatalf("want empty string for a tenant-less context, got %q", got)
		}
		if got == auth.SystemTenant.String() {
			t.Fatal("a tenant-less context must never resolve to the system tenant")
		}
	})

	t.Run("identity present but tenant unset (looseIdentityFromMD / spiffePlatformBypass shape) yields empty", func(t *testing.T) {
		// Mirrors what grpc.go's looseIdentityFromMD and spiffePlatformBypass
		// actually construct: an Identity with Subject/Issuer/CredentialType
		// set and Tenant left at its zero value.
		ctx := auth.WithIdentity(context.Background(), auth.Identity{
			Subject: "some-caller",
			Issuer:  auth.IssuerOIDC,
		})
		got := resolveTargetCallerTenant(ctx)
		if got != "" {
			t.Fatalf("want empty string for a zero-value tenant, got %q", got)
		}
	})

	t.Run("real tenant on context is passed through", func(t *testing.T) {
		ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("tenant-a"))
		got := resolveTargetCallerTenant(ctx)
		if got != "tenant-a" {
			t.Fatalf("want %q, got %q", "tenant-a", got)
		}
	})

	t.Run("explicit SystemTenant identity is passed through", func(t *testing.T) {
		ctx := auth.WithTenant(context.Background(), auth.SystemTenant)
		got := resolveTargetCallerTenant(ctx)
		if got != auth.SystemTenant.String() {
			t.Fatalf("want %q, got %q", auth.SystemTenant.String(), got)
		}
	})

	t.Run("end to end: a tenant-less context is rejected by resolveTargetUUID, not exempted", func(t *testing.T) {
		owned := &types.Target{ID: types.NewID(), Name: "prod-web", TenantID: "tenant-a"}
		s := fakeTargetGetter{byID: map[types.ID]*types.Target{owned.ID: owned}}

		ctx := context.Background() // no identity at all
		_, err := resolveTargetUUID(ctx, s, owned.ID.String(), resolveTargetCallerTenant(ctx))
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("want not-found for a tenant-less caller (must NOT be treated as the system tenant), got %v", err)
		}
	})
}
