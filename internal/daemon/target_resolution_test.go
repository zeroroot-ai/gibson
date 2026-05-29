package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/types"
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

	t.Run("legacy target with no tenant resolves for any caller", func(t *testing.T) {
		got, err := resolveTargetUUID(context.Background(), store, legacy.ID.String(), "tenant-b")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.ID != legacy.ID {
			t.Fatalf("want %s, got %s", legacy.ID, got.ID)
		}
	})
}
