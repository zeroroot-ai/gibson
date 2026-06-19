package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/brain"
	worldpb "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestWorldService_TenantScopedRead: the read path returns the caller's tenant's
// live World, and refuses a request with no tenant in context.
func TestWorldService_TenantScopedRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)

	reg.For("acme").Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	var resp *worldpb.ListHostsResponse
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		if resp, err = srv.ListHosts(tctx, &worldpb.ListHostsRequest{}); err != nil {
			t.Fatalf("ListHosts: %v", err)
		}
		if len(resp.Hosts) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(resp.GetHosts()) != 1 || resp.Hosts[0].Address != "10.0.0.5" {
		t.Fatalf("ListHosts = %+v, want one host 10.0.0.5", resp.GetHosts())
	}

	// No tenant in context -> PermissionDenied.
	if _, err := srv.ListHosts(context.Background(), &worldpb.ListHostsRequest{}); err == nil {
		t.Fatal("expected an error when no tenant is in context")
	}
}
