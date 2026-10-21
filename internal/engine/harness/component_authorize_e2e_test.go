// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// unusedRegistry stands in for the component registry, which Authorize never
// reads. Any call to it panics, and the test shows it.
type unusedRegistry struct{ component.ComponentRegistry }

// TestComponentServiceAuthorize_RunsTheRealDecision runs the pull transport end
// to end: the real work queue and work-context registry over miniredis, the real
// ComponentService.Authorize, and the real HarnessCallbackService as the
// decision, with an in-memory FGA tuple set. It shows that both transports give
// the same answer, and that a shared component (system tenant) is decided for
// the tenant that owns the work item (D86).
func TestComponentServiceAuthorize_RunsTheRealDecision(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	az := newFGABackedAuthorizer()
	az.Seed("user:u-1", "can_execute", "component:tool/nmap")
	decision := newAuthorizeService(&stubRunAuthzLookup{state: &RunAuthzState{
		RunID: "run-1", MissionID: "mission-A", UserID: "u-1", TenantID: "tenant-alpha", Status: "active",
	}}, az)

	queue := component.NewRedisWorkQueue(sc.Client())
	svc := component.NewComponentServiceServer(unusedRegistry{}, queue, slog.New(slog.DiscardHandler), nil, nil, nil, nil).
		WithWorkContextRegistry(component.NewRedisWorkContextRegistry(sc)).
		WithRunAuthorizer(decision)

	_, err = queue.Enqueue(context.Background(), "tenant-alpha", "tool", "nmap", component.WorkItem{
		WorkID: "work-1", WorkType: "execute",
		Context: map[string]string{authz.AuthzContextWorkKey: `{"run_id":"run-1","issued_at":1,"ttl_seconds":600}`},
	})
	require.NoError(t, err)

	// The component claimed the work item, as PollWork records.
	registry := component.NewRedisWorkContextRegistry(sc)
	require.NoError(t, registry.BindWorkClaim(context.Background(), "work-1", e2eClaimant))

	ask := func(ctx context.Context, resource string) (*componentpb.AuthorizeResponse, error) {
		return svc.Authorize(withClaimant(ctx), &componentpb.AuthorizeRequest{WorkId: "work-1", Action: "execute", Resource: resource})
	}
	system := auth.ContextWithTenant(context.Background(), auth.SystemTenant)

	t.Run("the tenant of the work item is allowed", func(t *testing.T) {
		resp, err := ask(authzCtx("tenant-alpha"), "tool:nmap")
		require.NoError(t, err)
		assert.True(t, resp.GetAllowed())
		assert.Equal(t, "fga_allow", resp.GetReason())
	})
	t.Run("a shared component is decided for the owner tenant", func(t *testing.T) {
		resp, err := ask(system, "tool:nmap")
		require.NoError(t, err, "the system tenant must not meet NotFound")
		assert.True(t, resp.GetAllowed())
	})
	t.Run("a denial is an answer with allowed false", func(t *testing.T) {
		resp, err := ask(authzCtx("tenant-alpha"), "tool:sqlmap")
		require.NoError(t, err)
		assert.False(t, resp.GetAllowed())
	})
	t.Run("the run of the real binding reaches the decision", func(t *testing.T) {
		// A work item bound to another run is an unknown run for the store, which
		// answers only for run-1. If the binding were ignored this would be allowed.
		_, err := queue.Enqueue(context.Background(), "tenant-alpha", "tool", "nmap", component.WorkItem{
			WorkID: "work-2", WorkType: "execute",
			Context: map[string]string{authz.AuthzContextWorkKey: `{"run_id":"run-other","issued_at":1,"ttl_seconds":600}`},
		})
		require.NoError(t, err)
		require.NoError(t, registry.BindWorkClaim(context.Background(), "work-2", e2eClaimant))
		_, err = svc.Authorize(withClaimant(authzCtx("tenant-alpha")), &componentpb.AuthorizeRequest{
			WorkId: "work-2", Action: "execute", Resource: "tool:nmap",
		})
		assert.Equal(t, codes.NotFound, grpcCode(err))
	})
	t.Run("another tenant cannot use the work item", func(t *testing.T) {
		_, err := ask(authzCtx("tenant-beta"), "tool:nmap")
		assert.Equal(t, codes.PermissionDenied, grpcCode(err))
	})
}

// TestCallbackManager_RunAuthorizerIsTheCallbackService proves that the decision
// the daemon gives to ComponentService is the service of the callback server, so
// the wiring of the authz store and the FGA authorizer on the callback server
// reaches the pull transport as well.
func TestCallbackManager_RunAuthorizerIsTheCallbackService(t *testing.T) {
	m := NewCallbackManager(CallbackConfig{ServiceOptions: []CallbackServiceOption{testEventBus()}, Enabled: false}, slog.Default())
	require.NotNil(t, m.RunAuthorizer())
	assert.Same(t, m.server.Service(), m.RunAuthorizer())

	// A decision set on the manager is the decision of the run authorizer.
	az := newFGABackedAuthorizer()
	az.Seed("user:u-1", "can_execute", "component:tool/nmap")
	m.SetAuthzStore(&stubRunAuthzLookup{state: &RunAuthzState{RunID: "r", UserID: "u-1", TenantID: "t", Status: "active"}})
	m.SetComponentAuthorizer(az)
	allowed, _, err := m.RunAuthorizer().AuthorizeRun(context.Background(), "t", "r", "execute", "tool:nmap")
	require.NoError(t, err)
	assert.True(t, allowed)
}

// e2eClaimant is the principal that claimed the work items of these tests.
const e2eClaimant = "agent_principal:e2e"

// withClaimant adds the identity of the claimant to ctx and keeps its tenant.
func withClaimant(ctx context.Context) context.Context {
	tenant := auth.SystemTenant
	if name := auth.TenantStringFromContext(ctx); name != auth.SystemTenantString {
		tenant, _ = auth.NewTenantID(name)
	}
	return auth.WithIdentity(ctx, auth.Identity{Subject: e2eClaimant, Tenant: tenant})
}
