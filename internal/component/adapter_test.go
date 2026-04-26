package component

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// resolveTenant
// ---------------------------------------------------------------------------

func TestResolveTenant_FromContext(t *testing.T) {
	reg, _ := newTestRegistry(t)
	adapter := NewRegistryAdapter(reg, "default-tenant")

	ctx := auth.ContextWithTenantString(context.Background(), "acme-corp")
	got := adapter.resolveTenant(ctx)
	assert.Equal(t, "acme-corp", got)
}

func TestResolveTenant_Fallback(t *testing.T) {
	reg, _ := newTestRegistry(t)
	adapter := NewRegistryAdapter(reg, "default-tenant")

	got := adapter.resolveTenant(context.Background())
	assert.Equal(t, "default-tenant", got)
}

func TestResolveTenant_EmptyContextTenant(t *testing.T) {
	reg, _ := newTestRegistry(t)
	adapter := NewRegistryAdapter(reg, "default-tenant")

	// Empty string tenant in context should fall back
	ctx := auth.ContextWithTenantString(context.Background(), "")
	got := adapter.resolveTenant(ctx)
	assert.Equal(t, "default-tenant", got)
}

// ---------------------------------------------------------------------------
// ListAgents — tenant-aware
// ---------------------------------------------------------------------------

func TestListAgents_UsesContextTenant(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	// Register an agent under "acme-corp" tenant
	_, err := reg.Register(ctx, "acme-corp", "agent", "custom-scanner", ComponentInfo{
		Version:  "1.0.0",
		Metadata: map[string]string{"grpc_endpoint": "localhost:9001"},
	})
	require.NoError(t, err)

	// Register an agent under "_system" tenant
	_, err = reg.Register(ctx, "_system", "agent", "platform-agent", ComponentInfo{
		Version:  "2.0.0",
		Metadata: map[string]string{"grpc_endpoint": "localhost:9002"},
	})
	require.NoError(t, err)

	adapter := NewRegistryAdapter(reg, "wrong-tenant")

	// Query with acme-corp context — should see acme-corp + _system agents
	acmeCtx := auth.ContextWithTenantString(ctx, "acme-corp")
	agents, err := adapter.ListAgents(acmeCtx)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, a := range agents {
		names[a.Name] = true
	}
	assert.True(t, names["custom-scanner"], "should see acme-corp's custom-scanner")
	assert.True(t, names["platform-agent"], "should see _system's platform-agent")
}

func TestListAgents_OtherTenantCannotSeeAcme(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	// Register an agent under "acme-corp" only
	_, err := reg.Register(ctx, "acme-corp", "agent", "acme-private", ComponentInfo{
		Version:  "1.0.0",
		Metadata: map[string]string{"grpc_endpoint": "localhost:9001"},
	})
	require.NoError(t, err)

	// Register a _system agent
	_, err = reg.Register(ctx, "_system", "agent", "shared-agent", ComponentInfo{
		Version:  "1.0.0",
		Metadata: map[string]string{"grpc_endpoint": "localhost:9002"},
	})
	require.NoError(t, err)

	adapter := NewRegistryAdapter(reg, "default")

	// Query with other-corp context — should only see _system, NOT acme-corp
	otherCtx := auth.ContextWithTenantString(ctx, "other-corp")
	agents, err := adapter.ListAgents(otherCtx)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, a := range agents {
		names[a.Name] = true
	}
	assert.False(t, names["acme-private"], "other-corp should NOT see acme-corp's agent")
	assert.True(t, names["shared-agent"], "other-corp should see _system's agent")
}

func TestListAgents_FallbackWhenNoTenantInContext(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	// Register under the adapter's default tenant
	_, err := reg.Register(ctx, "default-tenant", "agent", "default-agent", ComponentInfo{
		Version:  "1.0.0",
		Metadata: map[string]string{"grpc_endpoint": "localhost:9001"},
	})
	require.NoError(t, err)

	adapter := NewRegistryAdapter(reg, "default-tenant")

	// No tenant in context — should fall back to "default-tenant"
	agents, err := adapter.ListAgents(ctx)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, a := range agents {
		names[a.Name] = true
	}
	assert.True(t, names["default-agent"], "fallback should find default-tenant's agent")
}

// ---------------------------------------------------------------------------
// ListTools — tenant-aware
// ---------------------------------------------------------------------------

func TestListTools_UsesContextTenant(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	_, err := reg.Register(ctx, "acme-corp", "tool", "custom-tool", ComponentInfo{
		Version:  "1.0.0",
		Metadata: map[string]string{"grpc_endpoint": "localhost:9001"},
	})
	require.NoError(t, err)

	_, err = reg.Register(ctx, "_system", "tool", "nmap", ComponentInfo{
		Version:  "1.0.0",
		Metadata: map[string]string{"grpc_endpoint": "localhost:9002"},
	})
	require.NoError(t, err)

	adapter := NewRegistryAdapter(reg, "wrong-tenant")

	acmeCtx := auth.ContextWithTenantString(ctx, "acme-corp")
	tools, err := adapter.ListTools(acmeCtx)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Name] = true
	}
	assert.True(t, names["custom-tool"], "should see acme-corp's custom-tool")
	assert.True(t, names["nmap"], "should see _system's nmap")
}

// ---------------------------------------------------------------------------
// ListPlugins — tenant-aware
// ---------------------------------------------------------------------------

func TestListPlugins_UsesContextTenant(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	_, err := reg.Register(ctx, "acme-corp", "plugin", "acme-jira", ComponentInfo{
		Version:  "1.0.0",
		Metadata: map[string]string{"grpc_endpoint": "localhost:9001"},
	})
	require.NoError(t, err)

	_, err = reg.Register(ctx, "_system", "plugin", "gitlab", ComponentInfo{
		Version:  "1.0.0",
		Metadata: map[string]string{"grpc_endpoint": "localhost:9002"},
	})
	require.NoError(t, err)

	adapter := NewRegistryAdapter(reg, "wrong-tenant")

	acmeCtx := auth.ContextWithTenantString(ctx, "acme-corp")
	plugins, err := adapter.ListPlugins(acmeCtx)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, p := range plugins {
		names[p.Name] = true
	}
	assert.True(t, names["acme-jira"], "should see acme-corp's acme-jira")
	assert.True(t, names["gitlab"], "should see _system's gitlab")
}
