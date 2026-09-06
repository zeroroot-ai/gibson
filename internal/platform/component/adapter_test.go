// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// resolveTenant
// ---------------------------------------------------------------------------

func TestResolveTenant_FromContext(t *testing.T) {
	reg, _ := newTestRegistry(t)
	adapter := NewRegistryAdapter(reg)

	ctx := auth.ContextWithTenantString(context.Background(), "acme-corp")
	got, err := adapter.resolveTenant(ctx)
	require.NoError(t, err)
	assert.Equal(t, "acme-corp", got)
}

// A query with no tenant is refused. It used to resolve to the adapter's
// configured tenant — "default" in the daemon — which is a shared namespace, not
// anybody's tenant: every caller that arrived without an identity was served out
// of the same bucket and the query looked successful.
func TestResolveTenant_RefusesAnAbsentTenant(t *testing.T) {
	reg, _ := newTestRegistry(t)
	adapter := NewRegistryAdapter(reg)

	_, err := adapter.resolveTenant(context.Background())
	require.ErrorIs(t, err, ErrNoTenantInContext)
}

func TestResolveTenant_RefusesAnEmptyContextTenant(t *testing.T) {
	reg, _ := newTestRegistry(t)
	adapter := NewRegistryAdapter(reg)

	ctx := auth.ContextWithTenantString(context.Background(), "")
	_, err := adapter.resolveTenant(ctx)
	require.ErrorIs(t, err, ErrNoTenantInContext)
}

// The _system sentinel means "no identity resolved", not a tenant. Accepting it
// would reopen the same hole under a different name.
func TestResolveTenant_RefusesTheSystemSentinel(t *testing.T) {
	reg, _ := newTestRegistry(t)
	adapter := NewRegistryAdapter(reg)

	ctx := auth.ContextWithTenantString(context.Background(), auth.SystemTenantString)
	_, err := adapter.resolveTenant(ctx)
	require.ErrorIs(t, err, ErrNoTenantInContext)
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

	adapter := NewRegistryAdapter(reg)

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

	adapter := NewRegistryAdapter(reg)

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

// Every discovery entry point refuses a query with no tenant, rather than
// answering it out of a shared namespace. The registry has components in it, so
// a fallback would have returned them.
func TestDiscoveryRefusesEveryQueryWithNoTenant(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	for _, kind := range []string{"agent", "tool", "plugin"} {
		_, err := reg.Register(ctx, "default", kind, "shared-"+kind, ComponentInfo{
			Version:  "1.0.0",
			Metadata: map[string]string{"grpc_endpoint": "localhost:9001"},
		})
		require.NoError(t, err)
	}

	adapter := NewRegistryAdapter(reg)

	t.Run("ListAgents", func(t *testing.T) {
		got, err := adapter.ListAgents(ctx)
		require.ErrorIs(t, err, ErrNoTenantInContext)
		assert.Empty(t, got)
	})
	t.Run("ListTools", func(t *testing.T) {
		got, err := adapter.ListTools(ctx)
		require.ErrorIs(t, err, ErrNoTenantInContext)
		assert.Empty(t, got)
	})
	t.Run("ListPlugins", func(t *testing.T) {
		got, err := adapter.ListPlugins(ctx)
		require.ErrorIs(t, err, ErrNoTenantInContext)
		assert.Empty(t, got)
	})
	t.Run("DiscoverAgent", func(t *testing.T) {
		got, err := adapter.DiscoverAgent(ctx, "shared-agent")
		require.ErrorIs(t, err, ErrNoTenantInContext)
		assert.Nil(t, got)
	})
	t.Run("DiscoverTool", func(t *testing.T) {
		got, err := adapter.DiscoverTool(ctx, "shared-tool")
		require.ErrorIs(t, err, ErrNoTenantInContext)
		assert.Nil(t, got)
	})
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

	adapter := NewRegistryAdapter(reg)

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

	adapter := NewRegistryAdapter(reg)

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
