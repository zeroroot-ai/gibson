package component

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

// newTestRegistry creates a RedisComponentRegistry backed by a fresh miniredis
// instance. The miniredis server and its cleanup are managed by t.Cleanup.
func newTestRegistry(t *testing.T) (*RedisComponentRegistry, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { _ = client.Close() })

	reg := NewRedisComponentRegistry(client, 5*time.Second)
	return reg, mr
}

// componentNames extracts the Name field from a slice of ComponentInfo for
// easier assertion in table-driven tests.
func componentNames(infos []ComponentInfo) []string {
	names := make([]string, 0, len(infos))
	for _, info := range infos {
		names = append(names, info.Name)
	}
	sort.Strings(names)
	return names
}

// componentInstanceIDs extracts all InstanceID values, sorted.
func componentInstanceIDs(infos []ComponentInfo) []string {
	ids := make([]string, 0, len(infos))
	for _, info := range infos {
		ids = append(ids, info.InstanceID)
	}
	sort.Strings(ids)
	return ids
}

// ---------------------------------------------------------------------------
// Register + Discover round-trip
// ---------------------------------------------------------------------------

func TestRedisRegistry_RegisterAndDiscover(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	instanceID, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{
		Version: "1.0.0",
		Metadata: map[string]string{
			"region": "us-east-1",
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, instanceID)

	infos, err := reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	require.Len(t, infos, 1)

	info := infos[0]
	assert.Equal(t, instanceID, info.InstanceID)
	assert.Equal(t, "acme", info.TenantID)
	assert.Equal(t, "agent", info.Kind)
	assert.Equal(t, "scanner", info.Name)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, "us-east-1", info.Metadata["region"])
	assert.False(t, info.StartedAt.IsZero(), "StartedAt should be populated")
	assert.False(t, info.LastHeartbeat.IsZero(), "LastHeartbeat should be populated")
}

// Register always generates a fresh instance ID; any caller-supplied ID is
// replaced.
func TestRedisRegistry_Register_InstanceIDIgnored(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	callerID := "caller-supplied-id"
	returnedID, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{
		InstanceID: callerID,
	})
	require.NoError(t, err)
	assert.NotEqual(t, callerID, returnedID, "Register must override caller-supplied InstanceID")

	infos, err := reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, returnedID, infos[0].InstanceID)
}

// Multiple calls to Register for the same component create independent
// instances, each with a unique ID.
func TestRedisRegistry_Register_MultipleInstances(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	const n = 3
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{Version: "1.0.0"})
		require.NoError(t, err)
		ids = append(ids, id)
	}

	// All instance IDs must be unique.
	seen := make(map[string]struct{}, n)
	for _, id := range ids {
		require.NotContains(t, seen, id, "duplicate instance ID generated")
		seen[id] = struct{}{}
	}

	infos, err := reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	assert.Len(t, infos, n)
}

// ---------------------------------------------------------------------------
// TTL expiry removes entries
// ---------------------------------------------------------------------------

func TestRedisRegistry_TTLExpiry_RemovesEntry(t *testing.T) {
	reg, mr := newTestRegistry(t)
	ctx := context.Background()

	// Use a very short TTL: 2 seconds on the registry.
	reg.defaultTTL = 2 * time.Second

	_, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)

	// Entry should be present before expiry.
	infos, err := reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	assert.Len(t, infos, 1, "entry should exist before TTL expiry")

	// Fast-forward miniredis clock past the TTL.
	mr.FastForward(3 * time.Second)

	// Entry should have been evicted by TTL.
	infos, err = reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	assert.Empty(t, infos, "entry should be gone after TTL expiry")
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

func TestRedisRegistry_TenantIsolation(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	// Register the same kind/name under two different tenants.
	_, err := reg.Register(ctx, "tenant-a", "agent", "scanner", ComponentInfo{Version: "1.0.0"})
	require.NoError(t, err)

	_, err = reg.Register(ctx, "tenant-b", "agent", "scanner", ComponentInfo{Version: "2.0.0"})
	require.NoError(t, err)

	// Tenant A must only see its own entry.
	aInfos, err := reg.Discover(ctx, "tenant-a", "agent", "scanner")
	require.NoError(t, err)
	require.Len(t, aInfos, 1)
	assert.Equal(t, "tenant-a", aInfos[0].TenantID)

	// Tenant B must only see its own entry.
	bInfos, err := reg.Discover(ctx, "tenant-b", "agent", "scanner")
	require.NoError(t, err)
	require.Len(t, bInfos, 1)
	assert.Equal(t, "tenant-b", bInfos[0].TenantID)
}

// ---------------------------------------------------------------------------
// _system components visible to all tenants
// ---------------------------------------------------------------------------

func TestRedisRegistry_SystemComponentsVisibleToAllTenants(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	// Register a system-scoped component.
	sysID, err := reg.Register(ctx, systemTenant, "tool", "nmap", ComponentInfo{Version: "7.94"})
	require.NoError(t, err)

	// Register a tenant-scoped component for tenant-a.
	aID, err := reg.Register(ctx, "tenant-a", "tool", "custom-scan", ComponentInfo{Version: "1.0.0"})
	require.NoError(t, err)

	t.Run("SystemToolVisibleToTenantA", func(t *testing.T) {
		infos, err := reg.Discover(ctx, "tenant-a", "tool", "nmap")
		require.NoError(t, err)
		require.Len(t, infos, 1)
		assert.Equal(t, sysID, infos[0].InstanceID)
		assert.Equal(t, systemTenant, infos[0].TenantID)
	})

	t.Run("SystemToolVisibleToTenantB", func(t *testing.T) {
		infos, err := reg.Discover(ctx, "tenant-b", "tool", "nmap")
		require.NoError(t, err)
		require.Len(t, infos, 1)
		assert.Equal(t, sysID, infos[0].InstanceID)
	})

	t.Run("TenantScopedToolNotVisibleToTenantB", func(t *testing.T) {
		infos, err := reg.Discover(ctx, "tenant-b", "tool", "custom-scan")
		require.NoError(t, err)
		// tenant-b has no custom-scan, and _system has no custom-scan either.
		assert.Empty(t, infos)
	})

	t.Run("TenantScopedToolVisibleToTenantA", func(t *testing.T) {
		infos, err := reg.Discover(ctx, "tenant-a", "tool", "custom-scan")
		require.NoError(t, err)
		require.Len(t, infos, 1)
		assert.Equal(t, aID, infos[0].InstanceID)
	})
}

// Querying the _system tenant directly does not recurse and produce duplicates.
func TestRedisRegistry_Discover_SystemTenantNoDuplication(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	_, err := reg.Register(ctx, systemTenant, "tool", "nmap", ComponentInfo{})
	require.NoError(t, err)

	infos, err := reg.Discover(ctx, systemTenant, "tool", "nmap")
	require.NoError(t, err)
	assert.Len(t, infos, 1, "direct _system query must not duplicate results")
}

// ---------------------------------------------------------------------------
// Deregister removes entry
// ---------------------------------------------------------------------------

func TestRedisRegistry_Deregister(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	instanceID, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)

	// Entry should be present.
	infos, err := reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	require.Len(t, infos, 1)

	// Deregister the instance.
	err = reg.Deregister(ctx, "acme", "agent", "scanner", instanceID)
	require.NoError(t, err)

	// Entry should be gone.
	infos, err = reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	assert.Empty(t, infos)
}

// Deregistering a non-existent key returns ErrComponentNotFound.
func TestRedisRegistry_Deregister_NotFound(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	err := reg.Deregister(ctx, "acme", "agent", "scanner", "nonexistent-id")
	assert.ErrorIs(t, err, ErrComponentNotFound)
}

// Deregistering one instance does not affect sibling instances.
func TestRedisRegistry_Deregister_OnlyRemovesTargetInstance(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	id1, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)

	id2, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)

	err = reg.Deregister(ctx, "acme", "agent", "scanner", id1)
	require.NoError(t, err)

	infos, err := reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, id2, infos[0].InstanceID)
}

// ---------------------------------------------------------------------------
// RefreshTTL extends lifetime
// ---------------------------------------------------------------------------

func TestRedisRegistry_RefreshTTL_ExtendsLifetime(t *testing.T) {
	reg, mr := newTestRegistry(t)
	ctx := context.Background()

	reg.defaultTTL = 4 * time.Second

	instanceID, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)

	// Advance time to just before expiry.
	mr.FastForward(3 * time.Second)

	// Refresh the TTL before the key expires.
	err = reg.RefreshTTL(ctx, "acme", "agent", "scanner", instanceID)
	require.NoError(t, err)

	// Advance time past the original expiry but within the refreshed window.
	mr.FastForward(3 * time.Second)

	// Key should still be alive.
	infos, err := reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	assert.Len(t, infos, 1, "entry should survive past original TTL after refresh")

	// Advance time past the refreshed TTL.
	mr.FastForward(5 * time.Second)

	// Now the key should have expired.
	infos, err = reg.Discover(ctx, "acme", "agent", "scanner")
	require.NoError(t, err)
	assert.Empty(t, infos, "entry should be gone after refreshed TTL expires")
}

// RefreshTTL on a missing key returns ErrComponentNotFound.
func TestRedisRegistry_RefreshTTL_NotFound(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	err := reg.RefreshTTL(ctx, "acme", "agent", "scanner", "nonexistent-id")
	assert.ErrorIs(t, err, ErrComponentNotFound)
}

// RefreshTTL on an already-expired key returns ErrComponentNotFound.
func TestRedisRegistry_RefreshTTL_AfterExpiry(t *testing.T) {
	reg, mr := newTestRegistry(t)
	ctx := context.Background()

	reg.defaultTTL = 2 * time.Second

	instanceID, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)

	mr.FastForward(3 * time.Second)

	err = reg.RefreshTTL(ctx, "acme", "agent", "scanner", instanceID)
	assert.ErrorIs(t, err, ErrComponentNotFound)
}

// ---------------------------------------------------------------------------
// DiscoverAll returns all components of a kind (tenant + _system)
// ---------------------------------------------------------------------------

func TestRedisRegistry_DiscoverAll(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	// Register multiple agents for tenant-a.
	_, err := reg.Register(ctx, "tenant-a", "agent", "recon", ComponentInfo{})
	require.NoError(t, err)
	_, err = reg.Register(ctx, "tenant-a", "agent", "exploit", ComponentInfo{})
	require.NoError(t, err)

	// Register an agent for tenant-b (should not appear in tenant-a results).
	_, err = reg.Register(ctx, "tenant-b", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)

	// Register a system-scoped agent (should appear for all tenants).
	_, err = reg.Register(ctx, systemTenant, "agent", "orchestrator", ComponentInfo{})
	require.NoError(t, err)

	// Register a tool under tenant-a (different kind, should not appear).
	_, err = reg.Register(ctx, "tenant-a", "tool", "nmap", ComponentInfo{})
	require.NoError(t, err)

	infos, err := reg.DiscoverAll(ctx, "tenant-a", "agent")
	require.NoError(t, err)

	names := componentNames(infos)
	assert.Equal(t, []string{"exploit", "orchestrator", "recon"}, names)
}

// DiscoverAll for the _system tenant does not double-count.
func TestRedisRegistry_DiscoverAll_SystemTenantNoDuplication(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	_, err := reg.Register(ctx, systemTenant, "agent", "orchestrator", ComponentInfo{})
	require.NoError(t, err)
	_, err = reg.Register(ctx, systemTenant, "agent", "planner", ComponentInfo{})
	require.NoError(t, err)

	infos, err := reg.DiscoverAll(ctx, systemTenant, "agent")
	require.NoError(t, err)
	assert.Len(t, infos, 2)
}

// DiscoverAll returns an empty slice when no matching components exist.
func TestRedisRegistry_DiscoverAll_Empty(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	infos, err := reg.DiscoverAll(ctx, "nobody", "agent")
	require.NoError(t, err)
	assert.Empty(t, infos)
}

// ---------------------------------------------------------------------------
// ListTenantComponents returns only that tenant's components
// ---------------------------------------------------------------------------

func TestRedisRegistry_ListTenantComponents(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	// Register a variety of kinds and names under tenant-a.
	_, err := reg.Register(ctx, "tenant-a", "agent", "recon", ComponentInfo{})
	require.NoError(t, err)
	_, err = reg.Register(ctx, "tenant-a", "tool", "nmap", ComponentInfo{})
	require.NoError(t, err)
	_, err = reg.Register(ctx, "tenant-a", "plugin", "reporter", ComponentInfo{})
	require.NoError(t, err)

	// Register under tenant-b — should not appear for tenant-a.
	_, err = reg.Register(ctx, "tenant-b", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)

	// Register system component — should not appear in ListTenantComponents
	// because it lives under _system, not tenant-a.
	_, err = reg.Register(ctx, systemTenant, "agent", "orchestrator", ComponentInfo{})
	require.NoError(t, err)

	infos, err := reg.ListTenantComponents(ctx, "tenant-a")
	require.NoError(t, err)

	// Only the three tenant-a entries should be returned.
	assert.Len(t, infos, 3)

	// All returned entries must belong to tenant-a.
	for _, info := range infos {
		assert.Equal(t, "tenant-a", info.TenantID,
			"unexpected tenantID %q in ListTenantComponents result", info.TenantID)
	}

	names := componentNames(infos)
	assert.Equal(t, []string{"nmap", "recon", "reporter"}, names)
}

// ListTenantComponents returns an empty slice for a tenant with no registrations.
func TestRedisRegistry_ListTenantComponents_Empty(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	infos, err := reg.ListTenantComponents(ctx, "ghost-tenant")
	require.NoError(t, err)
	assert.Empty(t, infos)
}

// ListTenantComponents respects multi-instance registrations correctly.
func TestRedisRegistry_ListTenantComponents_MultipleInstances(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	// Two instances of the same component under the same tenant.
	id1, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)
	id2, err := reg.Register(ctx, "acme", "agent", "scanner", ComponentInfo{})
	require.NoError(t, err)

	infos, err := reg.ListTenantComponents(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, infos, 2)

	gotIDs := componentInstanceIDs(infos)
	wantIDs := []string{id1, id2}
	sort.Strings(wantIDs)
	assert.Equal(t, wantIDs, gotIDs)
}

// ---------------------------------------------------------------------------
// NewRedisComponentRegistry — constructor edge cases
// ---------------------------------------------------------------------------

func TestNewRedisComponentRegistry_DefaultTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	// Passing zero TTL should fall back to defaultRegistryTTL.
	reg := NewRedisComponentRegistry(client, 0)
	assert.Equal(t, defaultRegistryTTL, reg.defaultTTL)
}

func TestNewRedisComponentRegistry_NegativeTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	reg := NewRedisComponentRegistry(client, -1*time.Second)
	assert.Equal(t, defaultRegistryTTL, reg.defaultTTL)
}

func TestNewRedisComponentRegistry_CustomTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	reg := NewRedisComponentRegistry(client, 2*time.Minute)
	assert.Equal(t, 2*time.Minute, reg.defaultTTL)
}

// ---------------------------------------------------------------------------
// Key scheme helpers
// ---------------------------------------------------------------------------

func TestInstanceKey(t *testing.T) {
	tests := []struct {
		tenant, kind, name, instanceID string
		want                           string
	}{
		{
			tenant:     "acme",
			kind:       "agent",
			name:       "scanner",
			instanceID: "abc-123",
			want:       "component:acme:agent:scanner:abc-123",
		},
		{
			tenant:     systemTenant,
			kind:       "tool",
			name:       "nmap",
			instanceID: "def-456",
			want:       "component:_system:tool:nmap:def-456",
		},
	}

	for _, tt := range tests {
		got := instanceKey(tt.tenant, tt.kind, tt.name, tt.instanceID)
		assert.Equal(t, tt.want, got)
	}
}

func TestScanPattern(t *testing.T) {
	tests := []struct {
		tenant, kind, name, instanceID string
		want                           string
	}{
		{
			tenant:     "acme",
			kind:       "agent",
			name:       "scanner",
			instanceID: "*",
			want:       "component:acme:agent:scanner:*",
		},
		{
			tenant:     "acme",
			kind:       "agent",
			name:       "*",
			instanceID: "*",
			want:       "component:acme:agent:*:*",
		},
		{
			tenant:     "acme",
			kind:       "*",
			name:       "*",
			instanceID: "*",
			want:       "component:acme:*:*:*",
		},
	}

	for _, tt := range tests {
		got := scanPattern(tt.tenant, tt.kind, tt.name, tt.instanceID)
		assert.Equal(t, tt.want, got)
	}
}

// TestComponentInfo_LegacyEntryRoundTrip ensures a pre-spec-era plugin/agent
// entry (no new dispatch fields) round-trips through JSON cleanly — no errors
// on unmarshal, no zero-value spam on marshal (thanks to omitempty tags).
func TestComponentInfo_LegacyEntryRoundTrip(t *testing.T) {
	legacy := []byte(`{
		"kind": "plugin",
		"name": "slack-notifier",
		"version": "1.2.0",
		"instance_id": "uuid-1",
		"tenant_id": "acme",
		"metadata": {"endpoint": "localhost:5001"},
		"started_at": "2026-04-17T00:00:00Z",
		"last_heartbeat": "2026-04-17T00:00:30Z"
	}`)

	var info ComponentInfo
	require.NoError(t, json.Unmarshal(legacy, &info))
	assert.Equal(t, "plugin", info.Kind)
	assert.Equal(t, "slack-notifier", info.Name)
	assert.Equal(t, componentpb.DispatchMode_DISPATCH_MODE_UNSPECIFIED, info.DispatchMode,
		"legacy entries have no dispatch_mode field; must decode to UNSPECIFIED")
	assert.Empty(t, info.Image)
	assert.Empty(t, info.Command)
	assert.Equal(t, int32(0), info.Resources.VCPU)

	out, err := json.Marshal(info)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "dispatch_mode")
	assert.NotContains(t, string(out), `"image"`)
}

// TestComponentInfo_SandboxedEntryRoundTrip verifies a sandboxed-tool entry
// carries all new fields through marshal/unmarshal without loss.
func TestComponentInfo_SandboxedEntryRoundTrip(t *testing.T) {
	orig := ComponentInfo{
		Kind:          "tool",
		Name:          "nmap",
		Version:       "0.1.0",
		InstanceID:    "catalog",
		TenantID:      "_system",
		Metadata:      map[string]string{"source": "gibson-tool-runner"},
		StartedAt:     time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC),
		LastHeartbeat: time.Date(2026, 4, 17, 12, 5, 0, 0, time.UTC),
		DispatchMode:  componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED,
		Image:         "ghcr.io/zeroroot-ai/gibson-tool-runner@sha256:deadbeef",
		Command:       []string{"/gibson-runner"},
		Env:           map[string]string{"GIBSON_TOOL_NAME": "nmap"},
		Resources: SandboxResources{
			VCPU:   2,
			Memory: "512Mi",
		},
		DefaultTimeoutSeconds: 300,
		InputSchemaJSON:       []byte(`{"type":"object","properties":{"target":{"type":"string"}}}`),
		OutputProtoType:       "gibson.tool.nmap.v1.ExecuteResponse",
		DefaultParseQuality:   componentpb.ParseQuality_PARSE_QUALITY_STRUCTURED,
		Description:           "TCP/UDP port scanner with service/OS detection.",
		Tags:                  []string{"recon", "network"},
	}

	raw, err := json.Marshal(orig)
	require.NoError(t, err)

	var got ComponentInfo
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, orig.DispatchMode, got.DispatchMode)
	assert.Equal(t, orig.Image, got.Image)
	assert.Equal(t, orig.Command, got.Command)
	assert.Equal(t, orig.Env, got.Env)
	assert.Equal(t, orig.Resources, got.Resources)
	assert.Equal(t, orig.DefaultTimeoutSeconds, got.DefaultTimeoutSeconds)
	assert.Equal(t, orig.InputSchemaJSON, got.InputSchemaJSON)
	assert.Equal(t, orig.OutputProtoType, got.OutputProtoType)
	assert.Equal(t, orig.DefaultParseQuality, got.DefaultParseQuality)
	assert.Equal(t, orig.Description, got.Description)
	assert.Equal(t, orig.Tags, got.Tags)
}
