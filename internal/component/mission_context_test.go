package component

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
	"github.com/zero-day-ai/gibson/internal/state"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestMissionContextResolver creates a MissionContextResolver backed by a
// fresh miniredis instance. Both the StateClient and TenantScopedStore are
// wired to the same miniredis so the test can inspect keys written by the
// resolver.
func newTestMissionContextResolver(t *testing.T) (*MissionContextResolver, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	ts := state.NewTenantScopedStore(sc, &state.TenantStoreConfig{
		AuthMode:      "enterprise",
		DefaultTenant: "default",
	})

	resolver := NewMissionContextResolver(sc, ts, nil)
	return resolver, mr
}

// writeWorkContext writes a work-item context hash into miniredis using the
// same key format as RegisterWorkContext, allowing tests to set up mappings
// directly without going through the MemoryResolver.
func writeWorkContext(t *testing.T, mr *miniredis.Miniredis, workID, missionID, tenantID string) {
	t.Helper()

	key := workContextKey(workID)
	mr.HSet(key, workContextMissionField, missionID)
	mr.HSet(key, workContextTenantField, tenantID)
	mr.SetTTL(key, workContextTTL)
}

// writeSlotOverrides JSON-encodes the SlotOverrides struct and stores it at
// the tenant-scoped key that ResolveMissionForWork reads.
func writeSlotOverrides(t *testing.T, mr *miniredis.Miniredis, tenant, missionID string, overrides SlotOverrides) {
	t.Helper()

	raw, err := json.Marshal(overrides)
	require.NoError(t, err)

	// Key format must match missionSlotOverridesKey + TenantScopedRedisKey
	key := auth.TenantScopedRedisKey(tenant, missionSlotOverridesKey(missionID))
	require.NoError(t, mr.Set(key, string(raw)))
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNewMissionContextResolver_PanicsOnNilStateClient(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	ts := state.NewTenantScopedStore(sc, nil)

	assert.Panics(t, func() {
		NewMissionContextResolver(nil, ts, nil)
	})
}

func TestNewMissionContextResolver_PanicsOnNilTenantStore(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	assert.Panics(t, func() {
		NewMissionContextResolver(sc, nil, nil)
	})
}

// ---------------------------------------------------------------------------
// ResolveMissionForWork: no context cases
// ---------------------------------------------------------------------------

func TestResolveMissionForWork_EmptyWorkIDReturnsEmpty(t *testing.T) {
	resolver, _ := newTestMissionContextResolver(t)
	ctx := context.Background()

	missionID, overrides, err := resolver.ResolveMissionForWork(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, missionID)
	assert.Nil(t, overrides)
}

func TestResolveMissionForWork_MissingWorkContextReturnsEmpty(t *testing.T) {
	resolver, _ := newTestMissionContextResolver(t)
	ctx := context.Background()

	missionID, overrides, err := resolver.ResolveMissionForWork(ctx, "nonexistent-work-id")
	require.NoError(t, err)
	assert.Empty(t, missionID)
	assert.Nil(t, overrides)
}

func TestResolveMissionForWork_WorkContextWithEmptyMissionIDReturnsEmpty(t *testing.T) {
	resolver, mr := newTestMissionContextResolver(t)
	ctx := context.Background()

	// Simulate a work item dispatched outside a mission.
	writeWorkContext(t, mr, "work-no-mission", "", "tenant-acme")

	missionID, overrides, err := resolver.ResolveMissionForWork(ctx, "work-no-mission")
	require.NoError(t, err)
	assert.Empty(t, missionID)
	assert.Nil(t, overrides)
}

// ---------------------------------------------------------------------------
// ResolveMissionForWork: mission found, no overrides
// ---------------------------------------------------------------------------

func TestResolveMissionForWork_ReturnsMissionIDWithoutOverrides(t *testing.T) {
	resolver, mr := newTestMissionContextResolver(t)
	ctx := context.Background()

	const workID = "work-no-overrides"
	const missionID = "mission-no-overrides"
	const tenant = "tenant-acme"

	writeWorkContext(t, mr, workID, missionID, tenant)
	// No slot-overrides key written — Get will return ErrNotFound.

	gotMission, gotOverrides, err := resolver.ResolveMissionForWork(ctx, workID)
	require.NoError(t, err)
	assert.Equal(t, missionID, gotMission)
	assert.Nil(t, gotOverrides, "no overrides configured; should return nil")
}

// ---------------------------------------------------------------------------
// ResolveMissionForWork: mission found with overrides
// ---------------------------------------------------------------------------

func TestResolveMissionForWork_ReturnsMissionIDAndOverrides(t *testing.T) {
	resolver, mr := newTestMissionContextResolver(t)
	ctx := context.Background()

	const workID = "work-with-overrides"
	const missionID = "mission-with-overrides"
	const tenant = "tenant-widgets"

	temp := 0.3
	overrides := SlotOverrides{
		MissionID: missionID,
		Overrides: map[string]SlotOverride{
			"reasoning": {
				PreferredProvider: "anthropic",
				PreferredModel:    "claude-opus-4-5",
				MaxTokens:         8192,
				Temperature:       &temp,
			},
			"fast": {
				PreferredProvider: "openai",
				PreferredModel:    "gpt-4o-mini",
			},
		},
	}

	writeWorkContext(t, mr, workID, missionID, tenant)
	writeSlotOverrides(t, mr, tenant, missionID, overrides)

	gotMission, gotOverrides, err := resolver.ResolveMissionForWork(ctx, workID)
	require.NoError(t, err)
	assert.Equal(t, missionID, gotMission)
	require.NotNil(t, gotOverrides)
	assert.Equal(t, missionID, gotOverrides.MissionID)

	reasoningOv, ok := gotOverrides.Overrides["reasoning"]
	require.True(t, ok)
	assert.Equal(t, "anthropic", reasoningOv.PreferredProvider)
	assert.Equal(t, "claude-opus-4-5", reasoningOv.PreferredModel)
	assert.Equal(t, 8192, reasoningOv.MaxTokens)
	require.NotNil(t, reasoningOv.Temperature)
	assert.InDelta(t, 0.3, *reasoningOv.Temperature, 0.001)

	fastOv, ok := gotOverrides.Overrides["fast"]
	require.True(t, ok)
	assert.Equal(t, "openai", fastOv.PreferredProvider)
	assert.Equal(t, "gpt-4o-mini", fastOv.PreferredModel)
	assert.Zero(t, fastOv.MaxTokens)
	assert.Nil(t, fastOv.Temperature)
}

// ---------------------------------------------------------------------------
// ResolveMissionForWork: tenant fallback
// ---------------------------------------------------------------------------

func TestResolveMissionForWork_UsesTenantFromWorkContext(t *testing.T) {
	resolver, mr := newTestMissionContextResolver(t)

	const workID = "work-tenant-from-ctx"
	const missionID = "mission-tenant-ctx"
	const tenant = "tenant-from-work-ctx"

	// The tenant is stored in the work context (written by RegisterWorkContext).
	// The request context has a different tenant — the stored one must win.
	writeWorkContext(t, mr, workID, missionID, tenant)
	writeSlotOverrides(t, mr, tenant, missionID, SlotOverrides{
		MissionID: missionID,
		Overrides: map[string]SlotOverride{
			"default": {PreferredProvider: "ollama"},
		},
	})

	// Put a different tenant in the context — should be ignored for key scoping.
	ctx := auth.ContextWithTenantString(context.Background(), "tenant-wrong")

	gotMission, gotOverrides, err := resolver.ResolveMissionForWork(ctx, workID)
	require.NoError(t, err)
	assert.Equal(t, missionID, gotMission)
	require.NotNil(t, gotOverrides)
	assert.Contains(t, gotOverrides.Overrides, "default")
}

func TestResolveMissionForWork_FallsBackToContextTenantWhenWorkContextTenantEmpty(t *testing.T) {
	resolver, mr := newTestMissionContextResolver(t)

	const workID = "work-ctx-tenant-fallback"
	const missionID = "mission-ctx-fallback"
	const tenant = "tenant-from-auth-ctx"

	// Stored tenant is empty — must fall back to the context tenant.
	writeWorkContext(t, mr, workID, missionID, "")
	writeSlotOverrides(t, mr, tenant, missionID, SlotOverrides{
		MissionID: missionID,
		Overrides: map[string]SlotOverride{
			"fast": {MaxTokens: 4096},
		},
	})

	ctx := auth.ContextWithTenantString(context.Background(), tenant)

	gotMission, gotOverrides, err := resolver.ResolveMissionForWork(ctx, workID)
	require.NoError(t, err)
	assert.Equal(t, missionID, gotMission)
	require.NotNil(t, gotOverrides)
	fastOv, ok := gotOverrides.Overrides["fast"]
	require.True(t, ok)
	assert.Equal(t, 4096, fastOv.MaxTokens)
}

func TestResolveMissionForWork_NoTenantAvailableReturnsMissionIDOnly(t *testing.T) {
	resolver, mr := newTestMissionContextResolver(t)

	const workID = "work-no-tenant"
	const missionID = "mission-no-tenant"

	// Both the stored tenant and the context tenant are empty.
	writeWorkContext(t, mr, workID, missionID, "")
	// Do not write any overrides — if we did, the lookup would fail anyway.

	ctx := context.Background() // no tenant in context

	gotMission, gotOverrides, err := resolver.ResolveMissionForWork(ctx, workID)
	require.NoError(t, err)
	assert.Equal(t, missionID, gotMission)
	assert.Nil(t, gotOverrides, "cannot look up overrides without a tenant")
}

// ---------------------------------------------------------------------------
// ResolveMissionForWork: malformed JSON overrides
// ---------------------------------------------------------------------------

func TestResolveMissionForWork_MalformedOverridesJSONTreatedAsNoOverrides(t *testing.T) {
	resolver, mr := newTestMissionContextResolver(t)

	const workID = "work-bad-json"
	const missionID = "mission-bad-json"
	const tenant = "tenant-bad-json"

	writeWorkContext(t, mr, workID, missionID, tenant)

	// Write invalid JSON to the overrides key.
	key := auth.TenantScopedRedisKey(tenant, missionSlotOverridesKey(missionID))
	require.NoError(t, mr.Set(key, "not-valid-json{{{"))

	gotMission, gotOverrides, err := resolver.ResolveMissionForWork(
		auth.ContextWithTenantString(context.Background(), tenant), workID,
	)
	require.NoError(t, err)
	assert.Equal(t, missionID, gotMission)
	assert.Nil(t, gotOverrides, "malformed JSON should fall back to nil overrides")
}

// ---------------------------------------------------------------------------
// missionSlotOverridesKey helper
// ---------------------------------------------------------------------------

func TestMissionSlotOverridesKey_Format(t *testing.T) {
	tests := []struct {
		missionID string
		expected  string
	}{
		{"mission-123", "mission:mission-123:slot-overrides"},
		{"01HXY2Z3456789ABCDEF", "mission:01HXY2Z3456789ABCDEF:slot-overrides"},
	}

	for _, tt := range tests {
		t.Run(tt.missionID, func(t *testing.T) {
			got := missionSlotOverridesKey(tt.missionID)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// resolveMissionContext shim tests
// ---------------------------------------------------------------------------

func TestResolveMissionContext_NilResolverReturnsEmpty(t *testing.T) {
	ctx := context.Background()

	missionID, overrides, err := resolveMissionContext(ctx, nil, "work-123", "tenant", "reasoning", nil)
	require.NoError(t, err)
	assert.Empty(t, missionID)
	assert.Nil(t, overrides)
}

func TestResolveMissionContext_EmptyWorkIDReturnsEmpty(t *testing.T) {
	resolver, _ := newTestMissionContextResolver(t)
	ctx := context.Background()

	missionID, overrides, err := resolveMissionContext(ctx, resolver, "", "tenant", "reasoning", nil)
	require.NoError(t, err)
	assert.Empty(t, missionID)
	assert.Nil(t, overrides)
}

// ---------------------------------------------------------------------------
// applySlotOverrides helper tests
// ---------------------------------------------------------------------------

func TestApplySlotOverrides_NilOverridesReturnsZeroValues(t *testing.T) {
	maxTokens, temperature := applySlotOverrides("reasoning", nil)
	assert.Zero(t, maxTokens)
	assert.Zero(t, temperature)
}

func TestApplySlotOverrides_SlotNotPresentReturnsZeroValues(t *testing.T) {
	overrides := &SlotOverrides{
		Overrides: map[string]SlotOverride{
			"fast": {MaxTokens: 1024},
		},
	}
	maxTokens, temperature := applySlotOverrides("reasoning", overrides)
	assert.Zero(t, maxTokens)
	assert.Zero(t, temperature)
}

func TestApplySlotOverrides_AppliesMaxTokens(t *testing.T) {
	overrides := &SlotOverrides{
		Overrides: map[string]SlotOverride{
			"reasoning": {MaxTokens: 8192},
		},
	}
	maxTokens, temperature := applySlotOverrides("reasoning", overrides)
	assert.Equal(t, int32(8192), maxTokens)
	assert.Zero(t, temperature)
}

func TestApplySlotOverrides_AppliesTemperature(t *testing.T) {
	temp := 0.7
	overrides := &SlotOverrides{
		Overrides: map[string]SlotOverride{
			"reasoning": {Temperature: &temp},
		},
	}
	maxTokens, temperature := applySlotOverrides("reasoning", overrides)
	assert.Zero(t, maxTokens)
	assert.InDelta(t, float32(0.7), temperature, 0.001)
}

func TestApplySlotOverrides_AppliesBothMaxTokensAndTemperature(t *testing.T) {
	temp := 0.2
	overrides := &SlotOverrides{
		Overrides: map[string]SlotOverride{
			"fast": {
				MaxTokens:   2048,
				Temperature: &temp,
			},
		},
	}
	maxTokens, temperature := applySlotOverrides("fast", overrides)
	assert.Equal(t, int32(2048), maxTokens)
	assert.InDelta(t, float32(0.2), temperature, 0.001)
}

func TestApplySlotOverrides_ZeroMaxTokensIsIgnored(t *testing.T) {
	temp := 0.5
	overrides := &SlotOverrides{
		Overrides: map[string]SlotOverride{
			"default": {
				MaxTokens:   0, // explicitly zero — should not override
				Temperature: &temp,
			},
		},
	}
	maxTokens, temperature := applySlotOverrides("default", overrides)
	assert.Zero(t, maxTokens, "zero MaxTokens should not be surfaced as an override")
	assert.InDelta(t, float32(0.5), temperature, 0.001)
}

func TestApplySlotOverrides_EmptyOverridesMapReturnsZeroValues(t *testing.T) {
	overrides := &SlotOverrides{
		Overrides: map[string]SlotOverride{},
	}
	maxTokens, temperature := applySlotOverrides("reasoning", overrides)
	assert.Zero(t, maxTokens)
	assert.Zero(t, temperature)
}

// ---------------------------------------------------------------------------
// SlotOverrides JSON round-trip
// ---------------------------------------------------------------------------

func TestSlotOverrides_JSONRoundTrip(t *testing.T) {
	temp := 0.4
	original := SlotOverrides{
		MissionID: "mission-json-rt",
		Overrides: map[string]SlotOverride{
			"reasoning": {
				PreferredProvider: "anthropic",
				PreferredModel:    "claude-opus-4-5",
				MaxTokens:         16384,
				Temperature:       &temp,
			},
			"vision": {
				PreferredProvider: "openai",
				PreferredModel:    "gpt-4o",
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded SlotOverrides
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.MissionID, decoded.MissionID)
	assert.Equal(t, len(original.Overrides), len(decoded.Overrides))

	reasoningOv := decoded.Overrides["reasoning"]
	assert.Equal(t, "anthropic", reasoningOv.PreferredProvider)
	assert.Equal(t, "claude-opus-4-5", reasoningOv.PreferredModel)
	assert.Equal(t, 16384, reasoningOv.MaxTokens)
	require.NotNil(t, reasoningOv.Temperature)
	assert.InDelta(t, 0.4, *reasoningOv.Temperature, 0.001)
}

// ---------------------------------------------------------------------------
// TTL behaviour (overrides key expiry is optional — the key is persistent until
// the mission orchestrator deletes it; verify it survives miniredis fast-forward)
// ---------------------------------------------------------------------------

func TestResolveMissionForWork_OverridesKeyHasNoForcedTTL(t *testing.T) {
	resolver, mr := newTestMissionContextResolver(t)

	const workID = "work-ttl-check"
	const missionID = "mission-ttl-check"
	const tenant = "tenant-ttl"

	writeWorkContext(t, mr, workID, missionID, tenant)
	writeSlotOverrides(t, mr, tenant, missionID, SlotOverrides{
		MissionID: missionID,
		Overrides: map[string]SlotOverride{
			"default": {PreferredProvider: "anthropic"},
		},
	})

	// Fast-forward past the work context TTL — the overrides key should still be readable.
	mr.FastForward(workContextTTL + time.Second)

	// After work context expires, the resolver returns empty missionID.
	gotMission, gotOverrides, err := resolver.ResolveMissionForWork(
		auth.ContextWithTenantString(context.Background(), tenant), workID,
	)
	require.NoError(t, err)
	assert.Empty(t, gotMission, "work context expired; mission ID should be empty")
	assert.Nil(t, gotOverrides)
}
