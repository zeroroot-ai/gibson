// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ResolveMissionForWork: no context cases
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ResolveMissionForWork: mission found, no overrides
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ResolveMissionForWork: mission found with overrides
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ResolveMissionForWork: tenant ownership gate (gibson#1250)
//
// The work id arrives from the remote component and is not trusted. The
// pre-fix behaviour these tests replace — "stored tenant wins, context tenant
// is the fallback" — let a component holding another tenant's work id read
// that tenant's mission id and have the overrides lookup performed under the
// other tenant's scope.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ResolveMissionForWork: malformed JSON overrides
// ---------------------------------------------------------------------------

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
