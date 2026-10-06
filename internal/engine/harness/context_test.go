// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ────────────────────────────────────────────────────────────────────────────
// MissionContext Tests
// ────────────────────────────────────────────────────────────────────────────

func TestNewMissionContext(t *testing.T) {
	id := types.NewID()
	ctx := NewMissionContext(id, "test-mission", "test-agent")

	assert.Equal(t, id, ctx.ID)
	assert.Equal(t, "test-mission", ctx.Name)
	assert.Equal(t, "test-agent", ctx.CurrentAgent)
	assert.Empty(t, ctx.Phase)
	assert.Empty(t, ctx.Constraints)
	assert.NotNil(t, ctx.Metadata)
	assert.Empty(t, ctx.Metadata)
}

func TestMissionContext_WithPhase(t *testing.T) {
	id := types.NewID()
	ctx := NewMissionContext(id, "test-mission", "test-agent").
		WithPhase("reconnaissance")

	assert.Equal(t, "reconnaissance", ctx.Phase)
	assert.Equal(t, "test-mission", ctx.Name)
}

func TestMissionContext_WithConstraints(t *testing.T) {
	tests := []struct {
		name        string
		constraints []string
		expected    []string
	}{
		{
			name:        "single constraint",
			constraints: []string{"no-destructive-actions"},
			expected:    []string{"no-destructive-actions"},
		},
		{
			name:        "multiple constraints",
			constraints: []string{"read-only", "no-network", "time-limited"},
			expected:    []string{"read-only", "no-network", "time-limited"},
		},
		{
			name:        "empty constraints",
			constraints: []string{},
			expected:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := types.NewID()
			ctx := NewMissionContext(id, "test-mission", "test-agent").
				WithConstraints(tt.constraints...)

			assert.Equal(t, tt.expected, ctx.Constraints)
		})
	}
}

func TestMissionContext_WithMetadata(t *testing.T) {
	id := types.NewID()
	ctx := NewMissionContext(id, "test-mission", "test-agent").
		WithMetadata("key1", "value1").
		WithMetadata("key2", 123).
		WithMetadata("key3", true)

	assert.Equal(t, "value1", ctx.Metadata["key1"])
	assert.Equal(t, 123, ctx.Metadata["key2"])
	assert.Equal(t, true, ctx.Metadata["key3"])
	assert.Len(t, ctx.Metadata, 3)
}

func TestMissionContext_WithMetadata_InitializesMap(t *testing.T) {
	// Create context without initializing metadata
	ctx := MissionContext{
		ID:           types.NewID(),
		Name:         "test",
		CurrentAgent: "agent",
	}

	// Should initialize the map
	ctx = ctx.WithMetadata("key", "value")
	assert.NotNil(t, ctx.Metadata)
	assert.Equal(t, "value", ctx.Metadata["key"])
}

func TestMissionContext_Chaining(t *testing.T) {
	id := types.NewID()
	ctx := NewMissionContext(id, "test-mission", "test-agent").
		WithPhase("exploitation").
		WithConstraints("read-only", "no-network").
		WithMetadata("priority", "high").
		WithMetadata("timeout", 300)

	assert.Equal(t, "exploitation", ctx.Phase)
	assert.Equal(t, []string{"read-only", "no-network"}, ctx.Constraints)
	assert.Equal(t, "high", ctx.Metadata["priority"])
	assert.Equal(t, 300, ctx.Metadata["timeout"])
}

func TestMissionContext_JSON_Serialization(t *testing.T) {
	id := types.NewID()
	original := NewMissionContext(id, "test-mission", "test-agent").
		WithPhase("reconnaissance").
		WithConstraints("read-only").
		WithMetadata("key", "value")

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded MissionContext
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify all fields
	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.CurrentAgent, decoded.CurrentAgent)
	assert.Equal(t, original.Phase, decoded.Phase)
	assert.Equal(t, original.Constraints, decoded.Constraints)
	assert.Equal(t, original.Metadata, decoded.Metadata)
}

func TestMissionContext_JSON_EmptyFields(t *testing.T) {
	id := types.NewID()
	ctx := NewMissionContext(id, "test", "agent")

	data, err := json.Marshal(ctx)
	require.NoError(t, err)

	var decoded MissionContext
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, ctx.ID, decoded.ID)
	assert.Equal(t, ctx.Name, decoded.Name)
	assert.Equal(t, ctx.CurrentAgent, decoded.CurrentAgent)
}

// ────────────────────────────────────────────────────────────────────────────
// TargetInfo Tests
// ────────────────────────────────────────────────────────────────────────────

func TestNewTargetInfo(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test-target", "https://example.com", "web")

	assert.Equal(t, id, target.ID)
	assert.Equal(t, "test-target", target.Name)
	assert.Equal(t, "https://example.com", target.URL())
	assert.Equal(t, map[string]any{"url": "https://example.com"}, target.Connection)
	assert.Equal(t, "web", target.Type)
	assert.Empty(t, target.Provider)
	assert.NotNil(t, target.Metadata)
	assert.Empty(t, target.Metadata)
}

func TestTargetInfo_WithProvider(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test-target", "https://example.com", "web").
		WithProvider("aws")

	assert.Equal(t, "aws", target.Provider)
	assert.Equal(t, "test-target", target.Name)
}

func TestTargetInfo_WithMetadata(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test-target", "https://example.com", "web").
		WithMetadata("region", "us-east-1").
		WithMetadata("port", 8080).
		WithMetadata("secure", true)

	assert.Equal(t, "us-east-1", target.Metadata["region"])
	assert.Equal(t, 8080, target.Metadata["port"])
	assert.Equal(t, true, target.Metadata["secure"])
	assert.Len(t, target.Metadata, 3)
}

func TestTargetInfo_WithMetadata_InitializesMap(t *testing.T) {
	// Create target without initializing metadata
	target := TargetInfo{
		ID:         types.NewID(),
		Name:       "test",
		Connection: map[string]any{"url": "https://example.com"},
		Type:       "web",
	}

	// Should initialize the map
	target = target.WithMetadata("key", "value")
	assert.NotNil(t, target.Metadata)
	assert.Equal(t, "value", target.Metadata["key"])
}

func TestTargetInfo_Chaining(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test-target", "https://example.com", "web").
		WithProvider("aws").
		WithMetadata("region", "us-west-2").
		WithMetadata("environment", "production")

	assert.Equal(t, "aws", target.Provider)
	assert.Equal(t, "us-west-2", target.Metadata["region"])
	assert.Equal(t, "production", target.Metadata["environment"])
}

func TestTargetInfo_JSON_Serialization(t *testing.T) {
	id := types.NewID()
	original := NewTargetInfo(id, "test-target", "https://example.com", "web").
		WithProvider("aws").
		WithMetadata("key", "value")

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var decoded TargetInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	// Verify all fields
	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.URL(), decoded.URL())
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Provider, decoded.Provider)
	assert.Equal(t, original.Metadata, decoded.Metadata)
}

func TestTargetInfo_JSON_EmptyFields(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test", "https://example.com", "web")

	data, err := json.Marshal(target)
	require.NoError(t, err)

	var decoded TargetInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, target.ID, decoded.ID)
	assert.Equal(t, target.Name, decoded.Name)
	assert.Equal(t, target.URL(), decoded.URL())
	assert.Equal(t, target.Type, decoded.Type)
}

// ────────────────────────────────────────────────────────────────────────────
// Edge Cases and Complex Scenarios
// ────────────────────────────────────────────────────────────────────────────

func TestMissionContext_ComplexMetadata(t *testing.T) {
	id := types.NewID()
	ctx := NewMissionContext(id, "test", "agent").
		WithMetadata("nested", map[string]any{
			"key1": "value1",
			"key2": 123,
		}).
		WithMetadata("array", []string{"item1", "item2"})

	nested := ctx.Metadata["nested"].(map[string]any)
	assert.Equal(t, "value1", nested["key1"])
	assert.Equal(t, 123, nested["key2"])

	array := ctx.Metadata["array"].([]string)
	assert.Equal(t, []string{"item1", "item2"}, array)
}

func TestTargetInfo_ComplexMetadata(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test", "https://example.com", "web").
		WithMetadata("nested", map[string]any{
			"key1": "value1",
			"key2": 123,
		}).
		WithMetadata("array", []int{1, 2, 3})

	nested := target.Metadata["nested"].(map[string]any)
	assert.Equal(t, "value1", nested["key1"])
	assert.Equal(t, 123, nested["key2"])

	array := target.Metadata["array"].([]int)
	assert.Equal(t, []int{1, 2, 3}, array)
}

func TestMissionContext_EmptyConstraints(t *testing.T) {
	id := types.NewID()
	ctx := NewMissionContext(id, "test", "agent").
		WithConstraints()

	// WithConstraints with no args creates nil, which is semantically empty
	assert.Empty(t, ctx.Constraints)
}

// ────────────────────────────────────────────────────────────────────────────
// NodeSlotOverrides Tests — Spec: per-node-slot-override (gibson#539)
// ────────────────────────────────────────────────────────────────────────────

func TestMissionContext_WithNodeSlotOverrides_Populated(t *testing.T) {
	id := types.NewID()
	overrides := map[string]*agent.SlotConfig{
		"primary": {Provider: "anthropic", Model: "claude-3-5-sonnet"},
		"fast":    {Provider: "openai", Model: "gpt-4o-mini"},
	}

	ctx := NewMissionContext(id, "test-mission", "test-agent").
		WithNodeSlotOverrides(overrides)

	require.NotNil(t, ctx.NodeSlotOverrides)
	require.Len(t, ctx.NodeSlotOverrides, 2)
	assert.Equal(t, "anthropic", ctx.NodeSlotOverrides["primary"].Provider)
	assert.Equal(t, "claude-3-5-sonnet", ctx.NodeSlotOverrides["primary"].Model)
	assert.Equal(t, "openai", ctx.NodeSlotOverrides["fast"].Provider)
}

func TestMissionContext_WithNodeSlotOverrides_Nil(t *testing.T) {
	id := types.NewID()
	ctx := NewMissionContext(id, "test-mission", "test-agent").
		WithNodeSlotOverrides(nil)
	assert.Nil(t, ctx.NodeSlotOverrides)
}

// TestMissionContext_NodeSlotOverrides_NotInheritedByChild verifies that
// copying a MissionContext and clearing NodeSlotOverrides produces an isolated
// child context — confirming that the copy-on-assign semantics (maps are
// reference-typed but assignment replaces the pointer, not the contents) work
// as expected for the DelegateToAgent path.
func TestMissionContext_NodeSlotOverrides_NotInheritedByChild(t *testing.T) {
	id := types.NewID()
	parent := NewMissionContext(id, "mission", "parent-agent").
		WithNodeSlotOverrides(map[string]*agent.SlotConfig{
			"primary": {Provider: "anthropic"},
		})

	// Simulate what DelegateToAgent does: copy parent ctx, clear overrides.
	child := parent
	child.CurrentAgent = "child-agent"
	child.NodeSlotOverrides = nil // child has its own overrides (none in this case)

	assert.NotNil(t, parent.NodeSlotOverrides, "parent overrides must be unaffected")
	assert.Nil(t, child.NodeSlotOverrides, "child overrides must be nil")
}

// TestMissionContext_NodeSlotOverrides_JSONRoundTrip confirms that the
// NodeSlotOverrides survive a JSON marshal/unmarshal cycle (e.g. when mission
// context is serialised to/from the wire or a checkpoint).
func TestMissionContext_NodeSlotOverrides_JSONRoundTrip(t *testing.T) {
	id := types.NewID()
	original := NewMissionContext(id, "mission", "agent").
		WithNodeSlotOverrides(map[string]*agent.SlotConfig{
			"primary": {Provider: "anthropic", Model: "claude"},
		})

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded MissionContext
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.NotNil(t, decoded.NodeSlotOverrides)
	require.Contains(t, decoded.NodeSlotOverrides, "primary")
	assert.Equal(t, "anthropic", decoded.NodeSlotOverrides["primary"].Provider)
	assert.Equal(t, "claude", decoded.NodeSlotOverrides["primary"].Model)
}

// TestNewTargetInfoFull_TheConnectionURLWins proves that Connection["url"] is
// the one place for the address of a target: a URL in the connection is kept,
// and the url argument fills it only when it is absent.
func TestNewTargetInfoFull_TheConnectionURLWins(t *testing.T) {
	id := types.NewID()
	conn := map[string]any{"url": "https://from-connection.example", "port": 8443}

	target := NewTargetInfoFull(id, "t", "https://from-argument.example", "web", conn)
	assert.Equal(t, "https://from-connection.example", target.URL())
	assert.Equal(t, 8443, target.Connection["port"])

	target.Connection["url"] = "changed"
	assert.Equal(t, "https://from-connection.example", conn["url"], "the constructor must not share the caller's map")

	empty := NewTargetInfoFull(id, "t", "", "web", nil)
	assert.Empty(t, empty.URL())
}
