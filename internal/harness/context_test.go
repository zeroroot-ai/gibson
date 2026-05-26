package harness

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
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
	assert.Equal(t, "https://example.com", target.URL)
	assert.Equal(t, "web", target.Type)
	assert.Empty(t, target.Provider)
	assert.NotNil(t, target.Headers)
	assert.Empty(t, target.Headers)
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

func TestTargetInfo_WithHeader(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test-target", "https://example.com", "web").
		WithHeader("Authorization", "Bearer token123").
		WithHeader("User-Agent", "Gibson/1.0")

	assert.Equal(t, "Bearer token123", target.Headers["Authorization"])
	assert.Equal(t, "Gibson/1.0", target.Headers["User-Agent"])
	assert.Len(t, target.Headers, 2)
}

func TestTargetInfo_WithHeader_InitializesMap(t *testing.T) {
	// Create target without initializing headers
	target := TargetInfo{
		ID:   types.NewID(),
		Name: "test",
		URL:  "https://example.com",
		Type: "web",
	}

	// Should initialize the map
	target = target.WithHeader("Authorization", "Bearer token")
	assert.NotNil(t, target.Headers)
	assert.Equal(t, "Bearer token", target.Headers["Authorization"])
}

func TestTargetInfo_WithHeaders(t *testing.T) {
	id := types.NewID()
	headers := map[string]string{
		"Authorization": "Bearer token123",
		"User-Agent":    "Gibson/1.0",
		"Accept":        "application/json",
	}

	target := NewTargetInfo(id, "test-target", "https://example.com", "web").
		WithHeaders(headers)

	assert.Equal(t, "Bearer token123", target.Headers["Authorization"])
	assert.Equal(t, "Gibson/1.0", target.Headers["User-Agent"])
	assert.Equal(t, "application/json", target.Headers["Accept"])
	assert.Len(t, target.Headers, 3)
}

func TestTargetInfo_WithHeaders_Merges(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test-target", "https://example.com", "web").
		WithHeader("Existing", "header").
		WithHeaders(map[string]string{
			"New1": "value1",
			"New2": "value2",
		})

	assert.Equal(t, "header", target.Headers["Existing"])
	assert.Equal(t, "value1", target.Headers["New1"])
	assert.Equal(t, "value2", target.Headers["New2"])
	assert.Len(t, target.Headers, 3)
}

func TestTargetInfo_WithHeaders_InitializesMap(t *testing.T) {
	// Create target without initializing headers
	target := TargetInfo{
		ID:   types.NewID(),
		Name: "test",
		URL:  "https://example.com",
		Type: "web",
	}

	// Should initialize the map
	target = target.WithHeaders(map[string]string{"Auth": "token"})
	assert.NotNil(t, target.Headers)
	assert.Equal(t, "token", target.Headers["Auth"])
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
		ID:   types.NewID(),
		Name: "test",
		URL:  "https://example.com",
		Type: "web",
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
		WithHeader("Authorization", "Bearer token").
		WithHeaders(map[string]string{"Accept": "application/json"}).
		WithMetadata("region", "us-west-2").
		WithMetadata("environment", "production")

	assert.Equal(t, "aws", target.Provider)
	assert.Equal(t, "Bearer token", target.Headers["Authorization"])
	assert.Equal(t, "application/json", target.Headers["Accept"])
	assert.Equal(t, "us-west-2", target.Metadata["region"])
	assert.Equal(t, "production", target.Metadata["environment"])
}

func TestTargetInfo_JSON_Serialization(t *testing.T) {
	id := types.NewID()
	original := NewTargetInfo(id, "test-target", "https://example.com", "web").
		WithProvider("aws").
		WithHeader("Authorization", "Bearer token").
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
	assert.Equal(t, original.URL, decoded.URL)
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Provider, decoded.Provider)
	assert.Equal(t, original.Headers, decoded.Headers)
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
	assert.Equal(t, target.URL, decoded.URL)
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

func TestTargetInfo_MultipleHeadersMerge(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test", "https://example.com", "web").
		WithHeaders(map[string]string{
			"Header1": "value1",
			"Header2": "value2",
		}).
		WithHeaders(map[string]string{
			"Header3": "value3",
			"Header4": "value4",
		})

	assert.Len(t, target.Headers, 4)
	assert.Equal(t, "value1", target.Headers["Header1"])
	assert.Equal(t, "value2", target.Headers["Header2"])
	assert.Equal(t, "value3", target.Headers["Header3"])
	assert.Equal(t, "value4", target.Headers["Header4"])
}

func TestTargetInfo_HeaderOverwrite(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test", "https://example.com", "web").
		WithHeader("Authorization", "Bearer token1").
		WithHeader("Authorization", "Bearer token2")

	// Second call should overwrite
	assert.Equal(t, "Bearer token2", target.Headers["Authorization"])
}

func TestMissionContext_EmptyConstraints(t *testing.T) {
	id := types.NewID()
	ctx := NewMissionContext(id, "test", "agent").
		WithConstraints()

	// WithConstraints with no args creates nil, which is semantically empty
	assert.Empty(t, ctx.Constraints)
}

func TestTargetInfo_EmptyHeaders(t *testing.T) {
	id := types.NewID()
	target := NewTargetInfo(id, "test", "https://example.com", "web").
		WithHeaders(map[string]string{})

	assert.NotNil(t, target.Headers)
	assert.Empty(t, target.Headers)
}
