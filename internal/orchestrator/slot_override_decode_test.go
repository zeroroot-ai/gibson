// slot_override_decode_test.go tests the decodeSlotOverrides helper that
// converts the "__llm_slots" TaskConfig sentinel value into a typed override
// map.  Both wire forms (in-memory + JSON round-trip) are tested.
//
// Spec: per-node-slot-override (gibson#539).
package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeSlotOverrides_InMemoryForm exercises the []map[string]string form
// that arrives before any Neo4j round-trip (graph_bootstrap → executeAgent in
// the same call).
func TestDecodeSlotOverrides_InMemoryForm(t *testing.T) {
	raw := []map[string]string{
		{"slot": "primary", "provider": "anthropic", "model": "claude-3-5-sonnet"},
		{"slot": "fast", "provider": "openai", "model": "gpt-4o-mini"},
	}

	overrides := decodeSlotOverrides(raw)
	require.NotNil(t, overrides)
	require.Len(t, overrides, 2)

	assert.Equal(t, "anthropic", overrides["primary"].Provider)
	assert.Equal(t, "claude-3-5-sonnet", overrides["primary"].Model)
	assert.Equal(t, "openai", overrides["fast"].Provider)
	assert.Equal(t, "gpt-4o-mini", overrides["fast"].Model)
}

// TestDecodeSlotOverrides_JSONForm exercises the []interface{} form that JSON
// unmarshaling into map[string]any produces when reading from Neo4j.
func TestDecodeSlotOverrides_JSONForm(t *testing.T) {
	raw := []any{
		map[string]any{"slot": "primary", "provider": "anthropic", "model": "claude-3-5-sonnet"},
		map[string]any{"slot": "fast", "provider": "openai", "model": "gpt-4o-mini"},
	}

	overrides := decodeSlotOverrides(raw)
	require.NotNil(t, overrides)
	require.Len(t, overrides, 2)

	assert.Equal(t, "anthropic", overrides["primary"].Provider)
	assert.Equal(t, "claude-3-5-sonnet", overrides["primary"].Model)
	assert.Equal(t, "openai", overrides["fast"].Provider)
	assert.Equal(t, "gpt-4o-mini", overrides["fast"].Model)
}

// TestDecodeSlotOverrides_NilInput returns nil for nil input (no override intent).
func TestDecodeSlotOverrides_NilInput(t *testing.T) {
	assert.Nil(t, decodeSlotOverrides(nil))
}

// TestDecodeSlotOverrides_UnrecognisedType returns nil for unrecognised types.
func TestDecodeSlotOverrides_UnrecognisedType(t *testing.T) {
	assert.Nil(t, decodeSlotOverrides("not-a-slice"))
	assert.Nil(t, decodeSlotOverrides(42))
}

// TestDecodeSlotOverrides_EmptySlice returns nil for empty slices.
func TestDecodeSlotOverrides_EmptySlice(t *testing.T) {
	assert.Nil(t, decodeSlotOverrides([]map[string]string{}))
	assert.Nil(t, decodeSlotOverrides([]any{}))
}

// TestDecodeSlotOverrides_EmptyProviderFiltered confirms that entries with an
// empty provider are silently dropped and do not appear in the output.
func TestDecodeSlotOverrides_EmptyProviderFiltered(t *testing.T) {
	raw := []any{
		map[string]any{"slot": "primary", "provider": "", "model": ""},
		map[string]any{"slot": "fast", "provider": "openai", "model": "gpt-4o-mini"},
	}

	overrides := decodeSlotOverrides(raw)
	require.NotNil(t, overrides)
	require.Len(t, overrides, 1, "empty-provider entry must be dropped")
	assert.Equal(t, "openai", overrides["fast"].Provider)
}
