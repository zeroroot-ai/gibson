package component

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestComponentKind_Validation_AcceptsAnyNonEmptyString verifies that ComponentKind
// accepts any non-empty string as valid
func TestComponentKind_Validation_AcceptsAnyNonEmptyString(t *testing.T) {
	tests := []struct {
		name     string
		kind     ComponentKind
		expected bool
	}{
		{"Predefined_Agent", ComponentKindAgent, true},
		{"Predefined_Tool", ComponentKindTool, true},
		{"Predefined_Plugin", ComponentKindPlugin, true},
		{"Custom_Kind", ComponentKind("custom"), true},
		{"Arbitrary_String", ComponentKind("my-custom-component"), true},
		{"Single_Char", ComponentKind("x"), true},
		{"Numeric", ComponentKind("123"), true},
		{"Mixed", ComponentKind("type-v2"), true},
		{"Empty_String", ComponentKind(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.kind.IsValid()
			assert.Equal(t, tt.expected, result,
				"ComponentKind(%q).IsValid() should return %v", tt.kind, tt.expected)
		})
	}
}

// TestParseComponentKind_AcceptsAnyNonEmptyString verifies that ParseComponentKind
// accepts any non-empty string
func TestParseComponentKind_AcceptsAnyNonEmptyString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  ComponentKind
		expectErr bool
	}{
		{"Predefined_Agent", "agent", ComponentKindAgent, false},
		{"Predefined_Tool", "tool", ComponentKindTool, false},
		{"Predefined_Plugin", "plugin", ComponentKindPlugin, false},
		{"Custom_Kind", "custom", ComponentKind("custom"), false},
		{"Arbitrary_String", "my-custom-component", ComponentKind("my-custom-component"), false},
		{"Single_Char", "x", ComponentKind("x"), false},
		{"Numeric", "123", ComponentKind("123"), false},
		{"Mixed", "type-v2", ComponentKind("type-v2"), false},
		{"Empty_String", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseComponentKind(tt.input)
			if tt.expectErr {
				assert.Error(t, err, "ParseComponentKind(%q) should return error", tt.input)
				assert.Contains(t, err.Error(), "cannot be empty")
			} else {
				require.NoError(t, err, "ParseComponentKind(%q) should not return error", tt.input)
				assert.Equal(t, tt.expected, result,
					"ParseComponentKind(%q) should return %q", tt.input, tt.expected)
			}
		})
	}
}

// TestComponentKind_JSON_AcceptsAnyNonEmptyString verifies that JSON marshaling/unmarshaling
// works with any non-empty string
func TestComponentKind_JSON_AcceptsAnyNonEmptyString(t *testing.T) {
	tests := []struct {
		name string
		kind ComponentKind
	}{
		{"Predefined_Agent", ComponentKindAgent},
		{"Predefined_Tool", ComponentKindTool},
		{"Predefined_Plugin", ComponentKindPlugin},
		{"Custom_Kind", ComponentKind("custom")},
		{"Arbitrary_String", ComponentKind("my-custom-component")},
		{"Single_Char", ComponentKind("x")},
		{"Numeric", ComponentKind("123")},
		{"Mixed", ComponentKind("type-v2")},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_Marshal", func(t *testing.T) {
			data, err := json.Marshal(tt.kind)
			require.NoError(t, err, "Marshaling ComponentKind(%q) should not error", tt.kind)
			assert.NotEmpty(t, data)
			assert.Equal(t, `"`+tt.kind.String()+`"`, string(data))
		})

		t.Run(tt.name+"_Unmarshal", func(t *testing.T) {
			jsonStr := `"` + string(tt.kind) + `"`
			var kind ComponentKind
			err := json.Unmarshal([]byte(jsonStr), &kind)
			require.NoError(t, err, "Unmarshaling %q should not error", jsonStr)
			assert.Equal(t, tt.kind, kind)
		})
	}

	t.Run("Empty_String_Marshal_Error", func(t *testing.T) {
		empty := ComponentKind("")
		_, err := json.Marshal(empty)
		assert.Error(t, err, "Marshaling empty ComponentKind should error")
		assert.Contains(t, err.Error(), "invalid")
	})

	t.Run("Empty_String_Unmarshal_Error", func(t *testing.T) {
		var kind ComponentKind
		err := json.Unmarshal([]byte(`""`), &kind)
		assert.Error(t, err, "Unmarshaling empty string should error")
	})
}

// TestComponentKind_Constants_StillDefined verifies that predefined constants are still available
func TestComponentKind_Constants_StillDefined(t *testing.T) {
	assert.Equal(t, "agent", string(ComponentKindAgent))
	assert.Equal(t, "tool", string(ComponentKindTool))
	assert.Equal(t, "plugin", string(ComponentKindPlugin))
	assert.Equal(t, "repository", string(ComponentKindRepository))
}

// TestAllComponentKinds_StillDefined verifies that AllComponentKinds function still exists
func TestAllComponentKinds_StillDefined(t *testing.T) {
	kinds := AllComponentKinds()
	assert.Len(t, kinds, 4)
	assert.Contains(t, kinds, ComponentKindAgent)
	assert.Contains(t, kinds, ComponentKindTool)
	assert.Contains(t, kinds, ComponentKindPlugin)
	assert.Contains(t, kinds, ComponentKindRepository)
}
