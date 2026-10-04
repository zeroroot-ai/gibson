// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestComponentKind_String tests the String method for ComponentKind
func TestComponentKind_String(t *testing.T) {
	tests := []struct {
		name     string
		kind     ComponentKind
		expected string
	}{
		{"Agent", ComponentKindAgent, "agent"},
		{"Tool", ComponentKindTool, "tool"},
		{"Plugin", ComponentKindPlugin, "plugin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.kind.String())
		})
	}
}

// TestComponentKind_IsValid tests the IsValid method for ComponentKind
func TestComponentKind_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		kind     ComponentKind
		expected bool
	}{
		{"ValidAgent", ComponentKindAgent, true},
		{"ValidTool", ComponentKindTool, true},
		{"ValidPlugin", ComponentKindPlugin, true},
		{"ValidCustomKind", ComponentKind("custom"), true},
		{"ValidUnknown", ComponentKind("unknown"), true},
		{"ValidTypo", ComponentKind("agentt"), true},
		{"ValidAnything", ComponentKind("anything"), true},
		{"InvalidEmpty", ComponentKind(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.kind.IsValid())
		})
	}
}

// TestComponentKind_MarshalJSON tests JSON marshaling for ComponentKind
func TestComponentKind_MarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		kind      ComponentKind
		expectErr bool
	}{
		{"ValidAgent", ComponentKindAgent, false},
		{"ValidTool", ComponentKindTool, false},
		{"ValidPlugin", ComponentKindPlugin, false},
		{"ValidCustomKind", ComponentKind("custom"), false},
		{"ValidAnything", ComponentKind("anything"), false},
		{"InvalidEmpty", ComponentKind(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.kind)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, data)
				assert.Equal(t, `"`+tt.kind.String()+`"`, string(data))
			}
		})
	}
}

// TestComponentKind_UnmarshalJSON tests JSON unmarshaling for ComponentKind
func TestComponentKind_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		expected  ComponentKind
		expectErr bool
	}{
		{"ValidAgent", `"agent"`, ComponentKindAgent, false},
		{"ValidTool", `"tool"`, ComponentKindTool, false},
		{"ValidPlugin", `"plugin"`, ComponentKindPlugin, false},
		{"ValidCustomKind", `"custom"`, ComponentKind("custom"), false},
		{"ValidAnything", `"anything"`, ComponentKind("anything"), false},
		{"InvalidEmpty", `""`, "", true},
		{"InvalidJSON", `invalid`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var kind ComponentKind
			err := json.Unmarshal([]byte(tt.json), &kind)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, kind)
			}
		})
	}
}

// TestParseComponentKind tests the ParseComponentKind function
func TestParseComponentKind(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  ComponentKind
		expectErr bool
	}{
		{"ValidAgent", "agent", ComponentKindAgent, false},
		{"ValidTool", "tool", ComponentKindTool, false},
		{"ValidPlugin", "plugin", ComponentKindPlugin, false},
		{"ValidCustomKind", "custom", ComponentKind("custom"), false},
		{"ValidUnknown", "unknown", ComponentKind("unknown"), false},
		{"ValidAnything", "anything", ComponentKind("anything"), false},
		{"InvalidEmpty", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseComponentKind(tt.input)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestComponentSource_String tests the String method for ComponentSource
func TestComponentSource_String(t *testing.T) {
	tests := []struct {
		name     string
		source   ComponentSource
		expected string
	}{
		{"Internal", ComponentSourceInternal, "internal"},
		{"External", ComponentSourceExternal, "external"},
		{"Remote", ComponentSourceRemote, "remote"},
		{"Config", ComponentSourceConfig, "config"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.source.String())
		})
	}
}

// TestComponentSource_IsValid tests the IsValid method for ComponentSource
func TestComponentSource_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		source   ComponentSource
		expected bool
	}{
		{"ValidInternal", ComponentSourceInternal, true},
		{"ValidExternal", ComponentSourceExternal, true},
		{"ValidRemote", ComponentSourceRemote, true},
		{"ValidConfig", ComponentSourceConfig, true},
		{"InvalidEmpty", ComponentSource(""), false},
		{"InvalidUnknown", ComponentSource("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.source.IsValid())
		})
	}
}

// TestComponentSource_MarshalJSON tests JSON marshaling for ComponentSource
func TestComponentSource_MarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		source    ComponentSource
		expectErr bool
	}{
		{"ValidInternal", ComponentSourceInternal, false},
		{"ValidExternal", ComponentSourceExternal, false},
		{"ValidRemote", ComponentSourceRemote, false},
		{"ValidConfig", ComponentSourceConfig, false},
		{"InvalidSource", ComponentSource("invalid"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.source)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, data)
			}
		})
	}
}

// TestComponentStatus_String tests the String method for ComponentStatus
func TestComponentStatus_String(t *testing.T) {
	tests := []struct {
		name     string
		status   ComponentStatus
		expected string
	}{
		{"Available", ComponentStatusAvailable, "available"},
		{"Running", ComponentStatusRunning, "running"},
		{"Stopped", ComponentStatusStopped, "stopped"},
		{"Error", ComponentStatusError, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

// TestComponentStatus_IsValid tests the IsValid method for ComponentStatus
func TestComponentStatus_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		status   ComponentStatus
		expected bool
	}{
		{"ValidAvailable", ComponentStatusAvailable, true},
		{"ValidRunning", ComponentStatusRunning, true},
		{"ValidStopped", ComponentStatusStopped, true},
		{"ValidError", ComponentStatusError, true},
		{"InvalidEmpty", ComponentStatus(""), false},
		{"InvalidUnknown", ComponentStatus("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.IsValid())
		})
	}
}

// BinPath is empty - should fail validation

// TestComponent_JSONMarshaling tests JSON marshaling/unmarshaling for Component
func TestComponent_JSONMarshaling(t *testing.T) {
	now := time.Now()
	original := Component{
		Kind:      ComponentKindAgent,
		Name:      "test-agent",
		Version:   "1.0.0",
		BinPath:   "/path/to/bin/agent",
		Source:    ComponentSourceExternal,
		Status:    ComponentStatusRunning,
		Port:      8080,
		PID:       1234,
		CreatedAt: now,
		UpdatedAt: now,
		StartedAt: &now,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var unmarshaled Component
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.Kind, unmarshaled.Kind)
	assert.Equal(t, original.Name, unmarshaled.Name)
	assert.Equal(t, original.Version, unmarshaled.Version)
	assert.Equal(t, original.BinPath, unmarshaled.BinPath)
	assert.Equal(t, original.Source, unmarshaled.Source)
	assert.Equal(t, original.Status, unmarshaled.Status)
	assert.Equal(t, original.Port, unmarshaled.Port)
	assert.Equal(t, original.PID, unmarshaled.PID)
}
