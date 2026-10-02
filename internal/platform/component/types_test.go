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

// TestAllComponentKinds tests the AllComponentKinds function
func TestAllComponentKinds(t *testing.T) {
	kinds := AllComponentKinds()
	assert.Len(t, kinds, 4)
	assert.Contains(t, kinds, ComponentKindAgent)
	assert.Contains(t, kinds, ComponentKindTool)
	assert.Contains(t, kinds, ComponentKindPlugin)
	assert.Contains(t, kinds, ComponentKindRepository)
}

// TestComponentKind_IsRepositoryKind tests that only ComponentKindRepository returns true
func TestComponentKind_IsRepositoryKind(t *testing.T) {
	tests := []struct {
		name     string
		kind     ComponentKind
		expected bool
	}{
		{"Repository", ComponentKindRepository, true},
		{"Tool", ComponentKindTool, false},
		{"Agent", ComponentKindAgent, false},
		{"Plugin", ComponentKindPlugin, false},
		{"CustomKind", ComponentKind("custom"), false},
		{"EmptyKind", ComponentKind(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.kind.IsRepositoryKind())
		})
	}
}

// TestComponentKind_IsComponentKind tests that tool, agent, plugin return true but repository returns false
func TestComponentKind_IsComponentKind(t *testing.T) {
	tests := []struct {
		name     string
		kind     ComponentKind
		expected bool
	}{
		{"Tool", ComponentKindTool, true},
		{"Agent", ComponentKindAgent, true},
		{"Plugin", ComponentKindPlugin, true},
		{"Repository", ComponentKindRepository, false},
		{"CustomKind", ComponentKind("custom"), false},
		{"EmptyKind", ComponentKind(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.kind.IsComponentKind())
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

// TestAllComponentSources tests the AllComponentSources function
func TestAllComponentSources(t *testing.T) {
	sources := AllComponentSources()
	assert.Len(t, sources, 4)
	assert.Contains(t, sources, ComponentSourceInternal)
	assert.Contains(t, sources, ComponentSourceExternal)
	assert.Contains(t, sources, ComponentSourceRemote)
	assert.Contains(t, sources, ComponentSourceConfig)
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

// TestAllComponentStatuses tests the AllComponentStatuses function
func TestAllComponentStatuses(t *testing.T) {
	statuses := AllComponentStatuses()
	assert.Len(t, statuses, 4)
	assert.Contains(t, statuses, ComponentStatusAvailable)
	assert.Contains(t, statuses, ComponentStatusRunning)
	assert.Contains(t, statuses, ComponentStatusStopped)
	assert.Contains(t, statuses, ComponentStatusError)
}

// TestComponent_Validate tests the Validate method for Component
func TestComponent_Validate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		component Component
		expectErr bool
	}{
		{
			name: "ValidComponent",
			component: Component{
				Kind:      ComponentKindAgent,
				Name:      "test-agent",
				Version:   "1.0.0",
				BinPath:   "/path/to/bin/agent",
				Source:    ComponentSourceExternal,
				Status:    ComponentStatusAvailable,
				CreatedAt: now,
				UpdatedAt: now,
			},
			expectErr: false,
		},
		{
			name: "ValidCustomKind",
			component: Component{
				Kind:      ComponentKind("custom"),
				Name:      "test",
				Version:   "1.0.0",
				BinPath:   "/path",
				Source:    ComponentSourceExternal,
				Status:    ComponentStatusAvailable,
				CreatedAt: now,
				UpdatedAt: now,
			},
			expectErr: false,
		},
		{
			name: "InvalidEmptyKind",
			component: Component{
				Kind:    ComponentKind(""),
				Name:    "test",
				Version: "1.0.0",
				BinPath: "/path",
				Source:  ComponentSourceExternal,
				Status:  ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "EmptyName",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "",
				Version: "1.0.0",
				BinPath: "/path",
				Source:  ComponentSourceExternal,
				Status:  ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "EmptyVersion",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "test",
				Version: "",
				BinPath: "/path",
				Source:  ComponentSourceExternal,
				Status:  ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "EmptyPath",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "test",
				Version: "1.0.0",
				// BinPath is empty - should fail validation
				Source: ComponentSourceExternal,
				Status: ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "InvalidSource",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "test",
				Version: "1.0.0",
				BinPath: "/path",
				Source:  ComponentSource("invalid"),
				Status:  ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "InvalidStatus",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "test",
				Version: "1.0.0",
				BinPath: "/path",
				Source:  ComponentSourceExternal,
				Status:  ComponentStatus("invalid"),
			},
			expectErr: true,
		},
		{
			name: "RemoteComponentWithoutPort",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "test",
				Version: "1.0.0",
				BinPath: "http://example.com",
				Source:  ComponentSourceRemote,
				Status:  ComponentStatusAvailable,
				Port:    0,
			},
			expectErr: true,
		},
		{
			name: "RemoteComponentWithValidPort",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "test",
				Version: "1.0.0",
				BinPath: "http://example.com",
				Source:  ComponentSourceRemote,
				Status:  ComponentStatusAvailable,
				Port:    8080,
			},
			expectErr: false,
		},
		{
			name: "RunningComponentWithoutPID",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "test",
				Version: "1.0.0",
				BinPath: "/path",
				Source:  ComponentSourceExternal,
				Status:  ComponentStatusRunning,
				PID:     0,
			},
			expectErr: true,
		},
		{
			name: "RunningComponentWithoutStartedAt",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "test",
				Version: "1.0.0",
				BinPath: "/path",
				Source:  ComponentSourceExternal,
				Status:  ComponentStatusRunning,
				PID:     1234,
			},
			expectErr: true,
		},
		{
			name: "RunningComponentValid",
			component: Component{
				Kind:      ComponentKindAgent,
				Name:      "test",
				Version:   "1.0.0",
				BinPath:   "/path",
				Source:    ComponentSourceExternal,
				Status:    ComponentStatusRunning,
				PID:       1234,
				StartedAt: &now,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.component.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestComponent_StatusChecks tests the status check methods for Component
func TestComponent_StatusChecks(t *testing.T) {
	tests := []struct {
		name            string
		status          ComponentStatus
		expectRunning   bool
		expectStopped   bool
		expectAvailable bool
		expectError     bool
	}{
		{"Running", ComponentStatusRunning, true, false, false, false},
		{"Stopped", ComponentStatusStopped, false, true, false, false},
		{"Available", ComponentStatusAvailable, false, false, true, false},
		{"Error", ComponentStatusError, false, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := Component{Status: tt.status}
			assert.Equal(t, tt.expectRunning, component.IsRunning())
			assert.Equal(t, tt.expectStopped, component.IsStopped())
			assert.Equal(t, tt.expectAvailable, component.IsAvailable())
			assert.Equal(t, tt.expectError, component.HasError())
		})
	}
}

// TestComponent_SourceChecks tests the source check methods for Component
func TestComponent_SourceChecks(t *testing.T) {
	tests := []struct {
		name           string
		source         ComponentSource
		expectRemote   bool
		expectExternal bool
		expectInternal bool
	}{
		{"Remote", ComponentSourceRemote, true, false, false},
		{"External", ComponentSourceExternal, false, true, false},
		{"Internal", ComponentSourceInternal, false, false, true},
		{"Config", ComponentSourceConfig, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component := Component{Source: tt.source}
			assert.Equal(t, tt.expectRemote, component.IsRemote())
			assert.Equal(t, tt.expectExternal, component.IsExternal())
			assert.Equal(t, tt.expectInternal, component.IsInternal())
		})
	}
}

// TestComponent_UpdateStatus tests the UpdateStatus method for Component
func TestComponent_UpdateStatus(t *testing.T) {
	t.Run("TransitionToRunning", func(t *testing.T) {
		component := Component{
			Status:    ComponentStatusAvailable,
			UpdatedAt: time.Now().Add(-1 * time.Hour),
		}
		oldUpdatedAt := component.UpdatedAt

		component.UpdateStatus(ComponentStatusRunning)

		assert.Equal(t, ComponentStatusRunning, component.Status)
		assert.NotNil(t, component.StartedAt)
		assert.Nil(t, component.StoppedAt)
		assert.True(t, component.UpdatedAt.After(oldUpdatedAt))
	})

	t.Run("TransitionToStopped", func(t *testing.T) {
		now := time.Now()
		component := Component{
			Status:    ComponentStatusRunning,
			StartedAt: &now,
			UpdatedAt: time.Now().Add(-1 * time.Hour),
		}
		oldUpdatedAt := component.UpdatedAt

		component.UpdateStatus(ComponentStatusStopped)

		assert.Equal(t, ComponentStatusStopped, component.Status)
		assert.NotNil(t, component.StoppedAt)
		assert.True(t, component.UpdatedAt.After(oldUpdatedAt))
	})

	t.Run("UpdatesTimestamp", func(t *testing.T) {
		component := Component{
			Status:    ComponentStatusAvailable,
			UpdatedAt: time.Now().Add(-1 * time.Hour),
		}
		oldUpdatedAt := component.UpdatedAt

		component.UpdateStatus(ComponentStatusError)

		assert.True(t, component.UpdatedAt.After(oldUpdatedAt))
	})
}

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
