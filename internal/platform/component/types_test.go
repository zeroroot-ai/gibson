package component

import (
	"encoding/json"
	"os"
	"path/filepath"
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
				RepoPath:  "/path/to/agent",
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
				RepoPath:  "/path",
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
				Kind:     ComponentKind(""),
				Name:     "test",
				Version:  "1.0.0",
				RepoPath: "/path",
				Source:   ComponentSourceExternal,
				Status:   ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "EmptyName",
			component: Component{
				Kind:     ComponentKindAgent,
				Name:     "",
				Version:  "1.0.0",
				RepoPath: "/path",
				Source:   ComponentSourceExternal,
				Status:   ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "EmptyVersion",
			component: Component{
				Kind:     ComponentKindAgent,
				Name:     "test",
				Version:  "",
				RepoPath: "/path",
				Source:   ComponentSourceExternal,
				Status:   ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "EmptyPath",
			component: Component{
				Kind:    ComponentKindAgent,
				Name:    "test",
				Version: "1.0.0",
				// Both RepoPath and BinPath are empty - should fail validation
				Source: ComponentSourceExternal,
				Status: ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "InvalidSource",
			component: Component{
				Kind:     ComponentKindAgent,
				Name:     "test",
				Version:  "1.0.0",
				RepoPath: "/path",
				Source:   ComponentSource("invalid"),
				Status:   ComponentStatusAvailable,
			},
			expectErr: true,
		},
		{
			name: "InvalidStatus",
			component: Component{
				Kind:     ComponentKindAgent,
				Name:     "test",
				Version:  "1.0.0",
				RepoPath: "/path",
				Source:   ComponentSourceExternal,
				Status:   ComponentStatus("invalid"),
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
				Kind:     ComponentKindAgent,
				Name:     "test",
				Version:  "1.0.0",
				RepoPath: "/path",
				Source:   ComponentSourceExternal,
				Status:   ComponentStatusRunning,
				PID:      0,
			},
			expectErr: true,
		},
		{
			name: "RunningComponentWithoutStartedAt",
			component: Component{
				Kind:     ComponentKindAgent,
				Name:     "test",
				Version:  "1.0.0",
				RepoPath: "/path",
				Source:   ComponentSourceExternal,
				Status:   ComponentStatusRunning,
				PID:      1234,
			},
			expectErr: true,
		},
		{
			name: "RunningComponentValid",
			component: Component{
				Kind:      ComponentKindAgent,
				Name:      "test",
				Version:   "1.0.0",
				RepoPath:  "/path",
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
		RepoPath:  "/path/to/agent",
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
	assert.Equal(t, original.RepoPath, unmarshaled.RepoPath)
	assert.Equal(t, original.BinPath, unmarshaled.BinPath)
	assert.Equal(t, original.Source, unmarshaled.Source)
	assert.Equal(t, original.Status, unmarshaled.Status)
	assert.Equal(t, original.Port, unmarshaled.Port)
	assert.Equal(t, original.PID, unmarshaled.PID)
}

// TestLoadManifest tests the LoadManifest function
func TestLoadManifest(t *testing.T) {
	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "gibson-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	t.Run("LoadValidJSONManifest", func(t *testing.T) {
		manifestPath := filepath.Join(tmpDir, "manifest.json")
		manifestContent := `{
			"kind": "agent",
			"name": "test-agent",
			"version": "1.0.0",
			"description": "Test agent",
			"runtime": {
				"type": "go",
				"entrypoint": "./agent"
			}
		}`
		err := os.WriteFile(manifestPath, []byte(manifestContent), 0644)
		require.NoError(t, err)

		manifest, err := LoadManifest(manifestPath)
		require.NoError(t, err)
		assert.NotNil(t, manifest)
		assert.Equal(t, "test-agent", manifest.Name)
		assert.Equal(t, "1.0.0", manifest.Version)
	})

	t.Run("LoadValidYAMLManifest", func(t *testing.T) {
		manifestPath := filepath.Join(tmpDir, "manifest.yaml")
		manifestContent := `kind: tool
name: test-tool
version: 2.0.0
description: Test tool
runtime:
  type: python
  entrypoint: ./tool.py
`
		err := os.WriteFile(manifestPath, []byte(manifestContent), 0644)
		require.NoError(t, err)

		manifest, err := LoadManifest(manifestPath)
		require.NoError(t, err)
		assert.NotNil(t, manifest)
		assert.Equal(t, "test-tool", manifest.Name)
		assert.Equal(t, "2.0.0", manifest.Version)
	})

	t.Run("ManifestNotFound", func(t *testing.T) {
		manifestPath := filepath.Join(tmpDir, "nonexistent.json")
		manifest, err := LoadManifest(manifestPath)
		assert.Error(t, err)
		assert.Nil(t, manifest)
		var compErr *ComponentError
		assert.ErrorAs(t, err, &compErr)
		assert.Equal(t, ErrCodeManifestNotFound, compErr.Code)
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		manifestPath := filepath.Join(tmpDir, "invalid.json")
		err := os.WriteFile(manifestPath, []byte("invalid json"), 0644)
		require.NoError(t, err)

		manifest, err := LoadManifest(manifestPath)
		assert.Error(t, err)
		assert.Nil(t, manifest)
	})

	t.Run("UnsupportedFormat", func(t *testing.T) {
		manifestPath := filepath.Join(tmpDir, "manifest.txt")
		err := os.WriteFile(manifestPath, []byte("content"), 0644)
		require.NoError(t, err)

		manifest, err := LoadManifest(manifestPath)
		assert.Error(t, err)
		assert.Nil(t, manifest)
	})

	t.Run("InvalidManifestContent", func(t *testing.T) {
		manifestPath := filepath.Join(tmpDir, "invalid-content.json")
		manifestContent := `{
			"name": "",
			"version": "1.0.0"
		}`
		err := os.WriteFile(manifestPath, []byte(manifestContent), 0644)
		require.NoError(t, err)

		manifest, err := LoadManifest(manifestPath)
		assert.Error(t, err)
		assert.Nil(t, manifest)
	})
}

// TestRuntimeType_IsValid tests the IsValid method for RuntimeType
func TestRuntimeType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		runtime  RuntimeType
		expected bool
	}{
		{"ValidGo", RuntimeTypeGo, true},
		{"ValidPython", RuntimeTypePython, true},
		{"ValidNode", RuntimeTypeNode, true},
		{"ValidDocker", RuntimeTypeDocker, true},
		{"ValidBinary", RuntimeTypeBinary, true},
		{"ValidHTTP", RuntimeTypeHTTP, true},
		{"ValidGRPC", RuntimeTypeGRPC, true},
		{"InvalidEmpty", RuntimeType(""), false},
		{"InvalidUnknown", RuntimeType("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.runtime.IsValid())
		})
	}
}

// TestAllRuntimeTypes tests the AllRuntimeTypes function
func TestAllRuntimeTypes(t *testing.T) {
	runtimes := AllRuntimeTypes()
	assert.Len(t, runtimes, 7)
	assert.Contains(t, runtimes, RuntimeTypeGo)
	assert.Contains(t, runtimes, RuntimeTypePython)
	assert.Contains(t, runtimes, RuntimeTypeNode)
	assert.Contains(t, runtimes, RuntimeTypeDocker)
	assert.Contains(t, runtimes, RuntimeTypeBinary)
	assert.Contains(t, runtimes, RuntimeTypeHTTP)
	assert.Contains(t, runtimes, RuntimeTypeGRPC)
}

// TestManifest_Validate tests the Validate method for Manifest
func TestManifest_Validate(t *testing.T) {
	tests := []struct {
		name      string
		manifest  Manifest
		expectErr bool
	}{
		{
			name: "ValidManifest",
			manifest: Manifest{
				Name:    "test-agent",
				Version: "1.0.0",
				Runtime: &RuntimeConfig{
					Type:       RuntimeTypeGo,
					Entrypoint: "./agent",
				},
			},
			expectErr: false,
		},
		{
			name: "InvalidRuntimeType",
			manifest: Manifest{
				Name:    "test",
				Version: "1.0.0",
				Runtime: &RuntimeConfig{
					Type:       RuntimeType("invalid"),
					Entrypoint: "./test",
				},
			},
			expectErr: true,
		},
		{
			name: "EmptyName",
			manifest: Manifest{
				Name:    "",
				Version: "1.0.0",
				Runtime: &RuntimeConfig{
					Type:       RuntimeTypeGo,
					Entrypoint: "./test",
				},
			},
			expectErr: true,
		},
		{
			name: "InvalidName",
			manifest: Manifest{
				Name:    "test@invalid!",
				Version: "1.0.0",
				Runtime: &RuntimeConfig{
					Type:       RuntimeTypeGo,
					Entrypoint: "./test",
				},
			},
			expectErr: true,
		},
		{
			name: "EmptyVersion",
			manifest: Manifest{
				Name:    "test",
				Version: "",
				Runtime: &RuntimeConfig{
					Type:       RuntimeTypeGo,
					Entrypoint: "./test",
				},
			},
			expectErr: true,
		},
		{
			name: "InvalidVersion",
			manifest: Manifest{
				Name:    "test",
				Version: "invalid",
				Runtime: &RuntimeConfig{
					Type:       RuntimeTypeGo,
					Entrypoint: "./test",
				},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.manifest.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestRuntimeConfig_Validate tests the Validate method for RuntimeConfig
func TestRuntimeConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		runtime   RuntimeConfig
		expectErr bool
	}{
		{
			name: "ValidGoRuntime",
			runtime: RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "./app",
			},
			expectErr: false,
		},
		{
			name: "ValidHTTPRuntime",
			runtime: RuntimeConfig{
				Type:       RuntimeTypeHTTP,
				Entrypoint: "./server",
				Port:       8080,
			},
			expectErr: false,
		},
		{
			name: "ValidDockerRuntime",
			runtime: RuntimeConfig{
				Type:       RuntimeTypeDocker,
				Entrypoint: "./app",
				Image:      "myapp:latest",
			},
			expectErr: false,
		},
		{
			name: "InvalidRuntimeType",
			runtime: RuntimeConfig{
				Type:       RuntimeType("invalid"),
				Entrypoint: "./app",
			},
			expectErr: true,
		},
		{
			name: "EmptyEntrypoint",
			runtime: RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "",
			},
			expectErr: true,
		},
		{
			name: "HTTPWithoutPort",
			runtime: RuntimeConfig{
				Type:       RuntimeTypeHTTP,
				Entrypoint: "./server",
				Port:       0,
			},
			expectErr: true,
		},
		{
			name: "DockerWithoutImage",
			runtime: RuntimeConfig{
				Type:       RuntimeTypeDocker,
				Entrypoint: "./app",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.runtime.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestBuildConfig_Validate tests the Validate method for BuildConfig
func TestBuildConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		build     BuildConfig
		expectErr bool
	}{
		{
			name: "ValidBuildCommand",
			build: BuildConfig{
				Command: "go build",
			},
			expectErr: false,
		},
		{
			name: "ValidDockerfile",
			build: BuildConfig{
				Dockerfile: "./Dockerfile",
				Context:    ".",
			},
			expectErr: false,
		},
		{
			name: "EmptyCommandAndDockerfile",
			build: BuildConfig{
				Command:    "",
				Dockerfile: "",
			},
			expectErr: true,
		},
		{
			name: "DockerfileWithoutContext",
			build: BuildConfig{
				Dockerfile: "./Dockerfile",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.build.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestComponentDependencies_Validate tests the Validate method for ComponentDependencies
func TestComponentDependencies_Validate(t *testing.T) {
	tests := []struct {
		name      string
		deps      ComponentDependencies
		expectErr bool
	}{
		{
			name: "ValidGibsonVersion",
			deps: ComponentDependencies{
				Gibson: ">=1.0.0",
			},
			expectErr: false,
		},
		{
			name: "ValidComponentDeps",
			deps: ComponentDependencies{
				Components: []string{"tool1@1.0.0", "plugin1@2.0.0"},
			},
			expectErr: false,
		},
		{
			name: "InvalidGibsonVersion",
			deps: ComponentDependencies{
				Gibson: "invalid",
			},
			expectErr: true,
		},
		{
			name: "InvalidComponentDep",
			deps: ComponentDependencies{
				Components: []string{"invalid-format"},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.deps.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidationHelpers tests the validation helper functions
func TestValidationHelpers(t *testing.T) {
	t.Run("isValidComponentName", func(t *testing.T) {
		tests := []struct {
			name     string
			input    string
			expected bool
		}{
			{"ValidSimple", "mycomponent", true},
			{"ValidWithDash", "my-component", true},
			{"ValidWithUnderscore", "my_component", true},
			{"ValidAlphanumeric", "component123", true},
			{"InvalidEmpty", "", false},
			{"InvalidSpecialChars", "my@component", false},
			{"InvalidSpace", "my component", false},
			{"InvalidDot", "my.component", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := isValidComponentName(tt.input)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("isValidSemanticVersion", func(t *testing.T) {
		tests := []struct {
			name     string
			input    string
			expected bool
		}{
			{"ValidMajorMinorPatch", "1.0.0", true},
			{"ValidMajorMinor", "1.0", true},
			{"ValidWithPrerelease", "1.0.0-alpha", true},
			{"ValidWithBuild", "1.0.0+build", true},
			{"ValidComplex", "1.0.0-alpha+build", true},
			{"InvalidEmpty", "", false},
			{"InvalidSingleNumber", "1", false},
			{"InvalidNonNumeric", "1.a.0", false},
			{"InvalidFormat", "invalid", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := isValidSemanticVersion(tt.input)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("isValidVersionConstraint", func(t *testing.T) {
		tests := []struct {
			name     string
			input    string
			expected bool
		}{
			{"ValidExact", "1.0.0", true},
			{"ValidGreaterOrEqual", ">=1.0.0", true},
			{"ValidLessThan", "<2.0.0", true},
			{"ValidTilde", "~1.2.0", true},
			{"ValidCaret", "^1.0.0", true},
			{"InvalidEmpty", "", false},
			{"InvalidFormat", "invalid", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := isValidVersionConstraint(tt.input)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("isValidDependency", func(t *testing.T) {
		tests := []struct {
			name     string
			input    string
			expected bool
		}{
			{"ValidDependency", "component@1.0.0", true},
			{"ValidWithConstraint", "component@>=1.0.0", true},
			{"InvalidEmpty", "", false},
			{"InvalidNoVersion", "component", false},
			{"InvalidNoName", "@1.0.0", false},
			{"InvalidMultipleAt", "comp@1.0.0@extra", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := isValidDependency(tt.input)
				assert.Equal(t, tt.expected, result)
			})
		}
	})
}

// TestRuntimeConfig_HelperMethods tests the helper methods for RuntimeConfig
func TestRuntimeConfig_HelperMethods(t *testing.T) {
	t.Run("IsNetworkBased", func(t *testing.T) {
		tests := []struct {
			runtime  RuntimeType
			expected bool
		}{
			{RuntimeTypeHTTP, true},
			{RuntimeTypeGRPC, true},
			{RuntimeTypeGo, false},
			{RuntimeTypePython, false},
			{RuntimeTypeDocker, false},
		}

		for _, tt := range tests {
			runtime := RuntimeConfig{Type: tt.runtime}
			assert.Equal(t, tt.expected, runtime.IsNetworkBased())
		}
	})

	t.Run("IsContainerBased", func(t *testing.T) {
		tests := []struct {
			runtime  RuntimeType
			expected bool
		}{
			{RuntimeTypeDocker, true},
			{RuntimeTypeHTTP, false},
			{RuntimeTypeGo, false},
		}

		for _, tt := range tests {
			runtime := RuntimeConfig{Type: tt.runtime}
			assert.Equal(t, tt.expected, runtime.IsContainerBased())
		}
	})

	t.Run("GetEnv", func(t *testing.T) {
		runtime := RuntimeConfig{}
		assert.NotNil(t, runtime.GetEnv())
		assert.Len(t, runtime.GetEnv(), 0)

		runtime.Env = map[string]string{"KEY": "value"}
		assert.Len(t, runtime.GetEnv(), 1)
		assert.Equal(t, "value", runtime.GetEnv()["KEY"])
	})

	t.Run("GetArgs", func(t *testing.T) {
		runtime := RuntimeConfig{}
		assert.NotNil(t, runtime.GetArgs())
		assert.Len(t, runtime.GetArgs(), 0)

		runtime.Args = []string{"arg1", "arg2"}
		assert.Len(t, runtime.GetArgs(), 2)
	})
}

// TestComponentDependencies_HelperMethods tests the helper methods for ComponentDependencies
func TestComponentDependencies_HelperMethods(t *testing.T) {
	t.Run("HasDependencies", func(t *testing.T) {
		deps := ComponentDependencies{}
		assert.False(t, deps.HasDependencies())

		deps.Gibson = ">=1.0.0"
		assert.True(t, deps.HasDependencies())
	})

	t.Run("GetComponents", func(t *testing.T) {
		deps := ComponentDependencies{}
		assert.NotNil(t, deps.GetComponents())
		assert.Len(t, deps.GetComponents(), 0)

		deps.Components = []string{"comp@1.0.0"}
		assert.Len(t, deps.GetComponents(), 1)
	})
}
