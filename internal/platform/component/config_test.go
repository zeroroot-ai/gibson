package component

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLogger implements the Logger interface for testing.
type mockLogger struct {
	warnings []string
}

func (m *mockLogger) Warnf(format string, args ...interface{}) {
	m.warnings = append(m.warnings, fmt.Sprintf(format, args...))
}

func (m *mockLogger) hasWarning(substr string) bool {
	for _, w := range m.warnings {
		if containsString(w, substr) {
			return true
		}
	}
	return false
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestComponentConfig_Validate tests the validation of ComponentConfig.
func TestComponentConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ComponentConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid internal component",
			config: ComponentConfig{
				Name:   "test-agent",
				Source: ComponentSourceInternal,
			},
			wantErr: false,
		},
		{
			name: "valid external component with path",
			config: ComponentConfig{
				Name:   "external-tool",
				Source: ComponentSourceExternal,
				Path:   "/usr/local/bin/tool",
			},
			wantErr: false,
		},
		{
			name: "valid remote component with repo and branch",
			config: ComponentConfig{
				Name:   "remote-plugin",
				Source: ComponentSourceRemote,
				Repo:   "https://github.com/example/plugin",
				Branch: "main",
			},
			wantErr: false,
		},
		{
			name: "valid remote component with repo and tag",
			config: ComponentConfig{
				Name:   "remote-plugin",
				Source: ComponentSourceRemote,
				Repo:   "https://github.com/example/plugin",
				Tag:    "v1.0.0",
			},
			wantErr: false,
		},
		{
			name: "valid config component",
			config: ComponentConfig{
				Name:   "config-based",
				Source: ComponentSourceConfig,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			config: ComponentConfig{
				Name:   "",
				Source: ComponentSourceInternal,
			},
			wantErr: true,
			errMsg:  "component name is required",
		},
		{
			name: "invalid name - starts with digit",
			config: ComponentConfig{
				Name:   "123-invalid",
				Source: ComponentSourceInternal,
			},
			wantErr: true,
			errMsg:  "invalid component name",
		},
		{
			name: "invalid name - special characters",
			config: ComponentConfig{
				Name:   "invalid@name",
				Source: ComponentSourceInternal,
			},
			wantErr: true,
			errMsg:  "invalid component name",
		},
		{
			name: "invalid source",
			config: ComponentConfig{
				Name:   "test",
				Source: ComponentSource("invalid"),
			},
			wantErr: true,
			errMsg:  "invalid component source",
		},
		{
			name: "external component missing path",
			config: ComponentConfig{
				Name:   "external-tool",
				Source: ComponentSourceExternal,
			},
			wantErr: true,
			errMsg:  "path is required for external components",
		},
		{
			name: "remote component missing repo",
			config: ComponentConfig{
				Name:   "remote-plugin",
				Source: ComponentSourceRemote,
			},
			wantErr: true,
			errMsg:  "repo is required for remote components",
		},
		{
			name: "remote component with both branch and tag",
			config: ComponentConfig{
				Name:   "remote-plugin",
				Source: ComponentSourceRemote,
				Repo:   "https://github.com/example/plugin",
				Branch: "main",
				Tag:    "v1.0.0",
			},
			wantErr: true,
			errMsg:  "cannot specify both branch and tag",
		},
		{
			name: "valid name with underscore",
			config: ComponentConfig{
				Name:   "_valid_name",
				Source: ComponentSourceInternal,
			},
			wantErr: false,
		},
		{
			name: "valid name with hyphen",
			config: ComponentConfig{
				Name:   "valid-name-123",
				Source: ComponentSourceInternal,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestComponentConfig_GetSettings tests the GetSettings method.
func TestComponentConfig_GetSettings(t *testing.T) {
	t.Run("nil settings returns empty map", func(t *testing.T) {
		config := ComponentConfig{Settings: nil}
		settings := config.GetSettings()
		assert.NotNil(t, settings)
		assert.Equal(t, 0, len(settings))
	})

	t.Run("existing settings returned as-is", func(t *testing.T) {
		config := ComponentConfig{
			Settings: map[string]interface{}{
				"key1": "value1",
				"key2": 42,
			},
		}
		settings := config.GetSettings()
		assert.Equal(t, 2, len(settings))
		assert.Equal(t, "value1", settings["key1"])
		assert.Equal(t, 42, settings["key2"])
	})
}

// TestComponentConfig_IsAutoStart tests the IsAutoStart method.
func TestComponentConfig_IsAutoStart(t *testing.T) {
	tests := []struct {
		name      string
		autoStart bool
		want      bool
	}{
		{
			name:      "auto start enabled",
			autoStart: true,
			want:      true,
		},
		{
			name:      "auto start disabled",
			autoStart: false,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ComponentConfig{AutoStart: tt.autoStart}
			assert.Equal(t, tt.want, config.IsAutoStart())
		})
	}
}

// TestComponentsConfig_Validate tests the validation of ComponentsConfig.
func TestComponentsConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ComponentsConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with all component types",
			config: ComponentsConfig{
				Agents: []ComponentConfig{
					{Name: "agent1", Source: ComponentSourceInternal},
				},
				Tools: []ComponentConfig{
					{Name: "tool1", Source: ComponentSourceInternal},
				},
				Plugins: []ComponentConfig{
					{Name: "plugin1", Source: ComponentSourceInternal},
				},
			},
			wantErr: false,
		},
		{
			name: "empty config is valid",
			config: ComponentsConfig{
				Agents:  []ComponentConfig{},
				Tools:   []ComponentConfig{},
				Plugins: []ComponentConfig{},
			},
			wantErr: false,
		},
		{
			name: "invalid agent",
			config: ComponentsConfig{
				Agents: []ComponentConfig{
					{Name: "", Source: ComponentSourceInternal},
				},
			},
			wantErr: true,
			errMsg:  "invalid agent configuration at index 0",
		},
		{
			name: "invalid tool",
			config: ComponentsConfig{
				Tools: []ComponentConfig{
					{Name: "tool1", Source: ComponentSource("invalid")},
				},
			},
			wantErr: true,
			errMsg:  "invalid tool configuration at index 0",
		},
		{
			name: "invalid plugin",
			config: ComponentsConfig{
				Plugins: []ComponentConfig{
					{Name: "plugin1", Source: ComponentSourceExternal}, // missing path
				},
			},
			wantErr: true,
			errMsg:  "invalid plugin configuration at index 0",
		},
		{
			name: "duplicate name across agents",
			config: ComponentsConfig{
				Agents: []ComponentConfig{
					{Name: "duplicate", Source: ComponentSourceInternal},
					{Name: "duplicate", Source: ComponentSourceInternal},
				},
			},
			wantErr: true,
			errMsg:  "duplicate component name: duplicate",
		},
		{
			name: "duplicate name across different kinds",
			config: ComponentsConfig{
				Agents: []ComponentConfig{
					{Name: "duplicate", Source: ComponentSourceInternal},
				},
				Tools: []ComponentConfig{
					{Name: "duplicate", Source: ComponentSourceInternal},
				},
			},
			wantErr: true,
			errMsg:  "duplicate component name: duplicate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestComponentsConfig_AllComponents tests the AllComponents method.
func TestComponentsConfig_AllComponents(t *testing.T) {
	config := ComponentsConfig{
		Agents: []ComponentConfig{
			{Name: "agent1", Source: ComponentSourceInternal},
			{Name: "agent2", Source: ComponentSourceInternal},
		},
		Tools: []ComponentConfig{
			{Name: "tool1", Source: ComponentSourceInternal},
		},
		Plugins: []ComponentConfig{
			{Name: "plugin1", Source: ComponentSourceInternal},
			{Name: "plugin2", Source: ComponentSourceInternal},
			{Name: "plugin3", Source: ComponentSourceInternal},
		},
	}

	all := config.AllComponents()
	assert.Equal(t, 6, len(all))
}

// TestComponentsConfig_ComponentsByKind tests the ComponentsByKind method.
func TestComponentsConfig_ComponentsByKind(t *testing.T) {
	config := ComponentsConfig{
		Agents: []ComponentConfig{
			{Name: "agent1", Source: ComponentSourceInternal},
		},
		Tools: []ComponentConfig{
			{Name: "tool1", Source: ComponentSourceInternal},
			{Name: "tool2", Source: ComponentSourceInternal},
		},
		Plugins: []ComponentConfig{
			{Name: "plugin1", Source: ComponentSourceInternal},
		},
	}

	agents := config.ComponentsByKind(ComponentKindAgent)
	assert.Equal(t, 1, len(agents))
	assert.Equal(t, "agent1", agents[0].Name)

	tools := config.ComponentsByKind(ComponentKindTool)
	assert.Equal(t, 2, len(tools))

	plugins := config.ComponentsByKind(ComponentKindPlugin)
	assert.Equal(t, 1, len(plugins))

	invalid := config.ComponentsByKind(ComponentKind("invalid"))
	assert.Equal(t, 0, len(invalid))
}

// TestLoadComponentsFromConfig tests the LoadComponentsFromConfig function.
func TestLoadComponentsFromConfig(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantErr  bool
		errMsg   string
		validate func(t *testing.T, cfg *ComponentsConfig, logger *mockLogger)
	}{
		{
			name: "valid complete configuration",
			yaml: `
components:
  agents:
    - name: test-agent
      source: internal
      auto_start: true
      settings:
        model: gpt-4
        temperature: 0.7
  tools:
    - name: test-tool
      source: external
      path: /usr/local/bin/tool
      auto_start: false
  plugins:
    - name: test-plugin
      source: remote
      repo: https://github.com/example/plugin
      branch: main
      auto_start: true
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *ComponentsConfig, logger *mockLogger) {
				require.NotNil(t, cfg)
				assert.Equal(t, 1, len(cfg.Agents))
				assert.Equal(t, 1, len(cfg.Tools))
				assert.Equal(t, 1, len(cfg.Plugins))
				assert.Equal(t, "test-agent", cfg.Agents[0].Name)
				assert.True(t, cfg.Agents[0].AutoStart)
				assert.Equal(t, ComponentSourceInternal, cfg.Agents[0].Source)
				assert.Equal(t, "test-tool", cfg.Tools[0].Name)
				assert.Equal(t, "/usr/local/bin/tool", cfg.Tools[0].Path)
				assert.Equal(t, "test-plugin", cfg.Plugins[0].Name)
				assert.Equal(t, "https://github.com/example/plugin", cfg.Plugins[0].Repo)
			},
		},
		{
			name: "empty components section",
			yaml: `
components:
  agents: []
  tools: []
  plugins: []
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *ComponentsConfig, logger *mockLogger) {
				require.NotNil(t, cfg)
				assert.Equal(t, 0, len(cfg.Agents))
				assert.Equal(t, 0, len(cfg.Tools))
				assert.Equal(t, 0, len(cfg.Plugins))
			},
		},
		{
			name: "missing components section",
			yaml: `
other_config:
  key: value
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *ComponentsConfig, logger *mockLogger) {
				require.NotNil(t, cfg)
				assert.Equal(t, 0, len(cfg.Agents))
			},
		},
		{
			name: "invalid component skipped with warning",
			yaml: `
components:
  agents:
    - name: valid-agent
      source: internal
    - name: ""
      source: internal
    - name: another-valid
      source: internal
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *ComponentsConfig, logger *mockLogger) {
				require.NotNil(t, cfg)
				assert.Equal(t, 2, len(cfg.Agents)) // Only valid ones
				assert.Equal(t, 1, len(logger.warnings))
				assert.True(t, logger.hasWarning("Skipping invalid agent"))
			},
		},
		{
			name: "external component missing path skipped",
			yaml: `
components:
  tools:
    - name: valid-tool
      source: internal
    - name: invalid-tool
      source: external
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *ComponentsConfig, logger *mockLogger) {
				require.NotNil(t, cfg)
				assert.Equal(t, 1, len(cfg.Tools))
				assert.Equal(t, "valid-tool", cfg.Tools[0].Name)
				assert.True(t, logger.hasWarning("path is required"))
			},
		},
		{
			name: "remote component missing repo skipped",
			yaml: `
components:
  plugins:
    - name: valid-plugin
      source: internal
    - name: invalid-plugin
      source: remote
      branch: main
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *ComponentsConfig, logger *mockLogger) {
				require.NotNil(t, cfg)
				assert.Equal(t, 1, len(cfg.Plugins))
				assert.Equal(t, "valid-plugin", cfg.Plugins[0].Name)
				assert.True(t, logger.hasWarning("repo is required"))
			},
		},
		{
			name: "malformed YAML",
			yaml: `
components:
  agents:
    - name: test
      source: internal
    invalid yaml structure here
`,
			wantErr: true,
			errMsg:  "failed to parse YAML",
		},
		{
			name: "duplicate names across kinds",
			yaml: `
components:
  agents:
    - name: duplicate
      source: internal
  tools:
    - name: duplicate
      source: internal
`,
			wantErr: true,
			errMsg:  "duplicate component name",
		},
		{
			name: "invalid source value",
			yaml: `
components:
  agents:
    - name: test-agent
      source: invalid-source
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *ComponentsConfig, logger *mockLogger) {
				// Invalid source should be caught during validation and skipped
				assert.Equal(t, 0, len(cfg.Agents))
				assert.True(t, logger.hasWarning("invalid component source"))
			},
		},
		{
			name: "component with settings",
			yaml: `
components:
  agents:
    - name: configured-agent
      source: internal
      settings:
        timeout: 30
        retries: 3
        endpoints:
          - https://api1.example.com
          - https://api2.example.com
`,
			wantErr: false,
			validate: func(t *testing.T, cfg *ComponentsConfig, logger *mockLogger) {
				require.NotNil(t, cfg)
				assert.Equal(t, 1, len(cfg.Agents))
				settings := cfg.Agents[0].GetSettings()
				assert.NotNil(t, settings["timeout"])
				assert.NotNil(t, settings["retries"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &mockLogger{warnings: []string{}}
			cfg, err := LoadComponentsFromConfig([]byte(tt.yaml), logger)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, cfg, logger)
				}
			}
		})
	}
}

// TestLoadComponentsFromConfig_NoLogger tests loading without a logger.
func TestLoadComponentsFromConfig_NoLogger(t *testing.T) {
	yaml := `
components:
  agents:
    - name: valid-agent
      source: internal
    - name: ""
      source: internal
`

	cfg, err := LoadComponentsFromConfig([]byte(yaml), nil)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 1, len(cfg.Agents)) // Invalid one skipped silently
}

// TestComponentsConfig_GetComponentByName tests the GetComponentByName method.
func TestComponentsConfig_GetComponentByName(t *testing.T) {
	config := ComponentsConfig{
		Agents: []ComponentConfig{
			{Name: "agent1", Source: ComponentSourceInternal},
		},
		Tools: []ComponentConfig{
			{Name: "tool1", Source: ComponentSourceInternal},
		},
		Plugins: []ComponentConfig{
			{Name: "plugin1", Source: ComponentSourceInternal},
		},
	}

	t.Run("find agent", func(t *testing.T) {
		comp, found := config.GetComponentByName("agent1")
		assert.True(t, found)
		assert.Equal(t, "agent1", comp.Name)
	})

	t.Run("find tool", func(t *testing.T) {
		comp, found := config.GetComponentByName("tool1")
		assert.True(t, found)
		assert.Equal(t, "tool1", comp.Name)
	})

	t.Run("find plugin", func(t *testing.T) {
		comp, found := config.GetComponentByName("plugin1")
		assert.True(t, found)
		assert.Equal(t, "plugin1", comp.Name)
	})

	t.Run("not found", func(t *testing.T) {
		_, found := config.GetComponentByName("nonexistent")
		assert.False(t, found)
	})
}

// TestComponentsConfig_CountMethods tests the counting methods.
func TestComponentsConfig_CountMethods(t *testing.T) {
	config := ComponentsConfig{
		Agents: []ComponentConfig{
			{Name: "agent1", Source: ComponentSourceInternal, AutoStart: true},
			{Name: "agent2", Source: ComponentSourceInternal, AutoStart: false},
		},
		Tools: []ComponentConfig{
			{Name: "tool1", Source: ComponentSourceInternal, AutoStart: true},
		},
		Plugins: []ComponentConfig{
			{Name: "plugin1", Source: ComponentSourceInternal, AutoStart: false},
		},
	}

	assert.Equal(t, 4, config.CountComponents())
	assert.Equal(t, 2, config.CountAutoStart())
}

// TestComponentsConfig_FilterMethods tests the filtering methods.
func TestComponentsConfig_FilterMethods(t *testing.T) {
	config := ComponentsConfig{
		Agents: []ComponentConfig{
			{Name: "agent1", Source: ComponentSourceInternal, AutoStart: true},
			{Name: "agent2", Source: ComponentSourceExternal, Path: "/path", AutoStart: false},
		},
		Tools: []ComponentConfig{
			{Name: "tool1", Source: ComponentSourceInternal, AutoStart: true},
		},
	}

	t.Run("filter by source", func(t *testing.T) {
		internal := config.FilterBySource(ComponentSourceInternal)
		assert.Equal(t, 2, len(internal))

		external := config.FilterBySource(ComponentSourceExternal)
		assert.Equal(t, 1, len(external))
	})

	t.Run("filter by auto start", func(t *testing.T) {
		autoStart := config.FilterByAutoStart()
		assert.Equal(t, 2, len(autoStart))
	})
}

// TestComponentsConfig_MergeComponentsConfig tests the merge functionality.
func TestComponentsConfig_MergeComponentsConfig(t *testing.T) {
	config1 := ComponentsConfig{
		Agents: []ComponentConfig{
			{Name: "agent1", Source: ComponentSourceInternal},
		},
		Tools: []ComponentConfig{
			{Name: "tool1", Source: ComponentSourceInternal},
		},
	}

	config2 := ComponentsConfig{
		Agents: []ComponentConfig{
			{Name: "agent2", Source: ComponentSourceInternal},
		},
		Plugins: []ComponentConfig{
			{Name: "plugin1", Source: ComponentSourceInternal},
		},
	}

	config1.MergeComponentsConfig(&config2)

	assert.Equal(t, 2, len(config1.Agents))
	assert.Equal(t, 1, len(config1.Tools))
	assert.Equal(t, 1, len(config1.Plugins))
}

// TestComponentsConfig_MergeComponentsConfig_Nil tests merging with nil.
func TestComponentsConfig_MergeComponentsConfig_Nil(t *testing.T) {
	config := ComponentsConfig{
		Agents: []ComponentConfig{
			{Name: "agent1", Source: ComponentSourceInternal},
		},
	}

	config.MergeComponentsConfig(nil)

	assert.Equal(t, 1, len(config.Agents))
}

// TestComponentsConfig_HasComponents tests the HasComponents method.
func TestComponentsConfig_HasComponents(t *testing.T) {
	t.Run("has components", func(t *testing.T) {
		config := ComponentsConfig{
			Agents: []ComponentConfig{
				{Name: "agent1", Source: ComponentSourceInternal},
			},
		}
		assert.True(t, config.HasComponents())
	})

	t.Run("no components", func(t *testing.T) {
		config := ComponentsConfig{}
		assert.False(t, config.HasComponents())
	})
}

// TestIsValidIdentifier tests the identifier validation function.
func TestIsValidIdentifier(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid simple name",
			input: "component",
			want:  true,
		},
		{
			name:  "valid with underscore",
			input: "_component",
			want:  true,
		},
		{
			name:  "valid with hyphen",
			input: "my-component",
			want:  true,
		},
		{
			name:  "valid with numbers",
			input: "component123",
			want:  true,
		},
		{
			name:  "valid complex",
			input: "My_Component-v2",
			want:  true,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "starts with number",
			input: "123component",
			want:  false,
		},
		{
			name:  "contains special characters",
			input: "component@name",
			want:  false,
		},
		{
			name:  "contains space",
			input: "my component",
			want:  false,
		},
		{
			name:  "contains dot",
			input: "my.component",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isValidIdentifier(tt.input))
		})
	}
}

// TestNormalizeComponentName tests the name normalization function.
func TestNormalizeComponentName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "lowercase conversion",
			input: "MyComponent",
			want:  "mycomponent",
		},
		{
			name:  "space to hyphen",
			input: "my component",
			want:  "my-component",
		},
		{
			name:  "underscore to hyphen",
			input: "my_component",
			want:  "my-component",
		},
		{
			name:  "complex normalization",
			input: "My_Complex Component",
			want:  "my-complex-component",
		},
		{
			name:  "already normalized",
			input: "my-component",
			want:  "my-component",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeComponentName(tt.input))
		})
	}
}

// TestParseComponentSourceString tests the source parsing convenience function.
func TestParseComponentSourceString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ComponentSource
		wantErr bool
	}{
		{
			name:    "internal",
			input:   "internal",
			want:    ComponentSourceInternal,
			wantErr: false,
		},
		{
			name:    "external",
			input:   "external",
			want:    ComponentSourceExternal,
			wantErr: false,
		},
		{
			name:    "remote",
			input:   "remote",
			want:    ComponentSourceRemote,
			wantErr: false,
		},
		{
			name:    "config",
			input:   "config",
			want:    ComponentSourceConfig,
			wantErr: false,
		},
		{
			name:    "invalid",
			input:   "invalid",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseComponentSourceString(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestComponentConfig_EdgeCases tests edge cases for ComponentConfig.
func TestComponentConfig_EdgeCases(t *testing.T) {
	t.Run("remote with branch and no tag", func(t *testing.T) {
		config := ComponentConfig{
			Name:   "test",
			Source: ComponentSourceRemote,
			Repo:   "https://github.com/example/repo",
			Branch: "develop",
		}
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("remote with tag and no branch", func(t *testing.T) {
		config := ComponentConfig{
			Name:   "test",
			Source: ComponentSourceRemote,
			Repo:   "https://github.com/example/repo",
			Tag:    "v2.0.0",
		}
		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("remote with neither branch nor tag", func(t *testing.T) {
		config := ComponentConfig{
			Name:   "test",
			Source: ComponentSourceRemote,
			Repo:   "https://github.com/example/repo",
		}
		err := config.Validate()
		assert.NoError(t, err) // This is valid - will use default branch
	})
}

// TestValidateAndFilterComponents tests the internal filter function directly.
func TestValidateAndFilterComponents(t *testing.T) {
	t.Run("filter out all invalid", func(t *testing.T) {
		components := []ComponentConfig{
			{Name: "", Source: ComponentSourceInternal},
			{Name: "123invalid", Source: ComponentSourceInternal},
		}
		logger := &mockLogger{warnings: []string{}}
		filtered := validateAndFilterComponents(components, "test", logger)
		assert.Equal(t, 0, len(filtered))
		assert.Equal(t, 2, len(logger.warnings))
	})

	t.Run("keep all valid", func(t *testing.T) {
		components := []ComponentConfig{
			{Name: "valid1", Source: ComponentSourceInternal},
			{Name: "valid2", Source: ComponentSourceInternal},
		}
		logger := &mockLogger{warnings: []string{}}
		filtered := validateAndFilterComponents(components, "test", logger)
		assert.Equal(t, 2, len(filtered))
		assert.Equal(t, 0, len(logger.warnings))
	})

	t.Run("empty slice", func(t *testing.T) {
		components := []ComponentConfig{}
		logger := &mockLogger{warnings: []string{}}
		filtered := validateAndFilterComponents(components, "test", logger)
		assert.Equal(t, 0, len(filtered))
	})
}

// TestLoadComponentsFromConfig_ComplexScenarios tests complex real-world scenarios.
func TestLoadComponentsFromConfig_ComplexScenarios(t *testing.T) {
	t.Run("mixed valid and invalid components", func(t *testing.T) {
		yaml := `
components:
  agents:
    - name: valid-agent-1
      source: internal
      auto_start: true
    - name: ""
      source: internal
    - name: valid-agent-2
      source: external
      path: /bin/agent
  tools:
    - name: valid-tool
      source: remote
      repo: https://github.com/example/tool
      tag: v1.0.0
    - name: invalid-tool
      source: external
  plugins:
    - name: valid-plugin
      source: config
      settings:
        key: value
`
		logger := &mockLogger{warnings: []string{}}
		cfg, err := LoadComponentsFromConfig([]byte(yaml), logger)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, 2, len(cfg.Agents))
		assert.Equal(t, 1, len(cfg.Tools))
		assert.Equal(t, 1, len(cfg.Plugins))
		assert.Equal(t, 2, len(logger.warnings))
	})

	t.Run("all components from same source", func(t *testing.T) {
		yaml := `
components:
  agents:
    - name: agent1
      source: internal
    - name: agent2
      source: internal
  tools:
    - name: tool1
      source: internal
`
		logger := &mockLogger{warnings: []string{}}
		cfg, err := LoadComponentsFromConfig([]byte(yaml), logger)
		require.NoError(t, err)

		internal := cfg.FilterBySource(ComponentSourceInternal)
		assert.Equal(t, 3, len(internal))
	})
}
