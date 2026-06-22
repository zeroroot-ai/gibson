package component

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadManifest_YAML tests loading manifests from YAML files
func TestLoadManifest_YAML(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError bool
		validate  func(t *testing.T, m *Manifest)
	}{
		{
			name: "valid YAML without kind field",
			content: `
name: test-component
version: 1.0.0
description: A test component
runtime:
  type: go
  entrypoint: ./main
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Equal(t, "test-component", m.Name)
				assert.Equal(t, "1.0.0", m.Version)
				assert.Equal(t, "A test component", m.Description)
				assert.Equal(t, RuntimeTypeGo, m.Runtime.Type)
				assert.Equal(t, "./main", m.Runtime.Entrypoint)
			},
		},
		{
			name: "valid YAML with kind field (backwards compatibility - field ignored)",
			content: `
kind: tool
name: test-tool
version: 2.0.0
runtime:
  type: python
  entrypoint: ./main.py
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Equal(t, "test-tool", m.Name)
				assert.Equal(t, "2.0.0", m.Version)
				assert.Equal(t, RuntimeTypePython, m.Runtime.Type)
				assert.Equal(t, "./main.py", m.Runtime.Entrypoint)
			},
		},
		{
			name: "YAML with build config",
			content: `
name: test-component
version: 1.0.0
build:
  command: go build -o bin/main
  artifacts:
    - ./bin/main
runtime:
  type: go
  entrypoint: ./bin/main
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				require.NotNil(t, m.Build)
				assert.Equal(t, "go build -o bin/main", m.Build.Command)
				assert.Equal(t, []string{"./bin/main"}, m.Build.Artifacts)
			},
		},
		{
			name: "YAML with dependencies",
			content: `
name: test-component
version: 1.0.0
runtime:
  type: go
  entrypoint: ./main
dependencies:
  gibson: ">=1.0.0"
  components:
    - other-component@1.0.0
  system:
    - docker
    - git
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				require.NotNil(t, m.Dependencies)
				assert.Equal(t, ">=1.0.0", m.Dependencies.Gibson)
				assert.Equal(t, []string{"other-component@1.0.0"}, m.Dependencies.Components)
				assert.Equal(t, []string{"docker", "git"}, m.Dependencies.System)
			},
		},
		{
			name: "YAML with network-based runtime",
			content: `
name: test-service
version: 1.0.0
runtime:
  type: http
  entrypoint: ./server
  port: 8080
  health_url: /health
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Equal(t, RuntimeTypeHTTP, m.Runtime.Type)
				assert.Equal(t, 8080, m.Runtime.Port)
				assert.Equal(t, "/health", m.Runtime.HealthURL)
			},
		},
		{
			name: "invalid YAML - missing name",
			content: `
version: 1.0.0
runtime:
  type: go
  entrypoint: ./main
`,
			wantError: true,
		},
		{
			name: "invalid YAML - missing version",
			content: `
name: test-component
runtime:
  type: go
  entrypoint: ./main
`,
			wantError: true,
		},
		{
			name: "valid YAML - missing runtime (repository manifest)",
			content: `
name: test-component
version: 1.0.0
kind: repository
`,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "component.yaml")
			err := os.WriteFile(manifestPath, []byte(tt.content), 0644)
			require.NoError(t, err)

			// Load manifest
			manifest, err := LoadManifest(manifestPath)

			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manifest)
				if tt.validate != nil {
					tt.validate(t, manifest)
				}
			}
		})
	}
}

// TestLoadManifest_JSON tests loading manifests from JSON files
func TestLoadManifest_JSON(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError bool
		validate  func(t *testing.T, m *Manifest)
	}{
		{
			name: "valid JSON without kind field",
			content: `{
  "name": "test-component",
  "version": "1.0.0",
  "runtime": {
    "type": "go",
    "entrypoint": "./main"
  }
}`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Equal(t, "test-component", m.Name)
				assert.Equal(t, "1.0.0", m.Version)
				assert.Equal(t, RuntimeTypeGo, m.Runtime.Type)
			},
		},
		{
			name: "valid JSON with kind field (backwards compatibility - field ignored)",
			content: `{
  "kind": "agent",
  "name": "test-agent",
  "version": "2.0.0",
  "runtime": {
    "type": "python",
    "entrypoint": "./agent.py"
  }
}`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Equal(t, "test-agent", m.Name)
				assert.Equal(t, "2.0.0", m.Version)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "component.json")
			err := os.WriteFile(manifestPath, []byte(tt.content), 0644)
			require.NoError(t, err)

			// Load manifest
			manifest, err := LoadManifest(manifestPath)

			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manifest)
				if tt.validate != nil {
					tt.validate(t, manifest)
				}
			}
		})
	}
}

// TestLoadManifest_Errors tests error cases for LoadManifest
func TestLoadManifest_Errors(t *testing.T) {
	t.Run("file not found", func(t *testing.T) {
		_, err := LoadManifest("/nonexistent/manifest.yaml")
		require.Error(t, err)
		assert.IsType(t, &ComponentError{}, err)
	})

	t.Run("unsupported file format", func(t *testing.T) {
		tmpDir := t.TempDir()
		manifestPath := filepath.Join(tmpDir, "manifest.txt")
		err := os.WriteFile(manifestPath, []byte("name: test"), 0644)
		require.NoError(t, err)

		_, err = LoadManifest(manifestPath)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported manifest format")
	})

	t.Run("invalid YAML syntax", func(t *testing.T) {
		tmpDir := t.TempDir()
		manifestPath := filepath.Join(tmpDir, "manifest.yaml")
		err := os.WriteFile(manifestPath, []byte("invalid: yaml: syntax:"), 0644)
		require.NoError(t, err)

		_, err = LoadManifest(manifestPath)
		require.Error(t, err)
	})

	t.Run("invalid JSON syntax", func(t *testing.T) {
		tmpDir := t.TempDir()
		manifestPath := filepath.Join(tmpDir, "manifest.json")
		err := os.WriteFile(manifestPath, []byte("{invalid json}"), 0644)
		require.NoError(t, err)

		_, err = LoadManifest(manifestPath)
		require.Error(t, err)
	})
}

// TestManifest_ParseRepositoryKind tests parsing manifest with kind: repository
func TestManifest_ParseRepositoryKind(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError bool
		validate  func(t *testing.T, m *Manifest)
	}{
		{
			name: "repository manifest with contents",
			content: `
kind: repository
name: test-repo
version: 1.0.0
description: A repository of components
contents:
  - kind: tool
    path: tools/mytool
  - kind: agent
    path: agents/myagent
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Equal(t, "repository", m.Kind)
				assert.Equal(t, "test-repo", m.Name)
				assert.Equal(t, "1.0.0", m.Version)
				assert.Len(t, m.Contents, 2)
				assert.Equal(t, "tool", m.Contents[0].Kind)
				assert.Equal(t, "tools/mytool", m.Contents[0].Path)
				assert.Equal(t, "agent", m.Contents[1].Kind)
				assert.Equal(t, "agents/myagent", m.Contents[1].Path)
			},
		},
		{
			name: "repository manifest with discover",
			content: `
kind: repository
name: auto-discover-repo
version: 1.0.0
discover: true
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Equal(t, "repository", m.Kind)
				assert.Equal(t, "auto-discover-repo", m.Name)
				assert.True(t, m.Discover)
				assert.Empty(t, m.Contents)
			},
		},
		{
			name: "repository manifest with build config",
			content: `
kind: repository
name: build-repo
version: 1.0.0
build:
  command: make build-all
  workdir: .
discover: true
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Equal(t, "repository", m.Kind)
				assert.Equal(t, "build-repo", m.Name)
				require.NotNil(t, m.Build)
				assert.Equal(t, "make build-all", m.Build.Command)
				assert.True(t, m.Discover)
			},
		},
		{
			name: "repository manifest without runtime (should pass)",
			content: `
kind: repository
name: no-runtime-repo
version: 1.0.0
discover: true
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Equal(t, "repository", m.Kind)
				assert.Nil(t, m.Runtime)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "component.yaml")
			err := os.WriteFile(manifestPath, []byte(tt.content), 0644)
			require.NoError(t, err)

			manifest, err := LoadManifest(manifestPath)

			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manifest)
				if tt.validate != nil {
					tt.validate(t, manifest)
				}
			}
		})
	}
}

// TestManifest_ParseContents tests parsing manifest with contents array
func TestManifest_ParseContents(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError bool
		validate  func(t *testing.T, m *Manifest)
	}{
		{
			name: "contents with multiple entries",
			content: `
kind: repository
name: multi-component-repo
version: 1.0.0
contents:
  - kind: tool
    path: cmd/tool1
  - kind: tool
    path: cmd/tool2
  - kind: agent
    path: pkg/agent
  - kind: plugin
    path: plugins/myplugin
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Len(t, m.Contents, 4)
				assert.Equal(t, "tool", m.Contents[0].Kind)
				assert.Equal(t, "cmd/tool1", m.Contents[0].Path)
				assert.Equal(t, "tool", m.Contents[1].Kind)
				assert.Equal(t, "cmd/tool2", m.Contents[1].Path)
				assert.Equal(t, "agent", m.Contents[2].Kind)
				assert.Equal(t, "pkg/agent", m.Contents[2].Path)
				assert.Equal(t, "plugin", m.Contents[3].Kind)
				assert.Equal(t, "plugins/myplugin", m.Contents[3].Path)
			},
		},
		{
			name: "contents with empty array",
			content: `
kind: repository
name: empty-contents-repo
version: 1.0.0
contents: []
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.NotNil(t, m.Contents)
				assert.Len(t, m.Contents, 0)
			},
		},
		{
			name: "no contents field",
			content: `
kind: repository
name: no-contents-repo
version: 1.0.0
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Empty(t, m.Contents)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "component.yaml")
			err := os.WriteFile(manifestPath, []byte(tt.content), 0644)
			require.NoError(t, err)

			manifest, err := LoadManifest(manifestPath)

			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manifest)
				if tt.validate != nil {
					tt.validate(t, manifest)
				}
			}
		})
	}
}

// TestManifest_ParseDiscover tests parsing manifest with discover: true
func TestManifest_ParseDiscover(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError bool
		validate  func(t *testing.T, m *Manifest)
	}{
		{
			name: "discover set to true",
			content: `
kind: repository
name: discover-repo
version: 1.0.0
discover: true
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.True(t, m.Discover)
			},
		},
		{
			name: "discover set to false",
			content: `
kind: repository
name: no-discover-repo
version: 1.0.0
discover: false
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.False(t, m.Discover)
			},
		},
		{
			name: "discover field omitted (defaults to false)",
			content: `
kind: repository
name: default-discover-repo
version: 1.0.0
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.False(t, m.Discover)
			},
		},
		{
			name: "discover with contents array (both can coexist)",
			content: `
kind: repository
name: both-repo
version: 1.0.0
discover: true
contents:
  - kind: tool
    path: tools/special
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.True(t, m.Discover)
				assert.Len(t, m.Contents, 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "component.yaml")
			err := os.WriteFile(manifestPath, []byte(tt.content), 0644)
			require.NoError(t, err)

			manifest, err := LoadManifest(manifestPath)

			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manifest)
				if tt.validate != nil {
					tt.validate(t, manifest)
				}
			}
		})
	}
}

// TestManifest_BackwardsCompatibility specifically tests that legacy manifests
// with "kind" field can still be parsed without errors
func TestManifest_BackwardsCompatibility(t *testing.T) {
	t.Run("YAML with kind field is parsed and ignored", func(t *testing.T) {
		content := `
kind: tool
name: legacy-tool
version: 1.0.0
runtime:
  type: go
  entrypoint: ./main
`
		tmpDir := t.TempDir()
		manifestPath := filepath.Join(tmpDir, "component.yaml")
		err := os.WriteFile(manifestPath, []byte(content), 0644)
		require.NoError(t, err)

		manifest, err := LoadManifest(manifestPath)
		require.NoError(t, err)
		assert.Equal(t, "legacy-tool", manifest.Name)
		assert.Equal(t, "1.0.0", manifest.Version)
		// Validate should pass even though kind field is present in YAML
		err = manifest.Validate()
		require.NoError(t, err)
	})

	t.Run("JSON with kind field is parsed and ignored", func(t *testing.T) {
		content := `{
  "kind": "agent",
  "name": "legacy-agent",
  "version": "2.0.0",
  "runtime": {
    "type": "python",
    "entrypoint": "./agent.py"
  }
}`
		tmpDir := t.TempDir()
		manifestPath := filepath.Join(tmpDir, "component.json")
		err := os.WriteFile(manifestPath, []byte(content), 0644)
		require.NoError(t, err)

		manifest, err := LoadManifest(manifestPath)
		require.NoError(t, err)
		assert.Equal(t, "legacy-agent", manifest.Name)
		assert.Equal(t, "2.0.0", manifest.Version)
		// Validate should pass even though kind field is present in JSON
		err = manifest.Validate()
		require.NoError(t, err)
	})

	t.Run("manifest without kind field passes validation", func(t *testing.T) {
		content := `
name: new-component
version: 1.0.0
runtime:
  type: go
  entrypoint: ./main
`
		tmpDir := t.TempDir()
		manifestPath := filepath.Join(tmpDir, "component.yaml")
		err := os.WriteFile(manifestPath, []byte(content), 0644)
		require.NoError(t, err)

		manifest, err := LoadManifest(manifestPath)
		require.NoError(t, err)
		assert.Equal(t, "new-component", manifest.Name)
		assert.Equal(t, "1.0.0", manifest.Version)
		// Validate should pass without kind field
		err = manifest.Validate()
		require.NoError(t, err)
	})
}

// TestHealthCheckProtocol_IsValid tests HealthCheckProtocol validation
func TestHealthCheckProtocol_IsValid(t *testing.T) {
	tests := []struct {
		protocol HealthCheckProtocol
		valid    bool
	}{
		{HealthCheckProtocolHTTP, true},
		{HealthCheckProtocolGRPC, true},
		{HealthCheckProtocolAuto, true},
		{"", true}, // Empty is valid (defaults to auto)
		{"invalid", false},
		{"HTTP", false}, // Case sensitive
		{"GRPC", false},
		{"tcp", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.protocol), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.protocol.IsValid())
		})
	}
}

// TestHealthCheckConfig_Defaults tests default values for HealthCheckConfig
func TestHealthCheckConfig_Defaults(t *testing.T) {
	t.Run("nil config returns defaults", func(t *testing.T) {
		var cfg *HealthCheckConfig = nil
		assert.Equal(t, HealthCheckProtocolAuto, cfg.GetProtocol())
		assert.Equal(t, 10*time.Second, cfg.GetInterval())
		assert.Equal(t, 5*time.Second, cfg.GetTimeout())
		assert.Equal(t, "/health", cfg.GetEndpoint())
		assert.Equal(t, "", cfg.GetServiceName())
	})

	t.Run("empty config returns defaults", func(t *testing.T) {
		cfg := &HealthCheckConfig{}
		assert.Equal(t, HealthCheckProtocolAuto, cfg.GetProtocol())
		assert.Equal(t, 10*time.Second, cfg.GetInterval())
		assert.Equal(t, 5*time.Second, cfg.GetTimeout())
		assert.Equal(t, "/health", cfg.GetEndpoint())
		assert.Equal(t, "", cfg.GetServiceName())
	})

	t.Run("explicit values are preserved", func(t *testing.T) {
		cfg := &HealthCheckConfig{
			Protocol:    HealthCheckProtocolGRPC,
			Interval:    30 * time.Second,
			Timeout:     10 * time.Second,
			Endpoint:    "/healthz",
			ServiceName: "my-service",
		}
		assert.Equal(t, HealthCheckProtocolGRPC, cfg.GetProtocol())
		assert.Equal(t, 30*time.Second, cfg.GetInterval())
		assert.Equal(t, 10*time.Second, cfg.GetTimeout())
		assert.Equal(t, "/healthz", cfg.GetEndpoint())
		assert.Equal(t, "my-service", cfg.GetServiceName())
	})
}

// TestHealthCheckConfig_Validate tests HealthCheckConfig validation
func TestHealthCheckConfig_Validate(t *testing.T) {
	t.Run("nil config is valid", func(t *testing.T) {
		var cfg *HealthCheckConfig = nil
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("empty config is valid", func(t *testing.T) {
		cfg := &HealthCheckConfig{}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid protocols pass validation", func(t *testing.T) {
		for _, protocol := range AllHealthCheckProtocols() {
			cfg := &HealthCheckConfig{Protocol: protocol}
			err := cfg.Validate()
			assert.NoError(t, err, "protocol %s should be valid", protocol)
		}
	})

	t.Run("invalid protocol fails validation", func(t *testing.T) {
		cfg := &HealthCheckConfig{Protocol: "invalid"}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid health check protocol")
	})

	t.Run("negative interval fails validation", func(t *testing.T) {
		cfg := &HealthCheckConfig{Interval: -1 * time.Second}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "interval must be positive")
	})

	t.Run("negative timeout fails validation", func(t *testing.T) {
		cfg := &HealthCheckConfig{Timeout: -1 * time.Second}
		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timeout must be positive")
	})

	t.Run("zero interval is valid (uses default)", func(t *testing.T) {
		cfg := &HealthCheckConfig{Interval: 0}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("zero timeout is valid (uses default)", func(t *testing.T) {
		cfg := &HealthCheckConfig{Timeout: 0}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

// TestLoadManifest_HealthCheckConfig tests loading manifests with health_check config
func TestLoadManifest_HealthCheckConfig(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError bool
		validate  func(t *testing.T, m *Manifest)
	}{
		{
			name: "manifest with grpc health check protocol",
			content: `
name: grpc-agent
version: 1.0.0
runtime:
  type: grpc
  entrypoint: ./agent
  port: 50051
  health_check:
    protocol: grpc
    timeout: 10s
    interval: 30s
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				require.NotNil(t, m.Runtime.HealthCheck)
				assert.Equal(t, HealthCheckProtocolGRPC, m.Runtime.HealthCheck.Protocol)
				assert.Equal(t, 10*time.Second, m.Runtime.HealthCheck.Timeout)
				assert.Equal(t, 30*time.Second, m.Runtime.HealthCheck.Interval)
			},
		},
		{
			name: "manifest with http health check protocol",
			content: `
name: http-service
version: 1.0.0
runtime:
  type: http
  entrypoint: ./server
  port: 8080
  health_check:
    protocol: http
    endpoint: /healthz
    timeout: 5s
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				require.NotNil(t, m.Runtime.HealthCheck)
				assert.Equal(t, HealthCheckProtocolHTTP, m.Runtime.HealthCheck.Protocol)
				assert.Equal(t, "/healthz", m.Runtime.HealthCheck.Endpoint)
				assert.Equal(t, 5*time.Second, m.Runtime.HealthCheck.Timeout)
			},
		},
		{
			name: "manifest with auto health check protocol",
			content: `
name: auto-service
version: 1.0.0
runtime:
  type: go
  entrypoint: ./server
  port: 50051
  health_check:
    protocol: auto
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				require.NotNil(t, m.Runtime.HealthCheck)
				assert.Equal(t, HealthCheckProtocolAuto, m.Runtime.HealthCheck.Protocol)
			},
		},
		{
			name: "manifest with grpc service name",
			content: `
name: grpc-service
version: 1.0.0
runtime:
  type: grpc
  entrypoint: ./server
  port: 50051
  health_check:
    protocol: grpc
    service_name: my.service.Name
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				require.NotNil(t, m.Runtime.HealthCheck)
				assert.Equal(t, "my.service.Name", m.Runtime.HealthCheck.ServiceName)
			},
		},
		{
			name: "manifest without health_check (uses defaults)",
			content: `
name: default-service
version: 1.0.0
runtime:
  type: go
  entrypoint: ./server
`,
			wantError: false,
			validate: func(t *testing.T, m *Manifest) {
				assert.Nil(t, m.Runtime.HealthCheck)
				// GetHealthCheckConfig should return a default config
				cfg := m.Runtime.GetHealthCheckConfig()
				require.NotNil(t, cfg)
				assert.Equal(t, HealthCheckProtocolAuto, cfg.GetProtocol())
				assert.Equal(t, 10*time.Second, cfg.GetInterval())
				assert.Equal(t, 5*time.Second, cfg.GetTimeout())
			},
		},
		{
			name: "manifest with invalid health check protocol",
			content: `
name: invalid-service
version: 1.0.0
runtime:
  type: go
  entrypoint: ./server
  health_check:
    protocol: invalid
`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "component.yaml")
			err := os.WriteFile(manifestPath, []byte(tt.content), 0644)
			require.NoError(t, err)

			manifest, err := LoadManifest(manifestPath)

			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manifest)
				if tt.validate != nil {
					tt.validate(t, manifest)
				}
			}
		})
	}
}

// TestRuntimeConfig_GetHealthCheckConfig tests the GetHealthCheckConfig helper
func TestRuntimeConfig_GetHealthCheckConfig(t *testing.T) {
	t.Run("returns explicit config when set", func(t *testing.T) {
		cfg := &HealthCheckConfig{
			Protocol: HealthCheckProtocolGRPC,
			Timeout:  15 * time.Second,
		}
		runtime := &RuntimeConfig{
			Type:        RuntimeTypeGo,
			Entrypoint:  "./main",
			HealthCheck: cfg,
		}
		result := runtime.GetHealthCheckConfig()
		assert.Equal(t, cfg, result)
		assert.Equal(t, HealthCheckProtocolGRPC, result.GetProtocol())
	})

	t.Run("returns default config when nil", func(t *testing.T) {
		runtime := &RuntimeConfig{
			Type:       RuntimeTypeGo,
			Entrypoint: "./main",
		}
		result := runtime.GetHealthCheckConfig()
		require.NotNil(t, result)
		assert.Equal(t, HealthCheckProtocolAuto, result.GetProtocol())
		assert.Equal(t, 10*time.Second, result.GetInterval())
		assert.Equal(t, 5*time.Second, result.GetTimeout())
	})
}
