package mission

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseWorkspaceIntegration tests end-to-end parsing of workspace configuration
func TestParseWorkspaceIntegration(t *testing.T) {
	yamlData := `
name: Code Generation Mission
version: 1.0.0
description: Multi-repository code generation mission

workspace:
  repositories:
    - name: backend
      url: https://github.com/org/backend.git
      branch: main
      credential_name: github-pat
    - name: frontend
      url: git@github.com:org/frontend.git
      branch: develop
      credential_name: github-ssh
      depends_on:
        - backend
    - name: shared-lib
      url: https://github.com/org/shared.git
      shallow: true
  cleanup_on_complete: true
  use_worktrees: true
  lsp_enabled: true
  lsp_timeout: 15s
  base_directory: /tmp/mission-workspaces

nodes:
  - id: analyze
    type: agent
    agent: code-analyzer
    task:
      description: Analyze repository structure
`

	// Parse the mission definition
	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	require.NoError(t, err, "Failed to parse mission with workspace config")
	require.NotNil(t, def, "Mission definition should not be nil")

	// Verify workspace configuration was parsed
	require.NotNil(t, def.Workspace, "Workspace config should be parsed")

	// Verify repositories
	assert.Len(t, def.Workspace.Repositories, 3, "Should have 3 repositories")

	// Verify backend repository
	backend := def.Workspace.GetRepository("backend")
	require.NotNil(t, backend, "Backend repository should exist")
	assert.Equal(t, "backend", backend.Name)
	assert.Equal(t, "https://github.com/org/backend.git", backend.URL)
	assert.Equal(t, "main", backend.Branch)
	assert.Equal(t, "github-pat", backend.CredentialName)
	assert.False(t, backend.Shallow)
	assert.Empty(t, backend.DependsOn)

	// Verify frontend repository
	frontend := def.Workspace.GetRepository("frontend")
	require.NotNil(t, frontend, "Frontend repository should exist")
	assert.Equal(t, "frontend", frontend.Name)
	assert.Equal(t, "git@github.com:org/frontend.git", frontend.URL)
	assert.Equal(t, "develop", frontend.Branch)
	assert.Equal(t, "github-ssh", frontend.CredentialName)
	assert.Equal(t, []string{"backend"}, frontend.DependsOn)

	// Verify shared library repository
	shared := def.Workspace.GetRepository("shared-lib")
	require.NotNil(t, shared, "Shared-lib repository should exist")
	assert.Equal(t, "shared-lib", shared.Name)
	assert.True(t, shared.Shallow)

	// Verify workspace settings
	settings := def.Workspace.Settings
	assert.True(t, settings.CleanupOnComplete)
	assert.True(t, settings.UseWorktrees)
	assert.True(t, settings.LSPEnabled)
	assert.Equal(t, "15s", settings.LSPTimeout.String())
	assert.Equal(t, "/tmp/mission-workspaces", settings.BaseDirectory)

	// Verify workspace utilities
	assert.True(t, def.Workspace.HasRepositories())

	// Verify validation passes
	err = def.Workspace.Validate()
	assert.NoError(t, err, "Workspace validation should pass")
}

// TestParseWorkspaceValidationErrors tests that invalid configurations are rejected
func TestParseWorkspaceValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		errorMsg string
	}{
		{
			name: "duplicate repository names",
			yaml: `
name: Test
version: 1.0.0
workspace:
  repositories:
    - name: duplicate
      url: https://github.com/org/repo1.git
    - name: duplicate
      url: https://github.com/org/repo2.git
nodes:
  - id: n1
    type: agent
    agent: a1
`,
			errorMsg: "duplicate repository name",
		},
		{
			name: "circular dependency",
			yaml: `
name: Test
version: 1.0.0
workspace:
  repositories:
    - name: repo-a
      url: https://github.com/org/a.git
      depends_on: [repo-b]
    - name: repo-b
      url: https://github.com/org/b.git
      depends_on: [repo-a]
nodes:
  - id: n1
    type: agent
    agent: a1
`,
			errorMsg: "circular dependency",
		},
		{
			name: "invalid URL format",
			yaml: `
name: Test
version: 1.0.0
workspace:
  repositories:
    - name: test
      url: not-a-url
nodes:
  - id: n1
    type: agent
    agent: a1
`,
			errorMsg: "invalid repository URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDefinitionFromBytes([]byte(tt.yaml))
			require.Error(t, err, "Should fail validation")
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

// TestWorkspaceConfigEmpty tests mission without workspace configuration
func TestWorkspaceConfigEmpty(t *testing.T) {
	yamlData := `
name: Simple Mission
version: 1.0.0

nodes:
  - id: task1
    type: agent
    agent: test-agent
`

	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	require.NoError(t, err)
	require.NotNil(t, def)

	// Workspace should be nil for missions without workspace config
	assert.Nil(t, def.Workspace, "Workspace should be nil when not configured")
}
