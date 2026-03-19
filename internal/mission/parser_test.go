package mission

import (
	"testing"
)

// TestParseDefinitionFromBytes tests basic parsing of mission YAML
func TestParseDefinitionFromBytes(t *testing.T) {
	yamlData := `
name: Test Mission
version: 1.0.0
description: A test mission

nodes:
  - id: node1
    type: agent
    agent: test-agent
    task:
      target: example.com
`

	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseDefinitionFromBytes failed: %v", err)
	}

	if def.Name != "Test Mission" {
		t.Errorf("Expected name 'Test Mission', got '%s'", def.Name)
	}

	if def.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", def.Version)
	}

	if len(def.Nodes) != 1 {
		t.Errorf("Expected 1 node, got %d", len(def.Nodes))
	}

	node, exists := def.Nodes["node1"]
	if !exists {
		t.Fatal("Node 'node1' not found")
	}

	if node.Type != NodeTypeAgent {
		t.Errorf("Expected node type 'agent', got '%s'", node.Type)
	}

	if node.AgentName != "test-agent" {
		t.Errorf("Expected agent name 'test-agent', got '%s'", node.AgentName)
	}
}

// TestParseDefinitionMapNodes tests parsing nodes as a map instead of array
func TestParseDefinitionMapNodes(t *testing.T) {
	yamlData := `
name: Test Mission Map Nodes
version: 1.0.0

nodes:
  recon:
    type: agent
    agent: recon-agent
    task:
      target: example.com
  scan:
    type: tool
    tool: port-scanner
    depends_on:
      - recon
    input:
      port_range: "1-1024"
`

	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseDefinitionFromBytes failed: %v", err)
	}

	if len(def.Nodes) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(def.Nodes))
	}

	// Check recon node
	recon, exists := def.Nodes["recon"]
	if !exists {
		t.Fatal("Node 'recon' not found")
	}
	if recon.Type != NodeTypeAgent {
		t.Errorf("Expected recon type 'agent', got '%s'", recon.Type)
	}

	// Check scan node
	scan, exists := def.Nodes["scan"]
	if !exists {
		t.Fatal("Node 'scan' not found")
	}
	if scan.Type != NodeTypeTool {
		t.Errorf("Expected scan type 'tool', got '%s'", scan.Type)
	}
	if len(scan.Dependencies) != 1 || scan.Dependencies[0] != "recon" {
		t.Errorf("Expected scan to depend on 'recon', got %v", scan.Dependencies)
	}

	// Check edges were created
	if len(def.Edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(def.Edges))
	}
	if def.Edges[0].From != "recon" || def.Edges[0].To != "scan" {
		t.Errorf("Expected edge from 'recon' to 'scan', got from '%s' to '%s'", def.Edges[0].From, def.Edges[0].To)
	}
}

// TestParseDefinitionWithDependencies tests parsing mission dependencies
func TestParseDefinitionWithDependencies(t *testing.T) {
	yamlData := `
name: Test Mission with Dependencies
version: 1.0.0

dependencies:
  agents:
    - recon-agent
    - scan-agent
  tools:
    - nmap
    - masscan

nodes:
  - id: node1
    type: agent
    agent: recon-agent
`

	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseDefinitionFromBytes failed: %v", err)
	}

	if def.Dependencies == nil {
		t.Fatal("Expected dependencies to be set")
	}

	if len(def.Dependencies.Agents) != 2 {
		t.Errorf("Expected 2 agent dependencies, got %d", len(def.Dependencies.Agents))
	}

	if len(def.Dependencies.Tools) != 2 {
		t.Errorf("Expected 2 tool dependencies, got %d", len(def.Dependencies.Tools))
	}
}

// TestParseDefinitionInvalidYAML tests error handling for invalid YAML
func TestParseDefinitionInvalidYAML(t *testing.T) {
	yamlData := `
name: Test Mission
nodes: {invalid yaml structure
`

	_, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err == nil {
		t.Fatal("Expected error for invalid YAML, got nil")
	}

	parseErr, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("Expected *ParseError, got %T", err)
	}

	if parseErr.Line == 0 {
		t.Error("Expected line number in parse error")
	}
}

// TestParseDefinitionMissingName tests error for missing required name field
func TestParseDefinitionMissingName(t *testing.T) {
	yamlData := `
version: 1.0.0

nodes:
  - id: node1
    type: agent
    agent: test-agent
`

	_, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err == nil {
		t.Fatal("Expected error for missing name, got nil")
	}

	parseErr, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("Expected *ParseError, got %T", err)
	}

	if parseErr.Message != "mission 'name' field is required" {
		t.Errorf("Expected name required error, got: %s", parseErr.Message)
	}
}

// TestParseDefinitionMissingNodes tests error for missing nodes
func TestParseDefinitionMissingNodes(t *testing.T) {
	yamlData := `
name: Test Mission
version: 1.0.0
`

	_, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err == nil {
		t.Fatal("Expected error for missing nodes, got nil")
	}
}

// TestParseDefinitionWithRetryPolicy tests parsing retry configuration
func TestParseDefinitionWithRetryPolicy(t *testing.T) {
	yamlData := `
name: Test Mission with Retry
version: 1.0.0

nodes:
  - id: node1
    type: agent
    agent: test-agent
    timeout: 5m
    retry:
      max_retries: 3
      backoff: exponential
      initial_delay: 1s
      max_delay: 30s
      multiplier: 2.0
`

	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseDefinitionFromBytes failed: %v", err)
	}

	node := def.Nodes["node1"]
	if node.RetryPolicy == nil {
		t.Fatal("Expected retry policy to be set")
	}

	if node.RetryPolicy.MaxRetries != 3 {
		t.Errorf("Expected max_retries 3, got %d", node.RetryPolicy.MaxRetries)
	}

	if node.RetryPolicy.BackoffStrategy != BackoffExponential {
		t.Errorf("Expected exponential backoff, got %s", node.RetryPolicy.BackoffStrategy)
	}

	if node.RetryPolicy.Multiplier != 2.0 {
		t.Errorf("Expected multiplier 2.0, got %f", node.RetryPolicy.Multiplier)
	}
}

// TestParseDefinitionTargetReference tests parsing target as string reference
func TestParseDefinitionTargetReference(t *testing.T) {
	yamlData := `
name: Test Mission with Target
version: 1.0.0
target: my-target-name

nodes:
  - id: node1
    type: agent
    agent: test-agent
`

	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseDefinitionFromBytes failed: %v", err)
	}

	if def.TargetRef != "my-target-name" {
		t.Errorf("Expected target ref 'my-target-name', got '%s'", def.TargetRef)
	}
}

// TestParseDefinitionWithWorkspace tests parsing workspace configuration
func TestParseDefinitionWithWorkspace(t *testing.T) {
	yamlData := `
name: Test Mission with Workspace
version: 1.0.0

workspace:
  repositories:
    - name: main-repo
      url: https://github.com/org/main.git
      branch: main
      credential_name: github-token
    - name: plugin-repo
      url: git@github.com:org/plugin.git
      branch: develop
      depends_on:
        - main-repo
  cleanup_on_complete: true
  use_worktrees: true
  lsp_enabled: true
  lsp_timeout: 10s
  base_directory: /tmp/workspaces

nodes:
  - id: node1
    type: agent
    agent: test-agent
`

	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseDefinitionFromBytes failed: %v", err)
	}

	if def.Workspace == nil {
		t.Fatal("Expected workspace to be set")
	}

	// Check repositories
	if len(def.Workspace.Repositories) != 2 {
		t.Fatalf("Expected 2 repositories, got %d", len(def.Workspace.Repositories))
	}

	// Check first repository
	repo1 := def.Workspace.Repositories[0]
	if repo1.Name != "main-repo" {
		t.Errorf("Expected repository name 'main-repo', got '%s'", repo1.Name)
	}
	if repo1.URL != "https://github.com/org/main.git" {
		t.Errorf("Expected URL 'https://github.com/org/main.git', got '%s'", repo1.URL)
	}
	if repo1.Branch != "main" {
		t.Errorf("Expected branch 'main', got '%s'", repo1.Branch)
	}
	if repo1.CredentialName != "github-token" {
		t.Errorf("Expected credential_name 'github-token', got '%s'", repo1.CredentialName)
	}

	// Check second repository
	repo2 := def.Workspace.Repositories[1]
	if repo2.Name != "plugin-repo" {
		t.Errorf("Expected repository name 'plugin-repo', got '%s'", repo2.Name)
	}
	if repo2.URL != "git@github.com:org/plugin.git" {
		t.Errorf("Expected SSH URL, got '%s'", repo2.URL)
	}
	if len(repo2.DependsOn) != 1 || repo2.DependsOn[0] != "main-repo" {
		t.Errorf("Expected depends_on ['main-repo'], got %v", repo2.DependsOn)
	}

	// Check settings
	if !def.Workspace.Settings.CleanupOnComplete {
		t.Error("Expected cleanup_on_complete to be true")
	}
	if !def.Workspace.Settings.UseWorktrees {
		t.Error("Expected use_worktrees to be true")
	}
	if !def.Workspace.Settings.LSPEnabled {
		t.Error("Expected lsp_enabled to be true")
	}
	if def.Workspace.Settings.LSPTimeout.String() != "10s" {
		t.Errorf("Expected lsp_timeout 10s, got %s", def.Workspace.Settings.LSPTimeout)
	}
	if def.Workspace.Settings.BaseDirectory != "/tmp/workspaces" {
		t.Errorf("Expected base_directory '/tmp/workspaces', got '%s'", def.Workspace.Settings.BaseDirectory)
	}
}

// TestParseDefinitionWithMinimalWorkspace tests parsing minimal workspace config
func TestParseDefinitionWithMinimalWorkspace(t *testing.T) {
	yamlData := `
name: Test Mission Minimal Workspace
version: 1.0.0

workspace:
  repositories:
    - name: simple-repo
      url: https://github.com/org/repo.git

nodes:
  - id: node1
    type: agent
    agent: test-agent
`

	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseDefinitionFromBytes failed: %v", err)
	}

	if def.Workspace == nil {
		t.Fatal("Expected workspace to be set")
	}

	if len(def.Workspace.Repositories) != 1 {
		t.Fatalf("Expected 1 repository, got %d", len(def.Workspace.Repositories))
	}

	repo := def.Workspace.Repositories[0]
	if repo.Name != "simple-repo" {
		t.Errorf("Expected repository name 'simple-repo', got '%s'", repo.Name)
	}
	if repo.URL != "https://github.com/org/repo.git" {
		t.Errorf("Expected URL 'https://github.com/org/repo.git', got '%s'", repo.URL)
	}
}

// TestParseDefinitionWorkspaceValidation tests workspace validation errors
func TestParseDefinitionWorkspaceValidation(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		errorMsg string
	}{
		{
			name: "missing repository name",
			yaml: `
name: Test
version: 1.0.0
workspace:
  repositories:
    - url: https://github.com/org/repo.git
nodes:
  - id: node1
    type: agent
    agent: test-agent
`,
			errorMsg: "name' field is required",
		},
		{
			name: "missing repository URL",
			yaml: `
name: Test
version: 1.0.0
workspace:
  repositories:
    - name: test-repo
nodes:
  - id: node1
    type: agent
    agent: test-agent
`,
			errorMsg: "url' field is required",
		},
		{
			name: "invalid repository URL",
			yaml: `
name: Test
version: 1.0.0
workspace:
  repositories:
    - name: test-repo
      url: not-a-valid-url
nodes:
  - id: node1
    type: agent
    agent: test-agent
`,
			errorMsg: "invalid repository URL",
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
      depends_on:
        - repo-b
    - name: repo-b
      url: https://github.com/org/b.git
      depends_on:
        - repo-a
nodes:
  - id: node1
    type: agent
    agent: test-agent
`,
			errorMsg: "circular dependency detected",
		},
		{
			name: "non-existent dependency",
			yaml: `
name: Test
version: 1.0.0
workspace:
  repositories:
    - name: test-repo
      url: https://github.com/org/repo.git
      depends_on:
        - non-existent
nodes:
  - id: node1
    type: agent
    agent: test-agent
`,
			errorMsg: "references non-existent repository",
		},
		{
			name: "invalid LSP timeout",
			yaml: `
name: Test
version: 1.0.0
workspace:
  repositories:
    - name: test-repo
      url: https://github.com/org/repo.git
  lsp_timeout: invalid-duration
nodes:
  - id: node1
    type: agent
    agent: test-agent
`,
			errorMsg: "invalid workspace.lsp_timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDefinitionFromBytes([]byte(tt.yaml))
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			parseErr, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("Expected *ParseError, got %T", err)
			}
			if parseErr.Message == "" {
				t.Error("Expected error message")
			}
			// Check that error message contains expected substring
			found := false
			if tt.errorMsg != "" {
				found = containsIgnoreCase(parseErr.Message, tt.errorMsg)
			}
			if !found {
				t.Errorf("Expected error message to contain '%s', got: %s", tt.errorMsg, parseErr.Message)
			}
		})
	}
}

// TestParseDefinitionNoWorkspace tests parsing mission without workspace
func TestParseDefinitionNoWorkspace(t *testing.T) {
	yamlData := `
name: Test Mission No Workspace
version: 1.0.0

nodes:
  - id: node1
    type: agent
    agent: test-agent
`

	def, err := ParseDefinitionFromBytes([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseDefinitionFromBytes failed: %v", err)
	}

	// Workspace should be nil when not specified
	if def.Workspace != nil {
		t.Error("Expected workspace to be nil when not specified")
	}
}

// containsIgnoreCase checks if a string contains a substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}

func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		found := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				found = false
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}
