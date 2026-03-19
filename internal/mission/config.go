package mission

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// WorkspaceConfig defines the workspace configuration for a mission.
// This is embedded in the MissionDefinition to configure repository cloning
// and workspace management for agents that need to interact with code repositories.
type WorkspaceConfig struct {
	// Repositories contains the list of Git repositories to clone.
	// Each repository becomes a workspace accessible to agents during mission execution.
	Repositories []RepositoryConfig `json:"repositories" yaml:"repositories"`

	// Settings contains workspace-wide settings for cleanup, LSP, and isolation.
	Settings WorkspaceSettings `json:"settings" yaml:"workspace"`
}

// RepositoryConfig defines a single Git repository to clone for the mission.
// This configuration maps directly to the SDK's workspace.RepositoryConfig type.
type RepositoryConfig struct {
	// Name is the unique identifier for this repository within the mission.
	// Agents use this name to access the workspace via harness.Workspace(name).
	// Required field.
	Name string `json:"name" yaml:"name"`

	// URL is the Git repository URL (HTTPS or SSH).
	// Examples:
	//   HTTPS: https://github.com/org/repo.git
	//   SSH:   git@github.com:org/repo.git
	// Required field.
	URL string `json:"url" yaml:"url"`

	// Branch is the Git branch to checkout after cloning.
	// Defaults to the repository's default branch if empty.
	Branch string `json:"branch,omitempty" yaml:"branch,omitempty"`

	// CredentialName references a stored credential for authentication.
	// The credential is retrieved from the credential store during workspace initialization.
	// Supports API tokens for HTTPS and SSH keys for SSH URLs.
	// Optional - public repositories don't need credentials.
	CredentialName string `json:"credential_name,omitempty" yaml:"credential_name,omitempty"`

	// Shallow enables shallow cloning with --depth 1 for faster clones.
	// Use this for large repositories where full history is not needed.
	// Default: false
	Shallow bool `json:"shallow,omitempty" yaml:"shallow,omitempty"`

	// DependsOn lists repository names that must be cloned before this one.
	// This enables dependency ordering for multi-repository projects.
	// The workspace manager will clone repositories in topologically sorted order.
	// Each entry must reference another repository's Name field.
	DependsOn []string `json:"depends_on,omitempty" yaml:"depends_on,omitempty"`
}

// WorkspaceSettings contains workspace-wide configuration options.
// These settings apply to all repositories defined in the mission.
type WorkspaceSettings struct {
	// CleanupOnComplete determines whether to delete workspace directories
	// after mission completion. Set to false to preserve workspaces for debugging.
	// Default: true
	CleanupOnComplete bool `json:"cleanup_on_complete" yaml:"cleanup_on_complete"`

	// UseWorktrees enables Git worktrees for agent isolation.
	// When true, each agent gets a separate worktree from the same repository,
	// allowing concurrent modifications without conflicts.
	// Default: false
	UseWorktrees bool `json:"use_worktrees,omitempty" yaml:"use_worktrees,omitempty"`

	// LSPEnabled determines whether to start language servers for code validation.
	// When true, editors will validate changes using LSP before applying them.
	// Default: false
	LSPEnabled bool `json:"lsp_enabled,omitempty" yaml:"lsp_enabled,omitempty"`

	// LSPTimeout is the maximum time to wait for LSP validation responses.
	// If validation exceeds this timeout, changes are applied with a warning.
	// Default: 5s
	LSPTimeout time.Duration `json:"lsp_timeout,omitempty" yaml:"lsp_timeout,omitempty"`

	// BaseDirectory is the directory where workspace clones are created.
	// Defaults to a temporary directory if not specified.
	BaseDirectory string `json:"base_directory,omitempty" yaml:"base_directory,omitempty"`
}

// Validate performs comprehensive validation of the workspace configuration.
// It checks for:
//   - Valid repository URLs
//   - Unique repository names
//   - Valid dependency references
//   - Acyclic dependency graph
//   - Valid timeout durations
//
// Returns an error describing the first validation failure encountered.
func (wc *WorkspaceConfig) Validate() error {
	if len(wc.Repositories) == 0 {
		// Workspace config is optional - if no repositories defined, nothing to validate
		return nil
	}

	// Track repository names for uniqueness and dependency validation
	repoNames := make(map[string]bool)
	for i, repo := range wc.Repositories {
		// Validate name is provided
		if repo.Name == "" {
			return fmt.Errorf("repository at index %d: name is required", i)
		}

		// Check for duplicate names
		if repoNames[repo.Name] {
			return fmt.Errorf("repository '%s': duplicate repository name", repo.Name)
		}
		repoNames[repo.Name] = true

		// Validate URL is provided and well-formed
		if repo.URL == "" {
			return fmt.Errorf("repository '%s': url is required", repo.Name)
		}

		if err := validateRepositoryURL(repo.URL); err != nil {
			return fmt.Errorf("repository '%s': %w", repo.Name, err)
		}
	}

	// Validate dependency references
	for _, repo := range wc.Repositories {
		for _, dep := range repo.DependsOn {
			if !repoNames[dep] {
				return fmt.Errorf("repository '%s': depends_on references non-existent repository '%s'", repo.Name, dep)
			}
			// Check for self-dependency
			if dep == repo.Name {
				return fmt.Errorf("repository '%s': cannot depend on itself", repo.Name)
			}
		}
	}

	// Validate dependency graph is acyclic
	if err := validateDependencyGraph(wc.Repositories); err != nil {
		return err
	}

	// Validate LSP timeout if specified
	if wc.Settings.LSPTimeout < 0 {
		return fmt.Errorf("workspace settings: lsp_timeout cannot be negative")
	}

	return nil
}

// validateRepositoryURL validates that a repository URL is well-formed.
// Supports both HTTPS and SSH URL formats.
func validateRepositoryURL(rawURL string) error {
	// Handle SSH URLs (git@github.com:org/repo.git)
	if strings.HasPrefix(rawURL, "git@") {
		parts := strings.SplitN(rawURL, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid SSH URL format: %s", rawURL)
		}
		// Validate host part
		hostPart := strings.TrimPrefix(parts[0], "git@")
		if hostPart == "" {
			return fmt.Errorf("invalid SSH URL: missing host")
		}
		// Validate path part
		if parts[1] == "" {
			return fmt.Errorf("invalid SSH URL: missing path")
		}
		return nil
	}

	// Handle HTTPS URLs
	if strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://") {
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}
		if parsedURL.Host == "" {
			return fmt.Errorf("invalid URL: missing host")
		}
		if parsedURL.Path == "" || parsedURL.Path == "/" {
			return fmt.Errorf("invalid URL: missing repository path")
		}
		return nil
	}

	return fmt.Errorf("invalid repository URL: must be HTTPS (https://...) or SSH (git@...)")
}

// validateDependencyGraph checks that the repository dependency graph is acyclic.
// Uses depth-first search with path tracking to detect cycles.
func validateDependencyGraph(repos []RepositoryConfig) error {
	// Build adjacency list
	graph := make(map[string][]string)
	for _, repo := range repos {
		graph[repo.Name] = repo.DependsOn
	}

	// Track visited nodes and nodes in current path
	visited := make(map[string]bool)
	inPath := make(map[string]bool)

	var dfs func(string, []string) error
	dfs = func(node string, path []string) error {
		if inPath[node] {
			// Found a cycle - build cycle description
			cycleStart := -1
			for i, n := range path {
				if n == node {
					cycleStart = i
					break
				}
			}
			cycle := append(path[cycleStart:], node)
			return fmt.Errorf("circular dependency detected: %s", strings.Join(cycle, " -> "))
		}

		if visited[node] {
			return nil
		}

		visited[node] = true
		inPath[node] = true
		path = append(path, node)

		for _, dep := range graph[node] {
			if err := dfs(dep, path); err != nil {
				return err
			}
		}

		inPath[node] = false
		return nil
	}

	// Check each repository as a potential starting point
	for _, repo := range repos {
		if !visited[repo.Name] {
			if err := dfs(repo.Name, []string{}); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetRepository returns the repository configuration by name.
// Returns nil if no repository with that name exists.
func (wc *WorkspaceConfig) GetRepository(name string) *RepositoryConfig {
	for i := range wc.Repositories {
		if wc.Repositories[i].Name == name {
			return &wc.Repositories[i]
		}
	}
	return nil
}

// HasRepositories returns true if at least one repository is configured.
func (wc *WorkspaceConfig) HasRepositories() bool {
	return len(wc.Repositories) > 0
}
