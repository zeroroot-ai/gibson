package mission

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkspaceConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    WorkspaceConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid single repository",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name: "main-repo",
						URL:  "https://github.com/org/repo.git",
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid multiple repositories with dependencies",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name: "core",
						URL:  "https://github.com/org/core.git",
					},
					{
						Name:      "plugin",
						URL:       "https://github.com/org/plugin.git",
						DependsOn: []string{"core"},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid SSH URL",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name: "ssh-repo",
						URL:  "git@github.com:org/repo.git",
					},
				},
			},
			wantError: false,
		},
		{
			name: "empty repositories is valid",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{},
			},
			wantError: false,
		},
		{
			name: "missing repository name",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name: "",
						URL:  "https://github.com/org/repo.git",
					},
				},
			},
			wantError: true,
			errorMsg:  "name is required",
		},
		{
			name: "missing repository URL",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name: "test",
						URL:  "",
					},
				},
			},
			wantError: true,
			errorMsg:  "url is required",
		},
		{
			name: "duplicate repository names",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name: "duplicate",
						URL:  "https://github.com/org/repo1.git",
					},
					{
						Name: "duplicate",
						URL:  "https://github.com/org/repo2.git",
					},
				},
			},
			wantError: true,
			errorMsg:  "duplicate repository name",
		},
		{
			name: "invalid HTTPS URL",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name: "invalid",
						URL:  "not-a-url",
					},
				},
			},
			wantError: true,
			errorMsg:  "invalid repository URL",
		},
		{
			name: "invalid SSH URL format",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name: "invalid-ssh",
						URL:  "git@github.com",
					},
				},
			},
			wantError: true,
			errorMsg:  "invalid SSH URL format",
		},
		{
			name: "non-existent dependency",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name:      "dependent",
						URL:       "https://github.com/org/repo.git",
						DependsOn: []string{"non-existent"},
					},
				},
			},
			wantError: true,
			errorMsg:  "references non-existent repository",
		},
		{
			name: "self-dependency",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name:      "self-dep",
						URL:       "https://github.com/org/repo.git",
						DependsOn: []string{"self-dep"},
					},
				},
			},
			wantError: true,
			errorMsg:  "cannot depend on itself",
		},
		{
			name: "circular dependency simple",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name:      "repo-a",
						URL:       "https://github.com/org/a.git",
						DependsOn: []string{"repo-b"},
					},
					{
						Name:      "repo-b",
						URL:       "https://github.com/org/b.git",
						DependsOn: []string{"repo-a"},
					},
				},
			},
			wantError: true,
			errorMsg:  "circular dependency detected",
		},
		{
			name: "circular dependency complex",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name:      "repo-a",
						URL:       "https://github.com/org/a.git",
						DependsOn: []string{"repo-b"},
					},
					{
						Name:      "repo-b",
						URL:       "https://github.com/org/b.git",
						DependsOn: []string{"repo-c"},
					},
					{
						Name:      "repo-c",
						URL:       "https://github.com/org/c.git",
						DependsOn: []string{"repo-a"},
					},
				},
			},
			wantError: true,
			errorMsg:  "circular dependency detected",
		},
		{
			name: "negative LSP timeout",
			config: WorkspaceConfig{
				Repositories: []RepositoryConfig{
					{
						Name: "test",
						URL:  "https://github.com/org/repo.git",
					},
				},
				Settings: WorkspaceSettings{
					LSPTimeout: -1 * time.Second,
				},
			},
			wantError: true,
			errorMsg:  "lsp_timeout cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateRepositoryURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid HTTPS GitHub URL",
			url:       "https://github.com/org/repo.git",
			wantError: false,
		},
		{
			name:      "valid HTTPS GitLab URL",
			url:       "https://gitlab.com/org/repo.git",
			wantError: false,
		},
		{
			name:      "valid HTTP URL",
			url:       "http://git.example.com/repo.git",
			wantError: false,
		},
		{
			name:      "valid SSH GitHub URL",
			url:       "git@github.com:org/repo.git",
			wantError: false,
		},
		{
			name:      "valid SSH GitLab URL",
			url:       "git@gitlab.com:org/group/repo.git",
			wantError: false,
		},
		{
			name:      "valid SSH with custom port",
			url:       "git@example.com:2222/org/repo.git",
			wantError: false,
		},
		{
			name:      "invalid - no protocol",
			url:       "github.com/org/repo.git",
			wantError: true,
			errorMsg:  "must be HTTPS",
		},
		{
			name:      "invalid - SSH without colon",
			url:       "git@github.com",
			wantError: true,
			errorMsg:  "invalid SSH URL format",
		},
		{
			name:      "invalid - SSH without path",
			url:       "git@github.com:",
			wantError: true,
			errorMsg:  "missing path",
		},
		{
			name:      "invalid - HTTPS without host",
			url:       "https:///repo.git",
			wantError: true,
			errorMsg:  "missing host",
		},
		{
			name:      "invalid - HTTPS without path",
			url:       "https://github.com",
			wantError: true,
			errorMsg:  "missing repository path",
		},
		{
			name:      "invalid - HTTPS with only slash",
			url:       "https://github.com/",
			wantError: true,
			errorMsg:  "missing repository path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRepositoryURL(tt.url)
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateDependencyGraph(t *testing.T) {
	tests := []struct {
		name      string
		repos     []RepositoryConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid linear dependency chain",
			repos: []RepositoryConfig{
				{Name: "a", URL: "url1", DependsOn: []string{}},
				{Name: "b", URL: "url2", DependsOn: []string{"a"}},
				{Name: "c", URL: "url3", DependsOn: []string{"b"}},
			},
			wantError: false,
		},
		{
			name: "valid diamond dependency",
			repos: []RepositoryConfig{
				{Name: "base", URL: "url1", DependsOn: []string{}},
				{Name: "left", URL: "url2", DependsOn: []string{"base"}},
				{Name: "right", URL: "url3", DependsOn: []string{"base"}},
				{Name: "top", URL: "url4", DependsOn: []string{"left", "right"}},
			},
			wantError: false,
		},
		{
			name: "simple cycle",
			repos: []RepositoryConfig{
				{Name: "a", URL: "url1", DependsOn: []string{"b"}},
				{Name: "b", URL: "url2", DependsOn: []string{"a"}},
			},
			wantError: true,
			errorMsg:  "circular dependency detected",
		},
		{
			name: "three-node cycle",
			repos: []RepositoryConfig{
				{Name: "a", URL: "url1", DependsOn: []string{"b"}},
				{Name: "b", URL: "url2", DependsOn: []string{"c"}},
				{Name: "c", URL: "url3", DependsOn: []string{"a"}},
			},
			wantError: true,
			errorMsg:  "circular dependency detected",
		},
		{
			name: "cycle with extra nodes",
			repos: []RepositoryConfig{
				{Name: "independent", URL: "url1", DependsOn: []string{}},
				{Name: "a", URL: "url2", DependsOn: []string{"b"}},
				{Name: "b", URL: "url3", DependsOn: []string{"c"}},
				{Name: "c", URL: "url4", DependsOn: []string{"a"}},
			},
			wantError: true,
			errorMsg:  "circular dependency detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDependencyGraph(tt.repos)
			if tt.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWorkspaceConfig_GetRepository(t *testing.T) {
	config := WorkspaceConfig{
		Repositories: []RepositoryConfig{
			{Name: "repo1", URL: "url1"},
			{Name: "repo2", URL: "url2"},
			{Name: "repo3", URL: "url3"},
		},
	}

	t.Run("existing repository", func(t *testing.T) {
		repo := config.GetRepository("repo2")
		require.NotNil(t, repo)
		assert.Equal(t, "repo2", repo.Name)
		assert.Equal(t, "url2", repo.URL)
	})

	t.Run("non-existent repository", func(t *testing.T) {
		repo := config.GetRepository("non-existent")
		assert.Nil(t, repo)
	})

	t.Run("empty name", func(t *testing.T) {
		repo := config.GetRepository("")
		assert.Nil(t, repo)
	})
}

func TestWorkspaceConfig_HasRepositories(t *testing.T) {
	t.Run("with repositories", func(t *testing.T) {
		config := WorkspaceConfig{
			Repositories: []RepositoryConfig{
				{Name: "repo1", URL: "url1"},
			},
		}
		assert.True(t, config.HasRepositories())
	})

	t.Run("without repositories", func(t *testing.T) {
		config := WorkspaceConfig{
			Repositories: []RepositoryConfig{},
		}
		assert.False(t, config.HasRepositories())
	})

	t.Run("nil repositories", func(t *testing.T) {
		config := WorkspaceConfig{}
		assert.False(t, config.HasRepositories())
	})
}
