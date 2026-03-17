package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClaimsMapper_ExtractClaims(t *testing.T) {
	mapper := NewClaimsMapper()

	tests := []struct {
		name        string
		claims      map[string]any
		issuer      string
		wantClaims  map[string]any
		checkFields []string
	}{
		{
			name: "GitHub Actions - repository and ref",
			claims: map[string]any{
				"iss":              "https://token.actions.githubusercontent.com",
				"repository":       "myorg/infra",
				"ref":              "refs/heads/main",
				"workflow":         "CI Pipeline",
				"actor":            "john-doe",
				"repository_owner": "myorg",
			},
			issuer: "https://token.actions.githubusercontent.com",
			checkFields: []string{
				"repository", "repo", "repo_owner", "repo_name",
				"ref", "branch", "branch_name",
				"workflow", "actor", "username",
				"repository_owner",
			},
			wantClaims: map[string]any{
				"repository":       "myorg/infra",
				"repo":             "myorg/infra",
				"repo_owner":       "myorg",
				"repo_name":        "infra",
				"ref":              "refs/heads/main",
				"branch":           "refs/heads/main",
				"branch_name":      "main",
				"workflow":         "CI Pipeline",
				"actor":            "john-doe",
				"username":         "john-doe",
				"repository_owner": "myorg",
			},
		},
		{
			name: "GitHub Actions - tag ref",
			claims: map[string]any{
				"repository": "myorg/app",
				"ref":        "refs/tags/v1.0.0",
			},
			issuer: "https://token.actions.githubusercontent.com",
			checkFields: []string{
				"tag_name",
			},
			wantClaims: map[string]any{
				"tag_name": "v1.0.0",
			},
		},
		{
			name: "GitLab CI - project and ref",
			claims: map[string]any{
				"iss":             "https://gitlab.com",
				"project_path":    "myorg/security-pipelines",
				"ref":             "main",
				"ref_type":        "branch",
				"pipeline_source": "push",
				"user_login":      "alice",
			},
			issuer: "https://gitlab.com",
			checkFields: []string{
				"project", "project_path", "group", "project_name",
				"ref", "branch", "ref_type", "pipeline_source",
				"username",
			},
			wantClaims: map[string]any{
				"project":         "myorg/security-pipelines",
				"project_path":    "myorg/security-pipelines",
				"group":           "myorg",
				"project_name":    "security-pipelines",
				"ref":             "main",
				"branch":          "main",
				"ref_type":        "branch",
				"pipeline_source": "push",
				"username":        "alice",
			},
		},
		{
			name: "Google Workspace - hosted domain",
			claims: map[string]any{
				"iss":            "https://accounts.google.com",
				"hd":             "company.com",
				"email":          "user@company.com",
				"email_verified": true,
			},
			issuer: "https://accounts.google.com",
			checkFields: []string{
				"domain", "hosted_domain", "email_verified",
			},
			wantClaims: map[string]any{
				"domain":         "company.com",
				"hosted_domain":  "company.com",
				"email_verified": true,
			},
		},
		{
			name: "Azure AD - groups and roles",
			claims: map[string]any{
				"iss":                "https://login.microsoftonline.com/tenant-id",
				"groups":             []string{"group1", "group2"},
				"roles":              []string{"admin", "developer"},
				"preferred_username": "user@company.onmicrosoft.com",
			},
			issuer: "https://login.microsoftonline.com/tenant-id",
			checkFields: []string{
				"groups", "roles", "username",
			},
			wantClaims: map[string]any{
				"groups":   []string{"group1", "group2"},
				"roles":    []string{"admin", "developer"},
				"username": "user@company.onmicrosoft.com",
			},
		},
		{
			name: "Standard OIDC - no special normalization",
			claims: map[string]any{
				"iss":   "https://custom-idp.example.com",
				"sub":   "user123",
				"email": "user@example.com",
			},
			issuer: "https://custom-idp.example.com",
			checkFields: []string{
				"iss", "sub", "email",
			},
			wantClaims: map[string]any{
				"iss":   "https://custom-idp.example.com",
				"sub":   "user123",
				"email": "user@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.ExtractClaims(tt.claims, tt.issuer)

			// Check that all expected fields are present
			for _, field := range tt.checkFields {
				assert.Contains(t, result, field, "Missing field: %s", field)
			}

			// Check specific values if provided
			for key, expected := range tt.wantClaims {
				assert.Equal(t, expected, result[key], "Field %s mismatch", key)
			}
		})
	}
}

func TestClaimsMapper_ExtractGroups(t *testing.T) {
	mapper := NewClaimsMapper()

	tests := []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{
			name: "string array",
			claims: map[string]any{
				"groups": []string{"admin", "developer"},
			},
			want: []string{"admin", "developer"},
		},
		{
			name: "interface array",
			claims: map[string]any{
				"groups": []interface{}{"admin", "developer"},
			},
			want: []string{"admin", "developer"},
		},
		{
			name: "single string",
			claims: map[string]any{
				"groups": "admin",
			},
			want: []string{"admin"},
		},
		{
			name:   "no groups claim",
			claims: map[string]any{},
			want:   []string{},
		},
		{
			name: "invalid type",
			claims: map[string]any{
				"groups": 12345,
			},
			want: []string{},
		},
		{
			name: "empty array",
			claims: map[string]any{
				"groups": []string{},
			},
			want: []string{},
		},
		{
			name: "mixed types in array (filtered)",
			claims: map[string]any{
				"groups": []interface{}{"admin", 123, "developer"},
			},
			want: []string{"admin", "developer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.ExtractGroups(tt.claims)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestClaimsMapper_ExtractRepoRef(t *testing.T) {
	mapper := NewClaimsMapper()

	tests := []struct {
		name   string
		claims map[string]any
		issuer string
		want   string
	}{
		{
			name: "GitHub Actions - valid repo and ref",
			claims: map[string]any{
				"repository": "myorg/infra",
				"ref":        "refs/heads/main",
			},
			issuer: "https://token.actions.githubusercontent.com",
			want:   "myorg/infra:refs/heads/main",
		},
		{
			name: "GitHub Actions - missing ref",
			claims: map[string]any{
				"repository": "myorg/infra",
			},
			issuer: "https://token.actions.githubusercontent.com",
			want:   "",
		},
		{
			name: "GitHub Actions - missing repository",
			claims: map[string]any{
				"ref": "refs/heads/main",
			},
			issuer: "https://token.actions.githubusercontent.com",
			want:   "",
		},
		{
			name: "GitLab CI - valid project and ref",
			claims: map[string]any{
				"project_path": "myorg/security",
				"ref":          "main",
			},
			issuer: "https://gitlab.com",
			want:   "myorg/security:main",
		},
		{
			name: "GitLab CI - missing ref",
			claims: map[string]any{
				"project_path": "myorg/security",
			},
			issuer: "https://gitlab.com",
			want:   "",
		},
		{
			name: "Non-CI/CD issuer",
			claims: map[string]any{
				"repository": "myorg/infra",
				"ref":        "refs/heads/main",
			},
			issuer: "https://custom-idp.example.com",
			want:   "",
		},
		{
			name:   "Empty claims",
			claims: map[string]any{},
			issuer: "https://token.actions.githubusercontent.com",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapper.ExtractRepoRef(tt.claims, tt.issuer)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestClaimsMapper_NormalizeGitHubActions(t *testing.T) {
	mapper := NewClaimsMapper()

	claims := map[string]any{
		"repository":       "zero-day-ai/gibson",
		"ref":              "refs/heads/feature-branch",
		"workflow":         "Security Scan",
		"actor":            "dependabot",
		"repository_owner": "zero-day-ai",
	}

	normalized := make(map[string]any)
	mapper.normalizeGitHubActions(claims, normalized)

	// Check repository normalization
	assert.Equal(t, "zero-day-ai/gibson", normalized["repo"])
	assert.Equal(t, "zero-day-ai/gibson", normalized["repository"])
	assert.Equal(t, "zero-day-ai", normalized["repo_owner"])
	assert.Equal(t, "gibson", normalized["repo_name"])

	// Check ref normalization
	assert.Equal(t, "refs/heads/feature-branch", normalized["ref"])
	assert.Equal(t, "refs/heads/feature-branch", normalized["branch"])
	assert.Equal(t, "feature-branch", normalized["branch_name"])

	// Check other fields
	assert.Equal(t, "Security Scan", normalized["workflow"])
	assert.Equal(t, "dependabot", normalized["actor"])
	assert.Equal(t, "dependabot", normalized["username"])
	assert.Equal(t, "zero-day-ai", normalized["repository_owner"])
}

func TestClaimsMapper_NormalizeGitLabCI(t *testing.T) {
	mapper := NewClaimsMapper()

	claims := map[string]any{
		"project_path":    "group/subgroup/project",
		"ref":             "develop",
		"ref_type":        "branch",
		"pipeline_source": "merge_request_event",
		"user_login":      "alice",
	}

	normalized := make(map[string]any)
	mapper.normalizeGitLabCI(claims, normalized)

	// Check project normalization
	assert.Equal(t, "group/subgroup/project", normalized["project"])
	assert.Equal(t, "group/subgroup/project", normalized["project_path"])
	assert.Equal(t, "group", normalized["group"])
	assert.Equal(t, "project", normalized["project_name"])

	// Check ref normalization
	assert.Equal(t, "develop", normalized["ref"])
	assert.Equal(t, "develop", normalized["branch"])
	assert.Equal(t, "branch", normalized["ref_type"])
	assert.Equal(t, "merge_request_event", normalized["pipeline_source"])

	// Check user
	assert.Equal(t, "alice", normalized["username"])
}

func TestClaimsMapper_NormalizeGoogle(t *testing.T) {
	mapper := NewClaimsMapper()

	claims := map[string]any{
		"hd":             "example.com",
		"email_verified": true,
	}

	normalized := make(map[string]any)
	mapper.normalizeGoogle(claims, normalized)

	assert.Equal(t, "example.com", normalized["domain"])
	assert.Equal(t, "example.com", normalized["hosted_domain"])
	assert.Equal(t, true, normalized["email_verified"])
}

func TestClaimsMapper_NormalizeAzureAD(t *testing.T) {
	mapper := NewClaimsMapper()

	claims := map[string]any{
		"groups":             []string{"engineers", "security"},
		"roles":              []string{"contributor"},
		"preferred_username": "user@company.onmicrosoft.com",
	}

	normalized := make(map[string]any)
	mapper.normalizeAzureAD(claims, normalized)

	assert.Equal(t, []string{"engineers", "security"}, normalized["groups"])
	assert.Equal(t, []string{"contributor"}, normalized["roles"])
	assert.Equal(t, "user@company.onmicrosoft.com", normalized["username"])
}

func TestClaimsMapper_EdgeCases(t *testing.T) {
	mapper := NewClaimsMapper()

	t.Run("nil claims map", func(t *testing.T) {
		result := mapper.ExtractClaims(nil, "https://issuer.com")
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("empty claims map", func(t *testing.T) {
		result := mapper.ExtractClaims(map[string]any{}, "https://issuer.com")
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("empty issuer", func(t *testing.T) {
		claims := map[string]any{"sub": "user123"}
		result := mapper.ExtractClaims(claims, "")
		assert.Contains(t, result, "sub")
		assert.Equal(t, "user123", result["sub"])
	})

	t.Run("malformed repository without slash", func(t *testing.T) {
		claims := map[string]any{
			"repository": "noslash",
			"ref":        "refs/heads/main",
		}
		normalized := make(map[string]any)
		mapper.normalizeGitHubActions(claims, normalized)

		// Should still set repo fields but not owner/name
		assert.Equal(t, "noslash", normalized["repo"])
		assert.NotContains(t, normalized, "repo_owner")
		assert.NotContains(t, normalized, "repo_name")
	})

	t.Run("malformed project path without slash", func(t *testing.T) {
		claims := map[string]any{
			"project_path": "noslash",
		}
		normalized := make(map[string]any)
		mapper.normalizeGitLabCI(claims, normalized)

		// Should still set project fields but not group/name
		assert.Equal(t, "noslash", normalized["project"])
		assert.NotContains(t, normalized, "group")
		assert.NotContains(t, normalized, "project_name")
	})
}

// Benchmark tests
func BenchmarkClaimsMapper_ExtractClaims(b *testing.B) {
	mapper := NewClaimsMapper()
	claims := map[string]any{
		"repository":       "myorg/infra",
		"ref":              "refs/heads/main",
		"workflow":         "CI",
		"actor":            "user",
		"repository_owner": "myorg",
	}
	issuer := "https://token.actions.githubusercontent.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapper.ExtractClaims(claims, issuer)
	}
}

func BenchmarkClaimsMapper_ExtractGroups(b *testing.B) {
	mapper := NewClaimsMapper()
	claims := map[string]any{
		"groups": []string{"admin", "developer", "security", "ops"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapper.ExtractGroups(claims)
	}
}
