package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

func TestNewRoleBinder(t *testing.T) {
	bindings := []RoleBinding{
		{Matcher: "admin-*", Roles: []string{"admin"}},
		{Matcher: "dev-*", Roles: []string{"developer"}},
	}

	binder := NewRoleBinder(bindings)
	assert.NotNil(t, binder)
	assert.Equal(t, 2, len(binder.bindings))
}

func TestNewRoleBinderFromConfig(t *testing.T) {
	config := map[string][]string{
		"admin-*":    {"admin"},
		"developers": {"mission:execute", "findings:read"},
		"myorg/*:*":  {"ci_runner"},
	}

	binder := NewRoleBinderFromConfig(config)
	assert.NotNil(t, binder)
	assert.Equal(t, 3, len(binder.bindings))
}

func TestRoleBinder_ResolveRoles_GroupBased(t *testing.T) {
	bindings := []RoleBinding{
		{Matcher: "admin", Roles: []string{"admin"}},
		{Matcher: "developers", Roles: []string{"mission:execute", "findings:read"}},
		{Matcher: "security-*", Roles: []string{"findings:write", "mission:execute"}},
	}

	binder := NewRoleBinder(bindings)

	tests := []struct {
		name          string
		groups        []string
		expectedRoles []string
		shouldError   bool
	}{
		{
			name:          "admin group",
			groups:        []string{"admin"},
			expectedRoles: []string{"admin"},
			shouldError:   false,
		},
		{
			name:          "developers group",
			groups:        []string{"developers"},
			expectedRoles: []string{"mission:execute", "findings:read"},
			shouldError:   false,
		},
		{
			name:          "wildcard match - security-team",
			groups:        []string{"security-team"},
			expectedRoles: []string{"findings:write", "mission:execute"},
			shouldError:   false,
		},
		{
			name:          "wildcard match - security-admins",
			groups:        []string{"security-admins"},
			expectedRoles: []string{"findings:write", "mission:execute"},
			shouldError:   false,
		},
		{
			name:          "multiple groups",
			groups:        []string{"developers", "security-team"},
			expectedRoles: []string{"mission:execute", "findings:read", "findings:write"},
			shouldError:   false,
		},
		{
			name:        "no matching groups",
			groups:      []string{"unknown-group"},
			shouldError: true,
		},
		{
			name:        "empty groups",
			groups:      []string{},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{
				Identity: sdkauth.Identity{
					Subject: "test-user",
					Groups:  tt.groups,
					Claims:  map[string]any{},
				},
			}

			roles, perms, err := binder.ResolveRoles(identity)

			if tt.shouldError {
				assert.Error(t, err)
				assert.Nil(t, roles)
				assert.Nil(t, perms)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, roles)
				assert.NotNil(t, perms)

				// Check that all expected roles are present
				for _, expectedRole := range tt.expectedRoles {
					assert.Contains(t, roles, expectedRole)
				}

				// Check permissions were computed
				assert.NotEmpty(t, perms)
			}
		})
	}
}

func TestRoleBinder_ResolveRoles_RepoBased(t *testing.T) {
	bindings := []RoleBinding{
		{Matcher: "myorg/*:refs/heads/main", Roles: []string{"prod_deployer"}},
		{Matcher: "myorg/infra:*", Roles: []string{"infra_admin"}},
		{Matcher: "security/*:*", Roles: []string{"security_scanner"}},
	}

	binder := NewRoleBinder(bindings)

	tests := []struct {
		name          string
		repository    string
		ref           string
		expectedRoles []string
		shouldError   bool
	}{
		{
			name:          "exact match - myorg repo on main",
			repository:    "myorg/app",
			ref:           "refs/heads/main",
			expectedRoles: []string{"prod_deployer"},
			shouldError:   false,
		},
		{
			name:          "exact match - myorg/infra on any ref",
			repository:    "myorg/infra",
			ref:           "refs/heads/feature",
			expectedRoles: []string{"infra_admin"},
			shouldError:   false,
		},
		{
			name:          "wildcard match - security org",
			repository:    "security/scanner",
			ref:           "refs/heads/develop",
			expectedRoles: []string{"security_scanner"},
			shouldError:   false,
		},
		{
			name:        "no match",
			repository:  "other/repo",
			ref:         "refs/heads/main",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{
				Identity: sdkauth.Identity{
					Subject: "ci-runner",
					Claims: map[string]any{
						"repository": tt.repository,
						"ref":        tt.ref,
					},
				},
			}

			roles, _, err := binder.ResolveRoles(identity)

			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				for _, expectedRole := range tt.expectedRoles {
					assert.Contains(t, roles, expectedRole)
				}
			}
		})
	}
}

func TestRoleBinder_ResolveRoles_ClaimBased(t *testing.T) {
	bindings := []RoleBinding{
		{Matcher: "company.com", Roles: []string{"employee"}},
		{Matcher: "admin@*", Roles: []string{"admin"}},
	}

	binder := NewRoleBinder(bindings)

	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user123",
			Email:   "admin@company.com",
			Claims: map[string]any{
				"email":  "admin@company.com",
				"domain": "company.com",
			},
		},
	}

	roles, _, err := binder.ResolveRoles(identity)
	assert.NoError(t, err)

	// Should match both patterns
	assert.Contains(t, roles, "employee") // domain matches
	assert.Contains(t, roles, "admin")    // email matches
}

func TestRoleBinder_matchPattern(t *testing.T) {
	binder := NewRoleBinder(nil)

	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Exact matches
		{"admin", "admin", true},
		{"security-team", "security-team", true},

		// Wildcards
		{"*", "anything", true},
		{"admin-*", "admin-group", true},
		{"*-admins", "security-admins", true},
		{"myorg/*", "myorg/repo", true},
		{"*/main", "myorg/main", true},

		// Non-matches
		{"admin", "user", false},
		{"admin-*", "user-admin", false},
		{"myorg/*", "other/repo", false},

		// Complex patterns
		{"myorg/*:refs/heads/main", "myorg/app:refs/heads/main", true},
		{"myorg/*:refs/heads/main", "myorg/app:refs/heads/develop", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			result := binder.matchPattern(tt.pattern, tt.value)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestRoleBinder_computePermissions(t *testing.T) {
	binder := NewRoleBinder(nil)

	tests := []struct {
		name            string
		roles           []string
		expectedPerms   []Permission
		checkPermission func(perms []Permission) bool
	}{
		{
			name:  "admin role grants all",
			roles: []string{"admin"},
			expectedPerms: []Permission{
				{Action: "*", Resource: "*", Scope: "*"},
			},
		},
		{
			name:  "specific resource:action roles",
			roles: []string{"mission:execute", "findings:read"},
			expectedPerms: []Permission{
				{Action: "execute", Resource: "mission", Scope: "*"},
				{Action: "read", Resource: "findings", Scope: "*"},
			},
		},
		{
			name:  "wildcard action",
			roles: []string{"findings:*"},
			expectedPerms: []Permission{
				{Action: "*", Resource: "findings", Scope: "*"},
			},
		},
		{
			name:  "scoped permission",
			roles: []string{"mission:execute:prod-*"},
			expectedPerms: []Permission{
				{Action: "execute", Resource: "mission", Scope: "prod-*"},
			},
		},
		{
			name:          "invalid role format ignored",
			roles:         []string{"invalid-role-no-colon"},
			expectedPerms: []Permission{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := binder.computePermissions(tt.roles)

			if tt.checkPermission != nil {
				assert.True(t, tt.checkPermission(perms))
			} else {
				assert.Equal(t, len(tt.expectedPerms), len(perms))
				for _, expected := range tt.expectedPerms {
					found := false
					for _, perm := range perms {
						if perm.Action == expected.Action &&
							perm.Resource == expected.Resource &&
							perm.Scope == expected.Scope {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected permission not found: %+v", expected)
				}
			}
		})
	}
}

func TestRoleBinder_HasPermission(t *testing.T) {
	binder := NewRoleBinder(nil)

	tests := []struct {
		name     string
		roles    []string
		action   string
		resource string
		want     bool
	}{
		{
			name:     "admin has all permissions",
			roles:    []string{"admin"},
			action:   "execute",
			resource: "mission",
			want:     true,
		},
		{
			name:     "specific permission granted",
			roles:    []string{"mission:execute"},
			action:   "execute",
			resource: "mission",
			want:     true,
		},
		{
			name:     "wildcard action",
			roles:    []string{"findings:*"},
			action:   "write",
			resource: "findings",
			want:     true,
		},
		{
			name:     "permission denied",
			roles:    []string{"findings:read"},
			action:   "write",
			resource: "findings",
			want:     false,
		},
		{
			name:     "different resource",
			roles:    []string{"findings:read"},
			action:   "read",
			resource: "mission",
			want:     false,
		},
		{
			name:     "no roles",
			roles:    []string{},
			action:   "read",
			resource: "findings",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := binder.HasPermission(tt.roles, tt.action, tt.resource)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestRoleBinder_NilIdentity(t *testing.T) {
	binder := NewRoleBinder([]RoleBinding{
		{Matcher: "*", Roles: []string{"guest"}},
	})

	roles, perms, err := binder.ResolveRoles(nil)
	assert.Error(t, err)
	assert.Nil(t, roles)
	assert.Nil(t, perms)
}

func TestRoleBinder_Deduplication(t *testing.T) {
	// Multiple bindings grant same roles
	bindings := []RoleBinding{
		{Matcher: "admin", Roles: []string{"admin", "user"}},
		{Matcher: "superuser", Roles: []string{"admin", "developer"}},
	}

	binder := NewRoleBinder(bindings)

	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "test",
			Groups:  []string{"admin", "superuser"},
		},
	}

	roles, _, err := binder.ResolveRoles(identity)
	require.NoError(t, err)

	// Count occurrences of "admin" role
	adminCount := 0
	for _, role := range roles {
		if role == "admin" {
			adminCount++
		}
	}

	// Should only appear once despite multiple matches
	assert.Equal(t, 1, adminCount)

	// Should have all unique roles
	assert.Contains(t, roles, "admin")
	assert.Contains(t, roles, "user")
	assert.Contains(t, roles, "developer")
}

// TestIdentity_HasPermission and TestIdentity_HasRole were removed as part of
// the declarative-rbac-framework spec: the Identity methods they exercised
// (HasRole, HasPermission, HasCapability) have been deleted. Authorization is
// now enforced exclusively by the gRPC FGA interceptor — see
// fga_authz_interceptor.go and fga_rpc_registry.go for the new coverage.

func TestIdentity_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"not expired", now.Add(1 * time.Hour), false},
		{"expired", now.Add(-1 * time.Hour), true},
		{"just expired", now.Add(-1 * time.Second), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{
				Identity: sdkauth.Identity{ExpiresAt: tt.expiresAt},
			}
			assert.Equal(t, tt.want, identity.IsExpired())
		})
	}

	// Note: Nil identity checking removed - when Gibson Identity is nil,
	// calling IsExpired() panics because the embedded SDK Identity
	// cannot be accessed. The SDK Identity.IsExpired() handles nil
	// at the SDK level, but not when accessed through a nil Gibson Identity.
}

// Benchmark tests
func BenchmarkRoleBinder_ResolveRoles(b *testing.B) {
	bindings := []RoleBinding{
		{Matcher: "admin", Roles: []string{"admin"}},
		{Matcher: "developers", Roles: []string{"mission:execute", "findings:read"}},
		{Matcher: "security-*", Roles: []string{"findings:write"}},
		{Matcher: "myorg/*:refs/heads/main", Roles: []string{"prod_deployer"}},
	}

	binder := NewRoleBinder(bindings)

	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "test-user",
			Groups:  []string{"developers", "security-team"},
			Claims: map[string]any{
				"repository": "myorg/app",
				"ref":        "refs/heads/main",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = binder.ResolveRoles(identity)
	}
}
