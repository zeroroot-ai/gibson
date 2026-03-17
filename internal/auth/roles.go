package auth

import (
	"strings"
)

// RoleBinder evaluates role bindings and computes permissions.
//
// Maps identity claims (groups, repository references) to Gibson roles.
// Supports wildcard patterns in binding matchers.
type RoleBinder struct {
	bindings []RoleBinding
}

// RoleBinding maps a claim value pattern to a list of roles.
//
// Matcher supports glob-style wildcards:
//   - "*" matches any sequence of characters
//   - "security-*" matches "security-team", "security-admins", etc.
//   - "myorg/*:refs/heads/main" matches any repo in myorg on main branch
type RoleBinding struct {
	// Matcher is the pattern to match against claim values.
	// Supports glob-style wildcards ("*").
	Matcher string

	// Roles are the Gibson roles to grant when the matcher matches.
	// Examples: ["admin"], ["mission:execute", "findings:read"]
	Roles []string
}

// NewRoleBinder creates a new role binder with the given bindings.
func NewRoleBinder(bindings []RoleBinding) *RoleBinder {
	return &RoleBinder{
		bindings: bindings,
	}
}

// NewRoleBinderFromConfig creates a role binder from issuer configuration.
//
// Converts the map-based configuration to RoleBinding structs.
func NewRoleBinderFromConfig(roleBindings map[string][]string) *RoleBinder {
	bindings := make([]RoleBinding, 0, len(roleBindings))
	for matcher, roles := range roleBindings {
		bindings = append(bindings, RoleBinding{
			Matcher: matcher,
			Roles:   roles,
		})
	}
	return &RoleBinder{bindings: bindings}
}

// ResolveRoles evaluates all role bindings against the identity's claims.
//
// Returns:
//   - roles: Unique list of resolved role names
//   - permissions: Computed permissions from roles
//   - error: If role resolution fails or no bindings match
//
// Checks claim values against bindings in order:
//  1. Groups (from groups claim)
//  2. Repository reference (for CI/CD tokens)
//  3. Individual claim values
func (b *RoleBinder) ResolveRoles(identity *Identity) ([]string, []Permission, error) {
	if identity == nil {
		return nil, nil, ErrNoRoleBindings()
	}

	rolesSet := make(map[string]bool) // Deduplicate roles

	// Check group-based bindings
	for _, group := range identity.Groups {
		for _, binding := range b.bindings {
			if b.matchPattern(binding.Matcher, group) {
				for _, role := range binding.Roles {
					rolesSet[role] = true
				}
			}
		}
	}

	// Check repository-based bindings for CI/CD tokens
	repoRef := b.extractRepoRef(identity)
	if repoRef != "" {
		for _, binding := range b.bindings {
			if b.matchPattern(binding.Matcher, repoRef) {
				for _, role := range binding.Roles {
					rolesSet[role] = true
				}
			}
		}
	}

	// Check other claim values (email, domain, etc.)
	for _, value := range identity.Claims {
		if strValue, ok := value.(string); ok {
			for _, binding := range b.bindings {
				if b.matchPattern(binding.Matcher, strValue) {
					for _, role := range binding.Roles {
						rolesSet[role] = true
					}
				}
			}
		}
	}

	// Convert set to slice
	roles := make([]string, 0, len(rolesSet))
	for role := range rolesSet {
		roles = append(roles, role)
	}

	if len(roles) == 0 {
		return nil, nil, ErrNoRoleBindings()
	}

	// Compute permissions from roles
	permissions := b.computePermissions(roles)

	return roles, permissions, nil
}

// matchPattern checks if a value matches a pattern with glob wildcards.
//
// Supports:
//   - Exact match: "security-team" matches "security-team"
//   - Prefix wildcard: "security-*" matches "security-team", "security-admins"
//   - Suffix wildcard: "*-admins" matches "security-admins", "platform-admins"
//   - Full wildcard: "*" matches anything
//   - Path wildcards: "myorg/*" matches "myorg/repo", "security/*:*" matches "security/scanner:refs/heads/main"
//
// Unlike filepath.Match, this treats "/" as a regular character, allowing wildcards to span path separators.
func (b *RoleBinder) matchPattern(pattern, value string) bool {
	// Try exact match first (fast path)
	if pattern == value {
		return true
	}

	// Handle wildcard matching
	return globMatch(pattern, value)
}

// globMatch implements simple glob matching with * wildcards.
// Unlike filepath.Match, this treats / as a regular character.
func globMatch(pattern, value string) bool {
	// Split pattern by '*'
	parts := strings.Split(pattern, "*")

	if len(parts) == 1 {
		// No wildcards - exact match only
		return pattern == value
	}

	// Check first part (prefix)
	if parts[0] != "" && !strings.HasPrefix(value, parts[0]) {
		return false
	}

	// Check last part (suffix)
	if parts[len(parts)-1] != "" && !strings.HasSuffix(value, parts[len(parts)-1]) {
		return false
	}

	// Check middle parts appear in order
	pos := len(parts[0])
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue
		}
		idx := strings.Index(value[pos:], parts[i])
		if idx == -1 {
			return false
		}
		pos += idx + len(parts[i])
	}

	return true
}

// extractRepoRef extracts repository reference from identity claims.
//
// For GitHub Actions: "myorg/repo:refs/heads/main"
// For GitLab CI: "myorg/project:main"
func (b *RoleBinder) extractRepoRef(identity *Identity) string {
	// Try GitHub Actions format
	if repo, ok := identity.Claims["repository"].(string); ok {
		if ref, ok := identity.Claims["ref"].(string); ok {
			return repo + ":" + ref
		}
	}

	// Try GitLab CI format
	if project, ok := identity.Claims["project_path"].(string); ok {
		if ref, ok := identity.Claims["ref"].(string); ok {
			return project + ":" + ref
		}
	}

	return ""
}

// computePermissions derives Permission structs from role names.
//
// Role name format: "resource:action" or special roles:
//   - "admin" grants all permissions ("*:*")
//   - "mission:execute" grants execute on missions
//   - "findings:read" grants read on findings
//   - "findings:*" grants all actions on findings
//
// Returns a list of Permission structs.
func (b *RoleBinder) computePermissions(roles []string) []Permission {
	var permissions []Permission

	for _, role := range roles {
		// Special case: admin role grants everything
		if role == "admin" {
			permissions = append(permissions, Permission{
				Action:   "*",
				Resource: "*",
				Scope:    "*",
			})
			continue
		}

		// Parse role format: "resource:action" or "resource:action:scope"
		parts := strings.Split(role, ":")
		if len(parts) >= 2 {
			resource := parts[0]
			action := parts[1]
			scope := "*"
			if len(parts) >= 3 {
				scope = parts[2]
			}

			permissions = append(permissions, Permission{
				Action:   action,
				Resource: resource,
				Scope:    scope,
			})
		}
	}

	return permissions
}

// HasPermission checks if roles grant a specific permission.
//
// Checks computed permissions for matching action/resource.
// Supports wildcard matching in permissions.
func (b *RoleBinder) HasPermission(roles []string, action, resource string) bool {
	permissions := b.computePermissions(roles)

	for _, perm := range permissions {
		// Check action match (exact or wildcard)
		actionMatch := perm.Action == action || perm.Action == "*"

		// Check resource match (exact or wildcard)
		resourceMatch := perm.Resource == resource || perm.Resource == "*"

		if actionMatch && resourceMatch {
			return true
		}
	}

	return false
}
