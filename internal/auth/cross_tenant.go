package auth

// crossTenantRoles is the set of role names that are permitted to operate
// across tenant boundaries. These are service-account / infrastructure roles
// whose privileges span all tenants. Normal user roles (owner, admin,
// operator, viewer) are intentionally absent.
//
// Cross-tenant detection is handled by checking the caller's roles against
// this fixed list. Normal user roles (owner, admin, operator, viewer) are
// intentionally absent.
var crossTenantRoles = map[string]struct{}{
	"platform-operator": {},
	"provisioner":       {},
	"tool-executor":     {},
	"agent-executor":    {},
	"plugin-executor":   {},
}

// IsCrossTenantCaller returns true if any of the supplied role names is a
// known cross-tenant role. Cross-tenant callers (platform operators, service
// accounts) may target arbitrary tenant IDs in requests; tenant-scoped
// callers may only act on the tenant extracted from their token.
//
// Returns false on an empty slice (fail-closed: unknown callers are not
// granted cross-tenant privileges).
func IsCrossTenantCaller(roles []string) bool {
	for _, r := range roles {
		if _, ok := crossTenantRoles[r]; ok {
			return true
		}
	}
	return false
}
