package auth

// crossTenantRoles is the set of role names that are permitted to operate
// across tenant boundaries. These are infrastructure roles whose privileges
// span all tenants.
//
// Only platform-operator (daemon) has cross-tenant access. The dashboard uses
// platform-service which forwards user context via x-gibson-user-id metadata
// and is NOT cross-tenant — it operates on behalf of a specific user's tenant.
//
// Normal user roles (owner, admin, operator, viewer) are intentionally absent.
var crossTenantRoles = map[string]struct{}{
	"platform-operator": {},
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
