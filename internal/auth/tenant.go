package auth

import (
	"context"
	"fmt"
	"strings"
)

// tenantContextKey is an unexported context key type for tenant isolation.
// Using an unexported type prevents collisions with context keys from other packages.
type tenantContextKey struct{}

// TenantFromContext extracts the tenant ID from the context.
//
// Returns an empty string if no tenant is present in the context.
// This function is safe to call with a nil context.
//
// Example:
//
//	tenant := auth.TenantFromContext(ctx)
//	if tenant == "" {
//	    // Handle missing tenant
//	}
func TenantFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	tenant, ok := ctx.Value(tenantContextKey{}).(string)
	if !ok {
		return ""
	}

	return tenant
}

// ContextWithTenant injects a tenant ID into the context.
//
// The tenant ID is stored using an unexported context key to prevent
// collisions with other context values.
//
// Example:
//
//	ctx = auth.ContextWithTenant(ctx, "acme-corp")
//	// Later...
//	tenant := auth.TenantFromContext(ctx)  // Returns "acme-corp"
func ContextWithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, tenant)
}

// ExtractTenantFromIdentity extracts the tenant ID from an identity's claims
// using the specified claim name.
//
// The claimName parameter supports dot notation for nested claims:
//   - "tenant_id" -> identity.Claims["tenant_id"]
//   - "org.id" -> identity.Claims["org"]["id"]
//   - "organization.tenant.id" -> identity.Claims["organization"]["tenant"]["id"]
//
// Returns an empty string if:
//   - identity is nil
//   - the claim does not exist
//   - the claim path is invalid
//   - the final value is not a string
//
// Example:
//
//	// Simple claim
//	tenant := ExtractTenantFromIdentity(identity, "tenant_id")
//
//	// Nested claim
//	tenant := ExtractTenantFromIdentity(identity, "org.id")
func ExtractTenantFromIdentity(identity *Identity, claimName string) string {
	if identity == nil || identity.Claims == nil {
		return ""
	}

	// Handle simple case (no dot notation)
	if !strings.Contains(claimName, ".") {
		return identity.GetStringClaim(claimName)
	}

	// Handle nested claims with dot notation
	parts := strings.Split(claimName, ".")
	var current any = identity.Claims

	for i, part := range parts {
		// Try to extract the next level
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}

		value, exists := m[part]
		if !exists {
			return ""
		}

		// Last part should be a string
		if i == len(parts)-1 {
			str, ok := value.(string)
			if !ok {
				return ""
			}
			return str
		}

		// Not the last part, continue traversing
		current = value
	}

	return ""
}

// TenantScopedRedisKey generates a tenant-scoped Redis key.
//
// The format is: tenant:{tenant}:{key}
//
// This ensures all Redis keys are isolated by tenant, preventing
// cross-tenant data access.
//
// Example:
//
//	key := TenantScopedRedisKey("acme", "mission:123")
//	// Returns: "tenant:acme:mission:123"
//
//	key := TenantScopedRedisKey("widgets-inc", "finding:abc-def")
//	// Returns: "tenant:widgets-inc:finding:abc-def"
func TenantScopedRedisKey(tenant, key string) string {
	return fmt.Sprintf("tenant:%s:%s", tenant, key)
}

// TenantNeo4jFilter generates a Neo4j WHERE clause filter for tenant isolation.
//
// The paramName parameter is the Cypher parameter name that will contain
// the tenant ID value.
//
// Returns a string in the format: "n.tenant_id = $paramName"
//
// Example:
//
//	filter := TenantNeo4jFilter("tenant")
//	// Returns: "n.tenant_id = $tenant"
//
//	// Used in Cypher query:
//	query := fmt.Sprintf("MATCH (n:Finding) WHERE %s RETURN n", filter)
//	params := map[string]any{"tenant": "acme"}
//	// Executes: MATCH (n:Finding) WHERE n.tenant_id = $tenant RETURN n
func TenantNeo4jFilter(paramName string) string {
	return fmt.Sprintf("n.tenant_id = $%s", paramName)
}
