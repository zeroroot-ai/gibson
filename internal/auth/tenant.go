package auth

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"google.golang.org/grpc/metadata"
)

// tenantContextKey is an unexported context key type for tenant isolation.
// Using an unexported type prevents collisions with context keys from other packages.
type tenantContextKey struct{}

// GibsonTenantHeader is the gRPC metadata key for the per-request tenant override.
// Dashboard middleware sets this header when the user has selected a specific tenant
// from the tenant picker. The daemon's TenantFromContext reads it to scope the request.
const GibsonTenantHeader = "x-gibson-tenant"

// TenantFromContext resolves the tenant for the current request using the following
// precedence (highest to lowest):
//
//  1. Explicit tenant already stored in context (set by auth interceptor or a
//     prior call to ContextWithTenant). Return immediately — no further work needed.
//
//  2. X-Gibson-Tenant gRPC metadata header from the dashboard:
//     - If the header is present AND the identity's Tenants list contains the
//       requested tenant → use it.
//     - If the header is present BUT the identity does NOT contain the tenant →
//       still return SystemTenant (the caller cannot spoof access; downstream
//       authz will deny them). A WARN is logged.
//
//  3. Identity.Tenants single-entry fast path:
//     - Exactly one tenant in Tenants → use it.
//
//  4. Identity.Tenants multi-entry fallback:
//     - Multiple tenants and no header → use the alphabetically-first one.
//       A WARN is logged so operators can see the ambiguity.
//
//  5. Cross-tenant role holders with empty Tenants → return SystemTenant.
//
//  6. All other cases → return SystemTenant.
//
// This function is safe to call with a nil context. It does NOT return an error;
// callers that need to enforce membership should call TenantFromContextWithCheck.
func TenantFromContext(ctx context.Context) string {
	tenant, _ := tenantFromContextInternal(ctx, nil)
	return tenant
}

// TenantFromContextWithCheck resolves the tenant for the current request (same
// precedence as TenantFromContext) but additionally returns an error when the
// X-Gibson-Tenant header requests a tenant that the identity is not a member of.
//
// Use this in the auth interceptor path where a PermissionDenied should be
// returned to the client rather than silently falling back to SystemTenant.
func TenantFromContextWithCheck(ctx context.Context, logger *slog.Logger) (string, error) {
	return tenantFromContextInternal(ctx, logger)
}

// tenantFromContextInternal is the shared implementation. When logger is nil,
// WARN messages are suppressed and membership-check failures return SystemTenant
// rather than an error (same as the old TenantFromContext contract).
func tenantFromContextInternal(ctx context.Context, logger *slog.Logger) (string, error) {
	if ctx == nil {
		return "", nil
	}

	// Step 1: explicit tenant already in context (fastest path).
	// Check key presence with two-value assertion so an explicitly stored
	// empty string is distinguishable from "key not present at all."
	// An explicitly stored empty string still skips subsequent steps (the
	// auth interceptor stores "" when it can't resolve a tenant, which
	// should fall through to the JWT-based resolution below).
	if rawTenant := ctx.Value(tenantContextKey{}); rawTenant != nil {
		if tenant, ok := rawTenant.(string); ok && tenant != "" {
			return tenant, nil
		}
	}

	// Retrieve identity for steps 2-5.
	identity, hasIdentity := GibsonIdentityFromContext(ctx)

	// Step 2: X-Gibson-Tenant header override.
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(GibsonTenantHeader); len(vals) > 0 && vals[0] != "" {
			requested := vals[0]

			if hasIdentity && identity != nil && len(identity.Tenants) > 0 {
				if containsString(identity.Tenants, requested) {
					return requested, nil
				}
				// User is requesting a tenant they are not a member of.
				if logger != nil {
					logger.Warn("tenant_access_denied: X-Gibson-Tenant not in identity.Tenants",
						"requested", requested,
						"tenants", identity.Tenants,
					)
					return SystemTenant, fmt.Errorf("tenant_not_member: %q is not in your organization list", requested)
				}
				// No logger → silent fallback for backward compat.
				return SystemTenant, nil
			}
			// Header present but identity has no Tenants (pre-migration user or
			// service account) — treat as a hint but do not enforce membership.
			return requested, nil
		}
	}

	if !hasIdentity || identity == nil {
		return SystemTenant, nil
	}

	// Step 3: single-tenant fast path.
	if len(identity.Tenants) == 1 {
		return identity.Tenants[0], nil
	}

	// Step 4: multi-tenant, no header — use alphabetically first.
	if len(identity.Tenants) > 1 {
		sorted := make([]string, len(identity.Tenants))
		copy(sorted, identity.Tenants)
		sort.Strings(sorted)
		if logger != nil {
			logger.Warn("tenant_ambiguous: user belongs to multiple tenants and no X-Gibson-Tenant header was sent; using alphabetically-first",
				"tenants", sorted,
				"selected", sorted[0],
			)
		}
		return sorted[0], nil
	}

	// Step 5: empty Tenants — cross-tenant role holders (platform operators,
	// provisioners) fall through to SystemTenant intentionally.
	return SystemTenant, nil
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

// containsString reports whether s is present in slice.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
