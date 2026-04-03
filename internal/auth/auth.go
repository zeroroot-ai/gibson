package auth

import (
	"context"

	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// gibsonIdentityKey is the context key for storing the full Gibson Identity.
// This is separate from the SDK Identity key to preserve Roles and Permissions.
type gibsonIdentityKey struct{}

// gibsonIdentityCtxKey is the singleton context key for Gibson Identity.
var gibsonIdentityCtxKey = gibsonIdentityKey{}

// Authenticator validates tokens and returns identity information.
//
// This interface abstracts the authentication mechanism to support
// multiple authentication strategies (OIDC, K8s TokenReview, static tokens).
//
// Implementations must be safe for concurrent use.
type Authenticator interface {
	// Authenticate validates a token and returns the authenticated identity.
	//
	// Returns an error if:
	//   - The token is malformed or expired
	//   - The token signature is invalid
	//   - The issuer is not trusted
	//   - The token audience doesn't match configuration
	//
	// The returned Identity contains the subject, issuer, claims, and
	// resolved roles/permissions.
	Authenticate(ctx context.Context, token string) (*Identity, error)
}

// Identity represents an authenticated principal with their claims and permissions.
//
// This extends the SDK Identity type with Gibson-specific authorization fields.
// The SDK Identity contains the base authentication information (subject, issuer,
// groups, claims, expiry), while Gibson adds resolved roles, permissions, and
// Casbin-backed capability grants.
//
// Identity is immutable after creation and safe to pass across goroutines.
type Identity struct {
	// Embed SDK Identity for base authentication fields
	// This provides: Subject, Issuer, Email, Groups, Claims, ExpiresAt, AuthenticatedAt
	sdkauth.Identity

	// Roles are the resolved Gibson role names after evaluating role bindings.
	// Examples: ["admin"], ["mission:execute", "findings:read"]
	// These are computed from Groups using role binding configuration.
	Roles []string

	// Permissions are the computed permissions derived from roles.
	// Used for fine-grained authorization checks.
	// These are computed from Roles using permission mapping.
	Permissions []Permission

	// Capabilities are the Casbin resource:action grants assigned to this identity.
	// For API keys these are sourced from the APIKeyRecord.Capabilities field.
	// An empty slice should be treated as ["*"] (unrestricted) by callers; the
	// APIKeyAuthenticator normalises this on every Authenticate call so that
	// legacy keys created before capability support was added retain full access.
	//
	// Examples: ["graphrag:write", "plugin:gitlab:read", "missions:execute", "*"]
	Capabilities []string
}

// Permission represents a fine-grained authorization grant.
//
// Permissions are derived from roles and define what actions
// an identity can perform on which resources.
type Permission struct {
	// Action is the permitted action.
	// Examples: "execute", "read", "write", "delete", "admin", "*"
	Action string

	// Resource is the resource type this permission applies to.
	// Examples: "mission", "finding", "agent", "tool", "plugin", "*"
	Resource string

	// Scope constrains the permission to specific resource instances.
	// Examples: "myorg/*" (all in org), "prod-*" (prod resources), "*" (all)
	Scope string
}

// HasPermission checks if the identity has a specific permission.
//
// Supports wildcard matching:
//   - Action "*" matches any action
//   - Resource "*" matches any resource
//   - Scope "*" matches any scope
//
// Returns true if any permission in the identity matches the request.
func (i *Identity) HasPermission(action, resource string) bool {
	if i == nil {
		return false
	}

	for _, perm := range i.Permissions {
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

// HasCapability reports whether the identity holds the named capability.
//
// Returns true if cap is present in i.Capabilities, or if the wildcard
// capability "*" is present (granting unrestricted access).
// A nil Identity always returns false.
func (i *Identity) HasCapability(cap string) bool {
	if i == nil {
		return false
	}
	for _, c := range i.Capabilities {
		if c == "*" || c == cap {
			return true
		}
	}
	return false
}

// HasRole checks if the identity has a specific role.
//
// Role names are case-sensitive exact matches.
func (i *Identity) HasRole(role string) bool {
	if i == nil {
		return false
	}

	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}

	return false
}

// ContextWithIdentity stores a Gibson Identity in the context.
//
// This stores BOTH the full Gibson Identity (with Roles/Permissions) AND
// the SDK Identity (for SDK compatibility). Use GibsonIdentityFromContext
// to retrieve the full identity with authorization data.
//
// Use IdentityFromContext for SDK Identity only (backward compatibility).
// Use GibsonIdentityFromContext for full identity with Roles/Permissions.
func ContextWithIdentity(ctx context.Context, identity *Identity) context.Context {
	if identity == nil {
		return ctx
	}
	// Store the full Gibson Identity for authorization checks
	ctx = context.WithValue(ctx, gibsonIdentityCtxKey, identity)
	// Also store the SDK Identity for SDK compatibility
	ctx = sdkauth.ContextWithIdentity(ctx, &identity.Identity)
	return ctx
}

// IdentityFromContext retrieves the SDK Identity from the context.
//
// Returns the SDK Identity and true if present, or nil and false if not.
// Note: This returns the SDK Identity, not the Gibson Identity with roles/permissions.
// For Gibson-specific authorization checks (roles, permissions), use GibsonIdentityFromContext.
func IdentityFromContext(ctx context.Context) (*sdkauth.Identity, bool) {
	return sdkauth.IdentityFromContext(ctx)
}

// GibsonIdentityFromContext retrieves the full Gibson Identity from the context.
//
// Returns the Gibson Identity with Roles and Permissions, and true if present.
// Returns nil and false if no identity is present.
//
// Use this function when you need to check roles or permissions:
//
//	identity, ok := auth.GibsonIdentityFromContext(ctx)
//	if ok && identity.HasRole("admin") {
//	    // allow admin action
//	}
func GibsonIdentityFromContext(ctx context.Context) (*Identity, bool) {
	if identity, ok := ctx.Value(gibsonIdentityCtxKey).(*Identity); ok {
		return identity, true
	}
	return nil, false
}
