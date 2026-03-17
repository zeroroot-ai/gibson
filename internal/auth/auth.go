package auth

import (
	"context"
	"time"
)

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
// Identity is immutable after creation and safe to pass across goroutines.
type Identity struct {
	// Subject is the unique identifier for the authenticated principal (sub claim).
	// This is typically a user ID, service account name, or workflow identifier.
	Subject string

	// Issuer is the OIDC issuer that validated this token.
	// Examples: "https://company.okta.com", "https://token.actions.githubusercontent.com"
	Issuer string

	// Email is the principal's email address if available.
	// Optional - may be empty for non-user identities (CI/CD, service accounts).
	Email string

	// Groups are the group memberships extracted from the token.
	// Used for role binding evaluation.
	Groups []string

	// Claims contains all extracted token claims as key-value pairs.
	// Includes standard OIDC claims and provider-specific claims.
	Claims map[string]any

	// Roles are the resolved Gibson role names after evaluating role bindings.
	// Examples: ["admin"], ["mission:execute", "findings:read"]
	Roles []string

	// Permissions are the computed permissions derived from roles.
	// Used for fine-grained authorization checks.
	Permissions []Permission

	// ExpiresAt is when the underlying token expires.
	// After this time, the identity should no longer be considered valid.
	ExpiresAt time.Time

	// AuthenticatedAt is when this identity was created (token validation time).
	AuthenticatedAt time.Time
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

// IsExpired returns true if the identity's token has expired.
func (i *Identity) IsExpired() bool {
	if i == nil {
		return true
	}
	return time.Now().After(i.ExpiresAt)
}
