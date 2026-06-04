// Package idp provides a vendor-neutral identity provider abstraction for
// the Gibson daemon. All daemon code that needs to provision agent identities
// or manage service accounts programs against this interface.
//
// The sole current concrete implementation lives in internal/idp/zitadel/.
// Changing the configured IdP requires only swapping the implementation behind
// this interface — no daemon, SDK, or dashboard code changes are needed.
//
// The word "zitadel" (or any other IdP product name) MUST NOT appear anywhere
// in this package or in any other package outside internal/idp/zitadel/.
package idp

import "context"

// AdminClient is the vendor-neutral interface for IdP admin operations
// required by agent identity provisioning.
//
// Implementations MUST be safe for concurrent use from multiple goroutines.
// The constructor for each implementation performs a startup-probe to verify
// connectivity; if the probe fails the daemon refuses to start.
type AdminClient interface {
	// CreateServiceAccount creates a new machine service account in the IdP.
	// Returns ErrAlreadyExists if an account with the same name already exists.
	CreateServiceAccount(ctx context.Context, req CreateServiceAccountRequest) (*ServiceAccount, error)

	// MintClientSecret generates a new client secret for an existing service account.
	// The returned string is the raw secret; it is the caller's responsibility to
	// handle it securely and never log it.
	MintClientSecret(ctx context.Context, accountID string) (clientSecret string, err error)

	// DeleteServiceAccount permanently removes the service account and revokes
	// any active sessions. Returns ErrNotFound if the account does not exist.
	DeleteServiceAccount(ctx context.Context, accountID string) error

	// ListServiceAccounts returns service accounts in the given tenant scope,
	// with optional role filtering and pagination.
	ListServiceAccounts(ctx context.Context, req ListServiceAccountsRequest) (*ListServiceAccountsResponse, error)

	// GetUserProfile retrieves a human user's profile from the IdP.
	// Returns ErrNotFound if the user does not exist.
	GetUserProfile(ctx context.Context, accountID string) (*UserProfile, error)

	// UpdateUserProfile updates mutable profile fields for a human user.
	// Only display_name and preferred_locale are editable; email is immutable.
	UpdateUserProfile(ctx context.Context, accountID string, req UpdateUserProfileRequest) (*UserProfile, error)

	// AddTenantMember adds (or re-affirms) the human user as a member of the
	// IdP organization that bounds a tenant, with the given role. Idempotent:
	// an already-present membership is treated as success (no error).
	AddTenantMember(ctx context.Context, req TenantMembershipRequest) error

	// RemoveTenantMember removes the human user from the IdP organization that
	// bounds a tenant. Idempotent: a missing membership is treated as success.
	RemoveTenantMember(ctx context.Context, req TenantMembershipRequest) error

	// EnsureHumanUser finds the human user with the given email in the IdP
	// organization, or creates one (triggering the IdP's verification /
	// credential-setup email). Returns the user id. Idempotent: an existing
	// user is found and returned rather than duplicated. Used by
	// MembershipService.AcceptInvitation to provision an invited member.
	EnsureHumanUser(ctx context.Context, req EnsureHumanUserRequest) (userID string, err error)

	// RevokeUserSessions terminates the user's active IdP sessions and revokes
	// their refresh-token grants. This blocks issuance of NEW tokens
	// immediately; any already-issued stateless access token remains valid
	// until it expires (the access-token TTL bounds the worst-case window —
	// gibson#622 v1 model). Idempotent: a user with no active sessions returns
	// zero counts, not an error.
	RevokeUserSessions(ctx context.Context, userID string) (RevokeUserSessionsResult, error)

	// Close releases any resources held by the client (HTTP connections, etc.).
	Close() error
}
