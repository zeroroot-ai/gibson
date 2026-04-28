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

	// AddTenantScopeMembership adds the service account to a tenant scope with
	// the specified role. For Zitadel this corresponds to project membership.
	AddTenantScopeMembership(ctx context.Context, req AddMembershipRequest) error

	// DeleteServiceAccount permanently removes the service account and revokes
	// any active sessions. Returns ErrNotFound if the account does not exist.
	DeleteServiceAccount(ctx context.Context, accountID string) error

	// ListServiceAccounts returns service accounts in the given tenant scope,
	// with optional role filtering and pagination.
	ListServiceAccounts(ctx context.Context, req ListServiceAccountsRequest) (*ListServiceAccountsResponse, error)

	// Close releases any resources held by the client (HTTP connections, etc.).
	Close() error
}
