// Package idp provides a vendor-neutral identity provider abstraction for
// the Gibson daemon. All daemon code that needs to provision agent identities
// or manage service accounts programs against this interface.
//
// The sole current concrete implementation lives in internal/platform/idp/zitadel/.
// Changing the configured IdP requires only swapping the implementation behind
// this interface — no daemon, SDK, or dashboard code changes are needed.
//
// The word "zitadel" (or any other IdP product name) MUST NOT appear anywhere
// in this package or in any other package outside internal/platform/idp/zitadel/.
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
	//
	// Machine principals (agent/tool/plugin) authenticate at runtime via a
	// capability-grant JWT, NOT an OAuth client_credentials grant — the service
	// account exists only to anchor the canonical numeric sub. The IdP therefore
	// mints no client secret (ADR-0045, gibson#670/#673).
	CreateServiceAccount(ctx context.Context, req CreateServiceAccountRequest) (*ServiceAccount, error)

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

	// CreateHumanUser provisions a password-bearing founding-owner human user
	// during self-serve signup. Unlike EnsureHumanUser (invitation flow, no
	// password — the invitee sets credentials via the emailed code), this sets
	// the password the user typed at signup so they can sign in immediately.
	//
	// Idempotent on email: if the user already exists, the password is reset to
	// the supplied value (resume path) and AlreadyExisted is true. This mirrors
	// the dashboard signup-bot's createOrResumeZitadelUser behaviour so a retry
	// after a partial first attempt does not strand the founding owner with a
	// stale password. Used by SignupService.Signup (gibson#812).
	CreateHumanUser(ctx context.Context, req CreateHumanUserRequest) (CreateHumanUserResult, error)

	// SetUserPassword sets a human user's password without requiring the old
	// one (admin reset). Used by the signup resume path. NEVER logs the value.
	SetUserPassword(ctx context.Context, userID, password string) error

	// SendVerificationEmail triggers (re-sends) the IdP's email-verification
	// flow for a human user. Best-effort for callers: in environments without
	// SMTP wired, or for a user created already-verified (no pending code), the
	// IdP rejects the resend; callers treat that as non-fatal. Used by
	// SignupService.Signup to mirror the dashboard's post-create verify step.
	SendVerificationEmail(ctx context.Context, userID string) error

	// RevokeUserSessions terminates the user's active IdP sessions and revokes
	// their refresh-token grants. This blocks issuance of NEW tokens
	// immediately; any already-issued stateless access token remains valid
	// until it expires (the access-token TTL bounds the worst-case window —
	// gibson#622 v1 model). Idempotent: a user with no active sessions returns
	// zero counts, not an error.
	RevokeUserSessions(ctx context.Context, userID string) (RevokeUserSessionsResult, error)

	// ListUserSessions returns the user's active IdP login sessions with the
	// metadata the IdP records (source IP, client/browser description, created
	// and last-active timestamps). Used by self-service session management
	// (UserService.ListMySessions). A user with no active sessions returns an
	// empty slice, not an error. Fields the IdP omits are left zero.
	ListUserSessions(ctx context.Context, userID string) ([]SessionInfo, error)

	// RevokeSession terminates a single IdP session by id, invalidating the
	// refresh tokens bound to it. Idempotent: terminating an already-gone
	// session is not an error. Callers are responsible for confirming the
	// session belongs to the acting principal before calling.
	RevokeSession(ctx context.Context, sessionID string) error

	// Close releases any resources held by the client (HTTP connections, etc.).
	Close() error
}
