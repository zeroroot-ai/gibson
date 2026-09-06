// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	// the password the user chose so they can sign in immediately.
	//
	// CREATE-ONLY. If a user with the email already exists, implementations
	// MUST return ErrAlreadyExists and MUST NOT touch that user. Signup never
	// writes a credential onto an account it did not just create: the password
	// arrives from a form submission, which establishes nothing about who sent
	// it. Changing an existing account's password is the IdP reset flow's job,
	// and that flow proves mailbox control first.
	//
	// Used by SignupService.Signup, which only reaches this call after the
	// address has been verified.
	CreateHumanUser(ctx context.Context, req CreateHumanUserRequest) (CreateHumanUserResult, error)

	// SetHumanPassword sets a known password on an existing human user. Used by
	// the self-hosted first-admin bootstrap to activate the founding-owner
	// account the invitation flow created without a usable credential. Idempotence
	// is the caller's responsibility (bootstrap only calls this on first setup,
	// gated by the absence of the credential Secret).
	SetHumanPassword(ctx context.Context, req SetHumanPasswordRequest) error

	// FindUserIDByEmail returns the id of the human user with the given email,
	// or ErrNotFound when there is none. Read-only.
	//
	// Its one purpose is choosing which message to send to an address during
	// signup — a verification link, or a notice that an account already exists.
	// The result MUST NOT change any response the requester can observe: the
	// duplicate-address fact belongs to the mailbox that owns the address, not
	// to whoever typed it into a form.
	FindUserIDByEmail(ctx context.Context, email string) (userID string, err error)

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
