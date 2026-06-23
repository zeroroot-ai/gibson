package idp

import "time"

// UserProfile is a vendor-neutral representation of a human user's profile.
type UserProfile struct {
	// AccountID is the IdP-assigned unique identifier for the user.
	AccountID string

	// Email is the user's primary email address. Immutable via this interface.
	Email string

	// DisplayName is the user's preferred display name.
	DisplayName string

	// AvatarURL is the URL of the user's profile picture (may be empty).
	AvatarURL string

	// Status is the user's account status ("active", "suspended", etc.).
	Status string

	// CreatedAt is when the account was created.
	CreatedAt time.Time

	// PreferredLocale is the user's preferred UI locale (e.g., "en-US").
	PreferredLocale string
}

// UpdateUserProfileRequest carries the mutable profile fields to update.
// Zero values mean "no change"; only non-zero fields are applied.
type UpdateUserProfileRequest struct {
	// DisplayName is the new display name (empty = no change).
	DisplayName string

	// PreferredLocale is the new locale (empty = no change).
	PreferredLocale string
}

// Role identifies the functional role of a machine service account.
// These values are vendor-neutral and map to IdP-specific role/claim
// values in each provider implementation.
type Role string

const (
	// RoleAgent identifies an agent service account.
	RoleAgent Role = "agent"
	// RoleTool identifies a tool service account.
	RoleTool Role = "tool"
	// RolePlugin identifies a plugin service account.
	RolePlugin Role = "plugin"
)

// ServiceAccount is a vendor-neutral representation of a machine service account
// in the IdP. Fields that the IdP does not support are left at their zero values
// (LastAuthenticatedAt is nil if the IdP does not track it).
type ServiceAccount struct {
	// AccountID is the IdP-assigned unique identifier for the service account.
	AccountID string

	// Name is the display name of the service account.
	Name string

	// Role is the functional role of the service account.
	Role Role

	// CreatedAt is when the service account was created.
	CreatedAt time.Time

	// LastAuthenticatedAt is when the service account last obtained a token,
	// or nil if the IdP does not track authentication history or the account
	// has never authenticated.
	LastAuthenticatedAt *time.Time

	// Description is the optional human-readable description.
	Description string
}

// EnsureHumanUserRequest carries parameters for finding-or-creating a human
// user in the IdP organization that bounds a tenant.
type EnsureHumanUserRequest struct {
	// OrgID is the IdP organization id the user belongs to / is created in.
	OrgID string
	// Email is the user's email address (also the login name). Required.
	Email string
}

// CreateHumanUserRequest carries parameters for provisioning a password-bearing
// human user during self-serve signup. It mirrors the request the dashboard
// signup-bot previously sent (createHumanUser): a profile, a verified-at-create
// email, and a password the user just typed.
//
// SECURITY: Password is forwarded to the IdP request body only and is NEVER
// logged or included in error messages.
type CreateHumanUserRequest struct {
	// OrgID is the IdP organization id the user is created in. Empty selects
	// the admin client's default (platform) org — the founding-owner user is
	// provisioned in the platform org; per-tenant org membership is added later
	// by the operator once the tenant's org exists.
	OrgID string

	// Email is the user's email address (also the login name). Required.
	Email string

	// GivenName / FamilyName populate the human profile. May be empty.
	GivenName  string
	FamilyName string

	// Password is the initial password. Required. NEVER logged.
	Password string

	// EmailVerified marks the email verified at create-time. When true the IdP
	// keeps the user in an active (sign-in-capable) state and mints no
	// verification code; when false the user is left pending a verification
	// email. Mirrors the dashboard's emailVerified=true signup default.
	EmailVerified bool
}

// CreateHumanUserResult reports the outcome of CreateHumanUser.
type CreateHumanUserResult struct {
	// UserID is the IdP-assigned id of the (created or resumed) human user.
	UserID string

	// AlreadyExisted is true when a user with the email already existed and was
	// resumed (its password reset to the supplied value) rather than created.
	AlreadyExisted bool
}

// RevokeUserSessionsResult reports what RevokeUserSessions did. Counts are
// best-effort observability; callers must not treat zero as failure.
type RevokeUserSessionsResult struct {
	// SessionsTerminated is the number of active IdP sessions terminated.
	SessionsTerminated int
	// GrantsRevoked is the number of refresh-token grants revoked.
	GrantsRevoked int
}

// SessionInfo describes one active login session of a user, as reported by the
// IdP. Fields the IdP does not populate are left zero (empty string / zero
// time); a missing optional field must never fail the whole listing.
type SessionInfo struct {
	// ID is the IdP's session id — the handle RevokeSession takes.
	ID string
	// IP is the source IP recorded at session creation, if any.
	IP string
	// Browser is a human-readable client description (browser / OS / device).
	Browser string
	// CreatedAt is when the session was established.
	CreatedAt time.Time
	// LastActiveAt is when the session was last seen active, if reported.
	LastActiveAt time.Time
}

// TenantMembershipRequest carries parameters for adding or removing a human
// user's membership of the IdP organization that bounds a tenant.
type TenantMembershipRequest struct {
	// OrgID is the IdP organization id provisioned for the tenant. Required.
	OrgID string

	// UserID is the IdP-assigned id of the human user. Required.
	UserID string

	// Role is the neutral tenant role to grant on add ("owner", "admin",
	// "member"); unknown values map to "member". Unused on remove.
	Role string
}

// CreateServiceAccountRequest carries parameters for creating a new service account.
type CreateServiceAccountRequest struct {
	// Name is the pre-formatted service account name: "<kind>-<tenant>-<name>".
	// The caller (TenantAdminService handler) is responsible for constructing
	// this name before invoking the AdminClient.
	Name string

	// Description is the optional human-readable description.
	Description string

	// Role is the functional role of the service account.
	Role Role
}

// ListServiceAccountsRequest carries parameters for listing service accounts.
type ListServiceAccountsRequest struct {
	// TenantScopeID identifies the tenant's scope in the IdP.
	TenantScopeID string

	// PageSize is the maximum number of accounts to return. Zero means use the
	// implementation's default.
	PageSize int

	// PageToken is the pagination cursor from a previous response. Empty string
	// requests the first page.
	PageToken string

	// RoleFilter restricts the results to accounts with this role.
	// An empty string means return all roles.
	RoleFilter Role
}

// ListServiceAccountsResponse carries the results of a list operation.
type ListServiceAccountsResponse struct {
	// ServiceAccounts is the page of results.
	ServiceAccounts []ServiceAccount

	// NextPageToken is the cursor for the next page. An empty string means
	// there are no more results.
	NextPageToken string
}
