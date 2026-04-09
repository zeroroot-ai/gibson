// Package membership provides types for user-to-tenant membership records.
//
// Membership is managed through Keycloak Organizations (identity plane)
// and OpenFGA (authorization plane). This package retains the domain types
// and interface that server.go uses for the legacy membership RPCs while those
// handlers are migrated to FGA-based lookups.
//
// The MembershipStore interface is kept so that server.go can gate those RPCs
// on a nil check (returning codes.Unavailable) until proper FGA-backed
// implementations replace them.
package membership

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors returned by MembershipStore operations.
var (
	ErrMemberNotFound    = errors.New("member not found in tenant")
	ErrAlreadyMember     = errors.New("user is already a member of this tenant")
	ErrInvalidRole       = errors.New("invalid role")
	ErrRoleHierarchy     = errors.New("cannot assign role higher than your own")
	ErrNotOwner          = errors.New("only the owner can perform this action")
	ErrCannotRemoveOwner = errors.New("cannot remove the tenant owner")
)

// Membership records a single user's membership in a tenant, including the role
// they hold and audit fields.
type Membership struct {
	TenantID string    `json:"tenant_id"`
	UserID   string    `json:"user_id"`
	Email    string    `json:"email"`
	Role     string    `json:"role"` // one of: owner, admin, operator, viewer
	AddedAt  time.Time `json:"added_at"`
	AddedBy  string    `json:"added_by"`
}

// roleLevels maps each role name to a numeric privilege level.
// Lower numbers represent higher privilege — owner(0) outranks admin(1), etc.
var roleLevels = map[string]int{
	"owner":    0,
	"admin":    1,
	"operator": 2,
	"viewer":   3,
}

// RoleLevel returns the numeric privilege level for a role name.
// Returns -1 for any unrecognised role name.
func RoleLevel(role string) int {
	if level, ok := roleLevels[role]; ok {
		return level
	}
	return -1
}

// IsValidRole reports whether role is one of the four recognised role names.
func IsValidRole(role string) bool {
	return RoleLevel(role) >= 0
}

// CanAssignRole reports whether a user holding assignerRole is permitted to
// grant targetRole to another user.
func CanAssignRole(assignerRole, targetRole string) bool {
	a, t := RoleLevel(assignerRole), RoleLevel(targetRole)
	if a < 0 || t < 0 {
		return false
	}
	return a <= t
}

// MembershipStore is the domain interface for managing user-to-tenant membership.
// Implementations backed by Redis have been removed; this interface is kept for
// server.go RPC handlers that check for nil and return codes.Unavailable.
type MembershipStore interface {
	AddMember(ctx context.Context, tenantID, userID, email, role, addedBy string) error
	RemoveMember(ctx context.Context, tenantID, userID string) error
	UpdateRole(ctx context.Context, tenantID, userID, newRole, changedBy string) error
	GetMember(ctx context.Context, tenantID, userID string) (*Membership, error)
	ListTenantMembers(ctx context.Context, tenantID string) ([]Membership, error)
	ListUserTenants(ctx context.Context, userID string) ([]Membership, error)
	TransferOwnership(ctx context.Context, tenantID, fromUserID, toUserID, changedBy string) error
}
