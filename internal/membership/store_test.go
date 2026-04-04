package membership

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore starts an in-process miniredis instance and returns a
// RedisMembershipStore wired to it. Cleanup is registered automatically.
func newTestStore(t *testing.T) *RedisMembershipStore {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // suppress noise during tests
	}))

	return NewRedisMembershipStore(client, logger)
}

// ---- AddMember / GetMember ----

// TestAddMember_RoundTrip verifies that a member can be added and retrieved with
// all fields intact.
func TestAddMember_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "admin", "signup")
	require.NoError(t, err)

	m, err := s.GetMember(ctx, "acme", "user-1")
	require.NoError(t, err)

	assert.Equal(t, "acme", m.TenantID)
	assert.Equal(t, "user-1", m.UserID)
	assert.Equal(t, "alice@acme.com", m.Email)
	assert.Equal(t, "admin", m.Role)
	assert.Equal(t, "signup", m.AddedBy)
	assert.False(t, m.AddedAt.IsZero(), "AddedAt must be set")
}

// TestAddMember_Duplicate verifies that adding the same user twice returns
// ErrAlreadyMember on the second call.
func TestAddMember_Duplicate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "viewer", "signup"))

	err := s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "viewer", "signup")
	require.ErrorIs(t, err, ErrAlreadyMember)
}

// TestAddMember_InvalidRole verifies that an unrecognised role string is rejected
// with ErrInvalidRole before any Redis writes occur.
func TestAddMember_InvalidRole(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "superuser", "signup")
	require.ErrorIs(t, err, ErrInvalidRole)
}

// ---- RemoveMember ----

// TestRemoveMember_Works verifies that a non-owner member can be removed and
// subsequent GetMember returns ErrMemberNotFound.
func TestRemoveMember_Works(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "operator", "signup"))
	require.NoError(t, s.RemoveMember(ctx, "acme", "user-1"))

	_, err := s.GetMember(ctx, "acme", "user-1")
	require.ErrorIs(t, err, ErrMemberNotFound)
}

// TestRemoveMember_OwnerRejected verifies that attempting to remove the owner
// returns ErrCannotRemoveOwner.
func TestRemoveMember_OwnerRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "owner-1", "owner@acme.com", "owner", "signup"))

	err := s.RemoveMember(ctx, "acme", "owner-1")
	require.ErrorIs(t, err, ErrCannotRemoveOwner)
}

// TestRemoveMember_NotFound verifies that removing a user who was never added
// returns ErrMemberNotFound.
func TestRemoveMember_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.RemoveMember(ctx, "acme", "ghost-user")
	require.ErrorIs(t, err, ErrMemberNotFound)
}

// TestRemoveMember_ReverseIndexCleaned verifies that removing a member also
// removes the tenant from the user's reverse-index SET, so ListUserTenants no
// longer returns that tenant.
func TestRemoveMember_ReverseIndexCleaned(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "viewer", "signup"))
	require.NoError(t, s.RemoveMember(ctx, "acme", "user-1"))

	tenants, err := s.ListUserTenants(ctx, "user-1")
	require.NoError(t, err)
	assert.Empty(t, tenants, "user-tenants index must be cleaned after removal")
}

// ---- UpdateRole ----

// TestUpdateRole_Works verifies that the role of an existing member can be
// changed and the new value is persisted.
func TestUpdateRole_Works(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "viewer", "signup"))
	require.NoError(t, s.UpdateRole(ctx, "acme", "user-1", "operator", "admin-1"))

	m, err := s.GetMember(ctx, "acme", "user-1")
	require.NoError(t, err)
	assert.Equal(t, "operator", m.Role)
}

// TestUpdateRole_InvalidRole verifies that UpdateRole rejects an unrecognised
// role name with ErrInvalidRole.
func TestUpdateRole_InvalidRole(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "viewer", "signup"))

	err := s.UpdateRole(ctx, "acme", "user-1", "god", "admin-1")
	require.ErrorIs(t, err, ErrInvalidRole)
}

// TestUpdateRole_NotFound verifies that updating a non-existent member returns
// ErrMemberNotFound.
func TestUpdateRole_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.UpdateRole(ctx, "acme", "ghost", "admin", "admin-1")
	require.ErrorIs(t, err, ErrMemberNotFound)
}

// ---- ListTenantMembers ----

// TestListTenantMembers_ReturnsAll verifies that ListTenantMembers returns every
// member that was added to a tenant.
func TestListTenantMembers_ReturnsAll(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "owner", "signup"))
	require.NoError(t, s.AddMember(ctx, "acme", "user-2", "bob@acme.com", "admin", "user-1"))
	require.NoError(t, s.AddMember(ctx, "acme", "user-3", "carol@acme.com", "viewer", "user-1"))

	// Add a member in a different tenant — must not appear.
	require.NoError(t, s.AddMember(ctx, "other-corp", "user-4", "dave@other.com", "owner", "signup"))

	members, err := s.ListTenantMembers(ctx, "acme")
	require.NoError(t, err)
	assert.Len(t, members, 3)

	userIDs := make(map[string]string, len(members))
	for _, m := range members {
		userIDs[m.UserID] = m.Role
	}

	assert.Equal(t, "owner", userIDs["user-1"])
	assert.Equal(t, "admin", userIDs["user-2"])
	assert.Equal(t, "viewer", userIDs["user-3"])
	assert.NotContains(t, userIDs, "user-4", "member from other tenant must not appear")
}

// TestListTenantMembers_EmptyTenant verifies that listing an empty tenant returns
// an empty slice rather than an error.
func TestListTenantMembers_EmptyTenant(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	members, err := s.ListTenantMembers(ctx, "empty-tenant")
	require.NoError(t, err)
	assert.Empty(t, members)
}

// ---- ListUserTenants ----

// TestListUserTenants_ReturnsAll verifies that ListUserTenants returns all tenants
// a user belongs to and the correct role for each.
func TestListUserTenants_ReturnsAll(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "user-1", "alice@acme.com", "owner", "signup"))
	require.NoError(t, s.AddMember(ctx, "corp-b", "user-1", "alice@corp-b.com", "admin", "invite"))
	require.NoError(t, s.AddMember(ctx, "corp-c", "user-1", "alice@corp-c.com", "viewer", "invite"))

	tenants, err := s.ListUserTenants(ctx, "user-1")
	require.NoError(t, err)
	assert.Len(t, tenants, 3)

	byTenant := make(map[string]string, len(tenants))
	for _, m := range tenants {
		byTenant[m.TenantID] = m.Role
	}

	assert.Equal(t, "owner", byTenant["acme"])
	assert.Equal(t, "admin", byTenant["corp-b"])
	assert.Equal(t, "viewer", byTenant["corp-c"])
}

// TestListUserTenants_NoTenants verifies that a user with no memberships returns
// an empty slice rather than an error.
func TestListUserTenants_NoTenants(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	tenants, err := s.ListUserTenants(ctx, "unknown-user")
	require.NoError(t, err)
	assert.Empty(t, tenants)
}

// ---- TransferOwnership ----

// TestTransferOwnership_Works verifies the full transfer: old owner becomes admin
// and the new user becomes owner.
func TestTransferOwnership_Works(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "owner-1", "owner@acme.com", "owner", "signup"))
	require.NoError(t, s.AddMember(ctx, "acme", "user-2", "bob@acme.com", "admin", "owner-1"))

	require.NoError(t, s.TransferOwnership(ctx, "acme", "owner-1", "user-2", "owner-1"))

	// Old owner is now admin.
	oldOwner, err := s.GetMember(ctx, "acme", "owner-1")
	require.NoError(t, err)
	assert.Equal(t, "admin", oldOwner.Role)

	// New owner now holds owner role.
	newOwner, err := s.GetMember(ctx, "acme", "user-2")
	require.NoError(t, err)
	assert.Equal(t, "owner", newOwner.Role)
}

// TestTransferOwnership_FromNotOwner verifies that the transfer fails with
// ErrNotOwner when the from-user is not the current owner.
func TestTransferOwnership_FromNotOwner(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "owner-1", "owner@acme.com", "owner", "signup"))
	require.NoError(t, s.AddMember(ctx, "acme", "admin-1", "admin@acme.com", "admin", "owner-1"))
	require.NoError(t, s.AddMember(ctx, "acme", "user-3", "bob@acme.com", "viewer", "owner-1"))

	err := s.TransferOwnership(ctx, "acme", "admin-1", "user-3", "admin-1")
	require.ErrorIs(t, err, ErrNotOwner)
}

// TestTransferOwnership_ToUserNotMember verifies that the transfer fails with
// ErrMemberNotFound when the target user is not a member of the tenant.
func TestTransferOwnership_ToUserNotMember(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.AddMember(ctx, "acme", "owner-1", "owner@acme.com", "owner", "signup"))

	err := s.TransferOwnership(ctx, "acme", "owner-1", "ghost-user", "owner-1")
	require.ErrorIs(t, err, ErrMemberNotFound)
}

// ---- Role helpers ----

// TestRoleLevel verifies that role names map to the expected numeric levels and
// that an unknown role returns -1.
func TestRoleLevel(t *testing.T) {
	tests := []struct {
		role  string
		level int
	}{
		{"owner", 0},
		{"admin", 1},
		{"operator", 2},
		{"viewer", 3},
		{"unknown", -1},
		{"", -1},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			assert.Equal(t, tt.level, RoleLevel(tt.role))
		})
	}
}

// TestIsValidRole verifies that IsValidRole returns true for known roles and
// false for anything else.
func TestIsValidRole(t *testing.T) {
	for _, role := range []string{"owner", "admin", "operator", "viewer"} {
		assert.True(t, IsValidRole(role), "expected %q to be valid", role)
	}
	for _, role := range []string{"superuser", "root", "", "OWNER"} {
		assert.False(t, IsValidRole(role), "expected %q to be invalid", role)
	}
}

// TestCanAssignRole verifies the full matrix of assigner → target role combinations.
func TestCanAssignRole(t *testing.T) {
	tests := []struct {
		assigner string
		target   string
		allowed  bool
	}{
		// Owner can assign anything.
		{"owner", "owner", true},
		{"owner", "admin", true},
		{"owner", "operator", true},
		{"owner", "viewer", true},
		// Admin cannot assign owner, can assign admin or below.
		{"admin", "owner", false},
		{"admin", "admin", true},
		{"admin", "operator", true},
		{"admin", "viewer", true},
		// Operator cannot assign owner/admin, can assign operator/viewer.
		{"operator", "owner", false},
		{"operator", "admin", false},
		{"operator", "operator", true},
		{"operator", "viewer", true},
		// Viewer can only assign viewer.
		{"viewer", "owner", false},
		{"viewer", "admin", false},
		{"viewer", "operator", false},
		{"viewer", "viewer", true},
		// Unknown roles.
		{"unknown", "viewer", false},
		{"owner", "unknown", false},
	}

	for _, tt := range tests {
		name := tt.assigner + "→" + tt.target
		t.Run(name, func(t *testing.T) {
			got := CanAssignRole(tt.assigner, tt.target)
			assert.Equal(t, tt.allowed, got,
				"CanAssignRole(%q, %q) = %v, want %v",
				tt.assigner, tt.target, got, tt.allowed,
			)
		})
	}
}
