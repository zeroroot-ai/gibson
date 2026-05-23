// Tests for the ListMyMemberships handler. Exercises identity validation,
// FGA wiring, the role lookup via BatchCheck, the tenant-name resolver
// fallback, and the stable-sort behavior of the response.
//
// Task 1.3 (spec: tenant-role-taxonomy) added:
//   - pickHighestRole table test
//   - Four new cases for owner-only / admin-only / member-only / over-permissioned

package api

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/authz"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// stubAuthorizer is a minimal Authorizer fake for the membership tests.
// Only ListObjects + BatchCheck are exercised; the other methods panic if
// touched, so the test surface is explicit.
type stubAuthorizer struct {
	listObjects func(ctx context.Context, user, relation, objectType string) ([]string, error)
	batchCheck  func(ctx context.Context, checks []authz.CheckRequest) ([]bool, error)
}

func (s *stubAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) { return false, nil }
func (s *stubAuthorizer) BatchCheck(ctx context.Context, checks []authz.CheckRequest) ([]bool, error) {
	if s.batchCheck != nil {
		return s.batchCheck(ctx, checks)
	}
	return make([]bool, len(checks)), nil
}
func (s *stubAuthorizer) Write(_ context.Context, _ []authz.Tuple) error  { return nil }
func (s *stubAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (s *stubAuthorizer) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	if s.listObjects != nil {
		return s.listObjects(ctx, user, relation, objectType)
	}
	return nil, nil
}
func (s *stubAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubAuthorizer) StoreID() string { return "" }
func (s *stubAuthorizer) ModelID() string { return "" }
func (s *stubAuthorizer) Close() error    { return nil }

// ctxWithSubject installs a verified Identity carrying sub into the context
// the way auth.UnaryServerInterceptor would in production.
func ctxWithSubject(t *testing.T, sub string) context.Context {
	t.Helper()
	id := auth.Identity{Subject: sub}
	return auth.WithIdentity(context.Background(), id)
}

// ctxNoIdentity returns a context with no installed Identity, simulating a
// caller that bypassed the interceptor (e.g. headers stripped at the edge).
func ctxNoIdentity() context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.New(nil))
}

func newServerForMembershipTest() *DaemonServer {
	return &DaemonServer{logger: slog.Default()}
}

// ---------------------------------------------------------------------------
// pickHighestRole table test (spec: tenant-role-taxonomy Req 2.1–2.3)
// ---------------------------------------------------------------------------

func TestPickHighestRole(t *testing.T) {
	tests := []struct {
		name    string
		isOwner bool
		isAdmin bool
		want    string
	}{
		{name: "owner_only", isOwner: true, isAdmin: false, want: "owner"},
		{name: "admin_only", isOwner: false, isAdmin: true, want: "admin"},
		{name: "member_only", isOwner: false, isAdmin: false, want: "member"},
		// Over-permissioned: both owner and admin true (FGA computed union can
		// produce this). Owner wins.
		{name: "owner_and_admin", isOwner: true, isAdmin: true, want: "owner"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickHighestRole(tt.isOwner, tt.isAdmin)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Existing handler tests (updated for 2*N BatchCheck layout)
// ---------------------------------------------------------------------------

func TestListMyMemberships_Unauthenticated(t *testing.T) {
	s := newServerForMembershipTest()
	_, err := s.ListMyMemberships(ctxNoIdentity(), &daemonpb.ListMyMembershipsRequest{})
	require.Error(t, err)
	st, ok := status_grpc.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestListMyMemberships_NoAuthorizer_ReturnsEmpty(t *testing.T) {
	s := newServerForMembershipTest()
	resp, err := s.ListMyMemberships(ctxWithSubject(t, "user-uuid-1"), &daemonpb.ListMyMembershipsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetMemberships())
}

func TestListMyMemberships_FGAError_ReturnsInternal(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		listObjects: func(_ context.Context, _, _, _ string) ([]string, error) {
			return nil, errors.New("fga unreachable")
		},
	}
	_, err := s.ListMyMemberships(ctxWithSubject(t, "user-uuid-1"), &daemonpb.ListMyMembershipsRequest{})
	require.Error(t, err)
	st, _ := status_grpc.FromError(err)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestListMyMemberships_ZeroMemberships(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		listObjects: func(_ context.Context, _, _, _ string) ([]string, error) {
			return nil, nil
		},
	}
	resp, err := s.ListMyMemberships(ctxWithSubject(t, "user-uuid-1"), &daemonpb.ListMyMembershipsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetMemberships())
}

// TestListMyMemberships_HappyPath_RoleAndSorting verifies the 2*N BatchCheck
// layout: for 3 tenants the stub receives 6 checks (owner+admin per tenant).
// "acme" is marked admin-only → role "admin". Others get no flags → "member".
func TestListMyMemberships_HappyPath_RoleAndSorting(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		listObjects: func(_ context.Context, user, relation, objectType string) ([]string, error) {
			assert.Equal(t, "user:user-uuid-1", user)
			assert.Equal(t, "member", relation)
			assert.Equal(t, "tenant", objectType)
			// Intentionally unsorted to verify the handler's sort.
			return []string{"zeta", "acme", "beta"}, nil
		},
		batchCheck: func(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
			// Expect 2*3 = 6 checks: [owner:zeta, admin:zeta, owner:acme, admin:acme, owner:beta, admin:beta]
			require.Len(t, checks, 6)
			out := make([]bool, len(checks))
			for i, c := range checks {
				assert.Equal(t, "user:user-uuid-1", c.User)
				assert.True(t, c.Relation == "owner" || c.Relation == "admin",
					"unexpected relation: %s", c.Relation)
				// Mark "acme" as admin-only.
				if c.Object == "tenant:acme" && c.Relation == "admin" {
					out[i] = true
				}
			}
			return out, nil
		},
	}
	// Resolver returns names for acme/beta but misses zeta.
	s.tenantNameResolver = func(_ context.Context, tid string) (string, bool, error) {
		switch tid {
		case "acme":
			return "Acme Corp", true, nil
		case "beta":
			return "Beta Org", true, nil
		}
		return "", false, nil
	}

	resp, err := s.ListMyMemberships(ctxWithSubject(t, "user-uuid-1"), &daemonpb.ListMyMembershipsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetMemberships(), 3)

	// Sorted by name ASC; zeta has no friendly name so its name == "zeta".
	assert.Equal(t, "Acme Corp", resp.Memberships[0].GetTenantName())
	assert.Equal(t, "acme", resp.Memberships[0].GetTenantId())
	assert.Equal(t, "admin", resp.Memberships[0].GetRole())

	assert.Equal(t, "Beta Org", resp.Memberships[1].GetTenantName())
	assert.Equal(t, "beta", resp.Memberships[1].GetTenantId())
	assert.Equal(t, "member", resp.Memberships[1].GetRole())

	assert.Equal(t, "zeta", resp.Memberships[2].GetTenantName())
	assert.Equal(t, "zeta", resp.Memberships[2].GetTenantId())
	assert.Equal(t, "member", resp.Memberships[2].GetRole())
}

func TestListMyMemberships_BatchCheckFailure_DegradesToMember(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		listObjects: func(_ context.Context, _, _, _ string) ([]string, error) {
			return []string{"acme"}, nil
		},
		batchCheck: func(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
			return nil, errors.New("batch failed")
		},
	}
	resp, err := s.ListMyMemberships(ctxWithSubject(t, "u1"), &daemonpb.ListMyMembershipsRequest{})
	require.NoError(t, err) // non-fatal degradation
	require.Len(t, resp.GetMemberships(), 1)
	assert.Equal(t, "member", resp.Memberships[0].GetRole())
}

func TestListMyMemberships_NameResolverNil_UsesIDFallback(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		listObjects: func(_ context.Context, _, _, _ string) ([]string, error) {
			return []string{"acme"}, nil
		},
	}
	s.tenantNameResolver = nil

	resp, err := s.ListMyMemberships(ctxWithSubject(t, "u1"), &daemonpb.ListMyMembershipsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetMemberships(), 1)
	assert.Equal(t, "acme", resp.Memberships[0].GetTenantName())
	assert.Equal(t, "acme", resp.Memberships[0].GetTenantId())
}

// ---------------------------------------------------------------------------
// New role-derivation test cases (spec: tenant-role-taxonomy Req 2.5)
// ---------------------------------------------------------------------------

// batchCheckForSingleTenant is a helper that builds a 2-item BatchCheck stub
// returning isOwner and isAdmin for the single tenant "acme".
func batchCheckForSingleTenant(isOwner, isAdmin bool) func(context.Context, []authz.CheckRequest) ([]bool, error) {
	return func(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
		// Handler sends [owner, admin] for each tenant.
		out := make([]bool, len(checks))
		for i, c := range checks {
			if c.Object == "tenant:acme" {
				switch c.Relation {
				case "owner":
					out[i] = isOwner
				case "admin":
					out[i] = isAdmin
				}
			}
		}
		return out, nil
	}
}

// TestListMyMemberships_RoleDerivation_OwnerOnly: owner tuple only → role "owner".
// Spec: tenant-role-taxonomy Req 2.5.
func TestListMyMemberships_RoleDerivation_OwnerOnly(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		listObjects: func(_ context.Context, _, _, _ string) ([]string, error) {
			return []string{"acme"}, nil
		},
		batchCheck: batchCheckForSingleTenant(true, false),
	}

	resp, err := s.ListMyMemberships(ctxWithSubject(t, "u1"), &daemonpb.ListMyMembershipsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetMemberships(), 1)
	assert.Equal(t, "owner", resp.Memberships[0].GetRole(),
		"tenant-role-taxonomy Req 2.5: owner-only tuple must produce role 'owner'")
}

// TestListMyMemberships_RoleDerivation_AdminOnly: admin tuple only → role "admin".
// Spec: tenant-role-taxonomy Req 2.5.
func TestListMyMemberships_RoleDerivation_AdminOnly(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		listObjects: func(_ context.Context, _, _, _ string) ([]string, error) {
			return []string{"acme"}, nil
		},
		batchCheck: batchCheckForSingleTenant(false, true),
	}

	resp, err := s.ListMyMemberships(ctxWithSubject(t, "u1"), &daemonpb.ListMyMembershipsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetMemberships(), 1)
	assert.Equal(t, "admin", resp.Memberships[0].GetRole(),
		"tenant-role-taxonomy Req 2.5: admin-only tuple must produce role 'admin'")
}

// TestListMyMemberships_RoleDerivation_MemberOnly: no owner or admin tuple → role "member".
// Spec: tenant-role-taxonomy Req 2.5.
func TestListMyMemberships_RoleDerivation_MemberOnly(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		listObjects: func(_ context.Context, _, _, _ string) ([]string, error) {
			return []string{"acme"}, nil
		},
		batchCheck: batchCheckForSingleTenant(false, false),
	}

	resp, err := s.ListMyMemberships(ctxWithSubject(t, "u1"), &daemonpb.ListMyMembershipsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetMemberships(), 1)
	assert.Equal(t, "member", resp.Memberships[0].GetRole(),
		"tenant-role-taxonomy Req 2.5: no owner or admin tuple must produce role 'member'")
}

// TestListMyMemberships_RoleDerivation_OverPermissioned: all three tuples present
// (owner + admin + member, as FGA computed union may produce) → role "owner" (highest).
// Spec: tenant-role-taxonomy Req 2.5.
func TestListMyMemberships_RoleDerivation_OverPermissioned(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		listObjects: func(_ context.Context, _, _, _ string) ([]string, error) {
			return []string{"acme"}, nil
		},
		// Both owner and admin true — the BatchCheck for owner and admin both return true.
		batchCheck: batchCheckForSingleTenant(true, true),
	}

	resp, err := s.ListMyMemberships(ctxWithSubject(t, "u1"), &daemonpb.ListMyMembershipsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetMemberships(), 1)
	assert.Equal(t, "owner", resp.Memberships[0].GetRole(),
		"tenant-role-taxonomy Req 2.5: over-permissioned (owner+admin) must produce highest role 'owner'")
}

// ---------------------------------------------------------------------------
// GetMyPermissions tests — gibson#289 owner RBAC closure parity
//
// Asserts that a user with role "owner" receives at minimum all permissions
// that a user with role "admin" receives, and that the returned role string
// correctly reflects the highest held FGA relation.
// ---------------------------------------------------------------------------

// batchCheckForPermissions builds a BatchCheck stub for GetMyPermissions.
// checks[0] = owner, checks[1] = admin (the order emitted by the handler).
func batchCheckForPermissions(isOwner, isAdmin bool) func(context.Context, []authz.CheckRequest) ([]bool, error) {
	return func(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
		out := make([]bool, len(checks))
		for i, c := range checks {
			switch c.Relation {
			case "owner":
				out[i] = isOwner
			case "admin":
				out[i] = isAdmin
			}
		}
		return out, nil
	}
}

// TestGetMyPermissions_OwnerRole: owner tuple → role "owner", IsAdmin true.
// Spec: gibson#289 — owner must return role "owner", not "admin".
func TestGetMyPermissions_OwnerRole(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		batchCheck: batchCheckForPermissions(true, false),
	}

	ctx := ctxWithSubject(t, "u1")
	resp, err := s.GetMyPermissions(ctx, &daemonpb.GetMyPermissionsRequest{TenantId: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "owner", resp.GetRole(),
		"gibson#289: owner tuple must produce role 'owner', not 'admin'")
	assert.True(t, resp.GetIsAdmin(),
		"gibson#289: owner has admin-level privilege; IsAdmin must be true")
}

// TestGetMyPermissions_AdminRole: admin-only tuple → role "admin", IsAdmin true.
func TestGetMyPermissions_AdminRole(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		batchCheck: batchCheckForPermissions(false, true),
	}

	ctx := ctxWithSubject(t, "u1")
	resp, err := s.GetMyPermissions(ctx, &daemonpb.GetMyPermissionsRequest{TenantId: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "admin", resp.GetRole())
	assert.True(t, resp.GetIsAdmin())
}

// TestGetMyPermissions_MemberRole: no owner or admin tuple → role "member", IsAdmin false.
func TestGetMyPermissions_MemberRole(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		batchCheck: batchCheckForPermissions(false, false),
	}

	ctx := ctxWithSubject(t, "u1")
	resp, err := s.GetMyPermissions(ctx, &daemonpb.GetMyPermissionsRequest{TenantId: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "member", resp.GetRole())
	assert.False(t, resp.GetIsAdmin())
}

// TestGetMyPermissions_OwnerAndAdmin: both owner+admin true (FGA computed union)
// → highest role "owner", IsAdmin true.
func TestGetMyPermissions_OwnerAndAdmin(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		batchCheck: batchCheckForPermissions(true, true),
	}

	ctx := ctxWithSubject(t, "u1")
	resp, err := s.GetMyPermissions(ctx, &daemonpb.GetMyPermissionsRequest{TenantId: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "owner", resp.GetRole(),
		"gibson#289: over-permissioned (owner+admin via FGA computed union) must produce role 'owner'")
	assert.True(t, resp.GetIsAdmin())
}

// TestGetMyPermissions_BatchCheckFailure: BatchCheck error → member role, non-fatal.
func TestGetMyPermissions_BatchCheckFailure(t *testing.T) {
	s := newServerForMembershipTest()
	s.authorizer = &stubAuthorizer{
		batchCheck: func(_ context.Context, _ []authz.CheckRequest) ([]bool, error) {
			return nil, errors.New("fga unavailable")
		},
	}

	ctx := ctxWithSubject(t, "u1")
	resp, err := s.GetMyPermissions(ctx, &daemonpb.GetMyPermissionsRequest{TenantId: "acme"})
	require.NoError(t, err, "BatchCheck failure must degrade gracefully, not return an error")
	assert.Equal(t, "member", resp.GetRole())
	assert.False(t, resp.GetIsAdmin())
}

// TestGetMyPermissions_OwnerClosureSupersetOfAdmin: owner's effective privilege level
// (IsAdmin=true, role="owner") must be at least as permissive as admin's
// (IsAdmin=true, role="admin"). This asserts the closure parity required by gibson#289.
func TestGetMyPermissions_OwnerClosureSupersetOfAdmin(t *testing.T) {
	tests := []struct {
		name         string
		isOwner      bool
		isAdmin      bool
		wantRole     string
		wantIsAdmin  bool
	}{
		{
			name:        "owner_has_admin_privilege",
			isOwner:     true,
			isAdmin:     false,
			wantRole:    "owner",
			wantIsAdmin: true, // owner implies admin — IsAdmin must be true
		},
		{
			name:        "admin_has_admin_privilege",
			isOwner:     false,
			isAdmin:     true,
			wantRole:    "admin",
			wantIsAdmin: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newServerForMembershipTest()
			s.authorizer = &stubAuthorizer{
				batchCheck: batchCheckForPermissions(tt.isOwner, tt.isAdmin),
			}
			ctx := ctxWithSubject(t, "u1")
			resp, err := s.GetMyPermissions(ctx, &daemonpb.GetMyPermissionsRequest{TenantId: "acme"})
			require.NoError(t, err)
			assert.Equal(t, tt.wantRole, resp.GetRole(),
				"gibson#289 closure parity: %s must return role %q", tt.name, tt.wantRole)
			assert.Equal(t, tt.wantIsAdmin, resp.GetIsAdmin(),
				"gibson#289 closure parity: %s IsAdmin must be %v", tt.name, tt.wantIsAdmin)
		})
	}
}
